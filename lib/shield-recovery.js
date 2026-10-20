// =====================================================================
// VNM Shield — Downtime Detection & Auto-Recovery
// ---------------------------------------------------------------------
// Two layers of recovery, deliberately separated:
//
//   IN-PANEL (this module)
//     - Health checks: database, QEMU binary, /dev/kvm, systemd
//       services, disk headroom, memory
//     - Controlled recovery of DEPENDENT services only (node agent,
//       watchdog) - the panel can never restart ITSELF from inside a
//       hung process, and it NEVER restarts or kills VMs because the
//       panel is unhealthy. VM downtime must never be collateral
//       damage of a panel problem.
//     - Every recovery: capture diagnostics FIRST (journal tail),
//       act, VERIFY the service is genuinely healthy after, record
//       the outcome. A restart that leaves the service dead is a
//       failure, not a success.
//     - Circuit breaker per target: at most N attempts per window
//       (default 3 / 30 min) with a cooldown between attempts. When
//       the breaker opens, recovery stops and the owner is told that
//       manual intervention is required - an endless restart loop
//       would only mask the failure and thrash the host.
//
//   EXTERNAL (watchdog/vnm-watchdog.js)
//     - Separate OS-level process that restarts the PANEL when the
//       panel is unreachable - see that file. It reuses the same
//       breaker philosophy and records its actions into the same
//       recovery log (when the DB is reachable; always to its own
//       file log otherwise).
// =====================================================================

'use strict';

const fs = require('fs');
const { exec } = require('child_process');
const os = require('os');
const { redact } = require('./shield-diagnoser');

// Services the panel is ALLOWED to restart on its own. vnm-panel is
// intentionally absent (see header) - and QEMU/VMs are NEVER here.
const RESTARTABLE = ['vnm-agent', 'vnm-watchdog'];

function createRecovery(ctx) {
  const db = ctx.db;
  const getSetting = ctx.getSetting;
  const setSetting = ctx.setSetting;
  const notify = ctx.notify;
  const dataDir = ctx.dataDir;
  const log = (...a) => { try { console.log('[Shield:Recovery]', ...a); } catch (e) {} };

  const dbGet = (sql, params) => new Promise((resolve, reject) => db.get(sql, params, (e, r) => e ? reject(e) : resolve(r)));
  const dbRun = (sql, params) => new Promise((resolve, reject) => db.run(sql, params, function (e) { e ? reject(e) : resolve(this); }));
  const isLinux = process.platform === 'linux';

  const execP = (cmd, timeoutMs) => new Promise((resolve) => {
    try {
      exec(cmd, { timeout: timeoutMs || 10000, maxBuffer: 2 * 1024 * 1024 }, (err, stdout, stderr) => {
        resolve({ ok: !err, stdout: String(stdout || ''), stderr: String(stderr || ''), error: err ? (err.message || String(err)) : null });
      });
    } catch (e) { resolve({ ok: false, stdout: '', stderr: '', error: e.message }); }
  });

  // ---------------- schema ----------------
  function ensureSchema() {
    return new Promise((resolve) => {
      db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS shield_recovery_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          target TEXT NOT NULL,
          action TEXT NOT NULL,
          reason TEXT,
          outcome TEXT NOT NULL,
          healthy_after INTEGER,
          diagnostics TEXT,
          duration_ms INTEGER,
          breaker_state TEXT,
          actor TEXT DEFAULT 'panel'
        )`, () => {
          db.run(`CREATE INDEX IF NOT EXISTS idx_shield_rec_time ON shield_recovery_log(created_at)`, () => resolve());
        });
      });
    });
  }

  // ---------------- circuit breakers ----------------
  // In-memory (per panel process). { target: { attempts: [ts,...], openUntil } }
  const breakers = new Map();

  async function breakerAllows(target) {
    const maxAttempts = parseInt((await getSetting('shield.recovery.maxAttempts')) || '3', 10);
    const windowMs = parseInt((await getSetting('shield.recovery.windowMinutes') || '30', 10) * 60 * 1000, 10);
    const cooldownMs = parseInt((await getSetting('shield.recovery.cooldownMinutes') || '5', 10) * 60 * 1000, 10);

    let b = breakers.get(target);
    if (!b) { b = { attempts: [], openUntil: 0 }; breakers.set(target, b); }
    const now = Date.now();
    if (b.openUntil > now) {
      return { allowed: false, state: 'open', retryInMs: b.openUntil - now };
    }
    // drop attempts outside the window
    b.attempts = b.attempts.filter((t) => now - t < windowMs);
    if (b.attempts.length >= maxAttempts) {
      b.openUntil = now + windowMs;
      return { allowed: false, state: 'open', retryInMs: windowMs };
    }
    const last = b.attempts.length ? b.attempts[b.attempts.length - 1] : 0;
    if (last && now - last < cooldownMs) {
      return { allowed: false, state: 'cooldown', retryInMs: cooldownMs - (now - last) };
    }
    return { allowed: true, state: 'closed', attemptsLeft: maxAttempts - b.attempts.length };
  }

  function breakerRecord(target, outcome) {
    let b = breakers.get(target);
    if (!b) { b = { attempts: [], openUntil: 0 }; breakers.set(target, b); }
    if (outcome === 'success') { b.attempts = []; b.openUntil = 0; return 'closed'; }
    b.attempts.push(Date.now());
    return b.attempts.length >= 3 ? 'opened' : 'tripped';
  }

  function breakerStates() {
    const out = {};
    const now = Date.now();
    for (const [t, b] of breakers) {
      out[t] = { attempts: b.attempts.filter((x) => now - x < 30 * 60 * 1000).length, open: b.openUntil > now, openUntil: b.openUntil > now ? new Date(b.openUntil).toISOString() : null };
    }
    return out;
  }

  // ---------------- diagnostics capture ----------------
  async function captureDiagnostics(target) {
    const parts = [];
    const journal = await execP(`journalctl -u ${target} -n 60 --no-pager 2>/dev/null`, 8000);
    if (journal.ok && journal.stdout) parts.push('--- journalctl -u ' + target + ' (last 60 lines) ---\n' + journal.stdout.slice(0, 12000));
    const self = await execP(`journalctl -u vnm-panel -n 30 --no-pager 2>/dev/null`, 8000);
    if (self.ok && self.stdout) parts.push('--- journalctl -u vnm-panel (last 30 lines) ---\n' + self.stdout.slice(0, 8000));
    try {
      const mem = fs.readFileSync('/proc/meminfo', 'utf8').split('\n').slice(0, 3).join('\n');
      parts.push('--- /proc/meminfo (head) ---\n' + mem);
    } catch (e) { /* non-linux */ }
    return redact(parts.join('\n\n')).slice(0, 20000);
  }

  // ---------------- health checks ----------------
  async function checkDb() {
    try {
      await dbGet(`SELECT 1 AS ok`);
      let integrity = 'skipped';
      if (Math.random() < 0.1) {  // occasional deep check
        const r = await new Promise((resolve) => db.get(`PRAGMA quick_check`, [], (e, row) => resolve(e ? 'error: ' + e.message : (row && row.quick_check) || 'unknown')));
        integrity = String(r);
      }
      return { ok: true, integrity };
    } catch (e) { return { ok: false, error: e.message }; }
  }

  async function checkQemu() {
    const r = await execP('command -v qemu-system-x86_64 && qemu-system-x86_64 --version | head -n 1', 8000);
    let kvm = 'absent';
    try { fs.accessSync('/dev/kvm', fs.constants.R_OK | fs.constants.W_OK); kvm = 'available'; }
    catch (e) { try { fs.accessSync('/dev/kvm', fs.constants.F_OK); kvm = 'present-no-access'; } catch (e2) { kvm = 'absent'; } }
    return { ok: r.ok, qemu: r.ok ? r.stdout.split('\n')[0] : 'not found', kvm };
  }

  async function checkServices() {
    if (!isLinux) return { ok: true, note: 'non-linux', services: [] };
    const wanted = ['vnm-panel', 'vnm-watchdog', 'vnm-agent'];
    const services = [];
    for (const s of wanted) {
      const r = await execP(`systemctl is-active ${s} 2>/dev/null`);
      const state = (r.stdout || '').trim() || (r.ok ? 'unknown' : 'not-found');
      services.push({ service: s, state });
    }
    return { ok: !services.some((s) => s.state === 'failed'), services };
  }

  async function checkDisk() {
    const dir = dataDir || os.homedir();
    const df = await execP(`df -h "${dir}" / 2>/dev/null | tail -n +2`);
    const dfi = await execP(`df -i "${dir}" / 2>/dev/null | tail -n +2`);
    const parse = (txt) => txt.split('\n').filter(Boolean).map((l) => {
      const parts = l.split(/\s+/);
      return { fs: parts[0], size: parts[1], used: parts[2], avail: parts[3], usePct: parts[4], mount: parts[5] };
    });
    const mounts = parse(df.stdout || '');
    const inodes = parse(dfi.stdout || '');
    const critical = mounts.some((m) => parseInt(m.usePct) >= 95);
    const warn = mounts.some((m) => parseInt(m.usePct) >= 85);
    return { ok: !critical, level: critical ? 'critical' : warn ? 'warn' : 'ok', mounts, inodes };
  }

  async function checkMemory() {
    try {
      const mem = fs.readFileSync('/proc/meminfo', 'utf8');
      const total = parseInt((mem.match(/MemTotal:\s+(\d+)/) || [])[1] || '0', 10);
      const avail = parseInt((mem.match(/MemAvailable:\s+(\d+)/) || [])[1] || '0', 10);
      const pct = total ? Math.round((100 * (total - avail)) / total) : null;
      return { ok: pct === null || pct < 92, usedPct: pct };
    } catch (e) { return { ok: true, note: 'unavailable' }; }
  }

  // One full health snapshot - used by the dashboard, the scheduler,
  // and the manual "Run diagnostics" button.
  async function runHealth() {
    const [dbCheck, qemu, services, disk, memory] = await Promise.all([
      checkDb(), checkQemu(), checkServices(), checkDisk(), checkMemory(),
    ]);
    const overall = dbCheck.ok && disk.ok && memory.ok && qemu.ok;
    const snap = { at: new Date().toISOString(), overall, database: dbCheck, qemu, services, disk, memory, breakers: breakerStates() };
    await setSetting('shield.recovery.lastHealth', JSON.stringify({ at: snap.at, overall, db: dbCheck.ok, disk: disk.level, mem: memory.usedPct }));
    return snap;
  }

  // ---------------- controlled recovery ----------------
  // Restarts a DEPENDENT service (never the panel, never VMs) with
  // diagnostics-first, verification-after, breaker-gated semantics.
  async function restartService(target, reason, actor) {
    if (!RESTARTABLE.includes(target)) {
      return { ok: false, error: `Refusing: '${target}' is not in the restartable set (${RESTARTABLE.join(', ')}) - VMs and the panel itself are never restarted by in-panel recovery.` };
    }
    const gate = await breakerAllows(target);
    if (!gate.allowed) {
      await dbRun(`INSERT INTO shield_recovery_log (target, action, reason, outcome, breaker_state, actor) VALUES (?,?,?,?,?,?)`,
        [target, 'restart', reason || 'scheduled', 'blocked-by-breaker', gate.state, actor || 'panel']);
      if (gate.state === 'open') {
        await notify({
          severity: 'high',
          title: `Auto-recovery circuit breaker OPEN for ${target}`,
          body: `Repeated recovery attempts for ${target} failed. Automatic restarts are suspended for the cooldown window. MANUAL INTERVENTION REQUIRED - see Shield → Recovery.`,
          diag: {
            fingerprint: 'breaker-open:' + target, category: 'recovery', component: 'recovery/' + target, severity: 'high',
            title: `Recovery circuit breaker open for ${target}`,
            explanation: 'The recovery engine attempted to restart this service multiple times within its window and stopped to prevent an endless restart loop.',
            confirmed_causes: ['The service keeps failing after restart.'],
            possible_causes: ['Configuration error introduced manually', 'Host resource exhaustion', 'Repeated crashes from a bad update'],
            suggested_fix: 'Inspect the captured diagnostics in Shield → Recovery, fix the root cause, then reset the breaker.',
            raw: { message: 'breaker open' },
          },
        });
      }
      return { ok: false, blocked: gate };
    }

    const started = Date.now();
    const diagnostics = await captureDiagnostics(target);
    const r = await execP(`systemctl restart ${target} 2>&1`, 30000);
    let healthyAfter = null;
    if (r.ok) {
      await new Promise((resolve) => setTimeout(resolve, 4000));  // settle
      const a = await execP(`systemctl is-active ${target} 2>/dev/null`);
      healthyAfter = (a.stdout || '').trim() === 'active';
    }
    const outcome = r.ok && healthyAfter ? 'success' : 'failed';
    const breakerState = breakerRecord(target, outcome);
    const durationMs = Date.now() - started;
    await dbRun(`INSERT INTO shield_recovery_log (target, action, reason, outcome, healthy_after, diagnostics, duration_ms, breaker_state, actor)
      VALUES (?,?,?,?,?,?,?,?,?)`,
      [target, 'restart', reason || 'manual', outcome, healthyAfter ? 1 : 0, diagnostics, durationMs, breakerState, actor || 'panel']);

    if (outcome === 'success') {
      await notify({
        severity: 'low',
        title: `Auto-recovery succeeded: ${target} restarted`,
        body: `Service ${target} was restarted automatically and verified healthy. Reason: ${reason || 'n/a'}. Full diagnostics are attached to the recovery record.`,
      });
    } else {
      await notify({
        severity: 'high',
        title: `Auto-recovery FAILED for ${target}`,
        body: `Attempted restart of ${target} did not produce a healthy service (${r.error || 'not active after restart'}). Diagnostics captured. ${gate.attemptsLeft !== undefined ? `Attempts left this window: ${Math.max(0, gate.attemptsLeft - 1)}` : ''}`,
        diag: {
          fingerprint: 'recovery-failed:' + target, category: 'recovery', component: 'recovery/' + target, severity: 'high',
          title: `Recovery attempt failed for ${target}`,
          explanation: 'The recovery engine restarted the service but it did not come back healthy, or the restart command itself failed.',
          confirmed_causes: ['The service is still unhealthy after a restart attempt.'],
          possible_causes: ['Crash-on-start configuration error', 'Missing dependency (disk full, network down)', 'Repeated underlying crash'],
          suggested_fix: 'Read the diagnostics in Shield → Recovery (journal excerpts were captured before the restart). The circuit breaker will suspend retries after too many failures.',
          raw: { message: redact((r.error || r.stderr || 'not healthy after restart')).slice(0, 300) },
        },
      });
    }
    return { ok: outcome === 'success', outcome, healthyAfter, durationMs, breakerState, attemptsLeft: (await breakerAllows(target)).attemptsLeft };
  }

  async function resetBreaker(target, by) {
    breakers.delete(target);
    await dbRun(`INSERT INTO shield_recovery_log (target, action, reason, outcome, actor) VALUES (?,?,?,?,?)`,
      [target, 'breaker-reset', 'manual reset by ' + (by || 'owner'), 'success', 'panel']);
    return { ok: true, target };
  }

  function history(limit) {
    return new Promise((resolve, reject) => db.all(
      `SELECT id, created_at, target, action, reason, outcome, healthy_after, duration_ms, breaker_state, actor
       FROM shield_recovery_log ORDER BY id DESC LIMIT ?`, [parseInt(limit || 50, 10)],
      (e, r) => e ? reject(e) : resolve(r || [])));
  }

  function recoveryDetail(id) {
    return new Promise((resolve, reject) => db.get(
      `SELECT * FROM shield_recovery_log WHERE id = ?`, [id],
      (e, r) => e ? reject(e) : resolve(r || null)));
  }

  return { ensureSchema, runHealth, restartService, resetBreaker, breakerStates, breakerAllows, history, recoveryDetail, RESTARTABLE, checkDb, checkDisk };
}

module.exports = { createRecovery };
