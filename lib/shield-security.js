// =====================================================================
// VNM Shield — Intrusion Detection & Security Monitoring
// ---------------------------------------------------------------------
// Five independent, individually-schedulable detectors:
//
//   1. SSH auth failures     - parses journalctl / auth.log for failed
//                              password / invalid user attempts and
//                              aggregates them per IP + per username;
//                              fires when a threshold is crossed.
//   2. Config watchers       - SHA-256 baselines for sshd_config,
//                              sudoers(+sudoers.d), firewall rules,
//                              systemd unit set and root crontab;
//                              any delta becomes an event.
//   3. Listening ports       - `ss -tlnp` diff vs baseline: a NEW
//                              listening port is an event.
//   4. Privileged accounts   - /etc/passwd UID-0 accounts + sudo/wheel
//                              group membership diff vs baseline.
//   5. Outbound connections  - established external connections
//                              grouped by process; new processes with
//                              external links get a low-severity event.
//
// POLICY (by design): no destructive automatic responses. The engine
// records, classifies, and alerts - it never blocks an IP, kills an
// account, or edits a firewall on its own unverified decision.
// Suggested responses (fail2ban etc.) appear in the event detail and
// the docs, always requiring a human.
//
// Login history (success + failure + 2FA) is recorded by app.js into
// shield_login_history and surfaced here.
//
// Every check degrades gracefully without root or on non-Linux hosts:
// unreadable sources are reported as "unmonitorable" in the snapshot
// instead of pretending to be clean.
// =====================================================================

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');
const os = require('os');

const isLinux = process.platform === 'linux';

function createSecurity(ctx) {
  const db = ctx.db;
  const getSetting = ctx.getSetting;
  const setSetting = ctx.setSetting;
  const notify = ctx.notify;   // async (event) => ...
  const log = (...a) => { try { console.log('[Shield:Security]', ...a); } catch (e) {} };

  const dbGet = (sql, params) => new Promise((resolve, reject) => db.get(sql, params, (e, r) => e ? reject(e) : resolve(r)));
  const dbAll = (sql, params) => new Promise((resolve, reject) => db.all(sql, params, (e, r) => e ? reject(e) : resolve(r || [])));
  const dbRun = (sql, params) => new Promise((resolve, reject) => db.run(sql, params, function (e) { e ? reject(e) : resolve(this); }));

  const execP = (cmd, timeoutMs) => new Promise((resolve) => {
    if (!isLinux) return resolve({ ok: false, error: 'not linux' });
    try {
      exec(cmd, { timeout: timeoutMs || 8000, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
        resolve({ ok: !err, stdout: String(stdout || ''), stderr: String(stderr || ''), error: err ? err.message : null });
      });
    } catch (e) { resolve({ ok: false, error: e.message }); }
  });

  // ---------------- schema ----------------
  function ensureSchema() {
    return new Promise((resolve) => {
      db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS shield_security_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          detector TEXT NOT NULL,
          severity TEXT NOT NULL DEFAULT 'medium',
          title TEXT NOT NULL,
          detail TEXT,
          status TEXT DEFAULT 'new',
          fingerprint TEXT
        )`, () => {
          db.run(`CREATE TABLE IF NOT EXISTS shield_sec_baseline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(scope, key)
          )`, () => {
            db.run(`CREATE TABLE IF NOT EXISTS shield_login_history (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
              user_id INTEGER,
              username TEXT,
              success INTEGER NOT NULL DEFAULT 0,
              reason TEXT,
              ip TEXT,
              user_agent TEXT
            )`, () => {
              db.run(`CREATE INDEX IF NOT EXISTS idx_shield_lh_time ON shield_login_history(created_at)`, () => {
                db.run(`CREATE INDEX IF NOT EXISTS idx_shield_lh_user ON shield_login_history(username)`, () => resolve());
              });
            });
          });
        });
      });
    });
  }

  async function recordEvent(detector, severity, title, detail, fingerprint) {
    await dbRun(`INSERT INTO shield_security_events (detector, severity, title, detail, fingerprint) VALUES (?,?,?,?,?)`,
      [detector, severity, title, detail ? JSON.stringify(detail).slice(0, 4000) : null, fingerprint || null]);
  }

  // ---- baseline set helpers (scope = detector name) ----
  async function getScope(scope) {
    const rows = await dbAll(`SELECT key, value FROM shield_sec_baseline WHERE scope = ?`, [scope]);
    const m = new Map();
    for (const r of rows) m.set(r.key, r.value);
    return m;
  }

  async function putScope(scope, map) {
    await dbRun(`DELETE FROM shield_sec_baseline WHERE scope = ?`, [scope]);
    for (const [k, v] of map) {
      await dbRun(`INSERT OR REPLACE INTO shield_sec_baseline (scope, key, value, updated_at) VALUES (?,?,?,CURRENT_TIMESTAMP)`, [scope, k, v]);
    }
  }

  // ---------------- 1. SSH auth failures ----------------
  async function checkSshFailures() {
    const windowMin = parseInt((await getSetting('shield.security.sshWindowMinutes')) || '10', 10);
    const threshold = parseInt((await getSetting('shield.security.sshFailThreshold')) || '10', 10);

    let text = '';
    const j = await execP(`journalctl -u ssh -u sshd --since "-${windowMin} minutes" --no-pager 2>/dev/null | grep -iE "failed password|invalid user" | tail -n 500`);
    if (j.ok && j.stdout) text = j.stdout;
    if (!text) {
      try { text = fs.readFileSync('/var/log/auth.log', 'utf8').split('\n').slice(-2000).join('\n'); } catch (e) { /* no access */ }
    }
    if (!text) return { detector: 'ssh', status: 'unmonitorable', note: 'Neither journalctl nor /var/log/auth.log is readable by this user.' };

    const byIp = new Map(), byUser = new Map();
    let total = 0;
    for (const line of text.split('\n')) {
      if (!/failed password|invalid user/i.test(line)) continue;
      total++;
      const ipm = line.match(/from\s+([0-9a-fA-F.:]+)/);
      const um = line.match(/(?:invalid user|for\s+(?:invalid user\s+)?)([a-zA-Z0-9._-]+)/);
      if (ipm) byIp.set(ipm[1], (byIp.get(ipm[1]) || 0) + 1);
      if (um) byUser.set(um[1], (byUser.get(um[1]) || 0) + 1);
    }

    const topIp = [...byIp.entries()].sort((a, b) => b[1] - a[1])[0];
    if (total >= threshold) {
      const detail = {
        windowMinutes: windowMin, threshold, total,
        topIps: [...byIp.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5),
        topUsers: [...byUser.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5),
        note: 'No automatic action taken. Suggested: verify these attempts, then consider fail2ban or firewall rules - see docs/VNM-SHIELD.md.',
      };
      await recordEvent('ssh', 'high', `Repeated SSH authentication failures (${total} in ${windowMin} min)`, detail,
        crypto.createHash('sha256').update('ssh-fails:' + (topIp ? topIp[0] : '')).digest('hex').slice(0, 16));
      await notify({
        severity: 'high',
        title: `Possible SSH brute-force in progress`,
        body: `${total} failed SSH logins in the last ${windowMin} minutes` + (topIp ? ` - top source ${topIp[0]} (${topIp[1]} attempts)` : '') +
          `. No automatic blocking was applied. Check Shield → Security events.`,
        diag: {
          fingerprint: crypto.createHash('sha256').update('ssh-fails:' + (topIp ? topIp[0] : '')).digest('hex').slice(0, 16),
          category: 'security', component: 'host/ssh', severity: 'high',
          title: 'Repeated SSH authentication failures',
          explanation: 'Many failed SSH logins were observed in a short window - the classic signature of a brute-force attempt.',
          confirmed_causes: ['Multiple failed authentication attempts against this host SSH server.'],
          possible_causes: ['Automated scanner on the internet (very common on any public VPS)', 'A legitimate user repeatedly typing a wrong password', 'A compromised client with saved wrong credentials'],
          suggested_fix: 'Verify no legitimate account is locked out, then enable fail2ban or add firewall rules. Shield never auto-blocks on unverified data.',
          raw: { message: `${total} failures` },
        },
      });
      return { detector: 'ssh', status: 'alert', total, top: topIp };
    }
    return { detector: 'ssh', status: 'ok', total, threshold };
  }

  // ---------------- 2. Config watchers ----------------
  const CONFIG_FILES = [
    { key: 'sshd_config', path: '/etc/ssh/sshd_config' },
    { key: 'sudoers', path: '/etc/sudoers' },
  ];

  function hashText(t) { return crypto.createHash('sha256').update(t).digest('hex'); }

  async function checkConfigFiles() {
    const findings = [];
    // static files
    for (const f of CONFIG_FILES) {
      let hash = null, note = null;
      try { hash = hashText(fs.readFileSync(f.path, 'utf8')); }
      catch (e) { note = 'unreadable (' + e.code + ')'; }
      findings.push({ kind: 'file', key: f.key, hash, note, path: f.path });
    }
    // sudoers.d directory listing + hashes (readable without root often)
    try {
      const files = fs.readdirSync('/etc/sudoers.d').sort();
      const combined = [];
      for (const sf of files) {
        try { combined.push(sf + ':' + hashText(fs.readFileSync(path.join('/etc/sudoers.d', sf), 'utf8'))); } catch (e) { combined.push(sf + ':unreadable'); }
      }
      findings.push({ kind: 'file', key: 'sudoers.d', hash: hashText(combined.join('|')), note: null, path: '/etc/sudoers.d/*' });
    } catch (e) { findings.push({ kind: 'file', key: 'sudoers.d', hash: null, note: 'unreadable', path: '/etc/sudoers.d' }); }

    // firewall rules
    const fw = await execP('ufw status verbose 2>/dev/null || iptables-save 2>/dev/null | head -c 65536');
    findings.push({ kind: 'command', key: 'firewall', hash: fw.ok && fw.stdout ? hashText(fw.stdout) : null, note: fw.ok ? null : 'unavailable' });

    // systemd unit set
    const units = await execP('systemctl list-unit-files --type=service --no-pager 2>/dev/null | awk \'{print $1" "$2}\' | sort');
    findings.push({ kind: 'command', key: 'systemd-units', hash: units.ok && units.stdout ? hashText(units.stdout) : null, note: units.ok ? null : 'unavailable' });

    // root crontab
    const cron = await execP('crontab -l 2>/dev/null');
    findings.push({ kind: 'command', key: 'root-crontab', hash: cron.ok ? hashText(cron.stdout || '(empty)') : null, note: cron.ok ? null : 'unavailable' });

    // diff vs baseline
    const baseline = await getScope('config');
    const changes = [];
    const next = new Map();
    for (const f of findings) {
      if (f.hash === null) { next.set(f.key, 'unmonitorable'); continue; }
      next.set(f.key, f.hash);
      const old = baseline.get(f.key);
      if (old === undefined) continue;              // first run: learn
      if (old !== f.hash) changes.push(f);
    }
    if (baseline.size > 0) {
      for (const [k] of baseline) if (!next.has(k)) changes.push({ kind: 'gone', key: k });
      if (changes.length) {
        const detail = {
          changed: changes.map((c) => c.key),
          note: 'Host-level security configuration changed. If you did not make this change, investigate immediately. Shield did NOT revert anything automatically.',
        };
        await recordEvent('config', 'high', 'Security configuration changed: ' + changes.map((c) => c.key).join(', '), detail,
          hashText('config:' + changes.map((c) => c.key).join(',')).slice(0, 16));
        await notify({
          severity: 'high',
          title: 'Security configuration changed on the host',
          body: `Changed: ${changes.map((c) => c.key).join(', ')}. If you did not change this, investigate now. No automatic action was taken.`,
          diag: {
            fingerprint: hashText('config:' + changes.map((c) => c.key).join(',')).slice(0, 16),
            category: 'security', component: 'host/config', severity: 'high',
            title: 'Security configuration changed',
            explanation: 'One or more host-level security files (SSH config, sudoers, firewall, systemd units, or root crontab) changed compared to the learned baseline.',
            confirmed_causes: ['The named configuration differs from the previously observed state.'],
            possible_causes: ['An administrator made a legitimate change', 'A package update rewrote a config file', 'Unauthorized access to the host'],
            suggested_fix: 'Check with everyone who has host access. If unexpected, review the file content and last modification time (stat <file>).',
            raw: { message: changes.map((c) => c.key).join(',') },
          },
        });
      }
    }
    if (baseline.size === 0 || changes.length || [...next.entries()].some(([k, v]) => baseline.get(k) !== v)) {
      await putScope('config', next);
    }
    return { detector: 'config', status: changes.length ? 'alert' : 'ok', changes: changes.map((c) => c.key), monitored: findings.length, unmonitorable: findings.filter((f) => f.hash === null).map((f) => f.key) };
  }

  // ---------------- 3. Listening ports ----------------
  async function checkListeningPorts() {
    const r = await execP(`ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4" "$6}' | sort -u`);
    if (!r.ok || !r.stdout) return { detector: 'ports', status: 'unmonitorable' };
    const current = new Map();
    for (const line of r.stdout.trim().split('\n')) {
      if (!line.trim()) continue;
      const [addrProc] = line.split(' ');
      const proc = line.includes('users:') ? (line.match(/users:\(\("([^"]+)"/) || [])[1] || '?' : '?';
      current.set(addrProc, proc);
    }
    const baseline = await getScope('ports');
    const newPorts = [];
    if (baseline.size > 0) {
      for (const [addr, proc] of current) {
        if (!baseline.has(addr)) newPorts.push({ addr, proc });
      }
    }
    const removed = baseline.size ? [...baseline.keys()].filter((k) => !current.has(k)) : [];
    if (newPorts.length) {
      const detail = {
        newPorts,
        note: 'A process started listening on a port that was not listening before. Verify this is expected before opening firewall access.',
      };
      await recordEvent('ports', 'medium', `New listening port(s): ${newPorts.map((p) => p.addr).join(', ')}`, detail,
        hashText('ports:' + newPorts.map((p) => p.addr).join(',')).slice(0, 16));
      await notify({
        severity: 'medium',
        title: 'New listening port detected',
        body: `New listener(s): ${newPorts.map((p) => p.addr + ' (' + p.proc + ')').join(', ')}. Verify this is expected.`,
        diag: {
          fingerprint: hashText('ports:' + newPorts.map((p) => p.addr).join(',')).slice(0, 16),
          category: 'security', component: 'host/ports', severity: 'medium',
          title: 'New listening port detected',
          explanation: 'A process is now accepting connections on a port that had no listener when the baseline was recorded.',
          confirmed_causes: ['A new service started, or an existing service began listening on an additional port.'],
          possible_causes: ['You (or staff) started a new service deliberately', 'A VM port-forward was added', 'Unexpected software was run on the host'],
          suggested_fix: 'Identify the process (ss -tlnp | grep <port>). Expected: nothing to do. Unexpected: stop it and check Shield → Security events history.',
          raw: { message: newPorts.map((p) => p.addr).join(',') },
        },
      });
    }
    if (baseline.size === 0 || newPorts.length || removed.length) await putScope('ports', new Map([...current].map(([a, p]) => [a, p])));
    return { detector: 'ports', status: newPorts.length ? 'alert' : 'ok', newPorts, count: current.size };
  }

  // ---------------- 4. Privileged accounts ----------------
  async function checkPrivilegedAccounts() {
    let passwd = null;
    try { passwd = fs.readFileSync('/etc/passwd', 'utf8'); } catch (e) { return { detector: 'accounts', status: 'unmonitorable' }; }
    const uid0 = passwd.split('\n').filter((l) => l.trim()).filter((l) => l.split(':')[2] === '0').map((l) => l.split(':')[0]).sort();
    let groups = '';
    const g = await execP(`getent group sudo adm wheel 2>/dev/null`);
    if (g.ok) groups = g.stdout;
    const current = new Map([['uid0', uid0.join(',')], ['groups', hashText(groups || '(none)')]]);

    const baseline = await getScope('accounts');
    const changes = [];
    const oldUid0 = (baseline.get('uid0') || '').split(',').filter(Boolean);
    if (baseline.size > 0) {
      const added = uid0.filter((u) => !oldUid0.includes(u));
      const removed = oldUid0.filter((u) => !uid0.includes(u));
      if (added.length || removed.length) changes.push({ added, removed });
      if (baseline.get('groups') && baseline.get('groups') !== current.get('groups')) changes.push({ sudoGroupsChanged: true });
    }
    if (changes.length) {
      const detail = { changes, note: 'Privileged account set changed. This is HIGH priority if unexpected. No automatic action taken.' };
      await recordEvent('accounts', 'critical', 'Privileged account set changed', detail, hashText('accounts:' + JSON.stringify(changes)).slice(0, 16));
      await notify({
        severity: 'critical',
        title: 'Privileged accounts changed on the host',
        body: `UID-0 or sudo group membership changed (${JSON.stringify(changes)}). If this was not you, treat the host as compromised and investigate.`,
        diag: {
          fingerprint: hashText('accounts:' + JSON.stringify(changes)).slice(0, 16),
          category: 'security', component: 'host/accounts', severity: 'critical',
          title: 'Privileged accounts changed',
          explanation: 'The set of accounts with root or sudo privileges on the host changed since the last check.',
          confirmed_causes: ['A new UID-0 account appeared, one was removed, or sudo/wheel group membership changed.'],
          possible_causes: ['An administrator added a legitimate account', 'A software installer created a service account', 'Attacker persistence after a compromise'],
          suggested_fix: 'If unexpected: audit with `last`, `lastb`, and the audit log; consider rebuilding the host from backups. Shield never edits accounts automatically.',
          raw: { message: JSON.stringify(changes) },
        },
      });
    }
    if (baseline.size === 0 || changes.length) await putScope('accounts', current);
    return { detector: 'accounts', status: changes.length ? 'alert' : 'ok', uid0, changes };
  }

  // ---------------- 5. Outbound connections (light) ----------------
  async function checkOutbound() {
    const r = await execP(`ss -tnp state established 2>/dev/null | tail -n +2`);
    if (!r.ok || !r.stdout) return { detector: 'outbound', status: 'unmonitorable' };
    const byProc = new Map();
    for (const line of r.stdout.split('\n')) {
      if (!line.trim()) continue;
      const proc = (line.match(/users:\(\("([^"]+)"/) || [])[1];
      const peer = (line.split(/\s+/)[4] || '');
      if (!proc || !peer) continue;
      // external = non-private peer
      if (/^(127\.|::1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|fe80)/.test(peer)) continue;
      if (!byProc.has(proc)) byProc.set(proc, new Set());
      byProc.get(proc).add(peer);
    }
    const current = new Map([...byProc.entries()].map(([p, peers]) => [p, String([...peers].sort().slice(0, 20).length)]));
    const baseline = await getScope('outbound');
    const newProcs = baseline.size ? [...current.keys()].filter((p) => !baseline.has(p)) : [];
    if (newProcs.length) {
      await recordEvent('outbound', 'low', `New process(es) with external connections: ${newProcs.join(', ')}`,
        { newProcs, note: 'Informational: a process not previously seen is talking to the internet.' },
        hashText('outbound:' + newProcs.join(',')).slice(0, 16));
    }
    if (baseline.size === 0 || newProcs.length || [...current.keys()].some((k) => !baseline.has(k))) {
      await putScope('outbound', new Map([...current.entries()].filter(([p]) => !['qemu-system-x86', 'node'].includes(p) || true)));
    }
    return { detector: 'outbound', status: newProcs.length ? 'alert' : 'ok', processes: [...byProc.keys()], newProcesses: newProcs };
  }

  // ---------------- login history ----------------
  async function recordLogin(entry) {
    await dbRun(`INSERT INTO shield_login_history (user_id, username, success, reason, ip, user_agent)
      VALUES (?,?,?,?,?,?)`,
      [entry.userId || null, String(entry.username || '').slice(0, 100), entry.success ? 1 : 0,
       String(entry.reason || '').slice(0, 100), String(entry.ip || '').slice(0, 64),
       String(entry.userAgent || '').slice(0, 250)]);
    // brute-force watch on panel logins themselves
    if (!entry.success) {
      const row = await dbGet(`SELECT COUNT(*) AS n FROM shield_login_history
        WHERE success = 0 AND ip = ? AND created_at > datetime('now', '-10 minutes')`, [entry.ip]);
      if ((row.n || 0) >= 10) {
        await recordEvent('login', 'high', `Repeated panel login failures from ${entry.ip}`,
          { ip: entry.ip, count: row.n, note: 'Panel-level brute force suspected. No auto-block applied.' },
          hashText('login-fails:' + entry.ip).slice(0, 16));
      }
    }
  }

  function loginHistory(limit, onlyFailures) {
    const sql = onlyFailures
      ? `SELECT * FROM shield_login_history WHERE success = 0 ORDER BY id DESC LIMIT ?`
      : `SELECT * FROM shield_login_history ORDER BY id DESC LIMIT ?`;
    return new Promise((resolve, reject) => db.all(sql, [parseInt(limit || 100, 10)], (e, r) => e ? reject(e) : resolve(r || [])));
  }

  function events(limit) {
    return new Promise((resolve, reject) => db.all(
      `SELECT * FROM shield_security_events ORDER BY id DESC LIMIT ?`, [parseInt(limit || 100, 10)],
      (e, r) => e ? reject(e) : resolve(r || [])));
  }

  // Full sweep (schedule + manual "Run security scan")
  async function sweep(source) {
    const results = [];
    for (const check of [checkSshFailures, checkConfigFiles, checkListeningPorts, checkPrivilegedAccounts, checkOutbound]) {
      try { results.push(await check()); }
      catch (e) { results.push({ detector: check.name, status: 'error', error: e.message }); log(check.name, 'failed:', e.message); }
    }
    await setSetting('shield.security.lastSweep', new Date().toISOString());
    return { at: new Date().toISOString(), source: source || 'schedule', results };
  }

  return { ensureSchema, sweep, checkSshFailures, checkConfigFiles, checkListeningPorts, checkPrivilegedAccounts, checkOutbound, recordLogin, loginHistory, events, recordEvent };
}

module.exports = { createSecurity };
