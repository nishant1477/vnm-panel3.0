// =====================================================================
// VNM Shield — Emergency Shield Mode
// ---------------------------------------------------------------------
// Owner-controlled incident lockdown. When active:
//   - every web session is revoked (all users, including admins,
//     must log in again)
//   - risky administrative operations are BLOCKED at the API layer:
//     VM delete, user create/delete/edit, settings changes, node
//     delete, backup restore, panel update, cleanup execution
//   - the owner can still log in, VIEW everything, and re-authenticate
//     (re-enter password) to perform a confirmed emergency action if
//     truly needed
//   - evidence is preserved: a snapshot of open incidents + security
//     events + recovery log is written to an evidence directory
//   - a one-time recovery code is generated and stored root-only
//     (0600) so the panel can be unlocked from the CLI even if the
//     web interface is unreachable:
//         sudo scripts/vnmctl emergency off --code <code>
//   - the owner is notified immediately on every activation
//
// Emergency mode NEVER locks out OS-level access (SSH/console) - by
// design there is always a way in for someone with host access.
// =====================================================================

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// (method, regexp) pairs for operations blocked during lockdown.
// Read-only access (GET) is never blocked.
const BLOCKED_OPERATIONS = [
  ['POST', /^\/api\/vms\/\d+\/delete/],
  ['POST', /^\/api\/vms\/delete/],
  ['POST', /^\/api\/users(\/|$)/],
  ['DELETE', /^\/api\/users(\/|$)/],
  ['POST', /^\/api\/settings(\/|$)/],
  ['POST', /^\/api\/nodes\/\d+\/(delete|remove)/],
  ['POST', /^\/api\/shield\/backup\/restore/],
  ['POST', /^\/api\/shield\/update\/apply/],
  ['POST', /^\/api\/shield\/cleanup\/apply/],
  ['POST', /^\/api\/shield\/restore/],
  ['POST', /^\/api\/vms(\/|$)/],          // VM create
  ['POST', /^\/api\/nodes(\/|$)/],        // node add/rotate
];

function createEmergency(ctx) {
  const db = ctx.db;
  const getSetting = ctx.getSetting;
  const setSetting = ctx.setSetting;
  const notify = ctx.notify;
  const dataDir = ctx.dataDir;
  const log = (...a) => { try { console.log('[Shield:Emergency]', ...a); } catch (e) {} };

  const stateDir = path.join(dataDir, 'shield');
  const stateFile = path.join(stateDir, 'emergency.lock');
  const recoveryCodeFile = path.join(stateDir, 'emergency-recovery.txt');
  const evidenceDir = path.join(stateDir, 'evidence');
  const REAUTH_WINDOW_MS = 10 * 60 * 1000;

  const dbAll = (sql, params) => new Promise((resolve, reject) => db.all(sql, params, (e, r) => e ? reject(e) : resolve(r || [])));
  const dbRun = (sql, params) => new Promise((resolve, reject) => db.run(sql, params, function (e) { e ? reject(e) : resolve(this); }));

  // ---------------- synchronous active state (for the request gate) ----------------
  // The Express gate middleware is synchronous, but the authoritative
  // state lives in a file + the DB. The FILE flag is checkable sync (it
  // is the primary source once emergency mode exists); the DB setting
  // is mirrored into a cache that activate()/deactivate() update
  // synchronously and a background refresh keeps warm. If the file is
  // absent AND the cache says off, the gate passes everything.
  let cachedDbActive = false;
  let cacheRefreshTimer = null;

  function syncActive() {
    try { if (fs.existsSync(stateFile)) return true; } catch (e) { /* unreadable */ }
    return cachedDbActive;
  }

  async function refreshDbActive() {
    try { cachedDbActive = (await getSetting('shield.emergency.active')) === '1'; }
    catch (e) { /* keep last value */ }
  }

  function startCacheRefresh() {
    if (cacheRefreshTimer) return;
    cacheRefreshTimer = setInterval(() => { refreshDbActive(); }, 15000);
    if (cacheRefreshTimer.unref) cacheRefreshTimer.unref();
    refreshDbActive();
  }

  function isActive() {
    // File flag first (works even if the DB is unreachable), DB as backup
    try {
      if (fs.existsSync(stateFile)) {
        const raw = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
        if (raw && raw.active) return true;
      }
    } catch (e) { /* corrupt file -> fall through to DB */ }
    return null;  // resolved asynchronously below
  }

  async function active() {
    try {
      if (fs.existsSync(stateFile)) {
        const raw = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
        if (raw && raw.active) return true;
      }
    } catch (e) { /* fall through */ }
    return (await getSetting('shield.emergency.active')) === '1';
  }

  async function info() {
    const on = await active();
    return {
      active: on,
      since: on ? await getSetting('shield.emergency.since') : null,
      reason: on ? await getSetting('shield.emergency.reason') : null,
      blockedOperations: BLOCKED_OPERATIONS.map(([m, re]) => `${m} ${re}`),
      note: 'Read-only access stays available. Owners re-authenticate to perform confirmed emergency actions.',
    };
  }

  // ---------------- activate ----------------
  async function activate(reason, by) {
    if (await active()) return { ok: true, already: true };
    const code = crypto.randomBytes(16).toString('hex');
    fs.mkdirSync(stateDir, { recursive: true });

    // 1. state file + recovery code (root-only readable)
    fs.writeFileSync(stateFile, JSON.stringify({ active: true, since: new Date().toISOString(), reason: reason || 'manual', by: by || 'owner' }, null, 2), { mode: 0o644 });
    fs.writeFileSync(recoveryCodeFile, code + '\n', { mode: 0o600 });
    cachedDbActive = true;   // gate must block IMMEDIATELY, not after the DB write
    await setSetting('shield.emergency.active', '1');
    await setSetting('shield.emergency.since', new Date().toISOString());
    await setSetting('shield.emergency.reason', String(reason || 'manual').slice(0, 200));

    // 2. revoke every web session (fresh authentication required)
    let revoked = 0;
    try {
      const r = await dbRun(`DELETE FROM sessions`);
      revoked = r.changes || 0;
    } catch (e) { log('session revocation failed:', e.message); }

    // 3. preserve evidence
    let evidencePath = null;
    try {
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      evidencePath = path.join(evidenceDir, stamp);
      fs.mkdirSync(evidencePath, { recursive: true });
      const dump = async (name, rows) => fs.writeFileSync(path.join(evidencePath, name + '.json'), JSON.stringify(rows, null, 2));
      await dump('open-incidents', await dbAll(`SELECT * FROM shield_incidents WHERE status != 'resolved' ORDER BY id DESC LIMIT 200`));
      await dump('security-events', await dbAll(`SELECT * FROM shield_security_events ORDER BY id DESC LIMIT 200`));
      await dump('recovery-log', await dbAll(`SELECT id, created_at, target, action, reason, outcome, actor FROM shield_recovery_log ORDER BY id DESC LIMIT 100`));
      await dump('integrity-events', await dbAll(`SELECT * FROM shield_events ORDER BY id DESC LIMIT 200`));
      fs.writeFileSync(path.join(evidencePath, 'README.txt'),
        `Evidence snapshot taken at emergency-mode activation (${new Date().toISOString()}).\nReason: ${reason || 'manual'}\nActivated by: ${by || 'owner'}\nThese files are frozen copies for incident response; the live tables keep updating.\n`);
    } catch (e) { log('evidence snapshot incomplete:', e.message); }

    // 4. notify the owner
    await notify({
      severity: 'critical',
      title: 'EMERGENCY SHIELD MODE ACTIVATED',
      body: `Emergency lockdown is ACTIVE.\nReason: ${reason || 'manual'}\nAll ${revoked} web session(s) were revoked; risky admin operations are blocked until this is lifted.\nUnlock from the panel (Shield → Emergency) or from the host:\n  sudo scripts/vnmctl emergency off --code <code>\nThe recovery code is in ${recoveryCodeFile} (root-readable only).\nEvidence snapshot: ${evidencePath || 'n/a'}`,
      diag: {
        fingerprint: 'emergency-activated', category: 'security', component: 'panel/emergency', severity: 'critical',
        title: 'Emergency Shield Mode activated',
        explanation: 'The owner activated the incident lockdown. All web sessions were revoked and destructive admin operations are blocked until the mode is lifted.',
        confirmed_causes: ['Owner-initiated lockdown.'],
        possible_causes: ['Active security incident', 'Suspected compromise', 'Precaution during investigation'],
        suggested_fix: 'Investigate using the preserved evidence, then lift the lockdown from the panel or via the CLI recovery code.',
        raw: { message: 'activated' },
      },
    });

    return { ok: true, active: true, sessionsRevoked: revoked, recoveryCodeFile, evidencePath };
  }

  // ---------------- deactivate ----------------
  async function deactivate(code, by) {
    const on = await active();
    if (!on) return { ok: true, already: false, active: false };
    if (code) {
      let expected = null;
      try { expected = fs.readFileSync(recoveryCodeFile, 'utf8').trim(); } catch (e) { /* missing */ }
      if (expected && code !== expected) {
        return { ok: false, error: 'Invalid recovery code' };
      }
    }
    try { fs.unlinkSync(stateFile); } catch (e) { /* already gone */ }
    try { fs.unlinkSync(recoveryCodeFile); } catch (e) { /* already gone */ }
    cachedDbActive = false;   // gate must unblock IMMEDIATELY
    await setSetting('shield.emergency.active', '0');
    await setSetting('shield.emergency.since', '');
    await setSetting('shield.emergency.reason', '');
    await notify({
      severity: 'medium',
      title: 'Emergency Shield Mode LIFTED',
      body: `Lockdown was lifted by ${by || 'owner'}. Normal operations resumed. Evidence snapshots remain on disk for review.`,
    });
    return { ok: true, active: false };
  }

  // ---------------- request gating ----------------
  // Used by the app-level middleware. Returns { blocked, reason } for
  // a request; never blocks GETs, login/logout, or the emergency
  // endpoints themselves. When emergency mode is NOT active nothing is
  // blocked at all (this check is FIRST - a misconfigured blocklist can
  // never take the panel hostage).
  function gateRequest(req, session) {
    if (!syncActive()) return { blocked: false };
    const m = req.method;
    if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return { blocked: false };
    const p = req.path || '';
    // always-available endpoints
    if (/^\/(api\/)?login/.test(p) || /^\/api\/logout/.test(p) || /^\/api\/shield\/emergency/.test(p) || p.startsWith('/agent-connect')) {
      return { blocked: false };
    }
    for (const [method, re] of BLOCKED_OPERATIONS) {
      if (m === method && re.test(p)) {
        // owner with fresh re-auth may pass (flag set by /api/shield/emergency/reauth)
        const reauthAt = session && session.emergencyReauthAt;
        if (session && session.role === 'admin' && reauthAt && (Date.now() - reauthAt) < REAUTH_WINDOW_MS) {
          return { blocked: false, via: 'reauth' };
        }
        return {
          blocked: true,
          reason: 'Emergency Shield Mode is active: this operation is temporarily blocked. An owner can re-authenticate via Shield → Emergency to perform it.',
        };
      }
    }
    return { blocked: false };
  }

  // Re-authentication: caller MUST verify the password BEFORE calling
  // this (the route layer does bcrypt.compare against the DB).
  function stampReauth(session) {
    session.emergencyReauthAt = Date.now();
    return { ok: true, validForMinutes: REAUTH_WINDOW_MS / 60000 };
  }

  function reauthValid(session) {
    return !!(session && session.role === 'admin' && session.emergencyReauthAt && (Date.now() - session.emergencyReauthAt) < REAUTH_WINDOW_MS);
  }

  return { active, info, activate, deactivate, gateRequest, stampReauth, reauthValid, startCacheRefresh, BLOCKED_OPERATIONS };
}

module.exports = { createEmergency };
