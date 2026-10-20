// =====================================================================
// VNM Shield — Orchestrator (VNM Panel v3.0 security layer)
// ---------------------------------------------------------------------
// Wires the individual engines (lib/shield-*.js) into the panel:
//
//   RBAC
//     owner  = existing 'admin' role   - full Shield control
//     staff  = new optional 'staff'    - can VIEW dashboards, run
//              diagnostics, ack incidents; cannot change protection
//              settings, restore, update, or lift emergency mode
//     customer = existing 'user' role  - no Shield access at all
//     (Roles live in the existing users.role column - no schema
//      change; create a staff user from Users → Edit → role.)
//
//   ROUTES  /admin/shield (dashboard) + /api/shield/* (JSON API) +
//           /api/health (public, tiny - used by the watchdog)
//
//   SCHEDULERS (all settings-driven, failure-isolated)
//     integrity scan, security sweep, health snapshot, VM sweep,
//     resource snapshot, scheduled backups, weekly restore tests
//
//   BOOT    ensureSchema() creates all shield tables;
//           start() auto-establishes the integrity baseline on the
//           very first boot (and after a panel update changes files,
//           the owner re-baselines explicitly from the dashboard)
//
//   HOOKS   processError(kind, err) - called from app.js's global
//           handlers so uncaught errors reach the Error Teller too
// =====================================================================

'use strict';

const path = require('path');
const fs = require('fs');
const createNotifier = require('./lib/shield-notifier');
const { createIntegrity } = require('./lib/shield-integrity');
const { createSecurity } = require('./lib/shield-security');
const { createRecovery } = require('./lib/shield-recovery');
const { createBackupVault } = require('./lib/shield-backup');
const { createVanguard } = require('./lib/shield-vanguard');
const { createUpdater } = require('./lib/shield-updater');
const { createEmergency } = require('./lib/shield-emergency');
const { diagnose, redact } = require('./lib/shield-diagnoser');

module.exports = function createShield(ctx) {
  const {
    app, db, checkAuth, checkAdmin, auditLog, VM_DIR, vmProcesses, isPidQemu, dbPath, dataDir,
  } = ctx;
  const panelRoot = path.join(__dirname);

  const log = (...a) => { try { console.log('[Shield]', ...a); } catch (e) {} };
  const dbGet = (sql, params) => new Promise((resolve, reject) => db.get(sql, params, (e, r) => e ? reject(e) : resolve(r)));
  const dbAll = (sql, params) => new Promise((resolve, reject) => db.all(sql, params, (e, r) => e ? reject(e) : resolve(r || [])));
  const dbRun = (sql, params) => new Promise((resolve, reject) => db.run(sql, params, function (e) { e ? reject(e) : resolve(this); }));

  // ---------------- settings helpers ----------------
  async function getSetting(key) {
    try {
      const row = await dbGet(`SELECT setting_value FROM settings WHERE setting_key = ?`, [key]);
      return row ? row.setting_value : null;
    } catch (e) { return null; }
  }
  async function setSetting(key, value) {
    await dbRun(`INSERT INTO settings (setting_key, setting_value, updated_at) VALUES (?,?,CURRENT_TIMESTAMP)
      ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = CURRENT_TIMESTAMP`, [key, String(value)]);
  }

  // ---------------- engines ----------------
  const notifier = createNotifier({ db, getSetting, setSetting });
  const notify = (event) => notifier.notify(event);
  const integrity = createIntegrity({ db, getSetting, setSetting, panelRoot, dataDir });
  const security = createSecurity({ db, getSetting, setSetting, notify });
  const recovery = createRecovery({ db, getSetting, setSetting, notify, dataDir });
  const backupVault = createBackupVault({ db, getSetting, setSetting, notify, panelRoot, dataDir, dbPath });
  const vanguard = createVanguard({ db, getSetting, setSetting, notify, VM_DIR, vmProcesses, isPidQemu, dataDir });
  const updater = createUpdater({ db, getSetting, setSetting, notify, backupVault, panelRoot, dataDir });
  const emergency = createEmergency({ db, getSetting, setSetting, notify, dataDir });

  // ---------------- RBAC ----------------
  // owner = admin role; staff = new role; customers have no access.
  function requireOwner(req, res, next) {
    if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Authentication required' });
    if (req.session.role !== 'admin') {
      if (req.session.role === 'staff') return res.status(403).json({ error: 'Owner role required for this action (staff accounts are read-only for Shield)' });
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  }
  function requireStaff(req, res, next) {   // admin OR staff
    if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Authentication required' });
    if (req.session.role !== 'admin' && req.session.role !== 'staff') return res.status(403).json({ error: 'Access denied' });
    next();
  }

  // Destructive operations demand explicit confirmation in the body -
  // defense-in-depth against drive-by clicks and CSRF mishaps (CSRF
  // is already enforced globally, this is the second lock on the door).
  function needConfirm(field) {
    return (req, res, next) => {
      if (req.body && (req.body.confirm === true || req.body.confirm === 'yes' || req.body[field || 'confirm'] === true)) return next();
      res.status(400).json({ error: 'This operation is destructive and requires explicit confirmation', requiresConfirmation: true });
    };
  }

  const wrap = (fn) => (req, res) => {
    Promise.resolve(fn(req, res)).catch((e) => {
      const status = e.httpStatus || 500;
      if (status >= 500) console.error('[Shield:API]', req.method, req.path, e.message);
      if (!res.headersSent) res.status(status).json({ error: e.message || 'Shield API error' });
    });
  };

  // =====================================================================
  // PUBLIC: tiny health endpoint for the watchdog / load balancers
  // =====================================================================
  app.get('/api/health', wrap(async (req, res) => {
    const t0 = Date.now();
    let dbOk = false;
    try { await dbGet(`SELECT 1 AS ok`); dbOk = true; } catch (e) { /* db down */ }
    const emergencyOn = await emergency.active().catch(() => false);
    res.status(dbOk ? 200 : 503).json({
      status: dbOk ? 'ok' : 'degraded',
      db: dbOk ? 'ok' : 'error',
      emergency: emergencyOn ? 'active' : 'off',
      version: process.env.PANEL_VERSION || 'unknown',
      uptimeSec: Math.round(process.uptime()),
      ms: Date.now() - t0,
    });
  }));

  // =====================================================================
  // DASHBOARD (server-rendered) - owner + staff
  // =====================================================================
  app.get('/admin/shield', checkAuth, (req, res, next) => {
    if (req.session.role !== 'admin' && req.session.role !== 'staff') return res.redirect('/dashboard');
    next();
  }, wrap(async (req, res) => {
    // This route is registered EARLY (before the view-locals middleware
    // further down app.js), so every local the partials expect is passed
    // explicitly here - mirroring the defaults that middleware applies.
    res.render('admin/shield', {
      title: 'VNM Shield - Security & Health', currentPage: 'shield',
      user: { username: req.session.username, role: req.session.role },
      isOwner: req.session.role === 'admin',
      siteLogo: res.locals.siteLogo || process.env.DEFAULT_LOGO_URL || '/images/logo-new.svg',
      siteName: res.locals.siteName || process.env.PANEL_NAME || 'VNM',
      panelVersion: res.locals.panelVersion || process.env.PANEL_VERSION || 'V3.0',
    });
  }));

  // =====================================================================
  // OVERVIEW - everything the dashboard needs in one call
  // =====================================================================
  app.get('/api/shield/overview', checkAuth, requireStaff, wrap(async (req, res) => {
    const [integrityStatus, health, incidents, secEvents, backupStatus, recoveryHistory, resources, lastVmsweep, emergencyInfo] = await Promise.all([
      integrity.status(),
      recovery.runHealth().catch(() => null),
      notifier.listIncidents({ status: 'open', limit: 10 }),
      security.events(10),
      backupVault.status(),
      recovery.history(8),
      vanguard.resourceSnapshot().catch(() => null),
      getSetting('shield.vmguard.lastSweep'),
      emergency.info(),
    ]);
    const logins = await security.loginHistory(8, true).catch(() => []);
    res.json({
      integrity: integrityStatus,
      health,
      incidents: incidents.map(parseIncident),
      securityEvents: secEvents.map(parseSecEvent),
      backup: backupStatus,
      recoveryHistory,
      resources,
      vmGuard: lastVmsweep ? safeJson(lastVmsweep) : null,
      emergency: emergencyInfo,
      recentFailedLogins: logins.length,
      watchdog: watchdogStatus(),
    });
  }));

  // Independent watchdog liveness: reads the heartbeat file the
  // watchdog process writes on every loop (stale > 3 intervals = dead).
  function watchdogStatus() {
    try {
      const hb = JSON.parse(fs.readFileSync(path.join(dataDir, 'shield', 'watchdog-heartbeat.json'), 'utf8'));
      const ageSec = Math.round((Date.now() - new Date(hb.at).getTime()) / 1000);
      return { running: ageSec < 180, state: hb.state || 'unknown', lastBeat: hb.at, ageSec, url: hb.url };
    } catch (e) {
      return { running: false, state: 'not-installed', note: 'Install the watchdog: sudo cp watchdog/vnm-watchdog.service /etc/systemd/system/ && systemctl enable --now vnm-watchdog' };
    }
  }

  function parseIncident(r) {
    return { ...r, confirmed_causes: safeJson(r.confirmed_causes), possible_causes: safeJson(r.possible_causes), technical: safeJson(r.technical) };
  }
  function parseSecEvent(r) { return { ...r, detail: safeJson(r.detail) }; }
  function safeJson(s) { try { return JSON.parse(s); } catch (e) { return s; } }

  // =====================================================================
  // INTEGRITY (anti-tamper)
  // =====================================================================
  app.get('/api/shield/integrity', checkAuth, requireStaff, wrap(async (req, res) => {
    res.json({ status: await integrity.status(), history: await integrity.history(30) });
  }));

  app.post('/api/shield/integrity/baseline', checkAuth, requireOwner, wrap(async (req, res) => {
    const r = await integrity.establishBaseline(req.body && req.body.reason);
    if (auditLog) auditLog.log({ userId: req.session.userId, username: req.session.username, action: 'shield.baseline', targetType: 'shield', result: 'success', details: r.files + ' files' });
    res.json(r);
  }));

  app.post('/api/shield/integrity/scan', checkAuth, requireStaff, wrap(async (req, res) => {
    const r = await integrity.scan('manual');
    if (r.changes && r.changes.length) {
      await notify({
        severity: 'critical',
        title: `File integrity: ${r.changes.length} unauthorized change(s) detected`,
        body: r.changes.slice(0, 8).map((c) => `${c.type.toUpperCase()}: ${c.path}`).join('\n') +
          (r.restored && r.restored.length ? `\n\nEnforce mode AUTO-RESTORED: ${r.restored.join(', ')}` : '\n\nMonitor mode: no files were changed automatically.') +
          '\n\nIf you made these changes yourself, re-baseline afterwards.',
        diag: {
          fingerprint: 'integrity:' + r.changes.map((c) => c.path).sort().join(',').slice(0, 200),
          category: 'security', component: 'panel/integrity', severity: 'critical',
          title: 'Panel file tampering detected',
          explanation: 'One or more security-critical panel files differ from the trusted SHA-256 baseline: modified, added, removed, or permission-changed.',
          confirmed_causes: ['The listed files are not in their baselined state.'],
          possible_causes: ['Legitimate update or manual edit that was not re-baselined', 'Interrupted update left partial files', 'Unauthorized modification by someone with host access'],
          suggested_fix: 'Compare each file (Shield → Integrity shows old/new hashes). Unexpected: restore from the trusted vault, then investigate HOW the change happened. Expected: re-baseline to accept the new state.',
          raw: { message: r.changes.map((c) => c.type + ':' + c.path).join(', ').slice(0, 300) },
        },
      });
    }
    res.json(r);
  }));

  app.post('/api/shield/integrity/restore', checkAuth, requireOwner, needConfirm(), wrap(async (req, res) => {
    const paths = (req.body && req.body.paths) || [];
    const results = [];
    for (const p of paths) {
      try { results.push(await integrity.restoreFile(p, 'manual-owner')); }
      catch (e) { results.push({ restored: false, path: p, error: e.message }); }
    }
    if (auditLog) auditLog.log({ userId: req.session.userId, username: req.session.username, action: 'shield.integrity.restore', targetType: 'shield', result: 'success', details: paths.join(', ') });
    res.json({ results });
  }));

  app.post('/api/shield/integrity/mode', checkAuth, requireOwner, wrap(async (req, res) => {
    const mode = req.body && req.body.mode;
    if (!['off', 'monitor', 'enforce'].includes(mode)) return res.status(400).json({ error: 'mode must be off | monitor | enforce' });
    await setSetting('shield.integrity.mode', mode);
    res.json({ ok: true, mode });
  }));

  app.post('/api/shield/integrity/maintenance', checkAuth, requireOwner, wrap(async (req, res) => {
    const minutes = parseInt((req.body && req.body.minutes) || '0', 10);
    const r = await integrity.setMaintenance(minutes, req.session.username);
    res.json(r);
  }));

  app.post('/api/shield/integrity/schedule', checkAuth, requireOwner, wrap(async (req, res) => {
    const m = parseInt((req.body && req.body.minutes) || '15', 10);
    await setSetting('shield.integrity.scheduleMinutes', String(Math.max(5, Math.min(1440, m))));
    res.json({ ok: true, minutes: m });
  }));

  // =====================================================================
  // INCIDENTS
  // =====================================================================
  app.get('/api/shield/incidents', checkAuth, requireStaff, wrap(async (req, res) => {
    res.json({ incidents: (await notifier.listIncidents({
      status: req.query.status, severity: req.query.severity, q: req.query.q, limit: req.query.limit,
    })).map(parseIncident) });
  }));

  app.post('/api/shield/incidents/:id/ack', checkAuth, requireStaff, wrap(async (req, res) => {
    const r = await notifier.updateIncidentStatus(parseInt(req.params.id, 10), 'acknowledged', req.session.username);
    res.json({ ok: true, incident: parseIncident(r) });
  }));

  app.post('/api/shield/incidents/:id/resolve', checkAuth, requireStaff, wrap(async (req, res) => {
    const r = await notifier.updateIncidentStatus(parseInt(req.params.id, 10), 'resolved', req.session.username);
    res.json({ ok: true, incident: parseIncident(r) });
  }));

  app.get('/api/shield/incidents/export', checkAuth, requireOwner, wrap(async (req, res) => {
    const rows = await notifier.exportIncidents();
    res.setHeader('Content-Disposition', 'attachment; filename="vnm-incident-report-' + Date.now() + '.json"');
    res.json({ generated: new Date().toISOString(), panel: process.env.PANEL_VERSION || 'unknown', incidents: rows });
  }));

  // =====================================================================
  // SECURITY (IDS + login history)
  // =====================================================================
  app.post('/api/shield/security/sweep', checkAuth, requireStaff, wrap(async (req, res) => {
    res.json(await security.sweep('manual'));
  }));

  app.get('/api/shield/security/events', checkAuth, requireStaff, wrap(async (req, res) => {
    res.json({ events: (await security.events(parseInt(req.query.limit || 50, 10))).map(parseSecEvent) });
  }));

  app.get('/api/shield/security/logins', checkAuth, requireOwner, wrap(async (req, res) => {
    res.json({ logins: await security.loginHistory(parseInt(req.query.limit || 100, 10), req.query.failures === '1') });
  }));

  // =====================================================================
  // RECOVERY / DIAGNOSTICS
  // =====================================================================
  app.get('/api/shield/recovery/health', checkAuth, requireStaff, wrap(async (req, res) => {
    res.json(await recovery.runHealth());
  }));

  app.post('/api/shield/recovery/restart', checkAuth, requireOwner, wrap(async (req, res) => {
    const target = req.body && req.body.target;
    const r = await recovery.restartService(target, (req.body && req.body.reason) || 'manual (dashboard)', req.session.username);
    if (auditLog) auditLog.log({ userId: req.session.userId, username: req.session.username, action: 'shield.recovery.restart', targetType: target, result: r.ok ? 'success' : 'failure', details: r.outcome || r.error || '' });
    res.status(r.ok ? 200 : (r.blocked ? 429 : 500)).json(r);
  }));

  app.post('/api/shield/recovery/breaker-reset', checkAuth, requireOwner, wrap(async (req, res) => {
    res.json(await recovery.resetBreaker(req.body && req.body.target, req.session.username));
  }));

  app.get('/api/shield/recovery/history', checkAuth, requireStaff, wrap(async (req, res) => {
    res.json({ history: await recovery.history(parseInt(req.query.limit || 50, 10)) });
  }));

  app.get('/api/shield/recovery/detail/:id', checkAuth, requireOwner, wrap(async (req, res) => {
    const r = await recovery.recoveryDetail(parseInt(req.params.id, 10));
    if (!r) return res.status(404).json({ error: 'not found' });
    res.json(r);
  }));

  // Manual "Run full diagnostics": everything, at once, read-only
  app.post('/api/shield/diagnostics', checkAuth, requireStaff, wrap(async (req, res) => {
    const [health, integrityScan, sec, vmSweep, resources] = await Promise.all([
      recovery.runHealth(),
      integrity.scan('manual-diagnostics'),
      security.sweep('manual-diagnostics').catch(() => null),
      vanguard.vmSweep('manual-diagnostics'),
      vanguard.resourceSnapshot(),
    ]);
    if (auditLog) auditLog.log({ userId: req.session.userId, username: req.session.username, action: 'shield.diagnostics', targetType: 'shield', result: 'success' });
    res.json({ at: new Date().toISOString(), health, integrity: integrityScan, security: sec, vmGuardian: vmSweep, resources });
  }));

  // =====================================================================
  // BACKUP VAULT
  // =====================================================================
  app.get('/api/shield/backup', checkAuth, requireStaff, wrap(async (req, res) => {
    res.json({ status: await backupVault.status(), backups: await backupVault.listBackups(30) });
  }));

  app.post('/api/shield/backup/create', checkAuth, requireOwner, wrap(async (req, res) => {
    const r = await backupVault.createBackup('manual', (req.body && req.body.reason) || 'manual (dashboard)');
    res.status(r.ok ? 200 : 500).json(r);
  }));

  app.post('/api/shield/backup/verify', checkAuth, requireOwner, wrap(async (req, res) => {
    const f = req.body && req.body.file;
    if (!f) return res.status(400).json({ error: 'file required' });
    res.json(await backupVault.verifyBackup(f));
  }));

  app.post('/api/shield/backup/restore-test', checkAuth, requireOwner, wrap(async (req, res) => {
    res.json(await backupVault.restoreTest());
  }));

  app.post('/api/shield/backup/restore', checkAuth, requireOwner, needConfirm(), wrap(async (req, res) => {
    const f = req.body && req.body.file;
    if (!f) return res.status(400).json({ error: 'file required' });
    const r = await backupVault.restoreBackup(f, { skipDb: req.body && req.body.skipDb });
    if (auditLog) auditLog.log({ userId: req.session.userId, username: req.session.username, action: 'shield.backup.restore', targetType: f, result: r.ok ? 'success' : 'failure' });
    res.status(r.ok ? 200 : 500).json(r);
  }));

  // =====================================================================
  // VM GUARDIAN + RESOURCES
  // =====================================================================
  app.get('/api/shield/vm/:id', checkAuth, requireStaff, wrap(async (req, res) => {
    const vm = await dbGet(`SELECT * FROM vms WHERE vm_id = ?`, [parseInt(req.params.id, 10)]);
    if (!vm) return res.status(404).json({ error: 'VM not found' });
    res.json(await vanguard.vmDiagnose(vm));
  }));

  app.post('/api/shield/vmguard/sweep', checkAuth, requireStaff, wrap(async (req, res) => {
    res.json(await vanguard.vmSweep('manual'));
  }));

  app.get('/api/shield/resources', checkAuth, requireStaff, wrap(async (req, res) => {
    res.json(await vanguard.resourceSnapshot());
  }));

  app.get('/api/shield/cleanup/candidates', checkAuth, requireOwner, wrap(async (req, res) => {
    res.json({ candidates: await vanguard.cleanupCandidates() });
  }));

  app.post('/api/shield/cleanup/apply', checkAuth, requireOwner, needConfirm(), wrap(async (req, res) => {
    const cats = (req.body && req.body.categories) || [];
    if (!Array.isArray(cats) || !cats.length) return res.status(400).json({ error: 'categories[] required' });
    const r = await vanguard.applyCleanup(cats);
    if (auditLog) auditLog.log({ userId: req.session.userId, username: req.session.username, action: 'shield.cleanup', targetType: 'shield', result: 'success', details: cats.join(',') });
    res.json(r);
  }));

  // =====================================================================
  // UPDATER
  // =====================================================================
  app.get('/api/shield/update/preflight', checkAuth, requireOwner, wrap(async (req, res) => {
    res.json(await updater.preflight());
  }));

  app.post('/api/shield/update/verify', checkAuth, requireOwner, wrap(async (req, res) => {
    const { zipPath, manifestPath } = req.body || {};
    if (!zipPath || !manifestPath) return res.status(400).json({ error: 'zipPath and manifestPath required (files uploaded to the server, e.g. via SFTP)' });
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    res.json(await updater.verifyRelease(manifest, zipPath));
  }));

  app.post('/api/shield/update/apply', checkAuth, requireOwner, needConfirm(), wrap(async (req, res) => {
    const { zipPath, manifestPath } = req.body || {};
    if (!zipPath || !manifestPath) return res.status(400).json({ error: 'zipPath and manifestPath required' });
    const r = await updater.applyUpdate(zipPath, manifestPath, req.session.username);
    if (auditLog) auditLog.log({ userId: req.session.userId, username: req.session.username, action: 'shield.update.apply', targetType: 'shield', result: r.ok ? 'success' : 'failure', details: r.version || r.error || '' });
    res.status(r.ok ? 200 : 500).json(r);
  }));

  app.post('/api/shield/update/rollback', checkAuth, requireOwner, needConfirm(), wrap(async (req, res) => {
    const r = await updater.rollbackLastUpdate(req.session.username);
    if (auditLog) auditLog.log({ userId: req.session.userId, username: req.session.username, action: 'shield.update.rollback', targetType: 'shield', result: r.ok ? 'success' : 'failure' });
    res.status(r.ok ? 200 : 500).json(r);
  }));

  app.get('/api/shield/update/history', checkAuth, requireStaff, wrap(async (req, res) => {
    res.json({ history: await updater.history(20) });
  }));

  // =====================================================================
  // EMERGENCY MODE
  // =====================================================================
  app.get('/api/shield/emergency', checkAuth, requireStaff, wrap(async (req, res) => {
    res.json(await emergency.info());
  }));

  app.post('/api/shield/emergency/on', checkAuth, requireOwner, wrap(async (req, res) => {
    const r = await emergency.activate((req.body && req.body.reason) || 'manual', req.session.username);
    if (auditLog) auditLog.log({ userId: req.session.userId, username: req.session.username, action: 'shield.emergency.on', targetType: 'shield', result: 'success', details: req.body && req.body.reason });
    res.json(r);
  }));

  app.post('/api/shield/emergency/off', checkAuth, requireOwner, wrap(async (req, res) => {
    const r = await emergency.deactivate(req.body && req.body.code, req.session.username);
    if (auditLog) auditLog.log({ userId: req.session.userId, username: req.session.username, action: 'shield.emergency.off', targetType: 'shield', result: r.ok ? 'success' : 'failure' });
    res.status(r.ok ? 200 : 403).json(r);
  }));

  app.post('/api/shield/emergency/reauth', checkAuth, wrap(async (req, res) => {
    // Password re-verification for sensitive actions during lockdown
    const bcrypt = require('bcryptjs');
    const row = await dbGet(`SELECT password FROM users WHERE id = ? AND is_active = 1`, [req.session.userId]);
    if (!row) return res.status(401).json({ error: 'Authentication required' });
    if (!req.body || !bcrypt.compareSync(String(req.body.password || ''), row.password)) {
      return res.status(401).json({ error: 'Incorrect password' });
    }
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Owner role required' });
    res.json(emergency.stampReauth(req.session));
  }));

  // =====================================================================
  // NOTIFICATIONS / SETTINGS
  // =====================================================================
  const SETTING_DEFS = [
    // notifications
    { key: 'shield.notify.minSeverity', label: 'Minimum severity to notify', type: 'select', options: ['info', 'low', 'medium', 'high', 'critical'], def: 'low' },
    { key: 'shield.notify.discord.webhook', label: 'Discord webhook URL', type: 'password', def: '' },
    { key: 'shield.notify.telegram.token', label: 'Telegram bot token', type: 'password', def: '' },
    { key: 'shield.notify.telegram.chatId', label: 'Telegram chat ID', type: 'text', def: '' },
    { key: 'shield.notify.webhook.url', label: 'Generic webhook URL', type: 'password', def: '' },
    { key: 'shield.notify.email.host', label: 'Email (SMTP) host', type: 'text', def: '' },
    { key: 'shield.notify.email.port', label: 'SMTP port (587 STARTTLS / 465 TLS)', type: 'text', def: '587' },
    { key: 'shield.notify.email.security', label: 'SMTP security', type: 'select', options: ['starttls', 'tls', 'none'], def: 'starttls' },
    { key: 'shield.notify.email.user', label: 'SMTP username', type: 'text', def: '' },
    { key: 'shield.notify.email.pass', label: 'SMTP password', type: 'password', def: '' },
    { key: 'shield.notify.email.from', label: 'Email from address', type: 'text', def: '' },
    { key: 'shield.notify.email.to', label: 'Email to address', type: 'text', def: '' },
    // integrity
    { key: 'shield.integrity.mode', label: 'Integrity protection mode', type: 'select', options: ['off', 'monitor', 'enforce'], def: 'monitor' },
    { key: 'shield.integrity.scheduleMinutes', label: 'Integrity scan interval (minutes)', type: 'number', def: '15' },
    // security
    { key: 'shield.security.sshFailThreshold', label: 'SSH failure alert threshold', type: 'number', def: '10' },
    { key: 'shield.security.sshWindowMinutes', label: 'SSH failure window (minutes)', type: 'number', def: '10' },
    // backup
    { key: 'shield.backup.scheduleHours', label: 'Backup interval (hours, 0=off)', type: 'number', def: '24' },
    { key: 'shield.backup.keep', label: 'Backups to keep', type: 'number', def: '10' },
    { key: 'shield.backup.remote.target', label: 'Remote copy target (rsync/scp)', type: 'text', def: '' },
    { key: 'shield.backup.remote.key', label: 'Remote SSH key path', type: 'text', def: '' },
    // recovery
    { key: 'shield.recovery.maxAttempts', label: 'Recovery attempts per window', type: 'number', def: '3' },
    { key: 'shield.recovery.cooldownMinutes', label: 'Recovery cooldown (minutes)', type: 'number', def: '5' },
    // update trust
    { key: 'shield.update.publicKey', label: 'Release signing public key (PEM)', type: 'textarea', def: '' },
    { key: 'shield.update.allowUnsigned', label: 'Allow unsigned releases (NOT recommended)', type: 'select', options: ['0', '1'], def: '0' },
  ];

  app.get('/api/shield/settings', checkAuth, requireOwner, wrap(async (req, res) => {
    const out = [];
    for (const def of SETTING_DEFS) {
      out.push({ ...def, value: await getSetting(def.key), isDefault: (await getSetting(def.key)) === null });
    }
    res.json({ settings: out });
  }));

  app.post('/api/shield/settings', checkAuth, requireOwner, wrap(async (req, res) => {
    const allowed = new Map(SETTING_DEFS.map((d) => [d.key, d]));
    let changed = 0;
    const rejected = [];
    for (const [k, v] of Object.entries(req.body || {})) {
      const def = allowed.get(k);
      if (!def) continue;   // unknown keys are silently ignored
      // enum validation: select fields only ever accept their documented options
      if (def.type === 'select' && !def.options.includes(String(v))) {
        rejected.push(k);
        continue;
      }
      await setSetting(k, v === null ? '' : String(v));
      changed++;
    }
    if (auditLog) auditLog.log({ userId: req.session.userId, username: req.session.username, action: 'shield.settings', targetType: 'shield', result: 'success', details: changed + ' keys' });
    res.json({ ok: true, changed, ...(rejected.length ? { rejected } : {}) });
  }));

  app.post('/api/shield/notify/test', checkAuth, requireOwner, wrap(async (req, res) => {
    const channel = req.body && req.body.channel;
    if (!['discord', 'telegram', 'webhook', 'email'].includes(channel)) return res.status(400).json({ error: 'channel must be discord|telegram|webhook|email' });
    res.json(await notifier.sendTest(channel));
  }));

  // =====================================================================
  // PROCESS-ERROR HOOK (called from app.js global handlers)
  // =====================================================================
  const processErrorCounts = new Map();
  async function processError(kind, err) {
    try {
      const diag = diagnose(err, { component: 'panel/process' });
      // hard throttle: same fingerprint max 1 notification / 10 min
      const last = processErrorCounts.get(diag.fingerprint) || 0;
      processErrorCounts.set(diag.fingerprint, Date.now());
      if (Date.now() - last < 10 * 60 * 1000) return;
      await notify({ severity: diag.severity, title: `[${kind}] ` + diag.title, body: diag.explanation + '\n\nSuggested fix: ' + diag.suggested_fix, diag });
    } catch (e) { log('processError hook failed:', e.message); }
  }

  // =====================================================================
  // BOOT / SCHEDULERS
  // =====================================================================
  let timers = [];
  function every(ms, name, fn) {
    if (!ms || ms < 60000) return;
    const t = setInterval(() => {
      Promise.resolve(fn()).catch((e) => log('scheduler', name, 'failed:', e.message));
    }, ms);
    t.unref();
    timers.push(t);
  }

  async function ensureSchema() {
    await notifier.ensureSchema();
    await integrity.ensureSchema();
    await security.ensureSchema();
    await recovery.ensureSchema();
    await backupVault.ensureSchema();
    await updater.ensureSchema();
    // emergency needs no table (settings + file flag)
    // login-history table lives in security module
  }

  async function start() {
    // emergency gate cache warm-up (file flag + DB mirror)
    try { emergency.startCacheRefresh(); } catch (e) { log('emergency cache refresh failed:', e.message); }

    // first boot: establish integrity baseline if none exists
    try {
      const info = await integrity.baselineInfo();
      if (!info.files) {
        const r = await integrity.establishBaseline('first-boot');
        log(`initial integrity baseline established: ${r.files} files`);
      }
    } catch (e) { log('initial baseline failed:', e.message); }

    const ivMins = Math.max(5, parseInt((await getSetting('shield.integrity.scheduleMinutes')) || '15', 10));
    every(ivMins * 60 * 1000, 'integrity', () => integrity.scan('schedule'));
    every(10 * 60 * 1000, 'security', () => security.sweep('schedule'));
    every(5 * 60 * 1000, 'health', () => recovery.runHealth());
    every(15 * 60 * 1000, 'vmguard', () => vanguard.vmSweep('schedule'));
    every(15 * 60 * 1000, 'resources', () => vanguard.resourceSnapshot());

    const backupHours = parseFloat((await getSetting('shield.backup.scheduleHours')) || '24');
    if (backupHours > 0) every(Math.round(backupHours * 3600 * 1000), 'backup', () => backupVault.createBackup('scheduled'));
    // weekly restore test: 7 days
    every(7 * 24 * 3600 * 1000, 'restore-test', () => backupVault.restoreTest());

    log('started (integrity scan every ' + ivMins + 'm)');
  }

  function stop() { timers.forEach((t) => clearInterval(t)); timers = []; }

  return {
    ensureSchema, start, stop, processError, notify,
    integrity, security, recovery, backupVault, vanguard, updater, emergency, notifier,
    gate: (req, session) => emergency.gateRequest(req, session),
    recordLogin: (entry) => security.recordLogin(entry).catch(() => {}),
  };
};
