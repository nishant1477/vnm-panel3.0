// =====================================================================
// VNM — Platform Layer (the "complete virtualization platform" upgrade)
// ---------------------------------------------------------------------
// Everything the roadmap called for beyond core VM CRUD, mounted as one
// Express router early in app.js (so its refined routes win over any
// legacy handler):
//
//   Snapshots & Backups   real qemu-img snapshot/convert operations for
//                         local AND remote-node VMs, integrity checks,
//                         retention, recovery-test restores
//   Automation            task engine API: jobs with progress, retries,
//                         cancellation + cron-lite schedules
//   Monitoring & Alerts   live/history metrics, alert rules, events,
//                         Discord webhook notifications
//   Multi-node            maintenance mode, drain preview, placement
//                         recommendations, capacity dashboard, live
//                         node-to-node VM migration
//   Security              API keys with scoped permissions, audit log
//                         viewer, per-VM firewall rule manager
//   VM power features     clone, bulk actions, tags / notes / groups
//   Networking            IP allocation manager with conflict detection,
//                         fleet-wide port-forward overview
//   Storage               pool registry + live usage across nodes
//   UX                    global search API backing the command palette
// =====================================================================

'use strict';

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const premium = require('./premium');

module.exports = function createPlatform(ctx) {
  const {
    app, db, checkAuth, checkAdmin, nodeManager, auditLog, logVMAction,
    VM_DIR, ISO_DIR, CLOUDVM_DIR, TEMPLATES_DIR, execPromise, ops,
  } = ctx;

  const router = express.Router();
  const dbGet = (sql, params) => new Promise((resolve, reject) => db.get(sql, params, (e, r) => e ? reject(e) : resolve(r)));
  const dbAll = (sql, params) => new Promise((resolve, reject) => db.all(sql, params, (e, r) => e ? reject(e) : resolve(r || [])));
  const dbRun = (sql, params) => new Promise((resolve, reject) => db.run(sql, params, function (e) { e ? reject(e) : resolve(this); }));
  const httpErr = (code, message, extra) => { const e = new Error(message); e.httpStatus = code; Object.assign(e, extra || {}); return e; };

  // Async handler wrapper: maps thrown httpErr to status codes.
  const ah = (fn) => (req, res) => {
    Promise.resolve(fn(req, res)).catch((e) => {
      const status = e.httpStatus || (e.code === 'NODE_OFFLINE' ? 409 : 500);
      if (status >= 500) console.error('[Platform]', req.method, req.path, e.message);
      res.status(status).json({ success: false, error: e.code || 'ERROR', message: e.message, ...(e.premium_required ? { premium_required: e.premium_required, feature: e.feature || '' } : {}) });
    });
  };

  const isAdmin = (req) => req.session.role === 'admin';

  // Premium tier gate — throws the 402 the frontend license modal listens for.
  function needPremium(featureId) {
    if (premium.hasFeature(featureId)) return;
    const f = premium.PREMIUM_FEATURES.find((x) => x.id === featureId) || { label: featureId };
    throw httpErr(402, `${f.label} is a premium feature. Unlock it with a VNM license key.`, { premium_required: featureId, feature: f.label });
  }

  // JSON-403 admin guard for API routes (checkAdmin redirects browsers to
  // /dashboard, which is right for pages but useless for API clients).
  function adminOnly(req, res, next) {
    if (!req.session.userId) return res.status(401).json({ success: false, error: 'UNAUTHENTICATED', message: 'Sign in required' });
    if (req.session.role !== 'admin') return res.status(403).json({ success: false, error: 'ADMIN_ONLY', message: 'Administrator access required' });
    next();
  }

  async function getVmOwned(req, vmId) {
    const vm = await ops.getVm(vmId);
    if (!vm) throw httpErr(404, 'VM not found or access denied');
    if (!isAdmin(req) && vm.owner_id !== req.session.userId) throw httpErr(404, 'VM not found or access denied');
    return vm;
  }

  // ============================== SCHEMA ==============================
  function ensureSchema() {
    return new Promise((resolve) => {
      db.serialize(() => {
        const done = (fn) => (e) => { if (e && !String(e.message || '').includes('duplicate column')) console.log('[Platform schema]', e.message); fn(); };
        db.run(`CREATE TABLE IF NOT EXISTS vm_backups (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          vm_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          kind TEXT DEFAULT 'file',
          status TEXT DEFAULT 'queued',
          size_bytes INTEGER,
          file_path TEXT,
          file_name TEXT,
          node_file TEXT,
          node_id INTEGER,
          notes TEXT,
          checksum TEXT,
          created_by INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, () => {
          db.run(`CREATE INDEX IF NOT EXISTS idx_backups_vm ON vm_backups(vm_id)`, () => {
            db.run(`CREATE TABLE IF NOT EXISTS storage_pools (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              node_id INTEGER NOT NULL,
              name TEXT NOT NULL,
              path TEXT NOT NULL,
              pool_type TEXT DEFAULT 'dir',
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`, () => {
              db.run(`CREATE TABLE IF NOT EXISTS ip_allocations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subnet TEXT NOT NULL DEFAULT '10.100.0.0/16',
                ip TEXT NOT NULL UNIQUE,
                label TEXT,
                vm_id INTEGER,
                status TEXT DEFAULT 'reserved',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
              )`, () => {
                db.run(`CREATE TABLE IF NOT EXISTS vm_firewall_rules (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  vm_id INTEGER NOT NULL,
                  direction TEXT DEFAULT 'in',
                  protocol TEXT DEFAULT 'tcp',
                  port_start INTEGER NOT NULL,
                  port_end INTEGER,
                  source TEXT DEFAULT 'any',
                  action TEXT DEFAULT 'allow',
                  priority INTEGER DEFAULT 100,
                  note TEXT,
                  enabled INTEGER DEFAULT 1,
                  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )`, () => {
                  db.run(`CREATE INDEX IF NOT EXISTS idx_fw_vm ON vm_firewall_rules(vm_id)`, () => {
                    db.run(`CREATE TABLE IF NOT EXISTS ssh_profiles (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER NOT NULL,
                      vm_id INTEGER,
                      name TEXT NOT NULL,
                      username TEXT,
                      notes TEXT,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )`, () => {
                      db.run(`CREATE TABLE IF NOT EXISTS api_keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        name TEXT NOT NULL,
                        prefix TEXT NOT NULL,
                        key_hash TEXT NOT NULL UNIQUE,
                        scopes TEXT NOT NULL DEFAULT '["read"]',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_used DATETIME,
                        expires_at DATETIME,
                        revoked INTEGER DEFAULT 0
                      )`, () => resolve());
                    });
                  });
                });
              });
            });
          });
        });
        // Additive columns on existing tables.
        db.run(`ALTER TABLE vms ADD COLUMN tags TEXT`, done(() => {}));
        db.run(`ALTER TABLE vms ADD COLUMN notes TEXT`, done(() => {}));
        db.run(`ALTER TABLE vms ADD COLUMN vm_group TEXT`, done(() => {}));
        db.run(`ALTER TABLE nodes ADD COLUMN maintenance_mode INTEGER DEFAULT 0`, done(() => {}));
        db.run(`ALTER TABLE nodes ADD COLUMN maintenance_reason TEXT`, done(() => {}));
      });
    });
  }

  // ======================= API KEYS =======================
  // The auth middleware itself lives in api-keys.js (it must register
  // BEFORE the CSRF middleware, which is mounted before this router is
  // created); these routes manage the keys themselves.
  router.get('/api/api-keys', checkAuth, ah(async (req, res) => {
    const rows = await dbAll(`SELECT id, name, prefix, scopes, created_at, last_used, expires_at, revoked FROM api_keys WHERE user_id = ? ORDER BY id DESC`, [req.session.userId]);
    res.json({ keys: rows.map((r) => ({ ...r, scopes: JSON.parse(r.scopes || '["read"]') })) });
  }));

  router.post('/api/api-keys', checkAuth, ah(async (req, res) => {
    const name = String(req.body.name || '').trim();
    if (!name || name.length > 64) throw httpErr(400, 'Key name is required (1-64 chars)');
    let scopes = ['read'];
    if (Array.isArray(req.body.scopes) && req.body.scopes.length) {
      scopes = [...new Set(req.body.scopes.map(String))];
      const valid = ['read', 'write'];
      if (scopes.some((s) => !valid.includes(s))) throw httpErr(400, 'Scopes must be any of: ' + valid.join(', '));
    }
    const secret = crypto.randomBytes(24).toString('hex');
    const full = `vnmak_${secret}`;
    const r = await dbRun(`INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes) VALUES (?, ?, ?, ?, ?)`,
      [req.session.userId, name, full.slice(0, 14) + '...', crypto.createHash('sha256').update(full).digest('hex'), JSON.stringify(scopes)]);
    auditLog.log({ ...auditLog.fromReq(req), action: 'api_key_create', targetType: 'api_key', targetId: r.lastID, details: name });
    res.json({ id: r.lastID, name, scopes, key: full, note: 'Store this key now - it is shown only once' });
  }));

  router.delete('/api/api-keys/:id', checkAuth, ah(async (req, res) => {
    const row = await dbGet(`SELECT * FROM api_keys WHERE id = ?`, [req.params.id]);
    if (!row || (row.user_id !== req.session.userId && !isAdmin(req))) throw httpErr(404, 'API key not found');
    await dbRun(`UPDATE api_keys SET revoked = 1 WHERE id = ?`, [row.id]);
    auditLog.log({ ...auditLog.fromReq(req), action: 'api_key_revoke', targetType: 'api_key', targetId: row.id, details: row.name });
    res.json({ success: true });
  }));

  // ======================= SNAPSHOTS =======================
  router.get('/api/vms/:vm_id/snapshots', checkAuth, ah(async (req, res) => {
    const vm = await getVmOwned(req, req.params.vm_id);
    const rows = await dbAll(`SELECT * FROM vm_snapshots WHERE vm_id = ? ORDER BY snapshot_id DESC`, [vm.vm_id]);
    res.json(rows);
  }));

  router.post('/api/vms/:vm_id/snapshots', checkAuth, ah(async (req, res) => {
    const vm = await getVmOwned(req, req.params.vm_id);
    const r = await ops.snapshotCreate(vm, String(req.body.snapshot_name || req.body.name || ''), req.body.description, req.session.username);
    res.json({ success: true, snapshot_id: r.snapshot_id, message: `Snapshot "${r.name}" created` });
  }));

  router.post('/api/vms/:vm_id/snapshots/:sid/restore', checkAuth, ah(async (req, res) => {
    const vm = await getVmOwned(req, req.params.vm_id);
    const snap = await dbGet(`SELECT * FROM vm_snapshots WHERE snapshot_id = ? AND vm_id = ?`, [req.params.sid, vm.vm_id]);
    if (!snap) throw httpErr(404, 'Snapshot not found');
    await ops.snapshotRestore(vm, snap);
    auditLog.log({ ...auditLog.fromReq(req), action: 'snapshot_restore', targetType: 'vm', targetId: vm.vm_id, details: snap.snapshot_name });
    res.json({ success: true, message: `Snapshot "${snap.snapshot_name}" restored - VM disk rolled back` });
  }));

  router.delete('/api/vms/:vm_id/snapshots/:sid', checkAuth, ah(async (req, res) => {
    const vm = await getVmOwned(req, req.params.vm_id);
    const snap = await dbGet(`SELECT * FROM vm_snapshots WHERE snapshot_id = ? AND vm_id = ?`, [req.params.sid, vm.vm_id]);
    if (!snap) throw httpErr(404, 'Snapshot not found');
    await ops.snapshotDelete(vm, snap);
    res.json({ success: true, message: `Snapshot "${snap.snapshot_name}" deleted` });
  }));

  // ======================= BACKUPS =======================
  router.get('/api/vms/:vm_id/backups', checkAuth, ah(async (req, res) => {
    const vm = await getVmOwned(req, req.params.vm_id);
    const rows = await dbAll(
      `SELECT b.*, n.name AS node_name, u.username AS created_by_name FROM vm_backups b
       LEFT JOIN nodes n ON n.id = b.node_id LEFT JOIN users u ON u.id = b.created_by
       WHERE b.vm_id = ? ORDER BY b.id DESC`, [vm.vm_id]);
    res.json(rows);
  }));

  router.get('/api/backups', checkAuth, adminOnly, ah(async (req, res) => {
    const clauses = []; const params = [];
    if (req.query.vm_id) { clauses.push('b.vm_id = ?'); params.push(req.query.vm_id); }
    if (req.query.status) { clauses.push('b.status = ?'); params.push(req.query.status); }
    const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
    const rows = await dbAll(
      `SELECT b.*, v.vm_name, n.name AS node_name, u.username AS created_by_name FROM vm_backups b
       JOIN vms v ON v.vm_id = b.vm_id
       LEFT JOIN nodes n ON n.id = b.node_id LEFT JOIN users u ON u.id = b.created_by
       ${where} ORDER BY b.id DESC LIMIT 200`, params);
    res.json(rows);
  }));

  router.post('/api/vms/:vm_id/backups', checkAuth, ah(async (req, res) => {
    const vm = await getVmOwned(req, req.params.vm_id);
    const task = await ctx.taskEngine.enqueue({
      type: 'vm.backup', targetId: vm.vm_id,
      label: `Backup ${vm.vm_name}`,
      params: { name: req.body.name, notes: req.body.notes, retention: req.body.retention },
      createdBy: req.session.userId, createdByName: req.session.username,
    });
    res.json({ success: true, task_id: task.id, message: 'Backup task queued' });
  }));

  router.post('/api/backups/:id/restore', checkAuth, ah(async (req, res) => {
    const backup = await dbGet(`SELECT * FROM vm_backups WHERE id = ?`, [req.params.id]);
    if (!backup) throw httpErr(404, 'Backup not found');
    const vm = await getVmOwned(req, backup.vm_id); // enforces ownership
    if (req.body.confirm !== true && req.body.confirm !== 'true') {
      throw httpErr(400, 'Restoring a backup REPLACES the current disk - send confirm:true', { code: 'CONFIRM_REQUIRED' });
    }
    const task = await ctx.taskEngine.enqueue({
      type: 'vm.restore-backup', targetId: vm.vm_id, label: `Restore ${backup.name}`,
      params: { backupId: backup.id }, createdBy: req.session.userId, createdByName: req.session.username,
    });
    auditLog.log({ ...auditLog.fromReq(req), action: 'backup_restore', targetType: 'vm', targetId: vm.vm_id, details: backup.name });
    res.json({ success: true, task_id: task.id, message: 'Restore task queued (VM must be stopped)' });
  }));

  router.post('/api/backups/:id/restore-new', checkAuth, ah(async (req, res) => {
    const backup = await dbGet(`SELECT * FROM vm_backups WHERE id = ?`, [req.params.id]);
    if (!backup) throw httpErr(404, 'Backup not found');
    await getVmOwned(req, backup.vm_id);
    const task = await ctx.taskEngine.enqueue({
      type: 'vm.restore-backup-new', targetId: backup.vm_id, label: `Recovery test: ${backup.name}`,
      params: { backupId: backup.id }, createdBy: req.session.userId, createdByName: req.session.username,
    });
    res.json({ success: true, task_id: task.id, message: 'Recovery test queued - a test clone will be created, original VM untouched' });
  }));

  router.post('/api/backups/:id/verify', checkAuth, ah(async (req, res) => {
    const backup = await dbGet(`SELECT * FROM vm_backups WHERE id = ?`, [req.params.id]);
    if (!backup) throw httpErr(404, 'Backup not found');
    await getVmOwned(req, backup.vm_id);
    const r = await ops.backupVerify(backup);
    if (r.sha256 && backup.checksum && r.sha256 !== backup.checksum) throw httpErr(422, 'Checksum mismatch');
    await dbRun(`UPDATE vm_backups SET checksum = COALESCE(?, checksum) WHERE id = ?`, [r.sha256, backup.id]);
    res.json({ success: true, verified: true, sha256: r.sha256, size_bytes: r.sizeBytes });
  }));

  router.delete('/api/backups/:id', checkAuth, ah(async (req, res) => {
    const backup = await dbGet(`SELECT * FROM vm_backups WHERE id = ?`, [req.params.id]);
    if (!backup) throw httpErr(404, 'Backup not found');
    await getVmOwned(req, backup.vm_id);
    await ops.backupDelete(backup);
    res.json({ success: true, message: `Backup "${backup.name}" deleted` });
  }));

  // ======================= VM EXTRAS (clone / bulk / meta) =======================
  router.post('/api/vms/:vm_id/clone', checkAuth, ah(async (req, res) => {
    const vm = await getVmOwned(req, req.params.vm_id);
    const task = await ctx.taskEngine.enqueue({
      type: 'vm.clone', targetId: vm.vm_id, label: `Clone ${vm.vm_name}`,
      params: { name: req.body.name }, createdBy: req.session.userId, createdByName: req.session.username,
    });
    res.json({ success: true, task_id: task.id, message: 'Clone task queued (VM must be stopped)' });
  }));

  router.post('/api/vms/bulk', checkAuth, ah(async (req, res) => {
    const ids = Array.isArray(req.body.vm_ids) ? req.body.vm_ids.map((x) => parseInt(x, 10)).filter(Number.isInteger) : [];
    const action = String(req.body.action || '');
    if (!ids.length) throw httpErr(400, 'vm_ids[] is required');
    if (!['start', 'stop', 'restart', 'delete'].includes(action)) throw httpErr(400, 'action must be start|stop|restart|delete');
    if (action === 'delete' && req.body.confirm !== true && req.body.confirm !== 'true') {
      throw httpErr(400, 'Bulk delete is destructive - send confirm:true', { code: 'CONFIRM_REQUIRED' });
    }
    const results = [];
    for (const id of ids) {
      try {
        const vm = await getVmOwned(req, id); // 404s non-owned ids
        if (action === 'start') await ops.vmStart(vm, req.session.username);
        else if (action === 'stop') await ops.vmStop(vm, req.session.username);
        else if (action === 'restart') await ops.vmRestart(vm, req.session.username);
        else if (action === 'delete') await ops.vmDeleteFull(vm, req.session.username);
        results.push({ vm_id: id, vm_name: vm.vm_name, ok: true });
      } catch (e) {
        results.push({ vm_id: id, ok: false, error: e.message });
      }
    }
    auditLog.log({ ...auditLog.fromReq(req), action: 'vm_bulk_' + action, targetType: 'vm', details: `${results.filter((r) => r.ok).length}/${ids.length} succeeded` });
    res.json({ success: true, results });
  }));

  router.put('/api/vms/:vm_id/meta', checkAuth, ah(async (req, res) => {
    const vm = await getVmOwned(req, req.params.vm_id);
    const tags = Array.isArray(req.body.tags)
      ? [...new Set(req.body.tags.map((t) => String(t).trim().toLowerCase()).filter((t) => t && t.length <= 24))].slice(0, 8)
      : undefined;
    await dbRun(`UPDATE vms SET tags = ?, notes = ?, vm_group = ? WHERE vm_id = ?`,
      [tags === undefined ? (vm.tags || null) : JSON.stringify(tags),
       req.body.notes === undefined ? vm.notes : String(req.body.notes).slice(0, 500),
       req.body.vm_group === undefined ? vm.vm_group : String(req.body.vm_group).slice(0, 64),
       vm.vm_id]);
    res.json({ success: true });
  }));

  // One call for the VM detail "Snapshots & Backups" tab.
  router.get('/api/vms/:vm_id/platform-summary', checkAuth, ah(async (req, res) => {
    const vm = await getVmOwned(req, req.params.vm_id);
    const [snapshots, backups, tasks, fw] = await Promise.all([
      dbAll(`SELECT * FROM vm_snapshots WHERE vm_id = ? ORDER BY snapshot_id DESC`, [vm.vm_id]),
      dbAll(`SELECT b.*, n.name AS node_name FROM vm_backups b LEFT JOIN nodes n ON n.id = b.node_id WHERE b.vm_id = ? ORDER BY b.id DESC`, [vm.vm_id]),
      ctx.taskEngine.listTasks({ targetId: vm.vm_id, limit: 10 }),
      dbAll(`SELECT * FROM vm_firewall_rules WHERE vm_id = ? ORDER BY priority ASC, id ASC`, [vm.vm_id]),
    ]);
    let tags = [];
    try { tags = JSON.parse(vm.tags || '[]'); } catch (e) {}
    res.json({ vm: { vm_id: vm.vm_id, vm_name: vm.vm_name, status: vm.status, tags, notes: vm.notes, vm_group: vm.vm_group }, snapshots, backups, tasks, firewall: fw });
  }));

  // ======================= MIGRATION =======================
  router.get('/api/vms/:vm_id/migrate/options', checkAuth, ah(async (req, res) => {
    const vm = await getVmOwned(req, req.params.vm_id);
    const cur = await ops.nodeForVm(vm);
    const placement = await placementRecommendation({ cpus: vm.cpus, memoryMb: vm.memory, diskGb: null, excludeNodeId: cur ? cur.id : null });
    res.json({ current_node: cur ? { id: cur.id, name: cur.name, mode: cur.mode } : null, targets: placement });
  }));

  router.post('/api/vms/:vm_id/migrate', checkAuth, ah(async (req, res) => {
    needPremium('live_migration');
    const vm = await getVmOwned(req, req.params.vm_id);
    const target = await dbGet(`SELECT * FROM nodes WHERE id = ?`, [req.body.target_node_id]);
    if (!target) throw httpErr(404, 'Target node not found');
    const task = await ctx.taskEngine.enqueue({
      type: 'vm.migrate', targetId: vm.vm_id, label: `Migrate ${vm.vm_name} -> ${target.name}`,
      params: { targetNodeId: target.id, startAfter: req.body.start_after !== false },
      createdBy: req.session.userId, createdByName: req.session.username,
    });
    auditLog.log({ ...auditLog.fromReq(req), action: 'vm_migrate', targetType: 'vm', targetId: vm.vm_id, details: `to node ${target.name}` });
    res.json({ success: true, task_id: task.id, message: `Migration to "${target.name}" queued` });
  }));

  // ======================= NODES (maintenance / placement / capacity) =======================
  router.post('/api/nodes/:id/maintenance', checkAuth, adminOnly, ah(async (req, res) => {
    const node = await dbGet(`SELECT * FROM nodes WHERE id = ?`, [req.params.id]);
    if (!node) throw httpErr(404, 'Node not found');
    const on = req.body.on === true || req.body.on === 'true' || req.body.on === 1;
    await dbRun(`UPDATE nodes SET maintenance_mode = ?, maintenance_reason = ? WHERE id = ?`,
      [on ? 1 : 0, on ? String(req.body.reason || 'Scheduled maintenance').slice(0, 200) : null, node.id]);
    auditLog.log({ ...auditLog.fromReq(req), action: on ? 'node_maintenance_on' : 'node_maintenance_off', targetType: 'node', targetId: node.id, details: req.body.reason || '' });
    res.json({ success: true, maintenance_mode: on ? 1 : 0 });
  }));

  async function placementRecommendation({ cpus, memoryMb, diskGb, excludeNodeId }) {
    const nodes = await nodeManager.listNodes();
    const out = [];
    for (const n of nodes) {
      if (excludeNodeId && n.id === excludeNodeId) continue;
      if (n.maintenance_mode) { out.push({ node: { id: n.id, name: n.name, mode: n.mode }, eligible: false, reasons: ['Maintenance mode'] }); continue; }
      if (n.mode === 'remote' && !n.online) { out.push({ node: { id: n.id, name: n.name, mode: n.mode }, eligible: false, reasons: ['Offline'] }); continue; }
      // Allocated resources from the VM table (requested-by-VMs view).
      const alloc = await dbGet(
        `SELECT COALESCE(SUM(cpus),0) AS cpus, COALESCE(SUM(memory),0) AS mem, COUNT(*) AS vms FROM vms WHERE COALESCE(node_id, (SELECT id FROM nodes WHERE mode='local' LIMIT 1)) = ?`,
        [n.id]);
      const reasons = [];
      let score = 50;
      const cpuPct = n.cpu_usage_percent != null ? n.cpu_usage_percent : null;
      const memPct = n.ram_total ? (n.ram_used / n.ram_total) * 100 : null;
      const diskPct = n.disk_total ? (n.disk_used / n.disk_total) * 100 : null;
      if (cpuPct != null) { score -= cpuPct * 0.5; reasons.push(`CPU at ${cpuPct.toFixed(0)}%`); } else reasons.push('CPU usage unknown');
      if (memPct != null) { score -= memPct * 0.3; reasons.push(`RAM at ${memPct.toFixed(0)}%`); } else reasons.push('RAM usage unknown');
      if (diskPct != null) { score -= diskPct * 0.2; reasons.push(`Disk at ${diskPct.toFixed(0)}%`); } else reasons.push('Disk usage unknown');
      if (cpus && alloc) {
        const nodeCores = n.cpu_cores || 0;
        if (nodeCores && alloc.cpus + cpus > nodeCores * 2) { out.push({ node: { id: n.id, name: n.name, mode: n.mode }, eligible: false, reasons: [...reasons, `CPU over-commit limit (${alloc.cpus}/${nodeCores * 2} vCPUs allocated)`] }); continue; }
        reasons.push(`${alloc.cpus} vCPUs allocated to ${alloc.vms} VMs`);
      }
      if (memoryMb && n.ram_total && alloc && (alloc.mem + memoryMb) * 1024 * 1024 > n.ram_total * 1.1) {
        out.push({ node: { id: n.id, name: n.name, mode: n.mode }, eligible: false, reasons: [...reasons, 'Not enough free RAM for this VM'] });
        continue;
      }
      score += 10; // baseline preference for reachable nodes
      out.push({ node: { id: n.id, name: n.name, mode: n.mode }, eligible: true, score: Math.round(score), reasons, stats: { cpuPct, memPct, diskPct } });
    }
    const eligible = out.filter((o) => o.eligible).sort((a, b) => (b.score || 0) - (a.score || 0));
    if (eligible.length) eligible[0].recommended = true;
    return out;
  }

  router.get('/api/nodes/placement', checkAuth, adminOnly, ah(async (req, res) => {
    const cpus = parseInt(req.query.cpus, 10) || 0;
    const memoryMb = parseInt(req.query.memory_mb, 10) || 0;
    const diskGb = parseFloat(req.query.disk_gb) || 0;
    res.json({ candidates: await placementRecommendation({ cpus, memoryMb, diskGb, excludeNodeId: null }) });
  }));

  router.get('/api/nodes/capacity', checkAuth, adminOnly, ah(async (req, res) => {
    const nodes = await nodeManager.listNodes();
    const out = [];
    for (const n of nodes) {
      const alloc = await dbGet(
        `SELECT COALESCE(SUM(cpus),0) AS cpus, COALESCE(SUM(memory),0) AS mem, COUNT(*) AS vms,
                COALESCE(SUM(CASE WHEN status='running' THEN 1 ELSE 0 END),0) AS running
         FROM vms WHERE COALESCE(node_id, (SELECT id FROM nodes WHERE mode='local' LIMIT 1)) = ?`, [n.id]);
      out.push({
        id: n.id, name: n.name, mode: n.mode, status: n.status, online: !!n.online,
        maintenance_mode: !!n.maintenance_mode, maintenance_reason: n.maintenance_reason || null,
        host: {
          cpuCores: n.cpu_cores, cpuModel: n.cpu, cpuUsagePercent: n.cpu_usage_percent,
          ramTotalBytes: n.ram_total, ramUsedBytes: n.ram_used,
          diskTotalBytes: n.disk_total, diskUsedBytes: n.disk_used,
          kvmAvailable: !!n.kvm_available, agentVersion: n.agent_version, os: n.os,
        },
        allocated: { cpus: alloc.cpus, memoryMb: alloc.mem, vms: alloc.vms, running: alloc.running },
      });
    }
    res.json({ nodes: out });
  }));

  router.get('/api/nodes/:id/drain-preview', checkAuth, adminOnly, ah(async (req, res) => {
    const node = await dbGet(`SELECT * FROM nodes WHERE id = ?`, [req.params.id]);
    if (!node) throw httpErr(404, 'Node not found');
    const vms = await dbAll(`SELECT vm_id, vm_name, status, cpus, memory FROM vms WHERE node_id = ?`, [node.id]);
    const placement = await placementRecommendation({ cpus: 0, memoryMb: 0, diskGb: 0, excludeNodeId: node.id });
    res.json({ node: { id: node.id, name: node.name }, vms, targets: placement });
  }));

  // ======================= STORAGE POOLS =======================
  async function dfUsage(p) {
    try {
      const { stdout } = await execPromise(`df -B1 --output=size,used,avail "${p.replace(/"/g, '')}" 2>/dev/null | tail -1`, { timeout: 5000 });
      const parts = stdout.trim().split(/\s+/);
      if (parts.length >= 3) return { totalBytes: +parts[0], usedBytes: +parts[1], freeBytes: +parts[2] };
    } catch (e) { /* not linux / missing */ }
    return null;
  }

  router.get('/api/storage/pools', checkAuth, adminOnly, ah(async (req, res) => {
    const pools = [];
    const localNode = await dbGet(`SELECT * FROM nodes WHERE mode = 'local' LIMIT 1`);
    // Default local pools.
    const localDefs = [
      { name: 'VM Storage', path: VM_DIR },
      { name: 'Backups', path: ops.BACKUP_DIR },
      { name: 'Templates', path: TEMPLATES_DIR || path.join(VM_DIR, 'templates') },
    ];
    for (const d of localDefs) {
      const usage = await dfUsage(d.path);
      pools.push({ node: localNode ? { id: localNode.id, name: localNode.name, mode: 'local' } : { id: null, name: 'Local Node', mode: 'local' }, name: d.name, path: d.path, usage, builtin: true });
    }
    // Registry pools (admin-created) for local node.
    const registry = await dbAll(`SELECT sp.*, n.name AS node_name, n.mode AS node_mode FROM storage_pools sp JOIN nodes n ON n.id = sp.node_id`, []);
    for (const rp of registry) {
      if (rp.node_mode === 'local') {
        pools.push({ node: { id: rp.node_id, name: rp.node_name }, name: rp.name, path: rp.path, usage: await dfUsage(rp.path), builtin: false, id: rp.id });
      }
    }
    // Remote nodes: default dirs + their registry pools, via agents.
    const remotes = await dbAll(`SELECT * FROM nodes WHERE mode = 'remote'`, []);
    for (const n of remotes) {
      if (!nodeManager.isNodeOnline(n.id)) {
        pools.push({ node: { id: n.id, name: n.name, mode: 'remote' }, name: 'Node Storage', path: null, usage: null, offline: true, builtin: true });
        continue;
      }
      try {
        const r = await nodeManager.sendNodeCommand(n.id, 'node.storage.list', {}, { timeoutMs: 8000 });
        for (const p of (r.pools || [])) {
          const reg = registry.find((x) => x.node_id === n.id && x.path === p.path);
          pools.push({ node: { id: n.id, name: n.name, mode: 'remote' }, name: reg ? reg.name : p.name, path: p.path, id: reg ? reg.id : undefined, usage: { totalBytes: p.totalBytes, usedBytes: p.usedBytes, freeBytes: p.freeBytes }, builtin: !reg });
        }
      } catch (e) {
        pools.push({ node: { id: n.id, name: n.name, mode: 'remote' }, name: 'Node Storage', path: null, usage: null, error: e.message, builtin: true });
      }
    }
    res.json({ pools });
  }));

  router.post('/api/storage/pools', checkAuth, adminOnly, ah(async (req, res) => {
    const name = String(req.body.name || '').trim();
    const p = String(req.body.path || '').trim();
    const nodeId = parseInt(req.body.node_id, 10);
    if (!name || name.length > 64) throw httpErr(400, 'Pool name required (1-64 chars)');
    if (!p || !path.isAbsolute(p)) throw httpErr(400, 'Path must be absolute');
    const node = await dbGet(`SELECT * FROM nodes WHERE id = ?`, [nodeId]);
    if (!node) throw httpErr(404, 'Node not found');
    if (node.mode === 'remote') {
      if (!nodeManager.isNodeOnline(node.id)) throw httpErr(409, 'Node is offline', { code: 'NODE_OFFLINE' });
      const r = await nodeManager.sendNodeCommand(node.id, 'node.storage.check', { path: p }, { timeoutMs: 8000 });
      if (!r || !r.exists) throw httpErr(400, 'Path does not exist on that node');
    } else {
      if (!fs.existsSync(p)) throw httpErr(400, 'Path does not exist on the panel host');
      const resolved = path.resolve(p) + path.sep;
      const forbidden = [path.resolve('/proc'), path.resolve('/sys'), path.resolve('/dev'), path.resolve('/etc')].map((x) => x + path.sep);
      if (forbidden.some((f) => resolved.startsWith(f))) throw httpErr(400, 'That path is not allowed as a storage pool');
    }
    const r = await dbRun(`INSERT INTO storage_pools (node_id, name, path) VALUES (?, ?, ?)`, [node.id, name, p]);
    auditLog.log({ ...auditLog.fromReq(req), action: 'storage_pool_create', targetType: 'node', targetId: node.id, details: `${name}: ${p}` });
    res.json({ success: true, id: r.lastID });
  }));

  router.delete('/api/storage/pools/:id', checkAuth, adminOnly, ah(async (req, res) => {
    const pool = await dbGet(`SELECT * FROM storage_pools WHERE id = ?`, [req.params.id]);
    if (!pool) throw httpErr(404, 'Pool not found');
    // Only unregisters - NEVER deletes data on disk.
    await dbRun(`DELETE FROM storage_pools WHERE id = ?`, [pool.id]);
    res.json({ success: true, message: 'Pool unregistered (files on disk were NOT touched)' });
  }));

  // ======================= NETWORK (IPs / firewall / fleet view) =======================
  const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

  router.get('/api/network/ips', checkAuth, ah(async (req, res) => {
    if (!isAdmin(req)) throw httpErr(403, 'Admin only');
    const rows = await dbAll(
      `SELECT i.*, v.vm_name FROM ip_allocations i LEFT JOIN vms v ON v.vm_id = i.vm_id ORDER BY i.ip ASC`, []);
    res.json(rows);
  }));

  router.post('/api/network/ips', checkAuth, adminOnly, ah(async (req, res) => {
    const ip = String(req.body.ip || '').trim();
    if (!IPV4_RE.test(ip)) throw httpErr(400, 'Invalid IPv4 address');
    const dup = await dbGet(`SELECT id FROM ip_allocations WHERE ip = ?`, [ip]);
    if (dup) throw httpErr(409, `IP ${ip} is already allocated (allocation #${dup.id})`, { code: 'IP_CONFLICT' });
    const usedByVm = await dbGet(`SELECT vm_id, vm_name FROM vms WHERE ipv4_address = ?`, [ip]);
    if (usedByVm) throw httpErr(409, `IP ${ip} is already in use by VM "${usedByVm.vm_name}" (#${usedByVm.vm_id})`, { code: 'IP_CONFLICT' });
    const r = await dbRun(`INSERT INTO ip_allocations (ip, label, subnet, status) VALUES (?, ?, ?, 'reserved')`,
      [ip, req.body.label ? String(req.body.label).slice(0, 100) : null, req.body.subnet || '10.100.0.0/16']);
    res.json({ success: true, id: r.lastID });
  }));

  router.patch('/api/network/ips/:id', checkAuth, adminOnly, ah(async (req, res) => {
    const row = await dbGet(`SELECT * FROM ip_allocations WHERE id = ?`, [req.params.id]);
    if (!row) throw httpErr(404, 'Allocation not found');
    if (req.body.vm_id) {
      const vm = await dbGet(`SELECT * FROM vms WHERE vm_id = ?`, [req.body.vm_id]);
      if (!vm) throw httpErr(404, 'VM not found');
      await dbRun(`UPDATE ip_allocations SET vm_id = ?, status = 'assigned', label = COALESCE(?, label) WHERE id = ?`,
        [vm.vm_id, req.body.label || null, row.id]);
    } else {
      await dbRun(`UPDATE ip_allocations SET vm_id = NULL, status = 'reserved' WHERE id = ?`, [row.id]);
    }
    res.json({ success: true });
  }));

  router.delete('/api/network/ips/:id', checkAuth, adminOnly, ah(async (req, res) => {
    const r = await dbRun(`DELETE FROM ip_allocations WHERE id = ?`, [req.params.id]);
    if (!r.changes) throw httpErr(404, 'Allocation not found');
    res.json({ success: true });
  }));

  router.get('/api/network/overview', checkAuth, adminOnly, ah(async (req, res) => {
    const forwards = await dbAll(
      `SELECT f.*, v.vm_name, v.vm_id, v.ssh_port, n.name AS node_name
       FROM vm_port_forwards f JOIN vms v ON v.vm_id = f.vm_id LEFT JOIN nodes n ON n.id = v.node_id
       ORDER BY v.vm_name ASC, f.host_port ASC`, []);
    const ips = await dbAll(`SELECT i.*, v.vm_name FROM ip_allocations i LEFT JOIN vms v ON v.vm_id = i.vm_id ORDER BY i.ip`, []);
    const vmNet = await dbAll(`SELECT vm_id, vm_name, network_type, nic_model, bridge_device, mac_address, ipv4_address, ssh_port FROM vms ORDER BY vm_name`, []);
    res.json({ forwards, ips, vms: vmNet });
  }));

  // ---- per-VM firewall rules ----
  router.get('/api/vms/:vm_id/firewall', checkAuth, ah(async (req, res) => {
    const vm = await getVmOwned(req, req.params.vm_id);
    res.json(await dbAll(`SELECT * FROM vm_firewall_rules WHERE vm_id = ? ORDER BY priority ASC, id ASC`, [vm.vm_id]));
  }));

  router.post('/api/vms/:vm_id/firewall', checkAuth, ah(async (req, res) => {
    const vm = await getVmOwned(req, req.params.vm_id);
    const protocol = String(req.body.protocol || 'tcp').toLowerCase();
    const direction = String(req.body.direction || 'in').toLowerCase();
    const action = String(req.body.action || 'allow').toLowerCase();
    if (!['tcp', 'udp', 'any'].includes(protocol)) throw httpErr(400, 'protocol must be tcp|udp|any');
    if (!['in', 'out'].includes(direction)) throw httpErr(400, 'direction must be in|out');
    if (!['allow', 'deny'].includes(action)) throw httpErr(400, 'action must be allow|deny');
    const portStart = parseInt(req.body.port_start, 10);
    const portEnd = req.body.port_end != null && req.body.port_end !== '' ? parseInt(req.body.port_end, 10) : portStart;
    if (!(portStart >= 1 && portStart <= 65535) || !(portEnd >= 1 && portEnd <= 65535) || portEnd < portStart) {
      throw httpErr(400, 'Invalid port range');
    }
    const r = await dbRun(
      `INSERT INTO vm_firewall_rules (vm_id, direction, protocol, port_start, port_end, source, action, priority, note)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [vm.vm_id, direction, protocol, portStart, portEnd,
       req.body.source ? String(req.body.source).slice(0, 100) : 'any', action,
       parseInt(req.body.priority, 10) || 100, req.body.note ? String(req.body.note).slice(0, 200) : null]);
    res.json({ success: true, id: r.lastID });
  }));

  router.post('/api/vms/:vm_id/firewall/defaults', checkAuth, ah(async (req, res) => {
    const vm = await getVmOwned(req, req.params.vm_id);
    const existing = await dbGet(`SELECT COUNT(*) AS c FROM vm_firewall_rules WHERE vm_id = ?`, [vm.vm_id]);
    if (existing.c > 0) throw httpErr(409, 'This VM already has firewall rules configured', { code: 'RULES_EXIST' });
    const defaults = [
      { direction: 'in', protocol: 'tcp', port_start: 22, port_end: 22, action: 'allow', priority: 10, note: 'SSH (safe default)' },
      { direction: 'in', protocol: 'tcp', port_start: 80, port_end: 80, action: 'allow', priority: 20, note: 'HTTP (safe default)' },
      { direction: 'in', protocol: 'tcp', port_start: 443, port_end: 443, action: 'allow', priority: 20, note: 'HTTPS (safe default)' },
      { direction: 'in', protocol: 'any', port_start: 1, port_end: 65535, action: 'deny', priority: 900, note: 'Deny all other inbound (safe default)' },
    ];
    for (const d of defaults) {
      await dbRun(
        `INSERT INTO vm_firewall_rules (vm_id, direction, protocol, port_start, port_end, source, action, priority, note)
         VALUES (?, ?, ?, ?, ?, 'any', ?, ?, ?)`,
        [vm.vm_id, d.direction, d.protocol, d.port_start, d.port_end, d.action, d.priority, d.note]);
    }
    res.json({ success: true, message: 'Safe-default rules applied (SSH/HTTP/HTTPS allowed, everything else denied)' });
  }));

  router.put('/api/firewall/rules/:id', checkAuth, ah(async (req, res) => {
    const rule = await dbGet(`SELECT * FROM vm_firewall_rules WHERE id = ?`, [req.params.id]);
    if (!rule) throw httpErr(404, 'Rule not found');
    await getVmOwned(req, rule.vm_id);
    await dbRun(`UPDATE vm_firewall_rules SET enabled = ? WHERE id = ?`, [req.body.enabled === false ? 0 : 1, rule.id]);
    res.json({ success: true });
  }));

  router.delete('/api/firewall/rules/:id', checkAuth, ah(async (req, res) => {
    const rule = await dbGet(`SELECT * FROM vm_firewall_rules WHERE id = ?`, [req.params.id]);
    if (!rule) throw httpErr(404, 'Rule not found');
    await getVmOwned(req, rule.vm_id);
    await dbRun(`DELETE FROM vm_firewall_rules WHERE id = ?`, [rule.id]);
    res.json({ success: true });
  }));

  // ======================= SSH PROFILES =======================
  router.get('/api/ssh-profiles', checkAuth, ah(async (req, res) => {
    const rows = await dbAll(`SELECT p.*, v.vm_name FROM ssh_profiles p LEFT JOIN vms v ON v.vm_id = p.vm_id WHERE p.user_id = ? ORDER BY p.id DESC`, [req.session.userId]);
    res.json(rows);
  }));

  router.post('/api/ssh-profiles', checkAuth, ah(async (req, res) => {
    const name = String(req.body.name || '').trim();
    if (!name || name.length > 64) throw httpErr(400, 'Profile name required');
    let vmId = null;
    if (req.body.vm_id) {
      await getVmOwned(req, req.body.vm_id);
      vmId = parseInt(req.body.vm_id, 10);
    }
    const r = await dbRun(`INSERT INTO ssh_profiles (user_id, vm_id, name, username, notes) VALUES (?, ?, ?, ?, ?)`,
      [req.session.userId, vmId, name, req.body.username ? String(req.body.username).slice(0, 64) : null, req.body.notes ? String(req.body.notes).slice(0, 300) : null]);
    res.json({ success: true, id: r.lastID });
  }));

  router.delete('/api/ssh-profiles/:id', checkAuth, ah(async (req, res) => {
    const r = await dbRun(`DELETE FROM ssh_profiles WHERE id = ? AND user_id = ?`, [req.params.id, req.session.userId]);
    if (!r.changes) throw httpErr(404, 'Profile not found');
    res.json({ success: true });
  }));

  // ======================= GLOBAL SEARCH (command palette backend) =======================
  router.get('/api/search', checkAuth, ah(async (req, res) => {
    const q = String(req.query.q || '').trim().toLowerCase();
    if (q.length < 2) return res.json({ vms: [], nodes: [], users: [], templates: [] });
    const like = `%${q.replace(/[%_]/g, '')}%`;
    const admin = isAdmin(req);
    const vms = await dbAll(
      admin
        ? `SELECT vm_id, vm_name, status, os_type, owner_id FROM vms WHERE LOWER(vm_name) LIKE ? OR CAST(vm_id AS TEXT) = ? OR LOWER(COALESCE(vm_group,'')) LIKE ? OR LOWER(COALESCE(tags,'')) LIKE ? ORDER BY vm_name LIMIT 6`
        : `SELECT vm_id, vm_name, status, os_type, owner_id FROM vms WHERE owner_id = ? AND (LOWER(vm_name) LIKE ? OR CAST(vm_id AS TEXT) = ?) ORDER BY vm_name LIMIT 6`,
      admin ? [like, q, like, like] : [req.session.userId, like, q]);
    let nodes = [], users = [], templates = [];
    if (admin) {
      nodes = await dbAll(`SELECT id, name, mode, status, maintenance_mode FROM nodes WHERE LOWER(name) LIKE ? LIMIT 4`, [like]);
      users = await dbAll(`SELECT id, username, email, role FROM users WHERE LOWER(username) LIKE ? OR LOWER(COALESCE(email,'')) LIKE ? LIMIT 4`, [like, like]);
      templates = await dbAll(`SELECT template_key, template_name, icon FROM os_templates WHERE is_active = 1 AND LOWER(template_name) LIKE ? LIMIT 4`, [like]);
    }
    res.json({ vms, nodes, users, templates });
  }));

  // ======================= AUDIT LOG VIEWER =======================
  router.get('/api/audit', checkAuth, adminOnly, ah(async (req, res) => {
    const rows = await auditLog.query({
      limit: Math.min(parseInt(req.query.limit, 10) || 100, 300),
      before: req.query.before || undefined,
      action: req.query.action || undefined,
      username: req.query.username || undefined,
    });
    res.json(rows);
  }));

  // ======================= ALERTS =======================
  const METRICS = ['cpu', 'mem', 'disk'];
  const SEVERITIES = ['info', 'warning', 'critical'];

  router.get('/api/alert-rules', checkAuth, adminOnly, ah(async (req, res) => {
    const rows = await dbAll(`SELECT r.*, 
      CASE WHEN r.scope='node' THEN (SELECT name FROM nodes WHERE id = r.target_id) ELSE (SELECT vm_name FROM vms WHERE vm_id = r.target_id) END AS target_name
      FROM alert_rules r ORDER BY r.id DESC`, []);
    res.json(rows);
  }));

  router.post('/api/alert-rules', checkAuth, adminOnly, ah(async (req, res) => {
    needPremium('alert_rules');
    const name = String(req.body.name || '').trim();
    const scope = String(req.body.scope || 'node');
    const metric = String(req.body.metric || 'cpu');
    const comparator = String(req.body.comparator || '>');
    const threshold = parseFloat(req.body.threshold);
    const severity = String(req.body.severity || 'warning');
    if (!name || name.length > 80) throw httpErr(400, 'Rule name required (1-80 chars)');
    if (!['node', 'vm'].includes(scope)) throw httpErr(400, 'scope must be node|vm');
    if (!METRICS.includes(metric)) throw httpErr(400, 'metric must be ' + METRICS.join('|'));
    if (!['>', '<'].includes(comparator)) throw httpErr(400, 'comparator must be > or <');
    if (!(threshold >= 0 && threshold <= 100)) throw httpErr(400, 'threshold must be 0-100 (percent)');
    if (!SEVERITIES.includes(severity)) throw httpErr(400, 'severity must be ' + SEVERITIES.join('|'));
    let targetId = req.body.target_id ? parseInt(req.body.target_id, 10) : null;
    if (targetId != null) {
      const exists = scope === 'node'
        ? await dbGet(`SELECT id FROM nodes WHERE id = ?`, [targetId])
        : await dbGet(`SELECT vm_id FROM vms WHERE vm_id = ?`, [targetId]);
      if (!exists) throw httpErr(404, `${scope} #${targetId} not found`);
    }
    const r = await dbRun(
      `INSERT INTO alert_rules (name, scope, target_id, metric, comparator, threshold, for_minutes, severity, channels, cooldown_minutes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [name, scope, targetId, metric, comparator, threshold,
       Math.max(0, parseInt(req.body.for_minutes, 10) || 5), severity,
       JSON.stringify(req.body.channels || ['panel']),
       Math.max(1, parseInt(req.body.cooldown_minutes, 10) || 30)]);
    res.json({ success: true, id: r.lastID });
  }));

  router.put('/api/alert-rules/:id', checkAuth, adminOnly, ah(async (req, res) => {
    needPremium('alert_rules');
    const rule = await dbGet(`SELECT * FROM alert_rules WHERE id = ?`, [req.params.id]);
    if (!rule) throw httpErr(404, 'Rule not found');
    await dbRun(`UPDATE alert_rules SET enabled = ? WHERE id = ?`, [req.body.enabled === false ? 0 : 1, rule.id]);
    res.json({ success: true });
  }));

  router.delete('/api/alert-rules/:id', checkAuth, adminOnly, ah(async (req, res) => {
    const r = await dbRun(`DELETE FROM alert_rules WHERE id = ?`, [req.params.id]);
    if (!r.changes) throw httpErr(404, 'Rule not found');
    res.json({ success: true });
  }));

  router.get('/api/alert-events', checkAuth, adminOnly, ah(async (req, res) => {
    const status = req.query.status === 'all' ? null : (req.query.status || 'open');
    const rows = status
      ? await dbAll(`SELECT * FROM alert_events WHERE status = ? ORDER BY id DESC LIMIT 100`, [status])
      : await dbAll(`SELECT * FROM alert_events ORDER BY id DESC LIMIT 100`);
    res.json(rows);
  }));

  router.post('/api/alert-events/:id/ack', checkAuth, adminOnly, ah(async (req, res) => {
    const r = await dbRun(`UPDATE alert_events SET status = 'acknowledged' WHERE id = ?`, [req.params.id]);
    if (!r.changes) throw httpErr(404, 'Event not found');
    res.json({ success: true });
  }));

  router.get('/api/alerts/settings', checkAuth, adminOnly, ah(async (req, res) => {
    const row = await dbGet(`SELECT setting_value FROM settings WHERE setting_key = 'alert_discord_webhook'`);
    const url = row ? row.setting_value : '';
    res.json({
      discord_webhook_configured: !!url,
      discord_webhook_preview: url ? url.slice(0, 60) + '...' : null,
      email_note: 'Email delivery requires an external SMTP relay; Discord webhooks are delivered natively by the panel.',
    });
  }));

  router.put('/api/alerts/settings', checkAuth, adminOnly, ah(async (req, res) => {
    const url = String(req.body.discord_webhook || '').trim();
    if (url && !/^https:\/\/(canary\.|ptb\.)?discord(app)?\.com\/api\/webhooks\//.test(url)) {
      throw httpErr(400, 'That does not look like a Discord webhook URL (https://discord.com/api/webhooks/...)');
    }
    await dbRun(`INSERT INTO settings (setting_key, setting_value) VALUES ('alert_discord_webhook', ?)
                 ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = CURRENT_TIMESTAMP`,
      [url || null]);
    auditLog.log({ ...auditLog.fromReq(req), action: 'alert_settings_update', targetType: 'settings', details: url ? 'webhook configured' : 'webhook cleared' });
    res.json({ success: true });
  }));

  router.post('/api/alerts/test', checkAuth, adminOnly, ah(async (req, res) => {
    const sent = await ctx.monitoring.sendDiscord('info', 'VNM Panel test notification - your alert pipeline is working.');
    if (!sent) throw httpErr(400, 'No Discord webhook is configured (Settings above) or delivery failed');
    res.json({ success: true, message: 'Test notification sent to your Discord webhook' });
  }));

  // ======================= MONITORING =======================
  router.get('/api/monitoring/live', checkAuth, ah(async (req, res) => {
    const live = await ctx.monitoring.getLive();
    if (!isAdmin(req)) {
      const owned = new Set((await dbAll(`SELECT vm_id FROM vms WHERE owner_id = ?`, [req.session.userId])).map((r) => r.vm_id));
      live.vms = live.vms.filter((v) => owned.has(v.vm_id));
      live.nodes = []; // host stats are admin-only
      live.overview = { ...live.overview, nodes: 0, nodesOnline: 0, cpuPercent: null, memUsedBytes: null, memTotalBytes: null, diskUsedBytes: null, diskTotalBytes: null };
    }
    res.json(live);
  }));

  router.get('/api/monitoring/history', checkAuth, ah(async (req, res) => {
    const scope = req.query.scope === 'node' ? 'node' : 'vm';
    const id = parseInt(req.query.id, 10);
    const hours = parseInt(req.query.hours, 10) || 1;
    if (!id) throw httpErr(400, 'id is required');
    if (scope === 'node' && !isAdmin(req)) throw httpErr(403, 'Node history is admin-only');
    if (scope === 'vm') await getVmOwned(req, id);
    res.json(await ctx.monitoring.getHistory({ scope, targetId: id, hours }));
  }));

  router.get('/api/monitoring/overview', checkAuth, adminOnly, ah(async (req, res) => {
    res.json(await ctx.monitoring.getOverview());
  }));

  // ======================= TASKS =======================
  const USER_TASK_TYPES = ['vm.backup', 'vm.start', 'vm.stop', 'vm.restart', 'vm.clone', 'vm.migrate', 'vm.restore-backup'];

  router.get('/api/task-types', checkAuth, ah(async (req, res) => {
    const all = [
      { type: 'vm.backup', label: 'Create a VM backup', params: ['name', 'retention'], user: true },
      { type: 'vm.restore-backup', label: 'Restore a backup', params: ['backupId'], user: true },
      { type: 'vm.restore-backup-new', label: 'Recovery-test a backup', params: ['backupId'], user: true },
      { type: 'vm.clone', label: 'Clone a VM', params: ['name'], user: true },
      { type: 'vm.migrate', label: 'Migrate a VM to another node', params: ['targetNodeId', 'startAfter'], user: true },
      { type: 'vm.start', label: 'Start a VM', params: [], user: true },
      { type: 'vm.stop', label: 'Stop a VM', params: [], user: true },
      { type: 'vm.restart', label: 'Restart a VM', params: [], user: true },
    ];
    res.json({ types: all });
  }));

  router.get('/api/tasks', checkAuth, ah(async (req, res) => {
    const tasks = await ctx.taskEngine.listTasks({
      status: req.query.status || undefined,
      type: req.query.type || undefined,
      targetId: req.query.target_id ? parseInt(req.query.target_id, 10) : undefined,
      limit: req.query.limit || 100,
    });
    if (isAdmin(req)) return res.json(tasks);
    // Users see tasks targeting their own VMs (or created by them).
    const owned = new Set((await dbAll(`SELECT vm_id FROM vms WHERE owner_id = ?`, [req.session.userId])).map((r) => r.vm_id));
    res.json(tasks.filter((t) => t.created_by === req.session.userId || (t.target_type === 'vm' && owned.has(t.target_id))));
  }));

  router.post('/api/tasks', checkAuth, ah(async (req, res) => {
    const type = String(req.body.type || '');
    if (!ctx.taskEngine.hasHandler(type)) throw httpErr(400, `Unknown task type "${type}"`, { code: 'UNKNOWN_TASK_TYPE' });
    const targetId = parseInt(req.body.target_id, 10);
    if (!targetId) throw httpErr(400, 'target_id (vm id) is required');
    await getVmOwned(req, targetId); // ownership enforcement for VM tasks
    const task = await ctx.taskEngine.enqueue({
      type, targetId, label: req.body.label || undefined,
      params: req.body.params || {}, createdBy: req.session.userId, createdByName: req.session.username,
    });
    res.json({ success: true, task_id: task.id });
  }));

  router.get('/api/tasks/:id', checkAuth, ah(async (req, res) => {
    const task = await ctx.taskEngine.getTask(parseInt(req.params.id, 10));
    if (!task) throw httpErr(404, 'Task not found');
    if (!isAdmin(req)) {
      const owned = new Set((await dbAll(`SELECT vm_id FROM vms WHERE owner_id = ?`, [req.session.userId])).map((r) => r.vm_id));
      if (task.created_by !== req.session.userId && !(task.target_type === 'vm' && owned.has(task.target_id))) {
        throw httpErr(404, 'Task not found');
      }
    }
    res.json(task);
  }));

  router.post('/api/tasks/:id/cancel', checkAuth, ah(async (req, res) => {
    const task = await ctx.taskEngine.getTask(parseInt(req.params.id, 10));
    if (!task) throw httpErr(404, 'Task not found');
    if (!isAdmin(req) && task.created_by !== req.session.userId) throw httpErr(403, 'Not your task');
    res.json(await ctx.taskEngine.cancelTask(task.id));
  }));

  router.post('/api/tasks/:id/retry', checkAuth, ah(async (req, res) => {
    const task = await ctx.taskEngine.getTask(parseInt(req.params.id, 10));
    if (!task) throw httpErr(404, 'Task not found');
    if (!isAdmin(req) && task.created_by !== req.session.userId) throw httpErr(403, 'Not your task');
    res.json(await ctx.taskEngine.retryTask(task.id));
  }));

  // ---- schedules ----
  router.get('/api/task-schedules', checkAuth, ah(async (req, res) => {
    const rows = await ctx.taskEngine.listSchedules();
    if (isAdmin(req)) return res.json(rows);
    const owned = new Set((await dbAll(`SELECT vm_id FROM vms WHERE owner_id = ?`, [req.session.userId])).map((r) => r.vm_id));
    res.json(rows.filter((s) => s.target_id == null || owned.has(s.target_id)));
  }));

  router.post('/api/task-schedules', checkAuth, ah(async (req, res) => {
    const taskType = String(req.body.task_type || '');
    if (!['vm.backup', 'vm.start', 'vm.stop', 'vm.restart'].includes(taskType)) {
      throw httpErr(400, 'Schedulable types: vm.backup, vm.start, vm.stop, vm.restart');
    }
    // Premium tier: backup schedules need Auto Backup, power schedules need Scheduled Power.
    if (taskType === 'vm.backup') needPremium('auto_backup');
    if (['vm.start', 'vm.stop', 'vm.restart'].includes(taskType)) needPremium('scheduled_power');
    let targetId = parseInt(req.body.target_id, 10) || null;
    if (targetId) await getVmOwned(req, targetId);
    const s = await ctx.taskEngine.createSchedule({
      name: String(req.body.name || 'Schedule').slice(0, 80),
      taskType, targetId,
      params: req.body.params || {},
      schedule: String(req.body.schedule || ''),
      createdBy: req.session.userId,
      enabled: req.body.enabled !== false,
    });
    res.json({ success: true, schedule: s });
  }));

  router.put('/api/task-schedules/:id', checkAuth, ah(async (req, res) => {
    const s = await ctx.taskEngine.getSchedule(parseInt(req.params.id, 10));
    if (!s) throw httpErr(404, 'Schedule not found');
    // Premium tier applies to edits too — you can't sneak a backup schedule
    // in by creating it as something else and PATCHing the type is not
    // supported, but enabling a paused premium schedule still counts.
    if (s.task_type === 'vm.backup' && req.body.enabled === true) needPremium('auto_backup');
    if (['vm.start', 'vm.stop', 'vm.restart'].includes(s.task_type) && req.body.enabled === true) needPremium('scheduled_power');
    if (!isAdmin(req)) {
      if (s.created_by !== req.session.userId) throw httpErr(403, 'Not your schedule');
      if (req.body.schedule && req.body.schedule !== s.schedule) throw httpErr(403, 'Only admins may edit schedule timing');
    }
    res.json({ success: true, schedule: await ctx.taskEngine.updateSchedule(s.id, req.body) });
  }));

  router.delete('/api/task-schedules/:id', checkAuth, ah(async (req, res) => {
    const s = await ctx.taskEngine.getSchedule(parseInt(req.params.id, 10));
    if (!s) throw httpErr(404, 'Schedule not found');
    if (!isAdmin(req) && s.created_by !== req.session.userId) throw httpErr(403, 'Not your schedule');
    await ctx.taskEngine.deleteSchedule(s.id);
    res.json({ success: true });
  }));

  router.post('/api/task-schedules/:id/run', checkAuth, ah(async (req, res) => {
    const s = await ctx.taskEngine.getSchedule(parseInt(req.params.id, 10));
    if (!s) throw httpErr(404, 'Schedule not found');
    // Premium tier: manually firing a premium-type schedule is usage too.
    if (s.task_type === 'vm.backup') needPremium('auto_backup');
    if (['vm.start', 'vm.stop', 'vm.restart'].includes(s.task_type)) needPremium('scheduled_power');
    if (!isAdmin(req) && s.created_by !== req.session.userId) throw httpErr(403, 'Not your schedule');
    const t = await ctx.taskEngine.runScheduleNow(s.id);
    res.json({ success: true, task_id: t.id });
  }));

  // ======================= PAGES =======================
  const page = (view, currentPage, title) => [
    (req, res) => res.render(view, { title, currentPage, user: { username: req.session.username, role: req.session.role } }),
  ];
  router.get('/admin/monitoring', checkAuth, checkAdmin, ...page('admin/monitoring', 'monitoring', 'Monitoring & Alerts - VNM Panel'));
  router.get('/admin/tasks', checkAuth, checkAdmin, ...page('admin/tasks', 'tasks', 'Task Automation - VNM Panel'));
  router.get('/admin/backups', checkAuth, checkAdmin, ...page('admin/backups', 'backups', 'Backup Center - VNM Panel'));
  router.get('/admin/storage', checkAuth, checkAdmin, ...page('admin/storage', 'storage', 'Storage Pools - VNM Panel'));
  router.get('/admin/network', checkAuth, checkAdmin, ...page('admin/network', 'network', 'Network Center - VNM Panel'));
  router.get('/admin/api-keys', checkAuth, checkAdmin, ...page('admin/api-keys', 'api-keys', 'API Keys - VNM Panel'));
  router.get('/admin/audit', checkAuth, checkAdmin, ...page('admin/audit', 'audit', 'Audit Log - VNM Panel'));
  router.get('/monitoring', checkAuth, ...page('users/monitoring', 'monitoring', 'My Monitoring - VNM Panel'));
  router.get('/tasks', checkAuth, ...page('users/tasks', 'tasks', 'My Tasks - VNM Panel'));

  return {
    router, ensureSchema,
    start() {
      ctx.taskEngine.start();
      ctx.monitoring.start();
      // Alert on failed tasks (roadmap: offline node / failed VM-start notifications).
      ctx.taskEngine.on('task-failed', (job) => {
        db.run(`INSERT INTO alert_events (rule_id, rule_name, scope, target_id, target_name, severity, message, value)
                VALUES (NULL, 'Task failed', 'task', ?, ?, 'warning', ?, NULL)`,
          [job.target_id, job.label || job.type, `Task "${job.label || job.type}" failed: ${(job.error || '').slice(0, 200)}`]);
      });
    },
  };
};
