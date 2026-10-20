// =====================================================================
// VNM Shield — Anti-Tamper File Integrity Engine
// ---------------------------------------------------------------------
// Establishes a trusted baseline (SHA-256 + size + mode) for every
// security-critical panel file:
//   - application code   (all top-level .js modules)
//   - templates          (views/**/*.ejs)
//   - client code        (public/css/*.css, public/js/*.js)
//   - installers/services (install.sh, uninstall.sh, unit files)
//   - node agent         (node-agent/*.js + node-agent/lib/*.js)
// node_modules and mutable data (DB, VM disks, logs) are deliberately
// NOT baselined - they change legitimately.
//
// Every scan compares live files against the baseline and records the
// exact delta (added / removed / content-modified / mode-changed) into
// a permanent history table.
//
// Protection modes (setting shield.integrity.mode):
//   off        - engine idle (still scannable manually)
//   monitor    - alert on changes, change nothing (default)
//   enforce    - alert AND auto-restore modified/removed files from
//                the trusted vault (only after re-verifying the vault
//                copy's own hash against the baseline)
//
// Maintenance mode (shield.maintenance) pauses scheduled scanning so
// legitimate updates don't page anyone - it is time-boxed and the
// dashboard shows it loudly while active.
// =====================================================================

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const MAX_FILE_SIZE = 20 * 1024 * 1024; // never hash anything absurd

function createIntegrity(ctx) {
  const db = ctx.db;
  const panelRoot = ctx.panelRoot || path.join(__dirname, '..');
  const vaultDir = ctx.vaultDir || path.join(ctx.dataDir, 'shield', 'vault');
  const getSetting = ctx.getSetting;
  const setSetting = ctx.setSetting;
  const log = (...a) => { try { console.log('[Shield:Integrity]', ...a); } catch (e) {} };

  const dbGet = (sql, params) => new Promise((resolve, reject) => db.get(sql, params, (e, r) => e ? reject(e) : resolve(r)));
  const dbAll = (sql, params) => new Promise((resolve, reject) => db.all(sql, params, (e, r) => e ? reject(e) : resolve(r || [])));
  const dbRun = (sql, params) => new Promise((resolve, reject) => db.run(sql, params, function (e) { e ? reject(e) : resolve(this); }));

  // ---------------- manifest ----------------
  // Which files count as critical. Relative to panelRoot.
  function buildManifest() {
    const out = [];
    const pushFile = (rel) => {
      const abs = path.join(panelRoot, rel);
      try { if (fs.statSync(abs).isFile()) out.push(rel); } catch (e) { /* not present on this install */ }
    };
    const pushDir = (dirRel, exts, recursive) => {
      const absDir = path.join(panelRoot, dirRel);
      let entries;
      try { entries = fs.readdirSync(absDir, { withFileTypes: true }); } catch (e) { return; }
      for (const ent of entries) {
        const rel = path.join(dirRel, ent.name);
        if (ent.isDirectory()) {
          if (recursive && !['node_modules', '.git', 'vendor'].includes(ent.name)) pushDir(rel, exts, recursive);
        } else if (ent.isFile() && (exts.length === 0 || exts.includes(path.extname(ent.name)))) {
          out.push(rel);
        }
      }
    };

    // top-level application modules
    pushDir('.', ['.js'], false);
    // views (recursive, admin + users + partials)
    pushDir('views', ['.ejs'], true);
    // client assets (skip vendored novnc - it is 3rd-party static)
    pushDir(path.join('public', 'css'), ['.css'], false);
    pushDir(path.join('public', 'js'), ['.js'], false);
    // installers / units / CLI
    pushFile('install.sh'); pushFile('uninstall.sh');
    pushFile('package.json');
    pushFile(path.join('scripts', 'lockdown.sh'));
    pushFile(path.join('scripts', 'vnmctl'));
    pushFile(path.join('watchdog', 'vnm-watchdog.js'));
    pushFile(path.join('watchdog', 'vnm-watchdog.service'));
    // node agent (runs privileged on nodes - definitely critical)
    pushDir('node-agent', ['.js'], false);
    pushDir(path.join('node-agent', 'lib'), ['.js'], false);
    pushFile(path.join('node-agent', 'install.sh'));
    pushFile(path.join('node-agent', 'vnm-agent.service'));
    // shield itself
    pushDir('lib', ['.js'], false);
    return out.sort();
  }

  function sha256File(absPath) {
    const st = fs.statSync(absPath);
    if (st.size > MAX_FILE_SIZE) throw new Error('file too large to baseline: ' + st.size);
    const h = crypto.createHash('sha256');
    h.update(fs.readFileSync(absPath));
    return { hash: h.digest('hex'), size: st.size, mode: (st.mode & 0o777) };
  }

  function vaultPathFor(relPath) {
    return path.join(vaultDir, relPath.replace(/\.\./g, '__') + '.vault');
  }

  // ---------------- schema ----------------
  function ensureSchema() {
    return new Promise((resolve) => {
      db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS shield_baseline (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          rel_path TEXT UNIQUE NOT NULL,
          sha256 TEXT NOT NULL,
          size INTEGER,
          mode INTEGER,
          baselined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          baseline_version INTEGER DEFAULT 1
        )`, () => {
          db.run(`CREATE TABLE IF NOT EXISTS shield_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            rel_path TEXT NOT NULL,
            event_type TEXT NOT NULL,
            old_sha256 TEXT, new_sha256 TEXT,
            old_mode INTEGER, new_mode INTEGER,
            size INTEGER,
            source TEXT,
            detail TEXT
          )`, () => {
            db.run(`CREATE INDEX IF NOT EXISTS idx_shield_ev_path ON shield_events(rel_path)`, () => {
              db.run(`CREATE INDEX IF NOT EXISTS idx_shield_ev_time ON shield_events(created_at)`, () => resolve());
            });
          });
        });
      });
    });
  }

  async function recordEvent(relPath, eventType, extra, source) {
    const e = extra || {};
    await dbRun(`INSERT INTO shield_events (rel_path, event_type, old_sha256, new_sha256, old_mode, new_mode, size, source, detail)
      VALUES (?,?,?,?,?,?,?,?,?)`,
      [relPath, eventType, e.oldHash || null, e.newHash || null, e.oldMode || null, e.newMode || null,
       e.size || null, source || 'scan', e.detail ? JSON.stringify(e.detail).slice(0, 2000) : null]);
  }

  // ---------------- baseline ----------------
  async function establishBaseline(reason) {
    await new Promise((resolve) => fs.mkdir(vaultDir, { recursive: true }, () => resolve()));
    const manifest = buildManifest();
    let stored = 0;
    const version = Date.now();
    await dbRun(`DELETE FROM shield_baseline`);
    for (const rel of manifest) {
      const abs = path.join(panelRoot, rel);
      try {
        const info = sha256File(abs);
        await dbRun(`INSERT INTO shield_baseline (rel_path, sha256, size, mode, baseline_version) VALUES (?,?,?,?,?)`,
          [rel, info.hash, info.size, info.mode, version]);
        // trusted vault copy (mirrors the directory structure)
        const vp = vaultPathFor(rel);
        await new Promise((resolve) => fs.mkdir(path.dirname(vp), { recursive: true }, () => resolve()));
        fs.copyFileSync(abs, vp);
        fs.chmodSync(vp, 0o600);
        stored++;
      } catch (e) {
        log('baseline skip', rel, e.message);
      }
    }
    await recordEvent('(baseline)', 'baseline', { size: stored, detail: { reason: reason || 'manual', files: stored } }, 'baseline');
    await setSetting('shield.integrity.lastBaseline', new Date().toISOString());
    return { files: stored, version };
  }

  async function baselineInfo() {
    const count = await dbGet(`SELECT COUNT(*) AS n, MAX(baseline_version) AS v, MAX(baselined_at) AS at FROM shield_baseline`);
    return { files: count.n || 0, version: count.v || null, at: count.at || null };
  }

  // ---------------- scan ----------------
  // Returns { changes: [...], mode, maintenance, clean }
  async function scan(reason) {
    const source = reason || 'manual';
    const mode = (await getSetting('shield.integrity.mode')) || 'monitor';
    const maintenance = await isMaintenance();
    if (maintenance && source === 'schedule') {
      return { changes: [], mode, maintenance: true, clean: true, skipped: 'maintenance' };
    }

    const baseline = await dbAll(`SELECT * FROM shield_baseline`);
    const seen = new Set();
    const changes = [];

    for (const row of baseline) {
      seen.add(row.rel_path);
      const abs = path.join(panelRoot, row.rel_path);
      let current = null;
      try { current = sha256File(abs); } catch (e) { current = null; }

      if (!current) {
        changes.push({ path: row.rel_path, type: 'removed', oldHash: row.sha256, severity: 'critical' });
        await recordEvent(row.rel_path, 'removed', { oldHash: row.sha256, oldMode: row.mode }, source);
        continue;
      }
      if (current.hash !== row.sha256) {
        changes.push({ path: row.rel_path, type: 'modified', oldHash: row.sha256, newHash: current.hash, severity: 'critical' });
        await recordEvent(row.rel_path, 'modified', { oldHash: row.sha256, newHash: current.hash }, source);
      } else if (current.mode !== row.mode) {
        changes.push({ path: row.rel_path, type: 'mode_changed', oldMode: row.mode, newMode: current.mode, severity: 'medium' });
        await recordEvent(row.rel_path, 'mode_changed', { oldMode: row.mode, newMode: current.mode }, source);
      }
    }

    // Files added into critical locations that were never baselined.
    // (Only checks the same top-level scopes the manifest covers.)
    const manifest = new Set(buildManifest());
    for (const rel of manifest) {
      if (!seen.has(rel)) {
        const abs = path.join(panelRoot, rel);
        try {
          const info = sha256File(abs);
          const row = await dbGet(`SELECT 1 FROM shield_baseline WHERE rel_path = ?`, [rel]);
          if (!row) {
            changes.push({ path: rel, type: 'added', newHash: info.hash, severity: 'high' });
            await recordEvent(rel, 'added', { newHash: info.hash }, source);
          }
        } catch (e) { /* unreadable */ }
      }
    }

    // ---- enforce mode: safe auto-restore ----
    let restored = [];
    if (mode === 'enforce' && changes.length) {
      for (const ch of changes) {
        if (ch.type === 'modified' || ch.type === 'removed') {
          try {
            const r = await restoreFile(ch.path, 'enforce-auto');
            if (r.restored) restored.push(ch.path);
          } catch (e) { log('auto-restore failed', ch.path, e.message); }
        }
      }
    }

    if (!changes.length) {
      await recordEvent('(scan)', 'scan_clean', { size: baseline.length }, source);
      await setSetting('shield.integrity.lastScan', new Date().toISOString());
      await setSetting('shield.integrity.lastResult', 'clean');
    } else {
      await setSetting('shield.integrity.lastScan', new Date().toISOString());
      await setSetting('shield.integrity.lastResult', `${changes.length} change(s)`);
    }

    return { changes, mode, maintenance, clean: changes.length === 0, restored, baselineFiles: baseline.length };
  }

  // ---------------- restore ----------------
  // Restores ONE file from the trusted vault. The vault copy is
  // re-verified against the baseline hash first - a tampered vault
  // never restores anything.
  async function restoreFile(relPath, source) {
    const row = await dbGet(`SELECT * FROM shield_baseline WHERE rel_path = ?`, [relPath]);
    if (!row) throw new Error('No baseline for ' + relPath);
    const vp = vaultPathFor(relPath);
    if (!fs.existsSync(vp)) throw new Error('No trusted vault copy for ' + relPath);
    const vaultInfo = sha256File(vp);
    if (vaultInfo.hash !== row.sha256) {
      await recordEvent(relPath, 'vault_mismatch', { oldHash: row.sha256, newHash: vaultInfo.hash }, source || 'restore');
      throw new Error('Vault copy does not match baseline - refusing to restore ' + relPath);
    }
    const abs = path.join(panelRoot, relPath);
    await new Promise((resolve) => fs.mkdir(path.dirname(abs), { recursive: true }, () => resolve()));
    fs.copyFileSync(vp, abs);
    fs.chmodSync(abs, row.mode || 0o644);
    await recordEvent(relPath, 'restored', { oldHash: row.sha256, newHash: vaultInfo.hash }, source || 'restore');
    return { restored: true, path: relPath };
  }

  async function restoreAll(changes, source) {
    const results = [];
    for (const ch of (changes || [])) {
      if (ch.type === 'modified' || ch.type === 'removed') {
        try { results.push(await restoreFile(ch.path, source)); }
        catch (e) { results.push({ restored: false, path: ch.path, error: e.message }); }
      }
    }
    return results;
  }

  // ---------------- maintenance mode ----------------
  // Time-boxed (default 60 min) so it can never silently disable
  // protection forever.
  async function isMaintenance() {
    const until = await getSetting('shield.maintenance.until');
    if (!until) return false;
    const t = new Date(until).getTime();
    if (!t || t < Date.now()) {
      if (t && t < Date.now()) await setSetting('shield.maintenance.until', '');
      return false;
    }
    return true;
  }

  async function setMaintenance(minutes, by) {
    if (!minutes || minutes <= 0) {
      await setSetting('shield.maintenance.until', '');
      await recordEvent('(maintenance)', 'maintenance_off', { detail: { by: by || 'manual' } }, 'maintenance');
      return { active: false };
    }
    const mins = Math.min(parseInt(minutes, 10) || 60, 24 * 60);
    const until = new Date(Date.now() + mins * 60 * 1000).toISOString();
    await setSetting('shield.maintenance.until', until);
    await recordEvent('(maintenance)', 'maintenance_on', { detail: { by: by || 'manual', minutes: mins, until } }, 'maintenance');
    return { active: true, until, minutes: mins };
  }

  // ---------------- history / queries ----------------
  function history(limit) {
    return new Promise((resolve, reject) => db.all(
      `SELECT * FROM shield_events ORDER BY id DESC LIMIT ?`, [parseInt(limit || 100, 10)],
      (e, r) => e ? reject(e) : resolve(r || [])));
  }

  async function status() {
    const mode = (await getSetting('shield.integrity.mode')) || 'monitor';
    const info = await baselineInfo();
    return {
      mode,
      maintenance: await isMaintenance(),
      baseline: info,
      lastScan: await getSetting('shield.integrity.lastScan'),
      lastResult: await getSetting('shield.integrity.lastResult'),
      scheduled: (await getSetting('shield.integrity.scheduleMinutes')) !== '0',
      scheduleMinutes: parseInt((await getSetting('shield.integrity.scheduleMinutes')) || '15', 10),
    };
  }

  return { ensureSchema, buildManifest, establishBaseline, scan, restoreFile, restoreAll, setMaintenance, isMaintenance, history, status, baselineInfo };
}

module.exports = { createIntegrity };
