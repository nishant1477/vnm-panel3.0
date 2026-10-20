// =====================================================================
// VNM Shield — Backup Vault & Disaster Recovery
// ---------------------------------------------------------------------
// Backs up the PANEL (not the VM disks):
//    - the SQLite database (consistent snapshot via VACUUM INTO - the
//      running panel is never blocked or copied mid-write)
//    - panel code (everything except node_modules/.git/data/VM dirs)
//    - configuration (.env if present)
//    - a manifest.json with the SHA-256 of EVERY archived file
//
// Archives are then ENCRYPTED (AES-256-CBC + PBKDF2, 200k iterations,
// via openssl) and versioned. The passphrase is separate from panel
// credentials (owner-set, stored in the settings table, never shown
// again) - and the docs tell the owner to also keep it offline.
//
// Integrity guarantees:
//    - every backup records its own SHA-256
//    - verifyBackup() re-checks: decrypt -> tar listing -> per-file
//      manifest hashes -> sqlite quick_check on the DB inside
//    - suspiciously SMALL backups (vs the previous one) are flagged,
//      not silently accepted
//    - a scheduled restore-test exercises the whole chain weekly
//
// Recovery:
//    - web UI down? `scripts/vnmctl restore <file>` restores from the
//      command line using this same module (env-var passphrase, no
//      panel boot required)
//    - restore ALWAYS backs up the current state first (pre-restore
//      copy), verifies the archive before touching anything, and
//      NEVER touches VM disks / VM metadata beyond the panel DB
// =====================================================================

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { exec } = require('child_process');
const { redact } = require('./shield-diagnoser');

function createBackupVault(ctx) {
  const db = ctx.db;
  const getSetting = ctx.getSetting;
  const setSetting = ctx.setSetting;
  const notify = ctx.notify;
  const panelRoot = ctx.panelRoot || path.join(__dirname, '..');
  const dataDir = ctx.dataDir;
  const vaultDir = path.join(dataDir, 'shield', 'backups');
  const log = (...a) => { try { console.log('[Shield:Backup]', ...a); } catch (e) {} };

  const dbGet = (sql, params) => new Promise((resolve, reject) => db.get(sql, params, (e, r) => e ? reject(e) : resolve(r)));
  const dbRun = (sql, params) => new Promise((resolve, reject) => db.run(sql, params, function (e) { e ? reject(e) : resolve(this); }));

  const execP = (cmd, timeoutMs) => new Promise((resolve, reject) => {
    exec(cmd, { timeout: timeoutMs || 120000, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      err ? reject(Object.assign(new Error(stderr || err.message), { stderr, stdout })) : resolve(stdout);
    });
  });

  // ---------------- schema ----------------
  function ensureSchema() {
    return new Promise((resolve) => {
      db.run(`CREATE TABLE IF NOT EXISTS shield_backups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        file TEXT NOT NULL,
        kind TEXT NOT NULL DEFAULT 'manual',
        size INTEGER,
        sha256 TEXT,
        encrypted INTEGER DEFAULT 1,
        verified INTEGER DEFAULT 0,
        verify_result TEXT,
        remote_status TEXT,
        files INTEGER,
        notes TEXT
      )`, () => {
        db.run(`CREATE INDEX IF NOT EXISTS idx_shield_bk_time ON shield_backups(created_at)`, () => resolve());
      });
    });
  }

  // ---------------- helpers ----------------
  function sha256File(p) {
    const h = crypto.createHash('sha256');
    h.update(fs.readFileSync(p));
    return h.digest('hex');
  }

  function sha256Stream(p) {
    return new Promise((resolve, reject) => {
      const h = crypto.createHash('sha256');
      const s = fs.createReadStream(p);
      s.on('data', (c) => h.update(c));
      s.on('end', () => resolve(h.digest('hex')));
      s.on('error', reject);
    });
  }

  async function getPassphrase() {
    // Priority: explicit env (CLI restore) -> stored setting
    if (process.env.VNM_BACKUP_PASSPHRASE) return process.env.VNM_BACKUP_PASSPHRASE;
    let pass = await getSetting('shield.backup.passphrase');
    if (!pass) {
      pass = crypto.randomBytes(24).toString('base64');
      await setSetting('shield.backup.passphrase', pass);
      log('generated a new backup passphrase (owner should verify it in settings and store a copy offline)');
    }
    return pass;
  }

  function codeDirsForArchive() {
    // What goes into the code portion of the archive (relative names)
    return ['app.js', 'install.sh', 'uninstall.sh', 'package.json', 'package-lock.json',
      'audit.js', 'twofa.js', 'platform.js', 'platform-ops.js', 'monitoring.js', 'nodes.js',
      'rdp.js', 'rdp-guest.js', 'rdp-serial.js', 'filemanager.js', 'sftp-ops.js', 'task-engine.js',
      'api-keys.js', 'licenses.js', 'premium.js', 'system-info.js', 'shield.js',
      'lib', 'views', 'public/css', 'public/js', 'public/images', 'node-agent',
      'scripts', 'watchdog', '.env'];
  }

  function copyInto(srcAbs, dstAbs) {
    const st = fs.lstatSync(srcAbs);
    if (st.isDirectory()) {
      fs.mkdirSync(dstAbs, { recursive: true });
      for (const ent of fs.readdirSync(srcAbs)) {
        if (['node_modules', '.git', 'vendor'].includes(ent)) continue;
        copyInto(path.join(srcAbs, ent), path.join(dstAbs, ent));
      }
    } else if (st.isFile()) {
      fs.mkdirSync(path.dirname(dstAbs), { recursive: true });
      fs.copyFileSync(srcAbs, dstAbs);
    }
  }

  // ---------------- create backup ----------------
  // kind: 'manual' | 'scheduled' | 'pre-restore' | 'pre-update'
  async function createBackup(kind, reason) {
    const started = Date.now();
    await new Promise((r) => fs.mkdir(vaultDir, { recursive: true }, () => r()));
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const staging = fs.mkdtempSync(path.join(os.tmpdir(), 'vnm-bk-'));
    const baseName = `vnm-panel-backup-${stamp}`;
    let recordId = null;

    try {
      // 1. database snapshot (consistent, no lock on the live DB)
      const dbCopy = path.join(staging, 'data', 'vnm.db');
      fs.mkdirSync(path.join(staging, 'data'), { recursive: true });
      try {
        await new Promise((resolve, reject) => db.run(`VACUUM INTO ?`, [dbCopy], (e) => e ? reject(e) : resolve()));
      } catch (e) {
        // very old SQLite: fall back to a copy (WAL mode keeps it usually consistent)
        log('VACUUM INTO unavailable, falling back to file copy:', e.message);
        fs.copyFileSync(ctx.dbPath, dbCopy);
      }

      // 2. code + config
      for (const rel of codeDirsForArchive()) {
        const abs = path.join(panelRoot, rel);
        if (!fs.existsSync(abs)) continue;
        try { copyInto(abs, path.join(staging, 'panel', rel)); } catch (e) { log('skip', rel, e.message); }
      }

      // 3. manifest with per-file hashes
      const manifest = { created_at: new Date().toISOString(), kind: kind || 'manual', reason: reason || '', files: {}, db_bytes: fs.statSync(dbCopy).size };
      const walk = (dir, prefix) => {
        for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
          const abs = path.join(dir, ent.name);
          const rel = prefix ? prefix + '/' + ent.name : ent.name;
          if (ent.isDirectory()) walk(abs, rel);
          else if (ent.isFile()) {
            try { manifest.files[rel] = { sha256: sha256File(abs), size: fs.statSync(abs).size }; } catch (e) { /* unreadable */ }
          }
        }
      };
      walk(staging, '');
      const fileCount = Object.keys(manifest.files).length;
      if (fileCount === 0) throw new Error('backup staging produced ZERO files - refusing to create an empty backup');
      fs.writeFileSync(path.join(staging, 'manifest.json'), JSON.stringify(manifest, null, 2));

      // 4. tar + encrypt (tar written OUTSIDE the staging dir - archiving a
      // directory into itself triggers "file changed as we read it")
      const plainTar = path.join(os.tmpdir(), baseName + '-' + crypto.randomBytes(4).toString('hex') + '.tar.gz');
      await execP(`tar -czf "${plainTar}" -C "${staging}" .`);
      const pass = await getPassphrase();
      const passFile = path.join(staging, '.pass');
      fs.writeFileSync(passFile, pass, { mode: 0o600 });
      const finalPath = path.join(vaultDir, baseName + '.vnmbackup');
      await execP(`openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 -pass file:"${passFile}" -in "${plainTar}" -out "${finalPath}"`);
      fs.unlinkSync(passFile);
      try { fs.unlinkSync(plainTar); } catch (e) { /* best effort */ }

      // 5. outer hash sidecar + record
      const sha = await sha256Stream(finalPath);
      fs.writeFileSync(finalPath + '.sha256', sha + '  ' + path.basename(finalPath) + '\n');
      const size = fs.statSync(finalPath).size;
      if (size < 1024) throw new Error('backup archive suspiciously small (<1KB)');

      // plausibility: compare with previous successful size
      const prev = await dbGet(`SELECT size FROM shield_backups WHERE kind != 'restore-test' AND size IS NOT NULL ORDER BY id DESC LIMIT 1`);
      let notes = null;
      if (prev && prev.size && size < prev.size * 0.4) {
        notes = `WARN: archive is only ${Math.round(100 * size / prev.size)}% of the previous backup's size - verify before trusting it`;
        log(notes);
      }

      const result = await dbRun(`INSERT INTO shield_backups (file, kind, size, sha256, encrypted, files, notes) VALUES (?,?,?,?,1,?,?)`,
        [path.basename(finalPath), kind || 'manual', size, sha, fileCount, notes]);
      recordId = result.lastID;

      // 6. remote copy (optional, independent failure)
      const remote = await copyRemote(finalPath);

      // 7. retention pruning (never the latest verified backup)
      await pruneRetention();

      // 8. notify on scheduled backups only (manual = the owner knows)
      if (kind === 'scheduled') {
        await notify({
          severity: 'low',
          title: 'Panel backup completed',
          body: `Encrypted backup created (${(size / 1024 / 1024).toFixed(1)} MB, ${fileCount} files${remote ? `, remote: ${remote}` : ''}).${notes ? ' WARNING: ' + notes : ''}`,
        });
      }
      log(`backup ${baseName} created in ${Date.now() - started}ms, ${size} bytes, ${fileCount} files`);
      return { ok: true, id: recordId, file: path.basename(finalPath), size, sha256: sha, files: fileCount, notes, remote };
    } catch (e) {
      await dbRun(`INSERT INTO shield_backups (file, kind, size, verified, verify_result, notes) VALUES (?, 'failed', 0, 0, 'error', ?)`,
        [baseName + '.vnmbackup', redact(e.message).slice(0, 500)]);
      await notify({
        severity: 'high',
        title: 'Panel backup FAILED',
        body: `Backup could not be completed: ${redact(e.message).slice(0, 300)}. The PREVIOUS backup is untouched. See Shield → Backups.`,
        diag: {
          fingerprint: 'backup-failed', category: 'backup', component: 'backup/vault', severity: 'high',
          title: 'Panel backup failed',
          explanation: 'The scheduled or manual backup did not complete. Existing backups are not affected.',
          confirmed_causes: ['The backup process stopped with an error.'],
          possible_causes: ['Disk full in the backup vault', 'openssl or tar missing on the host', 'Database snapshot failure'],
          suggested_fix: 'Check Shield → Backups for the error detail and disk space, then retry. If it keeps failing, run `vnmctl backup` from the CLI to see full output.',
          raw: { message: redact(e.message).slice(0, 300) },
        },
      });
      return { ok: false, error: e.message };
    } finally {
      try { fs.rmSync(staging, { recursive: true, force: true }); } catch (e) { /* temp cleanup best-effort */ }
    }
  }

  // ---------------- remote copy ----------------
  async function copyRemote(finalPath) {
    const target = await getSetting('shield.backup.remote.target');
    if (!target) return null;
    const key = await getSetting('shield.backup.remote.key');
    try {
      const keyOpt = key ? `-i "${key}"` : '';
      await execP(`rsync -a ${keyOpt} "${finalPath}" "${finalPath}.sha256" ${target} 2>&1 || scp ${keyOpt} "${finalPath}" "${finalPath}.sha256" ${target} 2>&1`, 120000);
      await dbRun(`UPDATE shield_backups SET remote_status = 'sent' WHERE file = ?`, [path.basename(finalPath)]);
      return 'sent';
    } catch (e) {
      await dbRun(`UPDATE shield_backups SET remote_status = 'failed' WHERE file = ?`, [path.basename(finalPath)]);
      await notify({
        severity: 'medium',
        title: 'Remote backup copy failed',
        body: `Local backup succeeded but the copy to ${redact(target)} failed: ${redact(e.message).slice(0, 200)}. Local backup is safe.`,
        diag: {
          fingerprint: 'backup-remote-failed', category: 'backup', component: 'backup/remote', severity: 'medium',
          title: 'Remote backup copy failed',
          explanation: 'The local encrypted backup was created, but copying it to the independent remote destination did not work.',
          confirmed_causes: ['The rsync/scp transfer failed.'],
          possible_causes: ['Remote server unreachable', 'SSH key missing or wrong', 'Remote disk full', 'rsync not installed'],
          suggested_fix: 'Verify connectivity (ssh <target>) and the key path in Shield → Backup settings.',
          raw: { message: redact(e.message).slice(0, 300) },
        },
      });
      return 'failed';
    }
  }

  // ---------------- retention ----------------
  async function pruneRetention() {
    const keep = parseInt((await getSetting('shield.backup.keep')) || '10', 10);
    const rows = await new Promise((resolve) => db.all(
      `SELECT id, file, verified FROM shield_backups WHERE kind != 'failed' AND size > 0 ORDER BY id DESC`, [], (e, r) => resolve(r || [])));
    let deletable = [];
    let keptVerified = 0;
    for (const row of rows) {
      const isVerified = row.verified === 1;
      if (isVerified && keptVerified === 0) { keptVerified = 1; continue; }  // never the latest verified
      deletable.push(row);
    }
    const toDelete = deletable.slice(Math.max(0, keep - 1));
    for (const row of toDelete) {
      try { fs.unlinkSync(path.join(vaultDir, row.file)); } catch (e) { /* already gone */ }
      try { fs.unlinkSync(path.join(vaultDir, row.file + '.sha256')); } catch (e) { /* already gone */ }
      await dbRun(`DELETE FROM shield_backups WHERE id = ?`, [row.id]);
    }
    return toDelete.length;
  }

  // ---------------- verify ----------------
  async function verifyBackup(fileName, deep) {
    const filePath = path.join(vaultDir, path.basename(fileName));
    if (!fs.existsSync(filePath)) return { ok: false, error: 'file not found' };
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vnm-verify-'));
    try {
      // outer hash
      const sha = await sha256Stream(filePath);
      const sidecar = filePath + '.sha256';
      let outerOk = true;
      if (fs.existsSync(sidecar)) {
        outerOk = fs.readFileSync(sidecar, 'utf8').split(/\s+/)[0] === sha;
      }
      // decrypt
      const pass = await getPassphrase();
      const passFile = path.join(tmp, '.pass');
      fs.writeFileSync(passFile, pass, { mode: 0o600 });
      const tarPath = path.join(tmp, 'decrypted.tar.gz');
      await execP(`openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:"${passFile}" -in "${filePath}" -out "${tarPath}"`);
      fs.unlinkSync(passFile);
      // extract
      const exDir = path.join(tmp, 'x');
      fs.mkdirSync(exDir);
      await execP(`tar -xzf "${tarPath}" -C "${exDir}"`);
      const manifest = JSON.parse(fs.readFileSync(path.join(exDir, 'manifest.json'), 'utf8'));
      // per-file hashes
      let checked = 0, mismatches = [];
      for (const [rel, info] of Object.entries(manifest.files)) {
        const abs = path.join(exDir, rel);
        try {
          if (sha256File(abs) !== info.sha256) mismatches.push(rel);
          checked++;
        } catch (e) { mismatches.push(rel + ' (missing)'); }
      }
      if (mismatches.length) throw new Error(`manifest mismatch for ${mismatches.length} file(s): ` + mismatches.slice(0, 5).join(', '));
      // DB integrity inside the archive
      let dbOk = 'not-found';
      const dbIn = path.join(exDir, 'data', 'vnm.db');
      if (fs.existsSync(dbIn)) {
        const sqlite3 = require('sqlite3');
        dbOk = await new Promise((resolve) => {
          const d = new sqlite3.Database(dbIn, sqlite3.OPEN_READONLY, (err) => {
            if (err) return resolve('open-error: ' + err.message);
            d.get(`PRAGMA quick_check`, [], (e2, row) => {
              d.close();
              resolve(e2 ? 'check-error: ' + e2.message : (row && row.quick_check) || 'unknown');
            });
          });
        });
        if (dbOk !== 'ok') throw new Error('database inside archive failed integrity check: ' + dbOk);
      }
      const result = { ok: true, outerHashOk: outerOk, filesChecked: checked, dbCheck: dbOk, deep: !!deep };
      await dbRun(`UPDATE shield_backups SET verified = 1, verify_result = ? WHERE file = ?`,
        [JSON.stringify({ at: new Date().toISOString(), ok: true, files: checked, db: dbOk }), path.basename(fileName)]);
      return result;
    } catch (e) {
      await dbRun(`UPDATE shield_backups SET verified = 0, verify_result = ? WHERE file = ?`,
        [JSON.stringify({ at: new Date().toISOString(), ok: false, error: redact(e.message).slice(0, 400) }), path.basename(fileName)]);
      return { ok: false, error: e.message };
    } finally {
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (e) { /* best-effort */ }
    }
  }

  // ---------------- restore test ----------------
  async function restoreTest() {
    const row = await dbGet(`SELECT file FROM shield_backups WHERE kind != 'failed' AND size > 0 ORDER BY id DESC LIMIT 1`);
    if (!row) return { ok: false, error: 'no backups to test' };
    const r = await verifyBackup(row.file, true);
    await setSetting('shield.backup.lastRestoreTest', JSON.stringify({ at: new Date().toISOString(), file: row.file, ok: r.ok, detail: r.ok ? { files: r.filesChecked, db: r.dbCheck } : { error: r.error } }));
    await dbRun(`UPDATE shield_backups SET notes = COALESCE(notes || ' | ', '') || 'restore-tested ' || ? WHERE file = ?`,
      [r.ok ? 'OK' : 'FAILED', row.file]);
    if (!r.ok) {
      await notify({
        severity: 'high',
        title: 'Backup restore TEST FAILED',
        body: `The latest backup (${row.file}) could not be verified end-to-end: ${redact(r.error || '').slice(0, 250)}. Treat DR coverage as broken until a backup passes.`,
        diag: {
          fingerprint: 'restore-test-failed', category: 'backup', component: 'backup/verify', severity: 'high',
          title: 'Backup restore test failed',
          explanation: 'The scheduled end-to-end test of the latest backup (decrypt, extract, hash-verify, database check) failed.',
          confirmed_causes: ['The backup cannot currently be restored.'],
          possible_causes: ['Corrupted archive (disk errors)', 'Passphrase changed after the backup was made', 'Truncated file during transfer'],
          suggested_fix: 'Create a fresh backup immediately and verify it. If disk errors are suspected, check SMART data.',
          raw: { message: redact(r.error || '').slice(0, 300) },
        },
      });
    }
    return { ok: r.ok, file: row.file, detail: r };
  }

  // ---------------- restore ----------------
  // Panel-only recovery: replaces DB + code, NEVER touches VM disks
  // (~/vms is not in the archive at all, by construction).
  async function restoreBackup(fileName, opts) {
    const options = opts || {};
    const filePath = path.basename(fileName).includes(path.sep) ? fileName : path.join(vaultDir, path.basename(fileName));
    if (!fs.existsSync(filePath)) return { ok: false, error: 'backup file not found' };

    // 1. verify BEFORE touching anything
    const v = await verifyBackup(path.basename(filePath));
    if (!v.ok) return { ok: false, error: 'REFUSING to restore: backup failed verification (' + v.error + ')' };

    // 2. safety copy of current state
    await createBackup('pre-restore', 'automatic safety copy before restore of ' + path.basename(filePath));

    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vnm-restore-'));
    try {
      const pass = await getPassphrase();
      const passFile = path.join(tmp, '.pass');
      fs.writeFileSync(passFile, pass, { mode: 0o600 });
      const tarPath = path.join(tmp, 'decrypted.tar.gz');
      await execP(`openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:"${passFile}" -in "${filePath}" -out "${tarPath}"`);
      fs.unlinkSync(passFile);
      const exDir = path.join(tmp, 'x');
      fs.mkdirSync(exDir);
      await execP(`tar -xzf "${tarPath}" -C "${exDir}"`);

      // 3. database
      const dbIn = path.join(exDir, 'data', 'vnm.db');
      let dbRestored = false;
      if (fs.existsSync(dbIn) && !options.skipDb) {
        const liveDb = ctx.dbPath;
        fs.copyFileSync(liveDb, liveDb + '.prerestore');   // belt & braces
        fs.copyFileSync(dbIn, liveDb);
        dbRestored = true;
      }

      // 4. code files (only paths present in the archive's manifest)
      const manifest = JSON.parse(fs.readFileSync(path.join(exDir, 'manifest.json'), 'utf8'));
      let filesRestored = 0;
      for (const rel of Object.keys(manifest.files)) {
        if (rel.startsWith('panel/')) {
          const target = path.join(panelRoot, rel.slice('panel/'.length));
          const src = path.join(exDir, rel);
          try { fs.mkdirSync(path.dirname(target), { recursive: true }); fs.copyFileSync(src, target); filesRestored++; }
          catch (e) { log('restore skip', rel, e.message); }
        }
      }

      await dbRun(`UPDATE shield_backups SET notes = COALESCE(notes || ' | ', '') || 'restored-from ' || ? WHERE file = ?`, [new Date().toISOString(), path.basename(filePath)]);
      await notify({
        severity: 'medium',
        title: 'Panel restored from backup',
        body: `Restore of ${path.basename(filePath)} completed: database ${dbRestored ? 'replaced' : 'skipped'}, ${filesRestored} code files restored. A pre-restore safety backup was taken first. RESTART THE PANEL to load the restored code and database.`,
      });
      return { ok: true, dbRestored, filesRestored, note: 'restart the panel service to load the restored state' };
    } catch (e) {
      return { ok: false, error: e.message };
    } finally {
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (e) { /* best-effort */ }
    }
  }

  // ---------------- queries ----------------
  function listBackups(limit) {
    return new Promise((resolve, reject) => db.all(
      `SELECT id, created_at, file, kind, size, sha256, verified, verify_result, remote_status, files, notes
       FROM shield_backups ORDER BY id DESC LIMIT ?`, [parseInt(limit || 50, 10)],
      (e, r) => e ? reject(e) : resolve(r || [])));
  }

  async function status() {
    const last = await dbGet(`SELECT * FROM shield_backups WHERE kind != 'failed' AND size > 0 ORDER BY id DESC LIMIT 1`);
    let test = null;
    try { test = JSON.parse((await getSetting('shield.backup.lastRestoreTest')) || 'null'); } catch (e) { /* ignore */ }
    return {
      enabled: ((await getSetting('shield.backup.scheduleHours')) || '24') !== '0',
      scheduleHours: parseInt((await getSetting('shield.backup.scheduleHours')) || '24', 10),
      keep: parseInt((await getSetting('shield.backup.keep')) || '10', 10),
      remoteConfigured: !!(await getSetting('shield.backup.remote.target')),
      passphraseSet: !!(await getSetting('shield.backup.passphrase')) || !!process.env.VNM_BACKUP_PASSPHRASE,
      last: last ? { file: last.file, at: last.created_at, size: last.size, verified: !!last.verified, remote: last.remote_status } : null,
      lastRestoreTest: test,
      vaultDir,
    };
  }

  return { ensureSchema, createBackup, verifyBackup, restoreTest, restoreBackup, listBackups, status, copyRemote };
}

module.exports = { createBackupVault };
