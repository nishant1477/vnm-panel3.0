// =====================================================================
// VNM Shield — Secure Updates & Installer Protection
// ---------------------------------------------------------------------
// Release format:
//   <release>.zip        - the new panel files
//   <release>.json       - manifest: { version, files: {path: sha256},
//                         removed: [paths], signature }
//   signature            - ed25519 over the canonical manifest JSON
//                          (without the signature field), made with
//                          the project release key. The PUBLIC half is
//                          embedded below; the private key never ships.
//   Owner-signed keys    - the owner can override the public key in
//                          settings (shield.update.publicKey) to sign
//                          their own internal releases.
//
// Update flow (all-or-nothing, single-writer):
//   1. JOB LOCK        - O_EXCL lock file: only one update/repair job
//                        can touch the panel at a time
//   2. PREFLIGHT       - node version, disk headroom, write access,
//                        QEMU present (warn-only), DB reachable
//   3. PRE-UPDATE BACKUP - encrypted vault backup ('pre-update')
//   4. VERIFY          - signature, then per-file SHA-256 of every
//                        file inside the zip BEFORE anything is copied
//   5. STAGED APPLY    - extract to temp; snapshot every file that
//                        will change into a rollback dir; then swap
//   6. POST-VALIDATE   - node --check on every shipped .js; a bad
//                        update is rolled back immediately
//   7. HISTORY         - every attempt recorded with outcome + detail
//
// The panel does not restart itself mid-request: the final word is
// "restart required" (systemd/watchdog/vnmctl does the restart, and
// vnmctl update can drive the whole flow including restart).
// =====================================================================

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { exec } = require('child_process');
const { redact } = require('./shield-diagnoser');

// Built-in project release public key (ed25519, SPKI PEM).
// Private counterpart lives with the maintainer only.
const BUILTIN_RELEASE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAL7QWTV+f50FVXGztNFHYl5PN+LrMD1pi+0LTKOOlpKI=
-----END PUBLIC KEY-----`;

function createUpdater(ctx) {
  const db = ctx.db;
  const getSetting = ctx.getSetting;
  const setSetting = ctx.setSetting;
  const notify = ctx.notify;
  const backupVault = ctx.backupVault;
  const panelRoot = ctx.panelRoot || path.join(__dirname, '..');
  const dataDir = ctx.dataDir;
  const log = (...a) => { try { console.log('[Shield:Updater]', ...a); } catch (e) {} };

  const dbRun = (sql, params) => new Promise((resolve, reject) => db.run(sql, params, function (e) { e ? reject(e) : resolve(this); }));
  const dbGet = (sql, params) => new Promise((resolve, reject) => db.get(sql, params, (e, r) => e ? reject(e) : resolve(r)));

  const execP = (cmd, timeoutMs) => new Promise((resolve, reject) => {
    exec(cmd, { timeout: timeoutMs || 60000, maxBuffer: 2 * 1024 * 1024, cwd: panelRoot }, (err, stdout, stderr) =>
      err ? reject(new Error((stderr || err.message).slice(0, 400))) : resolve(stdout));
  });

  // ---------------- schema ----------------
  function ensureSchema() {
    return new Promise((resolve) => {
      db.run(`CREATE TABLE IF NOT EXISTS shield_updates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        from_version TEXT, to_version TEXT,
        outcome TEXT NOT NULL,
        files_changed INTEGER,
        detail TEXT,
        rolled_back INTEGER DEFAULT 0
      )`, () => resolve());
    });
  }

  // ---------------- job lock ----------------
  const lockPath = path.join(dataDir, 'shield', 'update.lock');
  async function acquireLock(owner) {
    await new Promise((r) => fs.mkdir(path.dirname(lockPath), { recursive: true }, () => r()));
    try {
      const fd = fs.openSync(lockPath, 'wx');
      fs.writeSync(fd, JSON.stringify({ owner: owner || 'update', pid: process.pid, at: new Date().toISOString() }));
      fs.closeSync(fd);
      return true;
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      // stale lock? (>2h old)
      try {
        const st = fs.statSync(lockPath);
        if (Date.now() - st.mtimeMs > 2 * 3600 * 1000) { fs.unlinkSync(lockPath); return acquireLock(owner); }
      } catch (e2) { /* raced */ }
      return false;
    }
  }
  function releaseLock() { try { fs.unlinkSync(lockPath); } catch (e) { /* not held */ } }

  // ---------------- preflight ----------------
  async function preflight() {
    const checks = [];
    const nodeMajor = parseInt(process.versions.node.split('.')[0], 10);
    checks.push({ check: 'node', ok: nodeMajor >= 18, detail: `Node ${process.versions.node} (>=18 required)` });
    try { await dbGet(`SELECT 1 AS ok`); checks.push({ check: 'database', ok: true, detail: 'reachable' }); }
    catch (e) { checks.push({ check: 'database', ok: false, detail: e.message }); }
    try {
      const probe = path.join(panelRoot, '.vnm-write-probe');
      fs.writeFileSync(probe, 'ok'); fs.unlinkSync(probe);
      checks.push({ check: 'write-access', ok: true, detail: 'panel directory writable' });
    } catch (e) { checks.push({ check: 'write-access', ok: false, detail: e.message }); }
    try {
      const df = await execP(`df -m "${panelRoot}" | tail -n 1 | awk '{print $4}'`);
      const freeMb = parseInt(df.trim(), 10);
      checks.push({ check: 'disk', ok: freeMb > 1024, detail: `${freeMb} MB free (need >1024)` });
    } catch (e) { checks.push({ check: 'disk', ok: false, detail: e.message }); }
    try { await execP('command -v qemu-system-x86_64'); checks.push({ check: 'qemu', ok: true, detail: 'present (warn-only)', warnOnly: true }); }
    catch (e) { checks.push({ check: 'qemu', ok: true, detail: 'NOT found - VM features will fail, update itself unaffected', warnOnly: true }); }
    return { ok: checks.every((c) => c.ok || c.warnOnly), checks };
  }

  // ---------------- signature verification ----------------
  function canonicalManifest(m) {
    const copy = { version: m.version, files: m.files, removed: m.removed || [] };
    // stable key order, no whitespace
    const sortDeep = (o) => {
      if (Array.isArray(o)) return o.map(sortDeep);
      if (o && typeof o === 'object') {
        return Object.keys(o).sort().reduce((acc, k) => { acc[k] = sortDeep(o[k]); return acc; }, {});
      }
      return o;
    };
    return JSON.stringify(sortDeep(copy));
  }

  async function verifyRelease(manifest, zipPath) {
    const errors = [];
    // 1. structure
    if (!manifest || !manifest.version || !manifest.files || typeof manifest.files !== 'object') {
      return { ok: false, errors: ['manifest missing version/files'] };
    }
    // 2. signature (ed25519)
    const pubKeyPem = (await getSetting('shield.update.publicKey')) || BUILTIN_RELEASE_PUBLIC_KEY;
    let signatureOk = false;
    if (manifest.signature) {
      try {
        const verified = crypto.verify(null, Buffer.from(canonicalManifest(manifest)), crypto.createPublicKey(pubKeyPem), Buffer.from(manifest.signature, 'base64'));
        signatureOk = verified;
        if (!verified) errors.push('signature does NOT match this manifest (wrong key or tampered manifest)');
      } catch (e) {
        errors.push('signature verification error: ' + e.message);
      }
    } else {
      errors.push('manifest is UNSIGNED');
    }
    // 3. trust policy: signed releases always OK; unsigned only with explicit owner opt-in
    if (!signatureOk) {
      const allowUnsigned = (await getSetting('shield.update.allowUnsigned')) === '1';
      if (!allowUnsigned) {
        errors.push('unsigned/invalidally-signed releases are refused (enable only if you know why)');
      }
    }
    // 4. zip per-file hashes
    if (fs.existsSync(zipPath)) {
      try {
        const listing = await execP(`unzip -l "${zipPath}"`);
        const inZip = new Set(listing.split('\n').map((l) => l.trim().split(/\s+/).slice(3).join(' ')).filter((f) => f && !f.endsWith('/')));
        let checked = 0;
        for (const [rel, expected] of Object.entries(manifest.files)) {
          if (!inZip.has(rel)) { errors.push(`manifest lists file missing from zip: ${rel}`); continue; }
          // hash extracted copy (single unzip to temp of just this file)
          const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vnm-rel-'));
          try {
            await execP(`unzip -p "${zipPath}" "${rel}" > "${tmp}/f"`);
            const h = crypto.createHash('sha256').update(fs.readFileSync(path.join(tmp, 'f'))).digest('hex');
            if (h !== expected) errors.push(`hash mismatch for ${rel}`);
            checked++;
          } finally { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (e) { /* */ } }
        }
        if (checked === 0) errors.push('no files could be verified');
      } catch (e) {
        errors.push('zip inspection failed: ' + e.message);
      }
    } else {
      errors.push('zip file not found');
    }
    return { ok: errors.length === 0, errors, signatureOk, files: Object.keys(manifest.files || {}).length };
  }

  // ---------------- apply update ----------------
  async function applyUpdate(zipPath, manifestPath, actor) {
    if (!(await acquireLock('update'))) {
      return { ok: false, error: 'Another update/repair job is already running (job lock held). Try again later.' };
    }
    let record = null;
    const rollbackDir = path.join(dataDir, 'shield', 'rollback', String(Date.now()));
    let filesChanged = 0;
    try {
      // 1. preflight
      const pre = await preflight();
      if (!pre.ok) throw new Error('preflight failed: ' + pre.checks.filter((c) => !c.ok).map((c) => `${c.check} (${c.detail})`).join('; '));

      // 2. read manifest + verify
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      const verification = await verifyRelease(manifest, zipPath);
      if (!verification.ok) {
        await dbRun(`INSERT INTO shield_updates (from_version, to_version, outcome, detail) VALUES (?,?,?,?)`,
          [process.env.PANEL_VERSION || 'unknown', manifest.version || 'unknown', 'refused', JSON.stringify(verification.errors).slice(0, 2000)]);
        await notify({
          severity: 'high',
          title: 'Update REFUSED: release verification failed',
          body: `The release could not be verified and was NOT installed: ${verification.errors.slice(0, 3).join('; ')}. No files were changed.`,
          diag: {
            fingerprint: 'update-refused', category: 'update', component: 'update/verify', severity: 'high',
            title: 'Release verification failed',
            explanation: 'The offered update archive failed signature and/or checksum verification, so the updater refused to touch the installation.',
            confirmed_causes: ['The release is unsigned, signed by an unknown key, or its contents do not match the signed manifest.'],
            possible_causes: ['Corrupted download', 'Release from an untrusted source', 'Tampering attempt'],
            suggested_fix: 'Re-download the release from the official source and verify its checksum out-of-band (sha256sum). Unsigned installs can be enabled explicitly in settings if you build your own releases.',
            raw: { message: verification.errors.join('; ').slice(0, 300) },
          },
        });
        return { ok: false, stage: 'verify', errors: verification.errors };
      }

      // 3. pre-update backup
      const backup = await backupVault.createBackup('pre-update', 'before update to ' + manifest.version);
      if (!backup.ok) throw new Error('pre-update backup failed: ' + backup.error);

      // 4. staged apply
      const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'vnm-upd-'));
      const addedFiles = [], changedFiles = [];
      try {
        await execP(`unzip -q -o "${zipPath}" -d "${stage}"`);
        fs.mkdirSync(rollbackDir, { recursive: true });
        // snapshot current versions of every file about to change
        for (const rel of Object.keys(manifest.files)) {
          const target = path.join(panelRoot, rel);
          if (fs.existsSync(target)) {
            const snap = path.join(rollbackDir, rel);
            fs.mkdirSync(path.dirname(snap), { recursive: true });
            fs.copyFileSync(target, snap);
            changedFiles.push(rel);
          } else {
            addedFiles.push(rel);   // brand-new files: rollback must REMOVE them
          }
        }
        // syntax-validate JS files BEFORE copying
        const jsFiles = Object.keys(manifest.files).filter((f) => f.endsWith('.js'));
        for (const rel of jsFiles) {
          const src = path.join(stage, rel);
          if (!fs.existsSync(src)) continue;
          await execP(`node --check "${src}"`);
        }
        // copy new files
        for (const rel of Object.keys(manifest.files)) {
          const src = path.join(stage, rel);
          const target = path.join(panelRoot, rel);
          fs.mkdirSync(path.dirname(target), { recursive: true });
          fs.copyFileSync(src, target);
          filesChanged++;
        }
        // removals (snapshotted for rollback as well)
        for (const rel of (manifest.removed || [])) {
          const target = path.join(panelRoot, rel);
          if (fs.existsSync(target)) {
            const snap = path.join(rollbackDir, rel);
            fs.mkdirSync(path.dirname(snap), { recursive: true });
            fs.copyFileSync(target, snap);
            fs.unlinkSync(target);
            filesChanged++;
          }
        }
        // rollback manifest: what to restore + what to delete
        fs.writeFileSync(path.join(rollbackDir, 'rollback-manifest.json'),
          JSON.stringify({ added: addedFiles, changed: changedFiles, removed: manifest.removed || [], at: new Date().toISOString(), version: manifest.version }, null, 2));
      } finally {
        try { fs.rmSync(stage, { recursive: true, force: true }); } catch (e) { /* */ }
      }

      // 5. post-validate: every shipped .js must parse against the LIVE tree
      let syntaxFails = [];
      for (const rel of Object.keys(manifest.files).filter((f) => f.endsWith('.js'))) {
        try { await execP(`node --check "${path.join(panelRoot, rel)}"`); }
        catch (e) { syntaxFails.push(rel); }
      }
      if (syntaxFails.length) {
        const rb = await rollbackFrom(rollbackDir, syntaxFails);
        throw new Error(`post-update syntax check failed for ${syntaxFails.length} file(s); rolled back automatically: ${syntaxFails.slice(0, 3).join(', ')}`);
      }

      await dbRun(`INSERT INTO shield_updates (from_version, to_version, outcome, files_changed, detail) VALUES (?,?,?,?,?)`,
        [process.env.PANEL_VERSION || 'unknown', manifest.version, 'success', filesChanged,
         JSON.stringify({ backup: backup.file, rolledBack: false }).slice(0, 1000)]);
      await notify({
        severity: 'low',
        title: `Panel updated to ${manifest.version}`,
        body: `Update applied and validated (${filesChanged} files). Pre-update backup: ${backup.file}. RESTART the panel service to load the new code (systemctl restart vnm-panel or vnmctl restart).`,
      });
      return { ok: true, version: manifest.version, filesChanged, backup: backup.file, restartRequired: true };
    } catch (e) {
      await dbRun(`INSERT INTO shield_updates (from_version, to_version, outcome, files_changed, detail, rolled_back) VALUES (?,?,?,?,?,1)`,
        [process.env.PANEL_VERSION || 'unknown', 'unknown', 'failed', filesChanged, redact(e.message).slice(0, 1500)]);
      await notify({
        severity: 'high',
        title: 'Update FAILED - installation unchanged or rolled back',
        body: `Update did not complete: ${redact(e.message).slice(0, 300)}. A pre-update backup exists; failed file changes were rolled back automatically. See Shield → Updates.`,
        diag: {
          fingerprint: 'update-failed', category: 'update', component: 'update/apply', severity: 'high',
          title: 'Update failed',
          explanation: 'The update process stopped before or during the file swap. Changed files were restored from the automatic rollback snapshot.',
          confirmed_causes: ['The update did not complete successfully.'],
          possible_causes: ['Preflight failure (disk, permissions, DB)', 'New code failed syntax validation', 'Release verification failed'],
          suggested_fix: 'Read the failure detail in Shield → Updates. The panel continues on the previous version; retry after fixing the cause.',
          raw: { message: redact(e.message).slice(0, 300) },
        },
      });
      return { ok: false, error: e.message, filesChanged };
    } finally {
      releaseLock();
    }
  }

  async function rollbackFrom(rollbackDir, onlyFiles) {
    let restored = 0, removed = 0;
    // NEW-style snapshots carry a manifest: restore changed files,
    // DELETE files the update added, keep everything else
    const meta = path.join(rollbackDir, 'rollback-manifest.json');
    if (fs.existsSync(meta)) {
      try {
        const m = JSON.parse(fs.readFileSync(meta, 'utf8'));
        for (const rel of (m.added || [])) {
          if (onlyFiles && !onlyFiles.includes(rel)) continue;
          const target = path.join(panelRoot, rel);
          try { fs.unlinkSync(target); removed++; } catch (e) { /* already gone */ }
        }
      } catch (e) { /* fall through to dir walk */ }
    }
    const walk = (dir, prefix) => {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        if (ent.name === 'rollback-manifest.json') continue;
        const abs = path.join(dir, ent.name);
        const rel = prefix ? prefix + '/' + ent.name : ent.name;
        if (ent.isDirectory()) walk(abs, rel);
        else {
          if (onlyFiles && !onlyFiles.includes(rel)) continue;
          const target = path.join(panelRoot, rel);
          fs.mkdirSync(path.dirname(target), { recursive: true });
          fs.copyFileSync(abs, target);
          restored++;
        }
      }
    };
    if (fs.existsSync(rollbackDir)) walk(rollbackDir, '');
    return { restored, removed };
  }

  // Roll back the LAST update using the most recent rollback snapshot
  async function rollbackLastUpdate(actor) {
    const base = path.join(dataDir, 'shield', 'rollback');
    if (!fs.existsSync(base)) return { ok: false, error: 'no rollback snapshots exist' };
    const snaps = fs.readdirSync(base).sort();
    if (!snaps.length) return { ok: false, error: 'no rollback snapshots exist' };
    const last = snaps[snaps.length - 1];
    if (!(await acquireLock('rollback'))) return { ok: false, error: 'another job holds the update lock' };
    try {
      const r = await rollbackFrom(path.join(base, last), null);
      await dbRun(`INSERT INTO shield_updates (from_version, to_version, outcome, files_changed, detail, rolled_back) VALUES (?,?,?,?,?,1)`,
        ['unknown', (process.env.PANEL_VERSION || 'previous'), 'rolled-back', r.restored,
         JSON.stringify({ snapshot: last, by: actor || 'owner' }).slice(0, 500)]);
      await notify({
        severity: 'medium',
        title: 'Panel rolled back to previous version',
        body: `Rollback restored ${r.restored} file(s) from snapshot ${last}. RESTART the panel service to load the restored code.`,
      });
      return { ok: true, ...r, restartRequired: true };
    } finally { releaseLock(); }
  }

  function history(limit) {
    return new Promise((resolve, reject) => db.all(
      `SELECT * FROM shield_updates ORDER BY id DESC LIMIT ?`, [parseInt(limit || 30, 10)],
      (e, r) => e ? reject(e) : resolve(r || [])));
  }

  return { ensureSchema, preflight, verifyRelease, applyUpdate, rollbackLastUpdate, history, BUILTIN_RELEASE_PUBLIC_KEY, acquireLock, releaseLock };
}

module.exports = { createUpdater, BUILTIN_RELEASE_PUBLIC_KEY };
