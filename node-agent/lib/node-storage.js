// =====================================================================
// VNM Node Agent — node-storage.js
// ---------------------------------------------------------------------
// Real snapshot / backup / storage operations that run ON the node:
//   - qcow2 internal snapshots via `qemu-img snapshot -c/-a/-d`
//   - full file backups via `qemu-img convert` into the node's backup
//     directory, with SHA-256 integrity hashes
//   - same-node VM cloning (disk copy)
//   - per-VM live stats sampling (ps on the QEMU pid)
//   - storage pool usage reporting (df per directory)
//
// All qemu-img invocations use argv arrays (never shell strings), all
// ids are digits-only via cleanVmId, and every disk-mutating operation
// refuses to run while the VM's QEMU is alive (an actively-written
// qcow2 must not be snapshotted/restored/backed up).
// =====================================================================

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile, execFileSync } = require('child_process');

const provision = require('./vm-provision');
const qemu = require('./qemu-launcher');
const systemInfo = require('./system-info');

const BACKUP_DIR = process.env.AGENT_BACKUP_DIR || path.join(qemu.VM_DIR, 'backups');
const BACKUP_NAME_RE = /^vm-\d{1,10}-\d{9,14}-[A-Za-z0-9._-]{1,48}\.qcow2$/;

function httpError(code, message, extra) { return provision.httpError(code, message, extra); }

function runQemuImg(args, timeoutMs = 10 * 60 * 1000) {
  return new Promise((resolve, reject) => {
    const bin = provision.detectQemuImg();
    if (!bin) return reject(httpError(501, 'qemu-img is not available on this node (install qemu-utils or set QEMU_IMG_BIN)', { code: 'QEMU_IMG_UNAVAILABLE' }));
    execFile(bin, args, { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) return reject(httpError(500, `qemu-img ${args[0]} failed: ${(stderr || err.message || '').toString().slice(0, 300)}`, { code: 'QEMU_IMG_FAILED' }));
      resolve(stdout.toString());
    });
  });
}

function assertVmStopped(vmId) {
  const st = qemu.statusVM({ vm_id: vmId });
  if (st.running) throw httpError(409, 'VM is running on this node - stop it first (an actively-written disk cannot be snapshotted or restored)', { code: 'VM_RUNNING' });
}

function sha256File(p) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const st = fs.createReadStream(p, { highWaterMark: 1024 * 1024 });
    st.on('data', (c) => hash.update(c));
    st.on('end', () => resolve(hash.digest('hex')));
    st.on('error', reject);
  });
}

function diskFor(vmId) {
  const id = provision.cleanVmId(vmId);
  if (!id) throw httpError(400, 'Invalid VM id', { code: 'INVALID_VM_ID' });
  return { id, disk: provision.diskPathFor(id) };
}

function backupDirFor(vmId) { return path.join(BACKUP_DIR, `vm-${vmId}`); }

// ---------------- snapshots (qcow2 internal) ----------------
async function snapshotCreate(vmId, tag) {
  const { id, disk } = diskFor(vmId);
  const safeTag = String(tag || '').replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 64);
  if (!safeTag) throw httpError(400, 'Invalid snapshot tag', { code: 'INVALID_TAG' });
  assertVmStopped(id);
  if (!fs.existsSync(disk)) throw httpError(404, 'VM disk not found on this node', { code: 'DISK_NOT_FOUND' });
  await runQemuImg(['snapshot', '-c', safeTag, disk]);
  return { tag: safeTag, disk };
}

async function snapshotApply(vmId, tag, mode) { // mode: 'a' (apply) | 'd' (delete)
  const { id, disk } = diskFor(vmId);
  const safeTag = String(tag || '').replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 64);
  if (!safeTag) throw httpError(400, 'Invalid snapshot tag', { code: 'INVALID_TAG' });
  assertVmStopped(id);
  if (!fs.existsSync(disk)) throw httpError(404, 'VM disk not found on this node', { code: 'DISK_NOT_FOUND' });
  await runQemuImg(['snapshot', '-' + mode, safeTag, disk]);
  return { tag: safeTag };
}

async function snapshotList(vmId) {
  const { disk } = diskFor(vmId);
  if (!fs.existsSync(disk)) return { snapshots: [] };
  const out = await runQemuImg(['snapshot', '-l', disk], 30000).catch(() => '');
  const snapshots = [];
  for (const line of String(out).split('\n').slice(2)) {
    const m = /^\s*(\d+)\s+([-\dT:.Z]+)\s+(\d{2}:\d{2}:\d{2})\s+(\d+(?:\.\d+)?)\s*(\w*)\s+(\S+)$/.exec(line);
    if (m) snapshots.push({ id: m[1], date: m[2] + ' ' + m[3], sizeKiB: parseFloat(m[4]), tag: m[6] });
  }
  return { snapshots };
}

// ---------------- backups (full file exports) ----------------
async function backupCreate(vmId, name) {
  const { id, disk } = diskFor(vmId);
  if (!BACKUP_NAME_RE.test(String(name || ''))) throw httpError(400, 'Invalid backup name', { code: 'INVALID_NAME' });
  assertVmStopped(id);
  if (!fs.existsSync(disk)) throw httpError(404, 'VM disk not found on this node', { code: 'DISK_NOT_FOUND' });
  const dir = backupDirFor(id);
  fs.mkdirSync(dir, { recursive: true });
  const dest = path.join(dir, name);
  const part = dest + '.part';
  await runQemuImg(['convert', '-O', 'qcow2', disk, part]);
  try { fs.renameSync(part, dest); } catch (e) { try { fs.unlinkSync(part); } catch (e2) {} throw httpError(500, 'Could not finalize backup: ' + e.message); }
  const size = fs.statSync(dest).size;
  const sha = await sha256File(dest);
  return { file: name, path: dest, sizeBytes: size, sha256: sha };
}

function resolveBackupFile(name) {
  const base = String(name || '');
  // Backups created via the panel are always under backups/vm-<id>/<file>.
  const m = /^vm-(\d{1,10})-(.+)$/.exec(base);
  if (!m || !BACKUP_NAME_RE.test(base)) throw httpError(400, 'Invalid backup name', { code: 'INVALID_NAME' });
  const dir = backupDirFor(m[1]);
  const file = path.join(dir, base);
  const resolved = path.resolve(file) + path.sep;
  const resolvedDir = path.resolve(dir) + path.sep;
  if (!resolved.startsWith(resolvedDir)) throw httpError(400, 'Invalid backup name', { code: 'INVALID_NAME' });
  return { vmId: m[1], file };
}

async function backupRestore(vmId, name) {
  const { id, disk } = diskFor(vmId);
  const { vmId: ownerId, file } = resolveBackupFile(name);
  if (ownerId !== id) throw httpErr(400, 'Backup belongs to a different VM', { code: 'WRONG_VM' });
  assertVmStopped(id);
  if (!fs.existsSync(file)) throw httpError(404, 'Backup file not found on this node', { code: 'BACKUP_MISSING' });
  const aside = disk + `.pre-restore-${Date.now()}.bak`;
  if (fs.existsSync(disk)) fs.renameSync(disk, aside);
  try {
    await runQemuImg(['convert', '-O', 'qcow2', file, disk]);
    try { fs.unlinkSync(aside); } catch (e) {}
  } catch (e) {
    try { fs.renameSync(aside, disk); } catch (e2) {}
    throw e;
  }
  return { restored: name };
}

async function backupDelete(name) {
  const { file } = resolveBackupFile(name);
  if (fs.existsSync(file)) { try { fs.unlinkSync(file); } catch (e) { throw httpError(500, 'Delete failed: ' + e.message); } }
  return { deleted: name };
}

async function backupVerify(name) {
  const { file } = resolveBackupFile(name);
  if (!fs.existsSync(file)) throw httpError(404, 'Backup file not found on this node', { code: 'BACKUP_MISSING' });
  return { sha256: await sha256File(file), sizeBytes: fs.statSync(file).size };
}

async function backupList() {
  const out = [];
  if (!fs.existsSync(BACKUP_DIR)) return { backups: out };
  for (const vmDir of fs.readdirSync(BACKUP_DIR)) {
    const dir = path.join(BACKUP_DIR, vmDir);
    try {
      if (!fs.statSync(dir).isDirectory()) continue;
      for (const f of fs.readdirSync(dir)) {
        if (f.endsWith('.qcow2')) out.push({ vmId: vmDir.replace(/^vm-/, ''), file: f, sizeBytes: fs.statSync(path.join(dir, f)).size });
      }
    } catch (e) { /* skip unreadable */ }
  }
  return { backups: out };
}

function httpErr(code, message, extra) { return provision.httpError(code, message, extra); }

// ---------------- clone / disk info / stats ----------------
async function cloneVm(srcVmId, targetVmId) {
  const src = diskFor(srcVmId);
  const dst = diskFor(targetVmId);
  assertVmStopped(src.id);
  assertVmStopped(dst.id);
  if (!fs.existsSync(src.disk)) throw httpError(404, 'Source disk not found on this node', { code: 'DISK_NOT_FOUND' });
  // The target id is brand new; refuse to overwrite an existing disk.
  if (fs.existsSync(dst.disk)) throw httpError(409, 'Target disk already exists on this node', { code: 'TARGET_EXISTS' });
  await runQemuImg(['convert', '-O', 'qcow2', src.disk, dst.disk]);
  return { diskPath: dst.disk, sizeBytes: fs.statSync(dst.disk).size };
}

async function diskInfo(vmId, { hash = false } = {}) {
  const { disk } = diskFor(vmId);
  const exists = fs.existsSync(disk);
  return {
    path: disk, exists,
    sizeBytes: exists ? fs.statSync(disk).size : 0,
    sha256: exists && hash ? await sha256File(disk) : null,
  };
}

async function vmStats(vmIds) {
  const out = {};
  for (const rawId of (Array.isArray(vmIds) ? vmIds : [])) {
    const id = provision.cleanVmId(rawId);
    if (!id) continue;
    const pidFile = path.join(qemu.VM_DIR, `vm-${id}.pid`);
    try {
      if (!fs.existsSync(pidFile)) { out[String(id)] = { running: false }; continue; }
      const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10);
      const { stdout } = await new Promise((resolve, reject) =>
        execFile('ps', ['-p', String(pid), '-o', '%cpu,rss', '--no-headers'], { timeout: 4000 }, (e, so, se) => e ? reject(e) : resolve({ stdout: so })));
      const parts = String(stdout).trim().split(/\s+/);
      out[String(id)] = { running: true, cpu: parseFloat(parts[0]) || 0, memBytes: (parseFloat(parts[1]) || 0) * 1024 };
    } catch (e) { out[String(id)] = { running: false }; }
  }
  return { vms: out };
}

// ---------------- storage pools ----------------
async function storageList() {
  const pools = [];
  const dirs = [
    { name: 'VM Storage', path: qemu.VM_DIR },
    { name: 'Backups', path: BACKUP_DIR },
    { name: 'Templates', path: provision.TEMPLATES_DIR },
  ];
  for (const d of dirs) {
    try {
      const usage = await systemInfo.diskUsage(d.path);
      pools.push({ name: d.name, path: d.path, totalBytes: usage.totalBytes, usedBytes: usage.usedBytes, freeBytes: usage.freeBytes });
    } catch (e) { pools.push({ name: d.name, path: d.path, error: e.message }); }
  }
  return { pools };
}

function storageCheck(p) {
  const target = String(p || '');
  if (!path.isAbsolute(target)) throw httpError(400, 'Path must be absolute', { code: 'INVALID_PATH' });
  const forbidden = ['/proc', '/sys', '/dev', '/etc'].map((x) => path.resolve(x) + path.sep);
  const resolved = path.resolve(target) + path.sep;
  if (forbidden.some((f) => resolved.startsWith(f))) throw httpError(400, 'That path is not allowed', { code: 'FORBIDDEN_PATH' });
  let exists = false, isDir = false;
  try { const st = fs.statSync(target); exists = true; isDir = st.isDirectory(); } catch (e) { /* missing */ }
  return { path: target, exists, isDir };
}

module.exports = {
  BACKUP_DIR,
  snapshotCreate, snapshotApply, snapshotList,
  backupCreate, backupRestore, backupDelete, backupVerify, backupList,
  cloneVm, diskInfo, vmStats, storageList, storageCheck,
};
