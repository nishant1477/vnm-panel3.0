// =====================================================================
// VNM — Platform Operations (shared engine for tasks + APIs)
// ---------------------------------------------------------------------
// The heavy lifting behind the platform features: lifecycle ops that
// work for BOTH local and remote-node VMs (used by bulk actions,
// schedules and migrations), real qemu-img snapshot/backup operations,
// cloning, and node-to-node VM migration (streaming the disk over the
// authenticated agent relay in either direction).
//
// Everything here runs argv-only child processes (no shell strings with
// user input) and validates ids/ports/paths the same way the rest of
// the panel does.
// =====================================================================

'use strict';

const fs = require('fs');
const path = require('path');
const net = require('net');
const crypto = require('crypto');
const { spawn, execFileSync } = require('child_process');

const SNAPSHOT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_. -]{0,63}$/;

function createPlatformOps(ctx) {
  const {
    db, nodeManager, VM_DIR, logVMAction,
    startQemuVM, releaseLocalVncDisplay, vmProcesses, qemuStdins, isPidQemu,
    buildCloudInitFiles, createCloudInitSeed, generateMACAddress,
  } = ctx;

  const dbGet = (sql, params) => new Promise((resolve, reject) => db.get(sql, params, (e, r) => e ? reject(e) : resolve(r)));
  const dbAll = (sql, params) => new Promise((resolve, reject) => db.all(sql, params, (e, r) => e ? reject(e) : resolve(r || [])));
  const dbRun = (sql, params) => new Promise((resolve, reject) => db.run(sql, params, function (e) { e ? reject(e) : resolve(this); }));

  const httpErr = (code, message, extra) => { const e = new Error(message); e.httpStatus = code; Object.assign(e, extra || {}); return e; };
  const BACKUP_DIR = process.env.VNM_BACKUP_DIR || path.join(VM_DIR, 'backups');

  // ================= basics =================
  async function getVm(vmId) { return dbGet(`SELECT * FROM vms WHERE vm_id = ?`, [vmId]); }
  async function nodeForVm(vm) { return nodeManager.getNodeForVM(vm); }

  function localDiskPath(vm) {
    return vm.disk_file && String(vm.disk_file).trim()
      ? vm.disk_file
      : path.join(VM_DIR, `vm-${vm.vm_id}-disk.qcow2`);
  }
  function localSeedPath(vm) {
    return vm.seed_file && String(vm.seed_file).trim()
      ? vm.seed_file
      : path.join(VM_DIR, `vm-${vm.vm_id}-seed.iso`);
  }

  function assertStopped(vm, action) {
    if (vm.status === 'running') {
      throw httpErr(409, `VM must be stopped to ${action} (running VMs have an actively-written disk)`, { code: 'VM_RUNNING' });
    }
  }

  // ================= lifecycle (local + remote) =================
  async function vmStart(vm, actorName) {
    const node = await nodeForVm(vm);
    if (node && node.mode === 'remote') {
      const { getPortForwards } = ctx;
      const vmWithForwards = { ...vm, port_forwards: await getPortForwards(vm.vm_id) };
      await nodeManager.sendNodeCommand(node.id, 'vm.start', { vm: vmWithForwards }, { timeoutMs: 30000 });
      await dbRun(`UPDATE vms SET status = 'running', uptime = 0 WHERE vm_id = ?`, [vm.vm_id]);
      logVMAction(vm.vm_id, 'start', 'running', `VM started on remote node ${node.name}` + (actorName ? ` by ${actorName}` : ''));
      return { started: true, node: node.name };
    }
    if (vm.status === 'running') return { started: false, already: true };
    const result = await startQemuVM(vm);
    if (!result || !result.success) throw new Error('QEMU failed to start the VM');
    vmProcesses.set(vm.vm_id, result.pid);
    await dbRun(`UPDATE vms SET status = 'running', uptime = 0 WHERE vm_id = ?`, [vm.vm_id]);
    logVMAction(vm.vm_id, 'start', 'running', 'VM started successfully' + (actorName ? ` by ${actorName}` : ''));
    return { started: true };
  }

  async function vmStop(vm, actorName) {
    const node = await nodeForVm(vm);
    if (node && node.mode === 'remote') {
      await nodeManager.sendNodeCommand(node.id, 'vm.stop', { vm }, { timeoutMs: 20000 });
      await dbRun(`UPDATE vms SET status = 'stopped' WHERE vm_id = ?`, [vm.vm_id]);
      logVMAction(vm.vm_id, 'stop', 'stopped', `VM stopped on remote node ${node.name}` + (actorName ? ` by ${actorName}` : ''));
      return { stopped: true, node: node.name };
    }
    if (vm.status === 'stopped') return { stopped: false, already: true };
    releaseLocalVncDisplay(vm.vm_id);
    const pidFile = path.join(VM_DIR, `vm-${vm.vm_id}.pid`);
    if (fs.existsSync(pidFile)) {
      const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10);
      if (!isPidQemu(pid)) {
        try { fs.unlinkSync(pidFile); } catch (e) {}
      } else {
        try {
          if (process.platform === 'win32') {
            const { exec } = require('child_process');
            exec(`taskkill /F /PID ${pid}`, { shell: 'cmd' });
          } else {
            process.kill(-pid, 'SIGTERM');
            setTimeout(() => { try { process.kill(-pid, 'SIGKILL'); } catch (e) {} }, 3000).unref();
          }
        } catch (e) { /* already dead */ }
      }
    }
    vmProcesses.delete(vm.vm_id);
    qemuStdins.delete(String(vm.vm_id));
    await dbRun(`UPDATE vms SET status = 'stopped' WHERE vm_id = ?`, [vm.vm_id]);
    logVMAction(vm.vm_id, 'stop', 'stopped', 'VM stopped' + (actorName ? ` by ${actorName}` : ''));
    return { stopped: true };
  }

  async function vmRestart(vm, actorName) {
    await vmStop(vm, actorName);
    await new Promise((r) => setTimeout(r, 1500));
    return vmStart(vm, actorName);
  }

  async function vmDeleteFull(vm, actorName) {
    // Stop first (ignore "already stopped"), then clean every artifact the
    // same way the single-VM DELETE route does, for both local + remote.
    try { await vmStop(vm, actorName); } catch (e) { /* best effort */ }
    const node = await nodeForVm(vm).catch(() => null);
    if (node && node.mode === 'remote' && nodeManager.isNodeOnline(node.id)) {
      await nodeManager.sendNodeCommand(node.id, 'vm.cleanup', { vmId: String(vm.vm_id) }, { timeoutMs: 20000 }).catch(() => {});
    } else {
      for (const f of [localDiskPath(vm), localSeedPath(vm), path.join(VM_DIR, `vm-${vm.vm_id}.pid`), path.join(VM_DIR, `vm-${vm.vm_id}.vnc.json`)]) {
        try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch (e) {}
      }
      if (vm.img_file && fs.existsSync(vm.img_file)) { try { fs.unlinkSync(vm.img_file); } catch (e) {} }
    }
    // Remove registered backups' local files (remote backups live on the
    // node and are cleaned by vm.cleanup when the agent supports it; the
    // rows always go).
    const backups = await dbAll(`SELECT * FROM vm_backups WHERE vm_id = ?`, [vm.vm_id]).catch(() => []);
    for (const b of backups) {
      if (b.file_path && !b.node_id) { try { if (fs.existsSync(b.file_path)) fs.unlinkSync(b.file_path); } catch (e) {} }
    }
    await dbRun(`DELETE FROM vm_backups WHERE vm_id = ?`, [vm.vm_id]).catch(() => {});
    await dbRun(`DELETE FROM vm_port_forwards WHERE vm_id = ?`, [vm.vm_id]).catch(() => {});
    await dbRun(`DELETE FROM vm_firewall_rules WHERE vm_id = ?`, [vm.vm_id]).catch(() => {});
    await dbRun(`DELETE FROM vm_snapshots WHERE vm_id = ?`, [vm.vm_id]).catch(() => {});
    await dbRun(`UPDATE ip_allocations SET vm_id = NULL, status = 'reserved' WHERE vm_id = ?`, [vm.vm_id]).catch(() => {});
    await dbRun(`DELETE FROM vms WHERE vm_id = ?`, [vm.vm_id]);
    logVMAction(vm.vm_id, 'delete', 'completed', `VM deleted` + (actorName ? ` by ${actorName}` : ''));
    return { deleted: true };
  }

  // ================= SSH port allocation (per node) =================
  async function allocateSshPortOnNode(node, wanted) {
    if (!node) return wanted;
    const isRemote = node.mode === 'remote';
    const rows = await dbAll(
      `SELECT ssh_port, ssh_port_static FROM vms WHERE network_type = 'nat' AND COALESCE(node_id, (SELECT id FROM nodes WHERE mode='local' LIMIT 1)) = ?`,
      [node.id]
    );
    const used = new Set(rows.map((r) => parseInt(r.ssh_port || r.ssh_port_static || 0)).filter(Boolean));
    let candidate = wanted && !used.has(wanted) ? wanted : 2222;
    for (let i = 0; i < 1000; i++) {
      if (used.has(candidate)) { candidate++; continue; }
      if (isRemote) {
        try {
          const r = await nodeManager.sendNodeCommand(node.id, 'port.check', { port: candidate }, { timeoutMs: 6000 });
          if (r && r.free === true) return candidate;
        } catch (e) { return candidate; } // node offline: DB uniqueness is the best we can do
        candidate++; continue;
      }
      const free = await new Promise((resolve) => {
        const t = net.createServer();
        t.once('error', () => resolve(false));
        t.once('listening', () => t.close(() => resolve(true)));
        t.listen(candidate, '0.0.0.0');
      });
      if (free) return candidate;
      candidate++;
    }
    throw httpErr(503, 'No free SSH port found on target node', { code: 'NO_FREE_PORT' });
  }

  // ================= local qemu-img helpers =================
  function runQemuImgLocal(args) {
    try {
      return execFileSync('qemu-img', args, { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', timeout: 10 * 60 * 1000 });
    } catch (e) {
      throw httpErr(500, `qemu-img ${args[0]} failed: ${(e.stderr || e.message || '').toString().slice(0, 300)}`, { code: 'QEMU_IMG_FAILED' });
    }
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

  // qemu-img convert with -p progress parsing; onProgress(pct)
  function qemuImgConvertProgress(src, dst, onProgress) {
    return new Promise((resolve, reject) => {
      const child = spawn('qemu-img', ['convert', '-p', '-O', 'qcow2', src, dst], { stdio: ['ignore', 'pipe', 'pipe'], shell: false });
      let err = '';
      child.stdout.on('data', (d) => {
        const m = /(\d+(?:\.\d+)?)\s*\/\s*100%/.exec(d.toString());
        if (m && onProgress) onProgress(parseFloat(m[1]));
      });
      child.stderr.on('data', (d) => { err += d.toString(); });
      child.on('error', (e) => reject(httpErr(500, 'qemu-img convert failed to start: ' + e.message)));
      child.on('close', (code) => {
        if (code === 0) resolve();
        else reject(httpErr(500, `qemu-img convert failed: ${err.slice(0, 300)}`, { code: 'CONVERT_FAILED' }));
      });
    });
  }

  // ================= snapshots =================
  function snapshotTag(snapshotId, name) {
    const safe = String(name || 'snap').replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 48);
    return `vnm${snapshotId}-${safe}`;
  }

  async function snapshotCreate(vm, name, description, actor) {
    assertStopped(vm, 'create a snapshot');
    if (!SNAPSHOT_NAME_RE.test(name || '')) throw httpErr(400, 'Snapshot name must be 1-64 chars (letters, digits, space, . _ -)', { code: 'INVALID_NAME' });
    const r = await dbRun(`INSERT INTO vm_snapshots (vm_id, snapshot_name, description) VALUES (?, ?, ?)`, [vm.vm_id, name, description || null]);
    const snapId = r.lastID;
    const tag = snapshotTag(snapId, name);
    const node = await nodeForVm(vm);
    try {
      if (node && node.mode === 'remote') {
        await nodeManager.sendNodeCommand(node.id, 'vm.snapshot.create', { vmId: String(vm.vm_id), tag }, { timeoutMs: 120000 });
      } else {
        const disk = localDiskPath(vm);
        if (!fs.existsSync(disk)) throw httpErr(404, 'VM disk not found on the panel host', { code: 'DISK_NOT_FOUND' });
        runQemuImgLocal(['snapshot', '-c', tag, disk]);
      }
    } catch (e) {
      await dbRun(`DELETE FROM vm_snapshots WHERE snapshot_id = ?`, [snapId]).catch(() => {});
      throw e;
    }
    logVMAction(vm.vm_id, 'snapshot_create', 'completed', `Snapshot "${name}" created` + (actor ? ` by ${actor}` : ''));
    return { snapshot_id: snapId, name, tag };
  }

  async function snapshotRestore(vm, snapshot) {
    assertStopped(vm, 'restore a snapshot');
    const tag = snapshotTag(snapshot.snapshot_id, snapshot.snapshot_name);
    const node = await nodeForVm(vm);
    if (node && node.mode === 'remote') {
      await nodeManager.sendNodeCommand(node.id, 'vm.snapshot.restore', { vmId: String(vm.vm_id), tag }, { timeoutMs: 120000 });
    } else {
      const disk = localDiskPath(vm);
      if (!fs.existsSync(disk)) throw httpErr(404, 'VM disk not found on the panel host', { code: 'DISK_NOT_FOUND' });
      runQemuImgLocal(['snapshot', '-a', tag, disk]);
    }
    logVMAction(vm.vm_id, 'snapshot_restore', 'completed', `Snapshot "${snapshot.snapshot_name}" restored`);
  }

  async function snapshotDelete(vm, snapshot) {
    const tag = snapshotTag(snapshot.snapshot_id, snapshot.snapshot_name);
    const node = await nodeForVm(vm);
    if (node && node.mode === 'remote') {
      await nodeManager.sendNodeCommand(node.id, 'vm.snapshot.delete', { vmId: String(vm.vm_id), tag }, { timeoutMs: 60000 }).catch(() => {});
    } else {
      const disk = localDiskPath(vm);
      if (fs.existsSync(disk)) runQemuImgLocal(['snapshot', '-d', tag, disk]);
    }
    await dbRun(`DELETE FROM vm_snapshots WHERE snapshot_id = ?`, [snapshot.snapshot_id]);
    logVMAction(vm.vm_id, 'snapshot_delete', 'completed', `Snapshot "${snapshot.snapshot_name}" deleted`);
  }

  // ================= backups (full file exports) =================
  function backupFileName(vmId, name) {
    const safe = String(name || 'backup').replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 48);
    return `vm-${vmId}-${Date.now()}-${safe}.qcow2`;
  }

  async function backupCreate(vm, backupRow, onProgress) {
    assertStopped(vm, 'create a backup');
    const node = await nodeForVm(vm);
    if (node && node.mode === 'remote') {
      const res = await nodeManager.sendNodeCommand(node.id, 'vm.backup.create',
        { vmId: String(vm.vm_id), name: backupRow.node_name }, { timeoutMs: 30 * 60 * 1000 });
      await dbRun(`UPDATE vm_backups SET status='ready', size_bytes=?, node_file=?, node_id=?, checksum=?, file_path=NULL WHERE id=?`,
        [res.sizeBytes || null, res.file || backupRow.node_name, node.id, res.sha256 || null, backupRow.id]);
      return { sizeBytes: res.sizeBytes || null, sha256: res.sha256 || null, onNode: node.name };
    }
    const disk = localDiskPath(vm);
    if (!fs.existsSync(disk)) throw httpErr(404, 'VM disk not found on the panel host', { code: 'DISK_NOT_FOUND' });
    const dir = path.join(BACKUP_DIR, `vm-${vm.vm_id}`);
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, backupRow.file_name);
    await qemuImgConvertProgress(disk, file, onProgress);
    const stat = fs.statSync(file);
    const sha = await sha256File(file);
    await dbRun(`UPDATE vm_backups SET status='ready', size_bytes=?, file_path=?, checksum=? WHERE id=?`,
      [stat.size, file, sha, backupRow.id]);
    return { sizeBytes: stat.size, sha256: sha };
  }

  async function backupRestore(vm, backup) {
    assertStopped(vm, 'restore a backup');
    const node = await nodeForVm(vm);
    if (backup.node_id) {
      // Backup lives on a node - restore there.
      const srcNode = await dbGet(`SELECT * FROM nodes WHERE id = ?`, [backup.node_id]);
      if (!srcNode || srcNode.mode !== 'remote') throw httpErr(409, 'The node holding this backup is no longer a remote node', { code: 'NODE_GONE' });
      await nodeManager.sendNodeCommand(srcNode.id, 'vm.backup.restore', { vmId: String(vm.vm_id), name: backup.node_file }, { timeoutMs: 30 * 60 * 1000 });
      logVMAction(vm.vm_id, 'backup_restore', 'completed', `Backup "${backup.name}" restored from node ${srcNode.name}`);
      return;
    }
    if (!backup.file_path || !fs.existsSync(backup.file_path)) throw httpErr(404, 'Backup file is missing on the panel host', { code: 'BACKUP_MISSING' });
    // Verify integrity against the recorded checksum before touching the VM.
    if (backup.checksum) {
      const sha = await sha256File(backup.file_path);
      if (sha !== backup.checksum) throw httpErr(422, 'Backup integrity check FAILED - the file is corrupted and was not restored', { code: 'CHECKSUM_MISMATCH' });
    }
    const disk = localDiskPath(vm);
    const aside = disk + `.pre-restore-${Date.now()}.bak`;
    fs.renameSync(disk, aside);
    try {
      await qemuImgConvertProgress(backup.file_path, disk, () => {});
      try { fs.unlinkSync(aside); } catch (e) {}
    } catch (e) {
      // Roll back: bring the previous disk back immediately.
      try { fs.renameSync(aside, disk); } catch (e2) {}
      throw e;
    }
    logVMAction(vm.vm_id, 'backup_restore', 'completed', `Backup "${backup.name}" restored`);
  }

  async function backupDelete(backup) {
    if (backup.node_id) {
      const srcNode = await dbGet(`SELECT * FROM nodes WHERE id = ?`, [backup.node_id]);
      if (srcNode && srcNode.mode === 'remote' && nodeManager.isNodeOnline(srcNode.id)) {
        await nodeManager.sendNodeCommand(srcNode.id, 'vm.backup.delete', { name: backup.node_file }, { timeoutMs: 30000 }).catch(() => {});
      }
    } else if (backup.file_path && fs.existsSync(backup.file_path)) {
      try { fs.unlinkSync(backup.file_path); } catch (e) {}
    }
    await dbRun(`DELETE FROM vm_backups WHERE id = ?`, [backup.id]);
  }

  async function backupVerify(backup) {
    if (backup.node_id) {
      const srcNode = await dbGet(`SELECT * FROM nodes WHERE id = ?`, [backup.node_id]);
      if (!srcNode || !nodeManager.isNodeOnline(srcNode.id)) throw httpErr(409, 'Node holding this backup is offline', { code: 'NODE_OFFLINE' });
      const r = await nodeManager.sendNodeCommand(srcNode.id, 'vm.backup.verify', { name: backup.node_file }, { timeoutMs: 60000 });
      const ok = !backup.checksum || !r.sha256 || r.sha256 === backup.checksum;
      if (!ok) throw httpErr(422, 'Integrity check FAILED on the node', { code: 'CHECKSUM_MISMATCH' });
      return { verified: true, sha256: r.sha256, sizeBytes: r.sizeBytes };
    }
    if (!backup.file_path || !fs.existsSync(backup.file_path)) throw httpErr(404, 'Backup file is missing', { code: 'BACKUP_MISSING' });
    const sha = await sha256File(backup.file_path);
    const size = fs.statSync(backup.file_path).size;
    if (backup.checksum && sha !== backup.checksum) throw httpErr(422, 'Integrity check FAILED - checksum mismatch', { code: 'CHECKSUM_MISMATCH' });
    return { verified: true, sha256: sha, sizeBytes: size };
  }

  // ================= clone =================
  async function uniqueVmName(base) {
    let name = base; let i = 2;
    while (await dbGet(`SELECT 1 FROM vms WHERE vm_name = ?`, [name])) {
      name = `${base}-${i++}`;
      if (i > 99) throw httpErr(409, 'Could not find a free clone name', { code: 'NO_FREE_NAME' });
    }
    return name;
  }

  const CLONE_COLUMNS = `os_type, template_type, hostname, username, password, memory, cpus,
    cpu_sockets, cpu_cores, cpu_threads, cpu_model, custom_cpu_name, machine_type, board_name,
    product_name, custom_smbios_manufacturer, disk_size, smbios_manufacturer, smbios_product,
    smbios_version, smbios_serial, extra_args, enable_acpi, enable_kvm, network_type, ipv4_address,
    ipv4_gateway, ipv4_netmask, dns_servers, dns_primary, dns_secondary, http_port, ipv6_address,
    ipv6_gateway, bridge_device, vlan_id, nic_model, owner_id, node_id`;

  async function vmClone(vm, newName, onProgress) {
    assertStopped(vm, 'clone it');
    const name = await uniqueVmName(newName || `${vm.vm_name}-clone`);
    const node = await nodeForVm(vm);
    const newMac = generateMACAddress();
    const r = await dbRun(
      `INSERT INTO vms (vm_name, ${CLONE_COLUMNS}, status, uptime, node_name, mac_address, ssh_port_static)
       SELECT ?, ${CLONE_COLUMNS}, 'stopped', 0, ?, ?, ?
       FROM vms WHERE vm_id = ?`,
      [name, node ? node.name : 'localhost', newMac, 22, vm.vm_id]
    );
    const newId = r.lastID;
    try {
      // Fresh SSH forward port on that node - NAT clones must not share
      // the source VM's host port.
      const newPort = await allocateSshPortOnNode(node, parseInt(vm.ssh_port || vm.ssh_port_static || 2222, 10));
      await dbRun(`UPDATE vms SET ssh_port = ?, ssh_port_static = ? WHERE vm_id = ?`, [newPort, newPort, newId]);
      const diskFileName = `vm-${newId}-disk.qcow2`;
      if (node && node.mode === 'remote') {
        if (!nodeManager.isNodeOnline(node.id)) throw httpErr(409, `Node "${node.name}" is offline`, { code: 'NODE_OFFLINE' });
        const res = await nodeManager.sendNodeCommand(node.id, 'vm.clone',
          { vmId: String(vm.vm_id), targetVmId: String(newId) }, { timeoutMs: 30 * 60 * 1000 });
        // Rebuild the cloud-init seed for the new VM (same credentials, new ids).
        const seed = await nodeManager.sendNodeCommand(node.id, 'vm.createSeed',
          { vmId: String(newId), cloudInit: buildCloudInitFiles(vm, newId) }, { timeoutMs: 60000 });
        await dbRun(`UPDATE vms SET disk_file = ?, seed_file = ?, img_file = '' WHERE vm_id = ?`, [res.diskPath, seed.path, newId]);
      } else {
        const srcDisk = localDiskPath(vm);
        if (!fs.existsSync(srcDisk)) throw httpErr(404, 'Source VM disk not found', { code: 'DISK_NOT_FOUND' });
        const dstDisk = path.join(VM_DIR, diskFileName);
        onProgress && onProgress(10, 'Copying disk');
        await qemuImgConvertProgress(srcDisk, dstDisk, (p) => onProgress && onProgress(10 + p * 0.8, 'Copying disk'));
        const newRow = await getVm(newId);
        onProgress && onProgress(92, 'Generating cloud-init seed');
        const seedPath = await createCloudInitSeed(newId, newRow);
        await dbRun(`UPDATE vms SET disk_file = ?, seed_file = ?, img_file = '' WHERE vm_id = ?`, [dstDisk, seedPath, newId]);
      }
      logVMAction(vm.vm_id, 'clone', 'completed', `Cloned to "${name}" (ID ${newId})`);
      return { vm_id: newId, vm_name: name };
    } catch (e) {
      // Roll the partial clone back completely.
      if (node && node.mode === 'remote' && nodeManager.isNodeOnline(node.id)) {
        nodeManager.sendNodeCommand(node.id, 'vm.cleanup', { vmId: String(newId) }, { timeoutMs: 20000 }).catch(() => {});
      } else {
        for (const f of [path.join(VM_DIR, `vm-${newId}-disk.qcow2`), path.join(VM_DIR, `vm-${newId}-seed.iso`)]) {
          try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch (e2) {}
        }
      }
      await dbRun(`DELETE FROM vms WHERE vm_id = ?`, [newId]).catch(() => {});
      throw e;
    }
  }

  // ================= migration =================
  async function vmMigrate(vm, targetNode, { startAfter, onProgress, checkCancelled }) {
    const srcNode = await nodeForVm(vm);
    if (srcNode && targetNode && srcNode.id === targetNode.id) throw httpErr(400, 'VM is already on that node', { code: 'SAME_NODE' });
    if (targetNode.mode === 'remote' && !nodeManager.isNodeOnline(targetNode.id)) {
      throw httpErr(409, `Target node "${targetNode.name}" is offline`, { code: 'NODE_OFFLINE' });
    }
    if (targetNode.maintenance_mode) {
      throw httpErr(409, `Target node "${targetNode.name}" is in maintenance mode`, { code: 'NODE_MAINTENANCE' });
    }
    const wasRunning = vm.status === 'running';
    if (wasRunning) {
      onProgress && onProgress(2, 'Stopping VM for migration');
      await vmStop(vm, 'migration');
    }
    checkCancelled && await checkCancelled();

    const localTarget = targetNode.mode === 'local';
    const remoteSource = !!(srcNode && srcNode.mode === 'remote');

    // Resolve source disk location + size.
    let srcDisk = null, srcSize = 0, diskInfo = null;
    if (remoteSource) {
      diskInfo = await nodeManager.sendNodeCommand(srcNode.id, 'vm.diskinfo', { vmId: String(vm.vm_id) }, { timeoutMs: 20000 });
      if (!diskInfo || !diskInfo.exists) throw httpErr(404, 'VM disk not found on its node', { code: 'DISK_NOT_FOUND' });
      srcDisk = diskInfo.path; srcSize = diskInfo.sizeBytes || 0;
    } else {
      srcDisk = localDiskPath(vm);
      if (!fs.existsSync(srcDisk)) throw httpErr(404, 'VM disk not found on the panel host', { code: 'DISK_NOT_FOUND' });
      srcSize = fs.statSync(srcDisk).size;
    }

    // ---- Case 1: anything -> local panel ----
    if (localTarget) {
      const dstDisk = path.join(VM_DIR, `vm-${vm.vm_id}-disk.qcow2`);
      const partPath = dstDisk + '.migrate.part';
      if (remoteSource) {
        onProgress && onProgress(8, 'Streaming disk from node');
        const hash = crypto.createHash('sha256');
        await new Promise((resolve, reject) => {
          const out = fs.createWriteStream(partPath);
          nodeManager.relayNodeFilePull(srcNode.id, { path: srcDisk, expectedBytes: srcSize }, {
            onData: (buf) => { hash.update(buf); out.write(buf); },
            onProgress: (bytes) => onProgress && onProgress(8 + (bytes / Math.max(1, srcSize)) * 70, `Streaming disk (${(bytes / 1e6).toFixed(1)} MB)`),
          }).then(() => out.end(resolve)).catch((e) => { out.destroy(); reject(e); });
        });
        if (diskInfo.sha256 && hash.digest('hex') !== diskInfo.sha256) {
          try { fs.unlinkSync(partPath); } catch (e) {}
          throw httpErr(422, 'Disk checksum mismatch in transit - migration aborted, source untouched', { code: 'CHECKSUM_MISMATCH' });
        }
        try { fs.renameSync(partPath, dstDisk); } catch (e) { throw httpErr(500, 'Could not finalize migrated disk: ' + e.message); }
      } else {
        onProgress && onProgress(10, 'Preparing disk');
        try { fs.renameSync(srcDisk, dstDisk); } catch (e) { /* same-volume move or already local path */ }
      }
      checkCancelled && await checkCancelled();
      onProgress && onProgress(82, 'Generating cloud-init seed');
      const seedPath = await createCloudInitSeed(vm.vm_id, await getVm(vm.vm_id));
      // New SSH port on the local node.
      const newPort = await allocateSshPortOnNode(targetNode, parseInt(vm.ssh_port || vm.ssh_port_static || 2222, 10));
      await dbRun(`UPDATE vms SET node_id = ?, node_name = ?, disk_file = ?, seed_file = ?, ssh_port = ?, ssh_port_static = ?, img_file = '' WHERE vm_id = ?`,
        [targetNode.id, targetNode.name, dstDisk, seedPath, newPort, newPort, vm.vm_id]);
      if (remoteSource) {
        onProgress && onProgress(92, 'Cleaning up source node');
        await nodeManager.sendNodeCommand(srcNode.id, 'vm.cleanup', { vmId: String(vm.vm_id) }, { timeoutMs: 30000 }).catch(() => {});
      }
    } else {
      // ---- Case 2: -> remote node ----
      let streamSource = null; let tmpPulled = null;
      if (remoteSource) {
        // remote -> remote: pull to a panel temp file first, then push.
        onProgress && onProgress(8, 'Pulling disk from source node');
        tmpPulled = path.join(VM_DIR, `vm-${vm.vm_id}-migrate-tmp.qcow2`);
        const hash = crypto.createHash('sha256');
        await new Promise((resolve, reject) => {
          const out = fs.createWriteStream(tmpPulled);
          nodeManager.relayNodeFilePull(srcNode.id, { path: srcDisk, expectedBytes: srcSize }, {
            onData: (buf) => { hash.update(buf); out.write(buf); },
            onProgress: (bytes) => onProgress && onProgress(8 + (bytes / Math.max(1, srcSize)) * 45, `Pulling disk (${(bytes / 1e6).toFixed(1)} MB)`),
          }).then(() => out.end(resolve)).catch((e) => { out.destroy(); reject(e); });
        });
        if (diskInfo.sha256 && hash.digest('hex') !== diskInfo.sha256) {
          try { fs.unlinkSync(tmpPulled); } catch (e) {}
          throw httpErr(422, 'Disk checksum mismatch in transit - migration aborted, source untouched', { code: 'CHECKSUM_MISMATCH' });
        }
        streamSource = tmpPulled;
      } else {
        streamSource = srcDisk;
      }
      checkCancelled && await checkCancelled();
      onProgress && onProgress(55, 'Streaming disk to target node');
      await nodeManager.relayDiskUpload(targetNode.id,
        { vmId: String(vm.vm_id), totalBytes: fs.statSync(streamSource).size },
        fs.createReadStream(streamSource, { highWaterMark: 1024 * 1024 }),
        (bytes) => onProgress && onProgress(55 + (bytes / Math.max(1, srcSize)) * 30, `Streaming disk (${(bytes / 1e6).toFixed(1)} MB)`)
      );
      onProgress && onProgress(88, 'Generating cloud-init seed on node');
      const seed = await nodeManager.sendNodeCommand(targetNode.id, 'vm.createSeed',
        { vmId: String(vm.vm_id), cloudInit: buildCloudInitFiles(vm, vm.vm_id) }, { timeoutMs: 60000 });
      const newPort = await allocateSshPortOnNode(targetNode, parseInt(vm.ssh_port || vm.ssh_port_static || 2222, 10));
      const diskOnNode = await nodeManager.sendNodeCommand(targetNode.id, 'vm.diskinfo', { vmId: String(vm.vm_id) }, { timeoutMs: 20000 });
      await dbRun(`UPDATE vms SET node_id = ?, node_name = ?, disk_file = ?, seed_file = ?, ssh_port = ?, ssh_port_static = ?, img_file = '' WHERE vm_id = ?`,
        [targetNode.id, targetNode.name, diskOnNode.path, seed.path, newPort, newPort, vm.vm_id]);
      // Remove local artifacts (source disk or temp pull file).
      if (tmpPulled) { try { fs.unlinkSync(tmpPulled); } catch (e) {} }
      else { try { fs.unlinkSync(srcDisk); } catch (e) {} try { fs.unlinkSync(localSeedPath(vm)); } catch (e) {} }
      if (remoteSource) {
        onProgress && onProgress(95, 'Cleaning up source node');
        await nodeManager.sendNodeCommand(srcNode.id, 'vm.cleanup', { vmId: String(vm.vm_id) }, { timeoutMs: 30000 }).catch(() => {});
      }
    }

    if (startAfter && wasRunning) {
      onProgress && onProgress(97, 'Starting VM on target node');
      await vmStart(await getVm(vm.vm_id), 'migration');
    }
    logVMAction(vm.vm_id, 'migrate', 'completed', `Migrated to node "${targetNode.name}"`);
    return { migratedTo: targetNode.name, wasRunning, restarted: !!(startAfter && wasRunning) };
  }

  // ================= task handler registration =================
  function registerTaskHandlers(engine) {
    engine.register('vm.start', async (job) => {
      const vm = await getVm(job.target_id);
      if (!vm) throw httpErr(404, 'VM no longer exists');
      const r = await vmStart(vm, job.created_by_name || 'task');
      return { message: `VM ${vm.vm_name} started` + (r.node ? ` on ${r.node}` : '') };
    });
    engine.register('vm.stop', async (job) => {
      const vm = await getVm(job.target_id);
      if (!vm) throw httpErr(404, 'VM no longer exists');
      await vmStop(vm, job.created_by_name || 'task');
      return { message: `VM ${vm.vm_name} stopped` };
    });
    engine.register('vm.restart', async (job) => {
      const vm = await getVm(job.target_id);
      if (!vm) throw httpErr(404, 'VM no longer exists');
      await vmRestart(vm, job.created_by_name || 'task');
      return { message: `VM ${vm.vm_name} restarted` };
    });
    engine.register('vm.backup', async (job, tctx) => {
      const vm = await getVm(job.target_id);
      if (!vm) throw httpErr(404, 'VM no longer exists');
      tctx.setProgress(3, 'Preparing backup');
      const fileName = backupFileName(vm.vm_id, job.params.name || 'backup');
      const r = await dbRun(
        `INSERT INTO vm_backups (vm_id, name, status, file_name, notes, created_by) VALUES (?, ?, 'creating', ?, ?, ?)`,
        [vm.vm_id, job.params.name || `Backup ${new Date().toISOString().slice(0, 16).replace('T', ' ')}`, fileName, job.params.notes || null, job.created_by]
      );
      try {
        const res = await backupCreate(vm, { id: r.lastID, file_name: fileName, node_name: fileName },
          (p, text) => tctx.setProgress(5 + p * 0.9, text || 'Creating backup'));
        // Retention: keep only the newest N backups for this VM.
        const keep = parseInt(job.params.retention, 10) || 0;
        if (keep > 0) {
          const all = await dbAll(`SELECT id FROM vm_backups WHERE vm_id = ? AND status = 'ready' ORDER BY id DESC`, [vm.vm_id]);
          for (const old of all.slice(keep)) await backupDelete({ ...old, vm_id: vm.vm_id }).catch(() => {});
        }
        return { message: `Backup of ${vm.vm_name} complete (${((res.sizeBytes || 0) / 1e6).toFixed(1)} MB)`, backupId: r.lastID };
      } catch (e) {
        await dbRun(`UPDATE vm_backups SET status = 'failed' WHERE id = ?`, [r.lastID]).catch(() => {});
        throw e;
      }
    });
    engine.register('vm.restore-backup', async (job, tctx) => {
      const backup = await dbGet(`SELECT * FROM vm_backups WHERE id = ?`, [job.params.backupId]);
      if (!backup) throw httpErr(404, 'Backup not found');
      const vm = await getVm(backup.vm_id);
      if (!vm) throw httpErr(404, 'VM no longer exists');
      tctx.setProgress(5, 'Verifying backup integrity');
      if (backup.status === 'ready') await backupVerify(backup).catch((e) => { throw httpErr(422, e.message, { noRetry: true }); });
      tctx.setProgress(15, 'Restoring disk');
      await backupRestore(vm, backup);
      return { message: `Backup "${backup.name}" restored to ${vm.vm_name}` };
    });
    engine.register('vm.restore-backup-new', async (job, tctx) => {
      // Recovery testing: restore INTO A FRESH CLONE so the original VM
      // is never touched by a test restore.
      const backup = await dbGet(`SELECT * FROM vm_backups WHERE id = ?`, [job.params.backupId]);
      if (!backup) throw httpErr(404, 'Backup not found');
      const vm = await getVm(backup.vm_id);
      if (!vm) throw httpErr(404, 'Original VM no longer exists');
      if (backup.node_id) throw httpErr(400, 'Test-restore of node-held backups is not supported yet', { noRetry: true });
      if (!backup.file_path || !fs.existsSync(backup.file_path)) throw httpErr(404, 'Backup file missing', { noRetry: true });
      tctx.setProgress(5, 'Verifying backup integrity');
      if (backup.checksum) {
        const sha = await sha256File(backup.file_path);
        if (sha !== backup.checksum) throw httpErr(422, 'Backup integrity check FAILED', { noRetry: true });
      }
      tctx.setProgress(15, 'Creating recovery-test VM');
      const name = await uniqueVmName(`${vm.vm_name}-restore-test`);
      const r = await dbRun(
        `INSERT INTO vms (vm_name, ${CLONE_COLUMNS}, status, uptime, node_name, mac_address, ssh_port_static)
         SELECT ?, ${CLONE_COLUMNS}, 'stopped', 0, 'localhost', ?, 22 FROM vms WHERE vm_id = ?`,
        [name, generateMACAddress(), vm.vm_id]
      );
      const newId = r.lastID;
      try {
        const localNode = await dbGet(`SELECT * FROM nodes WHERE mode = 'local' LIMIT 1`);
        const newPort = await allocateSshPortOnNode(localNode, parseInt(vm.ssh_port || vm.ssh_port_static || 2222, 10));
        await dbRun(`UPDATE vms SET ssh_port = ?, ssh_port_static = ? WHERE vm_id = ?`, [newPort, newPort, newId]);
        const dstDisk = path.join(VM_DIR, `vm-${newId}-disk.qcow2`);
        await qemuImgConvertProgress(backup.file_path, dstDisk, (p) => tctx.setProgress(20 + p * 0.7, 'Writing test-restore disk'));
        const seedPath = await createCloudInitSeed(newId, await getVm(newId));
        await dbRun(`UPDATE vms SET disk_file = ?, seed_file = ?, img_file = '' WHERE vm_id = ?`, [dstDisk, seedPath, newId]);
        logVMAction(newId, 'recovery_test', 'completed', `Recovery test VM created from backup "${backup.name}"`);
        return { message: `Recovery test VM "${name}" (ID ${newId}) created from backup - original untouched`, vm_id: newId };
      } catch (e) {
        for (const f of [path.join(VM_DIR, `vm-${newId}-disk.qcow2`), path.join(VM_DIR, `vm-${newId}-seed.iso`)]) {
          try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch (e2) {}
        }
        await dbRun(`DELETE FROM vms WHERE vm_id = ?`, [newId]).catch(() => {});
        throw e;
      }
    });
    engine.register('vm.clone', async (job, tctx) => {
      const vm = await getVm(job.target_id);
      if (!vm) throw httpErr(404, 'VM no longer exists');
      const r = await vmClone(vm, job.params.name, (p, text) => tctx.setProgress(p, text));
      return { message: `Clone "${r.vm_name}" created (ID ${r.vm_id})`, vm_id: r.vm_id };
    });
    engine.register('vm.migrate', async (job, tctx) => {
      const vm = await getVm(job.target_id);
      if (!vm) throw httpErr(404, 'VM no longer exists');
      const target = await dbGet(`SELECT * FROM nodes WHERE id = ?`, [job.params.targetNodeId]);
      if (!target) throw httpErr(404, 'Target node not found');
      const r = await vmMigrate(vm, target, {
        startAfter: job.params.startAfter !== false,
        onProgress: (p, text) => tctx.setProgress(p, text),
        checkCancelled: tctx.checkCancelled,
      });
      return { message: `VM ${vm.vm_name} migrated to "${r.migratedTo}"` + (r.restarted ? ' and restarted' : '') };
    });
  }

  return {
    getVm, nodeForVm, localDiskPath,
    vmStart, vmStop, vmRestart, vmDeleteFull,
    allocateSshPortOnNode,
    snapshotCreate, snapshotRestore, snapshotDelete,
    backupCreate, backupRestore, backupDelete, backupVerify, backupFileName,
    vmClone, vmMigrate, uniqueVmName,
    registerTaskHandlers,
    BACKUP_DIR, httpErr,
  };
}

module.exports = createPlatformOps;
