// =====================================================================
// VNM Node Agent — QEMU launcher
// ---------------------------------------------------------------------
// Real VM lifecycle for VMs assigned to THIS node: spawns an actual
// qemu-system-x86_64 process, tracks it by PID file (same convention
// the panel already uses locally: ~/vms/vm-<id>.pid + .log), and is
// honestly capability-gated - if this host has no KVM/QEMU, vm.start
// fails with a clear, real error instead of pretending to boot.
//
// Scope note: this mirrors the panel's local launcher (app.js's
// startQemuVM) for the config every VM needs - memory, CPU, the root
// qcow2 disk, NAT or bridge networking, an optional attached ISO, the
// cloud-init seed ISO (built on this node by lib/vm-provision.js from
// user-data the panel generated), and a serial console. Not yet
// mirrored: custom SMBIOS fields and per-VM extra QEMU args - both are
// straightforward to port into buildArgs() below when needed; nothing
// about the surrounding process/PID-file/stop machinery has to change.
// =====================================================================

const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');
const systemInfo = require('./system-info');
const rdpGuest = require('./rdp-guest');

const net = require('net');

const isWindows = process.platform === 'win32';
const VM_DIR = process.env.AGENT_VM_DIR || path.join(os.homedir(), 'vms');
if (!fs.existsSync(VM_DIR)) fs.mkdirSync(VM_DIR, { recursive: true });
// Streamed templates/ISOs (pushed by the panel at VM-creation time) and
// agent-downloaded OS template caches live here.
const TEMPLATES_DIR = path.join(VM_DIR, 'templates');
if (!fs.existsSync(TEMPLATES_DIR)) fs.mkdirSync(TEMPLATES_DIR, { recursive: true });
const hmpPath = (vmId) => path.join(VM_DIR, `vm-${rdpGuest.cleanVmId(vmId)}.hmp`);

// ---------------------------------------------------------------
// Serial console access (QEMU stdin/stdout, launched with
// `-serial mon:stdio`): the panel uses this to drive the VM's built-in
// serial console - e.g. to log in and provision RDP without needing
// sshd inside the guest. writeSerial() feeds keystrokes; consoleTail()
// reads back the last lines of the serial log so a driver can watch for
// prompts and markers. Keyed by clean VM id.
// ---------------------------------------------------------------
const _vmStdins = new Map();

function writeSerial(vmId, data) {
  const stdin = _vmStdins.get(String(rdpgClean(vmId)));
  if (!stdin || stdin.destroyed) {
    const err = new Error(`vm-${vmId} has no serial console attached (is it running on this node?)`);
    err.code = 'SERIAL_NOT_CONNECTED'; err.httpStatus = 409;
    throw err;
  }
  stdin.write(String(data));
  return { success: true };
}

function consoleTail(vmId, lines = 100) {
  const logFile = path.join(VM_DIR, `vm-${rdpGuest.cleanVmId(vmId)}.log`);
  if (!fs.existsSync(logFile)) return { lines: 0, text: '' };
  try {
    const text = fs.readFileSync(logFile, 'utf8');
    const arr = text.split('\n');
    const n = Math.max(1, Math.min(parseInt(lines, 10) || 100, 2000));
    return { lines: arr.length, text: arr.slice(-n).join('\n') };
  } catch (e) {
    return { lines: 0, text: '', error: e.message };
  }
}

function serialConnected(vmId) { const s = _vmStdins.get(String(rdpgClean(vmId))); return !!(s && !s.destroyed); }
function rdpgClean(vmId) { return String(vmId).replace(/[^0-9]/g, ''); }

// ---------------------------------------------------------------
// VNC display allocation
// ---------------------------------------------------------------
// QEMU's -vnc :N binds TCP port 5900+N on localhost only (no -vnc
// host:port form is used, so it's never reachable except through this
// agent/panel's own relay - see agent.js's 'vnc-open' handling). Ports
// are tracked in-memory for the life of this agent process and also
// written to a sidecar file per VM so vncInfo() still works (e.g. after
// an agent restart) as long as the QEMU process itself is still up.
const _allocatedDisplays = new Set();
const VNC_BASE_PORT = 5900;
const VNC_MAX_DISPLAYS = 200;

// Where a VM's disk lives ON THIS NODE. Migrated VMs (see agent.js
// disk-upload-*) are stored here under the same naming the panel uses
// locally. The panel's vm.disk_file is a path on the *panel's* machine
// and means nothing here, so prefer this node-local path when it exists.
function diskPathFor(vmId) {
  return path.join(VM_DIR, `vm-${String(vmId).replace(/[^0-9]/g, '')}-disk.qcow2`);
}

function vncInfoPath(vmId) { return path.join(VM_DIR, `vm-${vmId}.vnc.json`); }

function isPortFree(port) {
  return new Promise((resolve) => {
    const tester = net.createServer();
    tester.once('error', () => resolve(false));
    tester.once('listening', () => tester.close(() => resolve(true)));
    tester.listen(port, '127.0.0.1');
  });
}

async function allocateDisplay() {
  for (let d = 0; d < VNC_MAX_DISPLAYS; d++) {
    if (_allocatedDisplays.has(d)) continue;
    if (await isPortFree(VNC_BASE_PORT + d)) { _allocatedDisplays.add(d); return d; }
  }
  throw new Error('No free VNC display slots on this node (all ' + VNC_MAX_DISPLAYS + ' in use)');
}

function releaseDisplay(vmId) {
  try {
    const p = vncInfoPath(vmId);
    if (fs.existsSync(p)) {
      const info = JSON.parse(fs.readFileSync(p, 'utf8'));
      if (typeof info.display === 'number') _allocatedDisplays.delete(info.display);
      fs.unlinkSync(p);
    }
  } catch (e) { /* best-effort cleanup */ }
}

function vncInfo(vm) {
  const p = vncInfoPath(vm.vm_id);
  if (!fs.existsSync(p)) return { available: false };
  try {
    const info = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (!isPidAlive(info.qemuPid)) { releaseDisplay(vm.vm_id); return { available: false }; }
    return { available: true, host: '127.0.0.1', port: info.port, display: info.display };
  } catch (e) { return { available: false }; }
}

function resolveQemuBinary() {
  const candidates = [process.env.QEMU_BIN, 'qemu-system-x86_64', '/usr/bin/qemu-system-x86_64', '/usr/libexec/qemu-kvm'].filter(Boolean);
  const { execFileSync } = require('child_process');
  for (const bin of candidates) {
    try { execFileSync(bin, ['--version'], { stdio: 'pipe', timeout: 5000 }); return bin; } catch (e) { /* try next */ }
  }
  return null;
}

function isPidAlive(pid) {
  if (!pid) return false;
  try { process.kill(pid, 0); return true; } catch (e) { return false; }
}

async function buildArgs(vm, vncDisplay) {
  const kvm = await systemInfo.detectKvm();
  const args = ['-m', String(vm.memory || 1024), '-smp', String(vm.cpus || 1), '-nographic'];
  if (kvm.available) args.push('-enable-kvm');
  args.push('-cpu', kvm.available ? 'host' : 'qemu64');

  // Graphical VNC display, bound to localhost only - reached exclusively
  // through the agent's own WebSocket relay (see agent.js 'vnc-open'),
  // never exposed directly. This runs alongside -serial mon:stdio (the
  // "VNM Built-in Console"); the two are independent and QEMU is happy
  // to serve both at once.
  if (typeof vncDisplay === 'number') {
    args.push('-vnc', `127.0.0.1:${vncDisplay}`);
  }

  args.push('-boot', (vm.boot_from_iso && vm.iso_attached) ? 'order=d,menu=off' : 'c');
  args.push('-drive', `if=floppy,index=-1`);
  args.push('-drive', `file=${vm.disk_file},format=qcow2,if=virtio,media=disk`);

  // Install ISO: prefer a node-local copy (streamed to this node at VM
  // creation / attach time). vm.iso_attached is a path on the PANEL's
  // machine and means nothing here - exactly like disk_file.
  let isoPath = null;
  if (vm.iso_attached) {
    const localIso = path.join(TEMPLATES_DIR, path.basename(vm.iso_attached));
    if (fs.existsSync(localIso)) isoPath = localIso;
    else if (fs.existsSync(vm.iso_attached)) isoPath = vm.iso_attached;
  }
  if (isoPath) {
    args.push('-drive', `file=${isoPath},format=raw,media=cdrom,if=ide,index=0`);
  }

  // Cloud-init seed ISO (cidata CD-ROM): carries the users/keys/network
  // config the panel generated - without it a cloud-init VM boots with
  // no credentials, i.e. no real SSH. Mirrors the panel's local launcher
  // (same drive config, index 1 so it never collides with the ISO above).
  const seedIso = path.join(VM_DIR, `vm-${vm.vm_id}-seed.iso`);
  if (fs.existsSync(seedIso)) {
    args.push('-drive', `file=${seedIso},format=raw,media=cdrom,if=ide,index=1`);
  }

  const netdevId = 'n0';
  const mac = vm.mac_address || `52:54:00:${[0, 0, 0].map(() => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(':')}`;
  // NIC model is selectable per VM (panel sends vms.nic_model); VirtIO is
  // the default and fastest, the others trade speed for driver compat.
  const nicModel = ['virtio-net-pci', 'e1000', 'e1000e', 'rtl8139', 'vmxnet3'].includes(vm.nic_model)
    ? vm.nic_model : 'virtio-net-pci';
  args.push('-device', `${nicModel},netdev=${netdevId},mac=${mac}`);
  if (vm.network_type === 'bridge' && vm.bridge_device) {
    args.push('-netdev', `bridge,id=${netdevId},br=${vm.bridge_device}`);
  } else {
    const sshPort = vm.ssh_port || 2222;
    // Optional RDP forward (host:rdp_port -> guest:3389) when "Enable RDP"
    // has been used on this VM. A busy port never blocks the VM from booting.
    let rdpFwd = '';
    if (vm.rdp_enabled && vm.rdp_port) {
      if (await rdpGuest.waitPortFree(parseInt(vm.rdp_port, 10))) {
        rdpFwd = `,hostfwd=tcp::${parseInt(vm.rdp_port, 10)}-:3389`;
      } else {
        console.warn(`[Agent] vm-${vm.vm_id}: RDP host port ${vm.rdp_port} is in use - starting without the RDP forward`);
      }
    }
    // Custom port-forward rules (vm_port_forwards rows sent by the panel
    // with the start payload) become extra QEMU hostfwd entries. Values
    // are re-validated here so a bad row can never corrupt the argv.
    const fwdExtra = (Array.isArray(vm.port_forwards) ? vm.port_forwards : [])
      .map(f => {
        const proto = String(f.protocol || 'tcp').toLowerCase() === 'udp' ? 'udp' : 'tcp';
        const host = parseInt(f.host_port, 10), guest = parseInt(f.guest_port, 10);
        return (host >= 1 && host <= 65535 && guest >= 1 && guest <= 65535 && host !== parseInt(sshPort, 10))
          ? `,hostfwd=${proto}::${host}-:${guest}` : '';
      })
      .filter(Boolean).join('');
    args.push('-netdev', `user,id=${netdevId},hostfwd=tcp::${sshPort}-:22${rdpFwd}${fwdExtra}`);
    if (fwdExtra) console.log(`[Agent] vm-${vm.vm_id}: custom port forwards attached`);
    // QEMU monitor socket so the panel can hot-add an RDP forward later.
    const hmpSock = hmpPath(vm.vm_id);
    try { fs.unlinkSync(hmpSock); } catch (e) { /* none */ }
    args.push('-monitor', `unix:${hmpSock},server,nowait`);
  }

  args.push('-serial', 'mon:stdio');
  return args;
}

async function startVM(vm) {
  const pidFile = path.join(VM_DIR, `vm-${vm.vm_id}.pid`);
  const logFile = path.join(VM_DIR, `vm-${vm.vm_id}.log`);

  if (fs.existsSync(pidFile)) {
    const existingPid = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10);
    if (isPidAlive(existingPid)) return { success: true, pid: existingPid, alreadyRunning: true };
    fs.unlinkSync(pidFile);
  }

  const qemuBin = resolveQemuBinary();
  if (!qemuBin) {
    const err = new Error('QEMU is not available on this node (checked QEMU_BIN, qemu-system-x86_64, /usr/bin/qemu-system-x86_64, /usr/libexec/qemu-kvm). Install qemu-system-x86 or set QEMU_BIN.');
    err.httpStatus = 501; err.code = 'QEMU_UNAVAILABLE';
    throw err;
  }
  const nodeLocalDisk = diskPathFor(vm.vm_id);
  if (fs.existsSync(nodeLocalDisk)) vm = { ...vm, disk_file: nodeLocalDisk };
  if (!vm.disk_file || !fs.existsSync(vm.disk_file)) {
    const err = new Error(`VM disk not found on this node (expected ${nodeLocalDisk}). Move the VM to this node again so its disk is copied over.`);
    err.httpStatus = 404; err.code = 'DISK_NOT_FOUND';
    throw err;
  }

  if (vm.network_type !== 'bridge') {
    const sshPort = vm.ssh_port || vm.ssh_port_static || 2222;
    if (!(await isPortFree(sshPort))) {
      const err = new Error(`SSH forward port ${sshPort} is already in use on this node - change this VM's SSH port or free the port.`);
      err.httpStatus = 409; err.code = 'PORT_IN_USE';
      throw err;
    }
    // Custom TCP forwards get the same honest treatment: fail with a
    // clear error BEFORE spawning QEMU (which would die on bind anyway).
    for (const f of (Array.isArray(vm.port_forwards) ? vm.port_forwards : [])) {
      if (String(f.protocol || 'tcp').toLowerCase() !== 'tcp') continue; // UDP bind probe is unreliable
      const hp = parseInt(f.host_port, 10);
      if (!(hp >= 1 && hp <= 65535) || hp === parseInt(sshPort, 10)) continue;
      if (!(await isPortFree(hp))) {
        const err = new Error(`Forward port ${hp}${f.label ? ` (${f.label})` : ''} is already in use on this node - free the port or change the rule.`);
        err.httpStatus = 409; err.code = 'PORT_IN_USE';
        throw err;
      }
    }
  }

  const vncDisplay = await allocateDisplay().catch((e) => {
    console.warn(`[Agent] VNC display allocation failed for vm-${vm.vm_id}: ${e.message} (starting without a graphical console)`);
    return null;
  });
  const args = await buildArgs(vm, vncDisplay);
  // stdin is a pipe so the panel can type into the VM's serial console
  // (-serial mon:stdio). Nothing is written unless a console command/RDP
  // provisioning explicitly asks for it.
  const child = spawn(qemuBin, args, { stdio: ['pipe', 'pipe', 'pipe'], detached: true, shell: false });
  if (child.stdin) {
    child.stdin.on('error', () => {}); // EPIPE when QEMU exits mid-write
    _vmStdins.set(String(vm.vm_id), child.stdin);
  }
  const pid = child.pid;
  if (!pid) {
    if (typeof vncDisplay === 'number') _allocatedDisplays.delete(vncDisplay);
    const err = new Error(`QEMU did not start (spawn returned no PID) for ${qemuBin}`);
    err.httpStatus = 500; err.code = 'SPAWN_FAILED';
    throw err;
  }

  fs.writeFileSync(pidFile, String(pid));
  if (vm.network_type !== 'bridge') rdpGuest.secureSocket(hmpPath(vm.vm_id)); // monitor socket: owner-only
  if (typeof vncDisplay === 'number') {
    fs.writeFileSync(vncInfoPath(vm.vm_id), JSON.stringify({ display: vncDisplay, port: VNC_BASE_PORT + vncDisplay, qemuPid: pid }));
  }
  const logStream = fs.createWriteStream(logFile, { flags: 'a' });
  child.stdout && child.stdout.pipe(logStream, { end: false });
  child.stderr && child.stderr.pipe(logStream, { end: false });
  // Release the VNC display slot on ANY exit, not just an explicit Stop -
  // otherwise a crash (the common real-world case) leaves the slot
  // marked occupied forever, and repeated crashes eventually exhaust all
  // VNC_MAX_DISPLAYS slots ("No free VNC display slots").
  child.on('exit', (code, signal) => {
    console.log(`[Agent] vm-${vm.vm_id} QEMU process exited (code ${code}, signal ${signal})`);
    _vmStdins.delete(String(vm.vm_id));
    try { fs.unlinkSync(pidFile); } catch (e) {}
    // DEEP FIX (fd leak): the log stream was piped with { end: false } and
    // never closed - every start/restart leaked one descriptor until EMFILE.
    try { logStream.end(); } catch (e) {}
    releaseDisplay(vm.vm_id);
  });
  child.unref();

  return { success: true, pid };
}

async function stopVM(vm) {
  const pidFile = path.join(VM_DIR, `vm-${vm.vm_id}.pid`);
  releaseDisplay(vm.vm_id);
  if (!fs.existsSync(pidFile)) return { success: true, message: 'VM was not running' };
  const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10);
  if (isPidAlive(pid)) {
    try {
      if (isWindows) require('child_process').exec(`taskkill /F /PID ${pid}`);
      else {
        process.kill(-pid, 'SIGTERM');
        setTimeout(() => { try { process.kill(-pid, 'SIGKILL'); } catch (e) {} }, 3000);
      }
    } catch (e) { /* already gone */ }
  }
  try { fs.unlinkSync(pidFile); } catch (e) {}
  return { success: true };
}

async function restartVM(vm) {
  await stopVM(vm);
  await new Promise((r) => setTimeout(r, 1500));
  return startVM(vm);
}

function statusVM(vm) {
  const pidFile = path.join(VM_DIR, `vm-${vm.vm_id}.pid`);
  if (!fs.existsSync(pidFile)) return { running: false };
  const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10);
  return { running: isPidAlive(pid), pid: isPidAlive(pid) ? pid : null };
}

module.exports = { startVM, stopVM, restartVM, statusVM, resolveQemuBinary, vncInfo, diskPathFor, hmpPath, VM_DIR, writeSerial, consoleTail, serialConnected };
