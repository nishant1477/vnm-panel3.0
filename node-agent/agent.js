#!/usr/bin/env node
// =====================================================================
// VNM Node Agent
// ---------------------------------------------------------------------
// Runs ON a node (local or remote) and gives the VNM Panel real access
// to that node's system: CPU/RAM/disk/KVM stats, VM start/stop/restart
// via real QEMU, and file-manager operations against VM guest
// filesystems over real SSH/SFTP.
//
// Connection model: the agent dials OUT to the panel's WebSocket
// endpoint (wss://panel-host/agent-connect) and authenticates with a
// per-node bearer token. This means a remote node behind NAT or a
// firewall that only allows outbound traffic still works, and the
// panel never needs inbound network access to the node. Once
// connected, the same socket carries heartbeats (agent -> panel) and
// commands + results (panel -> agent -> panel).
//
// Config is read from environment variables, or from a JSON config
// file (see loadFileConfig() below) written by install.sh for a
// systemd-managed install:
//   PANEL_URL     e.g. https://panel.example.com  (required)
//   AGENT_TOKEN   the per-node token issued by the panel (required)
//   AGENT_VM_DIR  where this node keeps VM disks/PIDs (default ~/vms)
//   QEMU_BIN      override the qemu-system-x86_64 path
// =====================================================================

const fs = require('fs');
const path = require('path');
const os = require('os');
const WebSocket = require('ws');
const crypto = require('crypto');
const { exec } = require('child_process');

const systemInfo = require('./lib/system-info');
const sftpOps = require('./lib/sftp-ops');
const guestSsh = require('./lib/guest-ssh');
const qemu = require('./lib/qemu-launcher');
const rdpGuest = require('./lib/rdp-guest');
const provision = require('./lib/vm-provision');
const storage = require('./lib/node-storage');

const AGENT_VERSION = require('./package.json').version;
const CONFIG_PATH = process.env.AGENT_CONFIG || '/etc/vnm-agent/config.json';

function loadFileConfig() {
  try {
    if (fs.existsSync(CONFIG_PATH)) return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch (e) { console.warn(`[Agent] Could not read ${CONFIG_PATH}: ${e.message}`); }
  return {};
}

const fileConfig = loadFileConfig();
const PANEL_URL = process.env.PANEL_URL || fileConfig.panelUrl;
const AGENT_TOKEN = process.env.AGENT_TOKEN || fileConfig.token;
const HEARTBEAT_MS = parseInt(process.env.AGENT_HEARTBEAT_MS || '15000', 10);
const RECONNECT_BASE_MS = 2000;
const RECONNECT_MAX_MS = 30000;

if (!PANEL_URL || !AGENT_TOKEN) {
  console.error('[Agent] Missing PANEL_URL or AGENT_TOKEN (set as env vars, or in ' + CONFIG_PATH + '). See node-agent/README.md.');
  process.exit(1);
}

function wsUrl() {
  const u = new URL(PANEL_URL);
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
  u.pathname = (u.pathname.replace(/\/$/, '')) + '/agent-connect';
  return u.toString();
}

let ws = null;
let reconnectDelay = RECONNECT_BASE_MS;
let heartbeatTimer = null;
const activeTransfers = new Map(); // requestId -> { stream, kind }

function log(message) {
  const line = `[Agent] ${message}`;
  console.log(line);
  try { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'log', message })); } catch (e) {}
}

function connect() {
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  log(`Connecting to ${wsUrl()} ...`);
  ws = new WebSocket(wsUrl(), { headers: { Authorization: `Bearer ${AGENT_TOKEN}` } });

  ws.on('open', () => {
    reconnectDelay = RECONNECT_BASE_MS;
    console.log('[Agent] Connected to panel');
    startHeartbeat();
  });

  ws.on('message', (data, isBinary) => {
    if (isBinary) return handleTransferChunk(data);
    let msg;
    try { msg = JSON.parse(data.toString()); } catch (e) { return; }
    if (msg.type === 'error') { console.error(`[Agent] Panel rejected the connection: ${msg.message}`); return; }
    handleControlMessage(msg).catch((e) => console.error('[Agent] handler error:', e));
  });

  ws.on('close', (code, reasonBuf) => {
    const reason = reasonBuf ? reasonBuf.toString() : '';
    console.warn(`[Agent] Disconnected from panel (code ${code}${reason ? ', reason: ' + reason : ''}) - reconnecting soon`);
    stopHeartbeat();
    for (const id of [...activeTransfers.keys()]) {
      const t = activeTransfers.get(id);
      if (!t) continue;
      if (t.kind === 'disk-upload') { abortDiskUpload(id); continue; }
      // DEEP FIX (leak): only disk uploads were cleaned up before. File
      // uploads left orphaned write streams; vnc/tcp relays left their TCP
      // sockets to QEMU ports open forever after a panel blip.
      if (t.kind === 'upload' || t.kind === 'download') {
        try { t.stream && t.stream.destroy(); } catch (e) {}
        activeTransfers.delete(id);
      } else if (t.kind === 'vnc' || t.kind === 'tcp') {
        try { t.socket && t.socket.destroy(); } catch (e) {}
        activeTransfers.delete(id);
      }
    }
    scheduleReconnect();
  });
  ws.on('error', (e) => console.error('[Agent] Socket error:', e.message));
  ws.on('unexpected-response', (req, res) => {
    console.error(`[Agent] Panel rejected the WebSocket upgrade with HTTP ${res.statusCode}.`);
    if (res.statusCode === 404) {
      console.error('[Agent] HTTP 404 on /agent-connect usually means a reverse proxy in front of the panel is routing this request to the wrong place, or is not forwarding WebSocket upgrades at all. See "Reverse proxy" in README.md.');
    } else if (res.statusCode >= 500) {
      console.error('[Agent] HTTP 5xx suggests the panel itself errored handling the upgrade, or a proxy/load balancer in front of it is misconfigured for WebSockets.');
    } else if (res.statusCode === 401 || res.statusCode === 403) {
      console.error('[Agent] Rejected as unauthorized - check that AGENT_TOKEN matches what the panel issued for this node (rotate the token and re-run install.sh if unsure).');
    }
    let body = '';
    res.on('data', (d) => { body += d; });
    res.on('end', () => {
      if (body) console.error('[Agent] Response body:', body.slice(0, 500));
      // DEEP FIX (silent death): with an 'unexpected-response' listener
      // registered, ws does NOT emit 'close' or 'error' - so a proxy 502 or
      // a panel 401 left this agent dead forever with no retry. Tear the
      // request down and schedule the reconnect explicitly.
      try { req.destroy(); } catch (e) {}
      try { ws.close(); } catch (e) {}
      scheduleReconnect();
    });
    res.on('error', () => {
      try { req.destroy(); } catch (e) {}
      try { ws.close(); } catch (e) {}
      scheduleReconnect();
    });
  });
}

let reconnectTimer = null;
function scheduleReconnect() {
  // DEEP FIX: guard against double-scheduling when 'unexpected-response'
  // and a later 'close' both fire for the same socket.
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => { reconnectTimer = null; connect(); }, reconnectDelay);
  reconnectDelay = Math.min(reconnectDelay * 1.7, RECONNECT_MAX_MS);
}

function startHeartbeat() {
  stopHeartbeat();
  const beat = async () => {
    try {
      const stats = await systemInfo.getLiveStats(qemu.VM_DIR);
      // Non-internal IPv4s of this node, so the panel can show which
      // address VMs on this node are reachable on (it stores its own
      // manual override on top of this if the admin set one).
      stats.addresses = listLocalIPv4s();
      send({ type: 'heartbeat', agentVersion: AGENT_VERSION, stats });
    } catch (e) { console.error('[Agent] heartbeat failed:', e.message); }
  };
  beat();
  heartbeatTimer = setInterval(beat, HEARTBEAT_MS);
}
function stopHeartbeat() { if (heartbeatTimer) clearInterval(heartbeatTimer); heartbeatTimer = null; }

function send(obj) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}
function sendBinary(requestId, buf) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(Buffer.concat([Buffer.from(requestId.padEnd(8, ' ').slice(0, 8)), buf]));
}

// ---------------------------------------------------------------
// Command dispatch (panel -> agent JSON request/response)
// ---------------------------------------------------------------
const ACTIONS = {
  'system.info': async () => systemInfo.getSystemInfo(qemu.VM_DIR),
  'system.stats': async () => systemInfo.getLiveStats(qemu.VM_DIR),

  'vm.start': async (payload) => qemu.startVM(payload.vm),
  'vm.stop': async (payload) => qemu.stopVM(payload.vm),
  'vm.restart': async (payload) => qemu.restartVM(payload.vm),
  'vm.status': async (payload) => qemu.statusVM(payload.vm),
  'vm.vncinfo': async (payload) => qemu.vncInfo(payload.vm),

  // ---- VM provisioning: create / resize / clean up this node's VM
  // artifacts. The panel generates all cloud-init content itself (same
  // generators it uses for local VMs) and sends it here; we just build
  // the seed ISO, cache/download the template, and materialize the
  // disk - so a VM created on this node is configured identically to a
  // local one.
  'vm.provision': async (payload) => {
    const vm = payload.vm || {};
    const id = provision.cleanVmId(vm.vm_id);
    if (!id) throw provision.httpError(400, 'Invalid VM id', { code: 'INVALID_VM_ID' });
    log('vm.provision vm-' + id + ' disk=' + vm.disk_size +
        ' template=' + (payload.template ? (payload.template.key || 'streamed') : (payload.isoStreamed ? 'iso:' + payload.isoStreamed : 'blank')));

    // Start clean: remove any half-created artifacts for this id left
    // by an earlier failed attempt (also stops a stale QEMU if one is
    // somehow still holding files for this id).
    provision.cleanupVm(id);

    let templatePath = null;
    if (payload.template && Array.isArray(payload.template.urls) && payload.template.urls.length) {
      const t = await provision.ensureTemplate({ key: payload.template.key, urls: payload.template.urls });
      templatePath = t.path;
    } else if (payload.template && payload.template.streamedName) {
      templatePath = provision.streamedPathFor(payload.template.streamedName);
      const info = await provision.qemuImgInfo(templatePath);
      if (!info.valid) throw provision.httpError(422, 'Streamed template not usable on this node: ' + info.reason, { code: 'TEMPLATE_INVALID' });
    }
    if (payload.isoStreamed) {
      const isoP = provision.streamedPathFor(payload.isoStreamed);
      if (!fs.existsSync(isoP)) throw provision.httpError(404, 'Streamed ISO not found on this node: ' + payload.isoStreamed, { code: 'ISO_NOT_FOUND' });
    }

    let seedPath = null;
    if (payload.cloudInit && payload.cloudInit.userData) {
      const r = await provision.createSeedIso(id, payload.cloudInit);
      seedPath = r.path;
    }

    let disk;
    if (templatePath) disk = await provision.createDiskFromTemplate(id, templatePath, vm.disk_size);
    else disk = await provision.createBlankDisk(id, vm.disk_size);

    // Verify the SSH forward port is actually free HERE (bind probe),
    // walking upward if it isn't - the panel persists what we return.
    const wantedPort = parseInt(vm.ssh_port || vm.ssh_port_static || 2222, 10);
    const sshPort = await provision.resolveSshPort(wantedPort);

    // Custom TCP port-forward rules: verify each host port is actually
    // free HERE at creation time, so a rule that can never bind fails the
    // create with a clear error instead of a confusing QEMU failure on
    // first start. (The panel already enforces per-VM uniqueness.)
    for (const f of (Array.isArray(vm.port_forwards) ? vm.port_forwards : [])) {
      if (String(f.protocol || 'tcp').toLowerCase() !== 'tcp') continue;
      const hp = parseInt(f.host_port, 10);
      if (!(hp >= 1 && hp <= 65535) || hp === sshPort) continue;
      if (!(await provision.isPortFree(hp))) {
        throw provision.httpError(409, `Port-forward host port ${hp}${f.label ? ` (${f.label})` : ''} is already in use on this node`, { code: 'PORT_IN_USE' });
      }
    }
    log('vm.provision vm-' + id + ' done: disk=' + disk.path + ' seed=' + (seedPath ? 'yes' : 'no') + ' sshPort=' + sshPort);
    return {
      diskPath: disk.path,
      seedPath,
      sshPort,
      sshPortChanged: sshPort !== wantedPort,
      virtualSize: disk.virtualSize || null
    };
  },

  'vm.createSeed': async (payload) => {
    const id = provision.cleanVmId(payload.vmId || (payload.vm && payload.vm.vm_id));
    const r = await provision.createSeedIso(id, payload.cloudInit || {});
    log('vm.createSeed vm-' + id + ' -> ' + r.path);
    return r;
  },

  'vm.resizeDisk': async (payload) => {
    const r = await provision.resizeDisk(payload.vmId, payload.newSize, { shrink: payload.shrink === true });
    log('vm.resizeDisk vm-' + payload.vmId + ' -> ' + payload.newSize);
    return r;
  },

  'vm.cleanup': async (payload) => {
    const r = provision.cleanupVm(payload.vmId);
    log('vm.cleanup vm-' + payload.vmId + ': ' + (r.removed.join(', ') || 'nothing to remove'));
    return r;
  },

  // ---- Node Terminal (v2.4.0): run a shell command on THIS node and
  // return stdout/stderr/exit-code. Admin-only at the panel layer and
  // audit-logged there; the agent just executes with a hard timeout and
  // output cap. Uses exec() (shell string) because the whole point is
  // interactive shell semantics for the panel's Node Terminal.
  'host.exec': async (payload) => {
    const command = String(payload.command || '');
    if (!command.trim()) throw provision.httpError(400, 'Empty command', { code: 'EMPTY_COMMAND' });
    const timeoutMs = Math.max(1000, Math.min(parseInt(payload.timeoutMs, 10) || 20000, 60000));
    log('host.exec: ' + command.slice(0, 200));
    return await new Promise((resolve) => {
      exec(command, { cwd: '/', timeout: timeoutMs, maxBuffer: 512 * 1024, killSignal: 'SIGKILL' },
        (err, stdout, stderr) => {
          resolve({
            stdout: String(stdout || '').slice(0, 256 * 1024),
            stderr: String(stderr || '').slice(0, 64 * 1024),
            code: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
            timedOut: !!(err && err.killed),
            signal: err && err.signal ? String(err.signal) : null
          });
        });
    });
  },

  // ---- Serial console bridge (v2.4.0): lets the panel drive a VM's
  // built-in serial console (write keystrokes / read the tail of the
  // serial log) - used for RDP provisioning without sshd in the guest.
  'vm.consoleWrite': async (payload) => {
    return qemu.writeSerial(payload.vm_id || (payload.vm && payload.vm.vm_id), payload.data || '');
  },
  'vm.consoleTail': async (payload) => {
    return qemu.consoleTail(payload.vm_id || (payload.vm && payload.vm.vm_id), payload.lines || 150);
  },
  'vm.consoleStatus': async (payload) => {
    const id = payload.vm_id || (payload.vm && payload.vm.vm_id);
    return { connected: qemu.serialConnected(id) };
  },

  // ---- PLATFORM (Round 5): snapshots / backups / clone / stats ----
  // All of these run qemu-img with argv arrays and refuse to touch a
  // disk while its QEMU is alive; see lib/node-storage.js.
  'vm.snapshot.create': async (payload) => {
    const r = await storage.snapshotCreate(payload.vmId, payload.tag);
    log('vm.snapshot.create vm-' + payload.vmId + ' tag=' + r.tag);
    return r;
  },
  'vm.snapshot.restore': async (payload) => {
    const r = await storage.snapshotApply(payload.vmId, payload.tag, 'a');
    log('vm.snapshot.restore vm-' + payload.vmId + ' tag=' + r.tag);
    return r;
  },
  'vm.snapshot.delete': async (payload) => {
    const r = await storage.snapshotApply(payload.vmId, payload.tag, 'd');
    log('vm.snapshot.delete vm-' + payload.vmId + ' tag=' + r.tag);
    return r;
  },
  'vm.snapshot.list': async (payload) => storage.snapshotList(payload.vmId),

  'vm.backup.create': async (payload) => {
    const r = await storage.backupCreate(payload.vmId, payload.name);
    log('vm.backup.create vm-' + payload.vmId + ' -> ' + r.file + ' (' + Math.round(r.sizeBytes / 1e6) + ' MB)');
    return r;
  },
  'vm.backup.restore': async (payload) => {
    const r = await storage.backupRestore(payload.vmId, payload.name);
    log('vm.backup.restore vm-' + payload.vmId + ' <- ' + r.restored);
    return r;
  },
  'vm.backup.delete': async (payload) => storage.backupDelete(payload.name),
  'vm.backup.verify': async (payload) => storage.backupVerify(payload.name),
  'vm.backup.list': async () => storage.backupList(),

  'vm.clone': async (payload) => {
    const r = await storage.cloneVm(payload.vmId, payload.targetVmId);
    log('vm.clone vm-' + payload.vmId + ' -> vm-' + payload.targetVmId + ' (' + Math.round(r.sizeBytes / 1e6) + ' MB)');
    return r;
  },
  'vm.diskinfo': async (payload) => storage.diskInfo(payload.vmId, { hash: payload.hash === true }),
  'vm.stats': async (payload) => storage.vmStats(payload.vmIds),
  'port.check': async (payload) => {
    const port = parseInt(payload.port, 10);
    if (!(port >= 1 && port <= 65535)) throw Object.assign(new Error('Invalid port'), { httpStatus: 400 });
    return { port, free: await provision.isPortFree(port) };
  },
  'node.storage.list': async () => storage.storageList(),
  'node.storage.check': async (payload) => storage.storageCheck(payload.path),

  // RDP access (see rdp-guest.js) - the panel cannot reach this node's
  // guest SSH forward or QEMU monitor, so these run here. All inputs are
  // validated: ids are digits only, ports are integers, hosts are IPv4.
  'rdp.provision': async (payload) => {
    const c = payload.vmConn || {};
    if (!rdpGuest.isIPv4(c.host) || !(parseInt(c.port, 10) >= 1 && parseInt(c.port, 10) <= 65535)) {
      throw Object.assign(new Error('Invalid VM connection details'), { httpStatus: 400, code: 'GUEST_SSH_FAILED' });
    }
    return rdpGuest.provisionGuest(
      { host: c.host, port: parseInt(c.port, 10), username: c.username, password: c.password },
      { log: (event, f) => log(`rdp ${event} ${JSON.stringify(f)}`), sshWaitMs: payload.sshWaitMs > 0 ? payload.sshWaitMs : undefined }
    );
  },
  'rdp.probe': async (payload) => {
    const host = payload.host || '127.0.0.1';
    const port = parseInt(payload.port, 10);
    if (!rdpGuest.isIPv4(host) || !(port >= 1 && port <= 65535)) throw Object.assign(new Error('Invalid probe target'), { httpStatus: 400 });
    return { online: await rdpGuest.probeRdp(host, port) };
  },
  'rdp.forward': async (payload) => {
    const port = parseInt(payload.port, 10);
    if (!(port >= 1024 && port <= 65535)) throw Object.assign(new Error('Invalid forward port'), { httpStatus: 400, code: 'HOSTFWD_FAILED' });
    const sock = qemu.hmpPath(payload.vm && payload.vm.vm_id); // throws INVALID_VM_ID for anything but digits
    if (payload.action === 'remove') await rdpGuest.hostfwdRemove(sock, port);
    else await rdpGuest.hostfwdAdd(sock, port);
    log(`rdp forward ${payload.action === 'remove' ? 'removed' : 'added'} vm=${payload.vm.vm_id} port=${port}`);
    return { success: true };
  },


  'file.list': async (payload) => withSftp(payload, (ctx) => sftpOps.listDirectory(ctx, payload)),
  'file.storage': async (payload) => withSftp(payload, (ctx) => sftpOps.getStorage(ctx)),
  'file.read': async (payload) => withSftp(payload, (ctx) => sftpOps.readTextFile(ctx, payload.path, payload.maxBytes)),
  'file.stat': async (payload) => withSftp(payload, (ctx) => sftpOps.statFile(ctx, payload.path)),
  'file.write': async (payload) => withSftp(payload, (ctx) => sftpOps.writeTextFile(ctx, payload.path, payload.content, payload.maxBytes)),
  'file.mkdir': async (payload) => withSftp(payload, (ctx) => sftpOps.createFolder(ctx, payload.path, payload.name)),
  'file.createFile': async (payload) => withSftp(payload, (ctx) => sftpOps.createFile(ctx, payload.path, payload.name)),
  'file.rename': async (payload) => withSftp(payload, (ctx) => sftpOps.renamePath(ctx, payload.path, payload)),
  'file.delete': async (payload) => withSftp(payload, (ctx) => sftpOps.deletePaths(ctx, undefined, payload.paths)),
  'file.compress': async (payload) => withSftp(payload, (ctx) => sftpOps.compress(ctx, payload.path, payload.names, payload.archiveName, payload.format)),
  'file.extract': async (payload) => withSftp(payload, (ctx) => sftpOps.extract(ctx, payload.path, payload.archiveName, payload.destName))
};

async function withSftp(payload, fn) {
  const ctx = await guestSsh.getSession(payload.vmConn);
  return fn(ctx);
}

async function handleControlMessage(msg) {
  if (msg.type === 'command') return handleCommand(msg);
  if (msg.type === 'upload-start') return handleUploadStart(msg);
  if (msg.type === 'upload-end') return handleUploadEnd(msg);
  if (msg.type === 'upload-abort') return handleUploadAbort(msg);
  if (msg.type === 'download-start') return handleDownloadStart(msg);
  if (msg.type === 'disk-upload-start') return handleDiskUploadStart(msg);
  if (msg.type === 'disk-upload-end') return handleDiskUploadEnd(msg);
  if (msg.type === 'disk-upload-abort') return abortDiskUpload(msg.requestId);
  if (msg.type === 'vnc-open') return handleVncOpen(msg);
  if (msg.type === 'vnc-close') return handleVncClose(msg);
  if (msg.type === 'tcp-open') return handleTcpOpen(msg);
  if (msg.type === 'tcp-close') return handleTcpClose(msg);
  if (msg.type === 'file-upload-start') return handleFileUploadStart(msg);
  if (msg.type === 'file-upload-end') return handleFileUploadEnd(msg);
  if (msg.type === 'file-upload-abort') return abortFileUpload(msg.requestId);
  if (msg.type === 'file-pull-start') return handleFilePullStart(msg);
}

async function handleCommand(msg) {
  const handler = ACTIONS[msg.action];
  if (!handler) {
    return send({ type: 'command-error', requestId: msg.requestId, error: `Unknown action: ${msg.action}` });
  }
  try {
    const result = await handler(msg.payload || {});
    send({ type: 'command-result', requestId: msg.requestId, result });
  } catch (e) {
    send({ type: 'command-error', requestId: msg.requestId, error: e.message, httpStatus: e.httpStatus, code: e.code });
  }
}

// ---------------------------------------------------------------
// Upload relay (panel -> agent binary chunks -> guest SFTP write)
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// VM disk migration (panel -> this node's VM directory)
// Streams a qcow2 into <VM_DIR>/vm-<id>-disk.qcow2.part, verifies the
// SHA-256 the panel computed while sending, then atomically renames it
// into place. A partial/corrupt transfer never appears under the real
// filename, so the launcher can't boot a half-copied disk. Flow control:
// the agent acks bytes once they're flushed to disk and the panel stops
// sending when too many are un-acked, so a slow disk can't make memory
// balloon during a multi-GB copy.
// ---------------------------------------------------------------
async function handleDiskUploadStart(msg) {
  try {
    const vmId = String(msg.vmId || '').replace(/[^0-9]/g, '');
    if (!vmId) throw Object.assign(new Error('Invalid VM id'), { httpStatus: 400 });
    const totalBytes = Number(msg.totalBytes);
    if (!Number.isFinite(totalBytes) || totalBytes <= 0) throw Object.assign(new Error('Invalid disk size'), { httpStatus: 400 });

    const usage = await systemInfo.diskUsage(qemu.VM_DIR);
    if (usage.freeBytes !== null && totalBytes > usage.freeBytes) {
      throw Object.assign(new Error(`Not enough free disk space on this node (need ${Math.ceil(totalBytes / 1e9)} GB, have ${Math.floor(usage.freeBytes / 1e9)} GB)`), { httpStatus: 507, code: 'DISK_FULL' });
    }
    const finalPath = qemu.diskPathFor(vmId);
    const running = qemu.statusVM({ vm_id: vmId });
    if (running.running) throw Object.assign(new Error('A VM with this id is currently running on this node'), { httpStatus: 409 });

    const partPath = finalPath + '.part';
    const out = fs.createWriteStream(partPath);
    const hash = crypto.createHash('sha256');
    const t = { kind: 'disk-upload', stream: out, partPath, finalPath, hash, bytes: 0, acked: 0, lastAck: 0, totalBytes, failed: false };
    out.on('error', (err) => {
      t.failed = true;
      send({ type: 'transfer-error', requestId: msg.requestId, error: 'Disk write failed: ' + err.message, code: err.code === 'ENOSPC' ? 'DISK_FULL' : undefined, httpStatus: err.code === 'ENOSPC' ? 507 : 500 });
      abortDiskUpload(msg.requestId);
    });
    t.onChunk = (buf) => {
      if (t.failed) return;
      t.bytes += buf.length;
      hash.update(buf);
      out.write(buf, () => {
        t.acked += buf.length;
        if (t.acked - t.lastAck >= 4 * 1024 * 1024) {
          t.lastAck = t.acked;
          send({ type: 'transfer-progress', requestId: msg.requestId, bytes: t.acked });
        }
      });
    };
    activeTransfers.set(msg.requestId, t);
    send({ type: 'transfer-ready', requestId: msg.requestId });
    console.log(`[Agent] Receiving disk for vm-${vmId} (${Math.round(totalBytes / 1e6)} MB)`);
  } catch (e) {
    send({ type: 'transfer-error', requestId: msg.requestId, error: e.message, httpStatus: e.httpStatus, code: e.code });
  }
}

function handleDiskUploadEnd(msg) {
  const t = activeTransfers.get(msg.requestId);
  if (!t || t.kind !== 'disk-upload') return;
  t.stream.end(() => {
    const fail = (error, code) => {
      try { fs.unlinkSync(t.partPath); } catch (e) {}
      activeTransfers.delete(msg.requestId);
      send({ type: 'transfer-error', requestId: msg.requestId, error, code, httpStatus: 422 });
    };
    if (t.failed) return;
    const digest = t.hash.digest('hex');
    if (t.bytes !== t.totalBytes) return fail(`Incomplete transfer: received ${t.bytes} of ${t.totalBytes} bytes`, 'INCOMPLETE');
    if (msg.sha256 && digest !== msg.sha256) return fail('Checksum mismatch - disk was corrupted in transit and has been discarded', 'CHECKSUM_MISMATCH');
    try { fs.renameSync(t.partPath, t.finalPath); }
    catch (e) { return fail('Could not finalize disk file: ' + e.message); }
    activeTransfers.delete(msg.requestId);
    console.log(`[Agent] Disk received and verified: ${t.finalPath}`);
    send({ type: 'transfer-done', requestId: msg.requestId, result: { path: t.finalPath, bytes: t.bytes, sha256: digest } });
  });
}

function abortDiskUpload(requestId) {
  const t = activeTransfers.get(requestId);
  if (!t || t.kind !== 'disk-upload') return;
  activeTransfers.delete(requestId);
  try { t.stream.destroy(); } catch (e) {}
  try { fs.unlinkSync(t.partPath); } catch (e) {}
}

async function handleUploadStart(msg) {
  try {
    const ctx = await guestSsh.getSession(msg.vmConn);
    const safeName = sftpOps.assertSafeName(msg.filename, 'File name');
    const remotePath = sftpOps.joinRemotePath(msg.targetDir, safeName);
    const writeStream = ctx.sftp.createWriteStream(remotePath);
    let bytes = 0;
    let limitHit = false;
    writeStream.on('error', (err) => {
      send({ type: 'transfer-error', requestId: msg.requestId, error: 'Upload failed: ' + err.message });
      activeTransfers.delete(msg.requestId);
    });
    activeTransfers.set(msg.requestId, {
      kind: 'upload', stream: writeStream, remotePath,
      onChunk: (buf) => {
        bytes += buf.length;
        if (msg.maxBytes && bytes > msg.maxBytes && !limitHit) {
          limitHit = true;
          writeStream.destroy();
          send({ type: 'transfer-error', requestId: msg.requestId, error: 'File exceeds the upload size limit', code: 'TOO_LARGE', httpStatus: 413 });
          activeTransfers.delete(msg.requestId);
          return;
        }
        if (!limitHit) writeStream.write(buf);
      }
    });
  } catch (e) {
    send({ type: 'transfer-error', requestId: msg.requestId, error: e.message, httpStatus: e.httpStatus });
  }
}
function handleTransferChunk(data) {
  const requestId = data.slice(0, 8).toString('utf8').trim();
  const payload = data.slice(8);
  const t = activeTransfers.get(requestId);
  if (t && t.onChunk) t.onChunk(payload);
}
function handleUploadEnd(msg) {
  const t = activeTransfers.get(msg.requestId);
  if (!t) return;
  t.stream.end(() => {
    send({ type: 'transfer-done', requestId: msg.requestId, result: { success: true, path: t.remotePath } });
    activeTransfers.delete(msg.requestId);
  });
}
function handleUploadAbort(msg) {
  const t = activeTransfers.get(msg.requestId);
  if (!t) return;
  try { t.stream.destroy(); } catch (e) {}
  activeTransfers.delete(msg.requestId);
}

// ---------------------------------------------------------------
// Download relay (guest SFTP read -> agent binary chunks -> panel)
// ---------------------------------------------------------------
async function handleDownloadStart(msg) {
  try {
    const ctx = await guestSsh.getSession(msg.vmConn);
    const info = await sftpOps.statFile(ctx, msg.path);
    const readStream = ctx.sftp.createReadStream(info.path);
    activeTransfers.set(msg.requestId, { kind: 'download', stream: readStream });
    readStream.on('data', (chunk) => sendBinary(msg.requestId, chunk));
    readStream.on('error', (err) => {
      send({ type: 'transfer-error', requestId: msg.requestId, error: 'Download failed: ' + err.message });
      activeTransfers.delete(msg.requestId);
    });
    readStream.on('end', () => {
      send({ type: 'transfer-done', requestId: msg.requestId, result: { size: info.size } });
      activeTransfers.delete(msg.requestId);
    });
  } catch (e) {
    send({ type: 'transfer-error', requestId: msg.requestId, error: e.message, httpStatus: e.httpStatus });
  }
}

// ---------------------------------------------------------------
// File pull (node filesystem -> panel). Streams a file that lives on
// THIS node (a VM disk during migration, a backup for export) back to
// the panel using the same binary framing as every other transfer.
// Restricted to files inside this agent's own VM directory tree so the
// relay can never be used to read arbitrary files off the node.
// ---------------------------------------------------------------
async function handleFilePullStart(msg) {
  try {
    const target = String(msg.path || '');
    if (!path.isAbsolute(target)) throw Object.assign(new Error('Path must be absolute'), { httpStatus: 400, code: 'INVALID_PATH' });
    const resolved = path.resolve(target);
    const vmRoot = path.resolve(qemu.VM_DIR) + path.sep;
    const backupRoot = path.resolve(storage.BACKUP_DIR) + path.sep;
    if (!resolved.startsWith(vmRoot) && !resolved.startsWith(backupRoot)) {
      throw Object.assign(new Error("Only files inside this agent's VM or backup directories can be pulled"), { httpStatus: 403, code: 'FORBIDDEN_PATH' });
    }
    let st;
    try { st = fs.statSync(resolved); } catch (e) { throw Object.assign(new Error('File not found on this node'), { httpStatus: 404, code: 'NOT_FOUND' }); }
    if (!st.isFile()) throw Object.assign(new Error('Not a regular file'), { httpStatus: 400, code: 'NOT_A_FILE' });
    const expected = Number(msg.expectedBytes);
    if (Number.isFinite(expected) && expected > 0 && st.size !== expected) {
      throw Object.assign(new Error('File size changed before transfer (' + st.size + ' != ' + expected + ')'), { httpStatus: 409, code: 'SIZE_MISMATCH' });
    }
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(resolved, { highWaterMark: 1024 * 1024 });
    activeTransfers.set(msg.requestId, { kind: 'file-pull', stream });
    stream.on('data', (chunk) => { hash.update(chunk); sendBinary(msg.requestId, chunk); });
    stream.on('error', (err) => {
      send({ type: 'transfer-error', requestId: msg.requestId, error: 'File pull failed: ' + err.message });
      activeTransfers.delete(msg.requestId);
    });
    stream.on('end', () => {
      send({ type: 'transfer-done', requestId: msg.requestId, result: { sizeBytes: st.size, sha256: hash.digest('hex') } });
      activeTransfers.delete(msg.requestId);
    });
    console.log('[Agent] Streaming file to panel: ' + resolved + ' (' + Math.round(st.size / 1e6) + ' MB)');
  } catch (e) {
    send({ type: 'transfer-error', requestId: msg.requestId, error: e.message, httpStatus: e.httpStatus, code: e.code });
  }
}

// ---------------------------------------------------------------
// noVNC relay (panel <-> agent binary chunks <-> raw TCP to the local
// QEMU VNC port). This is a plain byte pipe - the RFB protocol itself
// is spoken directly between the browser's noVNC client and QEMU; the
// agent and panel just carry the bytes, exactly like the upload/download
// relay above but bidirectional and open-ended instead of one-shot.
// ---------------------------------------------------------------
const net = require('net');

// MIRROR DOWNLOAD FIX: enable Node's Happy Eyeballs for ALL outbound sockets
// (panel connection, relays, downloads). On nodes with a global IPv6 address
// but broken v6 egress, the default resolver order (AAAA first) black-holes
// connects while curl/git work fine - racing families fixes the whole class
// of "node cannot reach the internet" issues. The downloader in
// lib/vm-provision.js additionally iterates addresses explicitly, so this
// stays a bonus, not a dependency. Opt out: VNM_NO_HAPPY_EYEBALLS=1.
try {
  if (process.env.VNM_NO_HAPPY_EYEBALLS !== '1' && typeof net.setDefaultAutoSelectFamily === 'function') {
    net.setDefaultAutoSelectFamily(true);
    if (typeof net.setDefaultAutoSelectFamilyAttemptTimeout === 'function') {
      net.setDefaultAutoSelectFamilyAttemptTimeout(750);
    }
    console.log('[NET] Happy Eyeballs enabled for all outbound sockets (disable with VNM_NO_HAPPY_EYEBALLS=1)');
  }
} catch (_happyEyeballsErr) { /* ancient Node - downloader-level fallback still applies */ }

async function handleVncOpen(msg) {
  try {
    const info = qemu.vncInfo(msg.vm);
    if (!info.available) {
      send({ type: 'transfer-error', requestId: msg.requestId, error: 'VM has no VNC console available (is it running?)', code: 'VNC_UNAVAILABLE', httpStatus: 409 });
      return;
    }
    const socket = net.connect({ host: info.host, port: info.port });
    activeTransfers.set(msg.requestId, { kind: 'vnc', socket });
    socket.on('connect', () => send({ type: 'transfer-ready', requestId: msg.requestId }));
    socket.on('data', (chunk) => sendBinary(msg.requestId, chunk));
    socket.on('error', (err) => {
      send({ type: 'transfer-error', requestId: msg.requestId, error: 'VNC socket error: ' + err.message });
      activeTransfers.delete(msg.requestId);
    });
    socket.on('close', () => {
      send({ type: 'transfer-done', requestId: msg.requestId, result: {} });
      activeTransfers.delete(msg.requestId);
    });
    activeTransfers.get(msg.requestId).onChunk = (buf) => { try { socket.write(buf); } catch (e) {} };
  } catch (e) {
    send({ type: 'transfer-error', requestId: msg.requestId, error: e.message, httpStatus: e.httpStatus });
  }
}
function handleVncClose(msg) {
  const t = activeTransfers.get(msg.requestId);
  if (!t) return;
  try { t.socket.destroy(); } catch (e) {}
  activeTransfers.delete(msg.requestId);
}


// ---------------------------------------------------------------
// Streamed file upload (panel -> this node's templates dir)
// Same verified, flow-controlled framing as the disk migration upload,
// but the destination is a template/ISO file in TEMPLATES_DIR rather
// than a VM disk. Used when a custom template or install ISO only
// exists on the panel (no download URL) and must be pushed to the node
// before vm.provision runs.
// ---------------------------------------------------------------
const STREAMED_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,118}\.(qcow2|iso|img)$/i;

async function handleFileUploadStart(msg) {
  try {
    const name = String(msg.name || '');
    if (!STREAMED_NAME_RE.test(name)) {
      throw provision.httpError(400, 'Invalid file name (allowed: letters, digits, dot, dash, underscore; .qcow2/.iso/.img)', { code: 'INVALID_NAME' });
    }
    const totalBytes = Number(msg.totalBytes);
    if (!Number.isFinite(totalBytes) || totalBytes <= 0) throw provision.httpError(400, 'Invalid file size', { code: 'INVALID_SIZE' });

    const usage = await systemInfo.diskUsage(qemu.VM_DIR);
    if (usage.freeBytes !== null && totalBytes > usage.freeBytes) {
      throw provision.httpError(507, 'Not enough free disk space on this node (need ' + Math.ceil(totalBytes / 1e9) + ' GB, have ' + Math.floor(usage.freeBytes / 1e9) + ' GB)', { code: 'DISK_FULL' });
    }

    const finalPath = provision.streamedPathFor(name);
    const partPath = finalPath + '.part';
    const out = fs.createWriteStream(partPath);
    const hash = crypto.createHash('sha256');
    const t = { kind: 'file-upload', stream: out, partPath, finalPath, hash, bytes: 0, acked: 0, lastAck: 0, totalBytes, failed: false };
    out.on('error', (err) => {
      t.failed = true;
      send({ type: 'transfer-error', requestId: msg.requestId, error: 'File write failed: ' + err.message, code: err.code === 'ENOSPC' ? 'DISK_FULL' : undefined, httpStatus: err.code === 'ENOSPC' ? 507 : 500 });
      abortFileUpload(msg.requestId);
    });
    t.onChunk = (buf) => {
      if (t.failed) return;
      t.bytes += buf.length;
      hash.update(buf);
      out.write(buf, () => {
        t.acked += buf.length;
        if (t.acked - t.lastAck >= 4 * 1024 * 1024) {
          t.lastAck = t.acked;
          send({ type: 'transfer-progress', requestId: msg.requestId, bytes: t.acked });
        }
      });
    };
    activeTransfers.set(msg.requestId, t);
    send({ type: 'transfer-ready', requestId: msg.requestId });
    console.log('[Agent] Receiving streamed file ' + name + ' (' + Math.round(totalBytes / 1e6) + ' MB)');
  } catch (e) {
    send({ type: 'transfer-error', requestId: msg.requestId, error: e.message, httpStatus: e.httpStatus, code: e.code });
  }
}

function handleFileUploadEnd(msg) {
  const t = activeTransfers.get(msg.requestId);
  if (!t || t.kind !== 'file-upload') return;
  t.stream.end(() => {
    const fail = (error, code) => {
      try { fs.unlinkSync(t.partPath); } catch (e) {}
      activeTransfers.delete(msg.requestId);
      send({ type: 'transfer-error', requestId: msg.requestId, error, code, httpStatus: 422 });
    };
    if (t.failed) return;
    const digest = t.hash.digest('hex');
    if (t.bytes !== t.totalBytes) return fail('Incomplete transfer: received ' + t.bytes + ' of ' + t.totalBytes + ' bytes', 'INCOMPLETE');
    if (msg.sha256 && digest !== msg.sha256) return fail('Checksum mismatch - file was corrupted in transit and has been discarded', 'CHECKSUM_MISMATCH');
    try { fs.renameSync(t.partPath, t.finalPath); }
    catch (e) { return fail('Could not finalize file: ' + e.message); }
    activeTransfers.delete(msg.requestId);
    console.log('[Agent] Streamed file received and verified: ' + t.finalPath);
    send({ type: 'transfer-done', requestId: msg.requestId, result: { path: t.finalPath, bytes: t.bytes, sha256: digest } });
  });
}

function abortFileUpload(requestId) {
  const t = activeTransfers.get(requestId);
  if (!t || t.kind !== 'file-upload') return;
  activeTransfers.delete(requestId);
  try { t.stream.destroy(); } catch (e) {}
  try { fs.unlinkSync(t.partPath); } catch (e) {}
}

// ---------------------------------------------------------------
// Generic localhost TCP relay (panel <-> agent <-> 127.0.0.1:port on
// this node). Used for the SSH web terminal: the panel's ssh2 client
// speaks SSH over this pipe, so the browser gets a real terminal into
// the VM's forwarded SSH port without the node ever being reachable
// inbound (works through NAT - same property as the rest of the agent
// protocol). Deliberately restricted to 127.0.0.1 targets so the agent
// can never be used as an SSRF pivot to arbitrary hosts.
// ---------------------------------------------------------------
async function handleTcpOpen(msg) {
  try {
    const host = (msg.host === '::1' || msg.host === 'localhost') ? '127.0.0.1' : msg.host;
    if (host !== '127.0.0.1') throw provision.httpError(400, 'Only 127.0.0.1 relay targets are allowed', { code: 'INVALID_TARGET' });
    const port = parseInt(msg.port, 10);
    if (!(port >= 1 && port <= 65535)) throw provision.httpError(400, 'Invalid relay port', { code: 'INVALID_PORT' });
    const socket = net.connect({ host, port });
    activeTransfers.set(msg.requestId, { kind: 'tcp', socket });
    socket.on('connect', () => { send({ type: 'transfer-ready', requestId: msg.requestId }); log('tcp relay open -> 127.0.0.1:' + port); });
    socket.on('data', (chunk) => sendBinary(msg.requestId, chunk));
    socket.on('error', (err) => {
      send({ type: 'transfer-error', requestId: msg.requestId, error: 'Relay socket error: ' + err.message });
      activeTransfers.delete(msg.requestId);
    });
    socket.on('close', () => {
      send({ type: 'transfer-done', requestId: msg.requestId, result: {} });
      activeTransfers.delete(msg.requestId);
    });
    activeTransfers.get(msg.requestId).onChunk = (buf) => { try { socket.write(buf); } catch (e) {} };
  } catch (e) {
    send({ type: 'transfer-error', requestId: msg.requestId, error: e.message, httpStatus: e.httpStatus, code: e.code });
  }
}
function handleTcpClose(msg) {
  const t = activeTransfers.get(msg.requestId);
  if (!t) return;
  try { t.socket.destroy(); } catch (e) {}
  activeTransfers.delete(msg.requestId);
}

function listLocalIPv4s() {
  const out = [];
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const a of (ifaces[name] || [])) {
      if (a.family === 'IPv4' && !a.internal) out.push(a.address);
    }
  }
  return out;
}

console.log(`[Agent] VNM Node Agent v${AGENT_VERSION} starting (pid ${process.pid})`);
console.log('[Agent] Made by Immortal');
console.log(`[Agent] Panel: ${PANEL_URL}`);
console.log(`[Agent] VM directory: ${qemu.VM_DIR}`);
connect();

process.on('SIGTERM', () => { console.log('[Agent] Shutting down'); if (ws) ws.close(); process.exit(0); });
process.on('SIGINT', () => { console.log('[Agent] Shutting down'); if (ws) ws.close(); process.exit(0); });
