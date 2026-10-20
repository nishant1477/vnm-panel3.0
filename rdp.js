// =====================================================================
// VNM — RDP access for VMs (xrdp inside Debian/Ubuntu guests)
// ---------------------------------------------------------------------
// "Enable RDP" does the following, none of which touch the existing
// SSH / VNC / serial-console code paths:
//
//   1. connects to the guest over the existing VM SSH mechanism,
//      detects the OS, checks sudo, and idempotently installs/configures
//      xrdp + a desktop session,
//   2. NAT VMs: allocates a unique host port (vms.rdp_port, unique index)
//      and adds a QEMU forward  host:<rdp_port> -> guest:3389 (hot-added
//      through the QEMU monitor on a running VM, and added to the QEMU
//      command line on every later start),
//      Non-NAT VMs: no forward - the VM's own address on port 3389 is used,
//   3. verifies with a real RDP handshake, and
//   4. reports live Online/Offline from a real handshake on every request.
//
// Remote-node VMs use the same flow relayed through the node agent
// (`rdp.provision`, `rdp.forward`, `rdp.probe`).
// =====================================================================

const express = require('express');
const path = require('path');
const fs = require('fs');
const net = require('net');
const guest = require('./rdp-guest');

const DEFAULT_START = 33890;
const DEFAULT_END = 34889;

// vms columns added by this feature (applied via app.js's existing
// `missingColumns` migration - additive, safe on existing databases).
const RDP_COLUMNS = [
  { name: 'rdp_enabled', def: 'INTEGER DEFAULT 0' },
  { name: 'rdp_port', def: 'INTEGER' },
  { name: 'rdp_status', def: "TEXT DEFAULT 'disabled'" },
  { name: 'rdp_error', def: 'TEXT' },
  { name: 'rdp_guest_os', def: 'TEXT' },
  { name: 'rdp_installed_at', def: 'DATETIME' },
  { name: 'rdp_restart_needed', def: 'INTEGER DEFAULT 0' },
  { name: 'rdp_auto', def: 'INTEGER DEFAULT 0' } // 1 = set RDP up automatically once the VM is running and reachable (chosen at VM creation)
];

// Error codes whose message is written for end users. Anything else is
// replaced by a generic message; the real error stays in the server log.
const USER_SAFE_CODES = new Set([
  'UNSUPPORTED_OS', 'GUEST_SSH_FAILED', 'GUEST_AUTH_FAILED', 'GUEST_NO_SUDO', 'GUEST_TIMEOUT',
  'GUEST_UPLOAD_FAILED', 'XRDP_INSTALL_FAILED', 'DESKTOP_INSTALL_FAILED', 'XRDP_NOT_LISTENING',
  'RDP_PORT_CONFLICT', 'GUEST_SETUP_FAILED', 'NO_FREE_PORT', 'HOSTFWD_FAILED', 'NO_MONITOR',
  'INVALID_VM_ID', 'GUEST_SSH_HANDSHAKE', 'GUEST_SSH_UNREACHABLE'
]);

function readRange() {
  let start = parseInt(process.env.RDP_PORT_START || DEFAULT_START, 10);
  let end = parseInt(process.env.RDP_PORT_END || DEFAULT_END, 10);
  const bad = !(start >= 1024 && end <= 65535 && start <= end);
  if (bad) {
    console.warn(`[RDP] Invalid RDP_PORT_START/RDP_PORT_END (${process.env.RDP_PORT_START}-${process.env.RDP_PORT_END}); using ${DEFAULT_START}-${DEFAULT_END}`);
    start = DEFAULT_START; end = DEFAULT_END;
  }
  return { start, end };
}

module.exports = function createRdp({ db, checkAuth, getSSHPort, nodeManager, auditLog, logVMAction, VM_DIR, vmRuntime, qemuStdins }) {
  const router = express.Router({ mergeParams: true });
  const { start: RDP_PORT_START, end: RDP_PORT_END } = readRange();
  const RDP_PUBLIC_HOST = (process.env.RDP_PUBLIC_HOST || '').trim();

  // v2.4.0: serial-console provisioner (panel-side). Preferred path for
  // RDP setup — logs into the VM's built-in serial console with the VM
  // password, so it works even when the guest has no reachable sshd.
  const serial = qemuStdins ? require('./rdp-serial')({ VM_DIR, qemuStdins, nodeManager }) : null;

  // vmId -> { step, startedAt }  (in-memory: a setup in flight)
  const jobs = new Map();
  // vmId -> last status string (to log transitions only)
  const lastStatus = new Map();
  // vmId -> timestamp of the last forward re-assert (throttle)
  const lastEnsure = new Map();
  // Auto-setup bookkeeping (in memory; the durable switch is vms.rdp_auto)
  const autoAttempts = new Map();   // vmId -> attempts made
  const autoNext = new Map();       // vmId -> earliest time of next attempt
  const autoLast = new Map();       // vmId -> last reason shown to the user while waiting
  const AUTO_EVERY_MS = 20000;
  const AUTO_MAX = Math.max(3, parseInt(process.env.RDP_AUTO_MAX_ATTEMPTS || '90', 10) || 90); // ~30 min of retries

  const dbGet = (sql, p = []) => new Promise((res, rej) => db.get(sql, p, (e, r) => (e ? rej(e) : res(r))));
  const dbAll = (sql, p = []) => new Promise((res, rej) => db.all(sql, p, (e, r) => (e ? rej(e) : res(r))));
  const dbRun = (sql, p = []) => new Promise((res, rej) => db.run(sql, p, function (e) { return e ? rej(e) : res(this); }));

  const hmpPath = (vmId) => path.join(VM_DIR, `vm-${guest.cleanVmId(vmId)}.hmp`);

  // -------------------------------------------------------------------
  // Structured logging - one JSON object per line, never any credential.
  // -------------------------------------------------------------------
  const SECRET_KEYS = /pass|secret|token|credential/i;
  function rlog(level, event, fields = {}) {
    const safe = {};
    for (const k of Object.keys(fields)) safe[k] = SECRET_KEYS.test(k) ? '[redacted]' : fields[k];
    const line = '[RDP] ' + JSON.stringify({ ts: new Date().toISOString(), event, ...safe });
    (console[level] || console.log)(line);
  }

  // Turn any error into { code, message } safe to show a user; log the real one.
  function describeError(e, vmId, where) {
    let code = e && e.code;
    let message;
    if (code === 'NODE_OFFLINE') message = 'The node this VM runs on is offline.';
    else if (code === 'TIMEOUT') message = 'The node did not respond in time. Check that the node agent is running and try again.';
    else if (code && USER_SAFE_CODES.has(code)) message = e.message;
    else { code = 'RDP_INTERNAL_ERROR'; message = 'Unexpected error while configuring RDP. Details were written to the panel log.'; }
    rlog('error', 'error', { vmId, where, code: (e && e.code) || code, message: e && e.message, stack: e && e.stack });
    return { code, message };
  }

  // -------------------------------------------------------------------
  // Schema / startup
  // -------------------------------------------------------------------
  async function ensureSchema() {
    // Unique index = the hard guarantee that two VMs can never share a
    // host RDP port, even if two enable requests race.
    try {
      await dbRun(`CREATE UNIQUE INDEX IF NOT EXISTS idx_vms_rdp_port ON vms(rdp_port) WHERE rdp_port IS NOT NULL`);
    } catch (e) {
      rlog('warn', 'index_failed', { message: e.message });
    }
    // A setup that was running when the panel stopped can never finish.
    try {
      const r = await dbRun(
        `UPDATE vms SET rdp_status = 'error', rdp_error = 'RDP setup was interrupted by a panel restart - click Enable RDP to retry' WHERE rdp_status = 'installing'`
      );
      if (r.changes) rlog('info', 'interrupted_setups_reset', { count: r.changes });
    } catch (e) { /* column may not exist yet on first boot */ }
  }

  // -------------------------------------------------------------------
  // Port allocation (serialised so concurrent requests can't collide)
  // -------------------------------------------------------------------
  let allocChain = Promise.resolve();
  function allocatePort(vmId, skip = new Set()) {
    const run = allocChain.then(() => _allocatePort(vmId, skip));
    allocChain = run.catch(() => {});
    return run;
  }

  async function _allocatePort(vmId, skip) {
    const own = await dbGet(`SELECT rdp_port FROM vms WHERE vm_id = ?`, [vmId]);
    if (own && own.rdp_port && !skip.has(own.rdp_port)) {
      rlog('info', 'port_reused', { vmId, port: own.rdp_port });
      return own.rdp_port;
    }

    const rows = await dbAll(`SELECT rdp_port, ssh_port, ssh_port_static FROM vms`);
    const used = new Set(skip);
    rows.forEach((r) => [r.rdp_port, r.ssh_port, r.ssh_port_static].forEach((p) => { if (p) used.add(parseInt(p, 10)); }));

    for (let p = RDP_PORT_START; p <= RDP_PORT_END; p++) {
      if (used.has(p)) continue;
      if (!(await guest.isPortFree(p))) { rlog('info', 'port_busy_skipped', { vmId, port: p }); continue; } // bound by a non-VM process
      try {
        await dbRun(`UPDATE vms SET rdp_port = ? WHERE vm_id = ?`, [p, vmId]);
        rlog('info', 'port_allocated', { vmId, port: p });
        return p;
      } catch (e) {
        if (/UNIQUE/i.test(e.message)) continue; // lost a race - try the next port
        throw e;
      }
    }
    const err = new Error(`No free RDP host ports left in ${RDP_PORT_START}-${RDP_PORT_END}. Free a port or widen RDP_PORT_START/RDP_PORT_END.`);
    err.code = 'NO_FREE_PORT';
    throw err;
  }

  // -------------------------------------------------------------------
  // Used by startQemuVM() (app.js): the extra QEMU hostfwd fragment.
  // Never blocks a VM from booting - if the port is unexpectedly taken
  // the VM starts without RDP and the problem is recorded.
  // -------------------------------------------------------------------
  async function getStartForward(vm) {
    if (!vm || !vm.rdp_enabled || !vm.rdp_port || vm.network_type !== 'nat') return '';
    const port = parseInt(vm.rdp_port, 10);
    if (!(port >= 1 && port <= 65535)) return '';
    if (!(await guest.waitPortFree(port))) {
      rlog('warn', 'start_port_in_use', { vmId: vm.vm_id, port });
      db.run(`UPDATE vms SET rdp_error = ?, rdp_restart_needed = 1 WHERE vm_id = ?`,
        [`Host port ${port} is in use by another process - RDP forward not active`, vm.vm_id],
        (e) => { if (e) rlog('error', 'db_update_failed', { vmId: vm.vm_id, message: e.message }); });
      return '';
    }
    db.run(`UPDATE vms SET rdp_restart_needed = 0, rdp_error = NULL WHERE vm_id = ?`, [vm.vm_id],
      (e) => { if (e) rlog('error', 'db_update_failed', { vmId: vm.vm_id, message: e.message }); });
    rlog('info', 'forward_on_start', { vmId: vm.vm_id, port });
    return `,hostfwd=tcp::${port}-:${guest.RDP_GUEST_PORT}`;
  }

  // Lock the monitor socket down to the owner once QEMU has created it.
  function secureMonitor(vmId) { try { guest.secureSocket(hmpPath(vmId)); } catch (e) { /* invalid id */ } }

  // -------------------------------------------------------------------
  // Request plumbing
  // -------------------------------------------------------------------
  function loadVM(req, res, next) {
    const vmId = req.params.vm_id;
    if (!/^\d{1,12}$/.test(String(vmId || ''))) return res.status(400).json({ error: 'Invalid VM id', code: 'INVALID_VM_ID' });
    const isAdmin = req.session.role === 'admin';
    const q = isAdmin ? `SELECT * FROM vms WHERE vm_id = ?` : `SELECT * FROM vms WHERE vm_id = ? AND owner_id = ?`;
    const p = isAdmin ? [vmId] : [vmId, req.session.userId];
    db.get(q, p, async (err, vm) => {
      if (err) { rlog('error', 'db_error', { message: err.message }); return res.status(500).json({ error: 'Database error' }); }
      if (!vm) return res.status(404).json({ error: 'VM not found or access denied' });
      req.vm = vm;
      try { req.node = await nodeManager.getNodeForVM(vm); } catch (e) { req.node = null; }
      next();
    });
  }
  router.use(checkAuth, loadVM);

  const isRemote = (node) => !!(node && node.mode === 'remote');
  const isNat = (vm) => vm.network_type === 'nat';

  // Same addressing rules as the existing file manager / SSH code.
  function connFor(vm) {
    if (isNat(vm)) return { host: '127.0.0.1', port: getSSHPort(vm), username: vm.username || 'root', password: vm.password || undefined };
    if (!guest.isIPv4(vm.ipv4_address)) {
      const e = new Error('This VM has no valid IPv4 address configured yet, so it cannot be reached over SSH.');
      e.code = 'GUEST_SSH_FAILED';
      throw e;
    }
    return { host: vm.ipv4_address, port: getSSHPort(vm), username: vm.username || 'root', password: vm.password || undefined };
  }

  function publicHost(req, vm, node) {
    if (!isNat(vm)) return vm.ipv4_address || null;
    if (RDP_PUBLIC_HOST) return RDP_PUBLIC_HOST;
    if (isRemote(node)) return node.address || node.hostname || null;
    return (req && req.hostname) || 'localhost';
  }

  async function probe(vm, node) {
    const nat = isNat(vm);
    const port = nat ? vm.rdp_port : guest.RDP_GUEST_PORT;
    const host = nat ? '127.0.0.1' : vm.ipv4_address;
    if (!port || !guest.isIPv4(host)) return false;
    if (isRemote(node)) {
      const r = await nodeManager.sendNodeCommand(node.id, 'rdp.probe', { port, host }, { timeoutMs: 8000 });
      return !!(r && r.online);
    }
    return guest.probeRdp(host, parseInt(port, 10));
  }

  // -------------------------------------------------------------------
  // QEMU forward on a running VM (NAT only)
  // -------------------------------------------------------------------
  async function activateForward(vm, node, port) {
    if (isRemote(node)) {
      await nodeManager.sendNodeCommand(node.id, 'rdp.forward', { vm: { vm_id: vm.vm_id }, port, action: 'add' }, { timeoutMs: 15000 });
    } else {
      await guest.hostfwdAdd(hmpPath(vm.vm_id), port);
    }
  }

  async function deactivateForward(vm, node, port) {
    try {
      if (isRemote(node)) {
        await nodeManager.sendNodeCommand(node.id, 'rdp.forward', { vm: { vm_id: vm.vm_id }, port, action: 'remove' }, { timeoutMs: 15000 });
      } else {
        await guest.hostfwdRemove(hmpPath(vm.vm_id), port);
      }
      rlog('info', 'forward_removed', { vmId: vm.vm_id, port });
    } catch (e) {
      rlog('warn', 'forward_remove_failed', { vmId: vm.vm_id, port, message: e.message, note: 'it disappears on the next VM restart' });
    }
  }

  // Idempotently (re)assert the forward on a running VM: covers VMs that
  // were restarted, agent reconnects, or a panel restart. Throttled.
  async function ensureForward(vm, node, { force = false } = {}) {
    if (!isNat(vm) || !vm.rdp_enabled || !vm.rdp_port || vm.status !== 'running') return 'skipped';
    const now = Date.now();
    if (!force && now - (lastEnsure.get(vm.vm_id) || 0) < 30000) return 'skipped';
    lastEnsure.set(vm.vm_id, now);
    try {
      await activateForward(vm, node, vm.rdp_port);
      if (vm.rdp_restart_needed) {
        await dbRun(`UPDATE vms SET rdp_restart_needed = 0, rdp_error = NULL WHERE vm_id = ?`, [vm.vm_id]);
        vm.rdp_restart_needed = 0;
        rlog('info', 'restart_requirement_cleared', { vmId: vm.vm_id });
      }
      return 'ok';
    } catch (e) {
      if (e.code === 'NO_MONITOR') {
        if (!vm.rdp_restart_needed) await dbRun(`UPDATE vms SET rdp_restart_needed = 1 WHERE vm_id = ?`, [vm.vm_id]).catch(() => {});
        vm.rdp_restart_needed = 1;
        return 'no_monitor';
      }
      describeError(e, vm.vm_id, 'ensureForward');
      return 'failed';
    }
  }

  // Boot-time: re-assert forwards for every running NAT VM with RDP on.
  async function restoreForwards() {
    let rows = [];
    try { rows = await dbAll(`SELECT * FROM vms WHERE rdp_enabled = 1 AND status = 'running' AND network_type = 'nat'`); } catch (e) { return; }
    for (const vm of rows) {
      try {
        const node = await nodeManager.getNodeForVM(vm).catch(() => null);
        if (isRemote(node)) continue; // remote agents may not have reconnected yet; the status poll re-asserts lazily
        const r = await ensureForward(vm, node, { force: true });
        rlog('info', 'forward_restore', { vmId: vm.vm_id, result: r });
      } catch (e) { describeError(e, vm.vm_id, 'restoreForwards'); }
    }
  }

  // -------------------------------------------------------------------
  // Live status
  // -------------------------------------------------------------------
  async function computeStatus(vm, node, req) {
    const nat = isNat(vm);
    const base = {
      vm_id: vm.vm_id,
      enabled: !!vm.rdp_enabled,
      network: nat ? 'nat' : 'direct',
      port: vm.rdp_enabled ? (nat ? (vm.rdp_port || null) : guest.RDP_GUEST_PORT) : null,
      host: vm.rdp_enabled ? publicHost(req, vm, node) : null,
      username: vm.username || null,
      guest_os: vm.rdp_guest_os || null,
      installed_at: vm.rdp_installed_at || null,
      vm_status: vm.status,
      auto: !!vm.rdp_auto,
      warning: (vm.rdp_enabled && (vm.username || 'root') === 'root')
        ? 'This VM logs in as root. Logging in as root over RDP is not recommended - create a regular user in the VM and use that instead.'
        : null
    };

    const finish = (o) => {
      if (lastStatus.get(vm.vm_id) !== o.status) {
        rlog('info', 'status_change', { vmId: vm.vm_id, from: lastStatus.get(vm.vm_id) || null, to: o.status });
        lastStatus.set(vm.vm_id, o.status);
      }
      return o;
    };

    const job = jobs.get(vm.vm_id);
    if (job) return finish({ ...base, status: 'installing', message: job.step });

    if (!vm.rdp_enabled) {
      if (vm.rdp_auto) {
        return finish({ ...base, status: 'waiting', message: vm.status !== 'running'
          ? 'RDP will be set up automatically as soon as this VM is started and reachable.'
          : (autoLast.get(vm.vm_id) || 'Waiting for the VM to finish its first boot - RDP is set up automatically afterwards…') });
      }
      if (vm.rdp_status === 'unsupported') return finish({ ...base, status: 'unsupported', message: vm.rdp_error });
      if (vm.rdp_status === 'error') return finish({ ...base, status: 'error', message: vm.rdp_error });
      return finish({ ...base, status: 'disabled' });
    }

    if (vm.status !== 'running') return finish({ ...base, status: 'offline', message: 'The VM is stopped' });

    // NAT: if the forward is known to be missing, try to re-assert it first
    // (a restarted VM / reconnected agent fixes itself here).
    if (nat && vm.rdp_restart_needed) {
      await ensureForward(vm, node);
      if (vm.rdp_restart_needed) {
        return finish({ ...base, status: 'pending_restart', message: vm.rdp_error || 'Restart the VM to activate the RDP port forward' });
      }
    }

    let online = false;
    try { online = await probe(vm, node); }
    catch (e) {
      const d = describeError(e, vm.vm_id, 'probe');
      return finish({ ...base, status: 'offline', message: d.message });
    }
    if (online) return finish({ ...base, status: 'online' });

    // Offline although everything is "configured": make sure the forward is really there.
    if (nat) ensureForward(vm, node).catch(() => {});
    return finish({ ...base, status: 'offline', message: 'The VM is running but xrdp is not answering yet' });
  }

  router.get('/', async (req, res) => {
    try { res.json(await computeStatus(req.vm, req.node, req)); }
    catch (e) { const d = describeError(e, req.vm.vm_id, 'status'); res.status(500).json({ error: d.message, code: d.code }); }
  });

  // Real RDP handshake after setup, with retries (the guest needs a moment).
  async function verifyHandshake(vm, node, step) {
    for (let i = 0; i < 8; i++) {
      step(i === 0 ? 'Verifying the RDP connection' : `Verifying the RDP connection (attempt ${i + 1})`);
      try { if (await probe(vm, node)) return true; } catch (e) { /* retry */ }
      await new Promise((r) => setTimeout(r, 1500));
    }
    return false;
  }

  // -------------------------------------------------------------------
  // Enable
  // -------------------------------------------------------------------
  async function runEnable(vm, node, req, opts = {}) {
    const vmId = vm.vm_id;
    const nat = isNat(vm);
    const step = (s) => { const j = jobs.get(vmId); if (j) j.step = s; };
    const wasEnabled = !!vm.rdp_enabled;
    const triedPorts = new Set();
    rlog('info', 'enable_started', { vmId, network: nat ? 'nat' : 'direct', node: isRemote(node) ? node.id : 'local', user: vm.username });
    try {
      // 1. Guest setup first - an unsupported OS or bad credentials must not consume a port.
      //
      // v2.4.0 SERIAL-FIRST: drive the VM's built-in serial console with
      // the VM password (no sshd needed — sshd is often absent/unreachable
      // on local-node VMs). Falls back to the classic SSH path when the
      // console isn't usable (image without a serial getty, no stored
      // VM password) or on a clean auth failure via serial.
      const onEvent = (event, f) => rlog('info', event, { vmId, ...f });
      const sshWaitMs = parseInt(process.env.RDP_SSH_WAIT_MS || '', 10) > 0
        ? parseInt(process.env.RDP_SSH_WAIT_MS, 10)
        : 10 * 60 * 1000;
      let result = null;
      let via = 'serial';
      if (serial && vm.password) {
        try {
          step('Connecting via the VM serial console');
          result = await serial.serialProvision(vm, node, { onProgress: step, log: onEvent, waitMs: sshWaitMs });
          rlog('info', 'guest_ready_serial', { vmId, os: result.os, desktop: result.desktop });
        } catch (e) {
          const fallthrough = e.code === 'SERIAL_UNAVAILABLE' || e.code === 'SERIAL_LOGIN_TIMEOUT' || e.code === 'SERIAL_UPLOAD_FAILED';
          if (!fallthrough) throw e; // GUEST_AUTH_FAILED / UNSUPPORTED_OS / GUEST_SETUP_FAILED are real answers
          rlog('warn', 'serial_provision_fallback', { vmId, code: e.code, message: e.message });
          step('Serial console not usable - falling back to SSH');
        }
      }
      if (!result) {
        via = 'ssh';
        step('Connecting to the VM over SSH');
        const conn = connFor(vm);
        // BUG FIX: under TCG (hosts without KVM) a first boot takes minutes.
        // The guest helper now waits for sshd; give both paths an explicit
        // budget (RDP_SSH_WAIT_MS, default 10 min, well under the 25 min
        // agent timeout).
        result = isRemote(node)
          ? await nodeManager.sendNodeCommand(node.id, 'rdp.provision', { vmConn: conn, sshWaitMs }, { timeoutMs: 25 * 60 * 1000 })
          : await guest.provisionGuest(conn, { onProgress: step, log: onEvent, sshWaitMs });
        rlog('info', 'guest_ready_ssh', { vmId, os: result.os, desktop: result.desktop });
      }
      const provisionedVia = via;

      // 2. Host side
      let port = null, restartNeeded = 0;
      if (nat) {
        for (let attempt = 0; attempt < 3; attempt++) {
          step('Allocating a host port');
          port = await allocatePort(vmId, triedPorts);
          step('Activating the port forward');
          try {
            await activateForward(vm, node, port);
            rlog('info', 'forward_added', { vmId, port, node: isRemote(node) ? node.id : 'local' });
            restartNeeded = 0;
            break;
          } catch (e) {
            if (e.code === 'NO_MONITOR') { restartNeeded = 1; break; } // VM predates RDP support: applies on next start
            if (e.code === 'HOSTFWD_FAILED' && attempt < 2) {
              triedPorts.add(port);
              await dbRun(`UPDATE vms SET rdp_port = NULL WHERE vm_id = ?`, [vmId]);
              rlog('warn', 'forward_rejected_retry', { vmId, port });
              continue;
            }
            throw e;
          }
        }
      }

      await dbRun(
        `UPDATE vms SET rdp_enabled = 1, rdp_status = 'configured', rdp_error = NULL, rdp_guest_os = ?,
                rdp_installed_at = CURRENT_TIMESTAMP, rdp_restart_needed = ?, rdp_auto = 0 WHERE vm_id = ?`,
        [result.os || null, restartNeeded, vmId]
      );
      autoAttempts.delete(vmId); autoNext.delete(vmId); autoLast.delete(vmId);

      // 3. Verify for real (not just "the install command succeeded").
      if (!restartNeeded) {
        const fresh = await dbGet(`SELECT * FROM vms WHERE vm_id = ?`, [vmId]);
        const ok = await verifyHandshake(fresh, node, step);
        rlog(ok ? 'info' : 'warn', 'handshake_verification', { vmId, ok });
      }

      logVMAction(vmId, 'rdp_enable', 'success', (nat ? `RDP enabled on host port ${port}${restartNeeded ? ' (restart VM to activate the forward)' : ''}` : 'RDP enabled (direct address, port 3389)') + ` [via ${provisionedVia}]`);
      if (req) auditLog.log({ ...auditLog.fromReq(req), action: 'vm_rdp_enable', targetType: 'vm', targetId: String(vmId), details: (opts.auto ? 'auto, ' : '') + (nat ? `port ${port}` : 'direct') });
      rlog('info', 'enable_completed', { vmId, port, restartNeeded: !!restartNeeded });
    } catch (e) {
      const d = describeError(e, vmId, 'enable');
      const unsupported = d.code === 'UNSUPPORTED_OS';
      try {
        if (opts.auto && !unsupported) {
          // Automatic mode: the VM is probably still doing its first boot. Stay in "waiting" and retry later.
          autoLast.set(vmId, `Last attempt: ${d.message} (retrying automatically)`);
          await dbRun(`UPDATE vms SET rdp_status = 'disabled', rdp_error = NULL WHERE vm_id = ?`, [vmId]);
          rlog('warn', 'auto_attempt_failed', { vmId, attempt: autoAttempts.get(vmId) || 0, code: d.code });
          return;
        }
        if (wasEnabled) {
          await dbRun(`UPDATE vms SET rdp_error = ? WHERE vm_id = ?`, [d.message, vmId]);
        } else {
          await dbRun(
            `UPDATE vms SET rdp_enabled = 0, rdp_port = NULL, rdp_status = ?, rdp_error = ?, rdp_auto = 0 WHERE vm_id = ?`,
            [unsupported ? 'unsupported' : 'error', d.message, vmId]
          );
        }
      } catch (dbErr) { rlog('error', 'record_failure_failed', { vmId, message: dbErr.message }); }
      logVMAction(vmId, 'rdp_enable', 'failed', d.message);
      if (req) auditLog.log({ ...auditLog.fromReq(req), action: 'vm_rdp_enable', result: 'failure', targetType: 'vm', targetId: String(vmId), details: d.message });
    } finally {
      jobs.delete(vmId);
    }
  }

  // Shared by the Enable button and by automatic setup: why can't RDP be set up right now?
  // Returns null when it can, else { status, body }.
  async function preflight(vm, node) {
    if (/windows|\bwin\d/i.test(`${vm.os_type || ''} ${vm.template_type || ''}`)) {
      const msg = 'Unsupported guest OS: RDP setup is only supported on Debian and Ubuntu VMs.';
      await dbRun(`UPDATE vms SET rdp_status = 'unsupported', rdp_error = ?, rdp_auto = 0 WHERE vm_id = ?`, [msg, vm.vm_id]).catch(() => {});
      return { status: 422, body: { error: msg, code: 'UNSUPPORTED_OS' } };
    }
    if (vm.status !== 'running') {
      return { status: 409, body: { error: 'Start the VM first - xrdp is installed inside the running guest over SSH.', code: 'VM_NOT_RUNNING' } };
    }
    // BUG FIX: the status column can lie - a QEMU that crashed after a
    // healthy start used to leave status='running' forever, so setup hung
    // on SSH timeouts instead of saying the VM is down. Trust the process,
    // not the column; correct the stale state while we're at it.
    if (!isRemote(node) && vmRuntime && typeof vmRuntime.isQemuAlive === 'function' && !vmRuntime.isQemuAlive(vm)) {
      try {
        await dbRun(`UPDATE vms SET status = 'stopped' WHERE vm_id = ? AND status = 'running'`, [vm.vm_id]);
        rlog('warn', 'stale_running_state_fixed', { vmId: vm.vm_id });
      } catch (e) { /* non-fatal */ }
      return { status: 409, body: { error: 'The VM is marked running but its QEMU process is not running (it may have crashed). Start the VM again, then retry.', code: 'VM_NOT_RUNNING' } };
    }
    if (!isNat(vm) && !guest.isIPv4(vm.ipv4_address)) {
      return { status: 409, body: { error: 'This VM has no IPv4 address configured yet, so it cannot be reached.', code: 'NO_VM_ADDRESS' } };
    }
    if (isRemote(node)) {
      let online = false;
      try { const n = await nodeManager.getNode(node.id); online = !!(n && nodeManager.sanitizeNode(n).online); } catch (e) { /* fallthrough */ }
      if (!online) return { status: 502, body: { error: `Node "${node.name}" is offline`, code: 'NODE_OFFLINE' } };
    }
    return null;
  }

  async function startJob(vm, node, req, opts = {}) {
    jobs.set(vm.vm_id, { step: 'Starting', startedAt: Date.now() });
    await dbRun(`UPDATE vms SET rdp_status = 'installing', rdp_error = NULL WHERE vm_id = ?`, [vm.vm_id]).catch(() => {});
    runEnable(vm, node, req, opts); // background - the UI polls GET /
  }

  router.post('/enable', async (req, res) => {
    const vm = req.vm, node = req.node;
    if (jobs.has(vm.vm_id)) {
      return res.status(409).json({ error: 'RDP setup is already in progress for this VM', code: 'RDP_BUSY' });
    }
    const blocked = await preflight(vm, node);
    if (blocked) return res.status(blocked.status).json(blocked.body);
    await dbRun(`UPDATE vms SET rdp_auto = 0 WHERE vm_id = ?`, [vm.vm_id]).catch(() => {}); // the user took control
    await startJob(vm, node, req);
    res.status(202).json({ success: true, status: 'installing', message: 'RDP setup started' });
  });

  // -------------------------------------------------------------------
  // Automatic setup ("Enable RDP" ticked when the VM was created, or
  // switched on later from the RDP page): a VM is created stopped and
  // needs a first boot (cloud-init) before SSH works, so we wait for it
  // and retry until xrdp is up - never touching VMs that did not ask.
  // -------------------------------------------------------------------
  function canAutoEnable({ isCloudInit, templateName }) {
    return !!isCloudInit && /ubuntu|debian/i.test(String(templateName || ''));
  }

  async function setAuto(vmId, on) {
    autoAttempts.delete(vmId); autoNext.delete(vmId); autoLast.delete(vmId);
    await dbRun(`UPDATE vms SET rdp_auto = ? WHERE vm_id = ?`, [on ? 1 : 0, vmId]);
    rlog('info', on ? 'auto_enabled' : 'auto_disabled', { vmId });
  }

  const tcpOpen = (host, port, ms = 1500) => new Promise((resolve) => {
    const s = net.connect({ host, port });
    const done = (v) => { try { s.destroy(); } catch (e) { /* ignore */ } resolve(v); };
    s.setTimeout(ms, () => done(false)); s.on('connect', () => done(true)); s.on('error', () => done(false));
  });

  async function autoTick() {
    let rows = [];
    try { rows = await dbAll(`SELECT * FROM vms WHERE rdp_auto = 1 AND rdp_enabled = 0 AND status = 'running'`); } catch (e) { return; }
    for (const vm of rows) {
      const id = vm.vm_id;
      if (jobs.has(id) || Date.now() < (autoNext.get(id) || 0)) continue;
      autoNext.set(id, Date.now() + AUTO_EVERY_MS);
      let node = null; try { node = await nodeManager.getNodeForVM(vm); } catch (e) { /* local */ }
      const blocked = await preflight(vm, node);
      if (blocked) {
        autoLast.set(id, blocked.body.error);
        if (blocked.body.code === 'UNSUPPORTED_OS') await setAuto(id, false);
        continue;
      }
      if (!isRemote(node)) { // cheap "is sshd up yet?" check; remote nodes are asked by the attempt itself
        let host; try { host = connFor(vm).host; } catch (e) { autoLast.set(id, e.message); continue; }
        if (!(await tcpOpen(host, getSSHPort(vm)))) { autoLast.set(id, 'Waiting for the VM to finish booting (SSH is not up yet)…'); continue; }
      }
      const n = (autoAttempts.get(id) || 0) + 1; autoAttempts.set(id, n);
      if (n > AUTO_MAX) {
        const msg = `Automatic RDP setup gave up after ${AUTO_MAX} attempts. ${autoLast.get(id) || ''} Click Enable RDP to try again.`.trim();
        await dbRun(`UPDATE vms SET rdp_auto = 0, rdp_status = 'error', rdp_error = ? WHERE vm_id = ?`, [msg, id]).catch(() => {});
        autoAttempts.delete(id); autoNext.delete(id); autoLast.delete(id);
        rlog('warn', 'auto_gave_up', { vmId: id });
        continue;
      }
      rlog('info', 'auto_attempt', { vmId: id, attempt: n });
      await startJob(vm, node, null, { auto: true });
    }
  }

  let autoTimer = null;
  function startAutoEnable() {
    if (autoTimer) return;
    autoTimer = setInterval(() => autoTick().catch((e) => rlog('error', 'auto_tick_failed', { message: e.message })), AUTO_EVERY_MS);
    autoTimer.unref();
    setTimeout(() => autoTick().catch(() => {}), 5000).unref();
  }

  router.post('/auto', async (req, res) => {
    try {
    const vm = req.vm;
    // Validate the body instead of silently treating anything malformed as
    // "switch off" - a missing/garbage enabled field is a client bug.
    const raw = req.body ? req.body.enabled : undefined;
    const valid = raw === true || raw === false || raw === 'true' || raw === 'false' || raw === 1 || raw === 0;
    if (!valid) {
      return res.status(400).json({ error: 'Expected a JSON body like { "enabled": true }', code: 'BAD_REQUEST' });
    }
    const on = raw === true || raw === 'true' || raw === 1;
    if (on && vm.rdp_enabled) return res.status(409).json({ error: 'RDP is already enabled for this VM.', code: 'RDP_ALREADY_ENABLED' });
    if (on && !canAutoEnable({ isCloudInit: String(vm.template_type || '') !== 'iso-installer', templateName: `${vm.os_type || ''} ${vm.template_type || ''}` })) {
      return res.status(422).json({ error: 'Automatic setup is only available for Debian / Ubuntu VMs.', code: 'UNSUPPORTED_OS' });
    }
    await setAuto(vm.vm_id, on);
    const fresh = await dbGet(`SELECT * FROM vms WHERE vm_id = ?`, [vm.vm_id]);
    if (!fresh) return res.status(404).json({ error: 'VM not found', code: 'VM_NOT_FOUND' });
    res.json(await computeStatus(fresh, req.node, req));
    } catch (e) {
      console.error('[RDP] /auto failed:', e.message);
      res.status(500).json({ error: 'Failed to update RDP auto-setup: ' + e.message, code: 'AUTO_FAILED' });
    }
  });

  // -------------------------------------------------------------------
  // .rdp connection file (double-click on Windows / macOS / Remmina).
  // Contains the address and username only - never a password.
  // -------------------------------------------------------------------
  router.get('/file', async (req, res) => {
    const vm = req.vm;
    if (!vm.rdp_enabled) return res.status(409).json({ error: 'RDP is not enabled for this VM.', code: 'RDP_NOT_ENABLED' });
    const st = await computeStatus(vm, req.node, req);
    if (!st.host || !st.port) return res.status(409).json({ error: 'No connection address is available yet.', code: 'NO_ADDRESS' });
    const clean = (v) => String(v == null ? '' : v).replace(/[\r\n\0]/g, '').trim();
    const body = [
      `full address:s:${clean(st.host)}:${parseInt(st.port, 10)}`,
      `username:s:${clean(st.username)}`,
      'prompt for credentials:i:1',
      'screen mode id:i:2',
      'session bpp:i:32',
      'compression:i:1',
      'dynamic resolution:i:1',
      'smart sizing:i:1',
      'redirectclipboard:i:1',
      'audiomode:i:0',
      'autoreconnection enabled:i:1'
    ].join('\r\n') + '\r\n';
    const fname = `${(vm.vm_name || 'vm').replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60) || 'vm'}.rdp`;
    res.set({ 'Content-Type': 'application/x-rdp', 'Content-Disposition': `attachment; filename="${fname}"`, 'Cache-Control': 'no-store' });
    res.send(body);
  });

  // -------------------------------------------------------------------
  // Disable (removes the forward and frees the port; xrdp stays
  // installed in the guest so re-enabling is instant)
  // -------------------------------------------------------------------
  router.post('/disable', async (req, res) => {
    const vm = req.vm, node = req.node;
    if (jobs.has(vm.vm_id)) return res.status(409).json({ error: 'RDP setup is in progress', code: 'RDP_BUSY' });
    try {
      if (isNat(vm) && vm.rdp_port && vm.status === 'running') await deactivateForward(vm, node, vm.rdp_port);
      await dbRun(
        `UPDATE vms SET rdp_enabled = 0, rdp_port = NULL, rdp_status = 'disabled', rdp_error = NULL, rdp_restart_needed = 0 WHERE vm_id = ?`,
        [vm.vm_id]
      );
      lastEnsure.delete(vm.vm_id);
      logVMAction(vm.vm_id, 'rdp_disable', 'success', 'RDP access disabled');
      auditLog.log({ ...auditLog.fromReq(req), action: 'vm_rdp_disable', targetType: 'vm', targetId: String(vm.vm_id) });
      rlog('info', 'disabled', { vmId: vm.vm_id });
      res.json({ success: true, status: 'disabled' });
    } catch (e) {
      const d = describeError(e, vm.vm_id, 'disable');
      res.status(500).json({ error: d.message, code: d.code });
    }
  });

  // -------------------------------------------------------------------
  // Reinstall: the guest is wiped, so xrdp is gone. Called by the
  // reinstall route (VM is stopped there, so no live forward remains).
  // -------------------------------------------------------------------
  async function resetVm(vmId, reason = 'reinstall') {
    jobs.delete(vmId);
    lastEnsure.delete(vmId);
    lastStatus.delete(vmId); autoAttempts.delete(vmId); autoNext.delete(vmId); autoLast.delete(vmId);
    try { fs.unlinkSync(hmpPath(vmId)); } catch (e) { /* none */ }
    await dbRun(
      `UPDATE vms SET rdp_enabled = 0, rdp_port = NULL, rdp_status = 'disabled', rdp_error = NULL,
              rdp_guest_os = NULL, rdp_installed_at = NULL, rdp_restart_needed = 0, rdp_auto = 0 WHERE vm_id = ?`,
      [vmId]
    );
    rlog('info', 'reset', { vmId, reason });
  }

  return { router, ensureSchema, getStartForward, secureMonitor, restoreForwards, resetVm, computeStatus, RDP_COLUMNS, hmpPath, canAutoEnable, setAuto, autoTick, startAutoEnable, portRange: `${RDP_PORT_START}-${RDP_PORT_END}` };
};

module.exports.RDP_COLUMNS = RDP_COLUMNS;
