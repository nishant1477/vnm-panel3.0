#!/usr/bin/env node
// =====================================================================
// RDP integration tests - see RDP.md ("Testing") and tests/run-rdp-tests.sh
// ---------------------------------------------------------------------
// What is REAL in this suite:
//   - rdp.js (the real router/allocator/status code) and real SQLite,
//   - real QEMU processes with real NAT (user-mode) networking, hostfwd
//     and the QEMU monitor,
//   - a real Linux guest (kernel + busybox) behind that NAT which answers
//     RDP handshakes on :3389 and relays :22 to the rig's sshd, so the
//     panel's SSH goes through the real VM SSH forward,
//   - real SSH sessions (ssh2) running the real provisioning script
//     (apt-get install xrdp ...) on the rig's Debian/Ubuntu host,
//   - the real nodes.js manager talking over a real WebSocket to the real
//     node-agent process, which launches its own QEMU.
// What is NOT real: the guest behind the NAT is a minimal stand-in (not an
// installed Debian/Ubuntu running xrdp), and provisioning runs on the rig
// host that the guest relays SSH to. Tests that would change that host
// (purging xrdp, faking /etc/os-release) only run with
// VNM_TEST_ALLOW_GUEST_MUTATION=1 and are reported as SKIPPED otherwise.
// A check passes only when an independent observation confirms the outcome
// (a socket handshake, `info usernet`, dpkg, a DB row) - never because a
// function merely returned.
// =====================================================================

const path = require('path');
const fs = require('fs');
const os = require('os');
const net = require('net');
const http = require('http');
const { spawn, execSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const express = require(path.join(ROOT, 'node_modules/express'));
const sqlite3 = require(path.join(ROOT, 'node_modules/sqlite3'));
const { Client: SshClient } = require(path.join(ROOT, 'node_modules/ssh2'));
const { WebSocketServer } = require(path.join(ROOT, 'node_modules/ws'));
const g = require(path.join(ROOT, 'rdp-guest'));
const createRdp = require(path.join(ROOT, 'rdp'));
const createNodeManager = require(path.join(ROOT, 'nodes'));

const RIG = process.env.VNM_TEST_DIR || '/tmp/vnm-rdp-test';
const SSH_PORT = parseInt(process.env.VNM_TEST_SSH_PORT || '2299', 10);
const MUT = process.env.VNM_TEST_ALLOW_GUEST_MUTATION === '1';
const PASS = 'Test#Pass123';
const QEMU_WRAP = path.join(RIG, 'qemu-system-x86_64');
const VMDIR = fs.mkdtempSync(path.join(os.tmpdir(), 'vnm-rdp-vms-'));
const AGENTDIR = fs.mkdtempSync(path.join(os.tmpdir(), 'vnm-rdp-agent-'));

// ---- harness (prints straight to stdout) ------------------------------
const out = (s) => process.stdout.write(s + '\n');
const results = { pass: 0, fail: 0, skip: 0 };
const failures = [];
const ok = (cond, msg) => { if (cond) { results.pass++; out('  PASS ' + msg); } else { results.fail++; failures.push(msg); out('  FAIL ' + msg); } return !!cond; };
const skip = (msg, why) => { results.skip++; out(`  SKIP ${msg} (${why})`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, ms = 30000, every = 300) { const end = Date.now() + ms; for (;;) { const v = await fn(); if (v) return v; if (Date.now() > end) return null; await sleep(every); } }
async function group(name, fn) {
  out(`\n== ${name}`);
  try { await fn(); } catch (e) { results.fail++; failures.push(`${name}: ${e.message}`); out('  FAIL (exception) ' + (e.stack || e.message)); }
}

// Capture everything the panel code logs, so we can assert no credential leaks.
const logBuf = [];
for (const k of ['log', 'info', 'warn', 'error']) {
  console[k] = (...a) => { logBuf.push(a.map(String).join(' ')); if (process.env.VNM_TEST_VERBOSE) process.stderr.write(a.join(' ') + '\n'); };
}

const listening = (port, host = '127.0.0.1') => new Promise((r) => { const s = net.connect(port, host); s.on('connect', () => { s.destroy(); r(true); }); s.on('error', () => r(false)); });
async function prereqs() {
  const miss = [];
  if (!fs.existsSync(QEMU_WRAP) || !fs.existsSync(path.join(RIG, 'vmlinuz'))) miss.push(`test guest not built in ${RIG} (run tests/build-test-guest.sh)`);
  if (!(await listening(SSH_PORT))) miss.push(`no sshd on 127.0.0.1:${SSH_PORT} (run tests/setup-ssh-guest.sh)`);
  try { execSync('qemu-system-x86_64 --version', { stdio: 'pipe' }); } catch (e) { miss.push('qemu-system-x86_64 not installed'); }
  if (miss.length) { out('Prerequisites missing:\n - ' + miss.join('\n - ')); process.exit(2); }
}

// plain SSH login + command (does NOT run the RDP provisioning)
function sshWorks(port) {
  return new Promise((resolve) => {
    const c = new SshClient(); let done = false;
    const fin = (v) => { if (!done) { done = true; try { c.end(); } catch (e) { /* ignore */ } resolve(v); } };
    c.on('ready', () => c.exec('echo ssh-ok', (e, s) => { if (e) return fin(false); let o = ''; s.on('data', (d) => { o += d; }); s.on('close', () => fin(/ssh-ok/.test(o))); }));
    c.on('error', () => fin(false));
    c.connect({ host: '127.0.0.1', port, username: 'tester', password: PASS, readyTimeout: 10000 });
  });
}

// ---- real QEMU guests -------------------------------------------------
const guests = new Map();
function startGuest(vmId, sshFwd, { fragment = '', monitor = true } = {}) {
  const hmp = path.join(VMDIR, `vm-${vmId}.hmp`);
  try { fs.unlinkSync(hmp); } catch (e) { /* none */ }
  const args = ['-m', '256', '-machine', 'pc,accel=tcg', '-nographic', '-device', 'virtio-net-pci,netdev=n0',
    '-netdev', `user,id=n0,hostfwd=tcp::${sshFwd}-:22${fragment}`];
  if (monitor) args.push('-monitor', `unix:${hmp},server,nowait`);
  args.push('-serial', 'mon:stdio');
  const child = spawn(QEMU_WRAP, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  const rec = { child, log: '', ready: false, exited: false };
  child.stdout.on('data', (d) => { rec.log += d; if (rec.log.includes('VNM_TEST_GUEST_READY')) rec.ready = true; });
  child.stderr.on('data', () => {});
  child.on('exit', () => { rec.exited = true; });
  guests.set(vmId, rec);
  return rec;
}
async function stopGuest(vmId) {
  const rec = guests.get(vmId); if (!rec || rec.exited) return;
  rec.child.kill('SIGKILL');
  await waitFor(() => rec.exited, 5000, 100);
}
const guestReady = (vmId, ms = 60000) => waitFor(() => (guests.get(vmId) || {}).ready, ms, 250);

// ---- panel under test -------------------------------------------------
const db = new sqlite3.Database(':memory:');
const run = (s, p = []) => new Promise((r, j) => db.run(s, p, function (e) { e ? j(e) : r(this); }));
const get = (s, p = []) => new Promise((r, j) => db.get(s, p, (e, x) => (e ? j(e) : r(x))));
const nodeManager = createNodeManager({ db, logError: () => {} });
const auditLog = { log() {}, fromReq() { return {}; } };
const servers = [];

async function mkPanel(env = {}) {
  const saved = {};
  for (const k of Object.keys(env)) { saved[k] = process.env[k]; process.env[k] = env[k]; }
  const rdp = createRdp({
    db,
    checkAuth: (req, res, next) => { req.session = { role: req.get('x-test-role') || 'admin', userId: parseInt(req.get('x-test-user') || '1', 10) }; next(); },
    getSSHPort: (vm) => vm.ssh_port || vm.ssh_port_static || 22,
    nodeManager, auditLog, logVMAction() {}, VM_DIR: VMDIR
  });
  for (const k of Object.keys(env)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  await rdp.ensureSchema();
  const app = express(); app.use(express.json()); app.use('/api/vms/:vm_id/rdp', rdp.router);
  const srv = http.createServer(app);
  const wss = new WebSocketServer({ noServer: true });
  srv.on('upgrade', (req, sock, head) => {
    if (req.url.startsWith('/agent-connect')) wss.handleUpgrade(req, sock, head, (ws) => nodeManager.handleAgentConnection(ws, req));
    else sock.destroy();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  servers.push(srv);
  const base = `http://127.0.0.1:${srv.address().port}`;
  const api = async (method, id, sub = '', headers = {}) => {
    const r = await fetch(`${base}/api/vms/${id}/rdp${sub}`, { method, headers });
    const text = await r.text(); let body; try { body = JSON.parse(text); } catch (e) { body = { raw: text }; }
    return { code: r.status, body, text };
  };
  const status = async (id) => (await api('GET', id)).body;
  const settle = (id, ms = 240000) => waitFor(async () => { const s = await status(id); return s.status !== 'installing' ? s : null; }, ms, 400);
  return { rdp, srv, api, status, settle, url: base };
}

async function addVm(id, o = {}) {
  await run(`INSERT INTO vms (vm_id, vm_name, os_type, template_type, username, password, status, network_type, ssh_port, ssh_port_static, ipv4_address, owner_id, node_id)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [id, 'vm' + id, o.os || 'Ubuntu 22.04', o.tpl || 'ubuntu', o.user || 'tester', o.pass || PASS, o.status || 'running',
      o.net || 'nat', o.ssh || null, o.sshStatic || null, o.ip || null, o.owner || 1, o.node || null]);
}
const row = (id) => get('SELECT * FROM vms WHERE vm_id = ?', [id]);
const hmpOf = (id) => path.join(VMDIR, `vm-${id}.hmp`);
const fwds = (id) => g.listForwards(hmpOf(id));
const sh = (c) => execSync(c, { stdio: 'pipe', shell: '/bin/bash' }).toString().trim();
const shOk = (c) => { try { sh(c); return true; } catch (e) { return false; } };
const mainXrdpPid = () => { try { return sh('pgrep -o -x xrdp'); } catch (e) { return ''; } };
const killQemu = () => { try { sh('pkill -x qemu-system-x86 || true'); } catch (e) { /* ignore */ } };

// ======================================================================
(async () => {
  await prereqs();
  await run(`CREATE TABLE vms (vm_id INTEGER PRIMARY KEY, vm_name TEXT, os_type TEXT, template_type TEXT, username TEXT, password TEXT, status TEXT,
              network_type TEXT, ssh_port INTEGER, ssh_port_static INTEGER, ipv4_address TEXT, owner_id INTEGER, node_id INTEGER)`);
  for (const c of createRdp.RDP_COLUMNS) await run(`ALTER TABLE vms ADD COLUMN ${c.name} ${c.def}`);
  await nodeManager.ensureSchema();
  let P = await mkPanel();

  // NAT VMs, each a real QEMU guest with a real SSH forward
  const SSHF = { 1: 22981, 2: 22982, 3: 22983, 4: 22984, 5: 22985, 6: 22986, 7: 22987, 8: 22988, 9: 22989 };
  await addVm(1, { ssh: SSHF[1] });
  await addVm(2, { ssh: SSHF[2] });
  await addVm(3, { ssh: SSHF[3], pass: 'wrong-password' });
  await addVm(4, { ssh: SSHF[4], user: 'nosudo' });
  for (const id of [5, 6, 7, 8, 9]) await addVm(id, { ssh: SSHF[id] });
  for (const id of [1, 2, 3, 4, 5, 6, 7, 8]) startGuest(id, SSHF[id]);
  startGuest(9, SSHF[9], { monitor: false }); // "started before RDP support existed": no monitor socket
  for (const id of [1, 2, 3, 4, 5, 6, 7, 8, 9]) if (!(await guestReady(id))) throw new Error(`guest ${id} did not boot`);
  out('rig: 9 real QEMU guests booted behind NAT');

  // ---------------------------------------------------------------
  await group('Test 1: fresh Debian/Ubuntu guest, no xrdp -> Enable RDP', async () => {
    if (!MUT) return skip('fresh install', 'needs VNM_TEST_ALLOW_GUEST_MUTATION=1 (purges xrdp on the rig host)');
    sh('pkill -x xrdp; pkill -x xrdp-sesman; rm -f /run/xrdp/*.pid; DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y xrdp xorgxrdp >/dev/null 2>&1; rm -rf /etc/xrdp /home/tester/.xsession; true');
    ok(!shOk('dpkg -s xrdp >/dev/null 2>&1') && !(await listening(3389)), 'precondition: xrdp is NOT installed and nothing listens on 3389');
    ok((await P.status(1)).status === 'disabled', 'status before enabling is Disabled');
    const e = await P.api('POST', 1, '/enable');
    ok(e.code === 202, `enable accepted (202) -> ${e.code}`);
    const seen = new Set();
    await waitFor(async () => { const s = await P.status(1); seen.add(s.status); return s.status !== 'installing' ? s : null; }, 240000, 300);
    ok(seen.has('installing'), `Installing state was reported during setup (saw: ${[...seen].join(',')})`);
    ok(shOk('dpkg -s xrdp 2>/dev/null | grep -q "Status: install ok installed"'), 'xrdp is really installed in the guest (dpkg)');
    ok(shOk('ss -ltn | grep -qE "[:.]3389[[:space:]]"') && shOk('pgrep -x xrdp'), 'xrdp is running and listening on 3389');
    ok(shOk('test -s /home/tester/.xsession'), '.xsession created for the VM user');
    const w = await waitFor(async () => { const s = await P.status(1); return s.status === 'online' ? s : null; }, 30000);
    ok(!!w, 'status reaches Online via a real RDP handshake through the QEMU forward');
    ok(w && w.port >= 33890 && w.port <= 34889, `host port allocated in the default range (${w && w.port})`);
    ok(w && /Ubuntu|Debian/.test(w.guest_os || ''), `guest OS detected (${w && w.guest_os})`);
  });

  await group('Test 2: xrdp already installed -> Enable RDP does not reinstall or break anything', async () => {
    if (!(await P.status(1)).enabled) { await P.api('POST', 1, '/enable'); await P.settle(1); } // Test 1 skipped: make sure xrdp exists
    shOk('printf "mate-session # user customised\\n" > /home/tester/.xsession; chown tester: /home/tester/.xsession');
    const dpkgBefore = sh('grep -c " install " /var/log/dpkg.log 2>/dev/null || echo 0');
    const pid = mainXrdpPid(), cfg = sh('md5sum /etc/xrdp/xrdp.ini');
    const e = await P.api('POST', 2, '/enable'); ok(e.code === 202, 'enable accepted on a VM whose guest already has xrdp');
    const s = await P.settle(2);
    ok(sh('grep -c " install " /var/log/dpkg.log 2>/dev/null || echo 0') === dpkgBefore, 'no package was (re)installed');
    ok(pid !== '' && mainXrdpPid() === pid, `running xrdp daemon was not restarted (pid ${pid})`);
    ok(sh('md5sum /etc/xrdp/xrdp.ini') === cfg, 'xrdp configuration untouched');
    ok(sh('cat /home/tester/.xsession') === 'mate-session # user customised', 'existing .xsession NOT overwritten');
    ok(s.status !== 'error', `VM 2 ended in a healthy state (${s.status})`);
  });

  await group('Test 3: re-running Enable RDP is idempotent', async () => {
    const before = await row(1); const pid = mainXrdpPid();
    const e = await P.api('POST', 1, '/enable'); ok(e.code === 202, 're-enable accepted');
    await P.settle(1);
    const after = await row(1); const f1 = (await fwds(1)).filter((f) => f.guestPort === 3389);
    ok(after.rdp_port === before.rdp_port, `same host port reused (${after.rdp_port})`);
    ok(f1.length === 1, 'exactly one QEMU 3389 forward (no duplicate)');
    ok(mainXrdpPid() === pid, 'xrdp not restarted');
    ok(!!(await waitFor(async () => (await P.status(1)).status === 'online', 20000)), 'still Online after the re-run');
  });

  await group('Test 5/15/16: two NAT VMs -> different ports; QEMU forwarding; real handshake', async () => {
    const s1 = await P.status(1), s2 = await P.status(2);
    ok(s1.port && s2.port && s1.port !== s2.port, `different host ports (${s1.port} vs ${s2.port})`);
    ok(!!(await waitFor(async () => (await P.status(2)).status === 'online', 30000)), 'VM 2 Online through its own forward');
    const f1 = await fwds(1), f2 = await fwds(2);
    ok(f1.some((f) => f.hostPort === s1.port && f.guestPort === 3389) && f1.some((f) => f.guestPort === 22), 'VM 1 QEMU (info usernet): 3389 forward present AND SSH forward untouched');
    ok(f2.some((f) => f.hostPort === s2.port && f.guestPort === 3389) && f2.some((f) => f.guestPort === 22), 'VM 2 QEMU: 3389 forward present AND SSH forward untouched');
    ok(await g.probeRdp('127.0.0.1', s1.port) && await g.probeRdp('127.0.0.1', s2.port), 'both host ports complete a genuine RDP handshake with their own guest');
    ok(!JSON.stringify(s1).includes(PASS) && !('password' in s1), 'status API never exposes credentials');
    ok(s1.username === 'tester' && !!s1.host && !!s1.port, 'status includes host, port, username');
    const [a, b] = await Promise.all([P.api('POST', 7, '/enable'), P.api('POST', 8, '/enable')]);
    await P.settle(7); await P.settle(8);
    const p7 = (await row(7)).rdp_port, p8 = (await row(8)).rdp_port;
    ok(a.code === 202 && b.code === 202 && p7 && p8 && new Set([s1.port, s2.port, p7, p8]).size === 4, `4 VMs, 4 distinct ports under concurrent enables (${[s1.port, s2.port, p7, p8].join(',')})`);
    let rejected = false; try { await run('UPDATE vms SET rdp_port = ? WHERE vm_id = 5', [s1.port]); } catch (e) { rejected = /UNIQUE/i.test(e.message); }
    ok(rejected, 'DB unique index rejects a duplicate rdp_port');
  });

  await group('Test 6/7: VM stop -> Offline, VM start -> Online again (real QEMU restart)', async () => {
    const before = await row(1);
    await stopGuest(1); await run("UPDATE vms SET status='stopped' WHERE vm_id=1");
    const s = await P.status(1);
    ok(s.status === 'offline' && /stopped/i.test(s.message || ''), `stopped VM -> "${s.status}" (${s.message})`);
    ok(!(await listening(before.rdp_port)), 'host RDP port is no longer bound while the VM is down');
    ok((await row(1)).rdp_port === before.rdp_port, 'port stays reserved for the VM in the database');
    const frag = await P.rdp.getStartForward(await row(1));
    ok(frag === `,hostfwd=tcp::${before.rdp_port}-:3389`, `QEMU start fragment rebuilt from the DB: "${frag}"`);
    startGuest(1, SSHF[1], { fragment: frag }); await run("UPDATE vms SET status='running' WHERE vm_id=1");
    const booting = await P.status(1);
    ok(booting.status === 'offline', `right after start, before the guest answers -> "${booting.status}" (not falsely Online)`);
    ok(!!(await waitFor(async () => (await P.status(1)).status === 'online', 60000)), 'once the guest answers, status returns to Online');
    const f = (await fwds(1)).filter((x) => x.guestPort === 3389);
    ok(f.length === 1 && f[0].hostPort === before.rdp_port, 'forward baked into the QEMU command line: same port, exactly once');
    ok(!!(await waitFor(() => sshWorks(SSHF[1]), 30000, 1000)), 'SSH through the VM SSH forward still works after the restart');
  });

  await group('Test 4: panel restart -> config persists, forwarding restored, interrupted installs reset', async () => {
    const before = await row(1);
    P.srv.close(); P = await mkPanel(); // brand-new module instance, same database
    const s = await P.status(1);
    ok((await row(1)).rdp_port === before.rdp_port && s.port === before.rdp_port && s.enabled, `RDP config and port survive a panel restart (${s.port})`);
    ok(!!(await waitFor(async () => (await P.status(1)).status === 'online', 20000)), 'status recalculated from reality -> Online');
    await g.hostfwdRemove(hmpOf(1), before.rdp_port);
    ok(!(await listening(before.rdp_port)), 'precondition: forward removed from the running VM');
    await P.rdp.restoreForwards();
    ok(await listening(before.rdp_port), 'restoreForwards() re-added the forward on the running VM');
    await run("UPDATE vms SET rdp_status='installing' WHERE vm_id=5");
    await P.rdp.ensureSchema();
    const r5 = await row(5);
    ok(r5.rdp_status === 'error' && /interrupted/i.test(r5.rdp_error || ''), 'interrupted installation is not left stuck in Installing');
    ok((await P.status(5)).status !== 'installing', 'API reports an error, not Installing');
    await run("UPDATE vms SET rdp_status='disabled', rdp_error=NULL WHERE vm_id=5");
  });

  await group('Test 8: Disable RDP', async () => {
    const before = await row(2);
    const r = await P.api('POST', 2, '/disable'); ok(r.code === 200, 'disable accepted');
    ok(!(await listening(before.rdp_port)), 'host-side forwarding removed (port no longer bound)');
    const after = await row(2);
    ok(after.rdp_port === null && !after.rdp_enabled, 'port released and DB updated');
    ok((await P.status(2)).status === 'disabled', 'status is Disabled');
    const f = await fwds(2); ok(!f.some((x) => x.guestPort === 3389) && f.some((x) => x.guestPort === 22), 'QEMU: 3389 forward gone, SSH forward intact');
    ok(await sshWorks(SSHF[2]), 'SSH through VM 2 still works');
    ok(shOk('dpkg -s xrdp >/dev/null 2>&1'), 'xrdp stays installed in the guest (fast re-enable)');
  });

  await group('Test 9: VM reinstall clears RDP and releases the port', async () => {
    const before = await row(1);
    await stopGuest(1); await run("UPDATE vms SET status='stopped' WHERE vm_id=1"); // the reinstall route requires a stopped VM
    await P.rdp.resetVm(1, 'reinstall');
    const after = await row(1);
    ok(!after.rdp_enabled && after.rdp_port === null && after.rdp_status === 'disabled' && !after.rdp_guest_os && !after.rdp_installed_at, 'RDP configuration fully cleared');
    ok(!fs.existsSync(hmpOf(1)), 'stale monitor socket removed');
    ok((await P.status(1)).status === 'disabled', 'status reset to Disabled');
    ok((await P.rdp.getStartForward(after)) === '', 'the new guest starts WITHOUT any RDP forward');
    startGuest(1, SSHF[1]); await guestReady(1); await run("UPDATE vms SET status='running' WHERE vm_id=1");
    ok(!(await fwds(1)).some((f) => f.guestPort === 3389) && !(await listening(before.rdp_port)), 'no stale forward points at the new guest');
    await P.api('POST', 6, '/enable'); await P.settle(6);
    ok((await row(6)).rdp_port === before.rdp_port, `released port ${before.rdp_port} is handed out again`);
  });

  await group('Test 10: unsupported guest OS', async () => {
    if (!MUT) skip('guest reports a non-Debian OS', 'needs VNM_TEST_ALLOW_GUEST_MUTATION=1 (temporarily edits /etc/os-release)');
    else {
      fs.copyFileSync('/etc/os-release', '/tmp/os-release.vnm-bak');
      try {
        sh(`sed -i 's/^ID=.*/ID=fedora/; s/^ID_LIKE=.*/ID_LIKE=rhel/; s/^PRETTY_NAME=.*/PRETTY_NAME="Fedora Linux 40"/' /etc/os-release`);
        const e = await P.api('POST', 5, '/enable'); ok(e.code === 202, 'enable accepted (the guest decides)');
        const s = await P.settle(5);
        ok(s.status === 'unsupported', `status "unsupported" (${s.status})`);
        ok(s.message === 'Unsupported guest OS (Fedora Linux 40): RDP setup is only supported on Debian and Ubuntu VMs.', `clear message: "${s.message}"`);
        const r = await row(5); ok(r.rdp_port === null && !r.rdp_enabled, 'no port consumed, nothing enabled');
        ok(!/\bat .*\.js:\d+/.test(JSON.stringify(s)), 'no stack trace in the response');
      } finally { fs.copyFileSync('/tmp/os-release.vnm-bak', '/etc/os-release'); }
      await run("UPDATE vms SET rdp_status='disabled', rdp_error=NULL WHERE vm_id=5");
    }
    await addVm(20, { os: 'Windows Server 2022', tpl: 'windows', ssh: 22990 });
    const w2 = await P.api('POST', 20, '/enable');
    ok(w2.code === 422 && w2.body.error === 'Unsupported guest OS: RDP setup is only supported on Debian and Ubuntu VMs.', `Windows VM refused up-front with the exact message (HTTP ${w2.code})`);
  });

  await group('Test 11: invalid SSH credentials', async () => {
    const e = await P.api('POST', 3, '/enable'); ok(e.code === 202, 'accepted');
    const s = await P.settle(3);
    ok(s.status === 'error' && /Invalid credentials/i.test(s.message || ''), `status error: "${s.message}"`);
    const r = await row(3); ok(!r.rdp_enabled && r.rdp_port === null, 'nothing enabled, no port consumed');
  });

  await group('Test 12: no sudo permission', async () => {
    const e = await P.api('POST', 4, '/enable'); ok(e.code === 202, 'accepted');
    const s = await P.settle(4);
    ok(s.status === 'error' && /cannot use sudo/i.test(s.message || ''), `status error: "${s.message}"`);
    const r = await row(4); ok(!r.rdp_enabled && r.rdp_port === null, 'nothing enabled, no port consumed');
    ok(!shOk('ls /home/nosudo/.xsession 2>/dev/null'), 'nothing was configured for that user');
  });

  await group('Test 13: port allocation conflicts + restart-required handling', async () => {
    // (a) a foreign process squats on the next candidate port
    let nextPort = null;
    for (let p = 33890; p < 34100 && !nextPort; p++) { const c = await get('SELECT COUNT(*) c FROM vms WHERE rdp_port = ?', [p]); if (!c.c && await g.isPortFree(p)) nextPort = p; }
    const squatter = net.createServer(); await new Promise((r) => squatter.listen(nextPort, '0.0.0.0', r));
    await P.api('POST', 5, '/enable'); await P.settle(5);
    const p5 = (await row(5)).rdp_port;
    ok(!!p5 && p5 !== nextPort, `port ${nextPort} held by a foreign process is skipped (VM got ${p5})`);
    // (b) start-time conflict -> Restart Required, never a false Online
    await P.api('POST', 5, '/disable');
    await run("UPDATE vms SET rdp_enabled=1, rdp_port=?, rdp_status='configured', rdp_restart_needed=0 WHERE vm_id=5", [nextPort]);
    ok((await P.rdp.getStartForward(await row(5))) === '', 'start-time conflict: the VM still boots, just without the forward');
    const s = await P.status(5);
    ok(s.status === 'pending_restart', `status is Restart Required ("${s.status}"), not Online`);
    await new Promise((r) => squatter.close(r));
    // (c) range exhausted
    const tiny = await mkPanel({ RDP_PORT_START: String(nextPort), RDP_PORT_END: String(nextPort) });
    await run("UPDATE vms SET rdp_enabled=0, rdp_port=NULL, rdp_status='disabled', rdp_restart_needed=0 WHERE vm_id=5");
    await run('UPDATE vms SET rdp_port=? WHERE vm_id=6', [nextPort]); // occupy the only port
    await tiny.api('POST', 5, '/enable'); const t = await tiny.settle(5);
    ok(t.status === 'error' && /No free RDP host ports/.test(t.message || ''), `exhausted range -> clear error: "${t.message}"`);
    await run('UPDATE vms SET rdp_port=NULL WHERE vm_id=6');
    // (d) a VM started before RDP support (no monitor socket) -> Restart Required, resolved by a restart
    await P.api('POST', 9, '/enable'); await P.settle(9);
    const s9 = await P.status(9);
    ok(s9.status === 'pending_restart', `VM started without a monitor socket -> "${s9.status}" (${s9.message})`);
    await stopGuest(9); await run("UPDATE vms SET status='stopped' WHERE vm_id=9");
    const f9 = await P.rdp.getStartForward(await row(9)); startGuest(9, SSHF[9], { fragment: f9 }); await run("UPDATE vms SET status='running' WHERE vm_id=9");
    ok(!!(await waitFor(async () => (await P.status(9)).status === 'online', 60000)), 'after the restart: Restart Required cleared, Online');
  });

  await group('Network types: directly reachable VM (no NAT forward)', async () => {
    await addVm(40, { net: 'static_public', ip: '127.0.0.1', sshStatic: SSH_PORT });
    const e = await P.api('POST', 40, '/enable'); ok(e.code === 202, 'enable accepted for a non-NAT VM');
    const s = await P.settle(40); const r = await row(40);
    ok(r.rdp_enabled === 1 && r.rdp_port === null, 'no host port allocated and no NAT forward created');
    ok(s.host === '127.0.0.1' && s.port === 3389 && s.network === 'direct', `connection address is the VM address on 3389 (${s.host}:${s.port})`);
    ok(!!(await waitFor(async () => (await P.status(40)).status === 'online', 30000)), 'Online via a real handshake with xrdp on the guest\'s own address');
    await addVm(41, { net: 'static_public', ip: null, sshStatic: SSH_PORT });
    const e2 = await P.api('POST', 41, '/enable'); ok(e2.code === 409 && e2.body.code === 'NO_VM_ADDRESS', 'non-NAT VM without an address -> clear 409');
  });

  await group('Create-time option: automatic setup once the VM is up (rdp_auto)', async () => {
    // 11: running guest, SSH reachable.  12: marked running but the guest has not booted (SSH not up).  13: stopped.
    await addVm(11, { ssh: 22993 }); startGuest(11, 22993); await guestReady(11);
    await addVm(12, { ssh: 22994 });
    await addVm(13, { status: 'stopped', ssh: 22995 });
    await addVm(14, { os: 'Windows Server 2022', tpl: 'windows', ssh: 22998 });
    for (const id of [11, 12, 13, 14]) await run('UPDATE vms SET rdp_auto = 1 WHERE vm_id = ?', [id]);

    const w13 = await P.status(13);
    ok(w13.status === 'waiting' && w13.auto === true && /started/i.test(w13.message || ''), `stopped VM with auto-setup shows "waiting": "${w13.message}"`);
    await P.rdp.autoTick();
    const w12 = await P.status(12);
    ok(w12.status === 'waiting' && /SSH is not up/i.test(w12.message || ''), `VM still booting -> waiting, no attempt wasted: "${w12.message}"`);
    ok((await row(12)).rdp_auto === 1 && !(await row(12)).rdp_enabled, 'still queued for automatic setup');

    const t11 = await waitFor(async () => { const s = await P.status(11); return ['online', 'error', 'unsupported'].includes(s.status) ? s : null; }, 240000, 500);
    ok(!!t11 && t11.status === 'online', `running+reachable VM was set up with no click and reaches Online (got ${t11 && t11.status})`);
    const r11 = await row(11);
    ok(r11.rdp_enabled === 1 && r11.rdp_auto === 0 && r11.rdp_port >= 33890, `auto flag cleared after success, port ${r11.rdp_port} allocated`);
    ok(await g.probeRdp('127.0.0.1', r11.rdp_port), 'real RDP handshake through its forward');

    await P.rdp.autoTick();
    const t14 = await P.status(14);
    ok(t14.status === 'unsupported' && (await row(14)).rdp_auto === 0, `unsupported OS ends automatic setup immediately: "${t14.message}"`);

    // toggle endpoint
    const on = await P.api('POST', 13, '/auto'); // body missing -> turns it OFF
    ok(on.code === 200 && on.body.auto === false && on.body.status !== 'waiting', 'POST /auto without enabled=true turns auto-setup off');
    const post = async (id, enabled) => { const r = await fetch(`${P.url}/api/vms/${id}/rdp/auto`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }) }); return { code: r.status, body: await r.json() }; };
    const turnOn = await post(13, true);
    ok(turnOn.code === 200 && turnOn.body.status === 'waiting' && turnOn.body.auto === true, 'POST /auto {enabled:true} queues automatic setup');
    const win = await post(14, true); ok(win.code === 422 && win.body.code === 'UNSUPPORTED_OS', 'cannot queue automatic setup for a Windows VM (422)');
    const already = await post(11, true); ok(already.code === 409 && already.body.code === 'RDP_ALREADY_ENABLED', 'cannot queue it when RDP is already enabled (409)');
    // manual Enable takes over from auto
    await run('UPDATE vms SET status = ?, rdp_auto = 1 WHERE vm_id = 13', ['running']);
    startGuest(13, 22995); await guestReady(13);
    const man = await P.api('POST', 13, '/enable'); ok(man.code === 202, 'manual Enable accepted while auto-setup is queued');
    await P.settle(13);
    ok((await row(13)).rdp_auto === 0, 'manual Enable clears the automatic flag');
  });

  await group('.rdp connection file', async () => {
    const f = await fetch(`${P.url}/api/vms/11/rdp/file`);
    const text = await f.text(); const r11 = await row(11);
    ok(f.status === 200 && /application\/x-rdp/.test(f.headers.get('content-type')) && /attachment; filename="vm11\.rdp"/.test(f.headers.get('content-disposition')), 'downloads as an attachment named after the VM');
    ok(new RegExp(`full address:s:[^\\r\\n]+:${r11.rdp_port}\\r\\n`).test(text) && /username:s:tester\r\n/.test(text), 'contains the connection address and username');
    ok(!text.includes(PASS) && !/password/i.test(text), 'contains no password');
    ok(f.headers.get('cache-control') === 'no-store', 'not cacheable');
    const off = await fetch(`${P.url}/api/vms/12/rdp/file`); ok(off.status === 409, 'VM without RDP -> 409, no file');
    const other = await fetch(`${P.url}/api/vms/11/rdp/file`, { headers: { 'x-test-role': 'user', 'x-test-user': '999' } }); ok(other.status === 404, 'another user cannot download it (404)');
    await run("UPDATE vms SET username = ? WHERE vm_id = 11", ['te\r\nst']);
    const inj = await (await fetch(`${P.url}/api/vms/11/rdp/file`)).text();
    ok(!/\r\n[^\r\n]*st\r\n/.test(inj.replace(/username:s:test\r\n/, '')) && /username:s:test\r\n/.test(inj), 'CR/LF in a username cannot inject extra .rdp lines');
    await run("UPDATE vms SET username = ? WHERE vm_id = 11", ['tester']);
  });

  await group('Security / validation / authorization', async () => {
    ok((await P.api('GET', '1abc')).code === 400, 'non-numeric VM id rejected (400)');
    ok((await P.api('GET', '1;rm%20-rf')).code === 400, 'injection-style VM id rejected (400)');
    ok((await P.api('GET', 1, '', { 'x-test-role': 'user', 'x-test-user': '1' })).code === 200, 'owner can read own VM RDP status');
    ok((await P.api('GET', 1, '', { 'x-test-role': 'user', 'x-test-user': '999' })).code === 404, 'another user cannot see it (404)');
    ok((await P.api('POST', 1, '/enable', { 'x-test-role': 'user', 'x-test-user': '999' })).code === 404, 'another user cannot enable RDP on it (404)');
    ok((await P.api('POST', 6, '/disable', { 'x-test-role': 'user', 'x-test-user': '999' })).code === 404, 'another user cannot disable it (404)');
    await addVm(50, { status: 'stopped', ssh: 22992 });
    const ns = await P.api('POST', 50, '/enable'); ok(ns.code === 409 && ns.body.code === 'VM_NOT_RUNNING', 'VM not running -> clear 409');
  });

  // ---------------------------------------------------------------
  await group('Test 14: REMOTE NODE - real nodes.js <-> real node agent <-> real QEMU', async () => {
    const { node, token } = await nodeManager.createRemoteNode({ name: 'rig-remote' });
    await run("UPDATE nodes SET address='127.0.0.1' WHERE id=?", [node.id]);
    const agent = spawn(process.execPath, [path.join(ROOT, 'node-agent/agent.js')], {
      env: { ...process.env, PANEL_URL: P.url, AGENT_TOKEN: token, AGENT_VM_DIR: AGENTDIR, QEMU_BIN: QEMU_WRAP, AGENT_CONFIG: '/nonexistent', AGENT_HEARTBEAT_MS: '3000' },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let agentLog = ''; agent.stdout.on('data', (d) => { agentLog += d; }); agent.stderr.on('data', (d) => { agentLog += d; });
    try {
      ok(!!(await waitFor(async () => nodeManager.sanitizeNode(await nodeManager.getNode(node.id)).online, 20000)), 'agent connected to the panel over WebSocket');
      const RID = 60, RSSH = 22996;
      execSync(`qemu-img create -f qcow2 ${path.join(AGENTDIR, `vm-${RID}-disk.qcow2`)} 64M`, { stdio: 'pipe' });
      await addVm(RID, { ssh: RSSH, node: node.id, status: 'running' });
      const vmRow = async () => ({ ...(await row(RID)), memory: 256, cpus: 1, mac_address: '52:54:00:aa:bb:cc' });
      const start = await nodeManager.sendNodeCommand(node.id, 'vm.start', { vm: await vmRow() }, { timeoutMs: 30000 });
      ok(!!(start && start.success), 'VM started by the REAL agent launcher (its own QEMU process)');
      const vlog = path.join(AGENTDIR, `vm-${RID}.log`);
      ok(!!(await waitFor(() => fs.existsSync(vlog) && fs.readFileSync(vlog, 'utf8').includes('VNM_TEST_GUEST_READY'), 60000)), 'serial console output reaches the agent VM log (serial console intact)');
      const vnc = await nodeManager.sendNodeCommand(node.id, 'vm.vncinfo', { vm: await vmRow() }, { timeoutMs: 8000 });
      ok(vnc.available && await listening(vnc.port), `VNC still served by the agent's QEMU (port ${vnc.port})`);
      ok(!!(await waitFor(() => sshWorks(RSSH), 30000, 1000)), 'SSH through the agent VM\'s forward works');

      const e = await P.api('POST', RID, '/enable'); ok(e.code === 202, 'enable accepted for a remote-node VM');
      await P.settle(RID);
      const r = await row(RID);
      ok(r.rdp_enabled === 1 && r.rdp_port >= 33890, `remote VM got a port from the panel allocator (${r.rdp_port})`);
      ok(!!(await waitFor(async () => (await P.status(RID)).status === 'online', 40000)), 'Online: the probe ran ON THE AGENT and completed a real handshake through the node\'s QEMU forward');
      const st = await P.status(RID);
      ok(st.host === '127.0.0.1' && st.port === r.rdp_port, `connection address uses the node address (${st.host}:${st.port})`);
      ok(await listening(r.rdp_port), 'forward is live on the node (hot-added through the agent)');
      ok(/rdp forward added/.test(agentLog) && /rdp (os_detected|guest_step)/.test(agentLog), 'agent logged the operations');
      ok(!agentLog.includes(PASS), 'agent log contains no password');

      await nodeManager.sendNodeCommand(node.id, 'vm.stop', { vm: await vmRow() }, { timeoutMs: 15000 });
      await run("UPDATE vms SET status='stopped' WHERE vm_id=?", [RID]);
      ok(!!(await waitFor(async () => !(await listening(r.rdp_port)), 15000)), 'port released when the remote VM stops');
      ok((await P.status(RID)).status === 'offline', 'stopped remote VM -> Offline');
      await sleep(1500);
      await nodeManager.sendNodeCommand(node.id, 'vm.start', { vm: await vmRow() }, { timeoutMs: 30000 });
      await run("UPDATE vms SET status='running' WHERE vm_id=?", [RID]);
      ok(!!(await waitFor(async () => (await P.status(RID)).status === 'online', 90000)), 'after restart through the agent: Online again (forward baked into the agent\'s QEMU args)');

      const call = (action, payload) => nodeManager.sendNodeCommand(node.id, action, payload, { timeoutMs: 8000 }).then(() => 'accepted', (x) => x);
      const evil = await call('rdp.forward', { vm: { vm_id: '../../etc' }, port: 33999, action: 'add' });
      ok(evil.code === 'INVALID_VM_ID', `agent rejects a path-traversal vm_id (${evil.code || evil})`);
      const low = await call('rdp.forward', { vm: { vm_id: RID }, port: 22, action: 'add' });
      ok(low.code === 'HOSTFWD_FAILED', `agent refuses a privileged port (${low.code || low})`);
      const badHost = await call('rdp.probe', { host: '8.8.8.8; id', port: 3389 });
      ok(badHost.httpStatus === 400, 'agent rejects a non-IPv4 probe host');

      const d = await P.api('POST', RID, '/disable'); ok(d.code === 200, 'disable accepted');
      ok(!(await listening(r.rdp_port)) && (await row(RID)).rdp_port === null, 'forward removed on the node and port released');

      agent.kill('SIGKILL');
      await waitFor(async () => !nodeManager.sanitizeNode(await nodeManager.getNode(node.id)).online, 20000);
      const off = await P.api('POST', RID, '/enable');
      ok(off.code === 502 && off.body.code === 'NODE_OFFLINE', `node unavailable -> clear error (HTTP ${off.code}: ${off.body.error})`);
    } finally {
      try { agent.kill('SIGKILL'); } catch (e) { /* gone */ }
      killQemu();
    }
  });

  await group('Logging hygiene', async () => {
    const all = logBuf.join('\n');
    ok(!all.includes(PASS) && !all.includes('wrong-password'), 'no password appears anywhere in the captured panel logs');
    ok(/\[RDP\] \{"ts":"[^"]+","event":"enable_started"/.test(all), 'structured JSON events are logged');
    const need = ['enable_started', 'os_detected', 'port_allocated', 'forward_added', 'status_change', 'guest_ready', 'handshake_verification', 'disabled', 'reset', 'enable_completed', 'error', 'auto_attempt', 'auto_enabled'];
    const missing = need.filter((e) => !all.includes(`"event":"${e}"`));
    ok(missing.length === 0, `required events logged (missing: ${missing.join(',') || 'none'})`);
  });

  // ---------------------------------------------------------------
  out(`\n${results.pass} passed, ${results.fail} failed, ${results.skip} skipped`);
  if (failures.length) out('Failures:\n - ' + failures.join('\n - '));
  for (const id of guests.keys()) await stopGuest(id);
  killQemu();
  process.exit(results.fail ? 1 : 0);
})().catch((e) => { out('TEST HARNESS ERROR: ' + (e.stack || e)); killQemu(); process.exit(2); });
