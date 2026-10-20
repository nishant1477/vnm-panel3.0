#!/usr/bin/env node
// =====================================================================
// RDP end-to-end test against the REAL panel process (node app.js)
// ---------------------------------------------------------------------
// Boots the real panel on a throw-away HOME, logs in over HTTP with the
// real session + CSRF protection, and drives the real routes
// (start / stop / rdp enable / disable / reinstall / console command).
// QEMU is launched by the panel's own startQemuVM(); only the QEMU
// binary is swapped (QEMU_BIN) for tests/build-test-guest.sh's wrapper so
// a tiny real Linux guest boots without KVM or a cloud image.
// Verifies the RDP feature AND that SSH forward, VNC, serial console,
// stop/start and reinstall keep working alongside it.
// Needs the same rig as rdp-integration.js (build-test-guest.sh,
// setup-ssh-guest.sh).
// =====================================================================

const path = require('path');
const fs = require('fs');
const os = require('os');
const net = require('net');
const { spawn, execSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const sqlite3 = require(path.join(ROOT, 'node_modules/sqlite3'));
const { Client: SshClient } = require(path.join(ROOT, 'node_modules/ssh2'));
const g = require(path.join(ROOT, 'rdp-guest'));

const RIG = process.env.VNM_TEST_DIR || '/tmp/vnm-rdp-test';
const SSH_RIG_PORT = parseInt(process.env.VNM_TEST_SSH_PORT || '2299', 10);
const PASS = 'Test#Pass123';
const PORT = 18090;
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'vnm-e2e-home-'));
const VMS = path.join(HOME, 'vms');
const DBFILE = path.join(HOME, '.vnm', 'vnm.db');
const VMID = 1, SSHF = 22971;

const out = (s) => process.stdout.write(s + '\n');
const R = { pass: 0, fail: 0 }; const failed = [];
const ok = (c, m) => { if (c) { R.pass++; out('  PASS ' + m); } else { R.fail++; failed.push(m); out('  FAIL ' + m); } return !!c; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, ms = 30000, every = 300) { const end = Date.now() + ms; for (;;) { const v = await fn(); if (v) return v; if (Date.now() > end) return null; await sleep(every); } }
async function group(n, f) { out(`\n== ${n}`); try { await f(); } catch (e) { R.fail++; failed.push(`${n}: ${e.message}`); out('  FAIL (exception) ' + (e.stack || e.message)); } }
const listening = (port) => new Promise((r) => { const s = net.connect(port, '127.0.0.1'); s.on('connect', () => { s.destroy(); r(true); }); s.on('error', () => r(false)); });
const sh = (c) => execSync(c, { stdio: 'pipe', shell: '/bin/bash' }).toString().trim();

function sshWorks(port) {
  return new Promise((resolve) => {
    const c = new SshClient(); let done = false;
    const fin = (v) => { if (!done) { done = true; try { c.end(); } catch (e) { /* ignore */ } resolve(v); } };
    c.on('ready', () => c.exec('echo ssh-ok', (e, s) => { if (e) return fin(false); let o = ''; s.on('data', (d) => { o += d; }); s.on('close', () => fin(/ssh-ok/.test(o))); }));
    c.on('error', () => fin(false));
    c.connect({ host: '127.0.0.1', port, username: 'tester', password: PASS, readyTimeout: 10000 });
  });
}

// ---- real panel process ----------------------------------------------
let panel = null, panelLog = '';
async function bootPanel() {
  panelLog = '';
  panel = spawn(process.execPath, ['app.js'], {
    cwd: ROOT,
    env: { ...process.env, HOME, PORT: String(PORT), QEMU_BIN: path.join(RIG, 'qemu-system-x86_64'), NODE_ENV: 'development' },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  panel.stdout.on('data', (d) => { panelLog += d; }); panel.stderr.on('data', (d) => { panelLog += d; });
  const up = await waitFor(() => /Open http:\/\/localhost:/.test(panelLog), 60000, 300);
  if (!up) throw new Error('panel did not start:\n' + panelLog.slice(-1500));
}
const killPanel = () => new Promise((resolve) => {
  const p = panel; if (!p || p.exitCode !== null) return resolve();
  const t = setTimeout(() => { try { p.kill('SIGKILL'); } catch (e) { /* gone */ } }, 5000);
  p.once('exit', () => { clearTimeout(t); resolve(); });
  p.kill('SIGTERM');
});

// ---- HTTP session with cookies + CSRF --------------------------------
const jar = {};
async function http(method, p, body) {
  const headers = { Cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ') };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && jar.csrf_token) headers['x-csrf-token'] = jar.csrf_token;
  const res = await fetch(`http://127.0.0.1:${PORT}${p}`, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined, redirect: 'manual' });
  for (const c of (res.headers.getSetCookie ? res.headers.getSetCookie() : [])) { const [kv] = c.split(';'); const i = kv.indexOf('='); jar[kv.slice(0, i)] = kv.slice(i + 1); }
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch (e) { /* html */ }
  return { code: res.status, json, text };
}
async function login(password) {
  for (const k of Object.keys(jar)) delete jar[k];
  await http('GET', '/login');
  const r = await http('POST', '/api/login', { username: 'admin', password });
  if (!(r.json && r.json.success)) throw new Error('login failed: ' + r.text.slice(0, 200));
}

const dbRun = (s, p = []) => new Promise((res, rej) => { const d = new sqlite3.Database(DBFILE); d.run(s, p, function (e) { d.close(); e ? rej(e) : res(this); }); });
const dbGet = (s, p = []) => new Promise((res, rej) => { const d = new sqlite3.Database(DBFILE); d.get(s, p, (e, r) => { d.close(); e ? rej(e) : res(r); }); });
const vmRow = () => dbGet('SELECT * FROM vms WHERE vm_id = ?', [VMID]);
const rdpStatus = async () => (await http('GET', `/api/vms/${VMID}/rdp`)).json || {};
const qemuArgs = () => { try { return sh(`ps -eo args | grep -- "-name vm-${VMID}" | grep -v grep | head -1`); } catch (e) { return ''; } };
const logFile = path.join(VMS, `vm-${VMID}.log`);
const hmp = path.join(VMS, `vm-${VMID}.hmp`);
const guestLog = () => (fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : '');

async function startVm() {
  const r = await http('POST', `/api/vms/${VMID}/start`);
  if (!(r.json && r.json.success)) throw new Error('start failed: ' + r.text.slice(0, 300));
  return waitFor(async () => /VNM_TEST_GUEST_READY/.test(guestLog().split('\n').slice(-400).join('\n')) , 90000, 500);
}
async function stopVm() {
  const r = await http('POST', `/api/vms/${VMID}/stop`);
  await waitFor(async () => (await vmRow()).status === 'stopped' && !qemuArgs(), 30000, 500);
  return r;
}
const vncPortOf = (args) => { const m = /-vnc 127\.0\.0\.1:(\d+)/.exec(args); return m ? 5900 + parseInt(m[1], 10) : null; };

(async () => {
  if (!fs.existsSync(path.join(RIG, 'qemu-system-x86_64')) || !(await listening(SSH_RIG_PORT))) { out('Prerequisites missing: run tests/build-test-guest.sh and tests/setup-ssh-guest.sh'); process.exit(2); }
  try { sh('pkill -x qemu-system-x86 || true'); } catch (e) { /* ignore */ }
  fs.mkdirSync(VMS, { recursive: true });
  await bootPanel();
  const pw = (/username: admin\s+password: (\S+)/.exec(panelLog) || [])[1];
  if (!pw) throw new Error('could not find the generated admin password in the panel log');

  await group('Real panel boot: schema, routes, auth', async () => {
    const cols = await new Promise((res) => { const d = new sqlite3.Database(DBFILE); d.all('PRAGMA table_info(vms)', (e, r) => { d.close(); res(r.map((c) => c.name)); }); });
    ok(['rdp_enabled', 'rdp_port', 'rdp_status', 'rdp_error', 'rdp_guest_os', 'rdp_installed_at', 'rdp_restart_needed'].every((c) => cols.includes(c)), 'database initialised with the RDP columns automatically (no manual migration)');
    const idx = await dbGet("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_vms_rdp_port'");
    ok(!!idx, 'unique index on rdp_port created');
    const anon = await http('GET', `/api/vms/${VMID}/rdp`);
    ok(anon.code === 302 || anon.code === 401 || anon.code === 403, `unauthenticated GET is refused (${anon.code})`);
    await login(pw);
    const noCsrf = await fetch(`http://127.0.0.1:${PORT}/api/vms/${VMID}/rdp/enable`, { method: 'POST', headers: { Cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ') } });
    ok(noCsrf.status === 403, `POST without CSRF token is refused (${noCsrf.status})`);
  });

  // a VM row + disk, exactly like the panel stores them
  execSync(`qemu-img create -f qcow2 ${path.join(VMS, 'vm-1-disk.qcow2')} 64M`, { stdio: 'pipe' });
  await dbRun(`INSERT INTO vms (vm_name, os_type, template_type, username, password, memory, cpus, cpu_sockets, cpu_cores, cpu_threads, cpu_model, enable_kvm,
               disk_file, status, network_type, ssh_port, owner_id) VALUES ('rig-vm','Ubuntu 22.04','ubuntu','tester',?,256,1,1,1,1,'qemu64',0,?, 'stopped','nat',?,1)`,
    [PASS, path.join(VMS, 'vm-1-disk.qcow2'), SSHF]);

  await group('Existing VM lifecycle still works: start via the panel\'s own startQemuVM()', async () => {
    const booted = await startVm(); ok(!!booted, 'panel started the VM and the guest booted');
    const a = qemuArgs();
    ok(new RegExp(`hostfwd=tcp::${SSHF}-:22`).test(a), 'SSH port forward present on the QEMU command line');
    ok(!/3389/.test(a), 'no RDP forward while RDP is not enabled');
    ok(/-monitor unix:\S+vm-1\.hmp,server,nowait/.test(a), 'QEMU monitor socket configured (unix socket, not TCP)');
    ok(/-serial mon:stdio/.test(a), 'serial console argument unchanged (-serial mon:stdio)');
    ok(/-vnc 127\.0\.0\.1:\d+/.test(a), 'VNC bound to localhost');
    const mode = await waitFor(() => { try { return (fs.statSync(hmp).mode & 0o777) === 0o600; } catch (e) { return false; } }, 15000, 300);
    ok(!!mode, 'monitor socket is owner-only (mode 600)');
    ok(!!(await waitFor(() => sshWorks(SSHF), 30000, 1000)), 'SSH through the VM forward works');
    const vp = vncPortOf(a); ok(vp && await listening(vp), `VNC display is served (port ${vp})`);
    const c = await http('POST', `/api/vms/${VMID}/console/command`, { command: 'hello-serial' });
    ok(c.code === 200 && !!(await waitFor(() => /SERIAL_ECHO:hello-serial/.test(guestLog()), 15000, 300)), 'serial console input reaches the guest and its output returns');
  });

  let rdpPort = null;
  await group('Enable RDP through the real routes', async () => {
    ok((await rdpStatus()).status === 'disabled', 'status Disabled initially');
    const e = await http('POST', `/api/vms/${VMID}/rdp/enable`); ok(e.code === 202, `enable accepted (${e.code})`);
    const s = await waitFor(async () => { const x = await rdpStatus(); return x.status !== 'installing' ? x : null; }, 240000, 500);
    const online = await waitFor(async () => (await rdpStatus()).status === 'online', 40000, 500);
    ok(!!online, `Online via real RDP handshake through the QEMU forward (status: ${(s || {}).status})`);
    const row = await vmRow(); rdpPort = row.rdp_port;
    ok(rdpPort >= 33890 && rdpPort <= 34889 && row.rdp_enabled === 1, `port ${rdpPort} allocated in range and persisted`);
    const f = await g.listForwards(hmp);
    ok(f.some((x) => x.hostPort === rdpPort && x.guestPort === 3389) && f.some((x) => x.guestPort === 22), 'QEMU now forwards 3389 AND still forwards SSH');
    ok(await sshWorks(SSHF), 'SSH still works after enabling RDP');
    ok((vncPortOf(qemuArgs())) && await listening(vncPortOf(qemuArgs())), 'VNC still served after enabling RDP');
    await http('POST', `/api/vms/${VMID}/console/command`, { command: 'after-rdp' });
    ok(!!(await waitFor(() => /SERIAL_ECHO:after-rdp/.test(guestLog()), 15000, 300)), 'serial console still works after enabling RDP');
    const st = await rdpStatus(); ok(!JSON.stringify(st).includes(PASS), 'API response contains no credentials');
  });

  await group('Admin and user VM detail pages expose the RDP tab', async () => {
    const adm = await http('GET', `/admin/vm/${VMID}`); ok(adm.code === 200 && adm.text.includes('id="tab-rdp"') && adm.text.includes('enableRdp()') && adm.text.includes('copyRdp'), 'admin VM page renders with the RDP tab, Enable/Disable handlers and Copy button');
    const usr = await http('GET', `/vm/${VMID}`);
    ok(/x-csrf-token/i.test(adm.text) && /x-csrf-token/i.test(usr.text), 'both pages ship the fetch patch that attaches the CSRF header to the RDP buttons\' requests'); ok(usr.code === 200 && usr.text.includes('id="tab-rdp"') && usr.text.includes('disableRdp()'), 'user VM page renders with the RDP tab');
  });

  await group('Stop / start through the real routes: forward is rebuilt by startQemuVM()', async () => {
    const stopped = await stopVm(); ok(stopped.code === 200 && !qemuArgs(), 'VM stopped, QEMU process gone');
    const s = await rdpStatus(); ok(s.status === 'offline', `RDP status is Offline while stopped ("${s.status}")`);
    ok(!(await listening(rdpPort)), 'RDP host port released while stopped');
    fs.writeFileSync(logFile, ''); // fresh boot log
    await startVm();
    const a = qemuArgs();
    ok(new RegExp(`hostfwd=tcp::${SSHF}-:22,hostfwd=tcp::${rdpPort}-:3389`).test(a), `RDP forward is on the QEMU command line, next to SSH (hostfwd ...:${rdpPort}-:3389)`);
    ok(!!(await waitFor(async () => (await rdpStatus()).status === 'online', 60000, 500)), 'Online again after the restart');
    ok(await sshWorks(SSHF) && (await listening(vncPortOf(a))), 'SSH and VNC fine after the restart');
  });

  await group('Panel restart (QEMU keeps running): state restored and recalculated', async () => {
    const before = await vmRow();
    await killPanel(); await sleep(1000);
    ok(!!qemuArgs(), 'the VM\'s QEMU process survives a panel restart');
    await bootPanel(); await login(pw);
    const row = await vmRow();
    ok(row.rdp_port === before.rdp_port && row.rdp_enabled === 1, `RDP config and port persisted (${row.rdp_port})`);
    ok(!!(await waitFor(async () => (await rdpStatus()).status === 'online', 60000, 500)), 'status recalculated -> Online');
    ok(!!(await waitFor(() => /"event":"forward_restore"/.test(panelLog), 30000, 500)), 'boot-time forward restore ran (structured log)');
  });

  await group('Disable RDP through the real route', async () => {
    const d = await http('POST', `/api/vms/${VMID}/rdp/disable`); ok(d.code === 200, 'disable accepted');
    const row = await vmRow();
    ok(row.rdp_port === null && !row.rdp_enabled, 'port released and DB updated');
    ok(!(await listening(rdpPort)) && !(await g.listForwards(hmp)).some((f) => f.guestPort === 3389), 'host forward removed from the running QEMU');
    ok((await rdpStatus()).status === 'disabled', 'status Disabled');
    ok(await sshWorks(SSHF), 'SSH unaffected');
  });

  await group('Reinstall clears RDP (real /reinstall route)', async () => {
    // enable again, stop, then reinstall from a custom template
    await http('POST', `/api/vms/${VMID}/rdp/enable`);
    await waitFor(async () => (await rdpStatus()).status === 'online', 120000, 500);
    const portBefore = (await vmRow()).rdp_port; ok(!!portBefore, `RDP enabled again on port ${portBefore}`);
    await stopVm();
    execSync(`qemu-img create -f qcow2 ${path.join(HOME, 'tpl.qcow2')} 64M`, { stdio: 'pipe' });
    await dbRun(`INSERT INTO os_templates (template_key, template_name, template_type, username, password, local_path, is_active) VALUES ('rig-tpl','Rig Ubuntu','cloud-init','tester',?,?,1)`, [PASS, path.join(HOME, 'tpl.qcow2')]);
    const r = await http('POST', `/api/vms/${VMID}/reinstall`, { new_os_template: 'rig-tpl', new_username: 'tester', new_password: PASS, confirm: true });
    ok(r.code === 200 && r.json && r.json.success, `reinstall completed (${r.code}: ${(r.json && (r.json.message || r.json.error)) || r.text.slice(0, 120)})`);
    const row = await vmRow();
    ok(!row.rdp_enabled && row.rdp_port === null && row.rdp_status === 'disabled' && !row.rdp_guest_os, 'RDP configuration cleared and port released by the reinstall');
    ok((await rdpStatus()).status === 'disabled', 'API reports Disabled');
    fs.writeFileSync(logFile, ''); await startVm();
    ok(!/3389/.test(qemuArgs()), 'the reinstalled VM starts with NO RDP forward (no stale mapping)');
    ok(!(await listening(portBefore)), `old host port ${portBefore} is not bound`);
  });

  await group('Create VM with "Enable RDP" ticked (real POST /api/vms) -> boots -> RDP sets itself up', async () => {
    await stopVm().catch(() => {});
    await dbRun(`INSERT OR IGNORE INTO os_templates (template_key, template_name, template_type, username, password, local_path, is_active) VALUES ('rig-fedora','Rig Fedora 40','cloud-init','tester',?,?,1)`, [PASS, path.join(HOME, 'tpl.qcow2')]);
    const mk = (name, tpl, rdp) => http('POST', '/api/vms', { vm_name: name, hostname: name, os_template: tpl, custom_username: 'tester', custom_password: PASS, custom_memory: 256, custom_cpus: 1, disk_size: '1G', network_type: 'nat', owner_id: 1, enable_rdp: rdp });
    const no = await mk('rig-fedora-vm', 'rig-fedora', '1');
    ok(no.code === 200 && no.json && no.json.success && no.json.rdp_auto === false, `non-Debian/Ubuntu template: VM created, "Enable RDP" ignored (rdp_auto=${no.json && no.json.rdp_auto})`);
    const off = await mk('rig-plain-vm', 'rig-tpl', undefined);
    ok(off.code === 200 && off.json && off.json.rdp_auto === false, 'Debian/Ubuntu template without the option: nothing is queued');
    const r = await mk('rig-rdp-vm', 'rig-tpl', '1');
    ok(r.code === 200 && r.json && r.json.success, `VM created through the real API (${r.code}: ${(r.json && (r.json.error || r.json.message)) || ''})`);
    ok(r.json && r.json.rdp_auto === true, 'API reports rdp_auto: true (the wizard then opens the RDP page)');
    const id = r.json.vm_id;
    const row0 = await dbGet('SELECT rdp_auto, rdp_enabled, status FROM vms WHERE vm_id = ?', [id]);
    ok(row0.rdp_auto === 1 && row0.rdp_enabled === 0 && row0.status === 'stopped', 'stored as: auto-setup queued, not enabled yet, VM stopped');
    const st0 = (await http('GET', `/api/vms/${id}/rdp`)).json;
    ok(st0.status === 'waiting' && /started/i.test(st0.message), `RDP page shows "waiting": "${st0.message}"`);
    const fd = await dbGet('SELECT rdp_auto FROM vms WHERE vm_name = ?', ['rig-fedora-vm']); ok(fd.rdp_auto === 0, 'non-Debian VM has no automatic setup queued');

    const s = await http('POST', `/api/vms/${id}/start`); ok(s.json && s.json.success, 'VM started through the real start route');
    const online = await waitFor(async () => (await http('GET', `/api/vms/${id}/rdp`)).json.status === 'online', 300000, 1000);
    ok(!!online, 'with NO click on Enable RDP the VM reaches Online by itself after booting');
    const row1 = await dbGet('SELECT rdp_auto, rdp_enabled, rdp_port FROM vms WHERE vm_id = ?', [id]);
    ok(row1.rdp_enabled === 1 && row1.rdp_auto === 0 && row1.rdp_port >= 33890, `RDP enabled on port ${row1.rdp_port}, automatic flag cleared`);
    ok(await g.probeRdp('127.0.0.1', row1.rdp_port), 'real RDP handshake on the new VM\'s port');
    const file = await http('GET', `/api/vms/${id}/rdp/file`);
    ok(file.code === 200 && /full address:s:/.test(file.text) && !file.text.includes(PASS), 'the .rdp file download works through the real panel and has no password');
    // the dedicated pages exist in the real panel
    const pg = await http('GET', `/admin/vm/${id}/rdp`); ok(pg.code === 200 && /Remote Desktop \(RDP\)/.test(pg.text) && /enableRdp\(\)/.test(pg.text), 'real panel serves /admin/vm/:id/rdp');
    const up = await http('GET', `/vm/${id}/rdp`); ok(up.code === 200 && /toggleAuto\(/.test(up.text), 'real panel serves /vm/:id/rdp');
    const cr = await http('GET', '/admin/vm-create'); ok(cr.code === 200 && /id="enable_rdp"/.test(cr.text) && /updateRdpOption/.test(cr.text), 'Create VM page contains the "Enable RDP automatically" option');
    await http('POST', `/api/vms/${id}/stop`);
  });

  await group('Logging hygiene (real panel log)', async () => {
    ok(!panelLog.includes(PASS), 'password never appears in the panel log');
    ok(/\[RDP\] \{"ts":/.test(panelLog), 'structured [RDP] JSON log lines are emitted');
  });

  if (process.env.VNM_TEST_PANEL_LOG) fs.writeFileSync(process.env.VNM_TEST_PANEL_LOG, panelLog);
  out(`\n${R.pass} passed, ${R.fail} failed`);
  if (failed.length) out('Failures:\n - ' + failed.join('\n - '));
  await killPanel(); try { sh('pkill -x qemu-system-x86 || true'); } catch (e) { /* ignore */ }
  process.exit(R.fail ? 1 : 0);
})().catch(async (e) => { out('E2E HARNESS ERROR: ' + (e.stack || e)); out(panelLog.slice(-2500)); await killPanel(); try { sh('pkill -x qemu-system-x86 || true'); } catch (x) { /* ignore */ } process.exit(2); });
