#!/usr/bin/env node
// =====================================================================
// RDP UI test in a real DOM (jsdom): boots the real panel, loads the real
// VM detail pages over HTTP with their real scripts, then uses the RDP tab
// exactly like a person would - click the tab, Enable RDP, Copy, Disable.
// Not a full browser (no layout/CSS), but all page JavaScript, the CSRF
// fetch patch and every API call are the real thing.
// Needs: the rig from tests/build-test-guest.sh + tests/setup-ssh-guest.sh
//        and jsdom:  npm i --prefix /tmp/jsd jsdom   (JSDOM_PATH=/tmp/jsd/node_modules/jsdom)
// =====================================================================
const path = require('path');
const fs = require('fs');
const os = require('os');
const net = require('net');
const { spawn, execSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const sqlite3 = require(path.join(ROOT, 'node_modules/sqlite3'));
let jsdomLib;
try { jsdomLib = require(process.env.JSDOM_PATH || 'jsdom'); } catch (e) { console.log('jsdom not found: npm i --prefix /tmp/jsd jsdom && JSDOM_PATH=/tmp/jsd/node_modules/jsdom'); process.exit(2); }
const { JSDOM, CookieJar, VirtualConsole } = jsdomLib;

const RIG = process.env.VNM_TEST_DIR || '/tmp/vnm-rdp-test';
const PASS = 'Test#Pass123', PORT = 18091, SSHF = 22972;
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'vnm-ui-home-'));
const VMS = path.join(HOME, 'vms'), DBFILE = path.join(HOME, '.vnm', 'vnm.db');
const BASE = `http://127.0.0.1:${PORT}`;

const out = (s) => process.stdout.write(s + '\n');
const R = { pass: 0, fail: 0 }; const failed = [];
const ok = (c, m) => { if (c) { R.pass++; out('  PASS ' + m); } else { R.fail++; failed.push(m); out('  FAIL ' + m); } return !!c; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, ms = 30000, every = 250) { const end = Date.now() + ms; for (;;) { const v = await fn(); if (v) return v; if (Date.now() > end) return null; await sleep(every); } }
const sh = (c) => execSync(c, { stdio: 'pipe', shell: '/bin/bash' }).toString().trim();
const listening = (p) => new Promise((r) => { const s = net.connect(p, '127.0.0.1'); s.on('connect', () => { s.destroy(); r(true); }); s.on('error', () => r(false)); });

let panel = null, panelLog = '';
async function bootPanel() {
  panel = spawn(process.execPath, ['app.js'], { cwd: ROOT, env: { ...process.env, HOME, PORT: String(PORT), QEMU_BIN: path.join(RIG, 'qemu-system-x86_64'), NODE_ENV: 'development' }, stdio: ['ignore', 'pipe', 'pipe'] });
  panel.stdout.on('data', (d) => { panelLog += d; }); panel.stderr.on('data', (d) => { panelLog += d; });
  if (!(await waitFor(() => /Open http:\/\/localhost:/.test(panelLog), 60000, 300))) throw new Error('panel did not start');
}
const stopAll = async () => { try { panel && panel.kill('SIGKILL'); } catch (e) { /* gone */ } try { sh('pkill -x qemu-system-x86 || true'); } catch (e) { /* ignore */ } };

// plain-fetch session used for setup (login, start VM) and shared with the DOM
const cookies = {};
async function http(method, p, body) {
  const headers = { Cookie: Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ') };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && cookies.csrf_token) headers['x-csrf-token'] = cookies.csrf_token;
  const res = await fetch(BASE + p, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined, redirect: 'manual' });
  for (const c of res.headers.getSetCookie()) { const [kv] = c.split(';'); const i = kv.indexOf('='); cookies[kv.slice(0, i)] = kv.slice(i + 1); }
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch (e) { /* html */ }
  return { code: res.status, json, text };
}
const dbRun = (s, p = []) => new Promise((res, rej) => { const d = new sqlite3.Database(DBFILE); d.run(s, p, function (e) { d.close(); e ? rej(e) : res(this); }); });
const dbGet = (s, p = []) => new Promise((res, rej) => { const d = new sqlite3.Database(DBFILE); d.get(s, p, (e, r) => { d.close(); e ? rej(e) : res(r); }); });

// open a page in jsdom with the logged-in cookies and a real fetch
async function openPage(urlPath, errors) {
  const jar = new CookieJar();
  for (const [k, v] of Object.entries(cookies)) jar.setCookieSync(`${k}=${v}; Path=/`, BASE);
  const vc = new VirtualConsole();
  vc.on('jsdomError', (e) => errors.push('jsdomError: ' + (e.detail || e.message || e)));
  vc.on('error', (...a) => errors.push('console.error: ' + a.join(' ')));
  const clip = []; 
  const dom = await JSDOM.fromURL(BASE + urlPath, {
    cookieJar: jar, runScripts: 'dangerously', resources: 'usable', pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(window) {
      window.fetch = async (u, o = {}) => {
        const abs = new URL(u, BASE).href;
        const headers = Object.assign({}, o.headers, { Cookie: jar.getCookieStringSync(abs) });
        const res = await fetch(abs, Object.assign({}, o, { headers, redirect: 'manual' }));
        for (const c of res.headers.getSetCookie()) jar.setCookieSync(c, abs);
        return res;
      };
      window.matchMedia = window.matchMedia || (() => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }));
      window.confirm = () => true; window.alert = () => {};
      window.scrollTo = () => {}; // jsdom does not implement layout/scrolling (test-environment gap only)
      Object.defineProperty(window.navigator, 'clipboard', { value: { writeText: (t) => { clip.push(t); return Promise.resolve(); } } });
      window.WebSocket = class { constructor() { setTimeout(() => this.onerror && this.onerror(new Error('no ws in test')), 0); } close() {} send() {} };
      window.EventSource = class { constructor() {} close() {} };
    }
  });
  dom.clip = clip;
  await new Promise((r) => (dom.window.document.readyState === 'complete' ? r() : dom.window.addEventListener('load', r)));
  return dom;
}
const panelText = (dom) => (dom.window.document.getElementById('rdpPanel') || { textContent: '' }).textContent.replace(/\s+/g, ' ');
const badge = (dom) => { const t = panelText(dom); return ['ONLINE', 'OFFLINE', 'INSTALLING', 'RESTART REQUIRED', 'UNSUPPORTED OS', 'ERROR', 'DISABLED'].find((b) => t.includes(b)) || null; };
const btn = (dom, label) => [...dom.window.document.querySelectorAll('#rdpPanel button')].find((b) => b.textContent.includes(label));

(async () => {
  if (!fs.existsSync(path.join(RIG, 'qemu-system-x86_64')) || !(await listening(2299))) { out('Prerequisites missing: run tests/build-test-guest.sh and tests/setup-ssh-guest.sh'); process.exit(2); }
  sh('pkill -x qemu-system-x86 || true');
  fs.mkdirSync(VMS, { recursive: true });
  await bootPanel();
  const pw = (/username: admin\s+password: (\S+)/.exec(panelLog) || [])[1];
  await http('GET', '/login');
  const lg = await http('POST', '/api/login', { username: 'admin', password: pw });
  if (!(lg.json && lg.json.success)) throw new Error('login failed');

  execSync(`qemu-img create -f qcow2 ${path.join(VMS, 'vm-1-disk.qcow2')} 64M`, { stdio: 'pipe' });
  await dbRun(`INSERT INTO vms (vm_name, os_type, template_type, username, password, memory, cpus, cpu_sockets, cpu_cores, cpu_threads, cpu_model, enable_kvm, disk_file, status, network_type, ssh_port, owner_id)
               VALUES ('rig-vm','Ubuntu 22.04','ubuntu','tester',?,256,1,1,1,1,'qemu64',0,?,'stopped','nat',?,1)`, [PASS, path.join(VMS, 'vm-1-disk.qcow2'), SSHF]);

  for (const [name, urlPath] of [['ADMIN VM page', '/admin/vm/1'], ['USER VM page', '/vm/1']]) {
    out(`\n== ${name} (${urlPath}) - real DOM, VM stopped`);
    const errors = [];
    const dom = await openPage(urlPath, errors);
    const d = dom.window.document;
    // the page renders its tab bar from JavaScript after /api/vms/:id returns
    await waitFor(() => d.querySelector('.tab-btn[data-tab="overview"]'), 20000, 200);
    const tabBtn = d.querySelector('.tab-btn[data-tab="rdp"]');
    ok(!!tabBtn && /RDP/.test(tabBtn.textContent), 'an "RDP" tab button is in the tab bar');
    const order = [...d.querySelectorAll('.tab-btn')].map((b) => b.dataset.tab).join(' > ');
    ok(/overview > network > rdp > hardware/.test(order), `tab order: ${order}`);
    ok(!d.getElementById('tab-rdp').classList.contains('active'), 'RDP pane hidden until clicked');
    tabBtn.click();
    ok(d.getElementById('tab-rdp').classList.contains('active') && tabBtn.classList.contains('active') && !d.getElementById('tab-overview').classList.contains('active'), 'clicking the tab shows the RDP pane (and hides Overview)');
    ok(!!(await waitFor(() => badge(dom), 15000)), 'the RDP panel loads its status from the API');
    ok(badge(dom) === 'DISABLED' && /Remote Desktop \(RDP\)/.test(panelText(dom)), `status badge: ${badge(dom)}`);
    const en = btn(dom, 'Enable RDP');
    ok(!!en && en.disabled, 'Enable RDP button is shown but disabled while the VM is stopped');
    ok(errors.length === 0, `no JavaScript errors on the page${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
    dom.window.close();
  }

  out('\n== other ways to reach RDP (shortcuts), real DOM');
  {
    const errs = [];
    // header button on the VM page now opens the dedicated RDP page
    let dom = await openPage('/admin/vm/1', errs); let d = dom.window.document;
    await waitFor(() => d.querySelector('.tab-btn[data-tab="rdp"]'), 20000, 200);
    const headerLink = d.querySelector('a[href="/admin/vm/1/rdp"][title="Remote Desktop (RDP)"]');
    ok(!!headerLink && /RDP/.test(headerLink.textContent), 'admin VM page: an "RDP" button in the header (next to Console / SSH / Files) links to the RDP page');
    ok(!![...d.querySelectorAll('#tab-rdp a')].find((x) => x.getAttribute('href') === '/admin/vm/1/rdp') || !!(await waitFor(() => [...d.querySelectorAll('#rdpPanel a')].find((x) => x.getAttribute('href') === '/admin/vm/1/rdp'), 10000, 200)), 'the RDP tab links to the full RDP page too');
    dom.window.close();
    // deep link
    dom = await openPage('/admin/vm/1#rdp', errs); d = dom.window.document;
    ok(!!(await waitFor(() => d.getElementById('tab-rdp') && d.getElementById('tab-rdp').classList.contains('active'), 20000, 200)), 'admin: opening /admin/vm/1#rdp lands directly on the RDP tab');
    dom.window.close();
    dom = await openPage('/vm/1#rdp', errs); d = dom.window.document;
    ok(!!(await waitFor(() => d.getElementById('tab-rdp') && d.getElementById('tab-rdp').classList.contains('active'), 20000, 200)), 'user: opening /vm/1#rdp lands directly on the RDP tab');
    const uBtn = d.querySelector('a[href="/vm/1/rdp"][title="Remote Desktop (RDP)"]');
    ok(!!uBtn, 'user VM page: "RDP" button in the header too');
    dom.window.close();
    // VM lists
    dom = await openPage('/admin/vms', errs); d = dom.window.document;
    ok(!!(await waitFor(() => d.querySelector('a[href="/admin/vm/1/rdp"]'), 20000, 200)), 'admin "All VMs" list: every VM row has an RDP link');
    dom.window.close();
    dom = await openPage('/vms', errs); d = dom.window.document;
    ok(!!(await waitFor(() => d.querySelector('a[href="/vm/1/rdp"]'), 20000, 200)), 'user "My VMs" list: every VM row has an RDP link');
    dom.window.close();
    // Create VM page (where the screenshot was taken)
    dom = await openPage('/admin/vm-create', errs); d = dom.window.document;
    const cb = d.getElementById('enable_rdp');
    ok(!!cb && /Remote Desktop \(RDP\)/.test(d.body.textContent), 'Create VM page (step 1) has a "Remote Desktop (RDP)" card with an "Enable RDP automatically" switch');
    await waitFor(() => d.querySelectorAll('input[name="_template"]').length > 0, 20000, 200);
    const radios = [...d.querySelectorAll('input[name="_template"]')];
    const tpls = dom.window.eval('osTemplates'); // declared with let in the page, so not a window property
    const pick = (re) => radios.find((r) => re.test(r.value + ' ' + ((tpls[r.value] || {}).name || '')));
    const ubuntu = pick(/ubuntu/i), fedora = pick(/fedora/i);
    ok(!!ubuntu && !!fedora, `templates loaded (${radios.length})`);
    ubuntu.click(); await sleep(100);
    ok(cb.disabled === false, 'Ubuntu cloud-init template: the RDP switch is available');
    cb.click(); await sleep(50);
    ok(cb.checked && dom.window.collectFormData().enable_rdp === '1', 'ticking it puts enable_rdp=1 into the data sent to POST /api/vms');
    fedora.click(); await sleep(100);
    ok(cb.disabled === true && cb.checked === false && !dom.window.collectFormData().enable_rdp, 'Fedora template: switch is greyed out, unticked, and nothing is sent');
    ok(/Debian \/ Ubuntu/.test(d.getElementById('rdpHint').textContent), 'a hint explains why');
    dom.window.close();
    ok(errs.length === 0, `no JavaScript errors on any of those pages${errs.length ? ': ' + errs.slice(0, 3).join(' | ') : ''}`);
  }

  out('\n== start the VM through the panel, then use the tab like a person');
  const st = await http('POST', '/api/vms/1/start'); ok(st.json && st.json.success, 'VM started via the panel');
  ok(!!(await waitFor(() => fs.existsSync(path.join(VMS, 'vm-1.log')) && /VNM_TEST_GUEST_READY/.test(fs.readFileSync(path.join(VMS, 'vm-1.log'), 'utf8')), 90000, 500)), 'guest booted');
  await sleep(1500);

  const errors = [];
  const dom = await openPage('/admin/vm/1', errors);
  const d = dom.window.document;
  await waitFor(() => d.querySelector('.tab-btn[data-tab="rdp"]'), 20000, 200);
  d.querySelector('.tab-btn[data-tab="rdp"]').click();
  await waitFor(() => badge(dom), 15000);
  const en = btn(dom, 'Enable RDP');
  ok(!!en && !en.disabled, 'with the VM running, Enable RDP is clickable');
  en.click();
  ok(!!(await waitFor(() => badge(dom) === 'INSTALLING', 15000, 200)), 'after clicking: badge changes to INSTALLING with progress text');
  const seenSteps = new Set();
  const final = await waitFor(() => { if (badge(dom) === 'INSTALLING') seenSteps.add(panelText(dom).slice(-80)); return ['ONLINE', 'ERROR', 'OFFLINE'].includes(badge(dom)) ? badge(dom) : null; }, 300000, 400);
  ok(final === 'ONLINE', `the page reaches ONLINE on its own by polling (got ${final})`);
  const addr = (d.getElementById('rdpConnect') || {}).textContent;
  const row = await dbGet('SELECT rdp_port FROM vms WHERE vm_id=1');
  ok(/^127\.0\.0\.1:\d{5}$/.test(addr || '') && addr.endsWith(':' + row.rdp_port), `connection address shown: ${addr}`);
  const t = panelText(dom);
  ok(/RDP Host/.test(t) && /RDP Port/.test(t) && /Username/.test(t) && /tester/.test(t) && /Ubuntu/.test(t), 'host, port, username and guest OS are displayed');
  ok(!t.includes(PASS), 'the password is not displayed anywhere');
  btn(dom, 'Copy').click(); await sleep(200);
  ok(dom.clip.includes(addr), 'the Copy button puts the connection address on the clipboard');
  ok(!!btn(dom, 'Disable RDP') && !!btn(dom, 'Re-run setup'), 'Disable RDP and Re-run setup buttons are available once enabled');
  btn(dom, 'Disable RDP').click();
  ok(!!(await waitFor(() => badge(dom) === 'DISABLED', 20000, 250)), 'clicking Disable RDP returns the tab to DISABLED');
  ok(!(await listening(row.rdp_port)) && (await dbGet('SELECT rdp_port p FROM vms WHERE vm_id=1')).p === null, 'port released on the host');
  ok(!!btn(dom, 'Enable RDP') && !btn(dom, 'Enable RDP').disabled, 'Enable RDP is offered again');
  ok(errors.length === 0, `no JavaScript errors during the whole flow${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
  dom.window.close();

  out('\n== the dedicated RDP page (/admin/vm/1/rdp): create + use RDP');
  {
    const errs2 = [];
    const pdom = await openPage('/admin/vm/1/rdp', errs2); const pd = pdom.window.document;
    const pbadge = () => { const t = (pd.getElementById('pageContent') || { textContent: '' }).textContent.replace(/\s+/g, ' '); return ['ONLINE', 'OFFLINE', 'SETTING UP', 'WAITING FOR VM', 'RESTART REQUIRED', 'UNSUPPORTED OS', 'ERROR', 'NOT ENABLED'].find((b) => t.includes(b)) || null; };
    const pbtn = (label) => [...pd.querySelectorAll('#pageContent button, #pageContent a.btn')].find((b) => b.textContent.includes(label));
    ok(!!(await waitFor(() => pbadge(), 20000, 200)), 'page loads and shows the current RDP status');
    ok(pbadge() === 'NOT ENABLED', `status: ${pbadge()}`);
    const t0 = pd.getElementById('pageContent').textContent;
    ok(/Remote Desktop \(RDP\)/.test(t0) && /rig-vm/.test(t0) && /Connect to the VM over SSH/.test(t0) && /Verify the RDP connection/.test(t0), 'shows the VM name and the four setup stages');
    ok(/How to connect/.test(t0) && /Windows/.test(t0) && /Linux/.test(t0) && /macOS/.test(t0), 'has the how-to-connect guide for Windows / Linux / macOS');
    ok(!!pd.getElementById('autoBox'), 'offers "Set up RDP automatically"');
    const enableBtn = pbtn('Enable RDP'); ok(!!enableBtn && !enableBtn.disabled, 'Enable RDP is clickable (the VM is running)');
    enableBtn.click();
    ok(!!(await waitFor(() => pbadge() === 'SETTING UP', 15000, 150)), 'clicking it shows SETTING UP with the stage timeline');
    ok(!!(await waitFor(() => pd.querySelector('.rdp-steps li.active, .rdp-steps li.done'), 30000, 150)), 'a setup stage is highlighted while it runs');
    const pfinal = await waitFor(() => (['ONLINE', 'ERROR', 'OFFLINE'].includes(pbadge()) ? pbadge() : null), 300000, 400);
    ok(pfinal === 'ONLINE', `reaches ONLINE on its own (got ${pfinal})`);
    ok(pd.querySelectorAll('.rdp-steps li.done').length === 4, 'all four stages are ticked');
    const row2 = await dbGet('SELECT rdp_port FROM vms WHERE vm_id=1');
    const paddr = (pd.getElementById('rdpAddr') || {}).textContent;
    ok(paddr === `127.0.0.1:${row2.rdp_port}`, `connection address: ${paddr}`);
    const dl = pbtn('Download .rdp file'); ok(!!dl && dl.getAttribute('href') === '/api/vms/1/rdp/file' && dl.hasAttribute('download'), 'a "Download .rdp file" button points at the file endpoint');
    const rdpFile = await http('GET', '/api/vms/1/rdp/file'); ok(rdpFile.code === 200 && rdpFile.text.includes(`full address:s:127.0.0.1:${row2.rdp_port}`), 'and that file contains the same address');
    ok(pd.getElementById('pageContent').textContent.includes('xfreerdp /v:') || /xfreerdp/.test(pd.getElementById('pageContent').textContent), 'the Linux guide includes the ready-made xfreerdp command');
    pbtn('Copy xfreerdp').click(); await sleep(150);
    ok(pdom.clip.some((c) => c.startsWith('xfreerdp /v:127.0.0.1:' + row2.rdp_port)), 'Copy xfreerdp command puts the command on the clipboard');
    ok(!pd.getElementById('autoBox'), 'automatic-setup switch is hidden once RDP is enabled');
    pbtn('Disable RDP').click();
    ok(!!(await waitFor(() => pbadge() === 'NOT ENABLED', 20000, 250)), 'Disable RDP returns the page to NOT ENABLED');
    ok(!!pd.getElementById('autoBox'), 'automatic-setup switch is back');
    pd.getElementById('autoBox').click();
    ok(!!(await waitFor(() => ['WAITING FOR VM', 'SETTING UP', 'ONLINE'].includes(pbadge()), 30000, 250)), `switching on automatic setup takes effect (page now shows: ${pbadge()})`);
    ok(!!(await waitFor(() => pbadge() === 'ONLINE', 300000, 500)), 'and RDP comes ONLINE by itself - nobody clicked Enable RDP');
    const afterAuto = await dbGet('SELECT rdp_auto a, rdp_enabled e, rdp_port p FROM vms WHERE vm_id=1');
    ok(afterAuto.e === 1 && afterAuto.a === 0 && afterAuto.p >= 33890, `automatic flag cleared after success, port ${afterAuto.p}`);
    ok(errs2.length === 0, `no JavaScript errors on the RDP page${errs2.length ? ': ' + errs2.slice(0, 3).join(' | ') : ''}`);
    pdom.window.close();
    // user flavour of the page
    const udom = await openPage('/vm/1/rdp', errs2); const ud = udom.window.document;
    ok(!!(await waitFor(() => /Remote Desktop \(RDP\)/.test(ud.getElementById('pageContent').textContent) && /Enable RDP|Disable RDP|Re-run/.test(ud.getElementById('pageContent').textContent), 20000, 250)), 'user flavour /vm/1/rdp renders with its controls');
    udom.window.close();
  }

  out(`\n${R.pass} passed, ${R.fail} failed`);
  if (failed.length) out('Failures:\n - ' + failed.join('\n - '));
  await stopAll();
  process.exit(R.fail ? 1 : 0);
})().catch(async (e) => { out('HARNESS ERROR: ' + (e.stack || e)); out(panelLog.slice(-1500)); await stopAll(); process.exit(2); });
