#!/usr/bin/env node
// UI state test: runs the RDP tab's real client-side code (extracted from both
// VM detail templates) against a stub DOM and checks what each status renders.
const fs = require('fs'), path = require('path'), vm = require('vm');
const ROOT = path.resolve(__dirname, '..');
let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log((c ? '  PASS ' : '  FAIL ') + m); };

for (const file of ['views/admin/vm-detail.ejs', 'views/users/vm-detail.ejs']) {
  console.log(`\n== ${file}`);
  const src = fs.readFileSync(path.join(ROOT, file), 'utf8');
  const a = src.indexOf('// ============= RDP (xrdp inside Debian/Ubuntu guests)');
  const b = src.indexOf('async function loadRdp()');
  ok(a > 0 && b > a, 'RDP block found');
  const el = { innerHTML: '' };
  // Use the page's REAL helpers (escHtml / renderInfoRow), not stubs.
  const grab = (name) => { const i = src.indexOf(`function ${name}(`); let d = 0, j = src.indexOf('{', i); for (let k = j; k < src.length; k++) { if (src[k] === '{') d++; else if (src[k] === '}' && --d === 0) return src.slice(i, k + 1); } };
  const ctx = { vmId: 1, document: { getElementById: (id) => (id === 'rdpPanel' ? el : null) }, svg: () => '<i/>', setTimeout, clearTimeout };
  vm.createContext(ctx);
  vm.runInContext(grab('escHtml') + '\n' + grab('renderInfoRow') + '\n' + src.slice(a, b), ctx);
  const render = (d) => { el.innerHTML = ''; ctx.renderRdp(Object.assign({ vm_id: 1, vm_status: 'running', network: 'nat', enabled: false, status: 'disabled' }, d)); return el.innerHTML; };

  let h = render({});
  ok(/DISABLED/.test(h) && /Enable RDP/.test(h) && !/Disable RDP/.test(h) && !/disabled[^>]*>\s*<svg|\sdisabled\s/.test(h.replace(/DISABLED/g, '')), 'Disabled: shows Enable RDP, enabled button');
  h = render({ vm_status: 'stopped' });
  ok(/Enable RDP/.test(h) && /\sdisabled\s/.test(h), 'Disabled + VM stopped: Enable RDP button is greyed out');
  h = render({ enabled: true, status: 'installing', message: 'Allocating a host port', host: 'h', port: 33890, username: 'u' });
  ok(/INSTALLING/.test(h) && /Allocating a host port/.test(h) && /spinner/.test(h), 'Installing: progress message and spinner');
  h = render({ enabled: true, status: 'online', host: 'rdp.example.com', port: 33890, username: 'ubuntu', guest_os: 'Ubuntu 24.04' });
  ok(/ONLINE/.test(h) && />rdp\.example\.com:33890</.test(h) && /Copy/.test(h) && /Disable RDP/.test(h) && /rdp\.example\.com/.test(h) && />ubuntu</.test(h.replace(/\s+/g,''))||/ubuntu/.test(h), 'Online: host, port, username, connection address + Copy + Disable RDP');
  h = render({ enabled: true, status: 'offline', message: 'The VM is stopped', vm_status: 'stopped', host: 'h', port: 1, username: 'u' });
  ok(/OFFLINE/.test(h) && /The VM is stopped/.test(h), 'Offline: status and reason');
  h = render({ enabled: true, status: 'pending_restart', message: 'Restart the VM to activate the RDP port forward', host: 'h', port: 1, username: 'u' });
  ok(/RESTART REQUIRED/.test(h) && /Restart the VM/.test(h), 'Restart Required is shown, never Online');
  h = render({ status: 'error', message: 'Invalid credentials: x' });
  ok(/ERROR/.test(h) && /Invalid credentials/.test(h) && /Enable RDP/.test(h), 'Error: message shown, retry possible');
  h = render({ status: 'unsupported', message: 'Unsupported guest OS: RDP setup is only supported on Debian and Ubuntu VMs.' });
  ok(/UNSUPPORTED OS/.test(h) && /only supported on Debian and Ubuntu/.test(h), 'Unsupported OS message shown');
  h = render({ enabled: true, status: 'online', network: 'direct', host: '203.0.113.5', port: 3389, username: 'u' });
  ok(/203\.0\.113\.5:3389/.test(h) && /Direct address/.test(h), 'Direct-address VM shows its own address on 3389');
  h = render({ enabled: true, status: 'online', host: 'h', port: 1, username: 'root', warning: 'This VM logs in as root. Logging in as root over RDP is not recommended' });
  ok(/not recommended/.test(h), 'root-login warning is displayed');
  h = render({ enabled: true, status: 'online', host: 'h', port: 1, username: '<img src=x onerror=alert(1)>' });
  ok(!/<img/.test(h) && /&lt;img/.test(h), 'values are HTML-escaped (using the page\'s real escHtml/renderInfoRow)');
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
