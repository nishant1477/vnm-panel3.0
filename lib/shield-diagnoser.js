// =====================================================================
// VNM Shield — Automatic Error Teller & Diagnosis Engine
// ---------------------------------------------------------------------
// Pure classification engine (no side effects, no I/O): takes any
// error (Error object, string, or {code,message}) and returns a
// human-readable diagnosis with:
//   - incident category + severity + affected component
//   - a plain-language explanation of what the error means
//   - CONFIRMED causes (provably implied by the error signature)
//     clearly separated from POSSIBLE causes (things to check)
//   - a suggested fix / next step
//   - a stable fingerprint used by the incident store to group
//     duplicates into one incident instead of spamming notifications
//
// Everything that might end up in a notification or UI passes through
// redact() first: passwords, tokens, private keys and session ids are
// masked wherever they appear.
// =====================================================================

'use strict';

const crypto = require('crypto');

// ---------------- redaction ----------------
const SECRET_PATTERNS = [
  // key=value style credentials in logs / env dumps
  /\b(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|auth|credential)s?\s*[:=]\s*"?[^\s",}]{3,}"?/gi,
  // Bearer / Basic authorization headers
  /\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/=]{8,}/g,
  // JWTs
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  // PEM private key blocks (keep header/footer, mask body)
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  // base64-ish session ids after known field names
  /\b(sid|session[_-]?id|cookie)\s*[:=]\s*"?[A-Za-z0-9%+/=]{16,}"?/gi,
];

function redact(text, extraSecrets) {
  if (text === null || text === undefined) return '';
  let out = String(text);
  for (const re of SECRET_PATTERNS) {
    out = out.replace(re, (m) => {
      // keep the field name, mask the value
      const eq = m.search(/[:=]/);
      if (eq > 0) return m.slice(0, eq + 1) + '***REDACTED***';
      return '***REDACTED***';
    });
  }
  if (Array.isArray(extraSecrets)) {
    for (const s of extraSecrets) {
      if (typeof s === 'string' && s.length >= 6) {
        out = out.split(s).join('***REDACTED***');
      }
    }
  }
  return out;
}

// ---------------- knowledge base ----------------
// Order matters: first match wins. Each entry:
//   match: { code?: RegExp|string[], message?: RegExp, any?: boolean }
//   diagnosis fields on hit
const KB = [
  // ---- networking ----
  {
    id: 'net.eaddrinuse',
    match: { code: ['EADDRINUSE'] },
    category: 'networking', component: 'panel/network', severity: 'high',
    title: 'A network port is already in use',
    explanation: 'The panel (or one of its services) tried to listen on a TCP port, but another process is already bound to it. Only one process can own a port at a time.',
    confirmed: ['Another process is already listening on the same port.'],
    possible: ['A second copy of the panel was started (old instance never exited)', 'Another application (web server, proxy, game server) took the port', 'A previous panel process is stuck'],
    fix: 'Find the process holding the port (ss -tlnp | grep <port>) and stop it, or change the PORT setting. If it is an old panel copy: systemctl restart vnm-panel.',
  },
  {
    id: 'net.econnrefused',
    match: { code: ['ECONNREFUSED'] },
    category: 'networking', component: 'network', severity: 'medium',
    title: 'Connection refused by the remote host',
    explanation: 'The target machine actively refused the connection. The port is reachable but nothing is listening on it (or a firewall rejects it).',
    confirmed: ['Nothing is accepting connections on the target address/port right now.'],
    possible: ['The remote service (agent, SSH, VM service) is stopped', 'The service listens on a different port than configured', 'A firewall rule is rejecting the connection'],
    fix: 'Check that the remote service is running (systemctl status <service>) and that its port matches the configuration.',
  },
  {
    id: 'net.etimedout',
    match: { code: ['ETIMEDOUT', 'ETIMEOUT'] },
    category: 'networking', component: 'network', severity: 'medium',
    title: 'Network connection timed out',
    explanation: 'The remote host never answered. Packets are being dropped somewhere between this server and the target - common with broken IPv6 routes, firewall drops, or an unreachable host.',
    confirmed: ['No response arrived from the remote host within the timeout window.'],
    possible: ['Broken IPv6 egress on this host (AAAA-first resolution can pick a dead route)', 'Firewall silently dropping packets', 'The remote host is down or overloaded'],
    fix: 'Test with curl -4 <target> (force IPv4). If that works, the IPv6 route is broken - the panel already prefers IPv4; check the host routing table otherwise.',
  },
  {
    id: 'net.dns',
    match: { code: ['ENOTFOUND', 'EAI_AGAIN'] },
    category: 'networking', component: 'network/dns', severity: 'medium',
    title: 'DNS resolution failed',
    explanation: 'The server could not translate a hostname into an IP address. Either the name does not exist, or the configured DNS resolver is unreachable.',
    confirmed: ['The hostname could not be resolved to an IP address.'],
    possible: ['Typo in the hostname', 'DNS server down or misconfigured (/etc/resolv.conf)', 'Temporary resolver outage (EAI_AGAIN means "try again later")'],
    fix: 'Verify the hostname with `nslookup <host>` from the server. If all lookups fail, check /etc/resolv.conf.',
  },
  {
    id: 'net.econnreset',
    match: { code: ['ECONNRESET', 'EPIPE'] },
    category: 'networking', component: 'network', severity: 'low',
    title: 'Connection closed unexpectedly',
    explanation: 'The other side of an open connection closed it abruptly (or a middlebox cut it). For a management panel this is usually a browser/agent disconnecting mid-request.',
    confirmed: ['A live connection was terminated before the response finished.'],
    possible: ['Client closed the tab / cancelled a download', 'Node agent restarted mid-command', 'Idle timeout on a proxy or load balancer'],
    fix: 'Usually harmless and self-healing. If it repeats for one specific node, check that node agent logs.',
  },
  {
    id: 'net.handshake',
    match: { message: /(handshake|TLS|SSL|certificate)[^\n]*(timed out|failed|error)|(?:timed out|failed|error)[^\n]*(handshake|TLS|SSL)/i },
    category: 'networking', component: 'network/tls', severity: 'medium',
    title: 'Secure handshake failed',
    explanation: 'A TLS/SSH handshake did not complete. The TCP connection opened, but the two sides could not agree on an encrypted session.',
    confirmed: ['The endpoint is reachable, but the encrypted protocol negotiation failed.'],
    possible: ['The service on that port is not speaking the expected protocol', 'SSH server slow to boot (guest VM still initializing)', 'TLS version/cipher mismatch', 'Certificate validation failure'],
    fix: 'Check the service type on the target port. For fresh VMs, remember sshd can take minutes to appear after first boot.',
  },

  // ---- storage ----
  {
    id: 'storage.enospc',
    match: { code: ['ENOSPC'] },
    category: 'storage', component: 'disk', severity: 'critical',
    title: 'Disk is full',
    explanation: 'A write failed because the filesystem has no space left. At 100% usage the database, VM disks and logs all start failing - this needs immediate attention.',
    confirmed: ['The filesystem is out of free space (or out of inodes).'],
    possible: ['VM disk images grew to fill the volume', 'Large log files', 'Old backups accumulating'],
    fix: 'Open Shield → Resources for safe cleanup suggestions (logs, temp files, old backups). Never delete VM disk images manually.',
  },
  {
    id: 'storage.eacces',
    match: { code: ['EACCES', 'EPERM'] },
    category: 'permission', component: 'filesystem', severity: 'high',
    title: 'Permission denied',
    explanation: 'The panel process lacks the rights to read, write, or execute the target file. Either the file is owned by another user or its permission bits block the operation.',
    confirmed: ['The running user is not allowed to perform this operation on the target.'],
    possible: ['Files owned by root after an update ran as root', 'Directory permissions too strict (needs read+execute, files need read)', 'Read-only filesystem', 'Missing group access to /dev/kvm'],
    fix: 'Run the Shield → Lockdown check. It reports (and can fix) wrong ownership/permissions using the documented lockdown profile: sudo scripts/lockdown.sh --recover.',
  },
  {
    id: 'storage.enoent',
    match: { code: ['ENOENT'] },
    category: 'storage', component: 'filesystem', severity: 'medium',
    title: 'File or command not found',
    explanation: 'The requested file or external command does not exist at the expected path. For commands this means the binary is not installed (or not in PATH); for files it means they were moved, deleted, or never created.',
    confirmed: ['The exact path looked up does not exist.'],
    possible: ['Required software (qemu-system-x86_64, tar, openssl) not installed', 'A VM disk/template file was moved or deleted', 'The data directory is not where the panel expects it'],
    fix: 'Check the exact path in the error. Missing tools: install them (apt install qemu-kvm). Missing VM files: check Shield → Integrity for tamper alerts.',
  },

  // ---- SQLite ----
  {
    id: 'db.busy',
    match: { message: /SQLITE_BUSY|database is locked/i },
    category: 'database', component: 'database/sqlite', severity: 'medium',
    title: 'Database is locked',
    explanation: 'Another connection held the SQLite database write lock for longer than the busy timeout. SQLite allows one writer at a time; under heavy parallel load a writer can starve.',
    confirmed: ['Two or more writers competed for the database simultaneously.'],
    possible: ['A long-running backup or export held the lock', 'An external process (manual sqlite3 CLI) is writing', 'Very high concurrent write load'],
    fix: 'The panel retries automatically. If it persists, run Shield → Diagnostics (shows the database lock state) and check for external writers.',
  },
  {
    id: 'db.corrupt',
    match: { message: /SQLITE_CORRUPT|database disk image is malformed|not a database/i },
    category: 'database', component: 'database/sqlite', severity: 'critical',
    title: 'Database corruption detected',
    explanation: 'The SQLite database file failed an integrity check. This is usually caused by a hard power loss or a full disk at the moment of a write, not by normal operation.',
    confirmed: ['The database file content is inconsistent with SQLite expectations.'],
    possible: ['Power loss / crash during a write', 'Disk-full event during a write', 'Storage hardware errors'],
    fix: 'STOP further writes. Restore the latest verified backup: `vnmctl restore <backup-file>` (works even with the web panel down). The Backup Vault keeps versioned, verified copies.',
  },
  {
    id: 'db.readonly',
    match: { message: /attempt to write a readonly database/i },
    category: 'database', component: 'database/sqlite', severity: 'high',
    title: 'Database opened read-only',
    explanation: 'SQLite can read but not write the database file - the file, its directory, or the WAL files are not writable by the panel user.',
    confirmed: ['The database file or its directory lacks write permission for the running user.'],
    possible: ['Ownership changed to root (update ran as root)', 'Lockdown script applied overly strict permissions', 'Filesystem remounted read-only'],
    fix: 'Restore correct ownership with the lockdown recovery command: `sudo scripts/lockdown.sh --recover`.',
  },

  // ---- QEMU / KVM ----
  {
    id: 'qemu.cpu.host.kvm',
    match: { message: /CPU model 'host' requires KVM|accelerator "kvm" does not support/i },
    category: 'qemu', component: 'vm/qemu', severity: 'high',
    title: 'KVM acceleration unavailable',
    explanation: 'The VM was configured for KVM hardware acceleration, but the host cannot provide it (no /dev/kvm, nested virtualization disabled, or KVM module not loaded).',
    confirmed: ['KVM is not usable on this host right now.'],
    possible: ['Nested virtualization disabled in the provider control panel', 'kvm module not loaded (bare metal)', 'VM started inside another VM'],
    fix: 'The panel automatically falls back to software emulation (TCG) on such hosts. To get full speed, enable nested virt / load the kvm module; otherwise accept TCG performance.',
  },
  {
    id: 'qemu.disk.open',
    match: { message: /could not open (?:disk image|backing file|device)/i },
    category: 'qemu', component: 'vm/disk', severity: 'high',
    title: 'VM disk could not be opened',
    explanation: 'QEMU refused to start because it could not open one of the VM disk images - locked by another process, missing, or unreadable.',
    confirmed: ['The named disk image cannot be used by QEMU.'],
    possible: ['The image is locked (a stale QEMU process still holds it)', 'The image file was moved/renamed/deleted', 'Permission problem on the image file'],
    fix: 'Check for a stale process (ps aux | grep qemu), verify the path exists, and re-run the VM diagnostic from Shield → VM Guardian.',
  },
  {
    id: 'qemu.exited',
    match: { message: /QEMU exited (?:immediately|with code|after)/i },
    category: 'qemu', component: 'vm/qemu', severity: 'high',
    title: 'QEMU process died at startup',
    explanation: 'The QEMU process for a VM exited instead of staying alive. Its stderr (surfaced with this error) names the exact reason - bad arguments, missing files, or missing hardware support.',
    confirmed: ['QEMU terminated by itself; this is not a panel crash.'],
    possible: ['Invalid CPU/machine configuration for this host', 'Missing disk or cloud-init seed file', 'Port forwarding conflict with another VM'],
    fix: 'Read the QEMU reason included in the error, or open the VM console log. Shield → VM Guardian offers a per-VM diagnostic.',
  },
  {
    id: 'qemu.kvm.device',
    match: { message: /\/dev\/kvm[^\n]*(denied|not found|permission)|open \/dev\/kvm/i },
    category: 'qemu', component: 'vm/kvm', severity: 'medium',
    title: '/dev/kvm access problem',
    explanation: 'The KVM device exists but the panel user cannot use it, or it does not exist on this host.',
    confirmed: ['KVM device access failed.'],
    possible: ['User not in the kvm group', 'KVM module not loaded', 'Running inside a container without device passthrough'],
    fix: 'Add the service user to the kvm group (usermod -aG kvm <user>) and restart the service, or run on a host with KVM.',
  },

  // ---- SSH / RDP ----
  {
    id: 'ssh.auth.failed',
    match: { code: ['GUEST_AUTH_FAILED'] },
    category: 'ssh', component: 'vm/ssh', severity: 'medium',
    title: 'Guest SSH authentication failed',
    explanation: 'The SSH server inside the VM rejected the credentials the panel used. The VM is running and sshd is up - only the username/password is wrong.',
    confirmed: ['The guest OS refused the login credentials.'],
    possible: ['VM password was changed inside the guest', 'Cloud-init did not apply the configured password (image without cloud-init)', 'SSH server denies password logins (PasswordAuthentication no)'],
    fix: 'Reset the VM password from the panel (the serial console works without SSH), then retry.',
  },
  {
    id: 'ssh.handshake',
    match: { code: ['GUEST_SSH_HANDSHAKE'] },
    category: 'ssh', component: 'vm/ssh', severity: 'medium',
    title: 'Guest SSH handshake timed out',
    explanation: 'The SSH port answered, but the key exchange never completed - typical while a freshly booted VM is still initializing, or when the port is answered by something that is not sshd.',
    confirmed: ['The guest SSH endpoint did not complete a handshake in time.'],
    possible: ['Guest still booting (first boot runs cloud-init)', 'Guest under heavy load / out of memory', 'Another service bound to the forwarded port'],
    fix: 'Wait for boot to finish, then retry. The panel retries automatically for the configured wait window.',
  },
  {
    id: 'rdp.setup',
    match: { message: /RDP[^\n]*(fail|error|unable)|xrdp[^\n]*(fail|error)/i },
    category: 'rdp', component: 'vm/rdp', severity: 'medium',
    title: 'Remote Desktop setup problem',
    explanation: 'Installing or reaching the RDP stack inside the VM failed. The VM console and SSH are unaffected.',
    confirmed: ['The RDP enable/reach step failed.'],
    possible: ['Guest package repository unreachable from inside the VM', 'Guest out of disk space for new packages', 'xrdp service did not start after install'],
    fix: 'Open the VM console and check `systemctl status xrdp` and free disk space (df -h) inside the guest.',
  },

  // ---- process / system ----
  {
    id: 'sys.emfile',
    match: { code: ['EMFILE', 'ENFILE'] },
    category: 'process', component: 'panel/process', severity: 'high',
    title: 'Too many open files',
    explanation: 'The process hit its file-descriptor limit. Sockets, files and pipes all count; long-running panels leak these when something is not closed.',
    confirmed: ['The OS refused a new file/socket because the per-process limit was reached.'],
    possible: ['A resource leak (unclosed sockets/streams) in a long session', 'Limit too low for the workload (default is often 1024)'],
    fix: 'Raise the limit for the service (LimitNOFILE=65536 in the unit file) and restart. If it recurs quickly, report it - that would be a leak.',
  },
  {
    id: 'sys.oom',
    match: { message: /JavaScript heap out of memory|out of memory|killed process/i },
    category: 'process', component: 'panel/process', severity: 'critical',
    title: 'Out of memory',
    explanation: 'The process ran out of RAM - either the Node heap limit was hit, or the OS OOM-killer terminated a process because the host was out of memory.',
    confirmed: ['A process died or failed because memory was exhausted.'],
    possible: ['Host RAM oversubscribed by too many/too large VMs', 'A very large file operation inside the panel', 'Memory leak in a long-running session'],
    fix: 'Check host memory (free -h). Stop unneeded VMs or add RAM. For heap limits: raise --max-old-space-size in the service definition.',
  },
  {
    id: 'sys.service.failed',
    match: { message: /unit [^\s]+\.service (?:failed|is failed)|Failed with result/i },
    category: 'systemd', component: 'system/service', severity: 'high',
    title: 'A systemd service failed',
    explanation: 'A managed service entered the failed state - it exited with a non-zero code or was killed, and systemd recorded the failure.',
    confirmed: ['The named service unit is in failed state.'],
    possible: ['Application crash (see the service journal)', 'Configuration error after manual edits', 'Dependency (network, disk) unavailable at start'],
    fix: 'Inspect `journalctl -u <service> -n 100`. Shield → Auto-Recovery can restart it with cooldown protection and records every attempt.',
  },
  {
    id: 'sys.port.forward',
    match: { message: /could not set up host forwarding|hostfwd|address already in use/i },
    category: 'qemu', component: 'vm/network', severity: 'medium',
    title: 'Port forwarding conflict',
    explanation: 'Two VMs (or a VM and a host service) want the same host port. QEMU refuses to start the second one.',
    confirmed: ['The requested host port is taken.'],
    possible: ['Another VM has the same forwarded port', 'Host service already on that port', 'A previous QEMU instance still holds it'],
    fix: 'Change one VM port mapping (VM → Edit → Network) or free the port. The VMs page lists all forwards.',
  },

  // ---- panel / HTTP ----
  {
    id: 'panel.template',
    match: { message: /Failed to lookup view|template not found/i },
    category: 'panel', component: 'panel/views', severity: 'high',
    title: 'A page template is missing',
    explanation: 'The web server could not render a page because its template file is missing or unreadable - a strong indicator of an interrupted update or file tampering.',
    confirmed: ['The view file for the requested page does not exist where the panel expects it.'],
    possible: ['Interrupted or partial update', 'Files deleted or replaced by someone with host access', 'Wrong working directory'],
    fix: 'Run Shield → Integrity scan NOW: it compares every panel file against trusted SHA-256 baselines and can restore verified copies.',
  },
  {
    id: 'panel.badjson',
    match: { message: /Unexpected token [^\s]+ in JSON|invalid json body|failed to parse[^\n]*json/i },
    category: 'panel', component: 'panel/http', severity: 'low',
    title: 'Malformed request body',
    explanation: 'A client sent invalid JSON to an API endpoint. The panel rejected it safely; nothing on the server changed.',
    confirmed: ['Client-side bug or manual API call with a malformed payload.'],
    possible: ['Browser extension interfering with requests', 'Script calling the API with a formatting error'],
    fix: 'No server action needed. If you were scripting against the API, validate your JSON.',
  },
  {
    id: 'panel.authz',
    match: { message: /(access denied|forbidden|not authorized|insufficient permissions)/i },
    category: 'panel', component: 'panel/authz', severity: 'low',
    title: 'Authorization check rejected a request',
    explanation: 'A logged-in user tried to reach something outside their role or ownership. This is the access-control system working as designed.',
    confirmed: ['The request was correctly denied.'],
    possible: ['Customer tried an admin/staff endpoint', 'Attempt to access another user VM', 'Stale page after permissions changed'],
    fix: 'No action needed. Repeated denials from one account are visible in the Security events feed and may indicate probing.',
  },
  {
    id: 'panel.upstream.502',
    match: { message: /502 bad gateway|upstream (?:failed|unavailable)/i },
    category: 'panel', component: 'panel/http', severity: 'medium',
    title: 'Upstream/gateway failure',
    explanation: 'A proxied request (template download, agent call) got no usable answer from the far end.',
    confirmed: ['The upstream service did not return a valid response.'],
    possible: ['Upstream service down', 'Network filtering between this host and the upstream', 'DNS pointed somewhere wrong'],
    fix: 'Test the upstream URL from the host with curl. The error details list every address attempted.',
  },
];

// ---------------- classification ----------------
function normalizeError(err) {
  if (!err) return { code: '', message: '', stack: '' };
  if (typeof err === 'string') return { code: '', message: err, stack: '' };
  return {
    code: String(err.code || err.errno || ''),
    message: String(err.message || err.error || err.description || ''),
    stack: String(err.stack || ''),
    httpStatus: err.httpStatus || err.status || undefined,
  };
}

function matches(entry, n) {
  const m = entry.match || {};
  if (m.code) {
    const codes = Array.isArray(m.code) ? m.code : [m.code];
    if (codes.some((c) => (typeof c === 'string' ? n.code === c : c.test(n.code)))) return true;
  }
  if (m.message) {
    try { if (m.message.test(n.message) || m.message.test(n.stack)) return true; } catch (e) { /* ignore */ }
  }
  return false;
}

// Classify one error -> diagnosis (or a generic fallback diagnosis)
function diagnose(err, context) {
  const n = normalizeError(err);
  const ctx = context || {};
  const hit = KB.find((e) => matches(e, n));

  const base = {
    classified: !!hit,
    raw: { code: n.code, message: redact(n.message).slice(0, 500) },
    context: ctx.component ? String(ctx.component).slice(0, 80) : undefined,
    at: new Date().toISOString(),
  };

  if (hit) {
    return {
      ...base,
      kbId: hit.id,
      category: hit.category,
      component: ctx.component || hit.component,
      severity: hit.severity,
      title: hit.title,
      explanation: hit.explanation,
      confirmed_causes: hit.confirmed.slice(),
      possible_causes: hit.possible.slice(),
      suggested_fix: hit.fix,
      fingerprint: fingerprintOf(hit.id, ctx.component || hit.component, n.code),
    };
  }

  // ---- generic fallback by coarse signals ----
  let severity = 'medium', category = 'panel', component = ctx.component || 'panel';
  let explanation = 'The panel recorded an error it could not map to a known pattern. The technical details below are redacted but otherwise complete.';
  let confirmed = ['An error occurred in the component named below.'];
  let possible = ['A transient failure (network blip, busy disk)', 'A bug in an edge-case code path', 'An environment change on the host'];
  let fix = 'Open Shield → Diagnostics to run a full system check. If this repeats, export the incident report and keep it with a bug report.';

  if (n.code && /^E/.test(n.code)) { category = 'networking'; explanation = 'A low-level system call failed. The error code below names the exact failure type.'; }
  if ((n.httpStatus || 0) >= 500) { severity = 'high'; explanation = 'An internal server error was returned to a client. The server stayed up; this request failed.'; }
  if (/sqlite|database/i.test(n.message)) { category = 'database'; component = 'database/sqlite'; }
  if (/qemu|kvm/i.test(n.message)) { category = 'qemu'; component = 'vm/qemu'; }

  return {
    ...base,
    kbId: null,
    category, component, severity,
    title: n.code ? `System error (${n.code})` : 'Unclassified panel error',
    explanation,
    confirmed_causes: confirmed,
    possible_causes: possible,
    suggested_fix: fix,
    fingerprint: fingerprintOf('generic:' + (n.code || n.message.slice(0, 60)), component, ''),
  };
}

function fingerprintOf(...parts) {
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 16);
}

function newIncidentId() {
  const t = Date.now().toString(36).toUpperCase();
  const r = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `VNM-${t}-${r}`;
}

module.exports = { diagnose, redact, newIncidentId, KB, normalizeError };
