// =====================================================================
// VNM — RDP guest helper (shared by the panel and the node agent)
// ---------------------------------------------------------------------
// Everything that touches a guest VM or its QEMU process for the
// "Enable RDP" feature lives here so the panel (Local Node) and the
// node agent (Remote Nodes) behave identically:
//
//   - provisionGuest()  SSH into the guest, verify it's Debian/Ubuntu,
//                       and idempotently install/configure xrdp + a
//                       desktop session; waits for sshd to come up on
//                       slow first boots (waitForGuestSsh) instead of
//                       failing the setup with a handshake timeout
//   - probeRdp()        real RDP handshake probe (not just a TCP
//                       connect - QEMU's NAT forwarder accepts the TCP
//                       connection even when nothing listens in the
//                       guest)
//   - hostfwdAdd/Remove add/remove the NAT host-port forward on a
//                       RUNNING VM through its QEMU monitor socket
//
// Keep node-agent/lib/rdp-guest.js a byte-for-byte copy of this file
// (same pattern as sftp-ops.js / system-info.js).
// =====================================================================

const net = require('net');
const { Client } = require('ssh2');

const RDP_GUEST_PORT = 3389;

// ---------------------------------------------------------------------
// Provisioning script (runs inside the guest, as root)
// ---------------------------------------------------------------------
// Idempotent by design: every step checks current state first, existing
// xrdp config files are never rewritten, and an existing ~/.xsession is
// never overwritten. Exit codes: 0 ok, 42 unsupported OS, 50 apt
// update/network failure, 51 xrdp install failure, 52 desktop install
// failure, 53 xrdp not listening after setup.
function buildProvisionScript(targetUser) {
  const safeUser = /^[a-z_][a-z0-9_-]{0,31}$/i.test(String(targetUser || '')) ? targetUser : '';
  return `#!/bin/bash
set -u
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
TARGET_USER="${safeUser}"
CHANGED=0
log() { echo "VNM_RDP: $*"; }

if ! . /etc/os-release 2>/dev/null; then log "UNSUPPORTED: /etc/os-release not found"; exit 42; fi
case " \${ID:-} \${ID_LIKE:-} " in
  *" debian "*|*" ubuntu "*) ;;
  *) log "UNSUPPORTED: \${PRETTY_NAME:-unknown OS}"; exit 42 ;;
esac
if ! command -v apt-get >/dev/null 2>&1; then log "UNSUPPORTED: apt-get not found"; exit 42; fi
log "OS: \${PRETTY_NAME:-\$ID}"

# A freshly booted cloud image is usually still running cloud-init (which
# holds the dpkg lock). Wait for it, but never hang forever.
if command -v cloud-init >/dev/null 2>&1; then
  timeout 300 cloud-init status --wait >/dev/null 2>&1 || true
fi

APT="apt-get -y -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"

if dpkg -s xrdp >/dev/null 2>&1; then
  log "xrdp already installed"
else
  log "installing xrdp"
  # One broken third-party repo makes "apt-get update" exit non-zero even when
  # the main indexes refreshed fine - warn and let the install decide.
  $APT update >/dev/null 2>&1 || log "apt-get update reported errors - continuing"
  $APT install xrdp xorgxrdp >/dev/null 2>&1 || $APT install xrdp xorgxrdp >/dev/null 2>&1 || { log "xrdp install failed - check that the VM has internet access and working apt sources"; exit 51; }
  CHANGED=1
fi

# Desktop session: reuse an existing lightweight desktop; otherwise install
# XFCE (GNOME is unreliable under xrdp, so it is not used even if present).
DESKTOP_CMD=""
for b in xfce4-session mate-session startlxqt cinnamon-session startplasma-x11; do
  if command -v "$b" >/dev/null 2>&1; then DESKTOP_CMD="$b"; break; fi
done
if [ -z "$DESKTOP_CMD" ]; then
  log "installing XFCE desktop"
  $APT update >/dev/null 2>&1 || true
  $APT install xfce4 xfce4-terminal dbus-x11 >/dev/null 2>&1 || $APT install xfce4 xfce4-terminal dbus-x11 >/dev/null 2>&1 || { log "desktop install failed - check that the VM has internet access and working apt sources"; exit 52; }
  DESKTOP_CMD="xfce4-session"
  CHANGED=1
else
  log "desktop already present: $DESKTOP_CMD"
fi

# Session file for the login user - never overwrite an existing one.
if [ -n "$TARGET_USER" ] && id "$TARGET_USER" >/dev/null 2>&1; then
  USER_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
  if [ -n "$USER_HOME" ] && [ -d "$USER_HOME" ] && [ "$TARGET_USER" != "root" ]; then
    if [ ! -e "$USER_HOME/.xsession" ]; then
      echo "$DESKTOP_CMD" > "$USER_HOME/.xsession"
      chown "$TARGET_USER": "$USER_HOME/.xsession" 2>/dev/null || true
      chmod 644 "$USER_HOME/.xsession"
      log "created $USER_HOME/.xsession"
      CHANGED=1
    else
      log ".xsession already exists - left untouched"
    fi
  fi
fi

# xrdp needs read access to the TLS key on Debian/Ubuntu.
if getent group ssl-cert >/dev/null 2>&1 && ! id -nG xrdp 2>/dev/null | tr ' ' '\\n' | grep -qx ssl-cert; then
  usermod -aG ssl-cert xrdp 2>/dev/null && CHANGED=1
fi

# Older Debian/Ubuntu refuse to start Xorg for non-console users.
if [ -f /etc/X11/Xwrapper.config ] && grep -qE '^allowed_users=console' /etc/X11/Xwrapper.config; then
  sed -i 's/^allowed_users=console.*/allowed_users=anybody/' /etc/X11/Xwrapper.config
  CHANGED=1
fi

# Guest firewall: only touch ufw if it is actually active.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "^Status: active"; then
  if ! ufw status 2>/dev/null | grep -qE '^3389(/tcp)?[[:space:]]+ALLOW'; then
    ufw allow ${RDP_GUEST_PORT}/tcp >/dev/null 2>&1 && CHANGED=1
  fi
fi

systemctl enable xrdp >/dev/null 2>&1 || true
if systemctl is-active --quiet xrdp && [ "$CHANGED" = "0" ]; then
  log "xrdp already running - no restart needed"
else
  systemctl restart xrdp-sesman >/dev/null 2>&1 || true
  systemctl restart xrdp >/dev/null 2>&1 || systemctl start xrdp >/dev/null 2>&1 || true
fi

for i in $(seq 1 20); do
  if ss -ltn 2>/dev/null | grep -qE '[:.]${RDP_GUEST_PORT}[[:space:]]'; then
    # Listening is not enough: the service itself must be up (guards against
    # an unrelated process squatting on 3389).
    if pgrep -x xrdp >/dev/null 2>&1 || systemctl is-active --quiet xrdp 2>/dev/null; then
      log "xrdp service is running and listening on ${RDP_GUEST_PORT}"
      log "DONE desktop=$DESKTOP_CMD"
      exit 0
    fi
    log "port ${RDP_GUEST_PORT} is in use by something other than xrdp"
    exit 54
  fi
  sleep 1
done
log "xrdp is not listening on port ${RDP_GUEST_PORT} after setup"
exit 53
`;
}

// ---------------------------------------------------------------------
// SSH helpers
// ---------------------------------------------------------------------
function sshConnect(conn, opts = {}) {
  return new Promise((resolve, reject) => {
    const c = new Client();
    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      try { c.end(); } catch (e) { /* ignore */ }
      reject(err);
    };
    c.on('ready', () => { if (!settled) { settled = true; resolve(c); } });
    c.on('error', (err) => {
      const msg = String(err.message || '');
      const authFailed = err.level === 'client-authentication' || /authentication methods failed/i.test(msg);
      let e;
      if (authFailed) {
        e = new Error('Invalid credentials: the VM rejected the SSH username/password. Check the VM user and password.');
        e.code = 'GUEST_AUTH_FAILED';
      } else if (/handshake/i.test(msg)) {
        // QEMU's user-mode forwarder accepts the host-side TCP connection
        // long before the guest has anything listening, so "connected"
        // proves nothing. A handshake timeout means sshd is not answering
        // yet (still booting) or something other than SSH holds the port.
        e = new Error(`Connected to the VM's SSH port but it never completed the SSH handshake - sshd is probably not up yet (the VM is still booting) [${msg}]`);
        e.code = 'GUEST_SSH_HANDSHAKE';
      } else if (/ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|ETIMEDOUT|ECONNRESET|ENOTFOUND/i.test(msg)) {
        e = new Error(`Nothing is answering on the VM SSH port - is the VM running? [${msg}]`);
        e.code = 'GUEST_SSH_UNREACHABLE';
      } else {
        e = new Error('Could not reach the VM over SSH (is it fully booted and is sshd running?): ' + msg);
        e.code = 'GUEST_SSH_FAILED';
      }
      fail(e);
    });
    c.connect({
      host: conn.host,
      port: conn.port,
      username: conn.username || 'root',
      password: conn.password || undefined,
      readyTimeout: (opts && opts.readyTimeoutMs) || 15000,
      algorithms: { serverHostKey: ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519'] }
    });
  });
}

// ---------------------------------------------------------------------
// Wait for the guest's sshd to accept a connection (BUG FIX: RDP setup
// died with "Timed out while waiting for handshake").
// A first boot - especially under TCG software emulation on hosts without
// KVM, which boots 5-20x slower than KVM - can take minutes before sshd
// accepts logins, and QEMU's user-mode forwarder accepts the TCP
// connection long before that, so a single 15s attempt failed whole
// setups. Retry here instead; authentication failures are NEVER retried
// (retrying a bad password only gets the account locked out).
// ---------------------------------------------------------------------
async function waitForGuestSsh(conn, { totalMs = 10 * 60 * 1000, intervalMs = 5000, readyTimeoutMs = 15000, onProgress, log } = {}) {
  const deadline = Date.now() + totalMs;
  let lastErr = null;
  for (let attempt = 1; ; attempt++) {
    try {
      return await sshConnect(conn, { readyTimeoutMs });
    } catch (e) {
      lastErr = e;
      const retryable = e.code === 'GUEST_SSH_HANDSHAKE' || e.code === 'GUEST_SSH_UNREACHABLE' || e.code === 'GUEST_SSH_FAILED';
      if (!retryable) throw e; // auth failure and friends: fail fast, never retry
      const remaining = deadline - Date.now();
      if (remaining <= 0) break;
      const note = e.code === 'GUEST_SSH_UNREACHABLE'
        ? 'the SSH port is not reachable yet'
        : 'sshd is not answering yet';
      const progressMsg = `Waiting for the VM to finish booting - ${note} (attempt ${attempt})`;
      if (onProgress) onProgress(progressMsg);
      if (log) log('ssh_retry', { attempt, code: e.code, message: e.message, retryInMs: Math.min(intervalMs, remaining) });
      await new Promise((r) => setTimeout(r, Math.min(intervalMs, remaining)));
    }
  }
  const budget = Math.round(totalMs / 1000);
  const wrapped = new Error(
    lastErr.code === 'GUEST_SSH_HANDSHAKE'
      ? `Could not reach the VM over SSH after waiting ${budget}s: the connection was accepted but sshd never completed the handshake. If the VM was just started it may still be booting (software emulation boots slowly) - wait for the first boot to finish, then retry. [last: ${lastErr.message}]`
      : `Could not reach the VM over SSH after waiting ${budget}s: nothing answered on the VM SSH port. Make sure the VM is started and has finished booting, then retry. [last: ${lastErr.message}]`
  );
  wrapped.code = lastErr.code;
  throw wrapped;
}

function execOnce(client, command, { stdin, timeoutMs = 20 * 60 * 1000, onLine } = {}) {
  return new Promise((resolve, reject) => {
    client.exec(command, (err, stream) => {
      if (err) return reject(err);
      let stdout = '', stderr = '', carry = '';
      const timer = setTimeout(() => {
        try { stream.close(); } catch (e) { /* ignore */ }
        const e = new Error('Timed out while configuring RDP inside the VM');
        e.code = 'GUEST_TIMEOUT';
        reject(e);
      }, timeoutMs);
      stream.on('data', (d) => {
        const s = d.toString();
        stdout += s;
        if (onLine) {
          carry += s;
          let i;
          while ((i = carry.indexOf('\n')) >= 0) { onLine(carry.slice(0, i)); carry = carry.slice(i + 1); }
        }
      });
      stream.stderr.on('data', (d) => { stderr += d.toString(); });
      stream.on('close', (code) => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
      if (stdin !== undefined) stream.end(stdin); else stream.end();
    });
  });
}

function shQuote(s) { return `'${String(s).replace(/'/g, `'\\''`)}'`; }

// Parse /etc/os-release style output.
function parseOsRelease(text) {
  const out = {};
  String(text || '').split('\n').forEach((line) => {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (m) out[m[1]] = m[2].replace(/^"(.*)"$/, '$1');
  });
  return out;
}

function isDebianFamily(osr) {
  return /\b(debian|ubuntu)\b/i.test(`${osr.ID || ''} ${osr.ID_LIKE || ''}`);
}

function unsupportedError(label) {
  const e = new Error(`Unsupported guest OS${label ? ` (${label})` : ''}: RDP setup is only supported on Debian and Ubuntu VMs.`);
  e.code = 'UNSUPPORTED_OS';
  e.httpStatus = 422;
  return e;
}

// conn: { host, port, username, password }
// Returns { os: 'Ubuntu 22.04.4 LTS', desktop: 'xfce4-session', log: [...] }
async function provisionGuest(conn, { onProgress, log = () => {}, sshWaitMs } = {}) {
  log('ssh_connect', { host: conn.host, port: conn.port, user: conn.username });
  // BUG FIX ("Timed out while waiting for handshake"): the guest - on its
  // first boot, especially under TCG - can take minutes before sshd is
  // up. Wait for SSH instead of failing the whole setup on one attempt;
  // bad credentials still fail immediately inside waitForGuestSsh.
  const client = await waitForGuestSsh(conn, {
    totalMs: sshWaitMs && sshWaitMs > 0 ? sshWaitMs : 10 * 60 * 1000,
    intervalMs: 5000,
    readyTimeoutMs: 15000,
    onProgress: (msg) => { log('ssh_wait', { message: msg }); if (onProgress) onProgress(msg); },
    log
  });
  try {
    const probe = await execOnce(client, 'cat /etc/os-release 2>/dev/null; echo "UID=$(id -u)"', { timeoutMs: 20000 });
    const osr = parseOsRelease(probe.stdout);
    const uidMatch = probe.stdout.match(/^UID=(\d+)$/m);
    const isRoot = uidMatch && uidMatch[1] === '0';
    if (!osr.ID && !osr.ID_LIKE) throw unsupportedError('could not read /etc/os-release');
    log('os_detected', { os: osr.PRETTY_NAME || osr.ID, supported: isDebianFamily(osr), root: !!isRoot });
    if (!isDebianFamily(osr)) throw unsupportedError(osr.PRETTY_NAME || osr.ID);

    // Privilege check BEFORE anything is installed. Password goes in on stdin
    // only; passwordless sudo ignores it.
    if (!isRoot) {
      const sudoCheck = await execOnce(client, `sudo -S -p '' true 2>&1`, { stdin: (conn.password || '') + '\n', timeoutMs: 20000 });
      if (sudoCheck.code !== 0) {
        log('sudo_check_failed', { user: conn.username });
        throw Object.assign(new Error(`User "${conn.username}" cannot use sudo inside the VM, so xrdp cannot be installed. Use an account with sudo rights (or root).`), { code: 'GUEST_NO_SUDO' });
      }
      log('sudo_check_ok', { user: conn.username });
    }

    const script = buildProvisionScript(conn.username);
    // Unique per run so two users / concurrent runs can never collide on a stale file.
    const SCRIPT_REMOTE_PATH = `/tmp/.vnm-rdp-${process.pid}-${Date.now().toString(36)}.sh`;
    try {
    const up = await execOnce(client, `umask 077; cat > ${SCRIPT_REMOTE_PATH} && chmod 700 ${SCRIPT_REMOTE_PATH}`, { stdin: script, timeoutMs: 30000 });
    if (up.code !== 0) throw Object.assign(new Error('Could not upload the RDP setup script to the VM: ' + (up.stderr || '').trim()), { code: 'GUEST_UPLOAD_FAILED' });

    const lines = [];
    const onLine = (line) => {
      if (line.startsWith('VNM_RDP:')) {
        const msg = line.slice(8).trim();
        lines.push(msg);
        log('guest_step', { step: msg });
        if (onProgress) onProgress(msg);
      }
    };

    let run;
    if (isRoot) {
      run = await execOnce(client, `bash ${SCRIPT_REMOTE_PATH} 2>&1`, { onLine });
    } else {
      // The password goes in on stdin only (never on the command line). If
      // the account has passwordless sudo, sudo ignores it.
      run = await execOnce(client, `sudo -S -p '' bash ${SCRIPT_REMOTE_PATH} 2>&1`, { stdin: (conn.password || '') + '\n', onLine });
      if (run.code !== 0 && /not in the sudoers|may not run sudo|incorrect password|sorry, try again|a password is required/i.test(run.stdout)) {
        throw Object.assign(new Error(`User "${conn.username}" cannot use sudo inside the VM, so xrdp cannot be installed. Use an account with sudo rights (or root).`), { code: 'GUEST_NO_SUDO' });
      }
    }

    if (run.code === 42) throw unsupportedError(osr.PRETTY_NAME || osr.ID);
    if (run.code !== 0) {
      const last = lines.filter(Boolean).slice(-1)[0];
      const e = new Error(last ? `RDP setup failed: ${last}` : `RDP setup failed inside the VM (exit code ${run.code})`);
      e.code = ({ 51: 'XRDP_INSTALL_FAILED', 52: 'DESKTOP_INSTALL_FAILED', 53: 'XRDP_NOT_LISTENING', 54: 'RDP_PORT_CONFLICT' })[run.code] || 'GUEST_SETUP_FAILED';
      throw e;
    }
    const done = lines.find((l) => l.startsWith('DONE'));
    const desktop = done ? (done.match(/desktop=(\S+)/) || [])[1] : null;
    return { os: osr.PRETTY_NAME || osr.ID, desktop, log: lines, root: !!isRoot };
    } finally {
      // Runs on every path (success, sudo failure, setup failure, timeout).
      await execOnce(client, `rm -f ${SCRIPT_REMOTE_PATH}`, { timeoutMs: 10000 }).catch(() => {});
    }
  } finally {
    try { client.end(); } catch (e) { /* ignore */ }
  }
}

// ---------------------------------------------------------------------
// RDP probe: send an X.224 Connection Request and expect a TPKT reply.
// A plain TCP connect is NOT enough - QEMU's user-mode forwarder
// accepts the host-side connection even when the guest has nothing
// listening, then drops it. A real RDP server answers with 0x03 0x00.
// ---------------------------------------------------------------------
const X224_CONNECTION_REQUEST = Buffer.from([
  0x03, 0x00, 0x00, 0x13,             // TPKT, length 19
  0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR
  0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00 // RDP_NEG_REQ (TLS | CredSSP)
]);

function probeRdp(host, port, timeoutMs = 2500) {
  return new Promise((resolve) => {
    let done = false;
    const sock = net.connect({ host, port });
    const finish = (v) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.destroy(); } catch (e) { /* ignore */ }
      resolve(v);
    };
    const timer = setTimeout(() => finish(false), timeoutMs);
    sock.on('connect', () => sock.write(X224_CONNECTION_REQUEST));
    sock.on('data', (d) => finish(d.length >= 4 && d[0] === 0x03 && d[1] === 0x00));
    sock.on('error', () => finish(false));
    sock.on('close', () => finish(false));
  });
}

function isPortFree(port, host = '0.0.0.0') {
  return new Promise((resolve) => {
    const t = net.createServer();
    t.once('error', () => resolve(false));
    t.once('listening', () => t.close(() => resolve(true)));
    t.listen(port, host);
  });
}

// A restarting VM's previous QEMU may still hold the port for a moment.
async function waitPortFree(port, maxMs = 5000) {
  const end = Date.now() + maxMs;
  for (;;) {
    if (await isPortFree(port)) return true;
    if (Date.now() >= end) return false;
    await new Promise((r) => setTimeout(r, 250));
  }
}

// ---------------------------------------------------------------------
// QEMU monitor (HMP over a unix socket) - hot add/remove of the host
// forward on a running VM without a reboot.
// ---------------------------------------------------------------------
function hmpCommand(sockPath, command, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(sockPath);
    let buf = '', done = false;
    const finish = (err, val) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.destroy(); } catch (e) { /* ignore */ }
      err ? reject(err) : resolve(val);
    };
    const timer = setTimeout(() => finish(null, buf), timeoutMs);
    sock.on('connect', () => sock.write(command + '\n'));
    sock.on('data', (d) => {
      buf += d.toString();
      // banner prompt + the prompt after the command's output
      if ((buf.match(/\(qemu\)/g) || []).length >= 2) setTimeout(() => finish(null, buf), 100);
    });
    sock.on('error', (e) => {
      const err = new Error(e.code === 'ENOENT' || e.code === 'ECONNREFUSED'
        ? 'QEMU monitor socket is not available (this VM was started before RDP support was added)'
        : 'QEMU monitor error: ' + e.message);
      err.code = 'NO_MONITOR';
      finish(err);
    });
  });
}

function hmpFailed(output) {
  return /could not|invalid|error|unknown command|failed|cannot/i.test(
    String(output).replace(/\(qemu\)/g, '').replace(/QEMU [\d.]+ monitor.*/i, '')
  );
}

// Current user-mode host forwards, parsed from `info usernet`.
async function listForwards(sockPath) {
  const out = await hmpCommand(sockPath, 'info usernet');
  const res = [];
  const re = /TCP\[HOST_FORWARD\]\s+\d+\s+\S+\s+(\d+)\s+\S+\s+(\d+)/g;
  let m;
  while ((m = re.exec(out)) !== null) res.push({ hostPort: parseInt(m[1], 10), guestPort: parseInt(m[2], 10) });
  return res;
}

// Safe by construction: never touches a forward that isn't ours. A host port
// already forwarded to guest:3389 is "already done"; one forwarded anywhere
// else (e.g. this VM's SSH forward) is refused rather than replaced.
async function hostfwdAdd(sockPath, hostPort, netdevId = 'n0') {
  const existing = (await listForwards(sockPath)).find((f) => f.hostPort === hostPort);
  if (existing) {
    if (existing.guestPort === RDP_GUEST_PORT) return true;
    const e = new Error(`Host port ${hostPort} is already forwarded to guest port ${existing.guestPort} on this VM`);
    e.code = 'HOSTFWD_FAILED';
    throw e;
  }
  const out = await hmpCommand(sockPath, `hostfwd_add ${netdevId} tcp::${hostPort}-:${RDP_GUEST_PORT}`);
  if (hmpFailed(out)) {
    const e = new Error(`QEMU rejected the port forward on host port ${hostPort} (is it in use?)`);
    e.code = 'HOSTFWD_FAILED';
    throw e;
  }
  return true;
}

// Only ever removes a forward that points at guest:3389.
async function hostfwdRemove(sockPath, hostPort, netdevId = 'n0') {
  const existing = (await listForwards(sockPath)).find((f) => f.hostPort === hostPort);
  if (!existing || existing.guestPort !== RDP_GUEST_PORT) return false;
  await hmpCommand(sockPath, `hostfwd_remove ${netdevId} tcp::${hostPort}`);
  return true;
}

// ---------------------------------------------------------------------
// Validation / hardening helpers
// ---------------------------------------------------------------------
const fs = require('fs');

function isIPv4(v) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(v || ''));
  return !!m && m.slice(1).every((o) => parseInt(o, 10) <= 255);
}

function cleanVmId(v) {
  const s = String(v == null ? '' : v);
  if (!/^\d{1,12}$/.test(s)) {
    const e = new Error('Invalid VM id');
    e.code = 'INVALID_VM_ID'; e.httpStatus = 400;
    throw e;
  }
  return s;
}

// QEMU creates the monitor socket a moment after spawn, with the process
// umask. The monitor is a full control channel for the VM, so lock it to the
// owner (retrying until QEMU has created it).
function secureSocket(sockPath, attempts = 40, delayMs = 250) {
  let n = 0;
  const tick = () => {
    try { fs.chmodSync(sockPath, 0o600); return; } catch (e) { /* not there yet */ }
    if (++n < attempts) setTimeout(tick, delayMs).unref();
  };
  tick();
}

module.exports = {
  isIPv4, cleanVmId, secureSocket,
  RDP_GUEST_PORT, buildProvisionScript, provisionGuest, probeRdp, isPortFree, waitPortFree,
  hostfwdAdd, hostfwdRemove, listForwards, hmpCommand, parseOsRelease, isDebianFamily,
  waitForGuestSsh, sshConnect
};
