// =====================================================================
// VNM — RDP over the VM's built-in serial console (v2.4.0)
// ---------------------------------------------------------------------
// The user's requirement: "RDP enable should use the inbuilt console of
// the VM, not sshd, and log in with the VM password" — sshd is often
// absent or unreachable on local-node VMs, but every VM this panel
// launches has `-serial mon:stdio`, i.e. a real serial console wired to
// the QEMU process stdin/stdout. This module drives that console:
//
//   1. wake the login prompt (getty on ttyS0)
//   2. log in with the VM's username + password
//   3. upload the xrdp provision script as base64 chunks (serial-safe)
//   4. run it and watch the serial log for VNM_RDP progress markers
//
// Local VMs: writes go to the panel's own qemuStdins map and the tail
// comes from <VM_DIR>/vm-<id>.log (same file the console page shows).
// Remote nodes: the identical operations ride the agent's
// vm.consoleWrite / vm.consoleTail / vm.consoleStatus actions.
//
// rdp.js uses this FIRST and falls back to the classic SSH path when the
// console isn't usable (e.g. a guest image without a serial getty).
// =====================================================================

const fs = require('fs');
const path = require('path');

// How long we wait for the login prompt to appear after poking the
// console. A TCG (no-KVM) first boot can take many minutes before getty
// is up, so this is generous — the caller passes its own budget.
const DEFAULT_LOGIN_WAIT_MS = 10 * 60 * 1000;
const PROMPT_WAIT_MS = 45 * 1000;
const SCRIPT_TIMEOUT_MS = 20 * 60 * 1000;
const TAIL_LINES = 120;
const CHUNK_CHARS = 400; // per `echo ... >> file` line; serial line discipline limit is 4096, stay well under
const CHUNK_PAUSE_MS = 120; // let the guest's tty consume the bytes

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

class SerialError extends Error {
  constructor(message, code) { super(message); this.code = code; }
}

module.exports = function createRdpSerial({ VM_DIR, qemuStdins, nodeManager }) {

  const isRemote = (node) => !!(node && node.mode === 'remote');

  // ---- transport: local stdin / remote agent action ------------------
  function writeLocal(vmId, data) {
    const stdin = qemuStdins.get(String(vmId));
    if (!stdin || stdin.destroyed) throw new SerialError('The VM has no serial console attached (is it running?)', 'SERIAL_UNAVAILABLE');
    stdin.write(data);
  }
  function tailLocal(vmId) {
    const logFile = path.join(VM_DIR, `vm-${vmId}.log`);
    if (!fs.existsSync(logFile)) return { lines: 0, text: '' };
    try {
      const text = fs.readFileSync(logFile, 'utf8');
      const arr = text.split('\n');
      return { lines: arr.length, text: arr.slice(-TAIL_LINES).join('\n') };
    } catch (e) { return { lines: 0, text: '' }; }
  }
  async function writeRemote(node, vmId, data) {
    await nodeManager.sendNodeCommand(node.id, 'vm.consoleWrite', { vm_id: String(vmId), data }, { timeoutMs: 15000 });
  }
  async function tailRemote(node, vmId) {
    return await nodeManager.sendNodeCommand(node.id, 'vm.consoleTail', { vm_id: String(vmId), lines: TAIL_LINES }, { timeoutMs: 15000 });
  }

  async function probeRemote(node, vmId) {
    try {
      const r = await nodeManager.sendNodeCommand(node.id, 'vm.consoleStatus', { vm_id: String(vmId) }, { timeoutMs: 10000 });
      return !!(r && r.connected);
    } catch (e) { return false; }
  }

  // Wait until `re` matches in the console tail. Every poll also gives
  // the caller a heartbeat so long boots stay visible in the UI.
  async function waitFor(node, vmId, re, { totalMs, onProgress, note }) {
    const deadline = Date.now() + totalMs;
    let lastAnnounce = 0;
    for (;;) {
      const t = isRemote(node) ? await tailRemote(node, vmId).catch(() => ({ lines: 0, text: '' })) : tailLocal(vmId);
      const m = t.text.match(re);
      if (m) return m;
      const now = Date.now();
      if (now > deadline) {
        throw new SerialError(`Timed out waiting for ${note} on the VM's serial console.`, 'SERIAL_LOGIN_TIMEOUT');
      }
      if (onProgress && now - lastAnnounce > 15000) {
        lastAnnounce = now;
        onProgress(`${note} — still waiting (the VM may still be booting)`);
      }
      await sleep(1500);
    }
  }

  // Log in on the serial console. Returns true; throws SerialError with
  // a friendly code on failure.
  async function serialLogin(node, vmId, { username, password, waitMs, onProgress }) {
    // Wake the console: a bare newline makes getty print the login prompt
    // (or reveal an already-logged-in shell).
    onProgress('Waking the VM serial console');
    const write = (d) => (isRemote(node) ? writeRemote(node, vmId, d) : (writeLocal(vmId, d), Promise.resolve()));
    await write('\n');

    // Some images print the prompt only after console activity; a couple
    // of pokes spaced out covers slow getty startup.
    let sawPrompt = null;
    for (let poke = 0; poke < 3 && !sawPrompt; poke++) {
      sawPrompt = await (async () => {
        try {
          return await waitFor(node, vmId, /login:\s*$/m, { totalMs: poke === 0 ? 30000 : 60000, onProgress, note: 'login prompt' });
        } catch (e) {
          if (e.code !== 'SERIAL_LOGIN_TIMEOUT') throw e;
          await write('\n');
          return null;
        }
      })();
    }
    if (!sawPrompt) {
      // One more patient round using the full boot budget — first boots
      // under software emulation are slow.
      try {
        sawPrompt = await waitFor(node, vmId, /login:\s*$/m, { totalMs: waitMs, onProgress, note: 'login prompt' });
      } catch (e) {
        throw new SerialError(
          'The VM never showed a login prompt on its serial console. This image may not run a console on ttyS0 — the setup will fall back to SSH.',
          'SERIAL_LOGIN_TIMEOUT'
        );
      }
    }

    onProgress(`Logging in as ${username} (VM password)`);
    await write(username + '\n');
    await waitFor(node, vmId, /[Pp]assword:\s*$/m, { totalMs: PROMPT_WAIT_MS, onProgress, note: 'password prompt' });
    await write(password + '\n');

    // Shell prompt or login failure — first match wins.
    const outcome = await Promise.race([
      waitFor(node, vmId, /Login incorrect|login:\s*$/m, { totalMs: PROMPT_WAIT_MS, onProgress, note: 'login result' }).then(() => 'bad'),
      waitFor(node, vmId, /[$#]\s*$|\$\s|root@[^\n]*[#:]/m, { totalMs: PROMPT_WAIT_MS, onProgress, note: 'shell prompt' }).then(() => 'ok'),
    ]).catch(() => 'timeout');
    if (outcome === 'bad') {
      throw new SerialError('The VM rejected the username/password on the serial console. Check the VM user and password.', 'GUEST_AUTH_FAILED');
    }
    if (outcome === 'timeout') {
      // Could be a shell with an unusual prompt. Send a marker command —
      // if it echoes back, we're in.
      await write('\n');
      await write('echo VNM_SERIAL_OK_$((41+1))\n');
      try {
        await waitFor(node, vmId, /VNM_SERIAL_OK_42/, { totalMs: 30000, onProgress, note: 'shell confirmation' });
      } catch (e) {
        throw new SerialError('Logged in but could not confirm a working shell on the serial console.', 'SERIAL_LOGIN_TIMEOUT');
      }
    }
    return true;
  }

  // Upload + run the provision script over the serial console.
  async function serialRunScript(node, vmId, script, { onProgress, timeoutMs }) {
    const write = (d) => (isRemote(node) ? writeRemote(node, vmId, d) : (writeLocal(vmId, d), Promise.resolve()));

    // Base64 sidesteps every quoting/escaping hazard a tty can throw at us.
    const b64 = Buffer.from(script, 'utf8').toString('base64');
    const chunks = [];
    for (let i = 0; i < b64.length; i += CHUNK_CHARS) chunks.push(b64.slice(i, i + CHUNK_CHARS));

    onProgress('Uploading setup script over the serial console');
    await write('rm -f /tmp/.vnmrdp.b64 /tmp/.vnmrdp.sh\n');
    for (let i = 0; i < chunks.length; i++) {
      await write(`echo -n '${chunks[i]}' >> /tmp/.vnmrdp.b64\n`);
      await sleep(CHUNK_PAUSE_MS);
      if (onProgress && (i % 20) === 0 && i > 0) onProgress(`Uploading setup script (${i}/${chunks.length} chunks)`);
    }
    await write('base64 -d /tmp/.vnmrdp.b64 > /tmp/.vnmrdp.sh && chmod 700 /tmp/.vnmrdp.sh && echo VNM_UPLOAD_OK_$((41+1))\n');
    try {
      await waitFor(node, vmId, /VNM_UPLOAD_OK_42/, { totalMs: 60000, onProgress, note: 'script upload confirmation' });
    } catch (e) {
      throw new SerialError('The uploaded script did not arrive intact over the serial console.', 'SERIAL_UPLOAD_FAILED');
    }

    onProgress('Installing xrdp inside the VM (this can take several minutes)');
    // bg + nohup-style: the tty must not stall the script (apt output is
    // huge); we only watch for the completion marker. exec >/dev/null
    // keeps the console readable while our markers still come through.
    await write('( bash /tmp/.vnmrdp.sh; echo "VNM_RDP_EXIT_$?" ) >/dev/null 2>&1 &\n');

    const deadline = Date.now() + (timeoutMs || SCRIPT_TIMEOUT_MS);
    let lastProgress = 0;
    for (;;) {
      const t = isRemote(node) ? await tailRemote(node, vmId).catch(() => ({ lines: 0, text: '' })) : tailLocal(vmId);
      const m = t.text.match(/VNM_RDP_EXIT_(\d+)/);
      if (m) {
        const code = parseInt(m[1], 10);
        if (code === 0) return;
        const os = (t.text.match(/VNM_RDP: OS: ([^\n]+)/) || [])[1] || 'unknown';
        const failMsg = {
          42: `Unsupported guest OS for RDP setup (${os}) — only Debian and Ubuntu are supported.`,
          50: 'apt failed inside the VM — check that the VM has internet access.',
          51: 'Installing xrdp failed inside the VM — check internet access and apt sources.',
          52: 'Installing the desktop environment failed inside the VM (out of disk or memory?).',
          53: 'xrdp was installed but is not listening on port 3389 inside the VM.',
          54: 'Something other than xrdp is using port 3389 inside the VM.',
        }[code] || `The setup script inside the VM exited with code ${code}.`;
        const e = new SerialError(failMsg, code === 42 ? 'UNSUPPORTED_OS' : 'GUEST_SETUP_FAILED');
        e.exitCode = code;
        throw e;
      }
      // surface VNM_RDP: progress lines to the UI
      const prog = t.text.match(/VNM_RDP: ([^\n]+)/g) || [];
      const latest = prog[prog.length - 1];
      const now = Date.now();
      if (onProgress && latest && now - lastProgress > 8000) { lastProgress = now; onProgress(latest.replace(/^VNM_RDP: /, '')); }
      if (now > deadline) {
        throw new SerialError('The RDP setup inside the VM did not finish in time (slow network or heavy emulation). Retry — the script is idempotent.', 'GUEST_TIMEOUT');
      }
      await sleep(3000);
    }
  }

  // ---- main entry: provision RDP through the serial console ----------
  async function serialProvision(vm, node, { onProgress = () => {}, log = () => {}, waitMs } = {}) {
    const vmId = String(vm.vm_id).replace(/[^0-9]/g, '');
    const username = vm.username || 'root';
    const password = vm.password;
    if (!password) {
      // No stored VM password → serial login impossible, caller falls back to SSH.
      throw new SerialError('No VM password on file — serial-console login needs it.', 'SERIAL_UNAVAILABLE');
    }

    // 0. Console attached at all?
    if (isRemote(node)) {
      const online = nodeManager.isNodeOnline ? nodeManager.isNodeOnline(node.id) : true;
      if (!online) throw new SerialError('Node is offline.', 'SERIAL_UNAVAILABLE');
      onProgress('Checking the serial console on the node');
      const ok = await probeRemote(node, vmId);
      if (!ok) throw new SerialError('The VM has no serial console attached on its node (is it running there?).', 'SERIAL_UNAVAILABLE');
    } else {
      const stdin = qemuStdins.get(String(vmId));
      if (!stdin || stdin.destroyed) {
        throw new SerialError('The VM has no serial console attached (is it running?).', 'SERIAL_UNAVAILABLE');
      }
    }

    log('info', 'serial_provision_start', { vmId, user: username });

    // 1. Log in with the VM credentials.
    await serialLogin(node, vmId, {
      username, password,
      waitMs: waitMs || DEFAULT_LOGIN_WAIT_MS,
      onProgress
    });

    // 2. Run the provisioner (same script the SSH path uses).
    const { buildProvisionScript } = require('./rdp-guest');
    const script = buildProvisionScript(username);
    await serialRunScript(node, vmId, script, { onProgress });

    // 3. Read back what the guest reported (OS / desktop) from the tail.
    const t = isRemote(node) ? await tailRemote(node, vmId).catch(() => ({ text: '' })) : tailLocal(vmId);
    const os = (t.text.match(/VNM_RDP: OS: ([^\n]+)/) || [])[1] || 'linux';
    const desktop = (t.text.match(/VNM_RDP: DONE desktop=([^\n]+)/) || [])[1] || 'xfce4-session';
    log('info', 'serial_provision_done', { vmId, os, desktop });
    onProgress('RDP setup finished inside the VM');
    return { os, desktop, via: 'serial' };
  }

  return { serialProvision, SerialError };
};
