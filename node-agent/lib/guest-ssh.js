// =====================================================================
// VNM Node Agent — guest SSH/SFTP session cache
// ---------------------------------------------------------------------
// Mirrors the panel's local file-manager session manager, but keyed by
// the connection identity the panel sends with each relayed request
// (this agent has no VM database of its own - the panel owns that).
// =====================================================================

const { Client } = require('ssh2');

const IDLE_MS = parseInt(process.env.AGENT_SFTP_IDLE_MS || String(10 * 60 * 1000), 10);
const CONNECT_TIMEOUT_MS = parseInt(process.env.AGENT_SSH_CONNECT_TIMEOUT_MS || '15000', 10);

const sessions = new Map(); // key -> { conn, sftp, ready, lastUsed }

function keyFor(vmConn) {
  return `${vmConn.host}:${vmConn.port}:${vmConn.username}`;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, s] of sessions.entries()) {
    if (now - s.lastUsed > IDLE_MS) {
      try { s.sftp && s.sftp.end(); } catch (e) {}
      try { s.conn.end(); } catch (e) {}
      sessions.delete(key);
    }
  }
}, 60 * 1000).unref();

function getSession(vmConn) {
  const key = keyFor(vmConn);
  const existing = sessions.get(key);
  if (existing) { existing.lastUsed = Date.now(); return existing.ready; }

  const conn = new Client();
  const entry = { conn, sftp: null, lastUsed: Date.now() };
  const ready = new Promise((resolve, reject) => {
    let settled = false;
    const fail = (err) => { if (settled) return; settled = true; sessions.delete(key); try { conn.end(); } catch (e) {} reject(err); };
    const timer = setTimeout(() => fail(Object.assign(new Error('Connection to the guest VM timed out'), { httpStatus: 504 })), CONNECT_TIMEOUT_MS);

    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        clearTimeout(timer);
        if (err) return fail(Object.assign(new Error('SFTP subsystem unavailable on this VM: ' + err.message), { httpStatus: 502 }));
        if (settled) { try { sftp.end(); } catch (e) {} return; }
        settled = true;
        entry.sftp = sftp;
        sftp.on('close', () => sessions.delete(key));
        resolve({ conn, sftp });
      });
    });
    conn.on('error', (err) => { clearTimeout(timer); fail(Object.assign(new Error('SSH connection failed: ' + err.message), { httpStatus: 502 })); });

    conn.connect({
      host: vmConn.host, port: vmConn.port, username: vmConn.username, password: vmConn.password,
      readyTimeout: CONNECT_TIMEOUT_MS,
      algorithms: { serverHostKey: ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519'] }
    });
  });
  entry.ready = ready;
  sessions.set(key, entry);
  ready.catch(() => {});
  return ready;
}

module.exports = { getSession };
