// =====================================================================
// VNM — Node abstraction (panel side)
// ---------------------------------------------------------------------
// Everything the panel needs to know about "which node does this VM
// live on, and how do I talk to it":
//
//   - DB helpers for the `nodes` table (bootstrap the Local Node,
//     create/list/delete Remote nodes, resolve a VM to its node)
//   - Per-node auth tokens (generated once, shown once; the panel only
//     ever stores a hash - see README in node-agent/ for why)
//   - The agent WebSocket connection manager: Remote Node Agents dial
//     OUT to the panel (so a remote node behind NAT/a firewall with only
//     outbound connectivity still works, and the panel never needs to
//     know how to reach in to the agent's network). Once connected and
//     authenticated, the SAME socket carries:
//       - heartbeat / live stats (agent -> panel)
//       - commands + results (panel -> agent -> panel), for VM ops and
//         file-manager ops
//       - chunked binary relay for file upload/download
//
// The Local Node is just a DB row with mode='local' and no live
// connection at all - for a local VM, callers keep using the panel's
// existing direct code paths (QEMU spawn, direct SSH to the guest) and
// never call into the relay machinery here. See getNodeForVM().
// =====================================================================

const crypto = require('crypto');

const HEARTBEAT_STALE_MS = 45 * 1000;   // no heartbeat/message in this long -> mark offline
const COMMAND_TIMEOUT_MS = 20 * 1000;   // default timeout for a relayed JSON command
const TRANSFER_TIMEOUT_MS = 5 * 60 * 1000; // upload/download relay idle timeout

function genToken(nodeId) {
  return `vnm_agent_${nodeId}_${crypto.randomBytes(24).toString('hex')}`;
}
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
function parseNodeIdFromToken(token) {
  const m = /^vnm_agent_(\d+)_/.exec(token || '');
  return m ? parseInt(m[1], 10) : null;
}

module.exports = function createNodeManager({ db, logError }) {
  // nodeId -> { ws, lastSeen, pending: Map<requestId, {resolve, reject, timer}>, transfers: Map<requestId, handlers> }
  const connections = new Map();
  // nodeId -> Set<ws> of admin browser clients watching the Nodes page for live updates
  const watchers = new Map();

  function dbGet(sql, params) {
    return new Promise((resolve, reject) => db.get(sql, params, (err, row) => err ? reject(err) : resolve(row)));
  }
  function dbAll(sql, params) {
    return new Promise((resolve, reject) => db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows)));
  }
  function dbRun(sql, params) {
    return new Promise((resolve, reject) => db.run(sql, params, function (err) { err ? reject(err) : resolve(this); }));
  }

  // -----------------------------------------------------------------
  // Bootstrap + CRUD
  // -----------------------------------------------------------------
  async function ensureSchema() {
    await dbRun(`CREATE TABLE IF NOT EXISTS nodes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      mode TEXT NOT NULL CHECK(mode IN ('local','remote')),
      hostname TEXT,
      address TEXT,
      agent_port INTEGER,
      agent_token_hash TEXT,
      status TEXT DEFAULT 'offline',
      last_seen DATETIME,
      os TEXT,
      kernel TEXT,
      architecture TEXT,
      cpu TEXT,
      cpu_cores INTEGER,
      cpu_usage_percent REAL,
      ram_total INTEGER,
      ram_used INTEGER,
      disk_total INTEGER,
      disk_used INTEGER,
      kvm_available BOOLEAN DEFAULT 0,
      qemu_version TEXT,
      agent_version TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, []);

    // vms.node_id - additive, mirrors the existing missingColumns pattern
    await new Promise((resolve) => {
      db.run(`ALTER TABLE vms ADD COLUMN node_id INTEGER REFERENCES nodes(id)`, (err) => {
        if (!err) console.log('✓ Added column: node_id');
        resolve();
      });
    });

    // Node address bookkeeping (additive): manual_address is an admin-set
    // address (the FQDN/IP users should use to reach VMs on this node),
    // agent_addresses is what the agent reported its machine has, and
    // nodes.address holds the effective value (manual override wins, else
    // the socket address the agent dialed in from).
    await new Promise((resolve) => { db.run(`ALTER TABLE nodes ADD COLUMN manual_address TEXT`, () => resolve()); });
    await new Promise((resolve) => { db.run(`ALTER TABLE nodes ADD COLUMN agent_addresses TEXT`, () => resolve()); });

    let local = await dbGet(`SELECT * FROM nodes WHERE mode = 'local' LIMIT 1`, []);
    if (!local) {
      const r = await dbRun(
        `INSERT INTO nodes (name, mode, hostname, status) VALUES (?, 'local', ?, 'online')`,
        ['Local Node', require('os').hostname()]
      );
      local = await dbGet(`SELECT * FROM nodes WHERE id = ?`, [r.lastID]);
      console.log(`✓ Bootstrapped Local Node (id ${local.id})`);
    }

    await dbRun(`UPDATE vms SET node_id = ? WHERE node_id IS NULL`, [local.id]);

    // Keep the Local Node's own system info fresh on every boot (real
    // values - see system-info.js - never fabricated).
    try {
      const info = await require('./system-info').getSystemInfo(require('path').join(require('os').homedir(), 'vms'));
      await dbRun(
        `UPDATE nodes SET hostname=?, os=?, kernel=?, architecture=?, cpu=?, cpu_cores=?, cpu_usage_percent=?,
         ram_total=?, ram_used=?, disk_total=?, disk_used=?, kvm_available=?, qemu_version=?, status='online',
         last_seen=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
        [info.hostname, info.os, info.kernel, info.architecture, info.cpuModel, info.cpuCores, info.cpuUsagePercent,
         info.ramTotalBytes, info.ramUsedBytes, info.diskTotalBytes, info.diskUsedBytes, info.kvmAvailable ? 1 : 0,
         info.qemuVersion, local.id]
      );
    } catch (e) { console.warn('[Nodes] Could not refresh Local Node system info:', e.message); }

    return local;
  }

  async function listNodes() {
    const rows = await dbAll(`SELECT * FROM nodes ORDER BY (mode='local') DESC, id ASC`, []);
    return rows.map(sanitizeNode);
  }
  async function getNode(id) {
    const row = await dbGet(`SELECT * FROM nodes WHERE id = ?`, [id]);
    return row || null;
  }
  async function getNodeForVM(vm) {
    if (!vm.node_id) return dbGet(`SELECT * FROM nodes WHERE mode='local' LIMIT 1`, []);
    const node = await dbGet(`SELECT * FROM nodes WHERE id = ?`, [vm.node_id]);
    return node || dbGet(`SELECT * FROM nodes WHERE mode='local' LIMIT 1`, []);
  }
  function sanitizeNode(node) {
    if (!node) return node;
    const { agent_token_hash, ...safe } = node;
    safe.online = connections.has(node.id) || node.mode === 'local';
    return safe;
  }

  async function createRemoteNode({ name }) {
    const r = await dbRun(`INSERT INTO nodes (name, mode, status) VALUES (?, 'remote', 'pending')`, [name]);
    const token = genToken(r.lastID);
    await dbRun(`UPDATE nodes SET agent_token_hash = ? WHERE id = ?`, [hashToken(token), r.lastID]);
    const node = await getNode(r.lastID);
    return { node: sanitizeNode(node), token };
  }

  // Admin-set address override (FQDN or IP users should use to reach
  // VMs on this node). Setting it makes it the effective address;
  // clearing it (null/empty) falls back to the address the agent last
  // dialed in from (auto-detect).
  async function setNodeAddress(nodeId, address) {
    const node = await getNode(nodeId);
    if (!node) throw new Error('Node not found');
    if (address) {
      await dbRun(
        `UPDATE nodes SET manual_address=?, address=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
        [address, address, nodeId]
      );
    } else {
      const c = connections.get(Number(nodeId));
      const sockAddr = (c && c.remoteAddr) || null;
      await dbRun(
        `UPDATE nodes SET manual_address=NULL, address=COALESCE(?, address), updated_at=CURRENT_TIMESTAMP WHERE id=?`,
        [sockAddr, nodeId]
      );
    }
    return getNode(nodeId);
  }

  async function rotateToken(nodeId) {
    const node = await getNode(nodeId);
    if (!node || node.mode !== 'remote') throw new Error('Not a remote node');
    const token = genToken(nodeId);
    await dbRun(`UPDATE nodes SET agent_token_hash = ?, status='pending' WHERE id = ?`, [hashToken(token), nodeId]);
    disconnectNode(nodeId, 'Token rotated');
    return token;
  }

  // Verifies a bearer token against any node row (used by the
  // agent-package download route, which is hit from a fresh remote
  // server with no admin session - only a valid node token).
  async function verifyNodeToken(token) {
    const nodeId = parseNodeIdFromToken(token);
    if (!nodeId) return null;
    const node = await getNode(nodeId);
    if (!node || !node.agent_token_hash || hashToken(token) !== node.agent_token_hash) return null;
    return node;
  }

  async function deleteNode(nodeId) {
    const node = await getNode(nodeId);
    if (!node) throw new Error('Node not found');
    if (node.mode === 'local') throw new Error('Cannot delete the Local Node');
    const vmCount = await dbGet(`SELECT COUNT(*) as c FROM vms WHERE node_id = ?`, [nodeId]);
    if (vmCount && vmCount.c > 0) throw new Error(`Node still has ${vmCount.c} VM(s) assigned - reassign or remove them first`);
    disconnectNode(nodeId, 'Node deleted');
    await dbRun(`DELETE FROM nodes WHERE id = ?`, [nodeId]);
  }

  // -----------------------------------------------------------------
  // Agent connection lifecycle
  // -----------------------------------------------------------------
  function isNodeOnline(nodeId) {
    const c = connections.get(Number(nodeId));
    return !!(c && c.ws.readyState === c.ws.OPEN);
  }

  function broadcastNodeUpdate(node) {
    const payload = JSON.stringify({ type: 'node-update', node: sanitizeNode(node) });
    const set = watchers.get('*');
    if (!set) return;
    for (const ws of set) { if (ws.readyState === ws.OPEN) { try { ws.send(payload); } catch (e) {} } }
  }
  function watchNodes(ws) {
    if (!watchers.has('*')) watchers.set('*', new Set());
    watchers.get('*').add(ws);
    ws.on('close', () => { const s = watchers.get('*'); if (s) s.delete(ws); });
  }

  async function markOffline(nodeId, reason) {
    await dbRun(`UPDATE nodes SET status='offline', updated_at=CURRENT_TIMESTAMP WHERE id = ?`, [nodeId]);
    const node = await getNode(nodeId);
    console.log(`[Nodes] Node ${nodeId} offline${reason ? ' (' + reason + ')' : ''}`);
    broadcastNodeUpdate(node);
    return node;
  }

  function disconnectNode(nodeId, reason) {
    const c = connections.get(Number(nodeId));
    if (!c) return;
    if (c.staleTimer) { clearInterval(c.staleTimer); c.staleTimer = null; } // DEEP FIX: see disconnectAgentSocketOnly
    for (const [, p] of c.pending) { clearTimeout(p.timer); p.reject(new Error(reason || 'Node disconnected')); }
    for (const [, t] of c.transfers) { try { t.onAbort && t.onAbort(reason); } catch (e) {} }
    try { c.ws.close(); } catch (e) {}
    connections.delete(Number(nodeId));
    markOffline(nodeId, reason).catch(() => {});
  }

  async function handleAgentConnection(ws, req) {
    const remoteAddr = req.socket && req.socket.remoteAddress;
    console.log(`[Nodes] Incoming agent connection from ${remoteAddr || 'unknown'}`);
    const url = new URL(req.url, 'http://internal');
    const token = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('token') || '';
    const nodeId = parseNodeIdFromToken(token);
    if (!nodeId) { ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' })); return ws.close(); }

    const node = await getNode(nodeId).catch(() => null);
    if (!node || node.mode !== 'remote') { ws.send(JSON.stringify({ type: 'error', message: 'Unknown node' })); return ws.close(); }
    if (!node.agent_token_hash || hashToken(token) !== node.agent_token_hash) {
      console.warn(`[Nodes] Agent auth failed for node ${nodeId}`);
      ws.send(JSON.stringify({ type: 'error', message: 'Authentication failed' }));
      return ws.close();
    }

    // Replace any previous connection for this node (agent reconnected).
    disconnectAgentSocketOnly(nodeId);

    const entry = { ws, lastSeen: Date.now(), pending: new Map(), transfers: new Map(), remoteAddr: null };
    connections.set(nodeId, entry);
    // Remember where this agent dialed in from (its address as the panel
    // sees it) - that's where VMs on this node are SSH-reachable from the
    // outside, unless the admin set a manual override (manual wins).
    const seenAddr = String(remoteAddr || '').replace(/^::ffff:/, '') || null;
    entry.remoteAddr = seenAddr;
    // DEEP FIX (wedged node): this UPDATE previously had no guard - if it
    // rejected, handleAgentConnection aborted AFTER the entry was already
    // in the connections map but BEFORE the message listener was attached,
    // leaving an "online" node that never answers any command.
    try {
      await dbRun(`UPDATE nodes SET status='online', last_seen=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP,
                   address=COALESCE(manual_address, ?, address) WHERE id = ?`, [seenAddr, nodeId]);
    } catch (dbErr) {
      console.error('[Nodes] Failed to mark node online - dropping agent connection:', dbErr.message);
      disconnectAgentSocketOnly(nodeId);
      try { ws.close(); } catch (e) {}
      return;
    }
    console.log(`[Nodes] Agent connected for node ${nodeId} (${node.name})`);
    getNode(nodeId).then(broadcastNodeUpdate).catch(() => {});
    ws.send(JSON.stringify({ type: 'connected', nodeId }));

    const staleTimer = setInterval(() => {
      if (Date.now() - entry.lastSeen > HEARTBEAT_STALE_MS) {
        console.warn(`[Nodes] Node ${nodeId} heartbeat stale - marking offline`);
        clearInterval(staleTimer);
        disconnectNode(nodeId, 'Heartbeat timeout');
      }
    }, 10 * 1000);
    staleTimer.unref();
    entry.staleTimer = staleTimer; // DEEP FIX: cleared on replacement/disconnect below

    ws.on('message', async (data, isBinary) => {
      entry.lastSeen = Date.now();
      if (isBinary) return handleTransferChunk(entry, data);
      let msg;
      try { msg = JSON.parse(data.toString()); } catch (e) { return; }

      if (msg.type === 'heartbeat') {
        const s = msg.stats || {};
        const agentAddrs = Array.isArray(s.addresses) ? JSON.stringify(s.addresses) : null;
        await dbRun(
          `UPDATE nodes SET status='online', last_seen=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP,
           cpu_usage_percent=?, ram_total=?, ram_used=?, disk_total=?, disk_used=?,
           os=COALESCE(?,os), kernel=COALESCE(?,kernel), architecture=COALESCE(?,architecture),
           cpu=COALESCE(?,cpu), cpu_cores=COALESCE(?,cpu_cores), kvm_available=COALESCE(?,kvm_available),
           qemu_version=COALESCE(?,qemu_version), agent_version=COALESCE(?,agent_version),
           agent_addresses=COALESCE(?,agent_addresses)
           WHERE id = ?`,
          [s.cpuUsagePercent ?? null, s.ramTotalBytes ?? null, s.ramUsedBytes ?? null, s.diskTotalBytes ?? null, s.diskUsedBytes ?? null,
           s.os ?? null, s.kernel ?? null, s.architecture ?? null, s.cpuModel ?? null, s.cpuCores ?? null,
           (s.kvmAvailable === undefined ? null : (s.kvmAvailable ? 1 : 0)), s.qemuVersion ?? null, msg.agentVersion ?? null,
           agentAddrs, nodeId]
        ).catch((e) => console.warn('[Nodes] heartbeat update failed:', e.message));
        getNode(nodeId).then(broadcastNodeUpdate).catch(() => {});
        return;
      }

      if (msg.type === 'command-result' || msg.type === 'command-error') {
        const p = entry.pending.get(msg.requestId);
        if (!p) return;
        clearTimeout(p.timer);
        entry.pending.delete(msg.requestId);
        if (msg.type === 'command-error') p.reject(Object.assign(new Error(msg.error || 'Agent command failed'), { httpStatus: msg.httpStatus, code: msg.code }));
        else p.resolve(msg.result);
        return;
      }

      if (msg.type === 'transfer-ready' || msg.type === 'transfer-error' || msg.type === 'transfer-done' || msg.type === 'transfer-progress') {
        const t = entry.transfers.get(msg.requestId);
        if (t && t.onControl) t.onControl(msg);
        return;
      }

      if (msg.type === 'log') {
        console.log(`[Agent-${nodeId}] ${msg.message}`);
      }
    });

    ws.on('close', () => {
      clearInterval(staleTimer);
      connections.delete(nodeId);
      markOffline(nodeId, 'Connection closed').catch(() => {});
    });
    ws.on('error', (e) => console.warn(`[Nodes] Agent ${nodeId} socket error:`, e.message));  }

  function disconnectAgentSocketOnly(nodeId) {
    const c = connections.get(nodeId);
    if (!c) return;
    // DEEP FIX (reconnect bug): removeAllListeners() also removed the
    // 'close' handler that cleared this entry's stale-heartbeat timer, so
    // the orphaned interval fired ~45s later and disconnected the NEW agent
    // connection that had just replaced this one.
    if (c.staleTimer) { clearInterval(c.staleTimer); c.staleTimer = null; }
    try { c.ws.removeAllListeners(); c.ws.close(); } catch (e) {}
    connections.delete(nodeId);
  }

  function handleTransferChunk(entry, data) {
    // Binary frame framing: 8-byte ASCII requestId prefix + raw payload.
    const requestId = data.slice(0, 8).toString('utf8').trim();
    const payload = data.slice(8);
    const t = entry.transfers.get(requestId);
    if (t && t.onChunk) t.onChunk(payload);
  }

  function frameRequestId(requestId) {
    return requestId.padEnd(8, ' ').slice(0, 8);
  }

  // -----------------------------------------------------------------
  // Command relay (JSON request/response over the agent's socket)
  // -----------------------------------------------------------------
  function sendNodeCommand(nodeId, action, payload, opts) {
    opts = opts || {};
    const entry = connections.get(Number(nodeId));
    if (!entry || entry.ws.readyState !== entry.ws.OPEN) {
      const e = new Error('Node is offline'); e.httpStatus = 409; e.code = 'NODE_OFFLINE';
      return Promise.reject(e);
    }
    const requestId = crypto.randomBytes(8).toString('hex');
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        entry.pending.delete(requestId);
        const e = new Error('Node command timed out'); e.httpStatus = 504; e.code = 'TIMEOUT';
        reject(e);
      }, opts.timeoutMs || COMMAND_TIMEOUT_MS);
      entry.pending.set(requestId, { resolve, reject, timer });
      try {
        entry.ws.send(JSON.stringify({ type: 'command', requestId, action, payload }));
      } catch (e) {
        clearTimeout(timer);
        entry.pending.delete(requestId);
        reject(e);
      }
    });
  }

  // Relay a browser upload (readable stream of chunks) to the agent,
  // which writes it into the guest VM's filesystem over its own SFTP
  // session. Resolves when the agent confirms the write is complete.
  function relayUpload(nodeId, { vmConn, targetDir, filename, maxBytes }, sourceStream) {
    const entry = connections.get(Number(nodeId));
    if (!entry || entry.ws.readyState !== entry.ws.OPEN) {
      const e = new Error('Node is offline'); e.httpStatus = 409; e.code = 'NODE_OFFLINE';
      return Promise.reject(e);
    }
    const requestId = crypto.randomBytes(8).toString('hex').slice(0, 8);
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (err, result) => {
        if (settled) return; settled = true;
        clearTimeout(idleTimer);
        entry.transfers.delete(requestId);
        sourceStream.removeAllListeners();
        err ? reject(err) : resolve(result);
      };
      const idleTimer = setTimeout(() => finish(Object.assign(new Error('Upload relay timed out'), { httpStatus: 504 })), TRANSFER_TIMEOUT_MS);

      entry.transfers.set(requestId, {
        onControl: (msg) => {
          // DEEP FIX: the 5-minute timer was a hard TOTAL cap - a 4 GB
          // upload over WAN easily exceeds it while actively transferring.
          // Refresh on every control frame so it only fires on true
          // inactivity.
          idleTimer.refresh();
          if (msg.type === 'transfer-error') return finish(Object.assign(new Error(msg.error || 'Upload failed'), { httpStatus: msg.httpStatus || 500, code: msg.code }));
          if (msg.type === 'transfer-done') return finish(null, msg.result);
        },
        onAbort: (reason) => finish(new Error(reason || 'Node disconnected'))
      });

      entry.ws.send(JSON.stringify({ type: 'upload-start', requestId, vmConn, targetDir, filename, maxBytes }));
      sourceStream.on('data', (chunk) => {
        try { entry.ws.send(Buffer.concat([Buffer.from(frameRequestId(requestId)), chunk])); }
        catch (e) { finish(e); }
      });
      sourceStream.on('end', () => {
        try { entry.ws.send(JSON.stringify({ type: 'upload-end', requestId })); } catch (e) { finish(e); }
      });
      sourceStream.on('error', (e) => {
        try { entry.ws.send(JSON.stringify({ type: 'upload-abort', requestId })); } catch (e2) {}
        finish(e);
      });
    });
  }


  // Copy a stopped VM's qcow2 to a remote node's own VM directory.
  // Streams with a bounded in-flight window (agent acks bytes once
  // they're flushed to its disk; we pause reading the source while too
  // many are un-acked, and also honor the socket's own buffer), computes
  // SHA-256 while sending, and lets the agent verify + atomically rename.
  // onProgress(bytesAcked) is called as the agent confirms writes.
  function relayDiskUpload(nodeId, { vmId, totalBytes }, sourceStream, onProgress) {
    const entry = connections.get(Number(nodeId));
    if (!entry || entry.ws.readyState !== entry.ws.OPEN) {
      const e = new Error('Node is offline'); e.httpStatus = 409; e.code = 'NODE_OFFLINE';
      return Promise.reject(e);
    }
    const WINDOW = 32 * 1024 * 1024;        // max un-acked bytes in flight
    const SOCKET_HIGH_WATER = 8 * 1024 * 1024;
    const requestId = crypto.randomBytes(8).toString('hex').slice(0, 8);
    return new Promise((resolve, reject) => {
      let settled = false, sent = 0, acked = 0, paused = false, started = false;
      const hash = crypto.createHash('sha256');
      const finish = (err, result) => {
        if (settled) return; settled = true;
        clearTimeout(idleTimer); clearInterval(drainTimer);
        entry.transfers.delete(requestId);
        sourceStream.removeAllListeners('data'); sourceStream.removeAllListeners('end'); sourceStream.removeAllListeners('error');
        if (err) { try { sourceStream.destroy(); } catch (e) {} }
        err ? reject(err) : resolve(result);
      };
      let idleTimer;
      const bump = () => { clearTimeout(idleTimer); idleTimer = setTimeout(() => finish(Object.assign(new Error('Disk transfer stalled (no progress from node for 2 minutes)'), { httpStatus: 504 })), 2 * 60 * 1000); };
      bump();
      const maybeResume = () => {
        if (paused && (sent - acked) < WINDOW / 2 && entry.ws.bufferedAmount < SOCKET_HIGH_WATER / 2) { paused = false; sourceStream.resume(); }
      };
      const drainTimer = setInterval(maybeResume, 100);

      entry.transfers.set(requestId, {
        onControl: (msg) => {
          bump();
          if (msg.type === 'transfer-error') return finish(Object.assign(new Error(msg.error || 'Disk transfer failed'), { httpStatus: msg.httpStatus || 500, code: msg.code }));
          if (msg.type === 'transfer-done') return finish(null, msg.result);
          if (msg.type === 'transfer-progress') { acked = msg.bytes; if (onProgress) onProgress(acked); maybeResume(); }
          if (msg.type === 'transfer-ready' && !started) { started = true; startSending(); }
        },
        onAbort: (reason) => finish(new Error(reason || 'Node disconnected during disk transfer'))
      });

      entry.ws.send(JSON.stringify({ type: 'disk-upload-start', requestId, vmId, totalBytes }));

      function startSending() {
        sourceStream.on('data', (chunk) => {
          try {
            hash.update(chunk);
            entry.ws.send(Buffer.concat([Buffer.from(frameRequestId(requestId)), chunk]));
            sent += chunk.length;
            if ((sent - acked) >= WINDOW || entry.ws.bufferedAmount >= SOCKET_HIGH_WATER) { paused = true; sourceStream.pause(); }
          } catch (e) { finish(e); }
        });
        sourceStream.on('end', () => {
          try { entry.ws.send(JSON.stringify({ type: 'disk-upload-end', requestId, sha256: hash.digest('hex') })); }
          catch (e) { finish(e); }
        });
        sourceStream.on('error', (e) => {
          try { entry.ws.send(JSON.stringify({ type: 'disk-upload-abort', requestId })); } catch (e2) {}
          finish(e);
        });
      }
    });
  }

  // Stream an arbitrary file (a custom template or install ISO that only
  // exists on the panel's filesystem) into the node's own templates dir.
  // Same verified, flow-controlled transfer as relayDiskUpload above, but
  // the destination is TEMPLATES_DIR/<name> on the node; vm.provision
  // then picks it up via template.streamedName / isoStreamed.
  function relayNodeFileUpload(nodeId, { name, totalBytes }, sourceStream, onProgress) {
    const entry = connections.get(Number(nodeId));
    if (!entry || entry.ws.readyState !== entry.ws.OPEN) {
      const e = new Error('Node is offline'); e.httpStatus = 409; e.code = 'NODE_OFFLINE';
      return Promise.reject(e);
    }
    const WINDOW = 32 * 1024 * 1024;
    const SOCKET_HIGH_WATER = 8 * 1024 * 1024;
    const requestId = crypto.randomBytes(8).toString('hex').slice(0, 8);
    return new Promise((resolve, reject) => {
      let settled = false, sent = 0, acked = 0, paused = false, started = false;
      const hash = crypto.createHash('sha256');
      const finish = (err, result) => {
        if (settled) return; settled = true;
        clearTimeout(idleTimer); clearInterval(drainTimer);
        entry.transfers.delete(requestId);
        sourceStream.removeAllListeners('data'); sourceStream.removeAllListeners('end'); sourceStream.removeAllListeners('error');
        if (err) { try { sourceStream.destroy(); } catch (e) {} }
        err ? reject(err) : resolve(result);
      };
      let idleTimer;
      const bump = () => { clearTimeout(idleTimer); idleTimer = setTimeout(() => finish(Object.assign(new Error('File transfer stalled (no progress from node for 2 minutes)'), { httpStatus: 504 })), 2 * 60 * 1000); };
      bump();
      const maybeResume = () => {
        if (paused && (sent - acked) < WINDOW / 2 && entry.ws.bufferedAmount < SOCKET_HIGH_WATER / 2) { paused = false; sourceStream.resume(); }
      };
      const drainTimer = setInterval(maybeResume, 100);

      entry.transfers.set(requestId, {
        onControl: (msg) => {
          bump();
          if (msg.type === 'transfer-error') return finish(Object.assign(new Error(msg.error || 'File transfer failed'), { httpStatus: msg.httpStatus || 500, code: msg.code }));
          if (msg.type === 'transfer-done') return finish(null, msg.result);
          if (msg.type === 'transfer-progress') { acked = msg.bytes; if (onProgress) onProgress(acked); maybeResume(); }
          if (msg.type === 'transfer-ready' && !started) { started = true; startSending(); }
        },
        onAbort: (reason) => finish(new Error(reason || 'Node disconnected during file transfer'))
      });

      entry.ws.send(JSON.stringify({ type: 'file-upload-start', requestId, name, totalBytes }));

      function startSending() {
        sourceStream.on('data', (chunk) => {
          try {
            hash.update(chunk);
            entry.ws.send(Buffer.concat([Buffer.from(frameRequestId(requestId)), chunk]));
            sent += chunk.length;
            if ((sent - acked) >= WINDOW || entry.ws.bufferedAmount >= SOCKET_HIGH_WATER) { paused = true; sourceStream.pause(); }
          } catch (e) { finish(e); }
        });
        sourceStream.on('end', () => {
          try { entry.ws.send(JSON.stringify({ type: 'file-upload-end', requestId, sha256: hash.digest('hex') })); }
          catch (e) { finish(e); }
        });
        sourceStream.on('error', (e) => {
          try { entry.ws.send(JSON.stringify({ type: 'file-upload-abort', requestId })); } catch (e2) {}
          finish(e);
        });
      }
    });
  }

  // Pull a file that lives on a NODE's own filesystem (a VM disk during
  // migration, or a node-held backup) back to the panel. Mirrors the
  // disk-upload protocol in reverse: we send 'file-pull-start', the agent
  // streams binary frames with the same 8-byte requestId prefix plus
  // transfer-done/transfer-error control frames. The agent restricts
  // pullable paths to its own VM/backup directories, so this relay can
  // never read arbitrary files off a node. onProgress(bytes) fires about
  // once per 4 MB for task progress bars.
  function relayNodeFilePull(nodeId, { path: remotePath, expectedBytes }, { onData, onProgress } = {}) {
    const entry = connections.get(Number(nodeId));
    if (!entry || entry.ws.readyState !== entry.ws.OPEN) {
      const e = new Error('Node is offline'); e.httpStatus = 409; e.code = 'NODE_OFFLINE';
      return Promise.reject(e);
    }
    const requestId = crypto.randomBytes(8).toString('hex').slice(0, 8);
    return new Promise((resolve, reject) => {
      let settled = false, bytes = 0, lastProgress = 0;
      const finish = (err, result) => {
        if (settled) return; settled = true;
        clearTimeout(idleTimer);
        entry.transfers.delete(requestId);
        err ? reject(err) : resolve(result);
      };
      let idleTimer = setTimeout(() => finish(Object.assign(new Error('File pull stalled (no data from node for 2 minutes)'), { httpStatus: 504 })), 2 * 60 * 1000);
      const bump = () => {
        clearTimeout(idleTimer);
        idleTimer = setTimeout(() => finish(Object.assign(new Error('File pull stalled (no data from node for 2 minutes)'), { httpStatus: 504 })), 2 * 60 * 1000);
      };
      entry.transfers.set(requestId, {
        onControl: (msg) => {
          bump();
          if (msg.type === 'transfer-error') return finish(Object.assign(new Error(msg.error || 'File pull failed'), { httpStatus: msg.httpStatus || 500, code: msg.code }));
          if (msg.type === 'transfer-done') return finish(null, msg.result);
        },
        onChunk: (buf) => {
          bump();
          bytes += buf.length;
          if (onData) { try { onData(buf); } catch (e) { finish(e); } }
          if (onProgress && bytes - lastProgress >= 4 * 1024 * 1024) { lastProgress = bytes; onProgress(bytes); }
        },
        onAbort: (reason) => finish(new Error(reason || 'Node disconnected during file pull'))
      });
      entry.ws.send(JSON.stringify({ type: 'file-pull-start', requestId, path: remotePath, expectedBytes: expectedBytes || null }));
    });
  }

  // Relay a guest file download from the agent back through the panel.
  // `onChunk(buffer)` is called for each piece as it arrives; resolves
  // with { size } once the agent signals completion.
  function relayDownload(nodeId, { vmConn, path: remotePath }, onChunk) {
    const entry = connections.get(Number(nodeId));
    if (!entry || entry.ws.readyState !== entry.ws.OPEN) {
      const e = new Error('Node is offline'); e.httpStatus = 409; e.code = 'NODE_OFFLINE';
      return Promise.reject(e);
    }
    const requestId = crypto.randomBytes(8).toString('hex').slice(0, 8);
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (err, result) => {
        if (settled) return; settled = true;
        clearTimeout(idleTimer);
        entry.transfers.delete(requestId);
        err ? reject(err) : resolve(result);
      };
      const idleTimer = setTimeout(() => finish(Object.assign(new Error('Download relay timed out'), { httpStatus: 504 })), TRANSFER_TIMEOUT_MS);

      entry.transfers.set(requestId, {
        onControl: (msg) => {
          idleTimer.refresh(); // DEEP FIX: idle timeout, not a total cap
          if (msg.type === 'transfer-error') return finish(Object.assign(new Error(msg.error || 'Download failed'), { httpStatus: msg.httpStatus || 500, code: msg.code }));
          if (msg.type === 'transfer-done') return finish(null, msg.result);
        },
        onChunk: (buf) => { idleTimer.refresh(); onChunk(buf); },
        onAbort: (reason) => finish(new Error(reason || 'Node disconnected'))
      });

      entry.ws.send(JSON.stringify({ type: 'download-start', requestId, vmConn, path: remotePath }));
    });
  }

  // Relay a plain TCP connection to a localhost port ON THE NODE (used by
  // the SSH web terminal: the panel's ssh2 client speaks SSH over this
  // pipe, so the browser gets a real terminal into the VM's forwarded SSH
  // port even when the node is behind NAT). Same binary framing as the
  // noVNC relay below, kept open for the life of the viewer connection.
  function relayTcpOpen(nodeId, { host, port }, { onData, onReady, onClose }) {
    const entry = connections.get(Number(nodeId));
    if (!entry || entry.ws.readyState !== entry.ws.OPEN) {
      const e = new Error('Node is offline'); e.httpStatus = 409; e.code = 'NODE_OFFLINE';
      throw e;
    }
    const requestId = crypto.randomBytes(8).toString('hex').slice(0, 8);
    let closed = false;
    entry.transfers.set(requestId, {
      onControl: (msg) => {
        if (msg.type === 'transfer-ready') return onReady && onReady();
        if (msg.type === 'transfer-error') { closed = true; entry.transfers.delete(requestId); return onClose && onClose(msg.error); }
        if (msg.type === 'transfer-done') { closed = true; entry.transfers.delete(requestId); return onClose && onClose(null); }
      },
      onChunk: (buf) => onData && onData(buf),
      onAbort: (reason) => { if (!closed) { closed = true; onClose && onClose(reason || 'Node disconnected'); } }
    });
    entry.ws.send(JSON.stringify({ type: 'tcp-open', requestId, host: host || '127.0.0.1', port }));
    return {
      write: (buf) => { if (!closed) try { entry.ws.send(Buffer.concat([Buffer.from(frameRequestId(requestId)), buf])); } catch (e) {} },
      close: () => {
        if (closed) return;
        closed = true;
        entry.transfers.delete(requestId);
        try { entry.ws.send(JSON.stringify({ type: 'tcp-close', requestId })); } catch (e) {}
      }
    };
  }

  // Relay a noVNC WebSocket session to the agent, which opens a raw TCP
  // socket to the VM's local VNC port and pipes bytes both ways using the
  // same binary framing as upload/download, but bidirectional and kept
  // open for the life of the viewer's connection (not one-shot).
  // Returns { write(buf), close() }; onData/onReady/onClose are called as
  // the underlying agent-side TCP socket reports them.
  function relayVncOpen(nodeId, { vm }, { onData, onReady, onClose }) {
    const entry = connections.get(Number(nodeId));
    if (!entry || entry.ws.readyState !== entry.ws.OPEN) {
      const e = new Error('Node is offline'); e.httpStatus = 409; e.code = 'NODE_OFFLINE';
      throw e;
    }
    const requestId = crypto.randomBytes(8).toString('hex').slice(0, 8);
    let closed = false;
    entry.transfers.set(requestId, {
      onControl: (msg) => {
        if (msg.type === 'transfer-ready') return onReady && onReady();
        if (msg.type === 'transfer-error') { closed = true; entry.transfers.delete(requestId); return onClose && onClose(msg.error); }
        if (msg.type === 'transfer-done') { closed = true; entry.transfers.delete(requestId); return onClose && onClose(null); }
      },
      onChunk: (buf) => onData && onData(buf),
      onAbort: (reason) => { if (!closed) { closed = true; onClose && onClose(reason || 'Node disconnected'); } }
    });
    entry.ws.send(JSON.stringify({ type: 'vnc-open', requestId, vm }));
    return {
      write: (buf) => { if (!closed) try { entry.ws.send(Buffer.concat([Buffer.from(frameRequestId(requestId)), buf])); } catch (e) {} },
      close: () => {
        if (closed) return;
        closed = true;
        entry.transfers.delete(requestId);
        try { entry.ws.send(JSON.stringify({ type: 'vnc-close', requestId })); } catch (e) {}
      }
    };
  }

  return {
    ensureSchema, listNodes, getNode, getNodeForVM, sanitizeNode,
    createRemoteNode, rotateToken, deleteNode, verifyNodeToken, setNodeAddress,
    isNodeOnline, handleAgentConnection, watchNodes,
    sendNodeCommand, relayUpload, relayDownload, relayDiskUpload, relayVncOpen,
    relayTcpOpen, relayNodeFileUpload, relayNodeFilePull
  };
};
