// =====================================================================
// VNM Panel — Live VPS File Manager
// ---------------------------------------------------------------------
// Self-contained module that talks to the *guest* VPS filesystem over
// SFTP (via the existing ssh2 dependency), reusing the panel's own
// authentication/session system and VM ownership rules. It never
// touches the host filesystem, the VNM database files, QEMU disk
// images, or any other host path — every operation is performed
// through an SFTP/SSH session opened to the selected guest VM, exactly
// like the existing SSH Terminal feature already does.
//
// Exports a factory: require('./filemanager')({ db, checkAuth, getSSHPort })
// -> { router, handleFileManagerWS, broadcastFsChange }
// =====================================================================

const path = require('path');
const { Client } = require('ssh2');
const express = require('express');
const Busboy = require('busboy');

// ---------------------------------------------------------------------
// Config (overridable via env, per spec section 12 - "configurable
// through environment/config")
// ---------------------------------------------------------------------
const MAX_UPLOAD_MB = parseInt(process.env.FM_MAX_UPLOAD_MB || '4096', 10); // 4GB default
const MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024;
const MAX_EDIT_FILE_MB = parseInt(process.env.FM_MAX_EDIT_MB || '8', 10); // text editor cap
const MAX_EDIT_FILE_BYTES = MAX_EDIT_FILE_MB * 1024 * 1024;
const SFTP_IDLE_MS = parseInt(process.env.FM_IDLE_MS || String(10 * 60 * 1000), 10); // 10 min
const CONNECT_TIMEOUT_MS = parseInt(process.env.FM_CONNECT_TIMEOUT_MS || '15000', 10);

// Binaries we allow the remote compress/extract helpers to invoke. This
// is a fixed allowlist — nothing derived from user input ever reaches
// the executable position of a shell command.
const ARCHIVE_FORMATS = {
  'zip': { ext: '.zip' },
  'tar': { ext: '.tar' },
  'tar.gz': { ext: '.tar.gz' },
  'tgz': { ext: '.tgz' }
};

// =====================================================================
// Path safety helpers
// =====================================================================

function pathError(message, status) {
  const err = new Error(message);
  err.httpStatus = status || 400;
  err.isFileManagerError = true;
  return err;
}

// Normalizes an arbitrary user-supplied path into a safe, absolute,
// traversal-free POSIX path scoped to the guest's own filesystem root.
// There is no "host boundary" to escape here (SFTP only ever sees the
// guest's own '/'), but we still collapse '.'/'..' defensively and
// reject anything that isn't a clean absolute path.
function normalizeRemotePath(raw) {
  if (raw === undefined || raw === null || raw === '') return '/';
  if (typeof raw !== 'string') throw pathError('Invalid path');
  if (raw.indexOf('\u0000') !== -1) throw pathError('Invalid path');
  let p = raw.startsWith('/') ? raw : '/' + raw;
  p = path.posix.normalize(p);
  if (!p.startsWith('/')) p = '/' + p;
  return p;
}

// Validates a bare file/folder NAME (not a path) — used for create,
// rename, and as archive member names, so a value like "../../etc/passwd"
// can never be smuggled in through a "name" field.
function assertSafeName(name, label) {
  if (typeof name !== 'string' || !name.trim()) {
    throw pathError(`${label || 'Name'} is required`);
  }
  const trimmed = name.trim();
  if (trimmed === '.' || trimmed === '..') {
    throw pathError(`Invalid ${label || 'name'}`);
  }
  if (trimmed.includes('/') || trimmed.includes('\\') || trimmed.indexOf('\u0000') !== -1) {
    throw pathError(`${label || 'Name'} cannot contain a path separator`);
  }
  return trimmed;
}

function joinRemotePath(dir, name) {
  const safeName = assertSafeName(name);
  const base = normalizeRemotePath(dir);
  const joined = base === '/' ? '/' + safeName : base + '/' + safeName;
  return normalizeRemotePath(joined);
}

// Single-quote a value for safe inclusion in a POSIX shell command
// executed on the *guest* (used only for the compress/extract helpers,
// where we must call an external archiver binary). Never used to build
// SFTP protocol paths — those go through the sftp API directly, not a
// shell, so they cannot be affected by shell metacharacters at all.
function shQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

// =====================================================================
// Session manager — one SSH connection (+ derived SFTP handle) per
// (vmId, userId) pair, reusing the exact same credential lookup the
// existing SSH Terminal / /api/ssh/connect flow already uses.
// =====================================================================

function createSessionManager({ getSSHPort }) {
  // key -> { conn, sftp, ready:Promise, lastUsed, vmId, userId }
  const sessions = new Map();

  function keyFor(vmId, userId) {
    return `${vmId}:${userId}`;
  }

  function resolveHost(vm) {
    // The connection is made from the panel server itself (not the
    // browser), so for NAT-mode guests the forwarded SSH port always
    // lives on the panel's own loopback interface.
    if (vm.network_type === 'nat') return '127.0.0.1';
    // Non-NAT (bridge/static) VMs are reached at their own real address.
    // NEVER silently fall back to 127.0.0.1 here - a VM with no address
    // configured yet would otherwise connect to whatever happens to be
    // listening on the panel host itself (or another VM's forwarded
    // port), showing the wrong machine's files with no indication
    // anything was wrong. Fail clearly instead.
    if (!vm.ipv4_address) {
      throw pathError('This VM has no IPv4 address configured yet, so its files can\'t be reached', 409);
    }
    return vm.ipv4_address;
  }

  function closeSession(key) {
    const s = sessions.get(key);
    if (!s) return;
    sessions.delete(key);
    try { if (s.sftp) s.sftp.end(); } catch (e) { /* ignore */ }
    try { s.conn.end(); } catch (e) { /* ignore */ }
  }

  function touch(key) {
    const s = sessions.get(key);
    if (s) s.lastUsed = Date.now();
  }

  // Periodic idle sweep so a forgotten browser tab doesn't hold an SSH
  // connection open to a guest forever.
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [key, s] of sessions.entries()) {
      if (now - s.lastUsed > SFTP_IDLE_MS) {
        console.log(`[FileManager] Closing idle SFTP session ${key}`);
        closeSession(key);
      }
    }
  }, 60 * 1000);
  sweep.unref();

  // Returns a Promise<{ conn, sftp }> for a VM+user, reusing an
  // in-flight or already-ready connection when one exists.
  function getSession(vm, userId) {
    const key = keyFor(vm.vm_id, userId);
    const existing = sessions.get(key);
    if (existing) {
      touch(key);
      return existing.ready;
    }

    const conn = new Client();
    const entry = { conn, sftp: null, lastUsed: Date.now(), vmId: vm.vm_id, userId };

    const ready = new Promise((resolve, reject) => {
      let settled = false;
      const fail = (err) => {
        if (settled) return;
        settled = true;
        sessions.delete(key);
        try { conn.end(); } catch (e) { /* ignore */ }
        reject(err);
      };

      const timer = setTimeout(() => {
        fail(pathError('Connection to the VPS timed out', 504));
      }, CONNECT_TIMEOUT_MS);

      conn.on('ready', () => {
        conn.sftp((err, sftp) => {
          clearTimeout(timer);
          if (err) return fail(pathError('SFTP subsystem unavailable on this VPS: ' + err.message, 502));
          if (settled) { try { sftp.end(); } catch (e) {} return; }
          settled = true;
          entry.sftp = sftp;
          sessions.set(key, entry);
          sftp.on('close', () => {
            console.log(`[FileManager] SFTP session ${key} closed`);
            sessions.delete(key);
          });
          resolve({ conn, sftp });
        });
      });

      conn.on('error', (err) => {
        clearTimeout(timer);
        fail(pathError('SSH connection failed: ' + err.message, 502));
      });

      conn.connect({
        host: resolveHost(vm),
        port: getSSHPort(vm),
        username: vm.username || 'root',
        password: vm.password || undefined,
        readyTimeout: CONNECT_TIMEOUT_MS,
        algorithms: { serverHostKey: ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519'] }
      });
    });

    entry.ready = ready;
    sessions.set(key, entry);
    ready.catch(() => { /* rejection already logged via caller */ });
    return ready;
  }

  return { getSession, closeSession, keyFor };
}

// =====================================================================
// Router factory
// =====================================================================

module.exports = function createFileManager({ db, checkAuth, getSSHPort, logError, nodeManager }) {
  const router = express.Router({ mergeParams: true });
  const sessionMgr = createSessionManager({ getSSHPort });

  // vmId -> Set<ws>  (for the WebSocket live-update channel)
  const watchers = new Map();

  function broadcastFsChange(vmId, dir, kind) {
    const set = watchers.get(String(vmId));
    if (!set || set.size === 0) return;
    const payload = JSON.stringify({ type: 'fs-changed', path: dir, kind: kind || 'update' });
    for (const ws of set) {
      if (ws.readyState === ws.OPEN) {
        try { ws.send(payload); } catch (e) { /* ignore */ }
      }
    }
  }

  // ---- Ownership-checked VM loader (mirrors the existing vmQuery
  // pattern already used by /api/ssh/connect and the WS terminal) ----
  function loadVM(req, res, next) {
    const vmId = req.params.vm_id;
    if (!vmId || isNaN(vmId)) {
      return res.status(400).json({ error: 'Invalid VM id' });
    }
    const isAdmin = req.session.role === 'admin';
    const query = isAdmin ? `SELECT * FROM vms WHERE vm_id = ?` : `SELECT * FROM vms WHERE vm_id = ? AND owner_id = ?`;
    const params = isAdmin ? [vmId] : [vmId, req.session.userId];
    db.get(query, params, (err, vm) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!vm) return res.status(403).json({ error: 'VM not found or access denied' });
      req.vm = vm;
      next();
    });
  }

  function requireRunning(req, res, next) {
    if (req.vm.status !== 'running') {
      return res.status(409).json({ error: 'VPS is offline', vmStatus: req.vm.status, code: 'VPS_OFFLINE' });
    }
    next();
  }

  async function getSftp(req, res) {
    try {
      const { sftp, conn } = await sessionMgr.getSession(req.vm, req.session.userId);
      return { sftp, conn };
    } catch (err) {
      const status = err.httpStatus || 502;
      logError && logError('FileManager', req.vm.vm_id, 'connect', err);
      res.status(status).json({ error: err.message || 'Could not reach the VPS filesystem', code: 'SSH_UNAVAILABLE' });
      return null;
    }
  }

  // Maps common SFTP/SSH errors to clean HTTP responses.
  function handleFsError(res, err, fallbackMsg) {
    if (!err) return res.status(500).json({ error: fallbackMsg || 'Unknown error' });
    const code = err.code;
    if (code === 2 || /no such file/i.test(err.message || '')) {
      return res.status(404).json({ error: 'File or folder not found', code: 'NOT_FOUND' });
    }
    if (code === 3 || /permission denied/i.test(err.message || '')) {
      return res.status(403).json({ error: 'Permission denied', code: 'PERMISSION_DENIED' });
    }
    if (/no space left/i.test(err.message || '')) {
      return res.status(507).json({ error: 'Disk full on VPS', code: 'DISK_FULL' });
    }
    if (/timed?\s*out/i.test(err.message || '')) {
      return res.status(504).json({ error: 'Operation timed out', code: 'TIMEOUT' });
    }
    // SFTPv3 has no dedicated "already exists" status code - servers report
    // it as the generic FX_FAILURE ("Failure"), typically from mkdir/open
    // on a name that's already taken. Give the person something actionable
    // instead of the bare protocol string.
    if (/^failure$/i.test((err.message || '').trim())) {
      return res.status(409).json({ error: 'A file or folder with that name already exists', code: 'ALREADY_EXISTS' });
    }
    return res.status(500).json({ error: err.message || fallbackMsg || 'File manager error' });
  }

  router.use(checkAuth);
  router.use(loadVM);

  // Resolve which node this VM lives on. Local VMs fall straight
  // through, unchanged, to the routes below (exactly as before Node
  // Agent support existed). Remote VMs are fully handled here via the
  // agent relay - see remoteHandle() - and never reach the routes
  // below at all.
  router.use(async (req, res, next) => {
    if (!nodeManager) return next(); // defensive - filemanager usable standalone too
    try { req.node = await nodeManager.getNodeForVM(req.vm); }
    catch (e) { return res.status(500).json({ error: 'Could not resolve node for this VM' }); }
    if (!req.node || req.node.mode !== 'remote') return next();
    if (req.vm.status !== 'running') {
      return res.status(409).json({ error: 'VPS is offline', vmStatus: req.vm.status, code: 'VPS_OFFLINE' });
    }
    return remoteHandle(req, res, req.node);
  });

  function vmConnFor(vm) {
    if (vm.network_type === 'nat') return { host: '127.0.0.1', port: getSSHPort(vm), username: vm.username || 'root', password: vm.password || undefined };
    // See resolveHost() above for why this never falls back to 127.0.0.1.
    if (!vm.ipv4_address) {
      throw pathError('This VM has no IPv4 address configured yet, so its files can\'t be reached', 409);
    }
    return { host: vm.ipv4_address, port: getSSHPort(vm), username: vm.username || 'root', password: vm.password || undefined };
  }

  async function remoteHandle(req, res, node) {
    // DEEP FIX (hung downloads): once the /download relay has started
    // writing chunks, a mid-stream failure used to attempt a JSON error
    // response, which throws ERR_HTTP_HEADERS_SENT inside the catch and
    // leaves the browser waiting on a truncated body forever. Destroy the
    // connection instead once headers are out.
    const nodeErr = (e) => {
      if (res.headersSent) { try { res.destroy(); } catch (closed) {} return; }
      res.status(e.httpStatus || 502).json({ error: e.message || 'Node request failed', code: e.code });
    };
    let vmConn;
    try { vmConn = vmConnFor(req.vm); } catch (e) { return nodeErr(e); }

    try {
      if (req.method === 'GET' && req.path === '/') {
        const result = await nodeManager.sendNodeCommand(node.id, 'file.list', { vmConn, path: req.query.path, sort: req.query.sort, order: req.query.order, search: req.query.search });
        return res.json(result);
      }
      if (req.method === 'GET' && req.path === '/storage') {
        const result = await nodeManager.sendNodeCommand(node.id, 'file.storage', { vmConn });
        return res.json(result);
      }
      if (req.method === 'GET' && req.path === '/raw') {
        const result = await nodeManager.sendNodeCommand(node.id, 'file.read', { vmConn, path: req.query.path, maxBytes: MAX_EDIT_FILE_BYTES });
        return res.json(result);
      }
      if (req.method === 'GET' && req.path === '/download') {
        const info = await nodeManager.sendNodeCommand(node.id, 'file.stat', { vmConn, path: req.query.path });
        const filename = path.posix.basename(info.path);
        res.setHeader('Content-Disposition', `attachment; filename="${filename.replace(/"/g, '')}"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Length', info.size);
        await nodeManager.relayDownload(node.id, { vmConn, path: req.query.path }, (chunk) => res.write(chunk));
        return res.end();
      }
      if (req.method === 'POST' && req.path === '/upload') {
        const targetDir = req.query.path || '/';
        let busboy;
        try { busboy = Busboy({ headers: req.headers, limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 } }); }
        catch (e) { return res.status(400).json({ error: 'Invalid upload request' }); }
        let handled = false;
        let sawFile = false;
        const finishOnce = (status, payload) => { if (handled) return; handled = true; res.status(status).json(payload); };
        busboy.on('file', async (fieldname, fileStream, info) => {
          sawFile = true;
          try {
            const result = await nodeManager.relayUpload(node.id, { vmConn, targetDir, filename: info.filename, maxBytes: MAX_UPLOAD_BYTES }, fileStream);
            finishOnce(200, { success: true, path: result.path });
          } catch (e) { fileStream.resume(); finishOnce(e.code === 'TOO_LARGE' ? 413 : (e.httpStatus || 500), { error: e.message, code: e.code }); }
        });
        busboy.on('finish', () => { if (!sawFile) finishOnce(400, { error: 'No file was uploaded' }); });
        return req.pipe(busboy);
      }
      if (req.method === 'PUT' && req.path === '/save') {
        return express.text({ type: '*/*', limit: `${MAX_EDIT_FILE_MB + 1}mb` })(req, res, async () => {
          try {
            const result = await nodeManager.sendNodeCommand(node.id, 'file.write', { vmConn, path: req.query.path, content: typeof req.body === 'string' ? req.body : '', maxBytes: MAX_EDIT_FILE_BYTES });
            res.json(result);
          } catch (e) { nodeErr(e); }
        });
      }
      if (req.method === 'POST' && req.path === '/create-folder') {
        const result = await nodeManager.sendNodeCommand(node.id, 'file.mkdir', { vmConn, path: req.body.path, name: req.body.name });
        return res.json(result);
      }
      if (req.method === 'POST' && req.path === '/create-file') {
        const result = await nodeManager.sendNodeCommand(node.id, 'file.createFile', { vmConn, path: req.body.path, name: req.body.name });
        return res.json(result);
      }
      if (req.method === 'POST' && req.path === '/rename') {
        const result = await nodeManager.sendNodeCommand(node.id, 'file.rename', { vmConn, path: req.body.path, newName: req.body.newName, destPath: req.body.destPath });
        return res.json(result);
      }
      if (req.method === 'DELETE' && req.path === '/') {
        const paths = Array.isArray(req.body.paths) ? req.body.paths : [req.body.path];
        const result = await nodeManager.sendNodeCommand(node.id, 'file.delete', { vmConn, paths });
        return res.json(result);
      }
      if (req.method === 'POST' && req.path === '/compress') {
        const result = await nodeManager.sendNodeCommand(node.id, 'file.compress', { vmConn, path: req.body.path, names: req.body.names, archiveName: req.body.archiveName, format: req.body.format });
        return res.json(result);
      }
      if (req.method === 'POST' && req.path === '/extract') {
        const result = await nodeManager.sendNodeCommand(node.id, 'file.extract', { vmConn, path: req.body.path, archiveName: req.body.archiveName, destName: req.body.destName });
        return res.json(result);
      }
      return res.status(404).json({ error: 'Not found' });
    } catch (e) {
      return nodeErr(e);
    }
  }

  // -------------------------------------------------------------
  // GET / — list directory
  // -------------------------------------------------------------
  router.get('/', requireRunning, async (req, res) => {
    let remotePath;
    try { remotePath = normalizeRemotePath(req.query.path); }
    catch (e) { return res.status(400).json({ error: e.message }); }

    const sess = await getSftp(req, res);
    if (!sess) return;
    const { sftp } = sess;

    sftp.readdir(remotePath, (err, list) => {
      if (err) return handleFsError(res, err, 'Could not read directory');

      let entries = list.map((item) => {
        const attrs = item.attrs || {};
        const isDir = typeof attrs.isDirectory === 'function' ? attrs.isDirectory() : false;
        const isLink = typeof attrs.isSymbolicLink === 'function' ? attrs.isSymbolicLink() : false;
        return {
          name: item.filename,
          type: isDir ? 'directory' : (isLink ? 'symlink' : 'file'),
          size: attrs.size || 0,
          modified: attrs.mtime ? attrs.mtime * 1000 : null,
          permissions: attrs.mode ? (attrs.mode & 0o777).toString(8) : null,
          mode: attrs.mode || null
        };
      });

      const search = (req.query.search || '').toString().trim().toLowerCase();
      if (search) {
        entries = entries.filter((e) => e.name.toLowerCase().includes(search));
      }

      const sortKey = ['name', 'size', 'modified'].includes(req.query.sort) ? req.query.sort : 'name';
      const order = req.query.order === 'desc' ? -1 : 1;
      entries.sort((a, b) => {
        // Folders first, always, then apply the requested sort within each group.
        if (a.type === 'directory' && b.type !== 'directory') return -1;
        if (a.type !== 'directory' && b.type === 'directory') return 1;
        let av = a[sortKey], bv = b[sortKey];
        if (sortKey === 'name') { av = av.toLowerCase(); bv = bv.toLowerCase(); }
        if (av < bv) return -1 * order;
        if (av > bv) return 1 * order;
        return 0;
      });

      const parent = remotePath === '/' ? null : path.posix.dirname(remotePath);
      res.json({ path: remotePath, parent, entries });
    });
  });

  // -------------------------------------------------------------
  // GET /storage — live disk usage for the guest filesystem
  // -------------------------------------------------------------
  router.get('/storage', requireRunning, async (req, res) => {
    const sess = await getSftp(req, res);
    if (!sess) return;
    const { conn } = sess;

    conn.exec("df -Pk / | tail -n 1", (err, stream) => {
      if (err) return res.status(502).json({ error: 'Could not read storage info' });
      let out = '';
      let errOut = '';
      stream.on('data', (d) => { out += d.toString(); });
      stream.stderr.on('data', (d) => { errOut += d.toString(); });
      stream.on('close', () => {
        const parts = out.trim().split(/\s+/);
        if (parts.length < 4) {
          return res.status(502).json({ error: 'Could not parse storage info' });
        }
        const totalKb = parseInt(parts[1], 10) || 0;
        const usedKb = parseInt(parts[2], 10) || 0;
        const freeKb = parseInt(parts[3], 10) || 0;
        res.json({
          totalBytes: totalKb * 1024,
          usedBytes: usedKb * 1024,
          freeBytes: freeKb * 1024
        });
      });
    });
  });

  // -------------------------------------------------------------
  // GET /raw — text file content for preview/edit (size-capped)
  // -------------------------------------------------------------
  router.get('/raw', requireRunning, async (req, res) => {
    let remotePath;
    try { remotePath = normalizeRemotePath(req.query.path); }
    catch (e) { return res.status(400).json({ error: e.message }); }
    if (remotePath === '/') return res.status(400).json({ error: 'Not a file' });

    const sess = await getSftp(req, res);
    if (!sess) return;
    const { sftp } = sess;

    sftp.stat(remotePath, (err, stats) => {
      if (err) return handleFsError(res, err, 'Could not read file');
      if (typeof stats.isDirectory === 'function' && stats.isDirectory()) {
        return res.status(400).json({ error: 'Cannot open a directory as a file' });
      }
      if (stats.size > MAX_EDIT_FILE_BYTES) {
        return res.status(413).json({ error: `File is larger than ${MAX_EDIT_FILE_MB}MB — download it instead`, code: 'TOO_LARGE' });
      }
      sftp.readFile(remotePath, 'utf8', (readErr, data) => {
        if (readErr) return handleFsError(res, readErr, 'Could not read file');
        res.json({ path: remotePath, content: data, size: stats.size });
      });
    });
  });

  // -------------------------------------------------------------
  // GET /download — stream a file to the browser
  // -------------------------------------------------------------
  router.get('/download', requireRunning, async (req, res) => {
    let remotePath;
    try { remotePath = normalizeRemotePath(req.query.path); }
    catch (e) { return res.status(400).json({ error: e.message }); }
    if (remotePath === '/') return res.status(400).json({ error: 'Not a file' });

    const sess = await getSftp(req, res);
    if (!sess) return;
    const { sftp } = sess;

    sftp.stat(remotePath, (err, stats) => {
      if (err) return handleFsError(res, err, 'Could not read file');
      if (typeof stats.isDirectory === 'function' && stats.isDirectory()) {
        return res.status(400).json({ error: 'Use /compress to download a folder' });
      }
      const filename = path.posix.basename(remotePath);
      res.setHeader('Content-Disposition', `attachment; filename="${filename.replace(/"/g, '')}"`);
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Length', stats.size);

      const stream = sftp.createReadStream(remotePath);
      let responded = false;
      stream.on('error', (streamErr) => {
        if (!responded) { responded = true; res.status(500); }
        res.end();
        console.error(`[FileManager] download stream error:`, streamErr.message);
      });
      stream.pipe(res);
    });
  });

  // -------------------------------------------------------------
  // POST /upload — streamed multipart upload straight into SFTP
  // -------------------------------------------------------------
  router.post('/upload', requireRunning, async (req, res) => {
    let targetDir;
    try { targetDir = normalizeRemotePath(req.query.path || req.headers['x-fm-path']); }
    catch (e) { return res.status(400).json({ error: e.message }); }

    const sess = await getSftp(req, res);
    if (!sess) return;
    const { sftp } = sess;

    let busboy;
    try {
      busboy = Busboy({ headers: req.headers, limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 } });
    } catch (e) {
      return res.status(400).json({ error: 'Invalid upload request' });
    }

    let handled = false;
    let sawFile = false;

    const finishOnce = (status, payload) => {
      if (handled) return;
      handled = true;
      res.status(status).json(payload);
    };

    busboy.on('file', (fieldname, fileStream, info) => {
      sawFile = true;
      let safeName;
      try { safeName = assertSafeName(info.filename, 'File name'); }
      catch (e) {
        fileStream.resume();
        return finishOnce(400, { error: e.message });
      }
      const remotePath = joinRemotePath(targetDir, safeName);
      const writeStream = sftp.createWriteStream(remotePath);
      let limitHit = false;

      fileStream.on('limit', () => {
        limitHit = true;
        try { writeStream.destroy(); } catch (e) { /* ignore */ }
        finishOnce(413, { error: `File exceeds the ${MAX_UPLOAD_MB}MB upload limit`, code: 'TOO_LARGE' });
      });

      writeStream.on('error', (err) => {
        if (limitHit) return;
        finishOnce(500, { error: 'Upload failed: ' + err.message });
      });

      writeStream.on('close', () => {
        if (limitHit || handled) return;
        broadcastFsChange(req.vm.vm_id, targetDir, 'upload');
        finishOnce(200, { success: true, path: remotePath });
      });

      fileStream.pipe(writeStream);
    });

    busboy.on('error', (err) => {
      finishOnce(500, { error: 'Upload failed: ' + err.message });
    });

    busboy.on('finish', () => {
      if (!sawFile) finishOnce(400, { error: 'No file was uploaded' });
    });

    req.pipe(busboy);
  });

  // -------------------------------------------------------------
  // POST /create-folder
  // -------------------------------------------------------------
  router.post('/create-folder', requireRunning, express.json(), async (req, res) => {
    let target;
    try { target = joinRemotePath(req.body.path, req.body.name); }
    catch (e) { return res.status(400).json({ error: e.message }); }

    const sess = await getSftp(req, res);
    if (!sess) return;
    sess.sftp.mkdir(target, (err) => {
      if (err) return handleFsError(res, err, 'Could not create folder');
      broadcastFsChange(req.vm.vm_id, normalizeRemotePath(req.body.path), 'mkdir');
      res.json({ success: true, path: target });
    });
  });

  // -------------------------------------------------------------
  // POST /create-file — empty file
  // -------------------------------------------------------------
  router.post('/create-file', requireRunning, express.json(), async (req, res) => {
    let target;
    try { target = joinRemotePath(req.body.path, req.body.name); }
    catch (e) { return res.status(400).json({ error: e.message }); }

    const sess = await getSftp(req, res);
    if (!sess) return;
    sess.sftp.writeFile(target, '', { flag: 'wx' }, (err) => {
      if (err) return handleFsError(res, err, 'Could not create file');
      broadcastFsChange(req.vm.vm_id, normalizeRemotePath(req.body.path), 'create');
      res.json({ success: true, path: target });
    });
  });

  // -------------------------------------------------------------
  // PUT /save — save edited text file content
  //
  // NOTE: the panel's global `app.use(express.json())` middleware (set
  // up once, app-wide, before this router is mounted) caps JSON bodies
  // at its own small default limit - too small for multi-megabyte file
  // saves, and not something this feature should change app-wide. So
  // this endpoint intentionally takes the file content as a raw
  // text/plain body (parsed here, with our own larger limit) instead
  // of JSON, and the target path as a query parameter.
  // -------------------------------------------------------------
  router.put('/save', requireRunning, express.text({ type: '*/*', limit: `${MAX_EDIT_FILE_MB + 1}mb` }), async (req, res) => {
    let target;
    try { target = normalizeRemotePath(req.query.path); }
    catch (e) { return res.status(400).json({ error: e.message }); }
    if (target === '/') return res.status(400).json({ error: 'Not a file' });

    const content = typeof req.body === 'string' ? req.body : '';
    if (Buffer.byteLength(content, 'utf8') > MAX_EDIT_FILE_BYTES) {
      return res.status(413).json({ error: `File exceeds the ${MAX_EDIT_FILE_MB}MB editor limit`, code: 'TOO_LARGE' });
    }

    const sess = await getSftp(req, res);
    if (!sess) return;
    sess.sftp.writeFile(target, content, 'utf8', (err) => {
      if (err) return handleFsError(res, err, 'Could not save file');
      broadcastFsChange(req.vm.vm_id, path.posix.dirname(target), 'save');
      res.json({ success: true });
    });
  });

  // -------------------------------------------------------------
  // POST /rename — rename or move within the guest filesystem
  // -------------------------------------------------------------
  router.post('/rename', requireRunning, express.json(), async (req, res) => {
    let source, target;
    try {
      source = normalizeRemotePath(req.body.path);
      if (req.body.destPath) {
        target = normalizeRemotePath(req.body.destPath);
      } else {
        target = joinRemotePath(path.posix.dirname(source), req.body.newName);
      }
    } catch (e) { return res.status(400).json({ error: e.message }); }

    const sess = await getSftp(req, res);
    if (!sess) return;
    sess.sftp.rename(source, target, (err) => {
      if (err) return handleFsError(res, err, 'Could not rename');
      broadcastFsChange(req.vm.vm_id, path.posix.dirname(source), 'rename');
      broadcastFsChange(req.vm.vm_id, path.posix.dirname(target), 'rename');
      res.json({ success: true, path: target });
    });
  });

  // -------------------------------------------------------------
  // DELETE / — bulk delete files/folders (recursive for folders)
  // -------------------------------------------------------------
  router.delete('/', requireRunning, express.json(), async (req, res) => {
    const rawPaths = Array.isArray(req.body.paths) ? req.body.paths : [req.body.path];
    let targets;
    try { targets = rawPaths.map((p) => normalizeRemotePath(p)); }
    catch (e) { return res.status(400).json({ error: e.message }); }
    if (targets.some((t) => t === '/')) {
      return res.status(400).json({ error: 'Refusing to delete the VPS root directory' });
    }

    const sess = await getSftp(req, res);
    if (!sess) return;
    const { sftp } = sess;

    function removeRecursive(target, cb) {
      sftp.lstat(target, (err, stats) => {
        if (err) return cb(err);
        const isDir = typeof stats.isDirectory === 'function' && stats.isDirectory() &&
          !(typeof stats.isSymbolicLink === 'function' && stats.isSymbolicLink());
        if (!isDir) return sftp.unlink(target, cb);

        sftp.readdir(target, (readErr, list) => {
          if (readErr) return cb(readErr);
          let i = 0;
          const next = () => {
            if (i >= list.length) return sftp.rmdir(target, cb);
            const child = target === '/' ? '/' + list[i].filename : target + '/' + list[i].filename;
            i++;
            removeRecursive(child, (childErr) => {
              if (childErr) return cb(childErr);
              next();
            });
          };
          next();
        });
      });
    }

    const results = [];
    let idx = 0;
    const runNext = () => {
      if (idx >= targets.length) {
        const failed = results.filter((r) => !r.success);
        broadcastFsChange(req.vm.vm_id, path.posix.dirname(targets[0]), 'delete');
        return res.json({ success: failed.length === 0, results });
      }
      const target = targets[idx++];
      removeRecursive(target, (err) => {
        results.push({ path: target, success: !err, error: err ? err.message : null });
        runNext();
      });
    };
    runNext();
  });

  // -------------------------------------------------------------
  // Archive tool availability check (cached per session key)
  // -------------------------------------------------------------
  const archiveToolCache = new Map();
  function detectArchiveTools(conn, cacheKey, cb) {
    if (archiveToolCache.has(cacheKey)) return cb(archiveToolCache.get(cacheKey));
    conn.exec("for b in tar zip unzip gzip; do command -v $b >/dev/null 2>&1 && echo $b; done", (err, stream) => {
      if (err) return cb({});
      let out = '';
      stream.on('data', (d) => { out += d.toString(); });
      stream.on('close', () => {
        const found = {};
        out.split('\n').map((s) => s.trim()).filter(Boolean).forEach((b) => { found[b] = true; });
        archiveToolCache.set(cacheKey, found);
        setTimeout(() => archiveToolCache.delete(cacheKey), 5 * 60 * 1000).unref();
        cb(found);
      });
    });
  }

  // -------------------------------------------------------------
  // POST /compress
  // -------------------------------------------------------------
  router.post('/compress', requireRunning, express.json(), async (req, res) => {
    let dir;
    try { dir = normalizeRemotePath(req.body.path); }
    catch (e) { return res.status(400).json({ error: e.message }); }

    const format = ARCHIVE_FORMATS[req.body.format] ? req.body.format : 'tar.gz';
    const names = Array.isArray(req.body.names) ? req.body.names : [];
    if (names.length === 0) return res.status(400).json({ error: 'Select at least one item to compress' });

    let safeNames, archiveName;
    try {
      safeNames = names.map((n) => assertSafeName(n, 'Item name'));
      archiveName = assertSafeName(req.body.archiveName || `archive${ARCHIVE_FORMATS[format].ext}`, 'Archive name');
    } catch (e) { return res.status(400).json({ error: e.message }); }

    const sess = await getSftp(req, res);
    if (!sess) return;
    const { conn } = sess;
    const key = sessionMgr.keyFor(req.vm.vm_id, req.session.userId);

    detectArchiveTools(conn, key, (tools) => {
      let cmd;
      if (format === 'zip') {
        if (!tools.zip) return res.status(501).json({ error: '"zip" is not installed on this VPS', code: 'TOOL_MISSING' });
        cmd = `cd ${shQuote(dir)} && zip -r ${shQuote(archiveName)} -- ${safeNames.map(shQuote).join(' ')}`;
      } else {
        if (!tools.tar) return res.status(501).json({ error: '"tar" is not installed on this VPS', code: 'TOOL_MISSING' });
        const gzFlag = (format === 'tar') ? '' : 'z';
        if (gzFlag && !tools.gzip) return res.status(501).json({ error: '"gzip" is not installed on this VPS', code: 'TOOL_MISSING' });
        cmd = `cd ${shQuote(dir)} && tar -c${gzFlag}f ${shQuote(archiveName)} -- ${safeNames.map(shQuote).join(' ')}`;
      }

      conn.exec(cmd, (err, stream) => {
        if (err) return res.status(502).json({ error: 'Could not run compression on the VPS' });
        let errOut = '';
        stream.stderr.on('data', (d) => { errOut += d.toString(); });
        stream.on('close', (code) => {
          if (code !== 0) {
            return res.status(500).json({ error: 'Compression failed: ' + (errOut.trim() || `exit code ${code}`) });
          }
          broadcastFsChange(req.vm.vm_id, dir, 'compress');
          res.json({ success: true, path: joinRemotePath(dir, archiveName) });
        });
      });
    });
  });

  // -------------------------------------------------------------
  // POST /extract
  // -------------------------------------------------------------
  router.post('/extract', requireRunning, express.json(), async (req, res) => {
    let dir;
    try { dir = normalizeRemotePath(req.body.path); }
    catch (e) { return res.status(400).json({ error: e.message }); }

    let archiveName, destName;
    try {
      archiveName = assertSafeName(req.body.archiveName, 'Archive name');
      destName = req.body.destName ? assertSafeName(req.body.destName, 'Destination folder') : null;
    } catch (e) { return res.status(400).json({ error: e.message }); }

    const lower = archiveName.toLowerCase();
    const sess = await getSftp(req, res);
    if (!sess) return;
    const { conn } = sess;
    const key = sessionMgr.keyFor(req.vm.vm_id, req.session.userId);

    detectArchiveTools(conn, key, (tools) => {
      const destDir = destName ? joinRemotePath(dir, destName) : dir;
      let mkdirCmd = destName ? `mkdir -p ${shQuote(destDir)} && ` : '';
      let cmd;

      if (lower.endsWith('.zip')) {
        if (!tools.unzip) return res.status(501).json({ error: '"unzip" is not installed on this VPS', code: 'TOOL_MISSING' });
        cmd = `${mkdirCmd}cd ${shQuote(dir)} && unzip -o ${shQuote(archiveName)} -d ${shQuote(destDir)}`;
      } else if (lower.endsWith('.tar.gz') || lower.endsWith('.tgz') || lower.endsWith('.tar')) {
        if (!tools.tar) return res.status(501).json({ error: '"tar" is not installed on this VPS', code: 'TOOL_MISSING' });
        const gzFlag = lower.endsWith('.tar') ? '' : 'z';
        cmd = `${mkdirCmd}cd ${shQuote(dir)} && tar -x${gzFlag}f ${shQuote(archiveName)} -C ${shQuote(destDir)}`;
      } else {
        return res.status(400).json({ error: 'Unsupported archive type' });
      }

      conn.exec(cmd, (err, stream) => {
        if (err) return res.status(502).json({ error: 'Could not run extraction on the VPS' });
        let errOut = '';
        stream.stderr.on('data', (d) => { errOut += d.toString(); });
        stream.on('close', (code) => {
          if (code !== 0) {
            return res.status(500).json({ error: 'Extraction failed: ' + (errOut.trim() || `exit code ${code}`) });
          }
          broadcastFsChange(req.vm.vm_id, destDir, 'extract');
          res.json({ success: true, path: destDir });
        });
      });
    });
  });

  // -------------------------------------------------------------
  // WebSocket live-update channel: /file-manager/:vmId
  // -------------------------------------------------------------
  function handleFileManagerWS(ws, vmId, wsSession) {
    db.get(`SELECT owner_id FROM vms WHERE vm_id = ?`, [vmId], (err, vm) => {
      if (err || !vm) {
        ws.send(JSON.stringify({ type: 'error', message: 'VM not found' }));
        return ws.close();
      }
      if (wsSession.role !== 'admin' && vm.owner_id !== wsSession.userId) {
        ws.send(JSON.stringify({ type: 'error', message: 'Access denied' }));
        return ws.close();
      }

      const key = String(vmId);
      if (!watchers.has(key)) watchers.set(key, new Set());
      watchers.get(key).add(ws);
      ws.send(JSON.stringify({ type: 'watching', vmId }));

      ws.on('close', () => {
        const set = watchers.get(key);
        if (set) {
          set.delete(ws);
          if (set.size === 0) watchers.delete(key);
        }
      });
      ws.on('error', () => {});
    });
  }

  return { router, handleFileManagerWS, broadcastFsChange, _internal: { normalizeRemotePath, assertSafeName, joinRemotePath } };
};
