// =====================================================================
// VNM — shared SFTP operation primitives
// ---------------------------------------------------------------------
// Pure, connection-agnostic file-manager operations: given an already-
// connected { sftp, conn } pair (an ssh2 SFTPWrapper + Client) to a
// guest VM, perform list/upload/download/create/save/rename/delete/
// compress/extract/storage. No Express, no res/req anywhere in here.
//
// Used by:
//   - filemanager.js, for VMs on the Local Node (panel already has a
//     direct network path to the guest, exactly as before)
//   - node-agent/agent.js, for VMs on a Remote Node (the agent has the
//     direct network path to the guest; the panel doesn't)
//
// Keeping this in one module means "browse this VM's filesystem" behaves
// identically no matter which node the VM lives on.
// =====================================================================

const path = require('path');

const ARCHIVE_FORMATS = { 'zip': { ext: '.zip' }, 'tar': { ext: '.tar' }, 'tar.gz': { ext: '.tar.gz' }, 'tgz': { ext: '.tgz' } };

function pathError(message, status) {
  const err = new Error(message);
  err.httpStatus = status || 400;
  err.isFileManagerError = true;
  return err;
}

function normalizeRemotePath(raw) {
  if (raw === undefined || raw === null || raw === '') return '/';
  if (typeof raw !== 'string') throw pathError('Invalid path');
  if (raw.indexOf('\u0000') !== -1) throw pathError('Invalid path');
  let p = raw.startsWith('/') ? raw : '/' + raw;
  p = path.posix.normalize(p);
  if (!p.startsWith('/')) p = '/' + p;
  return p;
}

function assertSafeName(name, label) {
  if (typeof name !== 'string' || !name.trim()) throw pathError(`${label || 'Name'} is required`);
  const trimmed = name.trim();
  if (trimmed === '.' || trimmed === '..') throw pathError(`Invalid ${label || 'name'}`);
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

function shQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function mapFsError(err) {
  if (!err) return pathError('Unknown error', 500);
  if (err.isFileManagerError) return err;
  const code = err.code;
  let httpStatus = 500, mappedCode = null, message = err.message;
  if (code === 2 || /no such file/i.test(err.message || '')) { httpStatus = 404; mappedCode = 'NOT_FOUND'; message = 'File or folder not found'; }
  else if (code === 3 || /permission denied/i.test(err.message || '')) { httpStatus = 403; mappedCode = 'PERMISSION_DENIED'; message = 'Permission denied'; }
  else if (/no space left/i.test(err.message || '')) { httpStatus = 507; mappedCode = 'DISK_FULL'; message = 'Disk full on VPS'; }
  else if (/timed?\s*out/i.test(err.message || '')) { httpStatus = 504; mappedCode = 'TIMEOUT'; message = 'Operation timed out'; }
  else if (/^failure$/i.test((err.message || '').trim())) { httpStatus = 409; mappedCode = 'ALREADY_EXISTS'; message = 'A file or folder with that name already exists'; }
  const wrapped = pathError(message, httpStatus);
  wrapped.code = mappedCode;
  return wrapped;
}

// ---------------------------------------------------------------
// List directory
// ---------------------------------------------------------------
function listDirectory(ctx, { path: rawPath, sort, search, order }) {
  return new Promise((resolve, reject) => {
    let remotePath;
    try { remotePath = normalizeRemotePath(rawPath); } catch (e) { return reject(e); }
    ctx.sftp.readdir(remotePath, (err, list) => {
      if (err) return reject(mapFsError(err));
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
      const s = (search || '').toString().trim().toLowerCase();
      if (s) entries = entries.filter((e) => e.name.toLowerCase().includes(s));
      const sortKey = ['name', 'size', 'modified'].includes(sort) ? sort : 'name';
      const ord = order === 'desc' ? -1 : 1;
      entries.sort((a, b) => {
        if (a.type === 'directory' && b.type !== 'directory') return -1;
        if (a.type !== 'directory' && b.type === 'directory') return 1;
        let av = a[sortKey], bv = b[sortKey];
        if (sortKey === 'name') { av = av.toLowerCase(); bv = bv.toLowerCase(); }
        if (av < bv) return -1 * ord;
        if (av > bv) return 1 * ord;
        return 0;
      });
      const parent = remotePath === '/' ? null : path.posix.dirname(remotePath);
      resolve({ path: remotePath, parent, entries });
    });
  });
}

function getStorage(ctx) {
  return new Promise((resolve, reject) => {
    ctx.conn.exec("df -Pk / | tail -n 1", (err, stream) => {
      if (err) return reject(pathError('Could not read storage info', 502));
      let out = '';
      stream.on('data', (d) => { out += d.toString(); });
      stream.on('close', () => {
        const parts = out.trim().split(/\s+/);
        if (parts.length < 4) return reject(pathError('Could not parse storage info', 502));
        resolve({
          totalBytes: (parseInt(parts[1], 10) || 0) * 1024,
          usedBytes: (parseInt(parts[2], 10) || 0) * 1024,
          freeBytes: (parseInt(parts[3], 10) || 0) * 1024
        });
      });
    });
  });
}

function readTextFile(ctx, rawPath, maxBytes) {
  return new Promise((resolve, reject) => {
    let remotePath;
    try { remotePath = normalizeRemotePath(rawPath); } catch (e) { return reject(e); }
    if (remotePath === '/') return reject(pathError('Not a file'));
    ctx.sftp.stat(remotePath, (err, stats) => {
      if (err) return reject(mapFsError(err));
      if (typeof stats.isDirectory === 'function' && stats.isDirectory()) return reject(pathError('Cannot open a directory as a file'));
      if (maxBytes && stats.size > maxBytes) {
        const e = pathError(`File is larger than the editor limit`, 413); e.code = 'TOO_LARGE'; return reject(e);
      }
      ctx.sftp.readFile(remotePath, 'utf8', (readErr, data) => {
        if (readErr) return reject(mapFsError(readErr));
        resolve({ path: remotePath, content: data, size: stats.size });
      });
    });
  });
}

function statFile(ctx, rawPath) {
  return new Promise((resolve, reject) => {
    let remotePath;
    try { remotePath = normalizeRemotePath(rawPath); } catch (e) { return reject(e); }
    if (remotePath === '/') return reject(pathError('Not a file'));
    ctx.sftp.stat(remotePath, (err, stats) => {
      if (err) return reject(mapFsError(err));
      if (typeof stats.isDirectory === 'function' && stats.isDirectory()) return reject(pathError('Use compress to download a folder'));
      resolve({ path: remotePath, size: stats.size });
    });
  });
}

function writeTextFile(ctx, rawPath, content, maxBytes) {
  return new Promise((resolve, reject) => {
    let target;
    try { target = normalizeRemotePath(rawPath); } catch (e) { return reject(e); }
    if (target === '/') return reject(pathError('Not a file'));
    const body = typeof content === 'string' ? content : '';
    if (maxBytes && Buffer.byteLength(body, 'utf8') > maxBytes) {
      const e = pathError('File exceeds the editor size limit', 413); e.code = 'TOO_LARGE'; return reject(e);
    }
    ctx.sftp.writeFile(target, body, 'utf8', (err) => {
      if (err) return reject(mapFsError(err));
      resolve({ success: true, path: target });
    });
  });
}

function createFolder(ctx, dir, name) {
  return new Promise((resolve, reject) => {
    let target;
    try { target = joinRemotePath(dir, name); } catch (e) { return reject(e); }
    ctx.sftp.mkdir(target, (err) => {
      if (err) return reject(mapFsError(err));
      resolve({ success: true, path: target });
    });
  });
}

function createFile(ctx, dir, name) {
  return new Promise((resolve, reject) => {
    let target;
    try { target = joinRemotePath(dir, name); } catch (e) { return reject(e); }
    ctx.sftp.writeFile(target, '', { flag: 'wx' }, (err) => {
      if (err) return reject(mapFsError(err));
      resolve({ success: true, path: target });
    });
  });
}

function renamePath(ctx, rawPath, { newName, destPath }) {
  return new Promise((resolve, reject) => {
    let source, target;
    try {
      source = normalizeRemotePath(rawPath);
      target = destPath ? normalizeRemotePath(destPath) : joinRemotePath(path.posix.dirname(source), newName);
    } catch (e) { return reject(e); }
    ctx.sftp.rename(source, target, (err) => {
      if (err) return reject(mapFsError(err));
      resolve({ success: true, path: target, sourceDir: path.posix.dirname(source), destDir: path.posix.dirname(target) });
    });
  });
}

function removeRecursive(ctx, rawTarget) {
  return new Promise((resolve, reject) => {
    const sftp = ctx.sftp;
    function go(target, cb) {
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
            go(child, (childErr) => { if (childErr) return cb(childErr); next(); });
          };
          next();
        });
      });
    }
    go(rawTarget, (err) => err ? reject(mapFsError(err)) : resolve());
  });
}

async function deletePaths(ctx, dir, names) {
  let targets;
  try { targets = names.map((n) => normalizeRemotePath(dir === undefined ? n : joinRemotePath(dir, n))); }
  catch (e) { throw e; }
  if (targets.some((t) => t === '/')) throw pathError('Refusing to delete the VPS root directory');
  const results = [];
  for (const target of targets) {
    try { await removeRecursive(ctx, target); results.push({ path: target, success: true }); }
    catch (e) { results.push({ path: target, success: false, error: e.message }); }
  }
  return { success: results.every((r) => r.success), results };
}

function detectArchiveTools(ctx) {
  return new Promise((resolve) => {
    ctx.conn.exec("for b in tar zip unzip gzip; do command -v $b >/dev/null 2>&1 && echo $b; done", (err, stream) => {
      if (err) return resolve({});
      let out = '';
      stream.on('data', (d) => { out += d.toString(); });
      stream.on('close', () => {
        const found = {};
        out.split('\n').map((s) => s.trim()).filter(Boolean).forEach((b) => { found[b] = true; });
        resolve(found);
      });
    });
  });
}

function execCommand(ctx, cmd) {
  return new Promise((resolve, reject) => {
    ctx.conn.exec(cmd, (err, stream) => {
      if (err) return reject(pathError('Could not run command on the VPS', 502));
      let errOut = '';
      stream.stderr.on('data', (d) => { errOut += d.toString(); });
      stream.on('close', (code) => resolve({ code, stderr: errOut.trim() }));
    });
  });
}

async function compress(ctx, dir, names, archiveName, format) {
  const safeDir = normalizeRemotePath(dir);
  const fmt = ARCHIVE_FORMATS[format] ? format : 'tar.gz';
  const safeNames = names.map((n) => assertSafeName(n, 'Item name'));
  const safeArchive = assertSafeName(archiveName || `archive${ARCHIVE_FORMATS[fmt].ext}`, 'Archive name');
  const tools = await detectArchiveTools(ctx);
  let cmd;
  if (fmt === 'zip') {
    if (!tools.zip) { const e = pathError('"zip" is not installed on this VPS', 501); e.code = 'TOOL_MISSING'; throw e; }
    cmd = `cd ${shQuote(safeDir)} && zip -r ${shQuote(safeArchive)} -- ${safeNames.map(shQuote).join(' ')}`;
  } else {
    if (!tools.tar) { const e = pathError('"tar" is not installed on this VPS', 501); e.code = 'TOOL_MISSING'; throw e; }
    const gzFlag = (fmt === 'tar') ? '' : 'z';
    if (gzFlag && !tools.gzip) { const e = pathError('"gzip" is not installed on this VPS', 501); e.code = 'TOOL_MISSING'; throw e; }
    cmd = `cd ${shQuote(safeDir)} && tar -c${gzFlag}f ${shQuote(safeArchive)} -- ${safeNames.map(shQuote).join(' ')}`;
  }
  const { code, stderr } = await execCommand(ctx, cmd);
  if (code !== 0) throw pathError('Compression failed: ' + (stderr || `exit code ${code}`), 500);
  return { success: true, path: joinRemotePath(safeDir, safeArchive) };
}

async function extract(ctx, dir, archiveName, destName) {
  const safeDir = normalizeRemotePath(dir);
  const safeArchive = assertSafeName(archiveName, 'Archive name');
  const safeDest = destName ? assertSafeName(destName, 'Destination folder') : null;
  const lower = safeArchive.toLowerCase();
  const tools = await detectArchiveTools(ctx);
  const destDir = safeDest ? joinRemotePath(safeDir, safeDest) : safeDir;
  const mkdirCmd = safeDest ? `mkdir -p ${shQuote(destDir)} && ` : '';
  let cmd;
  if (lower.endsWith('.zip')) {
    if (!tools.unzip) { const e = pathError('"unzip" is not installed on this VPS', 501); e.code = 'TOOL_MISSING'; throw e; }
    cmd = `${mkdirCmd}cd ${shQuote(safeDir)} && unzip -o ${shQuote(safeArchive)} -d ${shQuote(destDir)}`;
  } else if (lower.endsWith('.tar.gz') || lower.endsWith('.tgz') || lower.endsWith('.tar')) {
    if (!tools.tar) { const e = pathError('"tar" is not installed on this VPS', 501); e.code = 'TOOL_MISSING'; throw e; }
    const gzFlag = lower.endsWith('.tar') ? '' : 'z';
    cmd = `${mkdirCmd}cd ${shQuote(safeDir)} && tar -x${gzFlag}f ${shQuote(safeArchive)} -C ${shQuote(destDir)}`;
  } else {
    throw pathError('Unsupported archive type');
  }
  const { code, stderr } = await execCommand(ctx, cmd);
  if (code !== 0) throw pathError('Extraction failed: ' + (stderr || `exit code ${code}`), 500);
  return { success: true, path: destDir };
}

module.exports = {
  pathError, mapFsError, normalizeRemotePath, assertSafeName, joinRemotePath, shQuote,
  listDirectory, getStorage, readTextFile, statFile, writeTextFile,
  createFolder, createFile, renamePath, deletePaths, compress, extract
};
