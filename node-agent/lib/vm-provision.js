// =====================================================================
// VNM Node Agent — VM provisioning (runs ON the node)
// ---------------------------------------------------------------------
// Everything needed to CREATE a VM's on-node artifacts, mirroring the
// panel's local creation flow but with argv-array child processes only
// (no shell strings anywhere - a template key or disk size can never
// become shell syntax):
//
//   ensureTemplate()            cache + download OS templates (qcow2)
//                               with per-URL fallback, validated with
//                               qemu-img info
//   createSeedIso()             build the cloud-init seed ISO
//                               (cloud-localds / genisoimage / xorriso /
//                               mkisofs) from user-data + meta-data the
//                               panel generated
//   createDiskFromTemplate()    qemu-img convert + resize -> vm disk
//   createBlankDisk()           qemu-img create (ISO-install mode)
//   resizeDisk()                grow (or explicit --shrink) a node disk
//   cleanupVm()                 remove every on-node artifact for a VM
//
// The panel always generates the cloud-init content itself (same
// generators it uses locally), so the seed written here is byte-for-byte
// what a local VM would get - one source of truth for guest config.
// =====================================================================

const fs = require('fs');
const path = require('path');
const net = require('net');
const dns = require('dns');
const { execFile } = require('child_process');
const systemInfo = require('./system-info');
const qemu = require('./qemu-launcher');

const VM_DIR = qemu.VM_DIR;
const TEMPLATES_DIR = path.join(VM_DIR, 'templates');
if (!fs.existsSync(TEMPLATES_DIR)) fs.mkdirSync(TEMPLATES_DIR, { recursive: true });

const DISK_SIZE_RE = /^(\d+(?:\.\d+)?)\s*([KMGT]?)(?:i?B)?$/i;
const UNIT_BYTES = { '': 1, K: 1024, M: 1024 ** 2, G: 1024 ** 3, T: 1024 ** 4 };
const ISO_TOOLS = ['cloud-localds', 'genisoimage', 'xorriso', 'mkisofs'];

// ---------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------
function cleanVmId(vmId) {
  return String(vmId || '').replace(/[^0-9]/g, '');
}

function parseDiskSize(size) {
  const m = DISK_SIZE_RE.exec(String(size || '').trim());
  if (!m) return null;
  const bytes = Math.round(parseFloat(m[1]) * (UNIT_BYTES[m[2].toUpperCase()] || 1));
  return Number.isFinite(bytes) && bytes > 0 ? bytes : null;
}

function diskPathFor(vmId) { return qemu.diskPathFor(vmId); }
function seedPathFor(vmId) { return path.join(VM_DIR, `vm-${cleanVmId(vmId)}-seed.iso`); }
function templatePathFor(key) {
  const safe = String(key || 'template').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 100);
  return path.join(TEMPLATES_DIR, `${safe}.qcow2`);
}
// A streamed file (custom template / install ISO pushed by the panel)
// lands in the same templates dir under its sanitized basename.
function streamedPathFor(name) {
  const safe = String(name || '').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120);
  return path.join(TEMPLATES_DIR, safe);
}

function runFile(bin, args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(bin, args, { timeout: opts.timeoutMs || 120000, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        err.stderr = stderr ? stderr.toString().slice(0, 400) : '';
        reject(err);
      } else resolve(stdout.toString());
    });
  });
}

function httpError(code, message, extra) {
  const e = new Error(message);
  e.httpStatus = code;
  Object.assign(e, extra || {});
  return e;
}

// ---------------------------------------------------------------
// qemu-img discovery + image validation
// ---------------------------------------------------------------
let _qemuImgBin = null;
function detectQemuImg() {
  if (_qemuImgBin) return _qemuImgBin;
  const candidates = [process.env.QEMU_IMG_BIN, 'qemu-img', '/usr/bin/qemu-img', '/usr/libexec/qemu-img'].filter(Boolean);
  for (const bin of candidates) {
    try { execFileSync0(bin, ['--version']); _qemuImgBin = bin; return bin; }
    catch (e) { if (e.code === 'EACCES') throw e; /* try next */ }
  }
  return null;
}
function execFileSync0(bin, args) { require('child_process').execFileSync(bin, args, { stdio: 'pipe', timeout: 5000 }); }

async function qemuImgInfo(imgPath) {
  const bin = detectQemuImg();
  if (!bin) throw httpError(501, 'qemu-img is not available on this node (set QEMU_IMG_BIN or install qemu-utils)', { code: 'QEMU_IMG_UNAVAILABLE' });
  if (!fs.existsSync(imgPath)) return { exists: false, valid: false, reason: 'file not found' };
  try {
    const out = await runFile(bin, ['info', '--output=json', '--force-share', imgPath], { timeoutMs: 15000 });
    const j = JSON.parse(out);
    return {
      exists: true,
      valid: j['format'] === 'qcow2' || j['format'] === 'raw',
      format: j['format'],
      virtualSize: j['virtual-size'] || null,
      actualSize: j['actual-size'] || null,
      reason: j['format'] !== 'qcow2' && j['format'] !== 'raw' ? `unsupported format ${j['format']}` : null
    };
  } catch (e) {
    return { exists: true, valid: false, reason: (e.stderr || e.message || '').slice(0, 200) };
  }
}

// ---------------------------------------------------------------
// Template cache + download (http/https only, redirect-aware)
// ---------------------------------------------------------------
const _inFlight = new Map();

// ---------------------------------------------------------------
// MIRROR DOWNLOAD FIX (broken IPv6 / IPv4 egress resilience)
// ---------------------------------------------------------------
// Same defect as the panel on hosts with a global IPv6 address but broken
// v6 egress: getaddrinfo returns AAAA first, the first connect black-holes
// at the TCP layer, and template downloads die with no HTTP response while
// curl/git on the same node work fine. httpDownload() now resolves the host
// into an ordered list (IPv4 first by default; VNM_PREFER_IPV6=1 flips) and
// tries each address in sequence, advancing only on connect-layer failures.
const AGENT_ADDR_CONNECT_TIMEOUT_MS = parseInt(process.env.AGENT_ADDR_CONNECT_TIMEOUT_MS) || 6000;
const _hostResolveCache = new Map();
const HOST_RESOLVE_TTL_MS = 60 * 1000;

function _preferIPv6() {
  const v = String(process.env.VNM_PREFER_IPV6 || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

async function _resolveHostCandidates(host) {
  const literal = net.isIP(host);
  if (literal) return [{ address: host, family: literal }];
  const cached = _hostResolveCache.get(host);
  if (cached && cached.expires > Date.now()) return cached.list.slice();
  const all = await dns.promises.lookup(host, { all: true, verbatim: true });
  const v4 = all.filter(a => a.family === 4);
  const v6 = all.filter(a => a.family === 6);
  let list = _preferIPv6() ? [...v6, ...v4] : [...v4, ...v6];
  const seen = new Set();
  list = list.filter(a => !seen.has(a.address) && seen.add(a.address));
  _hostResolveCache.set(host, { expires: Date.now() + HOST_RESOLVE_TTL_MS, list });
  return list.slice();
}

function _pinnedLookup(addr) {
  return function pinnedLookup(hostname, options, callback) {
    if (options && options.all) {
      return callback(null, [{ address: addr.address, family: addr.family }]);
    }
    return callback(null, addr.address, addr.family);
  };
}

// Public entry: iterate the host's resolved addresses for one URL.
async function httpDownload(url, destPath, redirectsLeft = 6) {
  let host = null;
  try { host = new URL(url).hostname; } catch (e) { host = null; }
  if (!host || net.isIP(host)) return httpDownloadVia(url, destPath, redirectsLeft, null);

  const candidates = await _resolveHostCandidates(host);
  if (!candidates.length) {
    throw Object.assign(new Error(`Could not resolve ${host} (no usable A/AAAA records)`), { code: 'DNS_FAILURE' });
  }
  const attempted = [];
  let lastErr = null;
  for (let i = 0; i < candidates.length; i++) {
    const cand = candidates[i];
    try {
      const r = await httpDownloadVia(url, destPath, redirectsLeft, cand);
      console.log(`[Provision] ${host}: connected via ${cand.address} (IPv${cand.family})`);
      return r;
    } catch (e) {
      lastErr = e;
      attempted.push(`${cand.address} (IPv${cand.family}): ${e.statusCode ? 'HTTP ' + e.statusCode : (e.code || 'connect failed')}`);
      if (e.statusCode) break; // server answered; switching address cannot change it
      console.log(`[Provision] ${host}: address ${cand.address} (IPv${cand.family}) failed (${e.code || e.message})${i < candidates.length - 1 ? ' - trying next resolved address' : ' - no more addresses for this host'}`);
    }
  }
  if (lastErr) {
    lastErr.attemptAddresses = attempted;
    lastErr.addressLog = attempted.join('; ');
  }
  throw lastErr;
}

// Original single-URL logic, unchanged apart from the pinned _addr and the
// connect deadline that bounds the time spent reaching THIS address.
function httpDownloadVia(url, destPath, redirectsLeft, _addr) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(url); } catch (e) { return reject(new Error(`Invalid URL: ${url}`)); }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return reject(new Error(`Only http(s) URLs are allowed (got ${parsed.protocol})`));
    }
    const mod = parsed.protocol === 'https:' ? require('https') : require('http');
    // MIRROR DOWNLOAD FIX: _addr pins this attempt to one resolved address
    // (Host header + SNI + cert validation still use the hostname). The
    // connect deadline separately bounds reaching THIS address so a
    // black-holed family fails in seconds instead of minutes.
    let connectDeadline = null;
    const req = mod.get(parsed, {
      headers: { 'User-Agent': 'VNM-NodeAgent/1.4' },
      timeout: 30000,
      lookup: _addr ? _pinnedLookup(_addr) : undefined,
      autoSelectFamily: false
    }, (res) => {
      if (connectDeadline) { clearTimeout(connectDeadline); connectDeadline = null; }
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        if (redirectsLeft <= 0) return reject(new Error('Too many redirects'));
        let next; try { next = new URL(res.headers.location, parsed).toString(); } catch (e) { return reject(new Error('Invalid redirect target')); }
        return httpDownload(next, destPath, redirectsLeft - 1).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        res.resume();
        const e = new Error(`HTTP ${res.statusCode} from ${parsed.hostname}`);
        e.statusCode = res.statusCode;
        return reject(e);
      }
      const out = fs.createWriteStream(destPath);
      res.pipe(out);
      out.on('finish', () => out.close(() => resolve({ bytes: out.bytesWritten || null })));
      out.on('error', (e) => { try { fs.unlinkSync(destPath); } catch (e2) {} reject(e); });
      res.on('error', (e) => { try { fs.unlinkSync(destPath); } catch (e2) {} reject(e); });
    });
    connectDeadline = setTimeout(() => {
      req.destroy(Object.assign(
        new Error(`connect to ${parsed.hostname}${_addr ? ' via ' + _addr.address + ' (IPv' + _addr.family + ')' : ''} timed out after ${AGENT_ADDR_CONNECT_TIMEOUT_MS}ms`),
        { code: 'ETIMEDOUT' }
      ));
    }, AGENT_ADDR_CONNECT_TIMEOUT_MS);
    req.on('timeout', () => req.destroy(new Error('Download timed out (30s with no data)')));
    req.on('error', (e) => {
      if (connectDeadline) clearTimeout(connectDeadline);
      try { fs.unlinkSync(destPath); } catch (e2) {}
      reject(e);
    });
  });
}

async function ensureTemplate({ key, urls }) {
  const finalPath = templatePathFor(key);
  const label = `template ${key}`;

  const cached = await qemuImgInfo(finalPath);
  if (cached.valid) return { path: finalPath, cached: true, virtualSize: cached.virtualSize, actualSize: cached.actualSize };
  if (cached.exists) {
    // A present-but-invalid cache (truncated download, wrong format) is
    // quarantined, never silently reused.
    try { fs.renameSync(finalPath, `${finalPath}.invalid.${Date.now()}`); } catch (e) { try { fs.unlinkSync(finalPath); } catch (e2) {} }
  }

  const urlList = (Array.isArray(urls) ? urls : [urls]).filter(Boolean);
  if (!urlList.length) throw httpError(400, `No download URLs provided for ${label}`, { code: 'NO_TEMPLATE_URLS' });

  if (_inFlight.has(finalPath)) return _inFlight.get(finalPath);
  const work = (async () => {
    const details = [];
    const partPath = `${finalPath}.part`;
    for (let i = 0; i < urlList.length; i++) {
      try {
        console.log(`[Provision] ${label}: downloading candidate ${i + 1}/${urlList.length}`);
        await httpDownload(urlList[i], partPath);
        const check = await qemuImgInfo(partPath);
        if (!check.valid) {
          try { fs.unlinkSync(partPath); } catch (e) {}
          details.push({ url: urlList[i], outcome: 'downloaded_but_invalid', reason: check.reason });
          continue;
        }
        fs.renameSync(partPath, finalPath);
        console.log(`[Provision] ${label}: cached from candidate ${i + 1} (${check.format}, virtual ${Math.round((check.virtualSize || 0) / 1e9)}GB)`);
        return { path: finalPath, cached: false, url: urlList[i], virtualSize: check.virtualSize, actualSize: check.actualSize };
      } catch (e) {
        details.push({ url: urlList[i], outcome: 'download_failed', statusCode: e.statusCode || null, addresses: e.attemptAddresses || null, reason: e.message });
      }
    }
    const noneAnswered = details.some(d => d.outcome === 'download_failed' && !d.statusCode);
    const hint = noneAnswered
      ? ' - no candidate URL ever returned an HTTP response: this is a TCP-level reachability problem (typically broken IPv6 or IPv4 egress on this node), not a mirror outage. Try VNM_PREFER_IPV6=1 (or =0) to flip the address-family order, and check this node\'s network.'
      : '';
    throw httpError(502, `All ${urlList.length} candidate URL(s) failed for ${label}${hint}`, { code: 'TEMPLATE_DOWNLOAD_FAILED', attempts: details });
  })();
  _inFlight.set(finalPath, work);
  try { return await work; } finally { _inFlight.delete(finalPath); }
}

// ---------------------------------------------------------------
// Cloud-init seed ISO
// ---------------------------------------------------------------
let _isoTool = null;
function detectIsoTool() {
  if (_isoTool) return _isoTool;
  for (const tool of ISO_TOOLS) {
    try { execFileSync0(tool, ['--version']); _isoTool = tool; return tool; }
    catch (e) { if (e.code === 'EACCES') throw e; /* not installed, try next */ }
  }
  return null;
}

async function createSeedIso(vmId, { userData, metaData }) {
  const id = cleanVmId(vmId);
  if (!id) throw httpError(400, 'Invalid VM id', { code: 'INVALID_VM_ID' });
  if (typeof userData !== 'string' || !userData.startsWith('#cloud-config')) {
    throw httpError(400, 'user-data must be a cloud-config document starting with #cloud-config', { code: 'INVALID_USER_DATA' });
  }

  const tool = detectIsoTool();
  if (!tool) {
    throw httpError(501, 'No ISO creation tool on this node - install one of: cloud-localds (cloud-utils), genisoimage, xorriso, mkisofs', { code: 'ISO_TOOL_UNAVAILABLE' });
  }

  const seedDir = path.join(VM_DIR, `vm-${id}-seed-dir`);
  const finalPath = seedPathFor(id);
  const partPath = `${finalPath}.part`;
  const userDataFile = path.join(seedDir, 'user-data');
  const metaDataFile = path.join(seedDir, 'meta-data');

  fs.rmSync(seedDir, { recursive: true, force: true });
  fs.rmSync(partPath, { force: true });
  fs.mkdirSync(seedDir, { recursive: true });
  fs.writeFileSync(userDataFile, userData, 'utf8');
  fs.writeFileSync(metaDataFile, typeof metaData === 'string' && metaData.trim() ? metaData : `instance-id: vm-${id}\n`, 'utf8');

  const args = tool === 'cloud-localds'
    ? [partPath, userDataFile, metaDataFile]
    : tool === 'xorriso'
      ? ['-as', 'genisoimage', '-output', partPath, '-volid', 'cidata', '-joliet', '-rock', seedDir]
      : ['-output', partPath, '-volid', 'cidata', '-joliet', '-rock', seedDir];

  try {
    await runFile(tool, args, { timeoutMs: 60000 });
    if (!fs.existsSync(partPath) || fs.statSync(partPath).size === 0) throw new Error('ISO tool produced no output file');
    fs.renameSync(partPath, finalPath);
  } catch (e) {
    try { fs.unlinkSync(partPath); } catch (e2) {}
    throw httpError(500, `Cloud-init seed ISO creation failed: ${e.message}`, { code: 'SEED_ISO_FAILED' });
  } finally {
    fs.rmSync(seedDir, { recursive: true, force: true });
  }
  return { path: finalPath, bytes: fs.statSync(finalPath).size, tool };
}

// ---------------------------------------------------------------
// Disk creation / resize / cleanup
// ---------------------------------------------------------------
async function assertFreeSpace(neededBytes, label) {
  const usage = await systemInfo.diskUsage(VM_DIR);
  if (usage.freeBytes !== null && neededBytes > usage.freeBytes) {
    throw httpError(507, `Not enough free disk space on this node for ${label} (need ~${Math.ceil(neededBytes / 1e9)}GB, have ${Math.floor(usage.freeBytes / 1e9)}GB)`, { code: 'DISK_FULL' });
  }
}

async function createDiskFromTemplate(vmId, templatePath, diskSize) {
  const id = cleanVmId(vmId);
  const sizeBytes = parseDiskSize(diskSize);
  if (!id) throw httpError(400, 'Invalid VM id', { code: 'INVALID_VM_ID' });
  if (!sizeBytes) throw httpError(400, `Invalid disk size "${diskSize}" (use e.g. 20G, 512M)`, { code: 'INVALID_DISK_SIZE' });

  const bin = detectQemuImg();
  if (!bin) throw httpError(501, 'qemu-img is not available on this node (set QEMU_IMG_BIN or install qemu-utils)', { code: 'QEMU_IMG_UNAVAILABLE' });

  const finalPath = diskPathFor(id);
  const partPath = `${finalPath}.part`;
  const tmpl = await qemuImgInfo(templatePath);
  if (!tmpl.valid) throw httpError(422, `Template image is not usable: ${tmpl.reason || templatePath}`, { code: 'TEMPLATE_INVALID' });

  await assertFreeSpace(Math.max(tmpl.actualSize || 0, 512 * 1024 * 1024) + Math.round(sizeBytes * 0.05), 'disk creation');

  fs.rmSync(partPath, { force: true });
  try {
    await runFile(bin, ['convert', '-O', 'qcow2', templatePath, partPath], { timeoutMs: 20 * 60 * 1000 });
    const grown = await qemuImgInfo(partPath);
    if (grown.virtualSize && grown.virtualSize > sizeBytes) {
      throw httpError(409, `Requested disk size (${diskSize}) is smaller than the template image (${(grown.virtualSize / 1024 ** 3).toFixed(1)}GB) - pick a larger size`, { code: 'TEMPLATE_LARGER_THAN_REQUESTED' });
    }
    if (grown.virtualSize !== sizeBytes) {
      await runFile(bin, ['resize', partPath, String(diskSize).trim()], { timeoutMs: 60000 });
    }
    fs.renameSync(partPath, finalPath);
  } catch (e) {
    try { fs.unlinkSync(partPath); } catch (e2) {}
    if (e.httpStatus) throw e;
    throw httpError(500, `Disk creation failed: ${e.message}${e.stderr ? ` (${e.stderr.trim()})` : ''}`, { code: 'DISK_CREATE_FAILED' });
  }
  const fin = await qemuImgInfo(finalPath);
  return { path: finalPath, virtualSize: fin.virtualSize, actualSize: fin.actualSize };
}

async function createBlankDisk(vmId, diskSize) {
  const id = cleanVmId(vmId);
  const sizeBytes = parseDiskSize(diskSize);
  if (!id) throw httpError(400, 'Invalid VM id', { code: 'INVALID_VM_ID' });
  if (!sizeBytes) throw httpError(400, `Invalid disk size "${diskSize}"`, { code: 'INVALID_DISK_SIZE' });
  const bin = detectQemuImg();
  if (!bin) throw httpError(501, 'qemu-img is not available on this node', { code: 'QEMU_IMG_UNAVAILABLE' });
  await assertFreeSpace(Math.round(sizeBytes * 0.05) + 64 * 1024 * 1024, 'disk creation');

  const finalPath = diskPathFor(id);
  const partPath = `${finalPath}.part`;
  fs.rmSync(partPath, { force: true });
  try {
    await runFile(bin, ['create', '-f', 'qcow2', partPath, String(diskSize).trim()], { timeoutMs: 60000 });
    fs.renameSync(partPath, finalPath);
  } catch (e) {
    try { fs.unlinkSync(partPath); } catch (e2) {}
    throw httpError(500, `Disk creation failed: ${e.message}`, { code: 'DISK_CREATE_FAILED' });
  }
  return { path: finalPath, virtualSize: sizeBytes };
}

async function resizeDisk(vmId, newSize, { shrink = false } = {}) {
  const id = cleanVmId(vmId);
  const sizeBytes = parseDiskSize(newSize);
  if (!id) throw httpError(400, 'Invalid VM id', { code: 'INVALID_VM_ID' });
  if (!sizeBytes) throw httpError(400, `Invalid disk size "${newSize}"`, { code: 'INVALID_DISK_SIZE' });
  const bin = detectQemuImg();
  if (!bin) throw httpError(501, 'qemu-img is not available on this node', { code: 'QEMU_IMG_UNAVAILABLE' });
  const diskPath = diskPathFor(id);
  if (!fs.existsSync(diskPath)) throw httpError(404, 'VM disk not found on this node', { code: 'DISK_NOT_FOUND' });
  const running = qemu.statusVM({ vm_id: id });
  if (running.running) throw httpError(409, 'Stop the VM before resizing its disk', { code: 'VM_RUNNING' });

  const cur = await qemuImgInfo(diskPath);
  if (!shrink && cur.virtualSize && sizeBytes < cur.virtualSize) {
    throw httpError(409, `Shrinking a disk destroys data - pass shrink:true to confirm (current ${(cur.virtualSize / 1024 ** 3).toFixed(1)}GB, asked ${(sizeBytes / 1024 ** 3).toFixed(1)}GB)`, { code: 'SHRINK_REQUIRES_CONFIRM' });
  }
  if (sizeBytes > (cur.virtualSize || 0)) await assertFreeSpace(sizeBytes - (cur.virtualSize || 0), 'disk resize');
  try {
    await runFile(bin, shrink ? ['resize', '--shrink', diskPath, String(newSize).trim()] : ['resize', diskPath, String(newSize).trim()], { timeoutMs: 10 * 60 * 1000 });
  } catch (e) {
    throw httpError(500, `Disk resize failed: ${e.message}${e.stderr ? ` (${e.stderr.trim()})` : ''}`, { code: 'DISK_RESIZE_FAILED' });
  }
  const fin = await qemuImgInfo(diskPath);
  return { path: diskPath, virtualSize: fin.virtualSize };
}

function isPortFree(port) {
  return new Promise((resolve) => {
    const tester = net.createServer();
    tester.once('error', () => resolve(false));
    tester.once('listening', () => tester.close(() => resolve(true)));
    tester.listen(port, '0.0.0.0');
  });
}

// Verify the requested SSH forward port is actually free on this node;
// if it's taken, walk upward to the next free one (the panel then
// persists whatever we return). Uniqueness ACROSS VMs on this node is
// the panel's job (DB); liveness is ours (bind probe).
async function resolveSshPort(requested) {
  let port = parseInt(requested, 10);
  if (!(port >= 1 && port <= 65535)) port = 2222;
  for (let i = 0; i < 500; i++) {
    if (await isPortFree(port + i)) return port + i;
  }
  throw httpError(503, 'No free SSH port on this node', { code: 'NO_FREE_PORT' });
}

function cleanupVm(vmId) {
  const id = cleanVmId(vmId);
  if (!id) throw httpError(400, 'Invalid VM id', { code: 'INVALID_VM_ID' });
  // Stop first (best effort) so a running QEMU can't keep writing into
  // files we're about to delete. Never throws.
  try { qemu.stopVM({ vm_id: id }); } catch (e) { /* already gone */ }
  const removed = [];
  for (const suffix of ['-disk.qcow2', '-disk.qcow2.part', '-seed.iso', '-seed.iso.part', '-seed-dir', '.pid', '.log', '.vnc.json', '.hmp']) {
    const p = path.join(VM_DIR, `vm-${id}${suffix}`);
    try {
      if (fs.existsSync(p)) { fs.rmSync(p, { recursive: true, force: true }); removed.push(path.basename(p)); }
    } catch (e) { /* best effort */ }
  }
  return { removed };
}

module.exports = {
  VM_DIR, TEMPLATES_DIR,
  cleanVmId, parseDiskSize,
  diskPathFor, seedPathFor, templatePathFor, streamedPathFor,
  detectQemuImg, qemuImgInfo, detectIsoTool,
  ensureTemplate, createSeedIso, createDiskFromTemplate, createBlankDisk,
  resizeDisk, resolveSshPort, isPortFree, cleanupVm, assertFreeSpace,
  httpError
};
