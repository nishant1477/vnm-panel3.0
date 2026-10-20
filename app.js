const express = require('express');
const http = require('http');
const https = require('https');
const WebSocket = require('ws');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const net = require('net');
const dns = require('dns');
const { spawn, exec, execSync, execFileSync } = require('child_process');
const os = require('os');
const util = require('util');
const execPromise = util.promisify(exec);
const { Client } = require('ssh2');
require('dotenv').config();
const licenses = require("./licenses");
const premium = require("./premium");

// MIRROR DOWNLOAD FIX: enable Node's Happy Eyeballs for ALL outbound sockets
// in this process (template downloads, Discord OAuth, monitoring webhooks,
// license checks). On hosts with a global IPv6 address but broken v6 egress,
// the default resolver order (AAAA first) black-holes connects while curl
// and git keep working - racing both families fixes the whole class of
// "panel cannot reach the internet" reports, not just template downloads.
// Opt out with VNM_NO_HAPPY_EYEBALLS=1; silently a no-op on Node versions
// that lack the API (the per-address fallback in the downloader below still
// applies there).
try {
  if (process.env.VNM_NO_HAPPY_EYEBALLS !== '1' && typeof net.setDefaultAutoSelectFamily === 'function') {
    net.setDefaultAutoSelectFamily(true);
    if (typeof net.setDefaultAutoSelectFamilyAttemptTimeout === 'function') {
      net.setDefaultAutoSelectFamilyAttemptTimeout(750);
    }
    console.log('[NET] Happy Eyeballs enabled for all outbound sockets (disable with VNM_NO_HAPPY_EYEBALLS=1)');
  }
} catch (_happyEyeballsErr) { /* ancient Node - downloader-level fallback still applies */ }

// ============= PLATFORM DETECTION =============
const isWindows = process.platform === 'win32';
const isLinux = process.platform === 'linux';

// ============= CONSTANTS =============
const DEFAULT_SSH_PORT = 2222;

// ============= VNM SHIELD (v3.0) — early reference holder =============
// shield.js is instantiated further down (it needs db/nodeManager), but the
// global error handlers below and the emergency gate middleware want to
// reach it. This holder is filled during boot, BEFORE the server accepts
// a single connection (server.listen is deferred until schema bootstrap).
const shieldRef = { processError: null, gate: null, recordLogin: null };

// ============= GLOBAL ERROR SAFETY NETS (AUDIT FIX #13) =============
// Previously the process had no top-level handlers, so a single unhandled
// rejection or a stray 'error' event anywhere (a Promise never .catch()'d,
// an EventEmitter without an 'error' listener) would crash the whole panel
// and take down every running VM's management state with it. We keep the
// process alive and log loudly instead, since a management panel should
// degrade gracefully rather than die on one bad request.
// SHIELD: every such error also reaches the Error Teller (diagnosis +
// incident grouping + notifications), throttled per fingerprint.
process.on('unhandledRejection', (reason, promise) => {
  console.error('[FATAL-SAFE] Unhandled Promise rejection:', reason && reason.stack ? reason.stack : reason);
  if (shieldRef.processError) { try { shieldRef.processError('unhandledRejection', reason); } catch (e) { /* shield must never crash us */ } }
});
process.on('uncaughtException', (err) => {
  console.error('[FATAL-SAFE] Uncaught exception:', err && err.stack ? err.stack : err);
  // Do not exit: an uncaught exception here is almost always inside a
  // single request/VM-action handler, not a truly fatal startup condition.
  if (shieldRef.processError) { try { shieldRef.processError('uncaughtException', err); } catch (e) { /* shield must never crash us */ } }
});

// ============= QEMU BINARY DETECTION (AUDIT FIX #3) =============
// Detect an available QEMU binary once at startup instead of hard-coding
// 'qemu-system-x86_64' and letting spawn() fail with an opaque ENOENT deep
// inside VM startup. Honors QEMU_BIN env override for non-standard installs.
let _qemuBinCache = null;
function resolveQemuBinary() {
  if (_qemuBinCache) return _qemuBinCache;
  // AUDIT FIX (regression found this session): only ever cache a
  // POSITIVE result. The previous version cached a negative ("not found")
  // result forever, using `_qemuBinCache !== null` as the cache-hit check
  // with `false` as the negative sentinel - but `false !== null` is true,
  // so one failed lookup (e.g. a transient shell-spawn hiccup, or simply
  // running this check before PATH was fully set up at boot) permanently
  // wedged every VM start for every OS/template behind a false
  // "QEMU binary not found" error for the lifetime of the process, with no
  // way to recover short of restarting the panel - exactly the "VM_START_
  // FAILED across multiple different OSes" symptom this was causing. Not
  // caching failures costs one cheap shell lookup per failed start attempt,
  // which is negligible next to never being able to start a VM again.
  const candidates = [
    process.env.QEMU_BIN,
    'qemu-system-x86_64',
    'qemu-system-x86_64.exe',
    '/usr/bin/qemu-system-x86_64',
    '/usr/libexec/qemu-kvm'
  ].filter(Boolean);
  for (const bin of candidates) {
    try {
      if (path.isAbsolute(bin)) {
        if (fs.existsSync(bin)) { _qemuBinCache = bin; break; }
      } else {
        const whichCmd = isWindows ? `where ${bin}` : `command -v ${bin}`;
        execSync(whichCmd, { stdio: 'pipe', shell: isWindows ? 'cmd' : '/bin/bash' });
        _qemuBinCache = bin;
        break;
      }
    } catch (e) { /* try next candidate */ }
  }
  return _qemuBinCache || false; // false (not cached) if none found this time
}

// ============= CLOUD-INIT ISO TOOL DETECTION (AUDIT FIX #9) =============
// Detect every supported ISO-generation tool once (instead of blindly
// try/catching each one at ISO-build time, which can misreport a tool as
// "missing" for unrelated reasons) and remember which one is usable.
let _isoToolCache = null;
function detectIsoTool() {
  if (_isoToolCache) return _isoToolCache;
  // Same fix as resolveQemuBinary() above: only cache a positive result.
  const checks = isWindows
    ? [{ name: 'mkisofs', cmd: 'where mkisofs' }]
    : [
        { name: 'cloud-localds', cmd: 'command -v cloud-localds' },
        { name: 'genisoimage', cmd: 'command -v genisoimage' },
        { name: 'xorriso', cmd: 'command -v xorriso' },
        { name: 'mkisofs', cmd: 'command -v mkisofs' }
      ];
  for (const c of checks) {
    try {
      execSync(c.cmd, { stdio: 'pipe', shell: isWindows ? 'cmd' : '/bin/bash' });
      _isoToolCache = c.name;
      return _isoToolCache;
    } catch (e) { /* not available, try next */ }
  }
  return false; // not cached - re-check next call instead of wedging forever
}

// ============= UTILITY FUNCTIONS =============

/**
 * Get validated SSH port from VM
 * Consolidates ssh_port and ssh_port_static into single value
 */
// Verify a PID actually belongs to a QEMU process before signaling it, so a
// PID file left over from a crashed/restarted VM can't cause us to kill an
// unrelated process that the OS has since reused that PID for (#24).
function isPidQemu(pid) {
  if (!pid || isNaN(pid)) return false;
  try {
    process.kill(pid, 0); // throws if the process doesn't exist / no permission
  } catch (e) {
    return false;
  }
  if (isLinux) {
    try {
      const cmdline = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8');
      return cmdline.includes('qemu');
    } catch (e) {
      return true; // /proc unavailable — fall back to trusting the kill(0) check
    }
  }
  return true;
}

function getSSHPort(vm) {
  const port = vm.ssh_port || vm.ssh_port_static || DEFAULT_SSH_PORT;
  const portNum = parseInt(port);
  if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
    return DEFAULT_SSH_PORT;
  }
  return portNum;
}

// AUDIT FIX (deep scan): disk_size flows from req.body straight into
// unquoted shell strings passed to execSync (`qemu-img resize/create ...
// ${diskSizeVal}`) at VM create, reinstall, and edit time. There was no
// format validation anywhere on that path, so a value like
// `20G; rm -rf /` would pass through as-is - a real command-injection
// vector, not just a cosmetic one, since VM create/edit is reachable by
// any authenticated user, not only admins depending on config. Anchored
// regex (same shape as the existing, already-safe parseSize in
// resizeDisk) rejects anything that isn't a bare number+unit.
function sanitizeDiskSize(sizeStr, fallback = '20G') {
  const s = String(sizeStr == null ? '' : sizeStr).trim();
  if (!s) return fallback;
  if (!/^\d+(?:\.\d+)?[KMGT]B?$/i.test(s)) {
    const err = new Error(`Invalid disk size "${s}" - expected a plain value like 20G, 100GB, 1T`);
    err.code = 'INVALID_DISK_SIZE';
    throw err;
  }
  return s;
}



/**
 * Log errors with VM context
 */
function logError(component, vm_id, action, error) {
  console.error(`[${component}-${vm_id}] ${action} FAILED: ${error.message}`);
  if (error.stack) {
    console.error(`[${component}-${vm_id}] Stack: ${error.stack}`);
  }
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// --- Lightweight in-memory rate limiter (no extra dependency) ---
// Tracks attempts per key (IP, or IP+userId) within a sliding window.
const _rateBuckets = new Map();
function rateLimit({ windowMs, max, keyFn, message }) {
  return (req, res, next) => {
    const key = keyFn(req);
    const now = Date.now();
    let bucket = _rateBuckets.get(key);
    if (!bucket || now - bucket.start > windowMs) {
      bucket = { start: now, count: 0 };
      _rateBuckets.set(key, bucket);
    }
    bucket.count++;
    if (bucket.count > max) {
      return res.status(429).json({ error: message || 'Too many requests, please try again later.' });
    }
    next();
  };
}
// Periodically clear stale buckets so the map doesn't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of _rateBuckets.entries()) {
    if (now - bucket.start > 30 * 60 * 1000) _rateBuckets.delete(key);
  }
}, 5 * 60 * 1000).unref();

const loginRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 8,
  keyFn: (req) => `login:${req.ip}`,
  message: 'Too many login attempts. Please wait a minute and try again.'
});
const vmActionRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  keyFn: (req) => `vmaction:${req.session?.userId || req.ip}`,
  message: 'Too many VM actions. Please slow down.'
});
const sshConnectRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  keyFn: (req) => `ssh:${req.session?.userId || req.ip}`,
  message: 'Too many SSH connection attempts. Please wait a minute.'
});
const PORT = process.env.PORT || 8080;

// For binary: use home directory or custom location for database
// __dirname will be /snapshot/vnm (read-only in binary), so use home directory
const dbDir = process.env.VNM_DATA_DIR || path.join(os.homedir(), '.vnm');
const dbPath = path.join(dbDir, 'vnm.db');

// Ensure database directory exists and is writable
try {
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true, mode: 0o755 });
    console.log('[Init] Created database directory:', dbDir);
  }
} catch (error) {
  console.error('[Init] Failed to create database directory:', dbDir, error.message);
  process.exit(1);
}

const db = new sqlite3.Database(dbPath);

const VM_DIR = path.join(os.homedir(), 'vms');
const TEMPLATES_DIR = path.join(VM_DIR, 'templates');
const ISO_DIR = path.join(VM_DIR, 'iso');
const CLOUDVM_DIR = path.join(VM_DIR, 'cloudvm');

// Create directories if they don't exist
if (!fs.existsSync(VM_DIR)) {
  fs.mkdirSync(VM_DIR, { recursive: true });
}
if (!fs.existsSync(TEMPLATES_DIR)) {
  fs.mkdirSync(TEMPLATES_DIR, { recursive: true });
}
if (!fs.existsSync(ISO_DIR)) {
  fs.mkdirSync(ISO_DIR, { recursive: true });
}

// ============= LOCAL VNC DISPLAY ALLOCATION =============
// Mirrors node-agent/lib/qemu-launcher.js's allocator for VMs that run
// directly on this (local) node. Ports are localhost-only and reached
// exclusively through the /vnc-console WebSocket relay below - never
// exposed on their own.
const _localVncDisplays = new Set();
// DEEP FIX (SSH port allocation race, module scope): in-flight SSH port
// reservations shared across ALL concurrent VM creates. Declaring this
// inside the route handler gave every request its own empty Set, so
// concurrent creators never saw each other's reservations and all claimed
// the same port.
const _sshPortReservations = new Set();
const VNC_BASE_PORT = 5900;
const VNC_MAX_DISPLAYS = 200;
function localVncInfoPath(vmId) { return path.join(VM_DIR, `vm-${vmId}.vnc.json`); }
function isLocalPortFree(port) {
  return new Promise((resolve) => {
    const tester = net.createServer();
    tester.once('error', () => resolve(false));
    tester.once('listening', () => tester.close(() => resolve(true)));
    tester.listen(port, '127.0.0.1');
  });
}
async function allocateLocalVncDisplay() {
  for (let d = 0; d < VNC_MAX_DISPLAYS; d++) {
    if (_localVncDisplays.has(d)) continue;
    // DEEP FIX (race): reserve synchronously BEFORE the async port probe.
    // Two concurrent VM starts both passed the has() check, both awaited
    // the probe, and both won the same display; the second QEMU then
    // failed to bind its VNC port. Release the reservation if the probe
    // finds the port taken.
    _localVncDisplays.add(d);
    if (await isLocalPortFree(VNC_BASE_PORT + d)) return d;
    _localVncDisplays.delete(d);
  }
  throw new Error('No free VNC display slots on this node');
}
function releaseLocalVncDisplay(vmId) {
  try {
    const p = localVncInfoPath(vmId);
    if (fs.existsSync(p)) {
      const info = JSON.parse(fs.readFileSync(p, 'utf8'));
      if (typeof info.display === 'number') _localVncDisplays.delete(info.display);
      fs.unlinkSync(p);
    }
  } catch (e) { /* best-effort */ }
}
function getLocalVncInfo(vmId) {
  const p = localVncInfoPath(vmId);
  if (!fs.existsSync(p)) return { available: false };
  try {
    const info = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (!isPidQemu(info.qemuPid)) { releaseLocalVncDisplay(vmId); return { available: false }; }
    return { available: true, host: '127.0.0.1', port: info.port, display: info.display };
  } catch (e) { return { available: false }; }
}
if (!fs.existsSync(CLOUDVM_DIR)) {
  fs.mkdirSync(CLOUDVM_DIR, { recursive: true });
}

// CPU Models available
const CPU_MODELS = {
  'host': {
    name: 'Host CPU (Native)',
    description: 'Use host CPU directly - best performance',
    features: 'host'
  },
  'max': {
    name: 'Maximum Features',
    description: 'Maximum supported features by QEMU',
    features: 'max'
  },
  'qemu64': {
    name: 'QEMU 64-bit',
    description: 'Generic 64-bit processor',
    features: 'qemu64'
  },
  'kvm64': {
    name: 'KVM 64-bit',
    description: 'Optimized for KVM',
    features: 'kvm64'
  },
  'core2duo': {
    name: 'Core 2 Duo',
    description: 'Intel Core 2 Duo',
    features: 'core2duo'
  },
  'corei7': {
    name: 'Core i7',
    description: 'Intel Core i7',
    // 'corei7' is not a real QEMU model name (QEMU refuses to start);
    // Haswell is the classic i7-class model this preset maps to.
    features: 'Haswell'
  },
  'skylake': {
    name: 'Skylake',
    description: 'Intel Skylake',
    features: 'Skylake-Client'
  },
  'cascadelake': {
    name: 'Cascade Lake',
    description: 'Intel Cascade Lake (Server)',
    features: 'Cascadelake-Server'
  },
  'opteron': {
    name: 'Opteron',
    description: 'AMD Opteron',
    features: 'opteron'
  },
  'epyc': {
    name: 'EPYC',
    description: 'AMD EPYC (Server)',
    features: 'EPYC'
  }
};

// Machine Types available for QEMU
const MACHINE_TYPES = {
  'pc': {
    name: 'PC (i440fx - Standard)',
    description: 'Legacy PC emulation, compatible with old guests',
    arch: 'x86_64',
    features: 'Legacy BIOS, VGA, ISA/PCI buses'
  },
  'q35': {
    name: 'Q35 (ICH9 - Modern)',
    description: 'Modern chipset, recommended for newer OS',
    arch: 'x86_64',
    features: 'UEFI-ready, PCIe support, higher performance'
  },
  'microvm': {
    name: 'MicroVM (Minimal)',
    description: 'Lightweight machine type with minimal overhead',
    arch: 'x86_64',
    features: 'Fast boot, low memory footprint, optimal for containers'
  },
  'virt': {
    name: 'Virtual (ARM Generic)',
    description: 'Generic virtual platform for ARM64',
    arch: 'aarch64',
    features: 'ARM64 architecture, flexible device model'
  },
  'versatilepb': {
    name: 'Versatile Platform Baseboard (ARM)',
    description: 'ARM reference board platform',
    arch: 'arm',
    features: 'ARM 32-bit, integrator-style board'
  },
  'raspi2': {
    name: 'Raspberry Pi 2 (ARM)',
    description: 'Emulate Raspberry Pi 2 hardware',
    arch: 'arm',
    features: 'ARM-based SBC, GPIO and peripherals'
  },
  'raspi3': {
    name: 'Raspberry Pi 3 (ARM)',
    description: 'Emulate Raspberry Pi 3 hardware',
    arch: 'arm',
    features: 'ARM 64-bit, WiFi/Bluetooth simulation'
  },
  'pseries': {
    name: 'POWER Series (PowerPC)',
    description: 'IBM Power Systems emulation',
    arch: 'ppc64',
    features: 'PowerPC 64-bit, server-class machine'
  },
  's390-ccw-virtio': {
    name: 'IBM System Z (s390x)',
    description: 'IBM mainframe architecture',
    arch: 's390x',
    features: 's390x architecture, enterprise computing'
  }
};

// Network Configuration Types
const NETWORK_TYPES = {
  nat: {
    name: 'NAT (User Mode)',
    description: 'User-mode networking with automatic port forwarding',
    icon: '<svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color: #3B82F6;"><rect x="2" y="2" width="20" height="20" rx="2"/><path d="M12 2v20M2 12h20M6 6h12M6 12h12M6 18h12"/></svg>'
  },
  static_public: {
    name: 'Static Public IPv4',
    description: 'Fixed public IP with bridge network',
    icon: '<svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color: #10B981;"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.88 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12.88"/></svg>'
  }
};

// DNS Providers
const DNS_PROVIDERS = [
  { name: 'Google DNS', primary: '8.8.8.8', secondary: '8.8.4.4' },
  { name: 'Cloudflare DNS', primary: '1.1.1.1', secondary: '1.0.0.1' },
  { name: 'Quad9 DNS', primary: '9.9.9.9', secondary: '149.112.112.112' },
  { name: 'OpenDNS', primary: '208.67.222.222', secondary: '208.67.220.220' },
  { name: 'Custom', primary: '', secondary: '' }
];

// SMBIOS Manufacturers
const SMBIOS_MANUFACTURERS = [
  'QEMU',
  'Proxmox',
  'Red Hat',
  'VirtualBox',
  'Microsoft Corporation',
  'Dell Inc.',
  'HP Inc.',
  'Lenovo',
  'Custom'
];

// SMBIOS Products
const SMBIOS_PRODUCTS = [
  'KVM Virtual Machine',
  'Standard PC',
  'RHEL Guest',
  'VirtualBox',
  'Virtual Machine',
  'Custom VM',
  'Cloud Instance'
];
// AUDIT FIX (OS template subsystem hardening): every built-in template now
// carries an ARRAY of candidate download URLs (`download_urls`) instead of
// a single hardcoded one, tried in order until one succeeds. `url` is kept
// as `download_urls[0]` for backward compatibility with any code still
// reading `.url` directly. `archived` flags EOL releases so the UI/API can
// show that status instead of implying it's the current recommended image.
//
// Root cause of the reported Fedora 40 404: the hardcoded filename was
// "Fedora-Cloud-Base-40-1.14.x86_64.qcow2" - Fedora's actual naming
// convention places "Generic" before the version and the architecture
// right after "Base": the real file is
// "Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2". Confirmed against
// Fedora's own release tree and multiple independent, current sources
// referencing that exact filename for release 40.
const OS_TEMPLATES = {
  ubuntu_22_cloud: {
    name: 'Ubuntu 22.04 LTS',
    type: 'cloud-init',
    icon: '/images/os/ubuntu.svg',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    // Canonical's "current" symlink for this series - maintained
    // permanently by Canonical for the life of the release, so a single
    // URL here is already the robust choice (no version-pinned filename to
    // go stale). Kept as an array for a consistent code path.
    download_urls: [
      'https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img',
      'https://cloud-images.ubuntu.com/releases/jammy/release/ubuntu-22.04-server-cloudimg-amd64.img'
    ],
    username: 'ubuntu',
    password: 'ubuntu',
    archived: false
  },
  ubuntu_24_cloud: {
    name: 'Ubuntu 24.04 LTS',
    type: 'cloud-init',
    icon: '/images/os/ubuntu.svg',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    download_urls: [
      'https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img',
      'https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img'
    ],
    username: 'ubuntu',
    password: 'ubuntu',
    archived: false
  },
  debian_12_cloud: {
    name: 'Debian 12',
    type: 'cloud-init',
    icon: '/images/os/debian.svg',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    // cloud.debian.org and cdimage.debian.org both serve the official
    // "latest" pointer for this release from the Debian project itself.
    download_urls: [
      'https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2',
      'https://cdimage.debian.org/cdimage/cloud/bookworm/latest/debian-12-generic-amd64.qcow2'
    ],
    username: 'debian',
    password: 'debian',
    archived: false
  },
  fedora_40_cloud: {
    name: 'Fedora 40 (Archived)',
    type: 'cloud-init',
    icon: '/images/os/fedora.svg',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    // Corrected filename (see comment above). Fedora 40 is EOL; try the
    // still-current releases/ tree first (not yet always removed even
    // after EOL), then the permanent archives.fedoraproject.org tree,
    // then the dl.fedoraproject.org mirror alias, in that order.
    download_urls: [
      'https://download.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2',
      'https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2',
      'https://dl.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2'
    ],
    checksum_urls: [
      'https://download.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-40-1.14-x86_64-CHECKSUM'
    ],
    username: 'fedora',
    password: 'fedora',
    archived: true
  },
  fedora_44_cloud: {
    name: 'Fedora 44',
    type: 'cloud-init',
    icon: '/images/os/fedora.svg',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    // Current supported Fedora release (GA 2026-04-28). AUDIT FIX: this was
    // pinned to build "44-1.5", which no longer exists upstream - Fedora
    // bumps the compose/build suffix on respins independent of the release
    // number. Confirmed current build against fedoraproject.org/cloud/download
    // is "44-1.7". This mismatch (not just the Fedora 40 filename convention)
    // is the second, previously-undiagnosed cause of the reported
    // "multiple OS templates" 404s. Both download_urls AND checksum_urls
    // must be bumped together whenever Fedora respins a build - they are
    // NOT independently discovered at runtime.
    download_urls: [
      'https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2',
      'https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2',
      'https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2'
    ],
    checksum_urls: [
      'https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-44-1.7-x86_64-CHECKSUM'
    ],
    username: 'fedora',
    password: 'fedora',
    archived: false
  },
  centos_9_cloud: {
    name: 'CentOS Stream 9',
    type: 'cloud-init',
    icon: '/images/os/centos.svg',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    download_urls: [
      'https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2',
      'https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2'
    ],
    username: 'centos',
    password: 'centos',
    archived: false
  },
  almalinux_9_cloud: {
    name: 'AlmaLinux 9',
    type: 'cloud-init',
    icon: '/images/os/almalinux.svg',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    download_urls: [
      'https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2',
      'https://ftp.osuosl.org/pub/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2'
    ],
    username: 'almalinux',
    password: 'almalinux',
    archived: false
  }
};
// Backward compatibility: any existing code reading `.url` directly still
// gets a working single URL (the first, primary candidate).
Object.values(OS_TEMPLATES).forEach(t => { t.url = t.download_urls[0]; });

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Security headers - lightweight, no new dependency. Applied to every
// response before anything else runs.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '0'); // deprecated header; explicitly disabled rather than relying on legacy browser heuristics
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
if (!process.env.SESSION_SECRET) {
  console.warn('⚠ SESSION_SECRET not set in .env — generating a random one for this run (sessions will not survive restarts).');
}

// Persist sessions in SQLite (the same DB the panel already uses) instead of
// the default in-memory store, so restarting the Node process — or running
// multiple panel instances against the same DB — doesn't silently log
// everyone out / lose active session state.
class SQLiteSessionStore extends session.Store {
  constructor(dbHandle) {
    super();
    this.db = dbHandle;
  }
  get(sid, cb) {
    this.db.get(`SELECT sess, expires FROM sessions WHERE sid = ?`, [sid], (err, row) => {
      if (err) return cb(err);
      if (!row) return cb(null, null);
      if (row.expires < Date.now()) {
        this.db.run(`DELETE FROM sessions WHERE sid = ?`, [sid]);
        return cb(null, null);
      }
      try {
        cb(null, JSON.parse(row.sess));
      } catch (e) {
        cb(null, null);
      }
    });
  }
  set(sid, sessionData, cb) {
    const maxAge = (sessionData.cookie && sessionData.cookie.maxAge) || 24 * 60 * 60 * 1000;
    const expires = Date.now() + maxAge;
    const sess = JSON.stringify(sessionData);
    this.db.run(
      `INSERT INTO sessions (sid, sess, expires) VALUES (?, ?, ?)
       ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expires = excluded.expires`,
      [sid, sess, expires],
      (err) => cb && cb(err)
    );
  }
  destroy(sid, cb) {
    this.db.run(`DELETE FROM sessions WHERE sid = ?`, [sid], (err) => cb && cb(err));
  }
  touch(sid, sessionData, cb) {
    const maxAge = (sessionData.cookie && sessionData.cookie.maxAge) || 24 * 60 * 60 * 1000;
    const expires = Date.now() + maxAge;
    this.db.run(`UPDATE sessions SET expires = ? WHERE sid = ?`, [expires, sid], (err) => cb && cb(err));
  }
}
// Periodically clear expired sessions
setInterval(() => {
  db.run(`DELETE FROM sessions WHERE expires < ?`, [Date.now()]);
}, 15 * 60 * 1000).unref();

const SESSION_SECRET = process.env.SESSION_SECRET || require('crypto').randomBytes(32).toString('hex');
const isProd = process.env.NODE_ENV === 'production';
app.set('trust proxy', 1);
const sessionMiddleware = session({
  store: new SQLiteSessionStore(db),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    // AUDIT FIX (session/CSRF): the installer's default .env ships with
    // NODE_ENV=production, which made this `secure: isProd` -> `secure:
    // true` unconditionally. A cookie marked Secure is refused by every
    // browser (and dropped by curl) over a plain-HTTP connection, which is
    // exactly how most freshly-installed panels are first reached (no
    // reverse proxy/TLS yet). The practical effect: login appears to
    // "succeed" (200 OK) but the session cookie never actually gets
    // stored, so the very next request looks unauthenticated - a
    // frustrating, hard-to-diagnose production bug that looks like broken
    // auth rather than a cookie policy issue.
    // 'auto' defers the decision to express-session itself, which checks
    // req.secure per-request (honoring 'trust proxy' + X-Forwarded-Proto
    // above) - so it's still Secure when actually served over HTTPS or via
    // a properly configured TLS-terminating reverse proxy, but does not
    // silently break plain-HTTP deployments.
    secure: 'auto',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
});
app.use(sessionMiddleware);

// --- CSRF protection (double-submit cookie pattern) ---
// Every session gets a token; it's exposed via a readable cookie so the
// browser JS can echo it back in a header on state-changing requests.
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = require('crypto').randomBytes(24).toString('hex');
  }
  // Same reasoning as the session cookie above: only mark this Secure when
  // the request actually arrived over HTTPS (directly or via a trusted
  // proxy setting X-Forwarded-Proto), so it isn't silently dropped by the
  // browser on a plain-HTTP install.
  res.cookie('csrf_token', req.session.csrfToken, {
    httpOnly: false,
    sameSite: 'lax',
    secure: req.secure
  });
  next();
});

const CSRF_EXEMPT_PATHS = new Set([
  '/login',           // no session/token to check yet (relative to the '/api' mount below)
  '/auth/discord',    // OAuth redirect flows
  '/auth/discord/callback'
]);
function csrfProtection(req, res, next) {
  const mutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
  // AUDIT FIX (CSRF): this middleware is mounted with app.use('/api', ...),
  // so Express strips the '/api' prefix and req.path here is already
  // relative (e.g. '/login', not '/api/login'). The exempt-path set and the
  // startsWith check below previously compared against the *full* path,
  // which could never match — meaning the login exemption silently never
  // applied. In practice /api/login was still reachable only because every
  // response (including the login page's own GET) sets a csrf_token
  // cookie/session token on first contact, but the login page's own fetch()
  // call doesn't attach that header (only pages using the admin footer's
  // fetch-patching script do), so this bug currently makes POST /api/login
  // fail with 403 "Invalid or missing CSRF token" for a fresh session.
  if (!mutating || CSRF_EXEMPT_PATHS.has(req.path) || req.path.startsWith('/auth/') || req.bearerApiKey) {
    return next();
  }
  const headerToken = req.get('x-csrf-token');
  if (!headerToken || headerToken !== req.session.csrfToken) {
    console.warn(`[CSRF] Rejected ${req.method} ${req.path} (bad/missing token) from ${req.ip}`);
    return res.status(403).json({ error: 'Invalid or missing CSRF token' });
  }
  next();
}
// PLATFORM (Round 5): API-key auth resolves BEFORE CSRF, because a
// machine client presenting a Bearer key has no browser session and so
// no CSRF token to echo back - the key itself is the authenticator.
const apiKeyAuth = require('./api-keys')(db);
app.use('/api', apiKeyAuth);
app.use('/api', csrfProtection);

// ============= VNM SHIELD: Emergency lockdown gate =============
// Mounted EARLY (before any mutating route) so emergency mode blocks risky
// operations no matter where their handlers live. Read-only requests are
// never blocked; login/logout and the emergency endpoints themselves stay
// available (see shield-emergency.gateRequest). The gate function is
// attached by shield.js during boot; until then everything passes.
app.use((req, res, next) => {
  if (shieldRef.gate && req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'OPTIONS') {
    try {
      const decision = shieldRef.gate(req, req.session);
      if (decision && decision.blocked) {
        return res.status(423).json({ error: decision.reason, emergency: true });
      }
    } catch (e) { /* a broken gate must never lock the whole panel */ }
  }
  next();
});

// Resolve an authenticated session (userId/role) for a WebSocket upgrade request.
// Reuses the same express-session middleware/store used for normal HTTP auth.
function getWsSession(req) {
  return new Promise((resolve) => {
    sessionMiddleware(req, {}, () => {
      if (req.session && req.session.userId) {
        resolve({ userId: req.session.userId, role: req.session.role, username: req.session.username });
      } else {
        resolve(null);
      }
    });
  });
}

// Initialize License Middleware
licenses.initLicenseMiddleware(app);

// Set EJS as view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// VM Process Manager (Global)
const vmProcesses = new Map();
// Store QEMU process stdin for console input
const qemuStdins = new Map();

// Initialize Database
function initializeDatabase(onReady) {
  // Enable WAL mode to reduce locking issues
  db.run('PRAGMA journal_mode = WAL', (err) => {
    if (err) console.log('[DB] Could not enable WAL mode:', err.message);
  });
  
  db.run('PRAGMA busy_timeout = 5000', (err) => {
    if (err) console.log('[DB] Could not set busy timeout:', err.message);
  });
  
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY,
      sess TEXT NOT NULL,
      expires INTEGER NOT NULL
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT,
      full_name TEXT,
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME,
      is_active BOOLEAN DEFAULT 1
    )`);

    // Add missing columns if they don't exist
    db.all(`PRAGMA table_info(users)`, (err, columns) => {
      if (err || !columns) { console.error('[DB] Could not read users table info:', err ? err.message : 'no result'); return; }
      const columnNames = columns.map(c => c.name);
      if (!columnNames.includes('full_name')) {
        db.run(`ALTER TABLE users ADD COLUMN full_name TEXT`, (err) => {
          if (err) console.log('[DB] full_name column already exists or error:', err.message);
        });
      }
      if (!columnNames.includes('last_login')) {
        db.run(`ALTER TABLE users ADD COLUMN last_login DATETIME`, (err) => {
          if (err) console.log('[DB] last_login column already exists or error:', err.message);
        });
      }
      if (!columnNames.includes('max_vms')) {
        db.run(`ALTER TABLE users ADD COLUMN max_vms INTEGER DEFAULT 3`, (err) => {
          if (err) console.log('[DB] max_vms column already exists or error:', err.message);
        });
      }
      if (!columnNames.includes('max_memory_mb')) {
        db.run(`ALTER TABLE users ADD COLUMN max_memory_mb INTEGER DEFAULT 8192`, (err) => {
          if (err) console.log('[DB] max_memory_mb column already exists or error:', err.message);
        });
      }
      if (!columnNames.includes('max_cpus')) {
        db.run(`ALTER TABLE users ADD COLUMN max_cpus INTEGER DEFAULT 8`, (err) => {
          if (err) console.log('[DB] max_cpus column already exists or error:', err.message);
        });
      }
      if (!columnNames.includes('max_disk_gb')) {
        db.run(`ALTER TABLE users ADD COLUMN max_disk_gb INTEGER DEFAULT 200`, (err) => {
          if (err) console.log('[DB] max_disk_gb column already exists or error:', err.message);
        });
      }
      if (!columnNames.includes('totp_secret')) {
        db.run(`ALTER TABLE users ADD COLUMN totp_secret TEXT`, (err) => {
          if (err) console.log('[DB] totp_secret column already exists or error:', err.message);
        });
      }
      if (!columnNames.includes('totp_enabled')) {
        db.run(`ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0`, (err) => {
          if (err) console.log('[DB] totp_enabled column already exists or error:', err.message);
        });
      }
      if (!columnNames.includes('totp_recovery_codes')) {
        db.run(`ALTER TABLE users ADD COLUMN totp_recovery_codes TEXT`, (err) => {
          if (err) console.log('[DB] totp_recovery_codes column already exists or error:', err.message);
        });
      }
    });

    db.run(`CREATE TABLE IF NOT EXISTS vms (
      vm_id INTEGER PRIMARY KEY AUTOINCREMENT,
      vm_name TEXT UNIQUE NOT NULL,
      os_type TEXT,
      template_type TEXT,
      hostname TEXT,
      username TEXT,
      password TEXT,
      memory INTEGER,
      cpus INTEGER,
      cpu_sockets INTEGER DEFAULT 1,
      cpu_cores INTEGER DEFAULT 2,
      cpu_threads INTEGER DEFAULT 1,
      cpu_model TEXT DEFAULT 'host',
      custom_cpu_name TEXT,
      machine_type TEXT DEFAULT 'pc',
      board_name TEXT DEFAULT 'Main-Board',
      product_name TEXT DEFAULT 'Virtual Machine',
      custom_smbios_manufacturer TEXT DEFAULT 'QEMU',
      disk_size TEXT,
      img_file TEXT,
      seed_file TEXT,
      disk_file TEXT,
      status TEXT DEFAULT 'stopped',
      uptime INTEGER DEFAULT 0,
      node_name TEXT DEFAULT 'localhost',
      smbios_manufacturer TEXT DEFAULT 'QEMU',
      smbios_product TEXT DEFAULT 'KVM Virtual Machine',
      smbios_version TEXT DEFAULT '1.0',
      smbios_serial TEXT,
      extra_args TEXT,
      enable_acpi BOOLEAN DEFAULT 1,
      enable_kvm BOOLEAN DEFAULT 1,
      network_type TEXT DEFAULT 'nat',
      ipv4_address TEXT,
      gateway TEXT,
      ipv4_gateway TEXT,
      netmask TEXT DEFAULT '24',
      ipv4_netmask TEXT DEFAULT '255.255.255.0',
      dns_servers TEXT DEFAULT '8.8.8.8,8.8.4.4',
      ssh_port INTEGER,
      ssh_port_static INTEGER DEFAULT 22,
      http_port INTEGER DEFAULT 80,
      ipv6_address TEXT,
      ipv6_gateway TEXT,
      mac_address TEXT,
      bridge_interface TEXT,
      vlan_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      owner_id INTEGER,
      FOREIGN KEY(owner_id) REFERENCES users(id)
    )`);

    // Add missing columns for existing databases (safe - ignores if already exist)
    const missingColumns = [
      { name: 'custom_cpu_name', def: 'TEXT' },
      { name: 'machine_type', def: "TEXT DEFAULT 'pc'" },
      { name: 'board_name', def: "TEXT DEFAULT 'Main-Board'" },
      { name: 'product_name', def: "TEXT DEFAULT 'Virtual Machine'" },
      { name: 'custom_smbios_manufacturer', def: "TEXT DEFAULT 'QEMU'" },
      { name: 'ipv4_netmask', def: "TEXT DEFAULT '255.255.255.0'" },
      { name: 'dns_primary', def: "TEXT DEFAULT '8.8.8.8'" },
      { name: 'dns_secondary', def: "TEXT DEFAULT '8.8.4.4'" },
      { name: 'iso_attached', def: 'TEXT' },
      { name: 'boot_from_iso', def: 'BOOLEAN DEFAULT 0' },
      { name: 'bridge_device', def: "TEXT DEFAULT 'vmbr0'" },
      // Networking upgrades: selectable virtual NIC model (per VM)
      { name: 'nic_model', def: "TEXT DEFAULT 'virtio-net-pci'" },
      // RDP access (rdp.js) - additive columns, safe on existing databases
      ...require('./rdp').RDP_COLUMNS,
      // v2.4.0: start this VM automatically when the panel/host boots
      { name: 'autostart', def: 'INTEGER DEFAULT 0' }
    ];    missingColumns.forEach(col => {
      db.run(`ALTER TABLE vms ADD COLUMN ${col.name} ${col.def}`, (err) => {
        if (err) {
          if (!err.message.includes('duplicate column')) {
            console.log(`Note: Column ${col.name} - ${err.message}`);
          }
        } else {
          console.log(`✓ Added column: ${col.name}`);
        }
      });
    });

    // Custom port-forward rules per VM (extra hostfwd entries beyond SSH).
    // The panel owns uniqueness/validation; the launchers turn each row
    // into a QEMU hostfwd at start time (local launcher + node agent).
    db.run(`CREATE TABLE IF NOT EXISTS vm_port_forwards (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vm_id INTEGER NOT NULL,
      protocol TEXT NOT NULL DEFAULT 'tcp',
      label TEXT,
      host_port INTEGER NOT NULL,
      guest_port INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_port_forwards_vm ON vm_port_forwards(vm_id)`);

    db.run(`CREATE TABLE IF NOT EXISTS vm_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vm_id INTEGER,
      action TEXT,
      status TEXT,
      message TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(vm_id) REFERENCES vms(vm_id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS vm_snapshots (
      snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
      vm_id INTEGER,
      snapshot_name TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      size_gb REAL,
      description TEXT,
      FOREIGN KEY(vm_id) REFERENCES vms(vm_id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS os_templates (
      template_id INTEGER PRIMARY KEY AUTOINCREMENT,
      template_key TEXT UNIQUE NOT NULL,
      template_name TEXT NOT NULL,
      template_type TEXT DEFAULT 'cloud-init',
      icon TEXT,
      description TEXT,
      disk_size TEXT DEFAULT '20G',
      memory INTEGER DEFAULT 2048,
      cpus INTEGER DEFAULT 2,
      download_url TEXT,
      local_path TEXT,
      username TEXT,
      password TEXT,
      is_custom BOOLEAN DEFAULT 0,
      is_active BOOLEAN DEFAULT 1,
      created_by INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(created_by) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      setting_key TEXT UNIQUE NOT NULL,
      setting_value TEXT,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // v2.4.0: per-user SSH public keys. Stored in the user's profile and
    // injected into every VM they own at create/edit/start (cloud-init
    // ssh_authorized_keys) - the classic self-service flow.
    db.run(`CREATE TABLE IF NOT EXISTS ssh_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      public_key TEXT NOT NULL,
      fingerprint TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`, () => {
      db.run(`CREATE INDEX IF NOT EXISTS idx_ssh_keys_user ON ssh_keys(user_id)`);
    });

    // Discord OAuth settings table
        // AUDIT FIX (dead imgur icons): built-in template icons used to hotlink
    // i.imgur.com URLs that now 404. Existing databases still carry them, so
    // re-point any built-in row still using an imgur icon at the matching
    // self-hosted icon (idempotent - matches nothing once migrated).
    const LOCAL_ICON_MIGRATION = {
      ubuntu_22_cloud: '/images/os/ubuntu.svg',
      ubuntu_24_cloud: '/images/os/ubuntu.svg',
      debian_12_cloud: '/images/os/debian.svg',
      fedora_40_cloud: '/images/os/fedora.svg',
      fedora_44_cloud: '/images/os/fedora.svg',
      centos_9_cloud: '/images/os/centos.svg',
      almalinux_9_cloud: '/images/os/almalinux.svg'
    };
    for (const [tplKey, tplIcon] of Object.entries(LOCAL_ICON_MIGRATION)) {
      db.run(`UPDATE os_templates SET icon = ? WHERE template_key = ? AND icon LIKE 'https://i.imgur.com/%'`, [tplIcon, tplKey]);
    }

    // Rebrand: point the default logo at the new mark. Only rows still
    // carrying the OLD default are touched - a custom logo is never
    // overwritten (idempotent - matches nothing once migrated).
    db.run(`UPDATE settings SET setting_value = '/images/logo-new.svg' WHERE setting_key = 'site_icon_url' AND setting_value = '/images/logo.png'`, function () {
      if (this.changes) console.log('Logo rebranded to /images/logo-new.svg (' + this.changes + ' row)');
    });

    db.run(`CREATE TABLE IF NOT EXISTS discord_settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      enabled BOOLEAN DEFAULT 0,
      client_id TEXT,
      client_secret TEXT,
      redirect_uri TEXT,
      bot_token TEXT,
      guild_id TEXT,
      auto_role_id TEXT,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Discord user accounts linking table
    db.run(`CREATE TABLE IF NOT EXISTS user_discord_accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL UNIQUE,
      discord_id TEXT UNIQUE NOT NULL,
      discord_username TEXT,
      discord_email TEXT,
      discord_avatar TEXT,
      connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // Initialize default site settings if not exist
    const defaultSettings = {
      'site_name': 'VNM',
      'site_description': 'Virtual Machine Management System',
      'site_icon_url': '/images/logo-new.svg',
    };
    
    Object.entries(defaultSettings).forEach(([key, value]) => {
      db.get(`SELECT * FROM settings WHERE setting_key = ?`, [key], (err, row) => {
        if (!row) {
          db.run(`INSERT INTO settings (setting_key, setting_value) VALUES (?, ?)`, [key, value]);
        }
      });
    });

    // Add Discord columns to users table if they don't exist
    db.all(`PRAGMA table_info(users)`, (err, columns) => {
      if (columns) {
        const columnNames = columns.map(c => c.name);
        if (!columnNames.includes('discord_id')) {
          db.run(`ALTER TABLE users ADD COLUMN discord_id TEXT`, (err) => {
            if (!err) console.log('✓ Added column: discord_id');
          });
        }
      }
    });

    db.get(`SELECT * FROM users WHERE username = 'admin'`, (err, row) => {
      if (!row) {
        const generatedPassword = require('crypto').randomBytes(12).toString('base64url');
        const hashedPassword = bcrypt.hashSync(generatedPassword, 10);
        db.run(`INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)`,
          ['admin', hashedPassword, 'admin@vnm.local', 'admin']);
        console.log('==========================================================');
        console.log(`✓ Default admin created. username: admin  password: ${generatedPassword}`);
        console.log('  Log in and change this password immediately.');
        console.log('==========================================================');
      } else {
        console.log(`✓ Admin user exists: ${row.username} (role: ${row.role})`);
      }
    });

    // Sentinel statement: since this whole block runs inside db.serialize(),
    // sqlite3 executes queued statements on this connection strictly in
    // order, so by the time this callback fires every CREATE/ALTER/INSERT
    // above it has completed. This lets callers know the schema is ready
    // instead of racing server.listen() against table creation.
    db.run('SELECT 1', () => {
      if (typeof onReady === 'function') onReady();
    });
  });
}

// AUTH
function checkAuth(req, res, next) {
  // PLATFORM (Round 5): a validated Bearer API key synthesizes a
  // per-request session view (never persisted to the session store),
  // so every existing ownership check and role gate below - and in
  // every route - works unchanged for API clients.
  if (!req.session.userId && req.bearerApiKey) {
    const k = req.bearerApiKey;
    // Synthetic per-request session: carries the key owner's identity so
    // every existing ownership/role check works unchanged. Never persisted
    // (save() is a no-op) and provides the method surface express-session's
    // res.end hook expects (touch/save), so responses complete normally.
    req.session = {
      userId: k.userId, username: k.username, role: k.role, apiKey: true,
      cookie: { httpOnly: true, path: '/' },
      touch: function () {},
      save: function (cb) { if (cb) cb(); },
      reload: function (cb) { if (cb) cb(); },
      destroy: function (cb) { if (cb) cb(); },
      regenerate: function (cb) { if (cb) cb(); },
      isModified: function () { return false; },
      isPopulated: function () { return false; },
    };
    return next();
  }
  if (!req.session.userId) {
    console.warn(`[Auth Error] Unauthenticated access attempt to ${req.method} ${req.path}`);
    // Always redirect to login, never return JSON error
    return res.redirect('/login');
  }
  console.log(`[Auth Success] User ${req.session.userId} (${req.session.username}) accessing ${req.method} ${req.path}`);
  next();
}

function checkAdmin(req, res, next) {
  if (!req.session.userId) {
    console.warn(`[Auth Error] Unauthenticated access attempt to admin ${req.method} ${req.path}`);
    // Always redirect to login
    return res.redirect('/login');
  }
  
  if (req.session.role !== 'admin') {
    console.warn(`[Auth Error] Non-admin user ${req.session.userId} (${req.session.username}) attempted admin access to ${req.method} ${req.path}`);
    // Redirect NON-admins to the user dashboard. (This used to point at
    // /admin/dashboard, which is itself admin-only, so non-admins bounced
    // between the two middlewares in an infinite redirect loop.)
    return res.redirect('/dashboard');
  }
  console.log(`[Auth Success] Admin ${req.session.userId} (${req.session.username}) accessing ${req.method} ${req.path}`);
  next();
}

// ============= LIVE VPS FILE MANAGER =============
// Self-contained module (filemanager.js) that talks to each guest VM's
// own filesystem over SFTP, reusing this app's existing session-based
// checkAuth middleware, VM ownership rules, getSSHPort() port
// resolution, and the shared sqlite `db` handle - see that file for
// the full implementation.
// ============= NODES (Local / Remote node abstraction) =============
// See nodes.js for the full node abstraction: DB helpers for the
// `nodes` table, per-node auth tokens, and the agent WebSocket
// connection/command-relay manager used for Remote nodes. Local VMs
// keep using the panel's existing direct QEMU/SSH code paths below -
// unchanged - the node abstraction only takes over for Remote VMs.
const nodeManager = require('./nodes')({ db, logError });

// ============= SECURITY: audit log + 2FA =============
const auditLog = require('./audit')(db);
const twofa = require('./twofa');

const fileManager = require('./filemanager')({ db, checkAuth, getSSHPort, logError, nodeManager });
app.use('/api/vms/:vm_id/files', fileManager.router);

// ============= RDP ACCESS (xrdp + NAT host-port forward) =============
// See rdp.js. Adds GET /api/vms/:id/rdp, POST /api/vms/:id/rdp/enable and
// POST /api/vms/:id/rdp/disable. SSH, VNC/noVNC and the serial console are
// untouched; startQemuVM() only asks this module for an extra hostfwd.
// BUG FIX (RDP setup trusted a stale status column): real liveness check
// for local VMs. If the DB says 'running' but the QEMU process is gone
// (crash after start, stale pid), rdp.js now refuses with an honest error
// and corrects the state instead of hanging on SSH for minutes.
function isQemuProcessAlive(vm) {
  if (!vm || !vm.vm_id) return false;
  const knownPid = vmProcesses.get(vm.vm_id);
  if (knownPid && isPidQemu(knownPid)) return true;
  try {
    const pidFile = path.join(VM_DIR, `vm-${vm.vm_id}.pid`);
    if (fs.existsSync(pidFile)) {
      const pid = parseInt(String(fs.readFileSync(pidFile, 'utf8')).trim(), 10);
      if (!isNaN(pid) && isPidQemu(pid)) return true;
    }
  } catch (e) { /* unreadable pid file */ }
  return false;
}
const rdp = require('./rdp')({ db, checkAuth, getSSHPort, nodeManager, auditLog, logVMAction, VM_DIR, vmRuntime: { isQemuAlive: isQemuProcessAlive }, qemuStdins });
app.use('/api/vms/:vm_id/rdp', rdp.router);

// ============= PLATFORM LAYER (Round 5 - full platform upgrade) =============
// Snapshots & Backup Center (real qemu-img ops, local + remote nodes),
// task engine with progress/retries/schedules, monitoring collector +
// alert rules + Discord webhooks, API keys, audit log viewer, storage
// pools, IP allocation + firewall managers, VM clone/bulk/tags, live
// node-to-node migration, placement recommendations + maintenance mode,
// and global search behind the command palette.
// Created here (needs nodeManager/auditLog above); the ROUTER is mounted
// further down, after the view-locals middleware, so platform-rendered
// pages get siteLogo/siteName/user/panelVersion like every other page -
// and still ahead of the legacy snapshot stubs it supersedes.
const taskEngine = require('./task-engine')({ db, logVMAction });
const monitoring = require('./monitoring')({ db, nodeManager, VM_DIR, execPromise });
const platformOps = require('./platform-ops')({
  db, nodeManager, VM_DIR, logVMAction, execPromise,
  startQemuVM, releaseLocalVncDisplay, vmProcesses, qemuStdins, isPidQemu,
  buildCloudInitFiles, createCloudInitSeed, generateMACAddress, getPortForwards,
});
platformOps.registerTaskHandlers(taskEngine);
const platform = require('./platform')({
  app, db, checkAuth, checkAdmin, nodeManager, auditLog, logVMAction,
  VM_DIR, ISO_DIR, CLOUDVM_DIR, TEMPLATES_DIR, execPromise,
  ops: platformOps, taskEngine, monitoring,
});

// ============= VNM SHIELD (v3.0) — anti-tamper + security + recovery =============
// The full security layer: file integrity, IDS, auto-recovery with circuit
// breakers, encrypted backup vault, VM guardian, verified updater, emergency
// lockdown, notifications/incidents, and the /admin/shield dashboard.
// See shield.js + lib/shield-*.js. Registered after platform so it can see
// the same primitives; routes are mounted immediately (they are additive -
// no existing route is touched). shieldRef hooks (emergency gate, process
// error diagnoser, login history) go live the moment this runs.
const shield = require('./shield')({
  app, db, checkAuth, checkAdmin, auditLog, logError,
  VM_DIR, vmProcesses, isPidQemu: isQemuProcessAlive, dbPath, dataDir: dbDir,
});
shieldRef.gate = (req, session) => shield.gate(req, session);
shieldRef.processError = (kind, err) => shield.processError(kind, err);
shieldRef.recordLogin = (entry) => shield.recordLogin(entry);

// ---- Node management API (Admin → Nodes) ----
app.get('/api/nodes', checkAuth, checkAdmin, async (req, res) => {
  try { res.json({ nodes: await nodeManager.listNodes() }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/nodes', checkAuth, checkAdmin, async (req, res) => {
  try {
    const name = (req.body.name || '').trim();
    if (!name) return res.status(400).json({ error: 'Node name is required' });
    const mode = req.body.mode === 'local' ? 'local' : 'remote';
    if (mode === 'local') return res.status(400).json({ error: 'A Local Node already exists and only one is supported' });
    const { node, token } = await nodeManager.createRemoteNode({ name });
    const panelUrl = `${req.protocol}://${req.get('host')}`;
    const installCommand = `curl -fsSL -H "Authorization: Bearer ${token}" ${panelUrl}/api/nodes/agent-package -o vnm-agent.tar.gz && tar xzf vnm-agent.tar.gz && cd node-agent && sudo bash install.sh --panel-url ${panelUrl} --token ${token}`;
    res.json({ node, token, installCommand });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/nodes/:id/rotate-token', checkAuth, checkAdmin, async (req, res) => {
  try {
    const token = await nodeManager.rotateToken(req.params.id);
    const panelUrl = `${req.protocol}://${req.get('host')}`;
    const installCommand = `curl -fsSL -H "Authorization: Bearer ${token}" ${panelUrl}/api/nodes/agent-package -o vnm-agent.tar.gz && tar xzf vnm-agent.tar.gz && cd node-agent && sudo bash install.sh --panel-url ${panelUrl} --token ${token}`;
    res.json({ success: true, token, installCommand });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.delete('/api/nodes/:id', checkAuth, checkAdmin, async (req, res) => {
  try { await nodeManager.deleteNode(req.params.id); res.json({ success: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});

// Update a node's manual address override: the FQDN/IP users should use
// to reach VMs on that node (shown on the SSH page and in ssh commands).
// Send an empty value to clear back to auto-detection (the socket
// address the agent last dialed in from).
app.put('/api/nodes/:id', checkAuth, checkAdmin, async (req, res) => {
  try {
    const address = String(req.body.address || '').trim();
    if (address && !/^[a-zA-Z0-9][a-zA-Z0-9.:-]{0,253}$/.test(address)) {
      return res.status(400).json({ error: 'Invalid address - use a bare hostname, IPv4, or IPv6 (no spaces, no paths, no http:// prefix)' });
    }
    const node = await nodeManager.setNodeAddress(req.params.id, address || null);
    if (!node) return res.status(404).json({ error: 'Node not found' });
    res.json({ success: true, node: nodeManager.sanitizeNode(node) });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Move a VM to a different node (admin only).
//
// Moving a VM to a REMOTE node really copies its qcow2 disk there (via
// the node agent's verified, flow-controlled transfer) BEFORE the VM's
// node_id is switched - reassigning without the disk would leave the
// remote node reporting "VM disk not found". Rules:
//   - the VM must be stopped (copying a live disk gives a corrupt image)
//   - the target node must be online
//   - the local disk is kept by default (pass delete_source:true to
//     remove it after the remote copy is verified)
//   - large disks take a while, so this returns 202 immediately and the
//     UI polls GET /api/vms/:id/node/migration for progress
// Moving a VM OFF a remote node isn't supported yet (it would need the
// reverse disk pull); that returns 501 rather than silently re-pointing
// the VM at a disk that isn't there.
const migrationJobs = new Map(); // vm_id -> job state

app.get('/api/vms/:vm_id/node/migration', checkAuth, checkAdmin, (req, res) => {
  const job = migrationJobs.get(String(req.params.vm_id));
  if (!job) return res.json({ status: 'none' });
  res.json(job);
});

app.put('/api/vms/:vm_id/node', checkAuth, checkAdmin, async (req, res) => {
  const vmId = String(req.params.vm_id);
  try {
    const target = await nodeManager.getNode(req.body.node_id);
    if (!target) return res.status(404).json({ error: 'Node not found' });

    const vm = await new Promise((resolve, reject) => db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vmId], (e, r) => e ? reject(e) : resolve(r)));
    if (!vm) return res.status(404).json({ error: 'VM not found' });

    const current = await nodeManager.getNodeForVM(vm);
    if (current && current.id === target.id) return res.json({ success: true, unchanged: true, node: nodeManager.sanitizeNode(target) });

    const existing = migrationJobs.get(vmId);
    if (existing && existing.status === 'running') return res.status(409).json({ error: 'A move for this VM is already in progress' });

    if (current && current.mode === 'remote') {
      return res.status(501).json({ error: 'Moving a VM off a remote node is not supported yet - its disk would have to be copied back first. The VM was not changed.', code: 'NOT_SUPPORTED' });
    }
    if (vm.status === 'running') return res.status(409).json({ error: 'Stop the VM before moving it to another node', code: 'VM_RUNNING' });

    // Local -> local can't happen (only one local node), so target is remote here.
    if (target.mode !== 'remote') return res.status(400).json({ error: 'Unsupported move' });
    if (!nodeManager.isNodeOnline(target.id)) return res.status(409).json({ error: `Node "${target.name}" is offline`, code: 'NODE_OFFLINE' });
    if (!vm.disk_file || !fs.existsSync(vm.disk_file)) return res.status(404).json({ error: `VM disk not found on this panel (${vm.disk_file || 'none'}), nothing to copy`, code: 'DISK_NOT_FOUND' });

    const totalBytes = fs.statSync(vm.disk_file).size;
    const job = { status: 'running', vm_id: vm.vm_id, node_id: target.id, node_name: target.name, totalBytes, sentBytes: 0, startedAt: new Date().toISOString(), error: null };
    migrationJobs.set(vmId, job);
    auditLog.log({ ...auditLog.fromReq(req), action: 'vm_move_node', targetType: 'vm', targetId: vmId, details: `to node ${target.id} (${target.name}), ${totalBytes} bytes` });
    res.status(202).json({ success: true, started: true, job });

    (async () => {
      try {
        const stream = fs.createReadStream(vm.disk_file, { highWaterMark: 1024 * 1024 });
        await nodeManager.relayDiskUpload(target.id, { vmId: vm.vm_id, totalBytes }, stream, (acked) => { job.sentBytes = acked; });
        // Only now - disk verified on the node - repoint the VM.
        await new Promise((resolve, reject) => db.run(`UPDATE vms SET node_id = ? WHERE vm_id = ?`, [target.id, vm.vm_id], (e) => e ? reject(e) : resolve()));
        job.sentBytes = totalBytes;
        job.status = 'done';
        job.finishedAt = new Date().toISOString();
        setTimeout(() => { if (migrationJobs.get(vmId) === job) migrationJobs.delete(vmId); }, 30 * 60 * 1000).unref();
        if (req.body.delete_source === true) {
          try { fs.unlinkSync(vm.disk_file); job.sourceDeleted = true; } catch (e) { job.sourceDeleted = false; }
        }
        console.log(`[Nodes] VM ${vm.vm_id} moved to node ${target.id} (${target.name}), disk verified`);
      } catch (e) {
        job.status = 'failed';
        job.error = e.message;
        job.code = e.code;
        job.finishedAt = new Date().toISOString();
        setTimeout(() => { if (migrationJobs.get(vmId) === job) migrationJobs.delete(vmId); }, 30 * 60 * 1000).unref();
        console.error(`[Nodes] Move of VM ${vm.vm_id} to node ${target.id} failed: ${e.message} (VM left on its original node)`);
      }
    })();
  } catch (e) {
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Health check: "Test Node" button. For the Local Node this runs the
// same real detection in-process; for a Remote Node it round-trips a
// real command over the agent's authenticated connection, which proves
// reachability, authentication, and the command channel all at once.
app.post('/api/nodes/:id/test', checkAuth, checkAdmin, async (req, res) => {
  try {
    const node = await nodeManager.getNode(req.params.id);
    if (!node) return res.status(404).json({ error: 'Node not found' });
    const checks = [];
    if (node.mode === 'local') {
      checks.push({ label: 'Agent reachable', pass: true, detail: 'Local node (no agent required)' });
      checks.push({ label: 'Authentication', pass: true, detail: 'n/a (local)' });
      const info = await require('./system-info').getSystemInfo(VM_DIR);
      checks.push({ label: 'Filesystem', pass: info.diskTotalBytes !== null, detail: info.diskTotalBytes !== null ? `${Math.round(info.diskFreeBytes / 1e9)}GB free` : 'df failed' });
      checks.push({ label: 'QEMU', pass: info.qemuAvailable, detail: info.qemuAvailable ? info.qemuVersion : 'not found' });
      checks.push({ label: 'KVM', pass: info.kvmAvailable, detail: info.kvmAvailable ? 'available' : 'not available' });
      checks.push({ label: 'VM subsystem', pass: !!resolveQemuBinary(), detail: resolveQemuBinary() || 'no usable binary' });
    } else {
      const online = nodeManager.isNodeOnline(node.id);
      checks.push({ label: 'Agent reachable', pass: online, detail: online ? 'Connected' : 'No active connection' });
      if (!online) return res.json({ success: false, checks });
      try {
        const info = await nodeManager.sendNodeCommand(node.id, 'system.info', {}, { timeoutMs: 10000 });
        checks.push({ label: 'Authentication', pass: true, detail: 'Verified (token accepted at connect time)' });
        checks.push({ label: 'Filesystem', pass: info.diskTotalBytes !== null, detail: info.diskTotalBytes !== null ? `${Math.round(info.diskFreeBytes / 1e9)}GB free` : 'df failed on node' });
        checks.push({ label: 'QEMU', pass: !!info.qemuAvailable, detail: info.qemuAvailable ? info.qemuVersion : 'not found' });
        checks.push({ label: 'KVM', pass: !!info.kvmAvailable, detail: info.kvmAvailable ? 'available' : 'not available' });
        checks.push({ label: 'VM subsystem', pass: true, detail: `${info.hostname} / ${info.os}` });
      } catch (e) {
        checks.push({ label: 'Authentication', pass: false, detail: e.message });
      }
    }
    res.json({ success: checks.every((c) => c.pass), checks });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// NODE TERMINAL (v2.4.0) - run a shell command on any node (local or
// remote) from the panel. Admin-only, audit-logged, hard timeout and
// output caps on both paths. Remote nodes execute through the agent's
// host.exec action (agent applies its own 60s cap); the local node
// executes directly. This is the backend for /admin/nodes/:id/terminal.
app.post('/api/nodes/:id/exec', checkAuth, checkAdmin, async (req, res) => {
  const command = String((req.body && req.body.command) || '');
  const timeoutMs = Math.max(1000, Math.min(parseInt((req.body && req.body.timeoutMs) || 20000, 10) || 20000, 60000));
  if (!command.trim()) return res.status(400).json({ error: 'Command required' });
  try {
    const node = await nodeManager.getNode(req.params.id);
    if (!node) return res.status(404).json({ error: 'Node not found' });
    let result;
    if (node.mode === 'local') {
      result = await new Promise((resolve) => {
        require('child_process').exec(command, { cwd: '/', timeout: timeoutMs, maxBuffer: 512 * 1024, killSignal: 'SIGKILL' },
          (err, stdout, stderr) => resolve({
            stdout: String(stdout || '').slice(0, 256 * 1024),
            stderr: String(stderr || '').slice(0, 64 * 1024),
            code: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
            timedOut: !!(err && err.killed),
            signal: err && err.signal ? String(err.signal) : null
          }));
      });
    } else {
      const online = nodeManager.isNodeOnline(node.id);
      if (!online) return res.status(409).json({ error: 'Node is offline - wait for the agent to reconnect, then retry' });
      result = await nodeManager.sendNodeCommand(node.id, 'host.exec', { command, timeoutMs }, { timeoutMs: timeoutMs + 15000 });
    }
    auditLog.log({ ...auditLog.fromReq(req), action: 'node_exec', targetType: 'node', targetId: node.id, details: `(${node.name}) $ ${command.slice(0, 300)} [exit ${result.code}${result.timedOut ? ' TIMEOUT' : ''}]` });
    res.json({ node: { id: node.id, name: node.name, mode: node.mode }, command, ...result });
  } catch (e) {
    res.status(e.httpStatus || 500).json({ error: e.message || 'Command failed' });
  }
});

// Agent install package - a tarball of the node-agent/ directory.
// Authenticated with EITHER an admin session (download link in the UI)
// or a valid node token (the copy-pasteable curl one-liner, run from a
// fresh remote server with no browser session at all).
app.get('/api/nodes/agent-package', async (req, res) => {
  const authHeader = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
  const isAdminSession = req.session && req.session.userId && req.session.role === 'admin';
  let validToken = null;
  if (authHeader) { try { validToken = await nodeManager.verifyNodeToken(authHeader); } catch (e) { validToken = null; } }
  if (!isAdminSession && !validToken) return res.status(401).json({ error: 'Authentication required' });

  const agentDir = path.join(__dirname, 'node-agent');

  // SELF-HEAL (agent install fix): if the executable bit was lost anywhere
  // in the deploy pipeline (zip extracted on Windows then git-pushed, some
  // SFTP/web uploads), install.sh arrives as 644 and `sudo ./install.sh`
  // on the node dies with a misleading "command not found" (sudo reports
  // non-executable files that way). Restore the bit on the live copy before
  // packing so every served tarball is directly runnable. The UI command
  // additionally uses `sudo bash install.sh`, which never needs the bit.
  try {
    const installer = path.join(agentDir, 'install.sh');
    if (fs.existsSync(installer)) fs.chmodSync(installer, 0o755);
    const serviceFile = path.join(agentDir, 'vnm-agent.service');
    if (fs.existsSync(serviceFile)) fs.chmodSync(serviceFile, 0o644);
  } catch (chmodErr) {
    console.error('[agent-package] exec-bit self-heal failed (continuing):', chmodErr.message);
  }
  res.setHeader('Content-Type', 'application/gzip');
  res.setHeader('Content-Disposition', 'attachment; filename="vnm-agent.tar.gz"');
  const tarProcess = spawn('tar', ['-czf', '-', '--exclude=node_modules', '-C', __dirname, 'node-agent'], { stdio: ['ignore', 'pipe', 'pipe'] });
  tarProcess.stdout.pipe(res);
  tarProcess.stderr.on('data', (d) => console.error('[agent-package tar]', d.toString()));
  tarProcess.on('error', (e) => { console.error('[agent-package] tar failed:', e.message); if (!res.headersSent) res.status(500).end(); });
});

// ============= AUTH ROUTES =============

app.post('/api/login', loginRateLimit, (req, res) => {
  const { username, password } = req.body;
  console.log(`[Auth] Login attempt for username: ${username}`);
  
  db.get(`SELECT * FROM users WHERE username = ? AND is_active = 1`, [username], (err, user) => {
    if (err) {
      console.error(`[Auth Error] Login query failed for ${username}:`, err);
      return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
    }
    
    if (!user || !bcrypt.compareSync(password, user.password)) {
      console.warn(`[Auth Error] Invalid credentials for username: ${username}`);
      auditLog.log({ username, action: 'login', result: 'failure', ip: req.ip, details: 'Invalid credentials' });
      if (shieldRef.recordLogin) shieldRef.recordLogin({ username, success: false, reason: 'invalid-credentials', ip: req.ip, userAgent: req.get('user-agent') });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.totp_enabled) {
      req.session.pendingTotpUserId = user.id;
      auditLog.log({ userId: user.id, username: user.username, action: 'login', result: 'pending_2fa', ip: req.ip });
      return res.json({ success: false, requiresTotp: true });
    }
    
    // Update last login
    db.run(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [user.id], (err) => {
      if (err) console.error('[DB Error] Failed to update last_login:', err);
    });
    
    // SECURITY (session fixation): rotate the session ID at login so a
    // cookie planted before authentication can never become a logged-in
    // session. A fresh CSRF token is issued with the new session.
    // pendingDiscordAuth (the Discord link handoff) is carried across the
    // rotation - otherwise a user sent here from the Discord flow would
    // lose the identity they are trying to link.
    const pendingDiscordHandoff = req.session.pendingDiscordAuth || null;
    req.session.regenerate((regenErr) => {
      if (regenErr) {
        console.error('[Auth Error] Session regeneration failed:', regenErr);
        return res.status(500).json({ error: 'Could not establish a secure session' });
      }
      if (pendingDiscordHandoff) req.session.pendingDiscordAuth = pendingDiscordHandoff;
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.role = user.role;
      req.session.csrfToken = require('crypto').randomBytes(24).toString('hex');
      res.cookie('csrf_token', req.session.csrfToken, { httpOnly: false, sameSite: 'lax', secure: req.secure });
      console.log(`[Auth Success] User ${user.id} (${user.username}) logged in with role: ${user.role}`);
      auditLog.log({ userId: user.id, username: user.username, action: 'login', result: 'success', ip: req.ip });
      if (shieldRef.recordLogin) shieldRef.recordLogin({ userId: user.id, username: user.username, success: true, reason: 'password', ip: req.ip, userAgent: req.get('user-agent') });
      // If this login is the second half of a Discord link flow, go back
      // to the link page instead of the dashboard.
      res.json({
        success: true,
        redirect: req.session.pendingDiscordAuth ? '/link-discord-account' : undefined,
        user: { id: user.id, username: user.username, role: user.role }
      });
    });
  });
});

// Second step of login when the account has 2FA enabled. Relies on the
// short-lived `pendingTotpUserId` set on the (already-secure, httpOnly)
// session by /api/login above - the real session fields (userId etc.)
// are never set until this step also passes, so checkAuth can't be
// satisfied by a password alone once 2FA is on.
app.post('/api/login/2fa', loginRateLimit, (req, res) => {
  const pendingId = req.session.pendingTotpUserId;
  if (!pendingId) return res.status(400).json({ error: 'No login in progress' });

  db.get(`SELECT * FROM users WHERE id = ? AND is_active = 1`, [pendingId], (err, user) => {
    if (err || !user || !user.totp_enabled) return res.status(400).json({ error: 'No login in progress' });

    const code = String(req.body.code || '').trim();
    let ok = twofa.verifyToken(user.totp_secret, code);
    let usedRecovery = false;

    if (!ok) {
      const recoveryHashes = JSON.parse(user.totp_recovery_codes || '[]');
      const codeHash = twofa.hashRecoveryCode(code);
      const idx = recoveryHashes.indexOf(codeHash);
      if (idx !== -1) {
        ok = true;
        usedRecovery = true;
        recoveryHashes.splice(idx, 1);
        db.run(`UPDATE users SET totp_recovery_codes = ? WHERE id = ?`, [JSON.stringify(recoveryHashes), user.id]);
      }
    }

    if (!ok) {
      auditLog.log({ userId: user.id, username: user.username, action: 'login_2fa', result: 'failure', ip: req.ip });
      if (shieldRef.recordLogin) shieldRef.recordLogin({ userId: user.id, username: user.username, success: false, reason: 'invalid-2fa-code', ip: req.ip, userAgent: req.get('user-agent') });
      return res.status(401).json({ error: 'Invalid code' });
    }

    // SECURITY (session fixation): rotate the session ID when the 2FA step
    // completes the login (regeneration also drops pendingTotpUserId).
    // pendingDiscordAuth is carried across like on the plain login path.
    const pendingDiscordHandoff = req.session.pendingDiscordAuth || null;
    req.session.regenerate((regenErr) => {
      if (regenErr) {
        console.error('[Auth Error] Session regeneration failed (2FA):', regenErr);
        return res.status(500).json({ error: 'Could not establish a secure session' });
      }
      if (pendingDiscordHandoff) req.session.pendingDiscordAuth = pendingDiscordHandoff;
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.role = user.role;
      req.session.csrfToken = require('crypto').randomBytes(24).toString('hex');
      res.cookie('csrf_token', req.session.csrfToken, { httpOnly: false, sameSite: 'lax', secure: req.secure });
      db.run(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [user.id]);
      console.log(`[Auth Success] User ${user.id} (${user.username}) completed 2FA login`);
      auditLog.log({ userId: user.id, username: user.username, action: 'login_2fa', result: usedRecovery ? 'success_recovery_code' : 'success', ip: req.ip });
      if (shieldRef.recordLogin) shieldRef.recordLogin({ userId: user.id, username: user.username, success: true, reason: usedRecovery ? '2fa-recovery' : '2fa', ip: req.ip, userAgent: req.get('user-agent') });
      res.json({
        success: true,
        redirect: req.session.pendingDiscordAuth ? '/link-discord-account' : undefined,
        user: { id: user.id, username: user.username, role: user.role }
      });
    });
  });
});

// ---- 2FA enrollment (any authenticated user can secure their own account) ----
app.post('/api/2fa/setup', checkAuth, (req, res) => {
  const secret = twofa.generateSecret();
  req.session.pendingTotpSecret = secret; // not persisted to users table until /enable confirms a valid code
  res.json({
    secret,
    otpauthUrl: twofa.otpauthUrl(secret, { label: req.session.username, issuer: res.locals.siteName || 'VNM' })
  });
});

app.post('/api/2fa/enable', checkAuth, (req, res) => {
  const secret = req.session.pendingTotpSecret;
  if (!secret) return res.status(400).json({ error: 'Start setup first' });
  if (!twofa.verifyToken(secret, req.body.code)) return res.status(400).json({ error: 'Invalid code - check your authenticator app and try again' });

  const recoveryCodes = twofa.generateRecoveryCodes(8);
  const hashedCodes = recoveryCodes.map(twofa.hashRecoveryCode);
  db.run(`UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_recovery_codes = ? WHERE id = ?`,
    [secret, JSON.stringify(hashedCodes), req.session.userId], (err) => {
      if (err) return res.status(500).json({ error: 'Could not enable 2FA' });
      delete req.session.pendingTotpSecret;
      auditLog.log({ ...auditLog.fromReq(req), action: '2fa_enabled' });
      res.json({ success: true, recoveryCodes }); // shown once - store them now
    });
});

app.post('/api/2fa/disable', checkAuth, (req, res) => {
  db.get(`SELECT * FROM users WHERE id = ?`, [req.session.userId], (err, user) => {
    if (err || !user || !bcrypt.compareSync(req.body.password || '', user.password)) {
      return res.status(401).json({ error: 'Incorrect password' });
    }
    db.run(`UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_recovery_codes = NULL WHERE id = ?`, [user.id], (err2) => {
      if (err2) return res.status(500).json({ error: 'Could not disable 2FA' });
      auditLog.log({ ...auditLog.fromReq(req), action: '2fa_disabled' });
      res.json({ success: true });
    });
  });
});

app.get('/api/2fa/status', checkAuth, (req, res) => {
  db.get(`SELECT totp_enabled FROM users WHERE id = ?`, [req.session.userId], (err, row) => {
    if (err) { console.error('[2FA] status query failed:', err.message); return res.status(500).json({ error: 'Internal server error' }); }
    res.json({ enabled: !!(row && row.totp_enabled) });
  });
});

app.post('/api/logout', (req, res) => {
  console.log(`[Auth] User ${req.session.userId} (${req.session.username}) logged out`);
  const wasUser = { userId: req.session.userId, username: req.session.username, ip: req.ip };
  req.session.destroy(() => {
    console.log(`[Auth] Session destroyed`);
    auditLog.log({ ...wasUser, action: 'logout', result: 'success' });
    res.json({ success: true });
  });
});

app.get('/api/auth/check', (req, res) => {
  if (req.session.userId) {
    res.json({ authenticated: true, user: { id: req.session.userId, username: req.session.username, role: req.session.role } });
  } else {
    res.json({ authenticated: false });
  }
});

// ============= DISCORD OAUTH ROUTES =============

const axios = require('axios');

// Get Discord OAuth state from session
function generateDiscordAuthUrl() {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM discord_settings WHERE enabled = 1`, (err, settings) => {
      if (err || !settings || !settings.client_id) {
        return reject(new Error('Discord auth not configured'));
      }

      const params = new URLSearchParams({
        client_id: settings.client_id,
        redirect_uri: settings.redirect_uri,
        response_type: 'code',
        scope: 'identify email',
        state: require('crypto').randomBytes(16).toString('hex')
      });

      resolve({
        url: `https://discord.com/api/oauth2/authorize?${params.toString()}`,
        state: params.get('state')
      });
    });
  });
}

// Check if Discord auth is enabled (public endpoint for login page)
app.get('/api/discord-enabled', (req, res) => {
  db.get(`SELECT enabled FROM discord_settings LIMIT 1`, (err, settings) => {
    if (err || !settings) {
      return res.json({ enabled: false });
    }
    res.json({ enabled: settings.enabled ? true : false });
  });
});

app.get('/api/discord-auth-url', async (req, res) => {
  try {
    const authData = await generateDiscordAuthUrl();
    req.session.discordState = authData.state;
    res.json({ url: authData.url });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  
  if (!code) {
    return res.redirect('/login?error=Discord authentication failed');
  }

  // Verify state to prevent CSRF. Both sides must be present - comparing
  // two undefined values used to pass this check.
  if (!state || !req.session.discordState || state !== req.session.discordState) {
    console.error('[Discord Auth] State mismatch - possible CSRF attack');
    return res.redirect('/login?error=State validation failed');
  }

  try {
    // Get Discord settings
    const settings = await new Promise((resolve, reject) => {
      db.get(`SELECT * FROM discord_settings WHERE enabled = 1`, (err, s) => {
        if (err || !s) reject(new Error('Discord auth not configured'));
        else resolve(s);
      });
    });

    // Exchange code for token
    const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', {
      client_id: settings.client_id,
      client_secret: settings.client_secret,
      code: code,
      grant_type: 'authorization_code',
      redirect_uri: settings.redirect_uri,
      scope: 'identify email'
    }, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const access_token = tokenResponse.data.access_token;

    // Get Discord user info
    const userResponse = await axios.get('https://discord.com/api/users/@me', {
      headers: { 'Authorization': `Bearer ${access_token}` }
    });

    const discordUser = userResponse.data;

    // An unverified Discord email proves nothing - don't match or create
    // panel accounts against it.
    if (discordUser.verified === false) {
      console.warn(`[Discord Auth] Rejected unverified Discord account ${discordUser.username} (${discordUser.id})`);
      return res.redirect('/login?error=' + encodeURIComponent('Your Discord email address is not verified. Verify it in Discord, then try again.'));
    }

    const discordId = discordUser.id;
    const discordUsername = discordUser.username;
    const discordEmail = discordUser.email;
    const discordAvatar = discordUser.avatar;

    console.log(`[Discord Auth] User ${discordUsername} (${discordId}) authenticated`);

    // Check if Discord account is already linked
    db.get(`SELECT * FROM user_discord_accounts WHERE discord_id = ?`, [discordId], (err, linked) => {
      if (err) {
        console.error('[Discord Auth] DB error:', err);
        return res.redirect('/login?error=Database error');
      }

      if (linked) {
        // Already linked - update avatar and log them in
        db.run(`UPDATE user_discord_accounts SET discord_avatar = ? WHERE discord_id = ?`, [discordAvatar || '', discordId], (err) => {
          if (err) console.error('[Discord Auth] Failed to update avatar:', err);
        });
        
        db.get(`SELECT * FROM users WHERE id = ? AND is_active = 1`, [linked.user_id], (err, user) => {
          if (err || !user) {
            return res.redirect('/login?error=User not found');
          }

          // Update last login
          db.run(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [user.id]);

          // SECURITY: rotate the session ID at login (session fixation).
          req.session.regenerate((regenErr) => {
            if (regenErr) {
              console.error('[Discord Auth] Session regeneration failed:', regenErr);
              return res.redirect('/login?error=Could not establish a secure session');
            }
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.role = user.role;
            req.session.csrfToken = require('crypto').randomBytes(24).toString('hex');
            res.cookie('csrf_token', req.session.csrfToken, { httpOnly: false, sameSite: 'lax', secure: req.secure });

            console.log(`[Discord Auth] User ${user.username} (${user.id}) logged in via Discord`);
            res.redirect('/dashboard');
          });
        });
      } else {
        // Check if email exists in system
        if (discordEmail) {
          db.get(`SELECT * FROM users WHERE email = ?`, [discordEmail], (err, existingUser) => {
            if (err) {
              console.error('[Discord Auth] DB error:', err);
              return res.redirect('/login?error=Database error');
            }

            if (existingUser) {
              // Email exists - offer to link
              req.session.pendingDiscordAuth = {
                discordId: discordId,
                discordUsername: discordUsername,
                discordEmail: discordEmail,
                discordAvatar: discordAvatar,
                action: 'link'
              };
              res.redirect('/link-discord-account');
            } else {
              // New user - create account
              createDiscordUser(discordId, discordUsername, discordEmail, discordAvatar, res, req);
            }
          });
        } else {
          // No email - require manual creation
          req.session.pendingDiscordAuth = {
            discordId: discordId,
            discordUsername: discordUsername,
            discordEmail: discordEmail,
            discordAvatar: discordAvatar,
            action: 'create'
          };
          res.redirect('/create-account-discord');
        }
      }
    });
  } catch (err) {
    console.error('[Discord Auth] Error:', err.message);
    res.redirect('/login?error=' + encodeURIComponent(err.message));
  }
});

function createDiscordUser(discordId, discordUsername, discordEmail, discordAvatar, res, req) {
  // Generate a random password (user won't use it for Discord login)
  const tempPassword = require('crypto').randomBytes(16).toString('hex');
  const hashedPassword = bcrypt.hashSync(tempPassword, 10);

  db.run(
    `INSERT INTO users (username, password, email, full_name, role, is_active) VALUES (?, ?, ?, ?, ?, ?)`,
    [discordUsername, hashedPassword, discordEmail, discordUsername, 'user', 1],
    function(err) {
      if (err) {
        console.error('[Discord Auth] Failed to create user:', err);
        return res.redirect('/login?error=Failed to create account');
      }

      const userId = this.lastID;

      // Link Discord account
      db.run(
        `INSERT INTO user_discord_accounts (user_id, discord_id, discord_username, discord_email, discord_avatar) VALUES (?, ?, ?, ?, ?)`,
        [userId, discordId, discordUsername, discordEmail, discordAvatar || ''],
        (err) => {
          if (err) {
            console.error('[Discord Auth] Failed to link Discord account:', err);
            return res.redirect('/login?error=Failed to link account');
          }

          // Log them in - with a freshly rotated session ID (fixation fix).
          db.run(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [userId]);

          req.session.regenerate((regenErr) => {
            if (regenErr) {
              console.error('[Discord Auth] Session regeneration failed (create):', regenErr);
              return res.redirect('/login?error=Could not establish a secure session');
            }
            req.session.userId = userId;
            req.session.username = discordUsername;
            req.session.role = 'user';
            req.session.csrfToken = require('crypto').randomBytes(24).toString('hex');
            res.cookie('csrf_token', req.session.csrfToken, { httpOnly: false, sameSite: 'lax', secure: req.secure });

            console.log(`[Discord Auth] New user ${discordUsername} (${userId}) created via Discord`);
            res.redirect('/dashboard');
          });
        }
      );
    }
  );
}

// ---------------------------------------------------------------------------
// Discord account-linking / first-time sign-up pages.
// The OAuth callback parks the verified Discord identity on the session
// (pendingDiscordAuth) and redirects here; these pages finish the flow.
// ---------------------------------------------------------------------------
app.get('/link-discord-account', (req, res) => {
  const pending = req.session.pendingDiscordAuth;
  if (!pending) return res.redirect('/login?error=Discord link session expired - please start again');
  res.render('users/link-discord', {
    title: 'Link Discord Account - VNM Panel',
    currentPage: 'link-discord',
    siteLogo: res.locals.siteLogo || process.env.DEFAULT_LOGO_URL || '/images/logo-new.svg',
    siteName: res.locals.siteName || process.env.PANEL_NAME || 'VNM',
    discordUsername: pending.discordUsername || 'Discord user',
    loggedIn: !!req.session.userId
  });
});

app.get('/create-account-discord', (req, res) => {
  const pending = req.session.pendingDiscordAuth;
  if (!pending) return res.redirect('/login?error=Discord sign-up session expired - please start again');
  res.render('users/create-account-discord', {
    title: 'Create Account - VNM Panel',
    currentPage: 'create-account-discord',
    siteLogo: res.locals.siteLogo || process.env.DEFAULT_LOGO_URL || '/images/logo-new.svg',
    siteName: res.locals.siteName || process.env.PANEL_NAME || 'VNM',
    discordUsername: pending.discordUsername || '',
    discordEmail: pending.discordEmail || ''
  });
});

// Finish first-time Discord sign-up: create the account, link the Discord
// identity, and log in. Consumes pendingDiscordAuth.
app.post('/api/create-account-discord', loginRateLimit, (req, res) => {
  const pending = req.session.pendingDiscordAuth;
  if (!pending) return res.status(400).json({ error: 'No pending Discord sign-up - start again from the login page' });

  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const email = String(req.body.email || '').trim();
  const fullName = String(req.body.fullName || '').trim();

  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
    return res.status(400).json({ error: 'Username must be 3-32 characters (letters, digits, dot, dash, underscore)' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address' });
  }

  db.get(`SELECT id, username, email FROM users WHERE username = ? OR (email != '' AND email = ?)`, [username, email || null], (err, existing) => {
    if (err) {
      console.error('[Discord Auth] Create-account lookup failed:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    if (existing) {
      const clash = existing.username === username ? 'Username' : 'Email';
      return res.status(409).json({ error: clash + ' is already taken - if it is yours, sign in with it and use "Login with Discord" to link instead' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    db.run(
      `INSERT INTO users (username, password, email, full_name, role, is_active) VALUES (?, ?, ?, ?, 'user', 1)`,
      [username, hashedPassword, email || null, fullName || username],
      function (insertErr) {
        if (insertErr) {
          console.error('[Discord Auth] Failed to create account:', insertErr);
          return res.status(500).json({ error: 'Could not create the account' });
        }
        const userId = this.lastID;
        db.run(
          `INSERT INTO user_discord_accounts (user_id, discord_id, discord_username, discord_email, discord_avatar) VALUES (?, ?, ?, ?, ?)`,
          [userId, pending.discordId, pending.discordUsername, pending.discordEmail, pending.discordAvatar || ''],
          (linkErr) => {
            if (linkErr) {
              console.error('[Discord Auth] Failed to link new account:', linkErr);
              return res.status(500).json({ error: 'Account created but Discord linking failed - contact an admin' });
            }
            db.run(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [userId]);
            auditLog.log({ userId, username, action: 'discord_account_created', result: 'success', ip: req.ip });

            // Rotate the session ID at login (fixation fix) and sign in.
            req.session.regenerate((regenErr) => {
              if (regenErr) {
                console.error('[Discord Auth] Session regeneration failed (signup):', regenErr);
                return res.status(500).json({ error: 'Could not establish a secure session' });
              }
              req.session.userId = userId;
              req.session.username = username;
              req.session.role = 'user';
              req.session.csrfToken = require('crypto').randomBytes(24).toString('hex');
              res.cookie('csrf_token', req.session.csrfToken, { httpOnly: false, sameSite: 'lax', secure: req.secure });
              res.json({ success: true });
            });
          }
        );
      }
    );
  });
});

// Link Discord to existing account (requires login first)
app.post('/api/link-discord-account', checkAuth, (req, res) => {
  if (!req.session.pendingDiscordAuth) {
    return res.status(400).json({ error: 'No pending Discord authentication' });
  }

  const { discordId, discordUsername, discordEmail, discordAvatar } = req.session.pendingDiscordAuth;
  const userId = req.session.userId;

  db.run(
    `INSERT OR REPLACE INTO user_discord_accounts (user_id, discord_id, discord_username, discord_email, discord_avatar) VALUES (?, ?, ?, ?, ?)`,
    [userId, discordId, discordUsername, discordEmail, discordAvatar || ''],
    (err) => {
      if (err) {
        console.error('[Discord Auth] Failed to link account:', err);
        return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
      }

      delete req.session.pendingDiscordAuth;
      console.log(`[Discord Auth] Linked Discord account ${discordUsername} to user ${userId}`);
      res.json({ success: true, message: 'Discord account linked successfully' });
    }
  );
});

// Unlink Discord account
app.post('/api/unlink-discord-account', checkAuth, (req, res) => {
  const userId = req.session.userId;

  db.run(`DELETE FROM user_discord_accounts WHERE user_id = ?`, [userId], (err) => {
    if (err) {
      return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
    }
    console.log(`[Discord Auth] Unlinked Discord account from user ${userId}`);
    res.json({ success: true, message: 'Discord account unlinked' });
  });
});

// Get Discord account info
app.get('/api/discord-account-info', checkAuth, (req, res) => {
  const userId = req.session.userId;

  db.get(
    `SELECT discord_id, discord_username, discord_email, discord_avatar, connected_at FROM user_discord_accounts WHERE user_id = ?`,
    [userId],
    (err, account) => {
      if (err) {
        return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
      }
      // Return null if no Discord account linked, or the account object if linked
      if (!account) {
        return res.json(null);
      }
      res.json(account);
    }
  );
});

// ============= OS TEMPLATES =============

app.get('/api/os-templates', checkAuth, (req, res) => {
  // First get database templates
  db.all(`SELECT * FROM os_templates WHERE is_active = 1 ORDER BY created_at DESC`, (err, dbTemplates) => {
    if (err || !dbTemplates) {
      // If error, return default built-in templates only (credentials stripped)
      const sanitized = {};
      Object.entries(OS_TEMPLATES).forEach(([key, t]) => {
        const { password, ...rest } = t;
        sanitized[key] = { ...rest, has_password: !!password };
      });
      return res.json(sanitized);
    }

    // Combine DB templates with built-in templates
    const dbTemplateMap = {};
    if (dbTemplates && dbTemplates.length > 0) {
      dbTemplates.forEach(t => {
        dbTemplateMap[t.template_key] = t;
      });
    }

    // Get built-in templates as object, with credentials stripped for the client
    const allTemplates = {};
    Object.entries(OS_TEMPLATES).forEach(([key, t]) => {
      const { password, ...rest } = t;
      allTemplates[key] = { ...rest, has_password: !!password };
    });

    // Add custom templates from DB (credentials stripped)
    if (dbTemplates && dbTemplates.length > 0) {
      dbTemplates.forEach(t => {
        allTemplates[t.template_key] = {
          template_key: t.template_key,
          name: t.template_name,
          type: t.template_type,
          icon: t.icon,
          disk_size: t.disk_size,
          memory: t.memory,
          cpus: t.cpus,
          username: t.username,
          has_password: !!t.password,
          url: t.download_url,
          is_custom: true
        };
      });
    }

    res.json(allTemplates);
  });
});

// Get all templates (admin) - includes inactive
app.get('/api/admin/templates', checkAuth, checkAdmin, (req, res) => {
  console.log(`[API] GET /api/admin/templates - Admin requesting all templates`);
  
  // Query custom templates from database
  db.all(`SELECT * FROM os_templates ORDER BY is_custom DESC, created_at DESC`, [], (err, dbTemplates) => {
    if (err) {
      console.error(`[API] GET /api/admin/templates - DB Query Error:`, err.message);
      return res.status(500).json({ 
        error: 'Database error', 
        message: err.message,
        status: 'error'
      });
    }

    // Build built-in templates list
    // AUDIT FIX (item 8): expose whether each built-in template is already
    // cached on disk so the frontend can show "Available" vs "Download
    // Required" instead of implying every template is deploy-ready. This
    // is a cheap existence check (not full qemu-img validation, to keep
    // this list endpoint fast) - the review step calls the dedicated
    // /status endpoint below for the authoritative validated check.
    const builtInList = [];
    for (const [key, template] of Object.entries(OS_TEMPLATES)) {
      const cachedPath = path.join(TEMPLATES_DIR, `${key}-template.qcow2`);
      builtInList.push({
        template_id: null,
        template_key: key,
        template_name: template.name,
        template_type: template.type,
        icon: template.icon,
        description: `Built-in template for ${template.name}`,
        disk_size: template.disk_size,
        memory: template.memory,
        cpus: template.cpus,
        download_url: template.url,
        local_path: null,
        username: template.username,
        password: template.password,
        is_custom: 0,
        is_active: 1,
        created_at: null,
        created_by: null,
        cached: fs.existsSync(cachedPath)
      });
    }

    // Combine: custom templates + built-in templates
    const allTemplates = [];
    
    // Add custom templates first
    if (dbTemplates && Array.isArray(dbTemplates)) {
      dbTemplates.forEach(t => {
        allTemplates.push({
          template_id: t.template_id,
          template_key: t.template_key,
          template_name: t.template_name,
          template_type: t.template_type,
          icon: t.icon,
          description: t.description,
          disk_size: t.disk_size,
          memory: t.memory,
          cpus: t.cpus,
          download_url: t.download_url,
          local_path: t.local_path,
          username: t.username,
          password: t.password,
          is_custom: t.is_custom,
          is_active: t.is_active,
          created_at: t.created_at,
          created_by: t.created_by
        });
      });
    }
    
    // Add built-in templates
    allTemplates.push(...builtInList);

    console.log(`[API] GET /api/admin/templates - Returning ${allTemplates.length} templates (${dbTemplates ? dbTemplates.length : 0} custom + ${builtInList.length} built-in)`);
    res.json(allTemplates);
  });
});

// Create custom template
app.post('/api/admin/templates', checkAuth, checkAdmin, async (req, res) => {
  const { template_key, template_name, template_type, icon, description, disk_size, memory, cpus, download_url, username, password } = req.body;

  if (!template_key || !template_name) {
    return res.status(400).json({ error: 'Template key and name are required' });
  }

  if (!disk_size) {
    return res.status(400).json({ error: 'Disk size is required' });
  }

  // Check if template key already exists
  db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [template_key], async (err, existing) => {
    if (err) { console.error('[Templates] duplicate-key check failed:', err.message); return res.status(500).json({ error: 'Internal server error' }); }
    if (existing) {
      return res.status(400).json({ error: 'Template with this key already exists' });
    }

    try {
      // Just store the template metadata - NO AUTO DOWNLOAD
      // User can download manually from templates list if needed
      const localPath = null; // Leave empty - user downloads manually

      // Insert into database
      db.run(
        `INSERT INTO os_templates 
        (template_key, template_name, template_type, icon, description, disk_size, memory, cpus, download_url, local_path, username, password, is_custom, created_by) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
        [template_key, template_name, template_type || 'cloud-init', icon || '📦', description || '', disk_size, memory || 2048, cpus || 2, download_url || '', localPath || '', username || '', password || '', req.session.userId],
        function(err) {
          if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
          
          res.json({
            success: true,
            template_id: this.lastID,
            template_key,
            message: 'Template created successfully! Download it manually from the templates list if needed.'
          });
        }
      );
    } catch (error) {
      res.status(500).json({ error: 'Failed to create template: ' + error.message });
    }
  });
});

// Update template
app.put('/api/admin/templates/:id', checkAuth, checkAdmin, (req, res) => {
  const { template_name, icon, description, disk_size, memory, cpus, username, password, is_active } = req.body;
  const templateId = req.params.id;

  const updates = [];
  const values = [];

  if (template_name) { updates.push('template_name = ?'); values.push(template_name); }
  if (icon !== undefined) { updates.push('icon = ?'); values.push(icon || '📦'); }
  if (description !== undefined) { updates.push('description = ?'); values.push(description || ''); }
  if (disk_size) { updates.push('disk_size = ?'); values.push(disk_size); }
  if (memory) { updates.push('memory = ?'); values.push(memory); }
  if (cpus) { updates.push('cpus = ?'); values.push(cpus); }
  if (username) { updates.push('username = ?'); values.push(username); }
  if (password) { updates.push('password = ?'); values.push(password); }
  if (is_active !== undefined) { updates.push('is_active = ?'); values.push(is_active ? 1 : 0); }
  
  updates.push('updated_at = datetime("now")');

  if (updates.length === 1) { // Only updated_at
    return res.status(400).json({ error: 'No fields to update' });
  }

  values.push(templateId);
  const query = `UPDATE os_templates SET ${updates.join(', ')} WHERE template_id = ?`;

  db.run(query, values, (err) => {
    if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
    res.json({ success: true, message: 'Template updated successfully' });
  });
});

// Update Built-in Template (creates/updates in database)
app.put('/api/admin/templates/builtin/:key', checkAuth, checkAdmin, (req, res) => {
  const templateKey = req.params.key;
  const { template_name, icon, description, disk_size, memory, cpus, username, password } = req.body;

  if (!OS_TEMPLATES[templateKey]) {
    return res.status(404).json({ error: 'Built-in template not found' });
  }

  const builtIn = OS_TEMPLATES[templateKey];

  // Check if already exists in database
  db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [templateKey], (err, existing) => {
    if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));

    const finalData = {
      template_key: templateKey,
      template_name: template_name || builtIn.name,
      template_type: builtIn.type,
      icon: icon || builtIn.icon,
      description: description || `Built-in: ${builtIn.name}`,
      disk_size: disk_size || builtIn.disk_size,
      memory: memory || builtIn.memory,
      cpus: cpus || builtIn.cpus,
      download_url: builtIn.url,
      username: username || builtIn.username,
      password: password || builtIn.password,
      is_custom: 0
    };

    if (existing) {
      // Update existing
      db.run(
        `UPDATE os_templates SET 
         template_name = ?, icon = ?, description = ?, disk_size = ?, memory = ?, cpus = ?, 
         username = ?, password = ?, updated_at = datetime("now")
         WHERE template_key = ?`,
        [finalData.template_name, finalData.icon, finalData.description, finalData.disk_size, 
         finalData.memory, finalData.cpus, finalData.username, finalData.password, templateKey],
        (err) => {
          if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
          res.json({ success: true, message: 'Built-in template updated successfully' });
        }
      );
    } else {
      // Insert new
      db.run(
        `INSERT INTO os_templates 
         (template_key, template_name, template_type, icon, description, disk_size, memory, cpus, 
          download_url, username, password, is_custom, created_by) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
        [finalData.template_key, finalData.template_name, finalData.template_type, finalData.icon, 
         finalData.description, finalData.disk_size, finalData.memory, finalData.cpus, 
         finalData.download_url, finalData.username, finalData.password, 1],
        (err) => {
          if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
          res.json({ success: true, message: 'Built-in template saved successfully' });
        }
      );
    }
  });
});

// Delete template
app.delete('/api/admin/templates/:id', checkAuth, checkAdmin, (req, res) => {
  const templateId = req.params.id;

  db.get(`SELECT * FROM os_templates WHERE template_id = ?`, [templateId], (err, template) => {
    if (err || !template) return res.status(404).json({ error: 'Template not found' });

    // Delete local file if exists
    if (template.local_path && fs.existsSync(template.local_path)) {
      try {
        fs.unlinkSync(template.local_path);
      } catch (e) {
        console.error('Failed to delete template file:', e.message);
      }
    }

    // Delete from database
    db.run(`DELETE FROM os_templates WHERE template_id = ?`, [templateId], (err) => {
      if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
      res.json({ success: true, message: 'Template deleted successfully' });
    });
  });
});

// AUDIT FIX (item 8): authoritative, non-downloading template availability
// check used by the Review Configuration step so it can show
// "Template: Available" / "Template: Download Required" instead of
// unconditionally claiming "Ready to Deploy" before the template has
// actually been verified. Runs the same qemu-img validation the download
// path uses, but never triggers a download itself.
app.get('/api/admin/templates/:key/status', checkAuth, checkAdmin, async (req, res) => {
  const templateKey = req.params.key;
  const template = OS_TEMPLATES[templateKey];
  if (!template) {
    // Not a built-in key - could be a custom template; report via DB.
    return db.get(`SELECT local_path FROM os_templates WHERE template_key = ?`, [templateKey], async (err, row) => {
      if (err || !row) return res.json({ template: templateKey, status: 'unknown' });
      if (row.local_path && fs.existsSync(row.local_path)) {
        const validation = await validateImageFile(row.local_path);
        return res.json({ template: templateKey, status: validation.valid ? 'available' : 'download_required' });
      }
      res.json({ template: templateKey, status: 'download_required' });
    });
  }
  const cachedPath = path.join(TEMPLATES_DIR, `${templateKey}-template.qcow2`);
  if (!fs.existsSync(cachedPath)) {
    return res.json({ template: templateKey, status: 'download_required' });
  }
  const validation = await validateImageFile(cachedPath);
  res.json({
    template: templateKey,
    status: validation.valid ? 'available' : 'download_required',
    reason: validation.valid ? undefined : validation.reason
  });
});

// Download template file (get template by key)
app.post('/api/admin/templates/:key/download', checkAuth, checkAdmin, async (req, res) => {
  const templateKey = req.params.key;

  try {
    // Check if it's a built-in template
    if (OS_TEMPLATES[templateKey]) {
      const template = OS_TEMPLATES[templateKey];
      const fileName = `${templateKey}-template.qcow2`;
      const localPath = path.join(TEMPLATES_DIR, fileName);

      // Create templates directory if it doesn't exist
      if (!fs.existsSync(TEMPLATES_DIR)) {
        fs.mkdirSync(TEMPLATES_DIR, { recursive: true });
      }

      // AUDIT FIX (OS template subsystem hardening): fs.existsSync() alone
      // previously meant "trust the cache" - a half-downloaded, corrupted,
      // or accidentally-HTML-page-saved-as-.qcow2 file would sit there
      // "cached" forever and break every future VM creation using it.
      // Validate with qemu-img info before trusting it; quarantine and
      // transparently redownload if invalid.
      if (fs.existsSync(localPath)) {
        const validation = await validateImageFile(localPath);
        if (validation.valid) {
          console.log(`[TEMPLATE] ${templateKey} already cached and validated at ${localPath}`);
          return res.json({ success: true, message: 'Template already cached locally', local_path: localPath });
        }
        console.warn(`[TEMPLATE] ${templateKey} cache at ${localPath} failed validation (${validation.reason}) - quarantining and redownloading`);
        try {
          fs.renameSync(localPath, `${localPath}.invalid.${Date.now()}`);
        } catch (e) {
          fs.unlink(localPath, () => {});
        }
      }

      console.log(`[TEMPLATE] Starting download of ${templateKey} (${template.download_urls.length} candidate URL(s))`);

      // Download the template (tries every configured fallback URL)
      try {
        await downloadTemplateWithFallback(template.download_urls, localPath, template.name);
      } catch (dlErr) {
        return res.status(502).json({
          success: false,
          error: 'TEMPLATE_DOWNLOAD_FAILED',
          template: templateKey,
          attempts: dlErr.attempts || template.download_urls.length,
          details: dlErr.details || [],
          message: dlErr.message
        });
      }

      console.log(`[TEMPLATE] Download complete for ${templateKey}`);

      // Save to database
      db.run(
        `INSERT OR REPLACE INTO os_templates 
        (template_key, template_name, template_type, icon, description, disk_size, memory, cpus, download_url, local_path, username, password, is_custom) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
        [templateKey, template.name, template.type, template.icon, `Built-in: ${template.name}`, template.disk_size, template.memory, template.cpus, template.url, localPath, template.username, template.password],
        (err) => {
          if (err) console.error('Failed to save template to database:', err);
          res.json({ success: true, message: 'Template downloaded and cached', local_path: localPath });
        }
      );
    } else {
      // Custom template
      db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [templateKey], async (err, template) => {
        if (err || !template) return res.status(404).json({ error: 'Template not found' });
        
        // Create templates directory if it doesn't exist
        if (!fs.existsSync(TEMPLATES_DIR)) {
          fs.mkdirSync(TEMPLATES_DIR, { recursive: true });
        }

        // Generate local path if not set
        let localPath = template.local_path;
        if (!localPath) {
          // Extract filename from URL or use template key
          const urlParts = template.download_url.split('/');
          const fileName = urlParts[urlParts.length - 1] || `${templateKey}-template.qcow2`;
          localPath = path.join(TEMPLATES_DIR, fileName);
        }

        if (fs.existsSync(localPath)) {
          const validation = await validateImageFile(localPath);
          if (validation.valid) {
            console.log(`[TEMPLATE] Custom template ${templateKey} already cached and validated at ${localPath}`);

            // Update database with local path if not set
            if (!template.local_path) {
              db.run(`UPDATE os_templates SET local_path = ? WHERE template_key = ?`, 
                [localPath, templateKey], 
                (err) => {
                  if (err) console.error('Failed to update template path:', err);
                }
              );
            }
            
            return res.json({ success: true, message: 'Template cached locally', local_path: localPath });
          }
          console.warn(`[TEMPLATE] Custom template ${templateKey} cache at ${localPath} failed validation (${validation.reason}) - quarantining and redownloading`);
          try {
            fs.renameSync(localPath, `${localPath}.invalid.${Date.now()}`);
          } catch (e) {
            fs.unlink(localPath, () => {});
          }
        }

        // Download the template
        try {
          console.log(`[TEMPLATE] Starting download of custom template (${templateKey}) from ${template.download_url}`);
          console.log(`[TEMPLATE] Saving to: ${localPath}`);
          
          await downloadTemplateFromURL(template.download_url, localPath);
          const validation = await validateImageFile(localPath);
          if (!validation.valid) {
            fs.unlink(localPath, () => {});
            throw new Error(`Downloaded file failed validation: ${validation.reason}`);
          }
          
          console.log(`[TEMPLATE] Download complete for custom template ${templateKey}`);

          // Update database with local path
          db.run(`UPDATE os_templates SET local_path = ? WHERE template_key = ?`, 
            [localPath, templateKey], 
            (err) => {
              if (err) console.error('Failed to update template path:', err);
            }
          );

          res.json({ success: true, message: 'Template downloaded and cached', local_path: localPath });
        } catch (downloadErr) {
          console.error(`[TEMPLATE] Download error for ${templateKey}:`, downloadErr.message);
          res.status(500).json({ error: 'Failed to download template: ' + downloadErr.message });
        }
      });
    }
  } catch (error) {
    console.error(`[TEMPLATE] Error:`, error.message);
    res.status(500).json({ error: 'Failed to download template: ' + error.message });
  }
});

// Get template cache info
app.get('/api/admin/templates/cache/info', checkAuth, checkAdmin, (req, res) => {
  try {
    const templates = [];
    
    if (fs.existsSync(TEMPLATES_DIR)) {
      const files = fs.readdirSync(TEMPLATES_DIR);
      files.forEach(file => {
        const filePath = path.join(TEMPLATES_DIR, file);
        const stat = fs.statSync(filePath);
        templates.push({
          filename: file,
          size: stat.size,
          size_readable: (stat.size / (1024 * 1024 * 1024)).toFixed(2) + ' GB',
          created: stat.birthtime,
          modified: stat.mtime
        });
      });
    }

    res.json({
      cache_directory: TEMPLATES_DIR,
      templates: templates,
      total_count: templates.length,
      total_size: templates.reduce((sum, t) => sum + t.size, 0),
      total_size_readable: (templates.reduce((sum, t) => sum + t.size, 0) / (1024 * 1024 * 1024)).toFixed(2) + ' GB'
    });
  } catch (error) {
    (console.error(error), res.status(500).json({ error: 'Internal server error' }));
  }
});

// Clear template cache (admin only)
app.post('/api/admin/templates/cache/clear', checkAuth, checkAdmin, (req, res) => {
  try {
    if (!fs.existsSync(TEMPLATES_DIR)) {
      return res.json({ success: true, message: 'Cache directory does not exist' });
    }

    const files = fs.readdirSync(TEMPLATES_DIR);
    let deleted = 0;
    let errors = [];

    files.forEach(file => {
      const filePath = path.join(TEMPLATES_DIR, file);
      try {
        fs.unlinkSync(filePath);
        deleted++;
      } catch (e) {
        errors.push(file + ': ' + e.message);
      }
    });

    res.json({
      success: true,
      deleted: deleted,
      errors: errors.length > 0 ? errors : null,
      message: `Cleared ${deleted} cached templates`
    });
  } catch (error) {
    (console.error(error), res.status(500).json({ error: 'Internal server error' }));
  }
});

// Get CPU Models
app.get('/api/cpu-models', (req, res) => {
  res.json(CPU_MODELS);
});

// Get SMBIOS options
app.get('/api/smbios', (req, res) => {
  res.json({
    manufacturers: SMBIOS_MANUFACTURERS,
    products: SMBIOS_PRODUCTS
  });
});

// Get Network Types
app.get('/api/network-types', (req, res) => {
  res.json(NETWORK_TYPES);
});

// Get DNS Providers
app.get('/api/dns-providers', (req, res) => {
  res.json(DNS_PROVIDERS);
});

// List available ISO files
app.get('/api/iso-list', (req, res) => {
  try {
    const files = fs.readdirSync(ISO_DIR).filter(f => f.endsWith('.iso'));
    res.json(files);
  } catch (error) {
    res.json([]);
  }
});

// ============= VIEW ROUTES (EJS Pages) =============

// Favicon endpoint
app.get('/favicon.ico', (req, res) => {
  res.redirect('/images/logo-new.svg');
});

// Middleware to pass user and settings to all views
app.use((req, res, next) => {
  // Set defaults first
  res.locals.user = req.session.userId ? {
    id: req.session.userId,
    username: req.session.username,
    role: req.session.role
  } : null;
  
  // Panel version from .env
  res.locals.panelVersion = process.env.PANEL_VERSION || 'V3.0';
  
  // Set default logo and site name
  res.locals.siteLogo = process.env.DEFAULT_LOGO_URL || '/images/logo-new.svg';
  res.locals.siteName = process.env.PANEL_NAME || 'VNM';
  
  // Load site settings from database (blocking, so sidebar reflects changes immediately)
  db.get(`SELECT setting_value FROM settings WHERE setting_key = 'site_icon_url' LIMIT 1`, (err, row) => {
    if (!err && row && row.setting_value) {
      res.locals.siteLogo = row.setting_value;
    }
    db.get(`SELECT setting_value FROM settings WHERE setting_key = 'site_name' LIMIT 1`, (err2, row2) => {
      if (!err2 && row2 && row2.setting_value) {
        res.locals.siteName = row2.setting_value;
      }
      next();
    });
  });
});

// License check middleware — silently bypassed
app.use((req, res, next) => { next(); });

// Mount the platform router AFTER the view-locals middleware above (so its
// pages receive siteLogo/siteName/user like every other view) but still
// before the legacy per-VM routes further down, whose snapshot stubs the
// platform's real qemu-img routes replace.
app.use(platform.router);

// Login page
app.get('/login', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.render('users/login', { 
    title: 'Login - VNM Panel',
    currentPage: 'login',
    siteLogo: res.locals.siteLogo || process.env.DEFAULT_LOGO_URL || '/images/logo-new.svg',
    siteName: res.locals.siteName || process.env.PANEL_NAME || 'VNM'
  });
});



// License Activation Page
app.get('/license_activation', checkAuth, (req, res) => {
  res.render('license_activation', {
    title: 'Activate License - VNM Panel',
    siteLogo: res.locals.siteLogo || '/images/logo-new.svg',
    siteName: res.locals.siteName || 'VNM'
  });
});

// License Activation POST
app.post('/api/license/activate', checkAuth, loginRateLimit, async (req, res) => {
  try {
    const result = await licenses.activateWithServer(req.body.license_key, req.session.username);
    auditLog.log({ ...auditLog.fromReq(req), action: 'license_activate', result: result.success ? 'success' : 'failure', details: result.message });
    res.json(result);
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// License status (used by the activation page, and can be polled elsewhere)
app.get('/api/license/status', checkAuth, async (req, res) => {
  try { res.json(await licenses.getStatusInfo()); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Deactivate the currently-activated license (frees the activation slot
// on the license server so it can be used on another install).
app.post('/api/license/deactivate', checkAuth, checkAdmin, async (req, res) => {
  try {
    await licenses.deactivateLocal('Deactivated by admin');
    auditLog.log({ ...auditLog.fromReq(req), action: 'license_deactivate', result: 'success' });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ============= PREMIUM FEATURES (VNM license key) =============
// Tier gating for Auto Backup / Live Migration / Alert Rules /
// Scheduled Power. The key is validated server-side against a
// SHA-256 digest (see premium.js) — the raw key is never stored.
app.get('/api/premium/status', checkAuth, async (req, res) => {
  try { res.json(await premium.getStatus()); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/premium/activate', checkAuth, loginRateLimit, async (req, res) => {
  try {
    const result = await premium.activate(req.body && req.body.key, req.session.username || 'web');
    auditLog.log({ ...auditLog.fromReq(req), action: 'premium_activate', result: result.success ? 'success' : 'failure', details: result.message });
    if (!result.success) return res.status(400).json({ error: result.message });
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/premium/deactivate', checkAuth, checkAdmin, async (req, res) => {
  try {
    await premium.deactivate(req.session.username || 'admin');
    auditLog.log({ ...auditLog.fromReq(req), action: 'premium_deactivate', result: 'success' });
    res.json({ success: true, message: 'Premium deactivated' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Dashboard - Normal users only
app.get('/dashboard', checkAuth, (req, res) => {
  // Show user dashboard (works for both regular users and admins)
  res.render('users/dashboard', {
    title: 'My VMs - VNM Panel',
    currentPage: 'dashboard',
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});
// Admin Dashboard - Admin only
app.get('/admin/dashboard', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/dashboard', {
    title: 'Dashboard - VNM Panel',
    currentPage: 'dashboard',
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// Virtual Machines list (Admin only)
app.get('/admin/vms', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vms', {
    title: 'Virtual Machines - VNM Panel',
    currentPage: 'vms'
  });
});

// Create VM (Admin only)
app.get('/admin/vm-create', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vm-create', {
    title: 'Create Virtual Machine - VNM Panel',
    currentPage: 'vm-create',
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// VM Details (Admin only)
app.get('/admin/vm/:id', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vm-detail', {
    title: 'VM Details - VNM Panel',
    currentPage: 'vm-detail',
    vmId: req.params.id
  });
});

// VM Console (Admin only)
app.get('/admin/vm/:id/console', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vm-console', {
    title: 'VM Console - VNM Panel',
    currentPage: 'vm-console',
    vmId: req.params.id
  });
});

// VM Edit Configuration Page (Admin only)
app.get('/admin/vm/:id/edit', checkAuth, checkAdmin, (req, res) => {
  db.get(`SELECT * FROM vms WHERE vm_id = ?`, [req.params.id], (err, vm) => {
    if (err || !vm) return res.status(404).render('users/404', { message: 'VM not found' });
    
    res.render('admin/vm-edit', {
      title: 'Edit VM - VNM Panel',
      currentPage: 'vm-edit',
      vmId: req.params.id,
      vm: vm
    });
  });
});

// Users management (admin only)
app.get('/admin/users', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/users', {
    title: 'Users - VNM Panel',
    currentPage: 'users'
  });
});

// Create new user page (admin only)
app.get('/admin/users/create', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/users-create', {
    title: 'Create User - VNM Panel',
    currentPage: 'users'
  });
});

// Edit user page (admin only)
app.get('/admin/users/:id/edit', checkAuth, checkAdmin, (req, res) => {
  const userId = parseInt(req.params.id);
  if (isNaN(userId)) {
    return res.status(400).render('admin/404', { title: 'Invalid User ID - VNM Panel', code: 400, message: 'Invalid User ID' });
  }
  
  res.render('admin/users-edit', {
    title: 'Edit User - VNM Panel',
    currentPage: 'users',
    userId: userId
  });
});

// Settings (admin only)
app.get('/admin/settings', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/settings', {
    title: 'Settings - VNM Panel',
    currentPage: 'settings'
  });
});

// OS Templates Management (admin only)
app.get('/admin/templates', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/templates', {
    title: 'OS Templates - VNM Panel',
    currentPage: 'templates'
  });
});

// Add OS Template (admin only)
app.get('/admin/templates/add', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/templates-add', {
    title: 'Add OS Template - VNM Panel',
    currentPage: 'templates'
  });
});

// Edit Built-in OS Template (admin only)
app.get('/admin/templates/builtin/:key/edit', checkAuth, checkAdmin, (req, res) => {
  const templateKey = req.params.key;
  console.log(`[ROUTE] GET /admin/templates/builtin/${templateKey}/edit`);
  
  if (!OS_TEMPLATES[templateKey]) {
    console.error(`[ERROR] Template key not found: ${templateKey}`);
    return res.status(400).render('admin/404', { title: 'Built-in Template Not Found - VNM Panel', code: 400, message: 'Built-in Template Not Found' });
  }
  
  const template = OS_TEMPLATES[templateKey];
  console.log(`[SUCCESS] Found built-in template: ${template.name}`);
  
  // Build template object for display
  const templateObj = {
    template_key: templateKey,
    template_name: template.name,
    template_type: template.type,
    icon: template.icon,
    description: `Built-in template for ${template.name}`,
    disk_size: template.disk_size,
    memory: template.memory,
    cpus: template.cpus,
    download_url: template.url,
    username: template.username,
    password: template.password,
    is_custom: 0,
    is_builtin: 1
  };
  
  res.render('admin/templates-edit', {
    title: `View ${template.name} - VNM Panel`,
    currentPage: 'templates',
    siteLogo: res.locals.siteLogo || '/images/logo-new.svg',
    templateKey: templateKey,
    isBuiltin: true,
    template: templateObj
  });
});

// ============= USER ROUTES (Non-Admin Users) =============

// User VMs list
app.get('/vms', checkAuth, (req, res) => {
  res.render('users/vms', {
    title: 'My Virtual Machines - VNM Panel',
    currentPage: 'vms',
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// Dedicated RDP pages (create / manage / connect) - admin and user versions
app.get('/admin/vm/:id/rdp', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vm-rdp', {
    title: 'Remote Desktop (RDP) - VNM Panel',
    currentPage: 'vm-detail',
    vmId: req.params.id
  });
});

app.get('/vm/:id/rdp', checkAuth, (req, res) => {
  res.render('users/vm-rdp', {
    title: 'Remote Desktop (RDP) - VNM Panel',
    currentPage: 'vm-detail',
    vmId: req.params.id,
    userId: req.session.userId,
    user: { username: req.session.username, role: req.session.role }
  });
});

// User VM detail page
app.get('/vm/:id', checkAuth, (req, res) => {
  res.render('users/vm-detail', {
    title: 'VM Details - VNM Panel',
    currentPage: 'vm-detail',
    vmId: req.params.id,
    userId: req.session.userId,
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// User VM console page
app.get('/vm/:id/console', checkAuth, (req, res) => {
  res.render('users/vm-console', {
    title: 'VM Console - VNM Panel',
    currentPage: 'vm-console',
    vmId: req.params.id,
    userId: req.session.userId,
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// User VM SSH connection page
app.get('/vm/:id/ssh', checkAuth, (req, res) => {
  res.render('users/vm-ssh', {
    title: 'SSH Connection - VNM Panel',
    currentPage: 'vm-ssh',
    vmId: req.params.id,
    userId: req.session.userId,
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// Admin VM SSH connection page
app.get('/admin/vm/:id/ssh', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vm-ssh', {
    title: 'SSH Connection - VNM Admin Panel',
    currentPage: 'vm-ssh',
    vmId: req.params.id,
    userId: req.session.userId,
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// VM File Manager page
app.get('/vm/:id/files', checkAuth, (req, res) => {
  res.render('users/vm-files', {
    title: 'File Manager - VNM Panel',
    currentPage: 'vm-files',
    vmId: req.params.id,
    userId: req.session.userId,
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// Admin VM File Manager page
app.get('/admin/vm/:id/files', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vm-files', {
    title: 'File Manager - VNM Admin Panel',
    currentPage: 'vm-files',
    vmId: req.params.id,
    userId: req.session.userId,
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// Admin Nodes page
app.get('/admin/nodes', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/nodes', {
    title: 'Nodes - VNM Admin Panel',
    currentPage: 'nodes',
    user: { username: req.session.username, role: req.session.role }
  });
});

// Node Terminal page (admin) - embedded shell on a single node.
app.get('/admin/nodes/:id/terminal', checkAuth, checkAdmin, async (req, res) => {
  try {
    const node = await nodeManager.getNode(req.params.id);
    if (!node) return res.status(404).send('Node not found');
    res.render('admin/node-terminal', {
      title: `Terminal: ${node.name} - VNM Admin Panel`,
      currentPage: 'nodes',
      user: { username: req.session.username, role: req.session.role },
      node: { id: node.id, name: node.name, mode: node.mode, online: nodeManager.isNodeOnline(node.id) }
    });
  } catch (e) {
    res.status(500).send('Could not load node');
  }
});

// User profile page
app.get('/profile', checkAuth, (req, res) => {
  res.render('users/profile', {
    title: 'My Profile - VNM Panel',
    currentPage: 'profile',
    user: {
      username: req.session.username,
      role: req.session.role,
      userId: req.session.userId
    }
  });
});

// ============= API ROUTES =============

// Get list of users for dropdown/assignment (accessible to admins)
app.get('/api/users/list', checkAuth, checkAdmin, (req, res) => {
  db.all(`SELECT id, username, email, role FROM users WHERE is_active = 1 ORDER BY username`, (err, users) => {
    if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
    res.json(users);
  });
});

app.get('/api/admin/users', checkAuth, checkAdmin, (req, res) => {
  db.all(`SELECT id, username, email, role, created_at, is_active FROM users`, (err, users) => {
    if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
    res.json(users);
  });
});

// Get single user
app.get('/api/admin/users/:id', checkAuth, checkAdmin, (req, res) => {
  const userId = parseInt(req.params.id);
  db.get(`SELECT id, username, email, full_name, role, created_at, is_active FROM users WHERE id = ?`, [userId], (err, user) => {
    if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  });
});

// Get user Discord info (for avatar display) - admin only
app.get('/api/admin/users/:id/discord-info', checkAuth, checkAdmin, (req, res) => {
  const userId = parseInt(req.params.id);
  db.get(
    `SELECT discord_id, discord_avatar FROM user_discord_accounts WHERE user_id = ?`,
    [userId],
    (err, discordAccount) => {
      if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
      // "No discord linked" is a normal state, not an error: return 200 with
      // linked:false instead of 404 (the users page polls this per row and a
      // 404 per unlinked user flooded the console with noise).
      if (!discordAccount) return res.json({ linked: false });
      res.json({ linked: true, discord_id: discordAccount.discord_id, discord_avatar: discordAccount.discord_avatar });
    }
  );
});

app.post('/api/admin/users', checkAuth, checkAdmin, (req, res) => {
  const { username, password, email, full_name, role } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  const hashedPassword = bcrypt.hashSync(password, 10);
  db.run(
    `INSERT INTO users (username, password, email, full_name, role, is_active) VALUES (?, ?, ?, ?, ?, 1)`,
    [username, hashedPassword, email || null, full_name || null, role || 'user'],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ error: 'Username already exists' });
        }
        return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
      }
      res.json({ success: true, id: this.lastID });
    }
  );
});

// Update user
app.put('/api/admin/users/:id', checkAuth, checkAdmin, (req, res) => {
  const userId = parseInt(req.params.id);
  const { email, full_name, password, role, is_active } = req.body;
  
  if (userId === 1 && role && role !== 'admin') {
    return res.status(400).json({ error: 'Default admin must remain an admin' });
  }
  
  let query = 'UPDATE users SET ';
  let values = [];
  
  if (email !== undefined) {
    query += 'email = ?, ';
    values.push(email);
  }
  
  if (full_name !== undefined) {
    query += 'full_name = ?, ';
    values.push(full_name);
  }
  
  if (password) {
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    query += 'password = ?, ';
    values.push(bcrypt.hashSync(password, 10));
  }
  
  if (role !== undefined) {
    query += 'role = ?, ';
    values.push(role);
  }
  
  if (is_active !== undefined) {
    query += 'is_active = ?, ';
    values.push(is_active ? 1 : 0);
  }
  
  // DEEP FIX: with no optional field present, slice(0, -2) used to eat the
  // "T " of "SET" producing "UPDATE users SE WHERE ..." -> SQL syntax error
  // -> 500. Reject explicitly instead.
  if (values.length === 0) {
    return res.status(400).json({ error: 'No fields to update' });
  }
  
  query = query.slice(0, -2); // Remove trailing comma and space
  query += ' WHERE id = ?';
  values.push(userId);
  
  db.run(query, values, (err) => {
    if (err) {
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(400).json({ error: 'Email already exists' });
      }
      return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
    }
    res.json({ success: true });
  });
});

app.delete('/api/admin/users/:id', checkAuth, checkAdmin, (req, res) => {
  if (req.params.id === '1') {
    return res.status(400).json({ error: 'Cannot delete default admin' });
  }
  db.run(`DELETE FROM users WHERE id = ?`, [req.params.id], (err) => {
    if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
    res.json({ success: true });
  });
});

// ============= VM MANAGEMENT (VM ID BASED) =============

app.get('/api/vms', checkAuth, (req, res) => {
  const userId = req.session.userId;
  
  // User pages always show ONLY the logged-in user's own VMs
  // (even if user is admin - they see their own VMs, not all VMs)
  // For all VMs, use /api/admin/vms endpoint
  let query = `SELECT vms.*, u.username as owner_username, COALESCE(t.icon, '⚫') as template_icon, COALESCE(t.template_name, vms.os_type) as template_name,
              n.name as node_name, n.mode as node_mode, COALESCE(n.manual_address, n.address) as node_address
              FROM vms
              LEFT JOIN users u ON vms.owner_id = u.id
              LEFT JOIN os_templates t ON vms.template_type = t.template_key
              LEFT JOIN nodes n ON vms.node_id = n.id
              WHERE vms.owner_id = ?
              ORDER BY vms.vm_id DESC`;
  let params = [userId];
  
  db.all(query, params, (err, vms) => {
    if (err) {
      console.error('[API Error] /api/vms:', err);
      return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
    }
    console.log(`[API Success] /api/vms: User ${userId} (${req.session.role}) fetched ${vms ? vms.length : 0} VMs (own VMs only)`);
    // SECURITY (list API): never ship the guest password field to the
    // browser. The owner/admin-gated detail endpoint keeps it for the
    // credentials card.
    res.json((vms || []).map(({ password, ...rest }) => rest));
  });
});

// Admin API endpoint: Get all VMs for admin pages
app.get('/api/admin/vms', checkAuth, checkAdmin, (req, res) => {
  const userId = req.session.userId;
  
  // Admin pages can see ALL VMs in the system
  let query = `SELECT vms.*, u.username as owner_username, COALESCE(t.icon, '⚫') as template_icon, COALESCE(t.template_name, vms.os_type) as template_name,
              n.name as node_name, n.mode as node_mode, COALESCE(n.manual_address, n.address) as node_address
              FROM vms
              LEFT JOIN users u ON vms.owner_id = u.id
              LEFT JOIN os_templates t ON vms.template_type = t.template_key
              LEFT JOIN nodes n ON vms.node_id = n.id
              ORDER BY vms.vm_id DESC`;
  let params = [];
  
  db.all(query, params, (err, vms) => {
    if (err) {
      console.error('[API Error] /api/admin/vms:', err);
      return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
    }
    console.log(`[API Success] /api/admin/vms: Admin ${userId} fetched ${vms ? vms.length : 0} VMs (all VMs)`);
    // SECURITY (list API): never ship the guest password field to the browser.
    res.json((vms || []).map(({ password, ...rest }) => rest));
  });
});

app.get('/api/vms/:vm_id', checkAuth, (req, res) => {
  const userId = req.session.userId;
  let query = `
    SELECT 
      vms.*,
      COALESCE(vms.ipv4_gateway, vms.gateway) as gateway,
      COALESCE(ot.icon, '⚫') as template_icon,
      n.id as node_ref_id, n.name as node_name, n.mode as node_mode,
      COALESCE(n.manual_address, n.address) as node_address,
      n.status as node_status
    FROM vms
    LEFT JOIN os_templates ot ON vms.template_type = ot.template_key
    LEFT JOIN nodes n ON vms.node_id = n.id
    WHERE vms.vm_id = ?
  `;
  let params = [req.params.vm_id];
  
  // Normal users can only see their own VMs
  if (req.session.role !== 'admin') {
    query += ` AND vms.owner_id = ?`;
    params.push(userId);
  }
  
  db.get(query, params, async (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });
    vm.port_forwards = await getPortForwards(vm.vm_id);
    res.json(vm);
  });
});

// VM CONSOLE - Stream last 100 lines of VM serial output
app.get('/api/vms/:vm_id/console', checkAuth, (req, res) => {
  const vm_id = req.params.vm_id;

  // DEEP FIX (IDOR): every other VM endpoint scopes non-admins to their own
  // VMs; this one served ANY VM's serial log (boot output plus every
  // console keystroke ever appended) to any logged-in user.
  let cq = `SELECT vm_id FROM vms WHERE vm_id = ?`;
  let cp = [vm_id];
  if (req.session.role !== 'admin') { cq += ` AND owner_id = ?`; cp.push(req.session.userId); }
  db.get(cq, cp, (cerr, crow) => {
    if (cerr || !crow) return res.status(404).json({ error: 'VM not found or access denied' });

    const logFile = path.join(VM_DIR, `vm-${vm_id}.log`);
    if (!fs.existsSync(logFile)) {
      return res.json({ vm_id: vm_id, logs: 'Console not available yet', lines: 0 });
    }
    try {
      const logs = fs.readFileSync(logFile, 'utf8');
      const lines = logs.split('\n');
      const last100 = lines.slice(-100).join('\n');
      res.json({
        vm_id: vm_id,
        logs: last100,
        total_lines: lines.length
      });
    } catch (error) {
      (console.error(error), res.status(500).json({ error: 'Internal server error' }));
    }
  });
});

// VM VNC STATUS - Pre-check before the browser opens the noVNC WebSocket,
// so "VM offline" / "VNC unavailable" / node-unreachable are shown as a
// normal UI message instead of a raw WebSocket close.
app.get('/api/vms/:vm_id/vnc-status', checkAuth, async (req, res) => {
  const userId = req.session.userId;
  let query = `SELECT * FROM vms WHERE vm_id = ?`;
  let params = [req.params.vm_id];
  if (req.session.role !== 'admin') { query += ` AND owner_id = ?`; params.push(userId); }

  db.get(query, params, async (err, vm) => {
    if (err || !vm) return res.status(404).json({ available: false, reason: 'VM not found or access denied' });
    if (vm.status !== 'running') return res.json({ available: false, reason: 'VM is offline - start it to use the console' });

    let node;
    try { node = await nodeManager.getNodeForVM(vm); } catch (e) { return res.json({ available: false, reason: 'Could not resolve node for this VM' }); }

    if (node && node.mode === 'remote') {
      try {
        const info = await nodeManager.sendNodeCommand(node.id, 'vm.vncinfo', { vm }, { timeoutMs: 10000 });
        return res.json(info && info.available ? { available: true } : { available: false, reason: 'VNC is not available for this VM yet - try restarting it' });
      } catch (e) {
        return res.json({ available: false, reason: e.message || 'Could not reach the node agent for this VM' });
      }
    }

    const info = getLocalVncInfo(vm.vm_id);
    return res.json(info.available ? { available: true } : { available: false, reason: 'VNC is not available for this VM yet - try restarting it' });
  });
});

// VM CONSOLE COMMAND - Send command to VM via serial console
app.post('/api/vms/:vm_id/console/command', checkAuth, async (req, res) => {
  const vm_id = req.params.vm_id;
  const { command } = req.body;
  const userId = req.session.userId;

  if (!command) {
    return res.status(400).json({ error: 'Command required' });
  }

  let query = `SELECT * FROM vms WHERE vm_id = ?`;
  let params = [vm_id];
  
  // Normal users can only send commands to their own VMs
  if (req.session.role !== 'admin') {
    query += ` AND owner_id = ?`;
    params.push(userId);
  }

  db.get(query, params, async (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });

    if (vm.status !== 'running') {
      return res.status(400).json({ error: 'VM is not running' });
    }

    try {
      const stdin = qemuStdins.get(String(vm_id));
      if (!stdin || stdin.destroyed) {
        return res.status(409).json({ error: 'VM console is not connected' });
      }
      // Actually write to the running QEMU process's stdin
      stdin.write(command.endsWith('\n') ? command : command + '\n');

      // Also append to log so it shows in console history
      const logFile = path.join(VM_DIR, `vm-${vm_id}.log`);
      fs.appendFileSync(logFile, command);

      console.log(`[VM-${vm_id}] Command executed: ${command}`);
      res.json({ 
        success: true, 
        message: 'Command sent to VM console',
        command: command,
        vmId: vm_id
      });
    } catch (error) {
      console.error(`[VM-${vm_id}] Error sending command:`, error.message);
      res.status(500).json({ error: 'Failed to send command: ' + error.message });
    }
  });
});

// GET VM EDIT CONFIG (retrieve editable fields)
app.get('/api/vms/:vm_id/edit', checkAuth, (req, res) => {
  let query = `SELECT * FROM vms WHERE vm_id = ?`;
  let params = [req.params.vm_id];
  if (req.session.role !== 'admin') {
    query += ` AND owner_id = ?`;
    params.push(req.session.userId);
  }
  db.get(query, params, (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });
    
    // Return editable fields
    res.json({
      vm_id: vm.vm_id,
      vm_name: vm.vm_name,
      hostname: vm.hostname,
      memory: vm.memory,
      cpus: vm.cpus,
      cpu_sockets: vm.cpu_sockets,
      cpu_cores: vm.cpu_cores,
      cpu_threads: vm.cpu_threads,
      cpu_model: vm.cpu_model,
      disk_size: vm.disk_size,
      status: vm.status,
      enable_acpi: vm.enable_acpi,
      enable_kvm: vm.enable_kvm,
      extra_args: vm.extra_args,
      network_type: vm.network_type,
      ipv4_address: vm.ipv4_address,
      ipv4_gateway: vm.ipv4_gateway,
      ipv4_netmask: vm.ipv4_netmask,
      dns_primary: vm.dns_primary,
      dns_secondary: vm.dns_secondary,
      ipv6_address: vm.ipv6_address,
      ipv6_gateway: vm.ipv6_gateway,
      mac_address: vm.mac_address,
      vlan_id: vm.vlan_id,
      autostart: !!vm.autostart,
      can_edit: vm.status === 'stopped'
    });
  });
});

// Resize disk qcow2 file (expand or shrink)
async function resizeDisk(vm_id, diskFilePath, newSize) {
  return new Promise((resolve, reject) => {
    try {
      if (!fs.existsSync(diskFilePath)) {
        return reject(new Error('Disk file not found'));
      }

      // Parse size to bytes (handle G, GB, T, TB)
      const parseSize = (sizeStr) => {
        const match = sizeStr.match(/^(\d+(?:\.\d+)?)\s*([KMGT]?B?)$/i);
        if (!match) return null;
        
        let size = parseFloat(match[1]);
        const unit = (match[2] || '').toUpperCase();
        
        const multipliers = { 'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4 };
        if (unit.startsWith('K')) size *= multipliers['K'];
        else if (unit.startsWith('M')) size *= multipliers['M'];
        else if (unit.startsWith('G')) size *= multipliers['G'];
        else if (unit.startsWith('T')) size *= multipliers['T'];
        
        return Math.floor(size);
      };

      const newSizeBytes = parseSize(newSize);
      if (!newSizeBytes) {
        return reject(new Error('Invalid size format. Use: 20G, 100GB, 1T, etc.'));
      }

      // Get current disk size from qemu-img (not file size, but virtual size)
      let currentSize;
      try {
        const infoOutput = execFileSync('qemu-img', ['info', diskFilePath, '--output=json'], { stdio: 'pipe', encoding: 'utf8' });
        const imageInfo = JSON.parse(infoOutput);
        currentSize = imageInfo['virtual-size'] || imageInfo['VirtualSize'] || 0;
        console.log(`[DISK-${vm_id}] Detected via qemu-img: Virtual size = ${(currentSize / (1024**3)).toFixed(2)}GB`);
      } catch (err) {
        console.warn(`[DISK-${vm_id}] Could not get size from qemu-img, falling back to file size`);
        const stats = fs.statSync(diskFilePath);
        currentSize = stats.size;
      }

      console.log(`[DISK-${vm_id}] Current: ${(currentSize / (1024**3)).toFixed(2)}GB, Target: ${(newSizeBytes / (1024**3)).toFixed(2)}GB`);

      if (newSizeBytes === currentSize) {
        return resolve({ message: 'size unchanged' });
      }

      // Determine if we're expanding or shrinking
      const isShrink = newSizeBytes < currentSize;
      const operation = isShrink ? 'shrink' : 'expand';

      // Use qemu-img to resize - always use +SIZE syntax for expand, =SIZE for shrink
      // AUDIT FIX (command injection): arguments are passed as an argv array to
      // execFileSync - no shell string interpolation of paths or sizes.
      const resizeArgs = isShrink
        ? ['resize', '--shrink', diskFilePath, newSize]
        : ['resize', diskFilePath, newSize];

      console.log(`[DISK-${vm_id}] ${operation.toUpperCase()}: Executing: qemu-img ${resizeArgs.join(' ')}`);
      
      // Execute and capture both stdout and stderr
      let output;
      try {
        output = execFileSync('qemu-img', resizeArgs, { stdio: 'pipe', encoding: 'utf8' });
        console.log(`[DISK-${vm_id}] Command output: ${output}`);
      } catch (execErr) {
        // Check if it's just a warning
        const stderr = execErr.stderr ? execErr.stderr.toString() : '';
        const stdout = execErr.stdout ? execErr.stdout.toString() : '';
        
        // If it's a shrink warning, it might still work
        if (isShrink && stderr.includes('Shrinking an image')) {
          console.log(`[DISK-${vm_id}] Shrink warning (expected):`, stderr);
        } else {
          throw execErr;
        }
      }

      console.log(`[DISK-${vm_id}] Disk ${operation}ed to ${newSize}`);
      resolve({ message: `${operation}ed to ${newSize}` });
    } catch (err) {
      reject(err);
    }
  });
}

// Regenerate cloud-init seed for a VM

// UPDATE VM CONFIGURATION (PUT request)
app.put('/api/vms/:vm_id/edit', checkAuth, (req, res) => {
  const vm_id = req.params.vm_id;
  const userId = req.session.userId;
  const {
    vm_name, hostname, memory, cpus, cpu_sockets, cpu_cores, cpu_threads, cpu_model,
    custom_cpu_name, username, password,
    disk_size, enable_acpi, enable_kvm, extra_args,
    network_type, ipv4_address, ipv4_gateway, ipv4_netmask, bridge_device,
    dns_primary, dns_secondary, ipv6_address, ipv6_gateway, mac_address, vlan_id,
    machine_type, board_name, product_name, custom_smbios_manufacturer,
    smbios_manufacturer, smbios_product, smbios_version, smbios_serial,
    ssh_port, ssh_port_static,
    nic_model, port_forwards,
    owner_id, autostart
  } = req.body;

  let query = `SELECT status, template_type, seed_file, ssh_port, ssh_port_static FROM vms WHERE vm_id = ?`;
  let params = [vm_id];
  
  // Normal users can only edit their own VMs
  if (req.session.role !== 'admin') {
    query += ` AND owner_id = ?`;
    params.push(userId);
  }

  db.get(query, params, (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });
    
    // Only allow editing stopped VMs
    if (vm.status !== 'stopped') {
      return res.status(400).json({ error: 'VM must be stopped to edit configuration' });
    }

    // Custom port-forward rules: full replace-set semantics (an empty
    // array clears every rule; omitting the key leaves them untouched).
    let pfReplace = null;
    if (port_forwards !== undefined) {
      const pfParsed = parsePortForwards(port_forwards, vm.ssh_port || vm.ssh_port_static);
      if (!pfParsed.ok) return res.status(400).json({ error: pfParsed.error });
      pfReplace = pfParsed.forwards || [];
    }

    // Store original VM state for change detection
    const originalVm = { ...vm };

    // Validate inputs - remove strict limits, allow any positive values
    const validatedMemory = memory ? parseInt(memory) : undefined;
    if (validatedMemory && validatedMemory < 1) {
      return res.status(400).json({ error: 'Memory must be at least 1 MB' });
    }
    
    const validatedCpus = cpus ? parseInt(cpus) : undefined;
    if (validatedCpus && validatedCpus < 1) {
      return res.status(400).json({ error: 'CPUs must be at least 1' });
    }
    
    const validatedSockets = cpu_sockets && cpu_sockets >= 1 ? cpu_sockets : undefined;
    const validatedCores = cpu_cores && cpu_cores >= 1 ? cpu_cores : undefined;
    const validatedThreads = cpu_threads && cpu_threads >= 1 ? cpu_threads : undefined;

    // Build update query dynamically
    const updates = [];
    const values = [];

    if (vm_name) { updates.push('vm_name = ?'); values.push(vm_name); }
    if (hostname) { updates.push('hostname = ?'); values.push(hostname); }
    if (validatedMemory) { updates.push('memory = ?'); values.push(validatedMemory); }
    if (validatedCpus) { updates.push('cpus = ?'); values.push(validatedCpus); }
    if (validatedSockets) { updates.push('cpu_sockets = ?'); values.push(validatedSockets); }
    if (validatedCores) { updates.push('cpu_cores = ?'); values.push(validatedCores); }
    if (validatedThreads) { updates.push('cpu_threads = ?'); values.push(validatedThreads); }
    if (cpu_model) { updates.push('cpu_model = ?'); values.push(cpu_model); }
    if (disk_size) {
      try {
        const cleanDiskSize = sanitizeDiskSize(disk_size);
        updates.push('disk_size = ?'); values.push(cleanDiskSize);
      } catch (e) {
        return res.status(400).json({ error: e.message });
      }
    }
    if (username) { updates.push('username = ?'); values.push(username); }
    if (password) { updates.push('password = ?'); values.push(password); }
    if (autostart !== undefined) { updates.push('autostart = ?'); values.push(autostart ? 1 : 0); }
    if (enable_acpi !== undefined) { updates.push('enable_acpi = ?'); values.push(enable_acpi ? 1 : 0); }
    if (enable_kvm !== undefined) { updates.push('enable_kvm = ?'); values.push(enable_kvm ? 1 : 0); }
    if (extra_args !== undefined) { updates.push('extra_args = ?'); values.push(extra_args || ''); }
    if (network_type) { updates.push('network_type = ?'); values.push(network_type); }
    if (ipv4_address !== undefined) { updates.push('ipv4_address = ?'); values.push(ipv4_address); }
    if (ipv4_gateway !== undefined) { updates.push('ipv4_gateway = ?'); values.push(ipv4_gateway); }
    if (ipv4_netmask !== undefined) { updates.push('ipv4_netmask = ?'); values.push(ipv4_netmask); }
    if (bridge_device !== undefined) { updates.push('bridge_device = ?'); values.push(bridge_device || 'vmbr0'); }
    if (dns_primary) { updates.push('dns_primary = ?'); values.push(dns_primary); }
    if (dns_secondary) { updates.push('dns_secondary = ?'); values.push(dns_secondary); }
    if (ipv6_address !== undefined) { updates.push('ipv6_address = ?'); values.push(ipv6_address); }
    if (ipv6_gateway !== undefined) { updates.push('ipv6_gateway = ?'); values.push(ipv6_gateway); }
    if (mac_address) { updates.push('mac_address = ?'); values.push(mac_address); }
    if (vlan_id !== undefined) { updates.push('vlan_id = ?'); values.push(vlan_id); }
    if (custom_cpu_name) { updates.push('custom_cpu_name = ?'); values.push(custom_cpu_name); }
    if (board_name) { updates.push('board_name = ?'); values.push(board_name); }
    if (product_name) { updates.push('product_name = ?'); values.push(product_name); }
    if (machine_type) { updates.push('machine_type = ?'); values.push(machine_type); }
    if (smbios_manufacturer) { updates.push('smbios_manufacturer = ?'); values.push(smbios_manufacturer); }
    if (smbios_product) { updates.push('smbios_product = ?'); values.push(smbios_product); }
    if (smbios_version) { updates.push('smbios_version = ?'); values.push(smbios_version); }
    if (smbios_serial) { updates.push('smbios_serial = ?'); values.push(smbios_serial); }
    
    // Handle SSH port - the two columns (ssh_port = auto-allocated,
    // ssh_port_static = user-set override) must never diverge, since
    // getSSHPort()/consumers prioritize ssh_port first. Whichever one the
    // caller supplies becomes authoritative and is mirrored into both
    // columns so an edit via ssh_port_static can't be silently shadowed
    // by a stale ssh_port value (this was the root cause of edits being
    // ignored).
    if (ssh_port_static !== undefined) {
      updates.push('ssh_port_static = ?', 'ssh_port = ?');
      values.push(ssh_port_static, ssh_port_static);
    } else if (ssh_port !== undefined) {
      updates.push('ssh_port = ?', 'ssh_port_static = ?');
      values.push(ssh_port, ssh_port);
    }

    if (nic_model !== undefined) {
      if (!NIC_MODELS.includes(nic_model)) {
        return res.status(400).json({ error: 'Invalid NIC model - use virtio-net-pci, e1000, e1000e, rtl8139 or vmxnet3' });
      }
      updates.push('nic_model = ?');
      values.push(nic_model);
    }
    
    // Only admins can change owner
    if (owner_id !== undefined && req.session.role === 'admin') {
      updates.push('owner_id = ?');
      values.push(owner_id || null); // Allow null to clear owner
      console.log(`[VM ${vm_id}] Admin changing owner to ${owner_id || 'null'}`);
    }

    if (updates.length === 0) {
      if (pfReplace === null) {
        return res.status(400).json({ error: 'No valid fields to update' });
      }
      // A port_forwards-only edit changes no vms column - keep the UPDATE
      // a valid no-op so the rule replace-set below still runs.
      updates.push('vm_id = vm_id');
    }

    values.push(vm_id);
    const query = `UPDATE vms SET ${updates.join(', ')} WHERE vm_id = ?`;

    db.run(query, values, async (err) => {
      if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));

      // Apply the port-forward replace-set once the VM row is updated.
      if (pfReplace) {
        db.run(`DELETE FROM vm_port_forwards WHERE vm_id = ?`, [vm_id]);
        for (const pf of pfReplace) {
          db.run(`INSERT INTO vm_port_forwards (vm_id, protocol, label, host_port, guest_port) VALUES (?, ?, ?, ?, ?)`,
            [vm_id, pf.protocol, pf.label, pf.host_port, pf.guest_port]);
        }
        console.log(`[VM-${vm_id}] Port forwards updated: ${pfReplace.length} rule(s)`);
      }
      
      try {
        // ALWAYS regenerate cloud-init seed when editing ANY field on a cloud-init VM
        // Delete old seed ISO and create new one with current config
        console.log(`[VM-${vm_id}] Template type check: '${originalVm.template_type}'`);
        
        // Always regenerate regardless of template_type
        console.log(`[VM-${vm_id}] ✓ Regenerating seed with current configuration...`);
        
        // Always delete old seed ISO first
        const seedIsoPath = path.join(VM_DIR, `vm-${vm_id}-seed.iso`);
        console.log(`[VM-${vm_id}] Checking for old seed: ${seedIsoPath}`);
        
        if (fs.existsSync(seedIsoPath)) {
          try {
            fs.unlinkSync(seedIsoPath);
            console.log(`[VM-${vm_id}] ✓ Deleted old seed ISO: ${seedIsoPath}`);
          } catch (delErr) {
            console.error(`[VM-${vm_id}] Failed to delete old seed: ${delErr.message}`);
          }
        } else {
          console.log(`[VM-${vm_id}] Old seed not found (OK if first time)`);
        }
        
        // Fetch updated VM with new config and create new seed ISO
        db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vm_id], (err, updatedVm) => {
          if (err) {
            console.error(`[VM-${vm_id}] Failed to fetch updated VM:`, err.message);
            return;
          }
          
          if (!updatedVm) {
            console.error(`[VM-${vm_id}] Updated VM not found in database`);
            return;
          }
          
          console.log(`[VM-${vm_id}] Creating new seed ISO with config - network_type: ${updatedVm.network_type}, ipv4: ${updatedVm.ipv4_address}, gateway: ${updatedVm.ipv4_gateway || updatedVm.gateway}`);
          
          // Remote-node VMs: rebuild the seed ON that node (same content,
          // different filesystem) - a panel-local ISO would be invisible
          // to the node's QEMU. Local VMs keep the direct call.
          nodeManager.getNodeForVM(updatedVm)
            .then((node) => {
              if (node && node.mode === 'remote') {
                return nodeManager.sendNodeCommand(node.id, 'vm.createSeed', {
                  vmId: String(vm_id),
                  cloudInit: buildCloudInitFiles(updatedVm, vm_id)
                }, { timeoutMs: 60000 });
              }
              return createCloudInitSeed(vm_id, updatedVm);
            })
            .then(() => {
              console.log(`[VM-${vm_id}] ✓ New cloud-init seed ISO created successfully`);
              logVMAction(vm_id, 'edit', 'success', `Cloud-init seed regenerated with updated configuration. Changes will apply on next VM boot.`);
            })
            .catch(seedErr => {
              console.error(`[VM-${vm_id}] ✗ Failed to create cloud-init seed: ${seedErr.message}`);
              logVMAction(vm_id, 'edit', 'warning', `Configuration updated but cloud-init seed creation failed: ${seedErr.message}`);
            });
        });
      } catch (err) {
        console.error(`[VM-${vm_id}] Error during seed regeneration:`, err.message);
      }
      
      res.json({ success: true, message: 'VM configuration updated', vm_id });
    });
  });
});

app.get('/api/vms/:vm_id/stats', checkAuth, async (req, res) => {
  try {
    let statsQuery = `SELECT * FROM vms WHERE vm_id = ?`;
    let statsParams = [req.params.vm_id];
    if (req.session.role !== 'admin') {
      statsQuery += ` AND owner_id = ?`;
      statsParams.push(req.session.userId);
    }
    db.get(statsQuery, statsParams, async (err, vm) => {
      if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });

      const stats = {
        vm_id: vm.vm_id,
        vm_name: vm.vm_name,
        status: vm.status,
        memory: vm.memory,
        cpus: vm.cpus,
        disk_size: vm.disk_size,
        uptime: vm.uptime || 0,
        cpu_usage: 0,
        memory_usage: 0,
        disk_usage: 'N/A',
        pid: vmProcesses.get(vm.vm_id) || null
      };

      if (vm.status === 'running' && vmProcesses.has(vm.vm_id)) {
        const pidFile = path.join(VM_DIR, `vm-${vm.vm_id}.pid`);
        try {
          if (fs.existsSync(pidFile)) {
            const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim());
            const { stdout } = await execPromise(`ps -p ${pid} -o %cpu,%mem,etime --no-headers 2>/dev/null || echo "0 0 0:00"`);
            const lines = stdout.trim().split('\n');
            if (lines.length > 0) {
              const data = lines[0].trim().split(/\s+/);
              stats.cpu_usage = parseFloat(data[0]) || 0;
              stats.memory_usage = parseFloat(data[1]) || 0;
            }
          }
        } catch (e) {
          // Silent fail
        }

        if (fs.existsSync(vm.disk_file)) {
          const size = fs.statSync(vm.disk_file).size / (1024 * 1024 * 1024);
          stats.disk_usage = size.toFixed(2) + ' GB';
        }
      }

      res.json(stats);
    });
  } catch (error) {
    (console.error(error), res.status(500).json({ error: 'Internal server error' }));
  }
});

// ============================================
// VM REINSTALL ENDPOINT
// ============================================
// POST /api/vms/:vm_id/reinstall
// Owner can reinstall their VM with a different OS template
// Deletes disk and seed ISO but keeps logs
app.post('/api/vms/:vm_id/reinstall', checkAuth, async (req, res) => {
  try {
    const vm_id = req.params.vm_id;
    const { new_os_template, new_username, new_password, confirm } = req.body;
    const userId = req.session.userId;

    if (!confirm) {
      return res.status(400).json({ error: 'Reinstall must be confirmed' });
    }

    if (!new_os_template) {
      return res.status(400).json({ error: 'Please select an OS template' });
    }

    // Get VM - only admins or the actual owner may reinstall; a NULL
    // owner_id is an orphaned VM and should require admin action, not be
    // grabbable by any authenticated user.
    const getVmQuery = req.session.role === 'admin' 
      ? `SELECT * FROM vms WHERE vm_id = ?`
      : `SELECT * FROM vms WHERE vm_id = ? AND owner_id = ?`;
    
    const params = req.session.role === 'admin' 
      ? [vm_id]
      : [vm_id, userId];

    db.get(getVmQuery, params, async (err, vm) => {
      if (err || !vm) {
        return res.status(404).json({ error: 'VM not found or access denied' });
      }

      // Only allow reinstall if VM is stopped
      if (vm.status !== 'stopped') {
        return res.status(400).json({ error: 'VM must be stopped to reinstall' });
      }

      console.log(`[VM-${vm_id}] ✓ Starting reinstall with template: ${new_os_template}`);
      console.log(`[VM-${vm_id}] Current status: ${vm.status}`);

      try {
        // Validate new template
        let template = null;
        let isCloudInit = false;
        let templateName = 'Custom OS';
        let username = new_username || 'root';
        let password = new_password || 'password';

        if (OS_TEMPLATES[new_os_template]) {
          // Built-in template
          template = OS_TEMPLATES[new_os_template];
          isCloudInit = true;
          templateName = template.name;
          username = new_username || template.username;
          password = new_password || template.password;
          console.log(`[VM-${vm_id}] Using built-in template: ${templateName}`);
        } else {
          // Check database for custom template
          const customTemplate = await new Promise((resolve, reject) => {
            db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [new_os_template], (err, result) => {
              if (err) reject(err);
              else resolve(result);
            });
          });

          if (!customTemplate) {
            const builtInKeys = Object.keys(OS_TEMPLATES);
            return res.status(400).json({ 
              error: `Invalid OS template: ${new_os_template}. Available: ${builtInKeys.join(', ')}` 
            });
          }

          template = customTemplate;
          isCloudInit = customTemplate.template_type === 'cloud-init';
          templateName = customTemplate.template_name;
          username = new_username || customTemplate.username || 'ubuntu';
          password = new_password || customTemplate.password || 'password';
          console.log(`[VM-${vm_id}] Using custom template: ${templateName}`);
        }

        // Update the DB record FIRST, before touching any files on disk.
        // If this fails, the VM is untouched and can be retried; previously
        // the old disk/seed were deleted before this update, so a DB failure
        // here would have left the VM pointing at a template with no disk.
        db.run(
          `UPDATE vms SET 
            os_type = ?, template_type = ?, username = ?, password = ?,
            img_file = '', seed_file = ?, disk_file = ?
          WHERE vm_id = ?`,
          [templateName, new_os_template, username, password, vm.seed_file, vm.disk_file, vm_id],
          async (err) => {
            if (err) {
              console.error(`[VM-${vm_id}] Failed to update VM info:`, err.message);
              return res.status(500).json({ error: 'Failed to update VM: ' + err.message });
            }

            console.log(`[VM-${vm_id}] ✓ VM info updated - template: ${templateName}, user: ${username}`);

            // DEEP FIX (reinstall atomicity): a failure after the row update
            // used to leave the DB claiming the NEW template/credentials
            // while the disk still contained the OLD OS (unusable VM), or -
            // worse - the old disk was deleted before the new image was
            // built, so a failed download meant permanent data loss. The
            // helpers below stage old artifacts aside and restore them (plus
            // the old DB values) on any failure path.
            const reinstallPrev = { os_type: vm.os_type, template_type: vm.template_type, username: vm.username, password: vm.password };
            const reinstallBak = { disk: null, seed: null };
            const rollbackReinstall = (reason) => {
              try {
                if (reinstallBak.disk && fs.existsSync(reinstallBak.disk)) {
                  try { if (fs.existsSync(vm.disk_file)) fs.unlinkSync(vm.disk_file); } catch (e) {}
                  fs.renameSync(reinstallBak.disk, vm.disk_file);
                }
                if (reinstallBak.seed && fs.existsSync(reinstallBak.seed)) {
                  try { if (fs.existsSync(vm.seed_file)) fs.unlinkSync(vm.seed_file); } catch (e) {}
                  fs.renameSync(reinstallBak.seed, vm.seed_file);
                }
                db.run(`UPDATE vms SET os_type = ?, template_type = ?, username = ?, password = ?, img_file = ?, seed_file = ?, disk_file = ? WHERE vm_id = ?`,
                  [reinstallPrev.os_type, reinstallPrev.template_type, reinstallPrev.username, reinstallPrev.password,
                   vm.img_file || '', vm.seed_file, vm.disk_file, vm_id]);
                logVMAction(vm_id, 'reinstall', 'rolled_back', `Reinstall rolled back: ${reason}`);
                console.warn(`[VM-${vm_id}] Reinstall rolled back: ${reason}`);
              } catch (e) {
                console.error(`[VM-${vm_id}] Rollback incomplete:`, e.message);
              }
            };
            const discardReinstallBak = () => {
              try {
                if (reinstallBak.disk && fs.existsSync(reinstallBak.disk)) fs.unlinkSync(reinstallBak.disk);
                if (reinstallBak.seed && fs.existsSync(reinstallBak.seed)) fs.unlinkSync(reinstallBak.seed);
              } catch (e) { console.warn(`[VM-${vm_id}] Backup cleanup (non-fatal):`, e.message); }
            };

            // A reinstall wipes the guest, so xrdp is gone: release the RDP
            // port and require "Enable RDP" to be run again.
            rdp.resetVm(vm_id, 'reinstall').catch((e) => console.error(`[VM-${vm_id}] RDP reset after reinstall failed: ${e.message}`));

            // ---- Remote node: re-provision ON the node itself ----------
            // The node's agent wipes this VM's old disk/seed and builds new
            // ones from the new template - the same protocol as initial
            // creation. No panel-local files are involved (a remote VM has
            // none), so the local cleanup/recreate code below is skipped.
            {
              const node = await nodeManager.getNodeForVM(vm).catch(() => null);
              if (node && node.mode === 'remote') {
                if (!nodeManager.isNodeOnline(node.id)) {
                  rollbackReinstall(`node "${node.name}" offline`);
                  return res.status(409).json({ error: `Node "${node.name}" is offline - cannot reinstall`, code: 'NODE_OFFLINE' });
                }
                try {
                  let templateSpec = null;
                  if (isCloudInit) {
                    if (OS_TEMPLATES[new_os_template]) {
                      const t = OS_TEMPLATES[new_os_template];
                      const urls = (t.download_urls && t.download_urls.length ? t.download_urls : [t.url]).filter(Boolean);
                      templateSpec = urls.length ? { key: new_os_template, urls } : null;
                    } else {
                      const ct = await new Promise((resolve, reject) => db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [new_os_template], (e, r) => e ? reject(e) : resolve(r)));
                      const safeKey = String(new_os_template).replace(/[^A-Za-z0-9._-]/g, '_');
                      if (ct && ct.download_url) templateSpec = { key: new_os_template, urls: [ct.download_url] };
                      else if (ct && ct.local_path && fs.existsSync(ct.local_path)) templateSpec = { key: new_os_template, streamedName: `${safeKey}-template.qcow2`, _localPath: ct.local_path };
                    }
                  }
                  if (templateSpec && templateSpec.streamedName) {
                    console.log(`[VM-${vm_id}] Streaming template image to node "${node.name}"...`);
                    await nodeManager.relayNodeFileUpload(node.id,
                      { name: templateSpec.streamedName, totalBytes: fs.statSync(templateSpec._localPath).size },
                      fs.createReadStream(templateSpec._localPath, { highWaterMark: 1024 * 1024 }));
                  }
                  const vmNow = await new Promise((resolve, reject) => db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vm_id], (e, r) => e ? reject(e) : resolve(r)));
                  const prov = await nodeManager.sendNodeCommand(node.id, 'vm.provision', {
                    vm: {
                      vm_id,
                      disk_size: vmNow.disk_size || '20G',
                      memory: vmNow.memory, cpus: vmNow.cpus,
                      ssh_port: getSSHPort(vmNow),
                      network_type: vmNow.network_type,
                      mac_address: vmNow.mac_address
                    },
                    template: templateSpec ? { key: templateSpec.key, urls: templateSpec.urls || undefined, streamedName: templateSpec.streamedName } : null,
                    cloudInit: isCloudInit ? buildCloudInitFiles(vmNow, vm_id) : null
                  }, { timeoutMs: 30 * 60 * 1000 });
                  await new Promise((resolve, reject) => db.run(
                    `UPDATE vms SET disk_file = ?, seed_file = ?, img_file = '' WHERE vm_id = ?`,
                    [prov.diskPath, prov.seedPath || '', vm_id],
                    (e) => e ? reject(e) : resolve()));
                  logVMAction(vm_id, 'reinstall', 'success', `VM reinstalled with ${templateName} on node "${node.name}". New credentials: ${username} / ****. VM ready to start.`);
                  return res.json({ success: true, message: `VM ${vm_id} reinstalled successfully with ${templateName} on node "${node.name}". Ready to start.`, vm_id });
                } catch (e) {
                  console.error(`[VM-${vm_id}] Remote reinstall failed:`, e.message);
                  logVMAction(vm_id, 'reinstall', 'error', `Remote reinstall failed: ${e.message}`);
                  return res.status(e.httpStatus || 502).json({ error: 'Reinstall failed: ' + e.message });
                }
              }
            }

            // Stage the old disk/seed aside instead of deleting them - they
            // are only discarded once the new image is fully built (see
            // discardReinstallBak) and restored on failure (rollbackReinstall).
            console.log(`[VM-${vm_id}] Staging old disk/seed aside (recoverable until the new image is ready)...`);

            if (vm.disk_file && fs.existsSync(vm.disk_file)) {
              try {
                reinstallBak.disk = `${vm.disk_file}.reinstall-bak`;
                fs.renameSync(vm.disk_file, reinstallBak.disk);
                console.log(`[VM-${vm_id}] ✓ Old disk staged: ${reinstallBak.disk}`);
              } catch (err) {
                console.warn(`[VM-${vm_id}] ⚠ Failed to stage old disk:`, err.message);
                reinstallBak.disk = null;
              }
            }

            if (vm.seed_file && fs.existsSync(vm.seed_file)) {
              try {
                reinstallBak.seed = `${vm.seed_file}.reinstall-bak`;
                fs.renameSync(vm.seed_file, reinstallBak.seed);
                console.log(`[VM-${vm_id}] ✓ Old seed staged: ${reinstallBak.seed}`);
              } catch (err) {
                console.warn(`[VM-${vm_id}] ⚠ Failed to stage old seed:`, err.message);
                reinstallBak.seed = null;
              }
            }

            try {
              // Re-download/setup template if cloud-init
              if (isCloudInit) {
                console.log(`[VM-${vm_id}] Preparing cloud-init template...`);

                db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vm_id], async (err, updatedVm) => {
                  if (err || !updatedVm) {
                    console.error(`[VM-${vm_id}] Failed to fetch updated VM`);
                    logVMAction(vm_id, 'reinstall', 'error', 'Failed to re-fetch VM after update');
                    rollbackReinstall('could not reload VM record');
                    return res.status(500).json({ error: 'Reinstall failed: could not reload VM record after update' });
                  }

                  try {
                    // Handle template download/copy
                    let imgSourcePath = null;

                    if (OS_TEMPLATES[new_os_template]) {
                      // Built-in template - check cache
                      const cachedTemplateName = `${new_os_template}-template.qcow2`;
                      const cachedTemplatePath = path.join(TEMPLATES_DIR, cachedTemplateName);

                      if (fs.existsSync(cachedTemplatePath)) {
                        console.log(`[VM-${vm_id}] ✓ Using cached template: ${cachedTemplatePath}`);
                        imgSourcePath = cachedTemplatePath;
                      } else {
                        // Download template
                        const downloadUrl = OS_TEMPLATES[new_os_template].url;
                        console.log(`[VM-${vm_id}] Downloading template from: ${downloadUrl}`);
                        
                        await downloadTemplate(new_os_template, cachedTemplatePath);
                        imgSourcePath = cachedTemplatePath;
                        console.log(`[VM-${vm_id}] ✓ Template downloaded and cached`);
                      }
                    } else {
                      // Custom template - use local path
                      const customTemplate = await new Promise((resolve, reject) => {
                        db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [new_os_template], (err, result) => {
                          if (err) reject(err);
                          else resolve(result);
                        });
                      });

                      if (customTemplate && customTemplate.local_path && fs.existsSync(customTemplate.local_path)) {
                        imgSourcePath = customTemplate.local_path;
                        console.log(`[VM-${vm_id}] ✓ Using custom template: ${imgSourcePath}`);
                      }
                    }

                    if (!imgSourcePath) {
                      console.error(`[VM-${vm_id}] Failed to locate template`);
                      logVMAction(vm_id, 'reinstall', 'error', 'Failed to locate OS template');
                      rollbackReinstall('OS template image not found');
                      return res.status(500).json({ error: 'Reinstall failed: could not locate the OS template image' });
                    }

                    // Create new disk from template
                    console.log(`[VM-${vm_id}] Creating new disk from template...`);
                    const diskSizeVal = sanitizeDiskSize(updatedVm.disk_size, '20G');
                    
                    try {
                      // Copy template to disk file
                      const copyCommand = process.platform === 'win32'
                        ? `Copy-Item -Path "${imgSourcePath}" -Destination "${updatedVm.disk_file}" -Force`
                        : `cp "${imgSourcePath}" "${updatedVm.disk_file}"`;

                      execSync(copyCommand, { shell: process.platform === 'win32' ? 'powershell' : '/bin/bash' });
                      console.log(`[VM-${vm_id}] ✓ Disk file created`);

                      // Resize disk to specified size
                      const resizeCommand = process.platform === 'win32'
                        ? `qemu-img resize "${updatedVm.disk_file}" "${diskSizeVal}"`
                        : `qemu-img resize "${updatedVm.disk_file}" "${diskSizeVal}"`;

                      execSync(resizeCommand, { stdio: 'pipe' });
                      console.log(`[VM-${vm_id}] ✓ Disk resized to ${diskSizeVal}`);

                      // Create new cloud-init seed
                      console.log(`[VM-${vm_id}] Creating cloud-init seed with new credentials...`);
                      await createCloudInitSeed(vm_id, updatedVm);
                      console.log(`[VM-${vm_id}] ✓ Cloud-init seed created`);

                      // New disk + seed fully built - now the old artifacts
                      // can be discarded for real.
                      discardReinstallBak();

                      // Log the action
                      logVMAction(vm_id, 'reinstall', 'success', 
                        `VM reinstalled with ${templateName}. Old disk and seed deleted. New credentials: ${username} / ****. VM ready to start.`);

                      res.json({ 
                        success: true, 
                        message: `VM ${vm_id} reinstalled successfully with ${templateName}. Ready to start.`,
                        vm_id 
                      });

                    } catch (err) {
                      console.error(`[VM-${vm_id}] Disk creation failed:`, err.message);
                      logVMAction(vm_id, 'reinstall', 'error', `Disk creation failed: ${err.message}`);
                      rollbackReinstall('disk creation failed: ' + err.message);
                      res.status(500).json({ error: 'Failed to create disk: ' + err.message });
                    }

                  } catch (err) {
                    console.error(`[VM-${vm_id}] Reinstall failed:`, err.message);
                    logVMAction(vm_id, 'reinstall', 'error', `Reinstall failed: ${err.message}`);
                    rollbackReinstall(err.message);
                    res.status(500).json({ error: 'Reinstall failed: ' + err.message });
                  }
                });

              } else {
                // Non-cloud-init template (ISO)
                discardReinstallBak();
                logVMAction(vm_id, 'reinstall', 'success', `VM configuration updated for ${templateName}. Ready to start.`);
                res.json({ 
                  success: true, 
                  message: `VM updated to ${templateName}. Ready to start.`,
                  vm_id 
                });
              }

            } catch (err) {
              console.error(`[VM-${vm_id}] Post-reinstall processing failed:`, err.message);
              logVMAction(vm_id, 'reinstall', 'error', `Post-reinstall processing failed: ${err.message}`);
              rollbackReinstall('post-reinstall processing failed: ' + err.message);
              res.status(500).json({ error: 'Post-reinstall processing failed: ' + err.message });
            }
          }
        );

      } catch (err) {
        console.error(`[VM-${vm_id}] Reinstall error:`, err.message);
        logVMAction(vm_id, 'reinstall', 'error', err.message);
        res.status(500).json({ error: 'Reinstall failed: ' + err.message });
      }
    });

  } catch (err) {
    console.error(`Reinstall endpoint error:`, err.message);
    (console.error(err), res.status(500).json({ error: 'Internal server error' }));
  }
});

// VM CREATE (Admin only)
// ---- Networking upgrade helpers ------------------------------------
// Selectable virtual NIC models (QEMU -device). VirtIO is the default and
// fastest; the others trade speed for guest driver compatibility.
const NIC_MODELS = ['virtio-net-pci', 'e1000', 'e1000e', 'rtl8139', 'vmxnet3'];

// Validate custom port-forward rules. Returns { ok, forwards } - forwards
// is null when the caller did not send the key at all (edit = no change),
// an array (possibly empty = clear all) when it did.
function parsePortForwards(raw, sshPort) {
  if (raw === undefined || raw === null) return { ok: true, forwards: null };
  if (!Array.isArray(raw)) return { ok: false, error: 'port_forwards must be an array' };
  if (raw.length > 16) return { ok: false, error: 'Too many port forwards (max 16)' };
  const seen = new Set();
  const out = [];
  for (const f of raw) {
    if (!f || typeof f !== 'object') return { ok: false, error: 'Invalid port forward entry' };
    const protocol = String(f.protocol || 'tcp').toLowerCase();
    if (!['tcp', 'udp'].includes(protocol)) return { ok: false, error: 'Port forward protocol must be "tcp" or "udp"' };
    const hostPort = parseInt(f.host_port, 10);
    const guestPort = parseInt(f.guest_port, 10);
    if (!Number.isInteger(hostPort) || hostPort < 1 || hostPort > 65535) return { ok: false, error: 'Host port must be an integer between 1 and 65535' };
    if (!Number.isInteger(guestPort) || guestPort < 1 || guestPort > 65535) return { ok: false, error: 'Guest port must be an integer between 1 and 65535' };
    if (sshPort && hostPort === parseInt(sshPort, 10)) return { ok: false, error: 'Host port ' + hostPort + ' conflicts with this VM\'s SSH port' };
    const key = protocol + ':' + hostPort;
    if (seen.has(key)) return { ok: false, error: 'Duplicate host port ' + hostPort + '/' + protocol };
    seen.add(key);
    const label = String(f.label || '').trim().slice(0, 40);
    out.push({ protocol, host_port: hostPort, guest_port: guestPort, label: label || (protocol + ' ' + hostPort + '-&gt;' + guestPort) });
  }
  return { ok: true, forwards: out };
}

// Fetch a VM's port-forward rules (never throws - empty list on error).
function getPortForwards(vmId) {
  return new Promise((resolve) => {
    db.all(`SELECT id, protocol, label, host_port, guest_port FROM vm_port_forwards WHERE vm_id = ? ORDER BY host_port`, [vmId], (err, rows) => resolve(err ? [] : (rows || [])));
  });
}

app.post('/api/vms', checkAuth, checkAdmin, async (req, res) => {
  const { 
    vm_name, os_template, hostname, custom_memory, custom_cpus,
    iso_file, custom_username, custom_password, disk_size,
    cpu_sockets, cpu_cores, cpu_threads, cpu_model, custom_cpu_name,
    machine_type, board_name, product_name, custom_smbios_manufacturer,
    smbios_manufacturer, smbios_product, smbios_version, smbios_serial,
    enable_acpi, enable_kvm, extra_args,
    network_type, ipv4_address, gateway, netmask, bridge_device,
    dns_servers, ssh_port, ssh_port_static, http_port,
    ipv6_address, ipv6_gateway, mac_address, vlan_id, owner_id,
    enable_rdp, node_id, nic_model, port_forwards
  } = req.body;
  
  // Alias gateway to ipv4_gateway for consistency
  const ipv4_gateway = gateway;
  const ipv4_netmask = netmask;
  // Parse DNS servers - can be comma-separated
  const dns_list = dns_servers ? dns_servers.split(',').map(d => d.trim()) : ['8.8.8.8', '8.8.4.4'];
  const dns_primary = dns_list[0] || '8.8.8.8';
  const dns_secondary = dns_list[1] || '8.8.4.4';
  
  // Either os_template or iso_file must be provided
  if (!os_template && !iso_file) {
    return res.status(400).json({ error: 'Please select a template or upload ISO' });
  }

  // AUDIT FIX (#14 - security hardening, deep debug pass): vm_name and
  // hostname were previously accepted with no validation at all before
  // being embedded directly into generated cloud-init YAML
  // (`hostname: ${hostname}`, ~line 4004/4117) and used in shell commands
  // elsewhere in the app. Path construction for VM resources uses the
  // numeric vm_id (DB-generated, safe), not vm_name, so this isn't a path-
  // traversal issue - but an unvalidated hostname containing a newline can
  // still inject arbitrary extra cloud-init YAML directives into the
  // generated guest config. This route is admin-only, so the practical
  // severity is limited (an admin already fully controls the VM's
  // cloud-init via other fields), but validating untrusted input before it
  // reaches a YAML/shell context is correct regardless of caller trust
  // level - and cheap to add without touching how vm_name/hostname are
  // used anywhere downstream.
  const NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$/;
  if (!vm_name || !NAME_PATTERN.test(vm_name)) {
    return res.status(400).json({
      error: 'Invalid VM name: use 1-63 characters, letters/numbers/dots/dashes/underscores only, starting with a letter or number.'
    });
  }
  if (hostname && !NAME_PATTERN.test(hostname)) {
    return res.status(400).json({
      error: 'Invalid hostname: use 1-63 characters, letters/numbers/dots/dashes/underscores only, starting with a letter or number.'
    });
  }

  // Validate memory - remove strict limits, allow any positive value
  const memoryNum = parseInt(custom_memory);
  if (!memoryNum || memoryNum < 1) {
    return res.status(400).json({ error: 'Memory must be at least 1 MB' });
  }

  // Validate CPUs - remove strict limits, allow any positive value
  const cpusNum = parseInt(custom_cpus);
  if (!cpusNum || cpusNum < 1) {
    return res.status(400).json({ error: 'CPUs must be at least 1' });
  }

  // Validate bridge device if using static IP
  if (network_type === 'static_public' && bridge_device) {
    if (!/^[a-z0-9]+$/.test(bridge_device)) {
      return res.status(400).json({ error: 'Invalid bridge device name. Use only lowercase letters and numbers (e.g., vmbr0, vmbr1)' });
    }
  }

  let template = null;
  let isCloudInit = false;
  let templateName = 'Custom ISO';
  let username = custom_username || 'root';
  let password = custom_password || 'password';

  if (os_template) {
    // Check if it's a built-in template
    if (OS_TEMPLATES[os_template]) {
      template = OS_TEMPLATES[os_template];
      isCloudInit = true;
      templateName = template.name;
      username = custom_username || template.username;
      password = custom_password || template.password;
    } else {
      // Not built-in, check database for custom template
      let customTemplate = null;
      try {
        customTemplate = await new Promise((resolve, reject) => {
          db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [os_template], (err, result) => {
            if (err) reject(err);
            else resolve(result);
          });
        });
      } catch (tplErr) {
        console.error('[VM Creation] Template lookup failed:', tplErr.message);
        return res.status(500).json({ success: false, error: 'TEMPLATE_LOOKUP_FAILED', message: 'Could not read the template registry: ' + tplErr.message });
      }

      if (!customTemplate) {
        const builtInKeys = Object.keys(OS_TEMPLATES);
        console.warn(`[VM Creation] Invalid template key: "${os_template}". Available built-in: ${builtInKeys.join(', ')}`);
        return res.status(400).json({ error: `Invalid OS template: ${os_template}. Please select a valid template.` });
      }

      // Use custom template
      template = customTemplate;
      isCloudInit = customTemplate.template_type === 'cloud-init';
      templateName = customTemplate.template_name;
      username = custom_username || customTemplate.username || 'ubuntu';
      password = custom_password || customTemplate.password || 'password';
      console.log(`[VM Creation] Using custom template: ${templateName} (${os_template})`);
    }
  }

  // AUDIT FIX (OS template subsystem hardening - username validation):
  // the reported example request used "Username = 11111", which was
  // accepted without any check and interpolated directly into generated
  // cloud-init YAML (`users:` section) as a Linux username. Enforce the
  // standard safe Linux username policy before any VM resources are
  // created/downloaded, per the requested spec. "root" is always allowed
  // even though it doesn't need special-casing against this pattern (it
  // already matches ^[a-z_]...).
  const USERNAME_PATTERN = /^[a-z_][a-z0-9_-]{0,31}$/;
  if (!username || !USERNAME_PATTERN.test(username)) {
    return res.status(400).json({
      success: false,
      error: 'INVALID_USERNAME',
      message: `Invalid username "${username}": Linux usernames must start with a lowercase letter or underscore and contain only lowercase letters, digits, underscores, or hyphens (max 32 characters).`
    });
  }

  const memory = parseInt(custom_memory) || (template ? template.memory : 2048);
  const cpuCount = parseInt(custom_cpus) || (template ? template.cpus : 2);
  const sockets = cpu_sockets || 1;
  const cores = cpu_cores || cpuCount;
  const threads = cpu_threads || 1;
  const cpuModelToUse = cpu_model && CPU_MODELS[cpu_model] ? cpu_model : 'host';
  let diskSizeVal;
  try {
    diskSizeVal = sanitizeDiskSize(disk_size || (template ? template.disk_size : '20G'));
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  const netType = network_type || 'nat';
  const nicModel = NIC_MODELS.includes(nic_model) ? nic_model : 'virtio-net-pci';
  const macAddr = mac_address || generateMACAddress();
  const vmOwner = owner_id || req.session.userId; // Use selected owner if provided, else current user

  // ---- Node targeting -------------------------------------------------
  // VMs are created on the Local node by default - identical to the
  // previous behavior, nothing below changes for them. When an admin
  // picks a Remote node, provisioning (template download, cloud-init
  // seed ISO, disk creation) happens ON that node through its agent and
  // the VM boots there with that node's real QEMU.
  let targetNode = null;
  if (node_id !== undefined && node_id !== null && String(node_id).trim() !== '') {
    targetNode = await nodeManager.getNode(node_id).catch(() => null);
    if (!targetNode) {
      return res.status(400).json({ success: false, error: 'INVALID_NODE', message: `Node "${node_id}" not found` });
    }
  }
  if (!targetNode) {
    try { targetNode = await nodeManager.getNodeForVM({ node_id: null }); } catch (nodeErr) { console.error('[VM Creation] Node registry lookup failed, defaulting to local:', nodeErr.message); targetNode = null; }
  }
  const isRemoteTarget = !!(targetNode && targetNode.mode === 'remote');
  if (isRemoteTarget && !nodeManager.isNodeOnline(targetNode.id)) {
    return res.status(409).json({ success: false, error: 'NODE_OFFLINE', message: `Node "${targetNode.name}" is offline - install/start its agent first (Admin -> Nodes)` });
  }
  // PLATFORM (Round 5): a node in maintenance mode accepts no new VMs -
  // this is what makes "graceful draining" possible (flip maintenance
  // on, migrate existing VMs away, then service the node).
  if (targetNode && targetNode.maintenance_mode) {
    return res.status(409).json({
      success: false, error: 'NODE_MAINTENANCE',
      message: `Node "${targetNode.name}" is in maintenance mode and is not accepting new VMs`
    });
  }

  // Parse disk size strings like "20G" / "512M" into GB (rough, integer GB)
  function diskSizeToGB(sizeStr) {
    if (!sizeStr) return 0;
    const m = String(sizeStr).trim().match(/^([\d.]+)\s*([GgMmTt])?/);
    if (!m) return 0;
    const num = parseFloat(m[1]);
    const unit = (m[2] || 'G').toUpperCase();
    if (unit === 'T') return num * 1024;
    if (unit === 'M') return num / 1024;
    return num; // default GB
  }
  const requestedDiskGB = diskSizeToGB(diskSizeVal);

  // Enforce per-user resource quotas (admins are exempt) before allocating
  // anything, so a single user can't unboundedly consume host resources.
  function withQuotaCheck(cb) {
    if (req.session.role === 'admin') return cb();
    db.get(`SELECT max_vms, max_memory_mb, max_cpus, max_disk_gb FROM users WHERE id = ?`, [vmOwner], (err, quota) => {
      if (err || !quota) return cb(); // fail open on lookup error rather than blocking creation entirely
      db.all(`SELECT memory, cpus, disk_size FROM vms WHERE owner_id = ?`, [vmOwner], (err2, existing) => {
        if (err2) return cb();
        const rows = existing || [];
        const usedVms = rows.length;
        const usedMemory = rows.reduce((sum, r) => sum + (r.memory || 0), 0);
        const usedCpus = rows.reduce((sum, r) => sum + (r.cpus || 0), 0);
        const usedDiskGB = rows.reduce((sum, r) => sum + diskSizeToGB(r.disk_size), 0);

        const maxVms = quota.max_vms ?? 3;
        const maxMemory = quota.max_memory_mb ?? 8192;
        const maxCpus = quota.max_cpus ?? 8;
        const maxDiskGB = quota.max_disk_gb ?? 200;

        if (usedVms + 1 > maxVms) {
          return res.status(403).json({ error: `VM limit reached (${maxVms} max). Contact an admin to increase your quota.` });
        }
        if (usedMemory + memory > maxMemory) {
          return res.status(403).json({ error: `Memory quota exceeded (${maxMemory}MB max, ${usedMemory}MB used).` });
        }
        if (usedCpus + cpuCount > maxCpus) {
          return res.status(403).json({ error: `CPU quota exceeded (${maxCpus} vCPUs max, ${usedCpus} used).` });
        }
        if (usedDiskGB + requestedDiskGB > maxDiskGB) {
          return res.status(403).json({ error: `Disk quota exceeded (${maxDiskGB}GB max, ${usedDiskGB.toFixed(1)}GB used).` });
        }
        cb();
      });
    });
  }
  
  // Handle SSH port - honor explicit values; otherwise auto-allocate a free
  // port starting at DEFAULT_SSH_PORT so NAT VMs don't collide on host port 22.
  // DEEP FIX (allocation race): two concurrent VM creates both read the
  // same "used" set from the DB before either INSERT commits, probe the
  // same free port, and both claim it (ssh_port has no UNIQUE index). The
  // module-level _sshPortReservations set closes that window for one
  // create's lifetime (reserved before the async probe, released when the
  // INSERT settles).
  function withSshPort(cb) {
    if (ssh_port_static || ssh_port) {
      return cb(ssh_port_static || ssh_port);
    }
    if (netType !== 'nat') {
      return cb(DEFAULT_SSH_PORT);
    }
    db.all(
      `SELECT ssh_port, ssh_port_static FROM vms WHERE network_type = 'nat' AND COALESCE(node_id, ?) = ?`,
      [targetNode ? targetNode.id : null, targetNode ? targetNode.id : null],
      (err, rows) => {
        const used = new Set();
        (rows || []).forEach(r => {
          const p = r.ssh_port || r.ssh_port_static;
          if (p) used.add(parseInt(p));
        });
        _sshPortReservations.forEach(p => used.add(p));

        // AUDIT FIX: DB-only allocation doesn't know about ports already
        // bound by non-VM processes on the host. Actually probe each
        // candidate port before handing it out.
        function isPortFree(port) {
          return new Promise((resolve) => {
            const tester = net.createServer();
            tester.once('error', () => resolve(false));
            tester.once('listening', () => {
              tester.close(() => resolve(true));
            });
            tester.listen(port, '0.0.0.0');
          });
        }

        async function findFreePort() {
          let candidate = DEFAULT_SSH_PORT;
          for (let i = 0; i < 1000; i++) {
            if (used.has(candidate)) { candidate++; continue; }
            // DEEP FIX (allocation race, part 2): reserve the candidate
            // synchronously BEFORE the async port probe. The probe yields
            // to the event loop, and concurrent creators building their own
            // "used" set at that moment must see this port as taken (the
            // set merge above includes _sshPortReservations). Reserving
            // only in the outer callback was too late - all concurrent
            // requests had already probed and claimed the same port.
            _sshPortReservations.add(candidate);
            // For a remote-node VM, port liveness is verified by that
            // node's own agent at provision time - probing HERE would
            // test the panel's ports, which are irrelevant to the node.
            // Per-node DB uniqueness is enforced by the query above.
            if (!isRemoteTarget && !(await isPortFree(candidate))) {
              _sshPortReservations.delete(candidate);
              candidate++;
              continue;
            }
            return candidate;
          }
          throw new Error('No free SSH port found in range');
        }

        findFreePort().then(cb).catch((e) => {
          console.error('SSH port allocation failed:', e.message);
          cb(DEFAULT_SSH_PORT);
        });
      }
    );
  }

  withQuotaCheck(() => {
  withSshPort((sshPortVal) => {
  _sshPortReservations.add(sshPortVal);
  // AUDIT FIX #1: turn the UNIQUE(vms.vm_name) constraint violation into a
  // clean 409 instead of a generic 500. A pre-check here gives a fast,
  // friendly response in the common case; the INSERT's own error handling
  // below still catches the SQLITE_CONSTRAINT race if two requests for the
  // same name land at almost the same time (the pre-check alone can't
  // prevent that race - only the DB's UNIQUE index can).
  db.get(`SELECT 1 FROM vms WHERE vm_name = ?`, [vm_name], (nameErr, existingName) => {
  if (existingName) {
    return res.status(409).json({
      success: false,
      error: 'VM_NAME_EXISTS',
      message: 'A VM with this name already exists.'
    });
  }
  // Custom port-forward rules (validated; persisted right after the row
  // exists so both the local and the remote-node path inherit them).
  const pfParsed = parsePortForwards(port_forwards, sshPortVal);
  if (!pfParsed.ok) return res.status(400).json({ error: pfParsed.error });
  const portForwardList = pfParsed.forwards;

  // Insert VM first to get vm_id
  db.run(
    `INSERT INTO vms (
      vm_name, os_type, template_type, hostname, username, password, 
      memory, cpus, cpu_sockets, cpu_cores, cpu_threads, cpu_model, custom_cpu_name,
      machine_type, board_name, product_name, custom_smbios_manufacturer,
      disk_size, img_file, seed_file, disk_file,
      status, uptime, node_name,
      smbios_manufacturer, smbios_product, smbios_version, smbios_serial,
      extra_args, enable_acpi, enable_kvm,
      network_type, ipv4_address, ipv4_gateway, ipv4_netmask,
      dns_servers, dns_primary, dns_secondary, ssh_port, ssh_port_static, http_port,
      ipv6_address, ipv6_gateway, mac_address, bridge_device, vlan_id, owner_id, node_id, nic_model
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      vm_name, templateName, os_template || (isCloudInit ? 'cloud-init' : 'iso-installer'), hostname, 
      username, password, memory, cpuCount, sockets, cores, threads, cpuModelToUse, custom_cpu_name || null,
      machine_type || 'pc', board_name || 'Main-Board', product_name || 'Virtual Machine', custom_smbios_manufacturer || 'QEMU',
      diskSizeVal, '', '', '',
      'stopped', 0, targetNode ? targetNode.name : 'localhost',
      smbios_manufacturer || 'QEMU', smbios_product || 'KVM Virtual Machine',
      smbios_version || '1.0', smbios_serial || `vm-${Date.now()}`,
      extra_args || '', enable_acpi !== false ? 1 : 0, enable_kvm !== false ? 1 : 0,
      netType, ipv4_address || null, ipv4_gateway || null, ipv4_netmask || '255.255.255.0',
      dns_servers || '8.8.8.8,8.8.4.4', dns_primary || '8.8.8.8', dns_secondary || '8.8.4.4', null, sshPortVal, http_port || 80,
      ipv6_address || null, ipv6_gateway || null,
      macAddr, bridge_device || 'vmbr0', vlan_id || null, vmOwner, targetNode ? targetNode.id : null, nicModel
    ],
    async function(err) {
      _sshPortReservations.delete(sshPortVal); // reservation only spans the pre-INSERT window
      if (err) {
        // AUDIT FIX #1 (race condition path): two concurrent requests for
        // the same vm_name can both pass the pre-check above and only one
        // wins at the DB's UNIQUE index - this is what actually enforces
        // uniqueness, so surface it the same clean way rather than 500ing.
        if (err.message && err.message.includes('UNIQUE constraint failed') && err.message.includes('vms.vm_name')) {
          console.warn(`[VM Creation] Duplicate vm_name race detected: "${vm_name}"`);
          return res.status(409).json({
            success: false,
            error: 'VM_NAME_EXISTS',
            message: 'A VM with this name already exists.'
          });
        }
        console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      const vm_id = this.lastID;

      // Persist custom port-forward rules (validated above) - applies to
      // BOTH local and remote VMs; the launchers read them at start time.
      if (portForwardList) {
        for (const pf of portForwardList) {
          db.run(`INSERT INTO vm_port_forwards (vm_id, protocol, label, host_port, guest_port) VALUES (?, ?, ?, ?, ?)`,
            [vm_id, pf.protocol, pf.label, pf.host_port, pf.guest_port]);
        }
        console.log(`[VM-${vm_id}] ${portForwardList.length} custom port forward(s) registered`);
      }

      // "Enable RDP" ticked in the wizard: set xrdp up automatically once this VM is running and reachable
      // (a new VM is created stopped and needs its first boot first - see rdp.js autoTick).
      let rdpAuto = false;
      if (enable_rdp === true || enable_rdp === 1 || enable_rdp === '1' || enable_rdp === 'true' || enable_rdp === 'on') {
        if (rdp.canAutoEnable({ isCloudInit, templateName })) {
          try { await rdp.setAuto(vm_id, true); rdpAuto = true; }
          catch (e) { console.error(`[VM-${vm_id}] could not enable automatic RDP setup: ${e.message}`); }
        } else {
          console.warn(`[VM-${vm_id}] "Enable RDP" ignored: only Debian/Ubuntu cloud-init templates are supported`);
        }
      }
      // ---- REMOTE NODE PROVISIONING ----------------------------------
      // For a VM on a remote node, everything below (template download,
      // cloud-init seed ISO, disk creation) happens ON that node through
      // its agent: the panel sends the cloud-init content it generated
      // (the exact same generators a local VM gets) plus the template's
      // download URLs - or streams the image over first when it only
      // exists on the panel - and the agent materializes the artifacts
      // with its own qemu-img/ISO tooling. Any failure cleans up both
      // the row and the node-side partial artifacts.
      if (isRemoteTarget) {
        try {
          // Resolve the template source for this VM.
          let templateSpec = null; // { key, urls: [...] } | { key, streamedName, _localPath }
          if (os_template && isCloudInit) {
            if (OS_TEMPLATES[os_template]) {
              const t = OS_TEMPLATES[os_template];
              const urls = (t.download_urls && t.download_urls.length ? t.download_urls : [t.url]).filter(Boolean);
              if (!urls.length) throw Object.assign(new Error(`Built-in template "${os_template}" has no download URLs`), { httpStatus: 500 });
              templateSpec = { key: os_template, urls };
            } else {
              const ct = await new Promise((resolve, reject) => db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [os_template], (e, r) => e ? reject(e) : resolve(r)));
              if (!ct) throw Object.assign(new Error(`Custom template "${os_template}" not found`), { httpStatus: 400 });
              const safeKey = String(os_template).replace(/[^A-Za-z0-9._-]/g, '_');
              if (ct.download_url) {
                templateSpec = { key: os_template, urls: [ct.download_url] };
              } else if (ct.local_path && fs.existsSync(ct.local_path)) {
                // Image only exists on the panel - stream it to the node.
                templateSpec = { key: os_template, streamedName: `${safeKey}-template.qcow2`, _localPath: ct.local_path };
              } else {
                throw Object.assign(new Error(`Custom template "${os_template}" has no download URL and no local image to stream`), { httpStatus: 400, code: 'NO_TEMPLATE_SOURCE' });
              }
            }
          }

          // Cloud-init content - generated exactly like a local VM's.
          let cloudInit = null;
          if (isCloudInit) {
            cloudInit = buildCloudInitFiles({
              vm_id, vm_name, hostname, username, password,
              network_type: netType,
              ipv4_address: ipv4_address || null,
              ipv4_gateway: ipv4_gateway || null,
              ipv4_netmask: ipv4_netmask || '255.255.255.0',
              dns_primary: dns_primary || '8.8.8.8',
              dns_secondary: dns_secondary || '8.8.4.4',
              ipv6_address: ipv6_address || null,
              ipv6_gateway: ipv6_gateway || null
            }, vm_id);
          }

          // Stream panel-only template images to the node first
          // (verified, flow-controlled transfer; skipped when the agent
          // can download the template itself).
          if (templateSpec && templateSpec.streamedName) {
            console.log(`[VM-${vm_id}] Streaming template image to node "${targetNode.name}"...`);
            await nodeManager.relayNodeFileUpload(targetNode.id,
              { name: templateSpec.streamedName, totalBytes: fs.statSync(templateSpec._localPath).size },
              fs.createReadStream(templateSpec._localPath, { highWaterMark: 1024 * 1024 }));
          }

          // Provision on the node: template cache/download -> seed ISO ->
          // disk convert/resize -> SSH port liveness verification.
          const prov = await nodeManager.sendNodeCommand(targetNode.id, 'vm.provision', {
            vm: {
              vm_id, disk_size: diskSizeVal, memory, cpus: cpuCount,
              ssh_port: sshPortVal, network_type: netType, mac_address: macAddr,
              nic_model: nicModel, port_forwards: portForwardList || []
            },
            template: templateSpec ? { key: templateSpec.key, urls: templateSpec.urls || undefined, streamedName: templateSpec.streamedName } : null,
            cloudInit
          }, { timeoutMs: 30 * 60 * 1000 });

          // The node may have adjusted the SSH forward port (the requested
          // one was already bound there) - persist what it actually uses.
          if (prov.sshPort && prov.sshPort !== sshPortVal) {
            await new Promise((resolve, reject) => db.run(`UPDATE vms SET ssh_port = ?, ssh_port_static = ? WHERE vm_id = ?`, [prov.sshPort, prov.sshPort, vm_id], (e) => e ? reject(e) : resolve()));
            console.log(`[VM-${vm_id}] SSH forward port adjusted by node: ${sshPortVal} -> ${prov.sshPort}`);
          }

          // Record the node-local paths. They exist on the NODE's
          // filesystem, not the panel's - panel-side fs.existsSync checks
          // on them simply and safely evaluate false.
          await new Promise((resolve, reject) => db.run(
            `UPDATE vms SET disk_file = ?, seed_file = ?, img_file = '' WHERE vm_id = ?`,
            [prov.diskPath, prov.seedPath || '', vm_id],
            (e) => e ? reject(e) : resolve()));

          logVMAction(vm_id, 'create', 'pending', `VM ${vm_name} (ID:${vm_id}) created on node "${targetNode.name}" from ${templateName}`);
          console.log(`[VM-${vm_id}] ✓ Provisioned on node "${targetNode.name}" (disk: ${prov.diskPath}, seed: ${prov.seedPath ? 'yes' : 'no'})`);
          return res.json({
            success: true,
            vm_id,
            rdp_auto: rdpAuto,
            node: { id: targetNode.id, name: targetNode.name },
            template: isCloudInit ? 'cloud-init' : 'iso-installer',
            ssh_port: prov.sshPort || sshPortVal,
            config: {
              cpus: cpuCount, sockets: sockets, cores: cores, threads: threads, cpu_model: cpuModelToUse,
              memory: memory, disk_size: diskSizeVal, network_type: netType,
              mac_address: macAddr, ipv4: ipv4_address, gateway: ipv4_gateway
            }
          });
        } catch (e) {
          console.error(`[VM-${vm_id}] Remote provisioning on node "${targetNode.name}" failed:`, e.message);
          // Best-effort cleanup of partial artifacts on the node, then
          // remove the row so panel state stays consistent.
          nodeManager.sendNodeCommand(targetNode.id, 'vm.cleanup', { vmId: String(vm_id) }, { timeoutMs: 20000 }).catch(() => {});
          db.run(`DELETE FROM vm_port_forwards WHERE vm_id = ?`, [vm_id]);
          db.run(`DELETE FROM vms WHERE vm_id = ?`, [vm_id]);
          logVMAction(vm_id, 'create', 'failed', `Remote provisioning on "${targetNode.name}" failed: ${e.message}`);
          if (e.code === 'TEMPLATE_DOWNLOAD_FAILED' && e.attempts) {
            return res.status(502).json({ success: false, error: 'TEMPLATE_DOWNLOAD_FAILED', template: os_template, attempts: e.attempts, details: e.details, message: e.message });
          }
          return res.status(e.httpStatus || 502).json({ success: false, error: e.code || 'REMOTE_PROVISION_FAILED', message: e.message });
        }
      }

      // Cloud-init images go to /cloudvm, ISO images go to /iso
      const img_file = isCloudInit 
        ? path.join(CLOUDVM_DIR, `${os_template || 'custom'}-${vm_id}.qcow2`)
        : path.join(ISO_DIR, `${os_template || 'custom'}-${vm_id}.qcow2`);
      const disk_file = path.join(VM_DIR, `vm-${vm_id}-disk.qcow2`);
      const seed_file = path.join(VM_DIR, `vm-${vm_id}-seed.iso`);

      try {
        // Update with file paths
        db.run(
          `UPDATE vms SET img_file = ?, seed_file = ?, disk_file = ? WHERE vm_id = ?`,
          [img_file, seed_file, disk_file, vm_id],
          async (err) => {
            if (err) {
              db.run(`DELETE FROM vms WHERE vm_id = ?`, [vm_id]);
              return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
            }

            try {
              // If using cloud-init template, check cache first
              if (os_template && isCloudInit) {
                // Check if it's a built-in or custom template
                let templateSourcePath = null;

                if (OS_TEMPLATES[os_template]) {
                  // Built-in template - use cache in /vms/templates
                  const cachedTemplateName = `${os_template}-template.qcow2`;
                  const cachedTemplatePath = path.join(TEMPLATES_DIR, cachedTemplateName);

                  let cacheIsValid = false;
                  if (fs.existsSync(cachedTemplatePath)) {
                    const validation = await validateImageFile(cachedTemplatePath);
                    if (validation.valid) {
                      cacheIsValid = true;
                    } else {
                      console.warn(`[VM-${vm_id}] Cached template at ${cachedTemplatePath} failed validation (${validation.reason}) - quarantining and redownloading`);
                      try {
                        fs.renameSync(cachedTemplatePath, `${cachedTemplatePath}.invalid.${Date.now()}`);
                      } catch (e) {
                        fs.unlink(cachedTemplatePath, () => {});
                      }
                    }
                  }

                  if (cacheIsValid) {
                    console.log(`[VM-${vm_id}] Using cached built-in template from: ${cachedTemplatePath}`);
                    templateSourcePath = cachedTemplatePath;
                  } else {
                    console.log(`[VM-${vm_id}] Cached template not found or invalid at ${cachedTemplatePath}`);
                    console.log(`[VM-${vm_id}] Downloading built-in template: ${templateName} to cache...`);
                    
                    // Download to cache first (tries every configured
                    // fallback URL for this template before giving up)
                    try {
                      await downloadTemplate(os_template, cachedTemplatePath);
                      console.log(`[VM-${vm_id}] ✓ Built-in template cached to: ${cachedTemplatePath}`);
                      templateSourcePath = cachedTemplatePath;
                    } catch (dlErr) {
                      console.error(`[VM-${vm_id}] Template download failed:`, dlErr.message);
                      // Preserve the structured diagnostic (attempts/details
                      // per candidate URL) on the re-thrown error so the
                      // outer catch block below can surface it in the API
                      // response instead of just a flat message string.
                      const wrapped = new Error(`Failed to download built-in template: ${dlErr.message}`);
                      wrapped.code = 'TEMPLATE_DOWNLOAD_FAILED';
                      wrapped.templateKey = os_template;
                      wrapped.attempts = dlErr.attempts;
                      wrapped.details = dlErr.details;
                      throw wrapped;
                    }
                  }
                } else {
                  // Custom template - check database for local path
                  const customTemplate = await new Promise((resolve, reject) => {
                    db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [os_template], (err, result) => {
                      if (err) reject(err);
                      else resolve(result);
                    });
                  });

                  if (!customTemplate) {
                    throw new Error(`Custom template "${os_template}" not found in database`);
                  }

                  let customCacheValid = false;
                  if (customTemplate.local_path && fs.existsSync(customTemplate.local_path)) {
                    const validation = await validateImageFile(customTemplate.local_path);
                    if (validation.valid) {
                      customCacheValid = true;
                    } else {
                      console.warn(`[VM-${vm_id}] Custom template cache at ${customTemplate.local_path} failed validation (${validation.reason}) - quarantining and redownloading`);
                      try {
                        fs.renameSync(customTemplate.local_path, `${customTemplate.local_path}.invalid.${Date.now()}`);
                      } catch (e) {
                        fs.unlink(customTemplate.local_path, () => {});
                      }
                    }
                  }

                  if (customCacheValid) {
                    console.log(`[VM-${vm_id}] Using cached custom template from: ${customTemplate.local_path}`);
                    templateSourcePath = customTemplate.local_path;
                  } else if (customTemplate.download_url) {
                    console.log(`[VM-${vm_id}] Custom template not cached or invalid, downloading from ${customTemplate.download_url}...`);
                    
                    // Generate local path if not set
                    let localPath = customTemplate.local_path;
                    if (!localPath) {
                      const urlParts = customTemplate.download_url.split('/');
                      const fileName = urlParts[urlParts.length - 1] || `${os_template}-template.qcow2`;
                      localPath = path.join(TEMPLATES_DIR, fileName);
                    }

                    try {
                      // Create templates directory if needed
                      if (!fs.existsSync(TEMPLATES_DIR)) {
                        fs.mkdirSync(TEMPLATES_DIR, { recursive: true });
                      }

                      await downloadTemplateFromURL(customTemplate.download_url, localPath);
                      const validation = await validateImageFile(localPath);
                      if (!validation.valid) {
                        fs.unlink(localPath, () => {});
                        throw new Error(`Downloaded custom template failed validation: ${validation.reason}`);
                      }
                      console.log(`[VM-${vm_id}] ✓ Custom template downloaded to: ${localPath}`);
                      
                      // Update database with local path
                      await new Promise((resolve, reject) => {
                        db.run(`UPDATE os_templates SET local_path = ? WHERE template_key = ?`,
                          [localPath, os_template],
                          (err) => {
                            if (err) {
                              console.error('Failed to update template path in DB:', err);
                              reject(err);
                            } else {
                              resolve();
                            }
                          }
                        );
                      });

                      templateSourcePath = localPath;
                    } catch (dlErr) {
                      console.error(`[VM-${vm_id}] Custom template download failed:`, dlErr.message);
                      throw new Error(`Failed to download custom template: ${dlErr.message}`);
                    }
                  } else {
                    throw new Error(`Custom template "${os_template}" has no local path or download URL`);
                  }
                }

                // Copy template to VM's image file
                if (templateSourcePath) {
                  try {
                    const copyCmd = process.platform === 'win32' 
                      ? `copy "${templateSourcePath}" "${img_file}"`
                      : `cp "${templateSourcePath}" "${img_file}"`;
                    
                    console.log(`[VM-${vm_id}] Copying template to: ${img_file}`);
                    await execPromise(copyCmd, { 
                      shell: process.platform === 'win32' ? 'cmd' : '/bin/bash',
                      stdio: 'pipe'
                    });
                    console.log(`[VM-${vm_id}] ✓ Copied template to ${img_file}`);
                  } catch (copyErr) {
                    console.error(`[VM-${vm_id}] Failed to copy template:`, copyErr.message);
                    throw new Error(`Failed to copy template: ${copyErr.message}`);
                  }
                }
              }

              // Create cloud-init seed if cloud-init type
              if (isCloudInit) {
                const vmData = {
                  vm_id,
                  vm_name,
                  hostname,
                  username,
                  password,
                  network_type: netType,
                  ipv4_address: ipv4_address || null,
                  ipv4_gateway: ipv4_gateway || null,
                  ipv4_netmask: ipv4_netmask || '255.255.255.0',
                  dns_primary: dns_primary || '8.8.8.8',
                  dns_secondary: dns_secondary || '8.8.4.4',
                  ipv6_address: ipv6_address || null,
                  ipv6_gateway: ipv6_gateway || null
                };
                await createCloudInitSeed(vm_id, vmData);
                
                // Create disk from template with resize to specified size
                console.log(`[VM-${vm_id}] Creating and resizing disk to ${diskSizeVal}...`);
                try {
                  // Copy template to disk file and resize in one step
                  const resizeDiskCmd = `qemu-img convert -O qcow2 "${img_file}" "${disk_file}" && qemu-img resize "${disk_file}" "${diskSizeVal}"`;
                  await execPromise(resizeDiskCmd, { 
                    shell: isWindows ? 'cmd' : '/bin/bash',
                    stdio: 'pipe'
                  });
                  
                  console.log(`[VM-${vm_id}] ✓ Disk created and resized to: ${diskSizeVal}`);
                } catch (diskError) {
                  logError('DISK', vm_id, 'creation', diskError);
                  throw new Error(`Disk creation failed: ${diskError.message}`);
                }
              } else {
                // ISO mode: Create a new disk from scratch with specified size
                console.log(`[VM-${vm_id}] Creating disk: ${disk_file} (size: ${diskSizeVal})`);
                try {
                  const createDiskCmd = `qemu-img create -f qcow2 "${disk_file}" "${diskSizeVal}"`;
                  
                  await execPromise(createDiskCmd, { 
                    shell: isWindows ? 'cmd' : '/bin/bash',
                    stdio: 'pipe'
                  });
                  console.log(`[VM-${vm_id}] ✓ Disk created: ${diskSizeVal}`);
                } catch (diskError) {
                  logError('DISK', vm_id, 'creation', diskError);
                  throw new Error(`Disk creation failed: ${diskError.message}`);
                }
              }

              logVMAction(vm_id, 'create', 'pending', `VM ${vm_name} (ID:${vm_id}) created from ${templateName}`);
              res.json({ 
                success: true, 
                vm_id: vm_id, 
                rdp_auto: rdpAuto,
                template: isCloudInit ? 'cloud-init' : 'iso-installer',
                ssh_port: sshPortVal,
                port_forwards: portForwardList || [],
                config: {
                  cpus: cpuCount,
                  sockets: sockets,
                  cores: cores,
                  threads: threads,
                  cpu_model: cpuModelToUse,
                  memory: memory,
                  disk_size: diskSizeVal,
                  network_type: netType,
                  mac_address: macAddr,
                  ipv4: ipv4_address,
                  gateway: ipv4_gateway
                }
              });
            } catch (downloadError) {
              logError('TEMPLATE', vm_id, 'download', downloadError);
              // AUDIT FIX #2: previously only img_file was cleaned up here,
              // leaving disk_file (qcow2) and seed_file (cloud-init ISO) -
              // and the seed working directory - orphaned on disk any time
              // failure happened after they'd already been created (e.g.
              // disk convert/resize succeeds but a later step throws).
              // Clean up every resource this request could have created,
              // but never touch the cached template itself.
              [img_file, disk_file, seed_file].forEach(f => {
                if (f && fs.existsSync(f)) {
                  try { fs.unlinkSync(f); } catch (e) { console.warn(`[VM-${vm_id}] cleanup: could not remove ${f}: ${e.message}`); }
                }
              });
              const seedDirLeftover = path.join(VM_DIR, `vm-${vm_id}-seed-dir`);
              if (fs.existsSync(seedDirLeftover)) {
                try { fs.rmSync(seedDirLeftover, { recursive: true, force: true }); } catch (e) {}
              }
              // Also remove a leftover .part file from an interrupted
              // template download, if the failure happened mid-download.
              const cachedTemplatePathGuess = path.join(TEMPLATES_DIR, `${os_template}-template.qcow2.part`);
              if (fs.existsSync(cachedTemplatePathGuess)) {
                try { fs.unlinkSync(cachedTemplatePathGuess); } catch (e) {}
              }
              db.run(`DELETE FROM vms WHERE vm_id = ?`, [vm_id]);
              // AUDIT FIX (OS template subsystem hardening): surface the
              // structured per-URL diagnostic (which candidate URLs were
              // tried, their individual HTTP status/error) when the
              // failure came from downloadTemplateWithFallback, matching
              // the requested {error, template, attempts, details} shape,
              // instead of only the flattened message string.
              if (downloadError.code === 'TEMPLATE_DOWNLOAD_FAILED') {
                return res.status(502).json({
                  success: false,
                  error: 'TEMPLATE_DOWNLOAD_FAILED',
                  template: downloadError.templateKey || os_template,
                  attempts: downloadError.attempts,
                  details: downloadError.details,
                  message: downloadError.message
                });
              }
              return res.status(500).json({ error: `Failed to create VM: ${downloadError.message}` });
            }
          }
        );
      } catch (error) {
        logError('VM', vm_id, 'creation', error);
        // Same rollback as above - this catch covers errors thrown before
        // the inner try/catch (e.g. from the UPDATE...paths callback path).
        [img_file, disk_file, seed_file].forEach(f => {
          if (f && fs.existsSync(f)) {
            try { fs.unlinkSync(f); } catch (e) {}
          }
        });
        db.run(`DELETE FROM vms WHERE vm_id = ?`, [vm_id]);
        (console.error(error), res.status(500).json({ error: 'Internal server error' }));
      }
    }
  );
  }); // end db.get vm_name uniqueness pre-check
  }); // end withSshPort
  }); // end withQuotaCheck
});

// VM START (Using VM ID)
app.post('/api/vms/:vm_id/start', checkAuth, vmActionRateLimit, async (req, res) => {
  try {
    const userId = req.session.userId;
    let query = `SELECT * FROM vms WHERE vm_id = ?`;
    let params = [req.params.vm_id];
    
    // Normal users can only start their own VMs
    if (req.session.role !== 'admin') {
      query += ` AND owner_id = ?`;
      params.push(userId);
    }
    
    db.get(query, params, async (err, vm) => {
      if (err || !vm) {
        console.error(`[API Error] /api/vms/${req.params.vm_id}/start: VM not found or access denied`);
        return res.status(404).json({ error: 'VM not found or access denied' });
      }

      // Route to this VM's node. Local VMs fall straight through to the
      // existing direct-QEMU code below, unchanged. Remote VMs are
      // delegated to that node's agent over the authenticated tunnel.
      let node; try { node = await nodeManager.getNodeForVM(vm); } catch (nodeErr) { console.error('[API Error] node lookup failed for VM ' + vm.vm_id + ':', nodeErr.message); return res.status(502).json({ success: false, error: 'NODE_LOOKUP_FAILED', message: 'Node registry unavailable: ' + nodeErr.message }); }
      if (node && node.mode === 'remote') {
        try {
          // Custom port-forward rules ride along with the VM row so the
          // node's launcher can attach them as QEMU hostfwd entries.
          const vmWithForwards = { ...vm, port_forwards: await getPortForwards(vm.vm_id) };
          const result = await nodeManager.sendNodeCommand(node.id, 'vm.start', { vm: vmWithForwards }, { timeoutMs: 30000 });
          db.run(`UPDATE vms SET status = 'running', uptime = 0 WHERE vm_id = ?`, [vm.vm_id]);
          logVMAction(vm.vm_id, 'start', 'running', `VM started on remote node ${node.name}`);
          return res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) started on ${node.name}`, vm_id: vm.vm_id });
        } catch (e) {
          logVMAction(vm.vm_id, 'start', 'failed', e.message);
          return res.status(e.httpStatus || 502).json({ success: false, error: e.code || 'NODE_START_FAILED', message: e.message });
        }
      }

      if (vm.status === 'running') {
        console.log(`[API] VM ${vm.vm_id} already running`);
        return res.json({ success: true, message: `VM ${vm.vm_name} is already running` });
      }

      try {
        console.log(`[API] Starting VM ${vm.vm_id} (${vm.vm_name}) by user ${userId}`);
        const result = await startQemuVM(vm);
        if (result.success) {
          vmProcesses.set(vm.vm_id, result.pid);
          db.run(`UPDATE vms SET status = 'running', uptime = 0 WHERE vm_id = ?`, [vm.vm_id]);
          logVMAction(vm.vm_id, 'start', 'running', `VM started successfully`);
          console.log(`[API Success] VM ${vm.vm_id} started successfully`);
          res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) started`, vm_id: vm.vm_id });
        } else {
          console.error(`[API Error] Failed to start VM ${vm.vm_id}`);
          res.status(500).json({ error: 'Failed to start VM' });
        }
      } catch (error) {
        console.error(`[API Error] Exception starting VM ${vm.vm_id}:`, error);
        logVMAction(vm.vm_id, 'start', 'failed', error.message);
        // AUDIT FIX #7/#8: surface the actual diagnostic (missing QEMU
        // binary, bad args, immediate crash - all non-sensitive, actionable
        // messages produced by startQemuVM) instead of a opaque "Internal
        // server error" that gives the admin nothing to act on and that the
        // frontend then shows as a confusing generic failure.
        res.status(500).json({ success: false, error: 'VM_START_FAILED', message: error.message || 'Failed to start VM' });
      }
    });
  } catch (error) {
    (console.error(error), res.status(500).json({ error: 'Internal server error' }));
  }
});

// VM STOP (Using VM ID)
app.post('/api/vms/:vm_id/stop', checkAuth, vmActionRateLimit, (req, res) => {
  const userId = req.session.userId;
  let query = `SELECT * FROM vms WHERE vm_id = ?`;
  let params = [req.params.vm_id];
  
  // Normal users can only stop their own VMs
  if (req.session.role !== 'admin') {
    query += ` AND owner_id = ?`;
    params.push(userId);
  }
  
  db.get(query, params, async (err, vm) => {
    if (err || !vm) {
      console.error(`[API Error] /api/vms/${req.params.vm_id}/stop: VM not found or access denied`);
      return res.status(404).json({ error: 'VM not found or access denied' });
    }

    let node; try { node = await nodeManager.getNodeForVM(vm); } catch (nodeErr) { console.error('[API Error] node lookup failed for VM ' + vm.vm_id + ':', nodeErr.message); return res.status(502).json({ success: false, error: 'NODE_LOOKUP_FAILED', message: 'Node registry unavailable: ' + nodeErr.message }); }
    if (node && node.mode === 'remote') {
      try {
        const result = await nodeManager.sendNodeCommand(node.id, 'vm.stop', { vm }, { timeoutMs: 20000 });
        db.run(`UPDATE vms SET status = 'stopped' WHERE vm_id = ?`, [vm.vm_id]);
        logVMAction(vm.vm_id, 'stop', 'stopped', `VM stopped on remote node ${node.name}`);
        return res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) stopped` });
      } catch (e) {
        return res.status(e.httpStatus || 502).json({ success: false, error: e.code || 'NODE_STOP_FAILED', message: e.message });
      }
    }

    if (vm.status === 'stopped') {
      console.log(`[API] VM ${vm.vm_id} already stopped`);
      return res.json({ success: true, message: 'VM already stopped' });
    }

    try {
      console.log(`[API] Stopping VM ${vm.vm_id} (${vm.vm_name}) by user ${userId}`);
      releaseLocalVncDisplay(vm.vm_id);
      const pidFile = path.join(VM_DIR, `vm-${vm.vm_id}.pid`);
      if (fs.existsSync(pidFile)) {
        const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim());
        if (!isPidQemu(pid)) {
          console.warn(`[API] PID ${pid} for VM ${vm.vm_id} is not a live QEMU process — skipping kill, just cleaning up state`);
          fs.unlinkSync(pidFile);
        } else {
        try {
          // On Windows, use taskkill; on Unix, use process group kill
          if (isWindows) {
            exec(`taskkill /F /PID ${pid}`, { shell: 'cmd' });
          } else {
            // Kill entire process group (- prefix means pgid)
            process.kill(-pid, 'SIGTERM');
            setTimeout(() => {
              try {
                process.kill(-pid, 'SIGKILL');
              } catch (e) {}
            }, 3000);
          }
        } catch (e) {
          // Process may already be dead
        }
        }
      }

      vmProcesses.delete(vm.vm_id);
      qemuStdins.delete(String(vm.vm_id));
      db.run(`UPDATE vms SET status = 'stopped' WHERE vm_id = ?`, [vm.vm_id]);
      logVMAction(vm.vm_id, 'stop', 'stopped', `VM stopped`);
      console.log(`[API Success] VM ${vm.vm_id} stopped successfully`);
      res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) stopped` });
    } catch (error) {
      console.error(`[API Error] Exception stopping VM ${vm.vm_id}:`, error);
      (console.error(error), res.status(500).json({ error: 'Internal server error' }));
    }
  });
});

// VM RESTART (Using VM ID)
app.post('/api/vms/:vm_id/restart', checkAuth, vmActionRateLimit, async (req, res) => {
  try {
    const userId = req.session.userId;
    let query = `SELECT * FROM vms WHERE vm_id = ?`;
    let params = [req.params.vm_id];
    
    // Normal users can only restart their own VMs
    if (req.session.role !== 'admin') {
      query += ` AND owner_id = ?`;
      params.push(userId);
    }
    
    db.get(query, params, async (err, vm) => {
      if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });

      let node; try { node = await nodeManager.getNodeForVM(vm); } catch (nodeErr) { console.error('[API Error] node lookup failed for VM ' + vm.vm_id + ':', nodeErr.message); return res.status(502).json({ success: false, error: 'NODE_LOOKUP_FAILED', message: 'Node registry unavailable: ' + nodeErr.message }); }
      if (node && node.mode === 'remote') {
        try {
          const result = await nodeManager.sendNodeCommand(node.id, 'vm.restart', { vm }, { timeoutMs: 30000 });
          db.run(`UPDATE vms SET status = 'running' WHERE vm_id = ?`, [vm.vm_id]);
          logVMAction(vm.vm_id, 'restart', 'running', `VM restarted on remote node ${node.name}`);
          return res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) restarted` });
        } catch (e) {
          logVMAction(vm.vm_id, 'restart', 'failed', e.message);
          return res.status(e.httpStatus || 502).json({ success: false, error: e.code || 'NODE_RESTART_FAILED', message: e.message });
        }
      }

      try {
        const pidFile = path.join(VM_DIR, `vm-${vm.vm_id}.pid`);
        if (fs.existsSync(pidFile)) {
          const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim());
          if (isPidQemu(pid)) {
            try {
              process.kill(pid, 'SIGTERM');
            } catch (e) {}
          } else {
            console.warn(`[API] PID ${pid} for VM ${vm.vm_id} is not a live QEMU process — skipping kill`);
          }
        }
        
        await new Promise(resolve => setTimeout(resolve, 2000));

        const result = await startQemuVM(vm);
        if (result.success) {
          vmProcesses.set(vm.vm_id, result.pid);
          db.run(`UPDATE vms SET status = 'running' WHERE vm_id = ?`, [vm.vm_id]);
          logVMAction(vm.vm_id, 'restart', 'running', `VM restarted successfully`);
          res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) restarted` });
        } else {
          res.status(500).json({ error: 'Failed to restart VM' });
        }
      } catch (error) {
        console.error(`[API Error] Exception restarting VM ${vm.vm_id}:`, error);
        logVMAction(vm.vm_id, 'restart', 'failed', error.message);
        res.status(500).json({ success: false, error: 'VM_RESTART_FAILED', message: error.message || 'Failed to restart VM' });
      }
    });
  } catch (error) {
    (console.error(error), res.status(500).json({ error: 'Internal server error' }));
  }
});

// VM REINSTALL (Using VM ID)

// VM DELETE (Using VM ID)
app.delete('/api/vms/:vm_id', checkAuth, vmActionRateLimit, (req, res) => {
  let query = `SELECT * FROM vms WHERE vm_id = ?`;
  let params = [req.params.vm_id];
  if (req.session.role !== 'admin') {
    query += ` AND owner_id = ?`;
    params.push(req.session.userId);
  }
  db.get(query, params, async (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });

    // VMs on a remote node keep their artifacts (disk, seed ISO, PID,
    // logs) on that node - delegate the cleanup to its agent, then drop
    // the row. If the node is unreachable the row is still deleted (a VM
    // must not be held hostage by a dead node) and the response says the
    // node-side files were left behind.
    try {
      const node = await nodeManager.getNodeForVM(vm).catch(() => null);
      if (node && node.mode === 'remote') {
        let nodeNote = '';
        try {
          await nodeManager.sendNodeCommand(node.id, 'vm.cleanup', { vmId: String(vm.vm_id) }, { timeoutMs: 20000 });
        } catch (e) {
          nodeNote = ` (warning: could not clean up files on node "${node.name}" - ${e.message})`;
        }
        vmProcesses.delete(vm.vm_id);
        qemuStdins.delete(String(vm.vm_id));
        db.run(`DELETE FROM vms WHERE vm_id = ?`, [vm.vm_id]);
        db.run(`DELETE FROM vm_port_forwards WHERE vm_id = ?`, [vm.vm_id]);
    db.run(`DELETE FROM vm_logs WHERE vm_id = ?`, [vm.vm_id]);
        logVMAction(vm.vm_id, 'delete', 'deleted', `VM ${vm.vm_name} deleted (node ${node.name})`);
        return res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) deleted${nodeNote}` });
      }
    } catch (e) { /* fall through to the local cleanup below */ }

    try {
      const pidFile = path.join(VM_DIR, `vm-${vm.vm_id}.pid`);
      if (fs.existsSync(pidFile)) {
        const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim());
        if (isPidQemu(pid)) {
          try {
            process.kill(pid, 'SIGKILL');
          } catch (e) {}
        } else {
          console.warn(`[API] PID ${pid} for VM ${vm.vm_id} is not a live QEMU process — skipping kill`);
        }
      }

      if (fs.existsSync(vm.img_file)) fs.unlinkSync(vm.img_file);
      if (fs.existsSync(vm.seed_file)) fs.unlinkSync(vm.seed_file);
      if (fs.existsSync(vm.disk_file)) fs.unlinkSync(vm.disk_file);

      vmProcesses.delete(vm.vm_id);
      qemuStdins.delete(String(vm.vm_id));
      db.run(`DELETE FROM vms WHERE vm_id = ?`, [vm.vm_id]);
      db.run(`DELETE FROM vm_port_forwards WHERE vm_id = ?`, [vm.vm_id]);
    db.run(`DELETE FROM vm_logs WHERE vm_id = ?`, [vm.vm_id]);
      
      logVMAction(vm.vm_id, 'delete', 'deleted', `VM ${vm.vm_name} deleted`);
      res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) deleted` });
    } catch (error) {
      (console.error(error), res.status(500).json({ error: 'Internal server error' }));
    }
  });
});

// VM LOGS (Using VM ID)
app.get('/api/vms/:vm_id/logs', checkAuth, (req, res) => {
  let ownerQuery = `SELECT vm_id FROM vms WHERE vm_id = ?`;
  let ownerParams = [req.params.vm_id];
  if (req.session.role !== 'admin') {
    ownerQuery += ` AND owner_id = ?`;
    ownerParams.push(req.session.userId);
  }
  db.get(ownerQuery, ownerParams, (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });
    db.all(
      `SELECT * FROM vm_logs WHERE vm_id = ? ORDER BY timestamp DESC LIMIT 50`,
      [req.params.vm_id],
      (err2, logs) => {
        if (err2) return res.status(500).json({ error: 'Failed to load logs' });
        res.json(logs || []);
      }
    );
  });
});

// VM SNAPSHOTS (Using VM ID)
app.get('/api/vms/:vm_id/snapshots', checkAuth, (req, res) => {
  const userId = req.session.userId;
  let query = `SELECT * FROM vm_snapshots WHERE vm_id = ?`;
  let params = [req.params.vm_id];
  
  // First check ownership if not admin
  if (req.session.role !== 'admin') {
    // Check if user owns this VM
    db.get(`SELECT * FROM vms WHERE vm_id = ? AND owner_id = ?`, [req.params.vm_id, userId], (err, vm) => {
      if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });
      
      db.all(query, params, (err, snapshots) => {
        if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
        res.json(snapshots || []);
      });
    });
  } else {
    db.all(query, params, (err, snapshots) => {
      if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
      res.json(snapshots || []);
    });
  }
});

// ============= ISO ATTACH/DETACH ENDPOINTS =============

// Attach ISO to VM (for ISO templates or manual ISO installation)
app.post('/api/vms/:vm_id/iso/attach', checkAuth, async (req, res) => {
  try {
    const vm_id = req.params.vm_id;
    const { iso_file } = req.body;
    const userId = req.session.userId;

    if (!iso_file) {
      return res.status(400).json({ error: 'ISO file is required' });
    }

    // Get VM
    let query = `SELECT * FROM vms WHERE vm_id = ?`;
    let params = [vm_id];

    if (req.session.role !== 'admin') {
      query += ` AND owner_id = ?`;
      params.push(userId);
    }

    db.get(query, params, async (err, vm) => {
      if (err || !vm) {
        return res.status(404).json({ error: 'VM not found or access denied' });
      }

      // Reject any path component (../, absolute paths, etc.) - only a bare
      // filename inside ISO_DIR is ever valid here.
      const isoBasename = path.basename(iso_file);
      if (isoBasename !== iso_file) {
        return res.status(400).json({ error: 'Invalid ISO file name' });
      }

      // Verify ISO file exists, and that the resolved path still lives
      // inside ISO_DIR (defense in depth against symlink/traversal tricks).
      const isoPath = path.join(ISO_DIR, isoBasename);
      const resolvedIsoPath = path.resolve(isoPath);
      const resolvedIsoDir = path.resolve(ISO_DIR) + path.sep;
      if (!resolvedIsoPath.startsWith(resolvedIsoDir) || !fs.existsSync(isoPath)) {
        return res.status(400).json({ error: 'ISO file not found' });
      }

      // Remote-node VM: the ISO must exist ON that node - stream it there
      // first (verified, flow-controlled transfer). The node's QEMU
      // launcher then resolves it by basename from its own templates dir.
      try {
        const node = await nodeManager.getNodeForVM(vm).catch(() => null);
        if (node && node.mode === 'remote') {
          if (!nodeManager.isNodeOnline(node.id)) {
            return res.status(409).json({ error: `Node "${node.name}" is offline - cannot attach ISO`, code: 'NODE_OFFLINE' });
          }
          console.log(`[VM-${vm_id}] Streaming ISO "${isoBasename}" to node "${node.name}"...`);
          await nodeManager.relayNodeFileUpload(node.id,
            { name: isoBasename, totalBytes: fs.statSync(isoPath).size },
            fs.createReadStream(isoPath, { highWaterMark: 1024 * 1024 }));
          logVMAction(vm_id, 'iso_attach', 'completed', `ISO streamed to node "${node.name}": ${isoBasename}`);
        }
      } catch (e) {
        return res.status(e.httpStatus || 502).json({ error: 'Could not deliver ISO to the node: ' + e.message });
      }

      // Update VM with attached ISO
      db.run(
        `UPDATE vms SET iso_attached = ?, boot_from_iso = 1 WHERE vm_id = ?`,
        [iso_file, vm_id],
        (err) => {
          if (err) {
            return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
          }

          logVMAction(vm_id, 'iso_attach', 'completed', `ISO file attached: ${iso_file}`);
          res.json({ success: true, message: `ISO file "${iso_file}" attached successfully` });
        }
      );
    });
  } catch (error) {
    (console.error(error), res.status(500).json({ error: 'Internal server error' }));
  }
});

// Detach ISO from VM
app.post('/api/vms/:vm_id/iso/detach', checkAuth, async (req, res) => {
  try {
    const vm_id = req.params.vm_id;
    const userId = req.session.userId;

    // Get VM
    let query = `SELECT * FROM vms WHERE vm_id = ?`;
    let params = [vm_id];

    if (req.session.role !== 'admin') {
      query += ` AND owner_id = ?`;
      params.push(userId);
    }

    db.get(query, params, (err, vm) => {
      if (err || !vm) {
        return res.status(404).json({ error: 'VM not found or access denied' });
      }

      // Update VM to remove attached ISO and boot from disk
      db.run(
        `UPDATE vms SET iso_attached = NULL, boot_from_iso = 0 WHERE vm_id = ?`,
        [vm_id],
        (err) => {
          if (err) {
            return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
          }

          logVMAction(vm_id, 'iso_detach', 'completed', 'ISO file detached, will boot from disk');
          res.json({ success: true, message: 'ISO file detached successfully' });
        }
      );
    });
  } catch (error) {
    (console.error(error), res.status(500).json({ error: 'Internal server error' }));
  }
});

// Get VM ISO status
app.get('/api/vms/:vm_id/iso/status', checkAuth, async (req, res) => {
  try {
    const vm_id = req.params.vm_id;
    const userId = req.session.userId;

    let query = `SELECT vm_id, iso_attached, boot_from_iso, status FROM vms WHERE vm_id = ?`;
    let params = [vm_id];

    if (req.session.role !== 'admin') {
      query += ` AND owner_id = ?`;
      params.push(userId);
    }

    db.get(query, params, (err, vm) => {
      if (err || !vm) {
        return res.status(404).json({ error: 'VM not found or access denied' });
      }

      res.json({
        vm_id: vm.vm_id,
        iso_attached: vm.iso_attached || null,
        boot_from_iso: vm.boot_from_iso ? true : false,
        vm_status: vm.status
      });
    });
  } catch (error) {
    (console.error(error), res.status(500).json({ error: 'Internal server error' }));
  }
});

// (Round 5) The legacy snapshot stub that only wrote a DB row is gone -
// the platform router mounted above now serves real qemu-img-backed
// snapshot create/restore/delete routes for both local and remote VMs.

// ADMIN DASHBOARD
app.get('/api/admin/dashboard', checkAuth, checkAdmin, (req, res) => {
  db.all(`SELECT COUNT(*) as total FROM users`, (err, userCount) => {
    db.all(`SELECT COUNT(*) as total FROM vms`, (err, vmCount) => {
      db.all(`SELECT COUNT(*) as total FROM vms WHERE status = 'running'`, (err, runningCount) => {
        res.json({
          totalUsers: userCount ? userCount[0].total : 0,
          totalVMs: vmCount ? vmCount[0].total : 0,
          runningVMs: runningCount ? runningCount[0].total : 0
        });
      });
    });
  });
});

// Recent activity feed for the admin dashboard - merges the per-VM action
// log with the security audit log, newest first.
app.get('/api/admin/activity', checkAuth, checkAdmin, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 10, 50);
  db.all(`SELECT id, vm_id, action, status, message, timestamp FROM vm_logs ORDER BY id DESC LIMIT ?`, [limit], (err, vmRows) => {
    if (err) {
      console.error('[API Error] /api/admin/activity (vm_logs):', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    const fromVm = (vmRows || []).map((r) => ({
      id: 'vm-' + r.id, action: r.action, message: r.message || r.action,
      vm_id: r.vm_id, status: r.status, timestamp: r.timestamp
    }));
    auditLog.query({ limit }).then((auditRows) => {
      const fromAudit = (auditRows || []).map((r) => ({
        id: 'audit-' + r.id,
        action: r.action,
        message: r.details
          ? (r.action || '').replace(/_/g, ' ') + ' - ' + r.details
          : (r.username || 'system') + ' ' + (r.action || '').replace(/_/g, ' '),
        vm_id: r.target_type === 'vm' ? r.target_id : null,
        status: r.result,
        timestamp: r.created_at
      }));
      const merged = fromVm.concat(fromAudit)
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, limit);
      res.json(merged);
    }).catch((e) => {
      console.error('[API Error] /api/admin/activity (audit_log):', e);
      res.json(fromVm);
    });
  });
});

// Live host stats for the admin dashboard CPU / memory meters.
app.get('/api/system/status', checkAuth, checkAdmin, async (req, res) => {
  try {
    const stats = await require('./system-info').getLiveStats(VM_DIR);
    const fmt = (bytes) => (bytes / 1024 ** 3).toFixed(1) + ' GB';
    res.json({
      cpu: stats.cpuUsagePercent + '%',
      memory: fmt(stats.ramUsedBytes) + ' / ' + fmt(stats.ramTotalBytes),
      cpuUsagePercent: stats.cpuUsagePercent,
      ramUsedBytes: stats.ramUsedBytes,
      ramTotalBytes: stats.ramTotalBytes,
      diskUsedBytes: stats.diskUsedBytes,
      diskTotalBytes: stats.diskTotalBytes,
      loadAvg: stats.loadAvg,
      uptimeSeconds: stats.uptimeSeconds
    });
  } catch (err) {
    console.error('[API Error] /api/system/status:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// HELPER FUNCTIONS

function logVMAction(vm_id, action, status, message) {
  db.run(
    `INSERT INTO vm_logs (vm_id, action, status, message) VALUES (?, ?, ?, ?)`,
    [vm_id, action, status, message]
  );
}

// Download OS template image
//
// AUDIT FIX (OS template subsystem hardening): full rewrite of the download
// path per the requested robustness spec. Key changes from the previous
// version:
//  - honors QEMU_BIN-style detection pattern for headers: sends a
//    User-Agent and Accept header (some CDNs/WAFs reject bare-Node-fetch
//    requests with a 403 even when curl/wget would succeed)
//  - connect timeout, per-chunk read-stall timeout, and a total download
//    timeout, all independently configurable via env vars
//  - retries transient failures (network errors, 5xx, 429) with capped
//    exponential backoff; does NOT retry permanent failures (404, 403) -
//    retrying a 404 just wastes time and delays the fallback-URL attempt
//  - downloads to "<target>.part" and only renames to the final path after
//    the file is fully written AND passes validateImageFile() - so a
//    half-downloaded or corrupt file can never be mistaken for a valid,
//    cached template
//  - cleans up the .part file on every failure path
//  - throttles progress logging to roughly once per 5% (or every ~3s)
//    instead of once per received chunk, which was flooding the logs
//  - guards against two concurrent downloads racing to write the same
//    target path (a second caller waits on the first's in-flight promise
//    instead of starting a duplicate download)
const DOWNLOAD_CONNECT_TIMEOUT_MS = parseInt(process.env.TEMPLATE_CONNECT_TIMEOUT_MS) || 15000;
const DOWNLOAD_STALL_TIMEOUT_MS = parseInt(process.env.TEMPLATE_STALL_TIMEOUT_MS) || 30000;
const DOWNLOAD_TOTAL_TIMEOUT_MS = parseInt(process.env.TEMPLATE_TOTAL_TIMEOUT_MS) || 30 * 60 * 1000; // 30 min
const DOWNLOAD_MAX_ATTEMPTS_PER_URL = 3;
const DOWNLOAD_USER_AGENT = 'VNM-Panel-TemplateFetcher/1.0 (+https://github.com/stripathi02123-tech/Vnm-panel)';

// In-flight download tracker for concurrent-download protection, keyed by
// the final target path.
const _inFlightDownloads = new Map();

function _isPermanentHttpFailure(statusCode) {
  // 404/403/410 etc. won't succeed on retry against the same URL - move on
  // to the next fallback URL (or fail) immediately rather than burning
  // retry attempts and time on something that cannot change.
  return statusCode >= 400 && statusCode < 500;
}

function _sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

// AUDIT FIX (item 5 - don't classify application/network errors as
// upstream 404s): Node's http/https client surfaces connection-layer
// failures via err.code on the 'error' event, with no HTTP status at all.
// Previously these fell into the same generic path as a real HTTP 404
// and were indistinguishable in logs/API responses once wrapped in
// "Failed to download built-in template: ...". This tags each failure
// with an explicit `category` so callers (and the JSON error payload)
// can tell "the URL is wrong" (upstream 4xx) apart from "the request
// never reached/completed against the URL" (DNS/TLS/timeout/reset/proxy).
function _classifyConnectionError(err) {
  const code = err.code || '';
  switch (code) {
    case 'ENOTFOUND':
    case 'EAI_AGAIN':
      return 'dns_failure';
    case 'CERT_HAS_EXPIRED':
    case 'DEPTH_ZERO_SELF_SIGNED_CERT':
    case 'UNABLE_TO_VERIFY_LEAF_SIGNATURE':
    case 'ERR_TLS_CERT_ALTNAME_INVALID':
      return 'tls_failure';
    case 'ECONNRESET':
      return 'connection_reset';
    case 'ECONNREFUSED':
      return 'connection_refused';
    case 'ETIMEDOUT':
      return 'timeout';
    case 'EHOSTUNREACH':
    case 'ENETUNREACH':
      // Classic broken-family symptom: the kernel has no working route for
      // one address family - most often IPv6 on hosts whose provider
      // assigned a global address but never delivered working v6 egress.
      return 'no_route';
    case 'EPROXYAUTH':
    case 'ERR_PROXY_CONNECTION':
      return 'proxy_failure';
    default:
      return code ? `network_error_${code}` : 'unknown_network_error';
  }
}

// ---------------------------------------------------------------
// MIRROR DOWNLOAD FIX (broken IPv6 / IPv4 egress resilience)
// ---------------------------------------------------------------
// On VPS hosts with a global IPv6 address but broken IPv6 egress, Node's
// default resolution order (getaddrinfo -> AAAA first) makes every outbound
// connect black-hole: the request dies at the TCP layer with ETIMEDOUT /
// no_route and never sees an HTTP response, while curl and git (which race
// families or prefer IPv4) work fine on the exact same host. The panel's
// Debian/Ubuntu/Fedora/CentOS/Alma template downloads were hitting exactly
// this: 502 TEMPLATE_DOWNLOAD_FAILED with zero HTTP responses from any
// mirror. The helpers below resolve each download host into an ORDERED
// address list - IPv4 first by default, VNM_PREFER_IPV6=1 flips the order -
// and _downloadOnce() then tries each address in sequence, advancing only
// on connect-layer failures (no HTTP status). An HTTP verdict of any kind
// (even 404) is a real server response and is handed to the existing
// retry/fallback-URL logic unchanged.
const _hostResolveCache = new Map(); // host -> { expires, list }
const HOST_RESOLVE_TTL_MS = 60 * 1000;

function _preferIPv6() {
  const v = String(process.env.VNM_PREFER_IPV6 || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

// Ordered A/AAAA resolution. IP literals pass through untouched. IPv4 first
// by default (matches curl's practical behavior and fixes the reported
// mirror black-hole); VNM_PREFER_IPV6=1 puts AAAA first for hosts whose
// IPv4 path is the broken one.
async function _resolveHostCandidates(host) {
  const literal = net.isIP(host);
  if (literal) return [{ address: host, family: literal }];
  const cached = _hostResolveCache.get(host);
  if (cached && cached.expires > Date.now()) return cached.list.slice();
  let list = [];
  const all = await dns.promises.lookup(host, { all: true, verbatim: true });
  const v4 = all.filter(a => a.family === 4);
  const v6 = all.filter(a => a.family === 6);
  list = _preferIPv6() ? [...v6, ...v4] : [...v4, ...v6];
  const seen = new Set();
  list = list.filter(a => !seen.has(a.address) && seen.add(a.address));
  _hostResolveCache.set(host, { expires: Date.now() + HOST_RESOLVE_TTL_MS, list });
  if (_hostResolveCache.size > 500) {
    _hostResolveCache.delete(_hostResolveCache.keys().next().value);
  }
  return list.slice();
}

// lookup() hook that pins the TCP layer to exactly one resolved address.
// Host header, TLS SNI and certificate validation still use the URL's
// hostname, so a pinned attempt is indistinguishable from a normal request
// to the origin server.
function _pinnedLookup(addr) {
  return function pinnedLookup(hostname, options, callback) {
    if (options && options.all) {
      return callback(null, [{ address: addr.address, family: addr.family }]);
    }
    return callback(null, addr.address, addr.family);
  };
}

// Public entry: resolve the URL's host, then try each address in order.
// Only connect-layer failures advance to the next address; any HTTP
// response is final for this URL (a different IP of the same host cannot
// change a 404/403 verdict, and 5xx already has its own retry logic).
async function _downloadOnce(url, partPath) {
  let host = null;
  try { host = new URL(url).hostname; } catch (e) { host = null; }
  if (!host || net.isIP(host)) return _downloadOnceVia(url, partPath, null);

  const candidates = await _resolveHostCandidates(host);
  if (!candidates.length) {
    throw Object.assign(new Error(`Could not resolve ${host} (no usable A/AAAA records)`), { permanent: false, category: 'dns_failure' });
  }
  const attempted = [];
  let lastErr = null;
  for (let i = 0; i < candidates.length; i++) {
    const cand = candidates[i];
    try {
      const r = await _downloadOnceVia(url, partPath, cand);
      console.log(`[TEMPLATE] ${host}: connected via ${cand.address} (IPv${cand.family})`);
      return r;
    } catch (err) {
      lastErr = err;
      attempted.push(`${cand.address} (IPv${cand.family}): ${err.statusCode ? 'HTTP ' + err.statusCode : (err.category || err.code || 'connect failed')}`);
      if (err.statusCode) break; // the server spoke - switching address cannot change the verdict
      console.log(`[TEMPLATE] ${host}: address ${cand.address} (IPv${cand.family}) failed at the connection layer (${err.category || err.code || 'unknown'})${i < candidates.length - 1 ? ' - trying next resolved address' : ' - no more addresses for this host'}`);
    }
  }
  if (lastErr) {
    lastErr.attemptAddresses = attempted;
    lastErr.addressLog = attempted.join('; ');
  }
  throw lastErr;
}

// Single attempt against a single URL (through one resolved address). The
// original logic is unchanged; only the signature gained the pinned _addr.
function _downloadOnceVia(url, partPath, _addr) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    let settled = false;
    let stallTimer = null;
    let totalTimer = null;
    const file = fs.createWriteStream(partPath);

    const cleanupTimers = () => {
      if (stallTimer) clearTimeout(stallTimer);
      if (totalTimer) clearTimeout(totalTimer);
    };
    const fail = (err) => {
      if (settled) return;
      settled = true;
      cleanupTimers();
      try { file.close(); } catch (e) {}
      fs.unlink(partPath, () => {});
      reject(err);
    };
    const succeed = () => {
      if (settled) return;
      settled = true;
      cleanupTimers();
      resolve(true);
    };

    totalTimer = setTimeout(() => {
      req.destroy();
      fail(Object.assign(new Error(`Download exceeded total timeout of ${DOWNLOAD_TOTAL_TIMEOUT_MS}ms`), { permanent: false }));
    }, DOWNLOAD_TOTAL_TIMEOUT_MS);

    const req = lib.get(url, {
      timeout: DOWNLOAD_CONNECT_TIMEOUT_MS,
      headers: {
        'User-Agent': DOWNLOAD_USER_AGENT,
        'Accept': 'application/octet-stream, */*'
      },
      // MIRROR DOWNLOAD FIX: pin this attempt to one resolved address when
      // the caller is iterating candidates. autoSelectFamily:false keeps the
      // attempt single-address - family order is decided one level up.
      lookup: _addr ? _pinnedLookup(_addr) : undefined,
      autoSelectFamily: false
    }, (response) => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
        const location = response.headers.location;
        response.resume(); // drain
        if (!location) {
          return fail(Object.assign(new Error('Redirect without Location header'), { statusCode: response.statusCode, permanent: true }));
        }
        // Resolve relative Location headers against the original URL.
        let redirectUrl;
        try {
          redirectUrl = new URL(location, url).toString();
        } catch (e) {
          return fail(Object.assign(new Error(`Invalid redirect Location: ${location}`), { permanent: true }));
        }
        cleanupTimers();
        try { file.close(); } catch (e) {}
        fs.unlink(partPath, () => {});
        // Recurse - each redirect hop gets its own timers/attempt.
        _followRedirect(redirectUrl, partPath, 1).then(resolve, reject);
        settled = true; // this promise's job is done; the recursive call owns resolve/reject now
        return;
      }

      if (response.statusCode !== 200) {
        response.resume();
        return fail(Object.assign(
          new Error(`HTTP ${response.statusCode}: ${response.statusMessage || 'Unknown'}`),
          { statusCode: response.statusCode, permanent: _isPermanentHttpFailure(response.statusCode) }
        ));
      }

      // Sanity-check the content type where the server provides one: a CDN
      // or WAF returning an HTML error/interstitial page with a 200 status
      // is a real, observed failure mode ("verify downloaded content is
      // actually a VM image" from the audit request) - catch the obvious
      // case early rather than only discovering it at qemu-img-info time.
      const contentType = (response.headers['content-type'] || '').toLowerCase();
      if (contentType.includes('text/html') || contentType.includes('application/json')) {
        response.resume();
        return fail(Object.assign(
          new Error(`Server returned HTTP 200 but Content-Type is "${contentType}" (expected a binary image) - likely an error/interstitial page, not the actual file`),
          { permanent: true }
        ));
      }

      const len = parseInt(response.headers['content-length'], 10);
      let downloaded = 0;
      let lastLoggedPercent = -5;
      let lastLogTime = Date.now();

      const resetStallTimer = () => {
        if (stallTimer) clearTimeout(stallTimer);
        stallTimer = setTimeout(() => {
          req.destroy();
          fail(Object.assign(new Error(`No data received for ${DOWNLOAD_STALL_TIMEOUT_MS}ms (stalled connection)`), { permanent: false }));
        }, DOWNLOAD_STALL_TIMEOUT_MS);
      };
      resetStallTimer();

      response.on('data', (chunk) => {
        downloaded += chunk.length;
        resetStallTimer();
        if (len) {
          const percent = (downloaded / len) * 100;
          const now = Date.now();
          if (percent - lastLoggedPercent >= 5 || now - lastLogTime >= 3000) {
            console.log(`[TEMPLATE] Progress: ${percent.toFixed(1)}% (${(downloaded / 1048576).toFixed(1)}MB / ${(len / 1048576).toFixed(1)}MB)`);
            lastLoggedPercent = percent;
            lastLogTime = now;
          }
        }
      });

      response.pipe(file);
      file.on('finish', () => {
        file.close(() => succeed());
      });
      file.on('error', (err) => fail(err));
    });

    req.on('error', (err) => {
      // AUDIT FIX (item 5): tag with a classification and a clean message
      // distinguishing this from an upstream HTTP status - there IS no
      // HTTP status here, the request never got a response at all.
      const category = _classifyConnectionError(err);
      fail(Object.assign(err, {
        permanent: false,
        category,
        message: `${category.replace(/_/g, ' ')} (${err.code || err.message}) - request to ${url} never received an HTTP response`
      }));
    });
    req.on('timeout', () => {
      req.destroy();
      fail(Object.assign(new Error(`Connection timed out after ${DOWNLOAD_CONNECT_TIMEOUT_MS}ms (no upstream response - not an HTTP error)`), { permanent: false, category: 'timeout' }));
    });
  });
}

function _followRedirect(url, partPath, depth) {
  if (depth > 8) {
    return Promise.reject(Object.assign(new Error('Too many redirects (>8)'), { permanent: true }));
  }
  return _downloadOnce(url, partPath).catch(err => {
    // _downloadOnce itself handles same-hop redirects internally via
    // recursion; errors bubbling here are genuine failures for this hop.
    throw err;
  });
}

// Downloads a single URL to targetPath with retries + backoff, writing to
// a .part file and only renaming into place after a successful
// content-level download (image validation happens one level up, in
// downloadTemplateWithFallback, since only that layer knows whether more
// fallback URLs remain worth trying on a validation failure).
async function downloadTemplateFromURL(url, targetPath) {
  const targetDir = path.dirname(targetPath);
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }
  const partPath = `${targetPath}.part`;

  let lastErr = null;
  for (let attempt = 1; attempt <= DOWNLOAD_MAX_ATTEMPTS_PER_URL; attempt++) {
    try {
      console.log(`[TEMPLATE] Attempt ${attempt}/${DOWNLOAD_MAX_ATTEMPTS_PER_URL}: ${url}`);
      await _downloadOnce(url, partPath);
      // Atomic rename into place only after a fully successful download.
      fs.renameSync(partPath, targetPath);
      console.log(`[TEMPLATE] ✓ Downloaded successfully: ${targetPath}`);
      return true;
    } catch (err) {
      lastErr = err;
      fs.unlink(partPath, () => {});
      const statusInfo = err.statusCode ? ` HTTP ${err.statusCode}` : '';
      console.log(`[TEMPLATE] Attempt ${attempt} failed:${statusInfo} ${err.message}`);
      if (err.permanent) {
        console.log(`[TEMPLATE] Failure is permanent (won't retry this URL)`);
        break;
      }
      if (attempt < DOWNLOAD_MAX_ATTEMPTS_PER_URL) {
        const backoffMs = Math.min(1000 * Math.pow(2, attempt - 1), 8000);
        console.log(`[TEMPLATE] Retrying in ${backoffMs}ms...`);
        await _sleep(backoffMs);
      }
    }
  }
  throw lastErr || new Error('Download failed for an unknown reason');
}

// Validate a downloaded/cached image with `qemu-img info` before trusting
// it. Rejects missing files, qemu-img failures (corrupt/non-image data -
// this is what catches an HTML error page saved with a .qcow2 extension),
// and images with zero virtual size.
async function validateImageFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return { valid: false, reason: 'File does not exist' };
  }
  let stat;
  try { stat = fs.statSync(filePath); } catch (err) { return { valid: false, reason: 'File does not exist or is not readable' }; }
  if (stat.size === 0) {
    return { valid: false, reason: 'File is empty (0 bytes)' };
  }
  try {
    const output = execSync(`qemu-img info --output=json "${filePath}"`, { stdio: 'pipe', timeout: 30000 }).toString();
    const info = JSON.parse(output);
    if (!info.format) {
      return { valid: false, reason: 'qemu-img info returned no format - not a recognized image' };
    }
    if (!info['virtual-size'] || info['virtual-size'] <= 0) {
      return { valid: false, reason: `Invalid virtual size: ${info['virtual-size']}` };
    }
    return { valid: true, format: info.format, virtualSize: info['virtual-size'] };
  } catch (err) {
    // qemu-img itself missing is a separate, already-diagnosed problem
    // (see resolveQemuBinary-style checks elsewhere); don't block template
    // caching entirely on its absence, but log loudly since validation is
    // effectively skipped.
    if (err.message && (err.message.includes('not found') || err.code === 'ENOENT')) {
      console.warn('[TEMPLATE] qemu-img not available - skipping image validation (install qemu-img to enable this check)');
      return { valid: true, skipped: true };
    }
    return { valid: false, reason: `qemu-img info failed: ${err.message.split('\n')[0]}` };
  }
}

// Try each candidate URL in order (per template.download_urls) until one
// downloads AND validates successfully. Only fails after every candidate
// has been exhausted, and returns a structured diagnostic object matching
// the shape requested in the audit: {error, template, attempts, details}.
async function downloadTemplateWithFallback(urls, targetPath, label) {
  const details = [];
  for (let i = 0; i < urls.length; i++) {
    const url = urls[i];
    console.log(`[TEMPLATE] ${label}: trying candidate ${i + 1}/${urls.length}`);
    try {
      await downloadTemplateFromURL(url, targetPath);
      const validation = await validateImageFile(targetPath);
      if (!validation.valid) {
        fs.unlink(targetPath, () => {});
        details.push({ url, outcome: 'downloaded_but_invalid', reason: validation.reason });
        console.log(`[TEMPLATE] ${label}: candidate ${i + 1} downloaded but failed validation: ${validation.reason}`);
        if (i < urls.length - 1) console.log(`[TEMPLATE] ${label}: trying fallback ${i + 2}...`);
        continue;
      }
      console.log(`[TEMPLATE] ${label}: ✓ succeeded via candidate ${i + 1} (format=${validation.format}, size=${validation.virtualSize || 'n/a'})`);
      return { success: true, url, details };
    } catch (err) {
      // AUDIT FIX (item 5): distinguish a genuine upstream HTTP status
      // (statusCode present -> the server responded) from a
      // connection-layer failure (category present, no statusCode -> the
      // request never got a response to classify as 404/403/etc).
      details.push({
        url,
        outcome: 'download_failed',
        statusCode: err.statusCode || null,
        category: err.statusCode ? 'http_status' : (err.category || 'unknown'),
        addresses: err.attemptAddresses || null,
        reason: err.message
      });
      const label_ = err.statusCode ? `HTTP ${err.statusCode}` : `${err.category || 'error'}: ${err.message}`;
      console.log(`[TEMPLATE] ${label}: candidate ${i + 1} failed - ${label_}`);
      if (i < urls.length - 1) console.log(`[TEMPLATE] ${label}: trying fallback ${i + 2}...`);
    }
  }
  const err = new Error(`All ${urls.length} candidate URL(s) failed for ${label}`);
  err.code = 'TEMPLATE_DOWNLOAD_FAILED';
  err.attempts = urls.length;
  err.details = details;
  // MIRROR DOWNLOAD FIX: when not a single candidate produced an HTTP
  // response, this is a TCP-level reachability problem on THIS host (the
  // reported VPS case: broken IPv6 egress black-holing every mirror), not a
  // mirror outage. Say so explicitly instead of letting the UI shrug "502".
  const noneAnswered = details.length > 0 && details.every(d => (d.outcome === 'download_failed' && !d.statusCode) || d.outcome === 'downloaded_but_invalid');
  if (noneAnswered && details.some(d => d.outcome === 'download_failed' && !d.statusCode)) {
    err.noHttpResponse = true;
    err.message += ' - no candidate URL ever returned an HTTP response: this is a TCP-level reachability problem (typically broken IPv6 or IPv4 egress on this host), not a mirror outage. Try VNM_PREFER_IPV6=1 (or =0) to flip the address-family order, and check this host\'s network.';
  }
  throw err;
}

// Download OS template from built-in templates OR directly from URL
async function downloadTemplate(sourceOrKey, targetPath) {
  // AUDIT FIX (concurrent-download protection): if two requests race to
  // populate the same cache path (e.g. two admins both creating the first
  // VM off a not-yet-cached template at the same time), the second caller
  // now waits on the first's in-flight download instead of starting a
  // redundant, competing download into the same .part file.
  if (_inFlightDownloads.has(targetPath)) {
    console.log(`[TEMPLATE] Download already in progress for ${targetPath} - waiting on it`);
    return _inFlightDownloads.get(targetPath);
  }

  const work = (async () => {
    let urls;
    let templateName;

    if (OS_TEMPLATES[sourceOrKey]) {
      const template = OS_TEMPLATES[sourceOrKey];
      urls = template.download_urls && template.download_urls.length ? template.download_urls : [template.url];
      templateName = template.name;
    } else if (typeof sourceOrKey === 'string' && sourceOrKey.startsWith('http')) {
      urls = [sourceOrKey];
      templateName = 'custom template';
    } else {
      throw new Error('Invalid template key or URL');
    }

    console.log(`[TEMPLATE] ${templateName}: ${urls.length} candidate URL(s) configured`);
    await downloadTemplateWithFallback(urls, targetPath, templateName);
    console.log(`[TEMPLATE] Download complete for ${templateName}`);
    return true;
  })();

  _inFlightDownloads.set(targetPath, work);
  try {
    return await work;
  } finally {
    _inFlightDownloads.delete(targetPath);
  }
}

// Generate Cloud-Init config for NAT (User Mode)
// Configures DHCP networking automatically
function generateNATCloudInitConfig(vm) {
  const username = vm.username || 'root';
  const password = vm.password || 'password';
  const hostname = vm.hostname || 'vnm-instance';

  // Build users section - support root and custom users
  let usersSection = `users:`;
  // AUDIT FIX #9/#10: modern cloud-init deprecates chpasswd.list in favor of
  // chpasswd.users with an explicit type, and previously the non-root
  // account's root fallback password was hard-coded to the literal string
  // "password" instead of the VM's actual configured password, which is
  // exactly the kind of mismatch that produces "login failed even though
  // credentials were expected".
  let chpasswdUsers = ``;

  if (username.toLowerCase() === 'root') {
    // If root user, configure root directly
    usersSection += `
  - name: root
    lock_passwd: false
    shell: /bin/bash
    homedir: /root`;
    chpasswdUsers = `    - {name: root, password: '${password}', type: text}`;
  } else {
    // If custom user, create the user with sudo privileges
    usersSection += `
  - name: ${username}
    lock_passwd: false
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    homedir: /home/${username}
    createhome: true
    
  - name: root
    lock_passwd: false
    shell: /bin/bash`;
    chpasswdUsers = `    - {name: ${username}, password: '${password}', type: text}
    - {name: root, password: '${password}', type: text}`;
  }

  const config = `#cloud-config

# ================================================
# SYSTEM CONFIG
# ================================================
hostname: ${hostname}
manage_etc_hosts: true
preserve_hostname: false

# ================================================
# USERS & AUTH
# ================================================
${usersSection}

disable_root: false
ssh_pwauth: true

chpasswd:
  expire: false
  users:
${chpasswdUsers}

# ================================================
# SSH CONFIG
# ================================================
write_files:
  - path: /etc/ssh/sshd_config.d/50-cloud-init.conf
    owner: root:root
    permissions: '0644'
    content: |
      PermitRootLogin yes
      PasswordAuthentication yes

# ================================================
# NETWORKING (DHCP - Automatic)
# ================================================
# AUDIT FIX (OS template subsystem hardening - cloud-init networking):
# previously hardcoded "eth0" here. Every supported guest (Ubuntu, Debian,
# Fedora, CentOS Stream, AlmaLinux) uses systemd's predictable network
# interface naming by default, which typically yields something like
# "ens3" or "enp0s2" under QEMU/virtio - never "eth0". A hardcoded "eth0"
# match configures a device that doesn't exist, leaving the guest with no
# network. Using a match pattern instead of a fixed name means this config
# applies to whichever NIC the guest actually enumerates, regardless of
# naming scheme.
network:
  version: 2
  renderer: networkd
  ethernets:
    primary-nic:
      match:
        name: "e*"
      dhcp4: true
      dhcp6: false

# ================================================
# FINAL MESSAGE
# ================================================
final_message: |
  ✓ VM CONFIGURED - NAT (User Mode)
  Hostname: ${hostname}
  Network: DHCP (Automatic)
  SSH: Default ports with forwarding
`;

  return config;
}

// Generate Cloud-Init config for Static Public IPv4 ONLY
// Configures static IPv4 with netplan v2 - NO DHCP
function generateStaticPublicIPv4CloudInitConfig(vm) {
  const username = vm.username || 'root';
  const password = vm.password || 'password';
  const hostname = vm.hostname || 'vnm-instance';
  const ipv4_address = vm.ipv4_address || '10.0.0.100';
  const gateway = vm.gateway || vm.ipv4_gateway || '10.0.0.1';
  const netmask = vm.netmask || vm.ipv4_netmask || 24;
  const dns = (vm.dns_primary || '8.8.8.8').trim();
  const dns_secondary = (vm.dns_secondary || '8.8.4.4').trim();

  // Convert netmask to CIDR
  let cidr = netmask;
  if (typeof netmask === 'string' && netmask.includes('.')) {
    const parts = netmask.split('.');
    cidr = parts.reduce((sum, octet) => {
      return sum + parseInt(octet).toString(2).replace(/0/g, '').length;
    }, 0);
  }

  // Build users section - support root and custom users
  let usersSection = `users:`;
  // AUDIT FIX #9/#10: modern cloud-init deprecates chpasswd.list in favor of
  // chpasswd.users with an explicit type, and previously the non-root
  // account's root fallback password was hard-coded to the literal string
  // "password" instead of the VM's actual configured password, which is
  // exactly the kind of mismatch that produces "login failed even though
  // credentials were expected".
  let chpasswdUsers = ``;

  if (username.toLowerCase() === 'root') {
    // If root user, configure root directly
    usersSection += `
  - name: root
    lock_passwd: false
    shell: /bin/bash
    homedir: /root`;
    chpasswdUsers = `    - {name: root, password: '${password}', type: text}`;
  } else {
    // If custom user, create the user with sudo privileges
    usersSection += `
  - name: ${username}
    lock_passwd: false
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    homedir: /home/${username}
    createhome: true
    
  - name: root
    lock_passwd: false
    shell: /bin/bash`;
    chpasswdUsers = `    - {name: ${username}, password: '${password}', type: text}
    - {name: root, password: '${password}', type: text}`;
  }

  const config = `#cloud-config

# ================================================
# SYSTEM CONFIG
# ================================================
hostname: ${hostname}
manage_etc_hosts: true
preserve_hostname: false

# ================================================
# USERS & AUTH
# ================================================
${usersSection}

disable_root: false
ssh_pwauth: true

chpasswd:
  expire: false
  users:
${chpasswdUsers}

# ================================================
# SSH CONFIG
# ================================================
write_files:
  - path: /etc/ssh/sshd_config.d/50-cloud-init.conf
    owner: root:root
    permissions: '0644'
    content: |
      PermitRootLogin yes
      PasswordAuthentication yes

  - path: /etc/netplan/99-static.yaml
    owner: root:root
    permissions: '0600'
    content: |
      network:
        version: 2
        renderer: networkd
        ethernets:
          primary-nic:
            match:
              name: "e*"
            dhcp4: false
            dhcp6: false
            addresses:
              - ${ipv4_address}/${cidr}
            routes:
              - to: 0.0.0.0/0
                via: ${gateway}
            nameservers:
              addresses: [${dns}, ${dns_secondary}]

  - path: /usr/local/bin/apply-network.sh
    owner: root:root
    permissions: '0755'
    content: |
      #!/bin/bash
      
      {
      echo "========== VERIFYING NETWORK CONFIG =========="
      echo "Time: $(date)"
      
      # Check if netplan config exists and is correct
      echo ""
      echo "Step 1: Checking netplan config..."
      if [ ! -f /etc/netplan/99-static.yaml ]; then
        echo "✗ Netplan config not found!"
        exit 1
      fi
      
      cat /etc/netplan/99-static.yaml
      
      # Apply (skip validate - netplan v2.12+ removed validate command)
      echo ""
      echo "Step 2: Applying netplan..."
      netplan apply || {
        echo "✗ Netplan apply failed!"
        systemctl status systemd-networkd || true
        exit 1
      }
      echo "✓ Netplan applied"
      
      sleep 2
      
      # Show final state
      echo ""
      echo "Step 3: Interface state AFTER netplan apply:"
      ip addr show
      ip route show
      
      echo ""
      echo "========== NETWORK CONFIG VERIFIED =========="
      } 2>&1 | tee /var/log/apply-network.log

# ================================================
# DISABLE WAIT-ONLINE + APPLY CONFIG
# ================================================
runcmd:
  - systemctl mask systemd-networkd-wait-online.service
  - systemctl mask systemd-network-online.target
  - bash /usr/local/bin/apply-network.sh

# ================================================
# FINAL MESSAGE
# ================================================
final_message: |
  ✓ VM CONFIGURED - Static IPv4
  IP: ${ipv4_address}/${cidr}
  Gateway: ${gateway}
  Hostname: ${hostname}
`;

  return config;
}

// Generate random MAC address
function generateMACAddress() {
  return 'fa:16:3e:' + [0, 1, 2].map(() => {
    return Math.floor(Math.random() * 256).toString(16).padStart(2, '0');
  }).join(':');
}

/**
 * Validate static IPv4 configuration
 * Returns {valid: boolean, error: string|null}
 */
function validateStaticIPv4Config(vm) {
  // Check required fields
  if (!vm.network_type || vm.network_type !== 'static_public') {
    return { valid: false, error: 'Network type must be static_public' };
  }
  
  if (!vm.ipv4_address) {
    return { valid: false, error: 'IPv4 address is required' };
  }
  
  // Validate IPv4 address format (basic check)
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(vm.ipv4_address)) {
    return { valid: false, error: `Invalid IPv4 address format: ${vm.ipv4_address}` };
  }
  
  // Validate each octet is 0-255
  const octets = vm.ipv4_address.split('.');
  for (const octet of octets) {
    const num = parseInt(octet);
    if (isNaN(num) || num < 0 || num > 255) {
      return { valid: false, error: `IPv4 octet out of range: ${octet}` };
    }
  }
  
  // Validate gateway
  const gateway = vm.gateway || vm.ipv4_gateway;
  if (gateway) {
    if (!ipv4Regex.test(gateway)) {
      return { valid: false, error: `Invalid gateway IPv4 format: ${gateway}` };
    }
    const gwOctets = gateway.split('.');
    for (const octet of gwOctets) {
      const num = parseInt(octet);
      if (isNaN(num) || num < 0 || num > 255) {
        return { valid: false, error: `Gateway octet out of range: ${octet}` };
      }
    }
  } else {
    return { valid: false, error: 'Gateway is required for static IPv4' };
  }
  
  // Validate netmask/CIDR
  let cidr = vm.netmask || vm.ipv4_netmask || 24;
  let cidrNum = parseInt(cidr);
  
  // If it contains dots, it's a dotted-decimal mask
  if (cidr.toString().includes('.')) {
    const parts = cidr.split('.');
    if (parts.length !== 4) {
      return { valid: false, error: 'Invalid netmask format' };
    }
    // Convert to CIDR to validate
    cidrNum = parts.reduce((sum, octet) => {
      const num = parseInt(octet);
      if (isNaN(num) || num < 0 || num > 255) {
        return -1;
      }
      return sum + num.toString(2).replace(/0/g, '').length;
    }, 0);
  }
  
  if (isNaN(cidrNum) || cidrNum < 1 || cidrNum > 32) {
    return { valid: false, error: `Invalid CIDR range: ${cidr} (must be 1-32)` };
  }
  
  // Validate DNS servers
  const dnsServers = (vm.dns_servers || vm.dns_primary || '8.8.8.8').split(',');
  for (const dns of dnsServers) {
    const cleanDns = dns.trim();
    if (cleanDns && !ipv4Regex.test(cleanDns)) {
      return { valid: false, error: `Invalid DNS server IP format: ${cleanDns}` };
    }
  }
  
  // Validate bridge device (if provided)
  if (vm.bridge_device && typeof vm.bridge_device === 'string') {
    if (!/^[a-z0-9]+$/.test(vm.bridge_device)) {
      return { valid: false, error: `Invalid bridge device name: ${vm.bridge_device}` };
    }
  }
  
  return { valid: true, error: null };
}

/**
 * Create Cloud-Init seed ISO with proper netplan v2 configuration
 * Includes meta-data, user-data, and network-config in correct format
 * Validates YAML syntax before creating ISO
 */
async function createCloudInitSeed(vm_id, vm) {
  return new Promise((resolve, reject) => {
    try {
      // Validate static IPv4 configuration if applicable
      if (vm.network_type === 'static_public') {
        const validation = validateStaticIPv4Config(vm);
        if (!validation.valid) {
          console.error(`[CLOUDINIT-${vm_id}] ✗ Validation Error: ${validation.error}`);
          return reject(new Error(`Static IPv4 validation failed: ${validation.error}`));
        }
        console.log(`[CLOUDINIT-${vm_id}] ✓ Static IPv4 configuration validated`);
      }
      
      const seedDir = path.join(VM_DIR, `vm-${vm_id}-seed-dir`);
      const seedIso = path.join(VM_DIR, `vm-${vm_id}-seed.iso`);
      const metaDataFile = path.join(seedDir, 'meta-data');
      const userDataFile = path.join(seedDir, 'user-data');
      const networkConfigFile = path.join(seedDir, 'network-config');

      // Clean up and create seed directory
      if (fs.existsSync(seedDir)) {
        fs.rmSync(seedDir, { recursive: true, force: true });
      }
      fs.mkdirSync(seedDir, { recursive: true });

      // Meta-data + user-data content comes from the shared generator
      // (also used for VMs provisioned on remote nodes).
      const { metaData, userData } = buildCloudInitFiles(vm, vm_id);
      if (vm.network_type === 'nat') {
        console.log(`[CLOUDINIT-${vm_id}] Using NAT (User Mode) configuration`);
      } else {
        console.log(`[CLOUDINIT-${vm_id}] Using Static Public IPv4 configuration`);
      }

      // Validate cloud-init YAML before writing
      console.log(`[CLOUDINIT-${vm_id}] Validating cloud-init configuration...`);
      
      // Basic YAML validation - check for common issues
      const validateCloudInitConfig = (config) => {
        const errors = [];
        
        // Check if it starts with #cloud-config
        if (!config.startsWith('#cloud-config')) {
          errors.push('Must start with #cloud-config');
        }
        
        // Check for proper indentation (2 spaces)
        const lines = config.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          // Check tab characters (bad in YAML)
          if (line.includes('\t')) {
            errors.push(`Line ${i + 1}: Contains tab character (use spaces instead)`);
          }
          // Check indentation is multiple of 2
          const indent = line.match(/^ */)[0].length;
          if (indent > 0 && indent % 2 !== 0) {
            errors.push(`Line ${i + 1}: Invalid indentation (must be multiple of 2)`);
          }
        }
        
        return errors;
      };
      
      const validationErrors = validateCloudInitConfig(userData);
      if (validationErrors.length > 0) {
        console.warn(`[CLOUDINIT-${vm_id}] ⚠ Configuration warnings:`);
        validationErrors.forEach(err => console.warn(`  - ${err}`));
      } else {
        console.log(`[CLOUDINIT-${vm_id}] ✓ Cloud-init configuration is valid`);
      }

      // Write configuration files - only meta-data and user-data (no network-config)
      fs.writeFileSync(metaDataFile, metaData, 'utf8');
      fs.writeFileSync(userDataFile, userData, 'utf8');
      // networkConfigFile is no longer written

      console.log(`[CLOUDINIT-${vm_id}] ✓ Configuration files written`);
      console.log(`[CLOUDINIT-${vm_id}] - meta-data: ${(metaData.length / 1024).toFixed(2)}KB`);
      console.log(`[CLOUDINIT-${vm_id}] - user-data: ${(userData.length / 1024).toFixed(2)}KB`);
      console.log(`[CLOUDINIT-${vm_id}] ✓ Using embedded netplan config (no separate network-config file)`);

      // Create ISO from seed files.
      // AUDIT FIX #9: detect the tool up front (detectIsoTool caches the
      // result) instead of blindly try/catching each command in sequence,
      // which could misreport a tool as "missing" when it was actually a
      // transient failure, and never considered cloud-localds or xorriso
      // even when they were installed.
      try {
        const tool = detectIsoTool();
        if (!tool) {
          const err = new Error('No ISO creation tool available - install one of: cloud-localds (cloud-utils), genisoimage, xorriso, mkisofs');
          console.error(`[CLOUDINIT-${vm_id}] ✗ ${err.message}`);
          logError('CLOUDINIT', vm_id, 'ISO creation', err);
          return reject(err);
        }

        let isoCommand;
        if (tool === 'cloud-localds') {
          // cloud-localds takes user-data/meta-data directly, not a directory
          isoCommand = `cloud-localds -v "${seedIso}" "${userDataFile}" "${metaDataFile}"`;
        } else if (tool === 'xorriso') {
          isoCommand = `xorriso -as genisoimage -output "${seedIso}" -volid cidata -joliet -rock "${seedDir}"`;
        } else if (tool === 'genisoimage') {
          isoCommand = `genisoimage -output "${seedIso}" -volid cidata -joliet -rock "${seedDir}"`;
        } else {
          // mkisofs (Linux or Windows)
          isoCommand = `mkisofs -output "${seedIso}" -volid cidata -joliet -rock "${seedDir}"`;
        }

        console.log(`[CLOUDINIT-${vm_id}] Using ISO tool: ${tool}`);
        execSync(isoCommand, { stdio: 'pipe', shell: isWindows ? 'cmd' : '/bin/bash' });

        console.log(`[CLOUDINIT-${vm_id}] ✓ ISO seed created: ${seedIso}`);

        // Verify the ISO was actually created and is non-trivially sized -
        // a 0-byte or missing file here previously surfaced only much later
        // as a confusing QEMU boot failure.
        if (fs.existsSync(seedIso) && fs.statSync(seedIso).size > 0) {
          const size = fs.statSync(seedIso).size;
          console.log(`[CLOUDINIT-${vm_id}] ✓ ISO size: ${(size / 1024).toFixed(2)}KB`);

          // Clean up seed directory after successful ISO creation
          try {
            fs.rmSync(seedDir, { recursive: true, force: true });
            console.log(`[CLOUDINIT-${vm_id}] ✓ Seed directory cleaned up`);
          } catch (e) {
            console.warn(`[CLOUDINIT-${vm_id}] ⚠ Could not clean seed directory`);
          }

          resolve(true);
        } else {
          throw new Error('ISO file not created or empty');
        }
      } catch (isoError) {
        console.error(`[CLOUDINIT-${vm_id}] ✗ ISO creation failed: ${isoError.message}`);
        logError('CLOUDINIT', vm_id, 'ISO creation', isoError);
        reject(new Error(`Cloud-init ISO creation failed: ${isoError.message}`));
      }
    } catch (error) {
      console.error(`[CLOUDINIT-${vm_id}] Error: ${error.message}`);
      console.error(`[CLOUDINIT-${vm_id}] Stack: ${error.stack}`);
      reject(error);
    }
  });
}

// Build the cloud-init seed CONTENT for a VM (meta-data + user-data).
// Used by createCloudInitSeed() for local VMs and sent verbatim to a
// remote node's agent at creation/edit time (vm.provision / vm.createSeed),
// so a VM created on a remote node gets byte-for-byte the same guest
// configuration - users, passwords, SSH config, networking - as a local
// one. One generator, two destinations.
function buildCloudInitFiles(vm, vm_id) {
  const metaData = `instance-id: vm-${vm_id}
local-hostname: ${vm.hostname || vm.vm_name || ('vm-' + vm_id)}
`;
  const userData = vm.network_type === 'nat'
    ? generateNATCloudInitConfig(vm)
    : generateStaticPublicIPv4CloudInitConfig(vm);
  return { metaData, userData };
}

// Cache the KVM-availability check (it doesn't change while the panel runs)
// so we don't hit the filesystem on every VM start.
let _kvmAvailableCache = null;
function isKvmAvailable() {
  if (_kvmAvailableCache !== null) return _kvmAvailableCache;
  try {
    fs.accessSync('/dev/kvm', fs.constants.R_OK | fs.constants.W_OK);
    _kvmAvailableCache = true;
  } catch (e) {
    _kvmAvailableCache = false;
    console.warn('[KVM] /dev/kvm not accessible - falling back to software emulation (tcg) for VMs with KVM enabled:', e.message);
  }
  return _kvmAvailableCache;
}

async function startQemuVM(vm) {
  return new Promise(async (resolve, reject) => {
    try {
      const pidFile = path.join(VM_DIR, `vm-${vm.vm_id}.pid`);
      const logFile = path.join(VM_DIR, `vm-${vm.vm_id}.log`);
      
      // Resolve acceleration FIRST (BUG FIX: VMs failed to start on hosts
      // without KVM). Which CPU models are legal depends on it: 'host'
      // requires KVM or HVF, so under TCG it must never reach QEMU.
      const kvmRequested = vm.enable_kvm === undefined || vm.enable_kvm === null || !!vm.enable_kvm;
      const kvmUsable = kvmRequested && isKvmAvailable();
      if (kvmRequested && !kvmUsable) {
        console.warn(`[VM-${vm.vm_id}] KVM requested but /dev/kvm is unavailable on this host - starting with software emulation (tcg) instead of failing to boot`);
      }

      // Validate CPU model - fallback to 'host' if model not available
      let cpuToUse = 'host';
      let cpuConfigured = null; // what the VM is configured with; logged with the effective model below
      if (vm.custom_cpu_name) {
        // Custom CPU name + CPU model - use both for full flexibility
        // Format: -cpu <cpu_model>,model-id=Custom Name
        // Note: No quotes needed when using spawn() array format
        let baseCpuModel = 'host';
        if (vm.cpu_model && CPU_MODELS[vm.cpu_model]) {
          baseCpuModel = vm.cpu_model;
        }
        // Base goes to QEMU by its real model name (features), not the
        // UI key - same fix as the preset branch.
        const baseQemuModel = (CPU_MODELS[baseCpuModel] && CPU_MODELS[baseCpuModel].features) || baseCpuModel;
        cpuToUse = `${baseQemuModel},model-id=${vm.custom_cpu_name}`;
        cpuConfigured = `'${baseCpuModel}' + custom name '${vm.custom_cpu_name}'`;
        console.log(`[VM-${vm.vm_id}] Using custom CPU: ${vm.custom_cpu_name} (base: ${baseCpuModel}, QEMU model: ${baseQemuModel})`);
      } else if (vm.cpu_model && CPU_MODELS[vm.cpu_model]) {
        // Pass the REAL QEMU model name, not the UI key ('skylake' is not
        // a QEMU model; 'Skylake-Client' is). Real QEMU exits at startup
        // on unknown models, so the key must never reach -cpu.
        cpuToUse = CPU_MODELS[vm.cpu_model].features || vm.cpu_model;
        cpuConfigured = `'${vm.cpu_model}' (preset)`;
        console.log(`[VM-${vm.vm_id}] Using preset CPU: ${vm.cpu_model} (QEMU model: ${cpuToUse})`);
      } else if (vm.cpu_model) {
        console.warn(`[VM-${vm.vm_id}] CPU model '${vm.cpu_model}' not found, falling back to 'host'`);
        cpuToUse = 'host';
        cpuConfigured = `'${vm.cpu_model}' (unknown preset) -> 'host'`;
        // Also update the database to fix the VM's CPU model
        db.run(`UPDATE vms SET cpu_model = 'host' WHERE vm_id = ?`, [vm.vm_id], (err) => {
          if (!err) console.log(`[VM-${vm.vm_id}] Updated database: cpu_model -> 'host'`);
        });
      } else {
        // Nothing configured at all: the panel's historical default is 'host'
        cpuConfigured = `'host' (panel default)`;
      }

      // BUG FIX (startQemuVM, "CPU model 'host' requires KVM or HVF"):
      // 'host' - the panel default, the 'host' preset and the implicit base
      // of custom CPU configs - requires KVM or HVF. On a host without
      // usable /dev/kvm the panel already fell back to TCG, but it still
      // passed '-cpu host', so QEMU exited with code 1 before the VM ever
      // booted. Under TCG, substitute the TCG-compatible 'max' model
      // (every feature software emulation can provide), preserving any
      // ',model-id=...' suffix so custom CPU display names survive.
      // The stored setting is NOT modified: if KVM becomes usable later
      // (or the VM moves to a KVM host), 'host' is used again as configured.
      if (!kvmUsable) {
        const firstComma = cpuToUse.indexOf(',');
        const cpuBase = (firstComma === -1 ? cpuToUse : cpuToUse.slice(0, firstComma)).trim();
        const cpuSuffix = firstComma === -1 ? '' : cpuToUse.slice(firstComma);
        if (cpuBase.toLowerCase() === 'host') {
          console.warn(`[VM-${vm.vm_id}] CPU model 'host' requires KVM or HVF, which is unavailable - substituting 'max' for TCG software emulation (stored CPU setting preserved)`);
          cpuToUse = `max${cpuSuffix}`;
        }
      }
      console.log(`[VM-${vm.vm_id}] Acceleration: ${kvmUsable ? 'kvm' : 'tcg (software emulation)'}`);
      console.log(`[VM-${vm.vm_id}] Effective CPU model (-cpu): ${cpuToUse}` + (cpuConfigured ? ` [configured: ${cpuConfigured}]` : ''));

      // Build QEMU command line as array (safer than string concatenation)
      const args = [
        `-m`, `${vm.memory}`,
        `-smp`, `cores=${vm.cpu_cores},threads=${vm.cpu_threads},sockets=${vm.cpu_sockets}`,
        `-cpu`, cpuToUse,
        `-name`, `vm-${vm.vm_id}`,
        // accel=kvm:tcg only makes sense (and only reliably works) when KVM is
        // actually usable; otherwise ask QEMU for tcg outright so it doesn't
        // try and fail to fall back on a host with no /dev/kvm.
        `-machine`, `${vm.machine_type || 'pc'},accel=${kvmUsable ? 'kvm:tcg' : 'tcg'}`,
        `-nographic`
      ];
      if (kvmUsable) {
        args.push(`-enable-kvm`);
      }
      
      // SMBIOS Configuration
      const smbiosManufacturer = vm.smbios_manufacturer || vm.custom_smbios_manufacturer || 'QEMU';
      const smbiosaProduct = vm.smbios_product || 'KVM Virtual Machine';
      const smbiosaVersion = vm.smbios_version || '1.0';
      const smbiosaSerial = vm.smbios_serial || `vm-${vm.vm_id}`;
      const boardName = vm.board_name || 'Main-Board';
      
      args.push(`-smbios`, `type=0,vendor=${smbiosManufacturer},version=${smbiosaVersion}`);
      args.push(`-smbios`, `type=1,manufacturer=${smbiosManufacturer},product=${smbiosaProduct},version=${smbiosaVersion},serial=${smbiosaSerial}`);
      args.push(`-smbios`, `type=2,manufacturer=${smbiosManufacturer},product=${boardName},version=${smbiosaVersion}`);
      
      console.log(`[VM-${vm.vm_id}] SMBIOS Config:`);
      console.log(`[VM-${vm.vm_id}]   Manufacturer: ${smbiosManufacturer}`);
      console.log(`[VM-${vm.vm_id}]   Product: ${smbiosaProduct}`);
      console.log(`[VM-${vm.vm_id}]   Board: ${boardName}`);
      console.log(`[VM-${vm.vm_id}]   Serial: ${smbiosaSerial}`);
      
      // ACPI configuration
      if (vm.enable_acpi === 0) {
        args.push(`-no-acpi`);
      }
      
      // Boot settings - check if ISO should boot first or disk
      if (vm.boot_from_iso && vm.iso_attached) {
        // Boot from ISO first, then fall back to disk
        args.push(`-boot`, `order=d,menu=off`);  // d = CDROM, then fallback
        console.log(`[VM-${vm.vm_id}] Boot Order: ISO (${vm.iso_attached}) → Disk`);
      } else {
        // Boot from HDD/disk only
        args.push(`-boot`, `c`);
        console.log(`[VM-${vm.vm_id}] Boot Order: Disk only`);
      }
      
      // Disable floppy device completely to avoid fd0 errors
      args.push(`-drive`, `if=floppy,index=-1`);
      
      // Drives - root disk
      // Always use disk_file for root filesystem (allows resizing)
      args.push(`-drive`, `file=${vm.disk_file},format=qcow2,if=virtio,media=disk`);
      
      // ISO media (if attached) - CD/DVD drive
      if (vm.iso_attached) {
        const isoBasename = path.basename(vm.iso_attached);
        const isoPath = path.join(ISO_DIR, isoBasename);
        if (fs.existsSync(isoPath)) {
          args.push(`-drive`, `file=${isoPath},format=raw,media=cdrom,if=ide,index=0`);
          console.log(`[VM-${vm.vm_id}] ISO Media Attached: ${vm.iso_attached}`);
        } else {
          console.warn(`[VM-${vm.vm_id}] ISO file not found: ${vm.iso_attached}`);
        }
      }
      
      // Cloud-init seed disk (CD-ROM) - MUST have for cloud-init to work
      const seedIso = path.join(VM_DIR, `vm-${vm.vm_id}-seed.iso`);
      if (fs.existsSync(seedIso)) {
        args.push(`-drive`, `file=${seedIso},format=raw,media=cdrom,if=ide,index=1`);
      }
      
      // Network Configuration - Support both NAT and Static IPv4
      const netdevId = 'n0';
      const macAddress = vm.mac_address || generateMACAddress();
      const nicModel = NIC_MODELS.includes(vm.nic_model) ? vm.nic_model : 'virtio-net-pci';
      
      if (vm.network_type === 'nat') {
        // NAT (User Mode) Network with SSH port forwarding only
        const sshPort = getSSHPort(vm);
        
        // Add the network device - NIC model is selectable per VM
        args.push(`-device`, `${nicModel},netdev=${netdevId},mac=${macAddress}`);
        
        // Add user-mode network with SSH port forwarding (+ RDP forward
        // when enabled) plus this VM's custom port-forward rules.
        const rdpForward = await rdp.getStartForward(vm);
        const customForwards = await getPortForwards(vm.vm_id);
        const extraForwards = customForwards
          .map(pf => `,hostfwd=${pf.protocol}::${pf.host_port}-:${pf.guest_port}`)
          .join('');
        args.push(`-netdev`, `user,id=${netdevId},hostfwd=tcp::${sshPort}-:22${rdpForward}${extraForwards}`);
        if (customForwards.length) {
          console.log(`[VM-${vm.vm_id}] Custom port forwards: ${customForwards.map(pf => `${pf.protocol} ${pf.host_port}->${pf.guest_port}${pf.label ? ' (' + pf.label + ')' : ''}`).join(', ')}`);
        }

        // QEMU monitor on a private unix socket so an RDP forward can be
        // hot-added to this VM later without a reboot (rdp.js). Independent
        // of the serial console (-serial mon:stdio below), which is unchanged.
        try {
          const hmpSock = rdp.hmpPath(vm.vm_id);
          try { fs.unlinkSync(hmpSock); } catch (e) { /* no stale socket */ }
          args.push(`-monitor`, `unix:${hmpSock},server,nowait`);
        } catch (e) {
          console.warn(`[VM-${vm.vm_id}] Could not configure QEMU monitor socket: ${e.message}`);
        }
        if (rdpForward) console.log(`[VM-${vm.vm_id}] RDP Port Forwarding: ${rdpForward.replace(',hostfwd=tcp::', 'host:')} (xrdp)`);
        
        console.log(`[VM-${vm.vm_id}] Network: NAT (User Mode) with SSH Port Forwarding`);
        console.log(`[VM-${vm.vm_id}] QEMU Command:`);
        console.log(`[VM-${vm.vm_id}]   -device ${nicModel},netdev=${netdevId},mac=${macAddress}`);
        console.log(`[VM-${vm.vm_id}]   -netdev user,id=${netdevId},hostfwd=tcp::${sshPort}-:22${extraForwards}`);
        console.log(`[VM-${vm.vm_id}] SSH Port Forwarding: localhost:${sshPort} → VM:22`);
        console.log(`[VM-${vm.vm_id}] MAC Address: ${macAddress}`);
      } else {
        // Static Public IPv4 - Bridge Mode
        const bridgeDevice = vm.bridge_device || 'vmbr0';
        const dnsServers = vm.dns_servers || '8.8.8.8,8.8.4.4';
        
        // Add network device
        args.push(`-device`, `${nicModel},netdev=${netdevId},mac=${macAddress}`);
        
        // Add bridge network interface
        args.push(`-netdev`, `bridge,id=${netdevId},br=${bridgeDevice}`);
        
        console.log(`[VM-${vm.vm_id}] Network: Static Public IPv4 (Bridge Mode)`);
        console.log(`[VM-${vm.vm_id}] QEMU Command:`);
        console.log(`[VM-${vm.vm_id}]   -device ${nicModel},netdev=${netdevId},mac=${macAddress}`);
        console.log(`[VM-${vm.vm_id}]   -netdev bridge,id=${netdevId},br=${bridgeDevice}`);
        console.log(`[VM-${vm.vm_id}] Bridge Device: ${bridgeDevice}`);
        console.log(`[VM-${vm.vm_id}] Configured Static IP: ${vm.ipv4_address}/${vm.netmask}`);
        console.log(`[VM-${vm.vm_id}] Gateway: ${vm.gateway}`);
        console.log(`[VM-${vm.vm_id}] DNS: ${dnsServers}`);
        console.log(`[VM-${vm.vm_id}] MAC Address: ${macAddress}`);
      }
      
      // Serial console with monitor support - stdin/stdout for direct terminal access
      args.push(`-serial`, `mon:stdio`);

      // Graphical VNC display for the noVNC console option, localhost-only
      // - reached exclusively through the /vnc-console WebSocket relay,
      // never exposed on its own. Runs independently of -serial mon:stdio
      // above (that's the "VNM Built-in Console"); a VM offers both.
      let vncDisplay = null;
      try {
        vncDisplay = await allocateLocalVncDisplay();
        args.push(`-vnc`, `127.0.0.1:${vncDisplay}`);
        console.log(`[VM-${vm.vm_id}] VNC console: 127.0.0.1:${5900 + vncDisplay} (display :${vncDisplay})`);
      } catch (e) {
        console.warn(`[VM-${vm.vm_id}] VNC display allocation failed: ${e.message} (starting without a graphical console)`);
      }
      
      // Extra arguments if provided - split into individual argv entries
      // (spawn() with an args array does NOT re-parse a single string,
      // so pushing the whole string as one item broke multi-flag extra_args)
      if (vm.extra_args && vm.extra_args.trim()) {
        const extraArgTokens = vm.extra_args.match(/"[^"]*"|'[^']*'|\S+/g) || [];
        extraArgTokens.forEach(tok => {
          // Strip matching surrounding quotes
          const unquoted = tok.replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1');
          args.push(unquoted);
        });
      }

      console.log(`[VM-${vm.vm_id}] CPU Config: ${vm.cpu_sockets} sockets x ${vm.cpu_cores} cores x ${vm.cpu_threads} threads = ${vm.cpus} total`);
      const cpuDisplayName = vm.custom_cpu_name || vm.cpu_model || 'host';
      console.log(`[VM-${vm.vm_id}] CPU Model (configured): ${cpuDisplayName} | Effective for QEMU (-cpu): ${cpuToUse} | Acceleration: ${kvmUsable ? 'kvm' : 'tcg'}`);
      console.log(`[VM-${vm.vm_id}] SMBIOS: ${vm.smbios_manufacturer} ${vm.smbios_product} (${vm.smbios_serial})`);
      console.log(`[VM-${vm.vm_id}] Network Mode: ${vm.network_type === 'nat' ? 'NAT (User Mode)' : 'Static Public IPv4'}`);
      if (vm.network_type !== 'nat') {
        console.log(`[VM-${vm.vm_id}] IPv4 Address: ${vm.ipv4_address}`);
      }
      console.log(`[VM-${vm.vm_id}] Template: ${vm.template_type} (${vm.os_type})`);
      console.log(`[VM-${vm.vm_id}] Starting: ${vm.vm_name}`);
      console.log(`[VM-${vm.vm_id}] Image File: ${vm.img_file}`);
      console.log(`[VM-${vm.vm_id}] Console: Direct terminal access via -nographic -serial mon:stdio`);

      // AUDIT FIX #3: resolve an actual QEMU binary up front instead of
      // hard-coding 'qemu-system-x86_64' and discovering it's missing only
      // via an opaque ENOENT deep inside spawn().
      const qemuBin = resolveQemuBinary();
      if (!qemuBin) {
        if (typeof vncDisplay === 'number') _localVncDisplays.delete(vncDisplay);
        const err = new Error(
          "QEMU binary not found (checked QEMU_BIN env, 'qemu-system-x86_64', /usr/bin/qemu-system-x86_64, /usr/libexec/qemu-kvm). " +
          "Install qemu-system-x86 (or qemu-kvm) or set QEMU_BIN to the correct path."
        );
        logError('QEMU', vm.vm_id, 'binary-detection', err);
        return reject(err);
      }

      // Use spawn for background process execution
      const qemuProcess = spawn(qemuBin, args, {
        stdio: ['pipe', 'pipe', 'pipe'],  // stdin: pipe (for console input), stdout: pipe, stderr: pipe
        detached: true,  // Let process run independently
        shell: false
      });
      
      // QEMU monitor socket (used only by rdp.js) -> owner-only permissions
      if (qemuProcess.pid && vm.network_type === 'nat') rdp.secureMonitor(vm.vm_id);

      // Store stdin for console input
      qemuStdins.set(String(vm.vm_id), qemuProcess.stdin);
      qemuProcess.stdin.on('error', (err) => {
        console.error(`[VM-${vm.vm_id}] stdin error:`, err.message);
      });

      const pid = qemuProcess.pid;

      // AUDIT FIX #4: root cause of "TypeError: Cannot read properties of
      // undefined (reading 'toString')" was exactly this line - if spawn()
      // fails synchronously (or the binary vanished between the check above
      // and now), qemuProcess.pid is undefined and calling .toString() on it
      // threw before the 'error' event listener below ever got a chance to
      // reject cleanly. Guard it and let the error/exit handlers do their job.
      if (!pid) {
        if (typeof vncDisplay === 'number') _localVncDisplays.delete(vncDisplay);
        const err = new Error(`Failed to start VM: spawn() did not return a PID for ${qemuBin}`);
        logError('QEMU', vm.vm_id, 'spawn', err);
        return reject(err);
      }
      
      // Save PID to file for later management
      fs.writeFileSync(pidFile, pid.toString());
      console.log(`[VM-${vm.vm_id}] ✓ Started with PID: ${pid}`);

      if (typeof vncDisplay === 'number') {
        try {
          fs.writeFileSync(localVncInfoPath(vm.vm_id), JSON.stringify({ display: vncDisplay, port: VNC_BASE_PORT + vncDisplay, qemuPid: pid }));
        } catch (e) { console.warn(`[VM-${vm.vm_id}] Could not write VNC sidecar file: ${e.message}`); }
      }
      
      // Keep the most recent QEMU startup stderr so an immediate failure
      // can be reported with the actual reason ("CPU model 'host'
      // requires KVM or HVF" etc.) instead of a bare exit code.
      let startupOutputTail = '';
      const noteStartupOutput = (data) => {
        startupOutputTail = (startupOutputTail + data.toString());
        if (startupOutputTail.length > 8000) startupOutputTail = startupOutputTail.slice(-4000);
      };

      // Capture QEMU output to log file with rotation
      const rotateLogIfNeeded = () => {
        if (fs.existsSync(logFile)) {
          const stat = fs.statSync(logFile);
          if (stat.size > 10 * 1024 * 1024) {  // 10MB
            const backupFile = `${logFile}.${Date.now()}.bak`;
            fs.renameSync(logFile, backupFile);
            console.log(`[VM-${vm.vm_id}] Log rotated: ${backupFile}`);
          }
        }
      };
      
      if (qemuProcess.stdout) {
        qemuProcess.stdout.on('data', (data) => {
          rotateLogIfNeeded();
          try {
            fs.appendFileSync(logFile, data.toString());
          } catch (writeErr) {
            // AUDIT FIX (#13 - deep error audit): a full disk or permission
            // problem here previously threw inside a stream 'data' handler,
            // which Node does not route through the stream's own error
            // handling - it becomes an uncaught exception. Log once per
            // occurrence and keep the VM running; losing a log line is far
            // better than crashing the panel over it.
            console.error(`[VM-${vm.vm_id}] Failed to write to log file: ${writeErr.message}`);
          }
        });
        // A pipe can itself emit 'error' (e.g. EPIPE if the underlying fd
        // closes unexpectedly). Without a listener this is an unhandled
        // 'error' event, which Node treats as fatal.
        qemuProcess.stdout.on('error', (err) => {
          console.error(`[VM-${vm.vm_id}] stdout stream error: ${err.message}`);
        });
      }
      
      if (qemuProcess.stderr) {
        qemuProcess.stderr.on('data', (data) => {
          rotateLogIfNeeded();
          noteStartupOutput(data);
          try {
            fs.appendFileSync(logFile, data.toString());
          } catch (writeErr) {
            console.error(`[VM-${vm.vm_id}] Failed to write to log file: ${writeErr.message}`);
          }
        });
        qemuProcess.stderr.on('error', (err) => {
          console.error(`[VM-${vm.vm_id}] stderr stream error: ${err.message}`);
        });
      }
      
      // Track whether we've already settled the promise, since both the
      // early-failure path below and this listener can fire.
      let settled = false;

      // Handle process exit
      qemuProcess.on('exit', (code, signal) => {
        console.log(`[VM-${vm.vm_id}] Process exited with code ${code}, signal ${signal}`);
        qemuStdins.delete(String(vm.vm_id));
        vmProcesses.delete(vm.vm_id);
        try {
          fs.unlinkSync(pidFile);
        } catch (e) {}
        // Release the VNC display slot on ANY exit, not just a startup
        // failure - a crash long after a healthy start (the common case
        // in practice) used to leave the slot marked occupied forever,
        // since the only other release paths were an explicit Stop and a
        // lazy check the next time someone happened to open that VM's
        // console. Repeated crashes without either of those happening
        // could exhaust all 200 slots ("No free VNC display slots").
        releaseLocalVncDisplay(vm.vm_id);
        // Honest state (BUG FIX): if QEMU is gone, the VM is NOT running,
        // whatever the DB still claims. Previously a crash after a healthy
        // start left status='running' forever, so the RDP preflight and
        // every other feature kept trying to reach a VM that did not
        // exist and surfaced it as a confusing SSH failure instead.
        db.run(`UPDATE vms SET status = 'stopped' WHERE vm_id = ? AND status = 'running'`, [vm.vm_id], (err) => {
          if (!err) console.log(`[VM-${vm.vm_id}] QEMU process gone - marked VM stopped in database`);
        });
        // If QEMU exits (crashes) within the startup grace window, don't let
        // the API report success for a VM that never actually came up.
        if (!settled) {
          settled = true;
          // Surface QEMU's own diagnostic - the line that says WHY it died
          // (e.g. "qemu-system-x86_64: CPU model 'host' requires KVM or
          // HVF") - instead of a bare exit code the admin had to dig for.
          const startupReason = (() => {
            const pickReason = (text) => {
              const lines = String(text || '').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
              for (let i = lines.length - 1; i >= 0; i--) {
                if (/qemu|error|failed|could not|requires|invalid|cannot|denied|not found|no such/i.test(lines[i])) return lines[i];
              }
              return lines.slice(-2).join(' | ');
            };
            let reason = pickReason(startupOutputTail);
            if (!reason) {
              try {
                reason = pickReason(fs.readFileSync(logFile, 'utf8').split(/\r?\n/).slice(-40).join('\n'));
              } catch (e) { /* no log file yet */ }
            }
            return reason;
          })();
          reject(new Error(
            `QEMU exited immediately (code ${code}, signal ${signal})` +
            (startupReason ? ` - ${startupReason}` : ' - check the VM log for details')
          ));
        }
      });
      qemuProcess.on('error', (err) => {
        console.error(`[VM-${vm.vm_id}] Process error: ${err.message}`);
        logError('QEMU', vm.vm_id, 'startup', err);
        releaseLocalVncDisplay(vm.vm_id);
        if (!settled) {
          settled = true;
          reject(new Error(`Failed to start VM: ${err.message}`));
        }
      });

      // Give QEMU a brief grace period to fail fast (missing binary, bad
      // args, immediate crash) before telling the caller it's running.
      // A real, healthy QEMU process will still be alive after this delay.
      setTimeout(() => {
        if (settled) return; // already rejected via exit/error above
        settled = true;
        resolve({ pid, success: true });
      }, 1000);
    } catch (error) {
      logError('QEMU', vm.vm_id, 'initialization', error);
      reject(new Error(`Failed to start VM: ${error.message}`));
    }
  });
}

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Redirect / to dashboard or login
app.get('/', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.redirect('/login');
});

// ============= SETTINGS ROUTES =============

// Get all settings (no auth required for reading defaults)
app.get('/api/settings', (req, res) => {
  db.all(`SELECT setting_key, setting_value FROM settings`, (err, rows) => {
    if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
    
    const settings = {
      panel_version: 'V3.0',
      panel_title: 'VNM Panel V3.0',
      panel_description: 'Professional VM Management Panel',
      site_icon_url: '/images/logo-new.svg',
      session_timeout: 24,
      max_sessions: 10
    };

    // Override with DB values
    if (rows && rows.length > 0) {
      rows.forEach(row => {
        settings[row.setting_key] = row.setting_value;
      });
    }

    res.json(settings);
  });
});

// Update setting (admin only)
app.post('/api/settings/:key', checkAuth, checkAdmin, (req, res) => {
  const { key } = req.params;
  const { value } = req.body;

  if (value === null || value === undefined) {
    return res.status(400).json({ error: 'Value required' });
  }

  db.run(
    `INSERT OR REPLACE INTO settings (setting_key, setting_value, updated_at) VALUES (?, ?, datetime('now'))`,
    [key, String(value)],
    (err) => {
      if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
      res.json({ success: true, key, value });
    }
  );
});

// Update multiple settings (admin only)
app.put('/api/settings', checkAuth, checkAdmin, (req, res) => {
  const settings = req.body;
  let completed = 0;
  const total = Object.keys(settings).length;
  const errors = [];

  if (total === 0) {
    return res.status(400).json({ error: 'No settings provided' });
  }

  Object.entries(settings).forEach(([key, value]) => {
    db.run(
      `INSERT OR REPLACE INTO settings (setting_key, setting_value, updated_at) VALUES (?, ?, datetime('now'))`,
      [key, String(value)],
      (err) => {
        completed++;
        if (err) {
          errors.push({ key, error: err.message });
        }
        
        if (completed === total) {
          if (errors.length > 0) {
            res.status(500).json({ success: false, errors, saved: total - errors.length });
          } else {
            res.json({ success: true, saved: total });
          }
        }
      }
    );
  });
});

// ============= DISCORD SETTINGS API =============

// Get Discord settings (admin only)
app.get('/api/admin/discord-settings', checkAuth, checkAdmin, (req, res) => {
  db.get(`SELECT * FROM discord_settings LIMIT 1`, (err, settings) => {
    if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
    
    if (!settings) {
      // Return default empty settings
      return res.json({
        enabled: 0,
        client_id: '',
        client_secret: '',
        redirect_uri: '',
        bot_token: '',
        guild_id: '',
        auto_role_id: '',
        updated_at: null
      });
    }

    // Don't send client_secret to frontend for security
    const safe = { ...settings };
    safe.client_secret = safe.client_secret ? '••••••••' : '';
    safe.bot_token = safe.bot_token ? '••••••••' : '';
    res.json(safe);
  });
});

// Update Discord settings (admin only)
app.put('/api/admin/discord-settings', checkAuth, checkAdmin, (req, res) => {
  const { enabled, client_id, client_secret, redirect_uri, bot_token, guild_id, auto_role_id } = req.body;

  if (!client_id || !client_secret || !redirect_uri) {
    if (enabled) {
      return res.status(400).json({ error: 'Client ID, Client Secret, and Redirect URI are required' });
    }
  }

  // Get current settings to preserve secrets if not being changed
  db.get(`SELECT * FROM discord_settings LIMIT 1`, (err, current) => {
    if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));

    const finalClientSecret = (client_secret && client_secret !== '••••••••') ? client_secret : (current?.client_secret || '');
    const finalBotToken = (bot_token && bot_token !== '••••••••') ? bot_token : (current?.bot_token || '');

    if (current) {
      // Update existing
      db.run(
        `UPDATE discord_settings SET 
         enabled = ?, client_id = ?, client_secret = ?, redirect_uri = ?, 
         bot_token = ?, guild_id = ?, auto_role_id = ?, updated_at = datetime('now')
         WHERE id = ?`,
        [enabled ? 1 : 0, client_id || '', finalClientSecret, redirect_uri || '', 
         finalBotToken, guild_id || '', auto_role_id || '', current.id],
        (err) => {
          if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
          
          const response = { success: true, message: 'Discord settings updated' };
          if (client_secret === '••••••••' || !client_secret) {
            response.message += ' (Client Secret preserved)';
          }
          res.json(response);
        }
      );
    } else {
      // Insert new
      db.run(
        `INSERT INTO discord_settings (enabled, client_id, client_secret, redirect_uri, bot_token, guild_id, auto_role_id) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [enabled ? 1 : 0, client_id || '', finalClientSecret, redirect_uri || '', 
         finalBotToken, guild_id || '', auto_role_id || ''],
        (err) => {
          if (err) return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
          res.json({ success: true, message: 'Discord settings created' });
        }
      );
    }
  });
});

// ============= USER PROFILE API =============

// Get user profile
app.get('/api/user/profile', checkAuth, (req, res) => {
  const userId = req.session.userId;
  if (!userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  db.get(
    `SELECT id, username, email, full_name, role, created_at, last_login FROM users WHERE id = ?`,
    [userId],
    (err, user) => {
      if (err) {
        console.error('[API Error] Failed to load profile:', err);
        // Fallback: try without full_name and last_login columns in case they don't exist yet
        db.get(
          `SELECT id, username, email, role, created_at FROM users WHERE id = ?`,
          [userId],
          (err2, user2) => {
            if (err2 || !user2) {
              return res.status(404).json({ error: 'User not found' });
            }
            // Add null values for missing columns
            user2.full_name = null;
            user2.last_login = null;
            res.json(user2);
          }
        );
        return;
      }
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      res.json(user);
    }
  );
});

// Update user profile (name & email)
app.put('/api/user/profile', checkAuth, (req, res) => {
  const { full_name, email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  
  db.run(
    `UPDATE users SET full_name = ?, email = ? WHERE id = ?`,
    [full_name || '', email, req.session.userId],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ error: 'Email already in use' });
        }
        return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
      }
      res.json({ success: true, message: 'Profile updated successfully' });
    }
  );
});

// Change password
app.put('/api/user/password', checkAuth, (req, res) => {
  const { current_password, new_password } = req.body;
  
  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'All password fields are required' });
  }
  
  if (new_password.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }
  
  // Get current password hash
  db.get(`SELECT password FROM users WHERE id = ?`, [req.session.userId], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Verify current password
    if (!bcrypt.compareSync(current_password, user.password)) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }
    
    // Hash new password
    const hashedPassword = bcrypt.hashSync(new_password, 10);
    
    // Update password
    db.run(
      `UPDATE users SET password = ? WHERE id = ?`,
      [hashedPassword, req.session.userId],
      function(err) {
        if (err) {
          return (console.error(err), res.status(500).json({ error: 'Internal server error' }));
        }
        res.json({ success: true, message: 'Password changed successfully' });
      }
    );
  });
});

// ============= SSH CONNECTION API =============

// SSH Connect endpoint - Test SSH connection
app.post('/api/ssh/connect', checkAuth, (req, res) => {
  const { vmId, host, port, username, password } = req.body;
  const userId = req.session.userId;
  
  if (!vmId || !host || !port || !username) {
    return res.status(400).json({ error: 'Missing connection parameters' });
  }
  
  // Verify VM ownership - admins may connect to any VM, regular users only
  // to their own (matches the same rule used by the WS SSH terminal).
  const vmQuery = req.session.role === 'admin'
    ? `SELECT * FROM vms WHERE vm_id = ?`
    : `SELECT * FROM vms WHERE vm_id = ? AND owner_id = ?`;
  const vmParams = req.session.role === 'admin' ? [vmId] : [vmId, userId];

  db.get(vmQuery, vmParams, (err, vm) => {
    if (err || !vm) {
      return res.status(403).json({ error: 'VM not found or access denied' });
    }
    
    // Generate session ID
    const sessionId = require('crypto').randomBytes(16).toString('hex');
    
    // Store connection info in the single shared session store (the same
    // one the WS SSH terminal and /api/ssh/command read from) so a session
    // created here is actually usable by the command endpoint.
    global.sshSessions = global.sshSessions || {};
    global.sshSessions[sessionId] = {
      vmId: parseInt(vmId),
      userId: userId,
      host: host,
      port: parseInt(port),
      username: username,
      password: null,
      createdAt: Date.now(),
      client: null
    };
    
    // Try to create SSH connection to verify it works. Use the actual
    // supplied password when present; only fall back to keyboard-interactive
    // (with a handler that replies with the same password) when none is
    // given, since tryKeyboard alone with no handler can never authenticate.
    const conn = new Client();
    let connectResponded = false;
    const connConfig = {
      host: host,
      port: parseInt(port),
      username: username,
      readyTimeout: 5000,
      strict: false
    };
    if (password) {
      connConfig.password = password;
    } else {
      connConfig.tryKeyboard = true;
    }

    if (!password) {
      conn.on('keyboard-interactive', (name, instructions, lang, prompts, finish) => {
        // No password was supplied for this connection test - respond with
        // empty answers rather than hanging the handshake indefinitely.
        finish(prompts.map(() => ''));
      });
    }
    
    conn.on('ready', () => {
      console.log(`[SSH] Connected to ${host}:${port}`);
      global.sshSessions[sessionId].client = conn;
      // AUDIT FIX (#13 - deep error audit): this `conn` object is stored
      // long-term in sshSessions and reused by /api/ssh/command for the
      // lifetime of the session - but the 'error' listener registered
      // below (for the initial connection attempt) closes over this same
      // `res`. If the connection later drops for any reason (long after
      // this request has already finished), that stale listener would
      // still fire and try to write to an already-sent response, throwing
      // ERR_HTTP_HEADERS_SENT. Replace it with a response-free listener
      // once we're past the initial handshake.
      connectResponded = true;
      conn.removeAllListeners('error');
      conn.on('error', (err) => {
        console.log(`[SSH] Session ${sessionId} connection error after connect: ${err.message}`);
        delete global.sshSessions[sessionId];
      });
      // DEEP FIX (leak): ssh2 emits 'close' (not 'error') when a connection
      // ends cleanly - idle timeout, server reboot - so without this
      // listener the session entry and its dead Client object leaked in
      // sshSessions forever.
      conn.on('close', () => { delete global.sshSessions[sessionId]; });
      res.json({
        success: true,
        sessionId: sessionId,
        message: 'SSH session created and connected'
      });
    });
    
    conn.on('error', (err) => {
      if (connectResponded) return;
      connectResponded = true;
      console.log(`[SSH] Connection error: ${err.message}`);
      delete global.sshSessions[sessionId];
      res.status(500).json({ 
        error: 'SSH connection failed: ' + err.message 
      });
    });
    
    conn.connect(connConfig);
  });
});

// SSH Command endpoint - Execute command on VM
app.post('/api/ssh/command', checkAuth, (req, res) => {
  const { vmId, command } = req.body;
  const userId = req.session.userId;
  
  if (!vmId || !command) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  // Find an active session for this VM
  let session = null;
  if (global.sshSessions) {
    for (const [id, s] of Object.entries(global.sshSessions)) {
      if (s.vmId === parseInt(vmId) && s.userId === userId && s.client) {
        session = s;
        break;
      }
    }
  }
  
  if (!session || !session.client) {
    return res.status(404).json({ error: 'SSH session not found. Connect first.' });
  }
  
  // Execute command via SSH
  session.client.exec(command, (err, stream) => {
    if (err) {
      return res.status(500).json({ 
        error: 'Command execution failed: ' + err.message 
      });
    }
    
    let output = '';
    let errorOutput = '';
    // AUDIT FIX (#13 - deep error audit): guard against responding twice -
    // 'close' and 'error' can both fire on some connection-drop scenarios,
    // and calling res.json() a second time throws
    // "ERR_HTTP_HEADERS_SENT" (itself another unhandled-exception source).
    let responded = false;
    const respondOnce = (payload, status) => {
      if (responded) return;
      responded = true;
      if (status) res.status(status);
      res.json(payload);
    };

    stream.on('close', () => {
      respondOnce({
        success: true,
        output: output || errorOutput || '(no output)',
        error: errorOutput || null
      });
    });

    // The exec stream itself can emit 'error' (e.g. the SSH connection
    // drops mid-command) - previously unhandled, which crashes the process.
    stream.on('error', (streamErr) => {
      console.error('[SSH] exec stream error:', streamErr.message);
      respondOnce({ error: 'Command execution failed: ' + streamErr.message }, 500);
    });
    
    stream.on('data', (data) => {
      output += data.toString();
    });
    
    stream.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });
  });
});

// ============= 404 HANDLER =============
app.use((req, res) => {
  res.status(404).render('users/404', {
    title: 'Page Not Found - VNM Panel',
    message: 'Page not found'
  });
});

// ============= VNM SHIELD: Express error middleware =============
// 4-arity = error handler (runs only when a handler throws / next(err)).
// Routes errors into the Error Teller (diagnosis + incident + notification,
// fingerprint-throttled), then answers the client without leaking stack
// traces. JSON for /api paths, a plain page otherwise.
app.use((err, req, res, next) => {
  if (err) {
    console.error(`[Shield:ExpressError] ${req.method} ${req.path}:`, err.message);
    if (shieldRef.processError) { try { shieldRef.processError('request', err); } catch (e) { /* never cascade */ } }
  }
  if (res.headersSent) return next(err);
  const status = (err && (err.httpStatus || err.status)) || 500;
  if (req.path.startsWith('/api')) {
    return res.status(status).json({ error: status >= 500 ? 'Internal server error' : err.message, hint: status >= 500 ? 'Details were recorded - see Shield → Incidents' : undefined });
  }
  res.status(status).send(status >= 500 ? 'Internal server error - details recorded in VNM Shield.' : (err && err.message) || 'Error');
});

// START SERVER
// server.listen() is deferred until initializeDatabase()'s callback fires,
// so no request (and no session-store query) can hit the DB before the
// required tables exist.
let _dbReadyForServer = false;
initializeDatabase(() => {
  Promise.all([
    nodeManager.ensureSchema(),
    auditLog.ensureSchema(),
    licenses.initLicenseStorage(null, db),
    premium.initPremiumStorage(null, db),   // premium tier state (single shared DB)
    platform.ensureSchema(),      // Round 5: platform tables (backups, api_keys, ...)
    taskEngine.ensureSchema(),    // Round 5: tasks + task_schedules
    monitoring.ensureSchema(),    // Round 5: metric_samples + alert_rules + alert_events
    shield.ensureSchema(),        // v3.0: shield_* tables (integrity, incidents, security, recovery, backups, updates)
  ])
    .then(() => {
      platform.start();           // Round 5: task runner + scheduler + monitoring collector
      shield.start();             // v3.0: schedulers (integrity/security/health/backup) + first-boot baseline
      _dbReadyForServer = true; startServerListening();
    })
    .catch((e) => { console.error('[Bootstrap] Schema bootstrap failed:', e); _dbReadyForServer = true; startServerListening(); });
});

// WebSocket handler for VM console
const vmConsoles = new Map();
// AUDIT FIX (#6): one shared log-tail watcher per vmId (see connection
// handler below) instead of one per connected client - see the comment at
// the watcher's creation site for why the old per-client version caused
// duplicated console output whenever more than one client watched the
// same VM.
const vmWatchers = new Map();
const sshSessions = new Map();

// noVNC console relay: browser <-> panel <-> (local TCP or agent relay) <->
// the VM's QEMU VNC socket. This is a raw byte pipe in both directions -
// the RFB protocol itself is spoken end-to-end between noVNC in the
// browser and QEMU, so nothing on this connection may ever inject a JSON
// text frame into the stream (that would corrupt the RFB handshake).
// Errors/availability are surfaced through the WebSocket close code/reason
// instead, and the frontend also does a REST pre-check (see
// /api/vms/:vm_id/vnc-status) before ever opening this connection so most
// failures are shown to the user before RFB is even constructed.
function handleVncConsoleWS(ws, vmIdParam, wsSession) {
  const vmId = parseInt(vmIdParam, 10);
  let closed = false;
  const closeSession = (code, reason) => {
    if (closed) return;
    closed = true;
    try { ws.close(code || 1000, (reason || '').slice(0, 120)); } catch (e) {}
  };

  let query = `SELECT * FROM vms WHERE vm_id = ?`;
  const params = [vmId];
  if (wsSession.role !== 'admin') { query += ` AND owner_id = ?`; params.push(wsSession.userId); }

  db.get(query, params, async (err, vm) => {
    if (closed) return;
    if (err || !vm) return closeSession(4004, 'VM not found or access denied');
    if (vm.status !== 'running') return closeSession(4009, 'VM is offline');

    let node;
    try { node = await nodeManager.getNodeForVM(vm); } catch (e) { return closeSession(4002, 'Could not resolve node for this VM'); }

    if (node && node.mode === 'remote') {
      let relay;
      try {
        relay = nodeManager.relayVncOpen(node.id, { vm }, {
          onData: (buf) => { if (!closed && ws.readyState === ws.OPEN) try { ws.send(buf, { binary: true }); } catch (e) {} },
          onClose: (reason) => closeSession(4010, reason || 'VNC session ended')
        });
      } catch (e) {
        return closeSession(4003, e.message || 'Could not reach the node agent for this VM');
      }
      ws.on('message', (data, isBinary) => { if (isBinary) relay.write(Buffer.isBuffer(data) ? data : Buffer.from(data)); });
      ws.on('close', () => { closed = true; relay.close(); });
      ws.on('error', () => { closed = true; relay.close(); });
      return;
    }

    // Local node: connect straight to the VM's local VNC port.
    const info = getLocalVncInfo(vm.vm_id);
    if (!info.available) return closeSession(4009, 'This VM has no VNC console available');
    const socket = net.connect({ host: info.host, port: info.port });
    socket.on('data', (chunk) => { if (!closed && ws.readyState === ws.OPEN) try { ws.send(chunk, { binary: true }); } catch (e) {} });
    socket.on('error', (e) => closeSession(4010, 'VNC socket error: ' + e.message));
    socket.on('close', () => closeSession(1000, 'VNC session ended'));
    ws.on('message', (data, isBinary) => { if (isBinary && !socket.destroyed) try { socket.write(Buffer.isBuffer(data) ? data : Buffer.from(data)); } catch (e) {} });
    ws.on('close', () => { closed = true; try { socket.destroy(); } catch (e) {} });
    ws.on('error', () => { closed = true; try { socket.destroy(); } catch (e) {} });
  });
}

wss.on('connection', async (ws, req) => {
  const url = req.url;
  console.log(`[WebSocket] New connection: ${url}`);

  // Node Agent connection - Path: /agent-connect
  // Authenticated with the node's own per-node token (see nodes.js),
  // NOT a panel browser session - this branch must run before the
  // session check below.
  if (url.startsWith('/agent-connect')) {
    return nodeManager.handleAgentConnection(ws, req);
  }

  // Admin Nodes page live-update channel - Path: /nodes-watch
  if (url.startsWith('/nodes-watch')) {
    const nodesWsSession = await getWsSession(req);
    if (!nodesWsSession || nodesWsSession.role !== 'admin') {
      ws.close();
      return;
    }
    nodeManager.watchNodes(ws);
    return;
  }

  // Require an authenticated panel session for every WebSocket connection
  // (console streaming and SSH terminal both carry sensitive VM access).
  const wsSession = await getWsSession(req);
  if (!wsSession) {
    console.warn(`[WebSocket] Rejected unauthenticated connection: ${url}`);
    ws.send(JSON.stringify({ type: 'error', message: 'Authentication required' }));
    ws.close();
    return;
  }

  // SSH Terminal WebSocket - Path: /ssh-terminal
  if (url.startsWith('/ssh-terminal')) {
    console.log(`[SSH-Terminal] New SSH terminal connection (user ${wsSession.userId})`);
    
    ws.on('message', async (message) => {
      try {
        const msg = JSON.parse(message.toString());
        
        if (msg.type === 'connect') {
          // Manual rate limit for SSH connect attempts (reuses same bucket store as HTTP)
          const sshKey = `ssh-ws:${wsSession.userId}`;
          const now = Date.now();
          let bucket = _rateBuckets.get(sshKey);
          if (!bucket || now - bucket.start > 60000) {
            bucket = { start: now, count: 0 };
            _rateBuckets.set(sshKey, bucket);
          }
          bucket.count++;
          if (bucket.count > 10) {
            ws.send(JSON.stringify({ type: 'error', message: 'Too many SSH connection attempts. Please wait a minute.' }));
            ws.close();
            return;
          }

          const { vmId, host, port, username, password } = msg;
          
          console.log(`[SSH-${vmId}] Initiating SSH connection to ${username}@${host}:${port}`);
          
          // Verify VM ownership against the authenticated session, not just that a row exists
          db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vmId], async (err, vm) => {
            if (err || !vm) {
              ws.send(JSON.stringify({ type: 'error', message: 'VM not found' }));
              return;
            }
            if (wsSession.role !== 'admin' && vm.owner_id !== wsSession.userId) {
              ws.send(JSON.stringify({ type: 'error', message: 'Access denied' }));
              ws.close();
              return;
            }

            // If this VM lives on a remote node, its SSH connection is
            // tunneled through that node's agent (below): the panel's ssh2
            // client speaks SSH over the agent's authenticated WebSocket
            // relay to the VM's forwarded port on the node itself. This
            // works even when the node is behind NAT (the agent dialed
            // out), and deliberately ignores the browser-supplied
            // host/port for remote VMs - the node's own 127.0.0.1 and the
            // VM's stored ssh_port are always what's used.
            let remoteNode = null;
            try {
              const n = await nodeManager.getNodeForVM(vm);
              if (n && n.mode === 'remote') remoteNode = n;
            } catch (e) { /* local VM */ }
            if (remoteNode && !nodeManager.isNodeOnline(remoteNode.id)) {
              ws.send(JSON.stringify({ type: 'error', message: `Node "${remoteNode.name}" is offline - start its agent and try again` }));
              return;
            }
            
            // Create SSH client
            const sshClient = new Client();
            
            sshClient.on('ready', () => {
              console.log(`[SSH-${vmId}] SSH client ready, opening shell`);
              
              sshClient.shell({ term: 'xterm-256color' }, (err, stream) => {
                if (err) {
                  console.error(`[SSH-${vmId}] Shell error:`, err.message);
                  ws.send(JSON.stringify({ type: 'error', message: 'Failed to open shell' }));
                  sshClient.end();
                  return;
                }
                
                console.log(`[SSH-${vmId}] Shell opened successfully`);
                ws.send(JSON.stringify({ type: 'connected' }));
                
                // Store session locally (for this WS's own input/close handling)...
                const sessionId = `${vmId}-${Date.now()}`;
                sshSessions.set(sessionId, { stream, client: sshClient, vmId });

                // ...and also in the shared global store, using the same shape
                // /api/ssh/connect uses, so /api/ssh/command can find and use
                // a session that was opened from the WS terminal too. Without
                // this, the REST command endpoint could never see a WS session
                // since it only read from global.sshSessions.
                global.sshSessions = global.sshSessions || {};
                global.sshSessions[sessionId] = {
                  vmId: parseInt(vmId),
                  userId: wsSession.userId,
                  host, port: parseInt(port), username,
                  createdAt: Date.now(),
                  client: sshClient
                };
                
                // Send raw data from SSH to WebSocket (binary, not JSON)
                // This preserves ANSI escape codes for proper terminal rendering
                stream.on('data', (data) => {
                  if (ws.readyState === WebSocket.OPEN) {
                    // Send raw binary data directly to xterm.js
                    ws.send(data, { binary: true });
                  }
                });
                
                stream.on('close', () => {
                  console.log(`[SSH-${vmId}] Shell closed`);
                  sshClient.end();
                  sshSessions.delete(sessionId);
                  if (global.sshSessions) delete global.sshSessions[sessionId];
                  if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'closed' }));
                  }
                });
                
                stream.on('error', (err) => {
                  console.error(`[SSH-${vmId}] Stream error:`, err.message);
                  sshSessions.delete(sessionId);
                  if (global.sshSessions) delete global.sshSessions[sessionId];
                  if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'error', message: err.message }));
                  }
                });
                
                // Store current session for this WebSocket
                ws.sshSessionId = sessionId;
              });
            });
            
            sshClient.on('error', (err) => {
              console.error(`[SSH-${vmId}] Connection error:`, err.message);
              ws.send(JSON.stringify({ type: 'error', message: `SSH Connection failed: ${err.message}` }));
              if (ws.readyState === WebSocket.OPEN) {
                ws.close();
              }
            });
            
            sshClient.on('close', () => {
              console.log(`[SSH-${vmId}] SSH connection closed`);
              if (ws.readyState === WebSocket.OPEN) {
                ws.close();
              }
            });
            
            // Connect to SSH server - directly for local VMs, or over the
            // node agent's TCP relay for VMs on a remote node (ssh2 runs
            // on top of a Duplex shim that pipes through the relay).
            if (remoteNode) {
              const sshPort = getSSHPort(vm);
              console.log(`[SSH-${vmId}] Remote-node VM: tunneling via agent on node ${remoteNode.name} to 127.0.0.1:${sshPort}`);
              const sockShim = new (require('stream').Duplex)({
                write(chunk, encoding, cb) { try { relay.write(chunk); } catch (e) { /* relay closed */ } cb(); },
                read() { /* data is pushed from the relay's onData */ },
                final(cb) { try { relay.close(); } catch (e) {} cb(); },
                destroy(err, cb) { try { relay.close(); } catch (e) {} cb(); }
              });
              const relay = nodeManager.relayTcpOpen(remoteNode.id, { host: '127.0.0.1', port: sshPort }, {
                onData: (buf) => { try { sockShim.push(buf); } catch (e) {} },
                onReady: () => { console.log(`[SSH-${vmId}] Agent relay established`); },
                onClose: (err) => {
                  console.log(`[SSH-${vmId}] Agent relay closed${err ? ': ' + err : ''}`);
                  try { sockShim.push(null); } catch (e) {}
                }
              });
              sshClient.on('close', () => { try { relay.close(); } catch (e) {} });
              sshClient.connect({
                sock: sockShim,
                username: username,
                password: password,
                readyTimeout: 30000,
                algorithms: {
                  serverHostKey: ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519']
                }
              });
            } else {
              sshClient.connect({
                host: host,
                port: parseInt(port),
                username: username,
                password: password,
                readyTimeout: 30000,
                algorithms: {
                  serverHostKey: ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519']
                }
              });
            }
          });
        } else if (msg.type === 'input' && ws.sshSessionId) {
          // Send user input to SSH shell (handle binary input)
          const session = sshSessions.get(ws.sshSessionId);
          if (session && session.stream) {
            session.stream.write(msg.data);
          }
        }
      } catch (err) {
        console.error('[SSH-Terminal] Message error:', err.message);
        ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
      }
    });
    
    ws.on('close', () => {
      console.log(`[SSH-Terminal] WebSocket closed`);
      if (ws.sshSessionId) {
        const session = sshSessions.get(ws.sshSessionId);
        if (session) {
          try {
            session.stream.end();
            session.client.end();
          } catch (e) {
            console.error('[SSH-Terminal] Error closing session:', e.message);
          }
          sshSessions.delete(ws.sshSessionId);
          if (global.sshSessions) delete global.sshSessions[ws.sshSessionId];
        }
      }
    });
    
    ws.on('error', (err) => {
      console.error(`[SSH-Terminal] WebSocket error:`, err.message);
    });
    
    return;
  }

  // File Manager live-update WebSocket - Path: /file-manager/:vmId
  if (url.startsWith('/file-manager')) {
    const fmVmId = url.split('/file-manager/')[1] ? url.split('/file-manager/')[1].split('?')[0] : null;
    if (!fmVmId || isNaN(fmVmId)) {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid VM ID' }));
      ws.close();
      return;
    }
    fileManager.handleFileManagerWS(ws, fmVmId, wsSession);
    return;
  }

  // noVNC console WebSocket - Path: /vnc-console/:vmId
  // Checked BEFORE the generic /console/:vmId fallback below, since that
  // one matches on the substring "/console/" and "/vnc-console/" contains
  // it too.
  if (url.startsWith('/vnc-console')) {
    const vncVmId = url.split('/vnc-console/')[1] ? url.split('/vnc-console/')[1].split('?')[0] : null;
    if (!vncVmId || isNaN(vncVmId)) {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid VM ID' }));
      ws.close();
      return;
    }
    handleVncConsoleWS(ws, vncVmId, wsSession);
    return;
  }

  // Extract vmId from URL path like /console/1 or just /1
  let vmId = null;
  if (url.includes('/console/')) {
    vmId = url.split('/console/')[1].split('?')[0];
  } else {
    vmId = url.split('/').pop().split('?')[0];
  }
  
  if (!vmId || vmId === '' || isNaN(vmId)) {
    console.log(`[WebSocket] Invalid vmId: "${vmId}"`);
    ws.send(JSON.stringify({ type: 'output', data: '\x1b[31m✗ Invalid VM ID\x1b[0m\r\n' }));
    ws.close();
    return;
  }

  console.log(`[Console-${vmId}] Client connected (user ${wsSession.userId})`);
  
  const logFile = path.join(VM_DIR, `vm-${vmId}.log`);
  // DEEP FIX (auth race): flipped to true only after the async ownership
  // check below passes - see the input-handler gate further down.
  let consoleAuthorized = false;

  // Send initial content
  db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vmId], (err, vm) => {
    if (err) {
      console.error(`[Console-${vmId}] DB error:`, err.message);
      ws.send(JSON.stringify({ type: 'output', data: `\x1b[31m✗ Database error\x1b[0m\r\n` }));
      return;
    }

    if (!vm) {
      console.log(`[Console-${vmId}] VM not found`);
      ws.send(JSON.stringify({ type: 'output', data: `\x1b[31m✗ VM ${vmId} not found\x1b[0m\r\n` }));
      return;
    }

    if (wsSession.role !== 'admin' && vm.owner_id !== wsSession.userId) {
      console.warn(`[Console-${vmId}] Access denied for user ${wsSession.userId}`);
      ws.send(JSON.stringify({ type: 'output', data: `\x1b[31m✗ Access denied\x1b[0m\r\n` }));
      ws.close();
      return;
    }

    // DEEP FIX (auth race): the client is only registered for broadcasts -
    // and its input accepted - AFTER the ownership check above passed.
    // Previously both happened synchronously at connect time, so a client
    // rejected a few milliseconds later had already injected keystrokes
    // into someone else's QEMU stdin during the check window.
    if (!vmConsoles.has(vmId)) vmConsoles.set(vmId, []);
    vmConsoles.get(vmId).push(ws);
    consoleAuthorized = true;

    let intro = '';
    if (vm.status === 'running') {
      intro = `\x1b[32m✓ VM ${vmId} is RUNNING\x1b[0m\r\n`;
    } else {
      intro = `\x1b[33m⚠ VM ${vmId} is ${vm.status.toUpperCase()}\x1b[0m\r\n`;
    }

    // Read and send existing log (to this newly-connected client only)
    let initialSize = 0;
    if (fs.existsSync(logFile)) {
      try {
        const content = fs.readFileSync(logFile, 'utf8');
        initialSize = Buffer.byteLength(content); // DEEP FIX: stat sizes are bytes; content.length counted UTF-16 units (multi-byte log lines duplicated the tail on the first watcher tick)
        ws.send(JSON.stringify({ 
          type: 'output', 
          data: intro + content 
        }));
        console.log(`[Console-${vmId}] Sent ${content.length} bytes of log`);
      } catch (e) {
        console.error(`[Console-${vmId}] Read error:`, e.message);
        ws.send(JSON.stringify({ type: 'output', data: intro + '\x1b[33m(Log file error)\x1b[0m\r\n' }));
      }
    } else {
      ws.send(JSON.stringify({ type: 'output', data: intro + '\x1b[36m[Console ready]\x1b[0m\r\n' }));
    }

    // AUDIT FIX (#6 - console reliability, deep debug pass): previously
    // EVERY connected client ran its OWN setInterval that independently
    // read "new bytes since my own lastSize" and then broadcast that chunk
    // to ALL clients for this vmId. With 2+ viewers open on the same VM
    // (a very normal case - one admin tab plus a user tab, or two browser
    // tabs), every new line of console output was read and broadcast once
    // per connected client, so everyone saw duplicated (or with 3+ clients,
    // tripled+) output - this is the concrete mechanism behind the
    // "output corruption" / "buffering" symptoms called out in the original
    // audit scope. Fixed by keeping exactly one shared watcher per vmId,
    // regardless of how many clients are watching it; broadcasting still
    // happens exactly once per new chunk of log data.
    let watcher = vmWatchers.get(vmId);
    if (!watcher) {
      watcher = { lastSize: initialSize, interval: null };
      watcher.interval = setInterval(() => {
        const clients = vmConsoles.get(vmId);
        if (!clients || clients.length === 0) {
          clearInterval(watcher.interval);
          vmWatchers.delete(vmId);
          return;
        }
        try {
          if (fs.existsSync(logFile)) {
            const stat = fs.statSync(logFile);
            if (stat.size > watcher.lastSize) {
              const fd = fs.openSync(logFile, 'r');
              const buffer = Buffer.alloc(stat.size - watcher.lastSize);
              fs.readSync(fd, buffer, 0, stat.size - watcher.lastSize, watcher.lastSize);
              fs.closeSync(fd);

              watcher.lastSize = stat.size;
              const newData = buffer.toString('utf8');

              clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                  client.send(JSON.stringify({ type: 'output', data: newData }));
                }
              });
            } else if (stat.size < watcher.lastSize) {
              // Log was rotated/truncated (see rotateLogIfNeeded) - reset
              // instead of computing a negative-length read.
              watcher.lastSize = stat.size;
            }
          }
        } catch (e) {
          console.error(`[Console-${vmId}] Watch error:`, e.message);
        }
      }, 50);
      vmWatchers.set(vmId, watcher);
    } else if (initialSize > watcher.lastSize) {
      // A watcher was already running (from an earlier client) and the log
      // grew since; make sure we don't re-broadcast bytes this new client
      // was already sent above as part of its own initial snapshot.
      watcher.lastSize = Math.max(watcher.lastSize, initialSize);
    }
  });

  // (client registration moved inside the authorized db.get callback above)

  // Handle input from terminal - gated on the async ownership check.
  ws.on('message', (message) => {
    if (!consoleAuthorized) return;
    try {
      const msg = JSON.parse(message);
      if (msg.type === 'input' && msg.data) {
        // Forward to the real QEMU process stdin if the VM is running
        const stdin = qemuStdins.get(String(vmId));
        if (stdin && !stdin.destroyed) {
          stdin.write(msg.data);
        }

        // Append to log file
        fs.appendFileSync(logFile, msg.data);
        
        // Broadcast to other clients
        if (vmConsoles.has(vmId)) {
          vmConsoles.get(vmId).forEach(client => {
            if (client !== ws && client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify({ type: 'output', data: msg.data }));
            }
          });
        }
        
        console.log(`[Console-${vmId}] Input: ${msg.data.length} bytes`);
      }
    } catch (e) {
      console.error(`[Console-${vmId}] Message parse error:`, e.message);
    }
  });

  // Handle disconnect
  ws.on('close', () => {
    console.log(`[Console-${vmId}] Client disconnected`);
    
    if (vmConsoles.has(vmId)) {
      const clients = vmConsoles.get(vmId);
      const idx = clients.indexOf(ws);
      if (idx > -1) {
        clients.splice(idx, 1);
      }
      
      // Clean up the console entry and its shared watcher immediately
      // once the last client leaves, instead of waiting for the watcher's
      // own next 50ms tick to notice and self-clear.
      if (clients.length === 0) {
        vmConsoles.delete(vmId);
        const watcher = vmWatchers.get(vmId);
        if (watcher && watcher.interval) {
          clearInterval(watcher.interval);
        }
        vmWatchers.delete(vmId);
      }
    }
  });

  ws.on('error', (error) => {
    console.error(`[Console-${vmId}] WebSocket error:`, error.message);
  });
});

function startServerListening() {
// AUDIT FIX #5: previously there was no 'error' listener on the HTTP
// server, so EADDRINUSE (another VNM instance, or anything else already
// bound to PORT) crashed the process with a raw, unhelpful stack trace.
// Detect it, report a clear diagnostic, and exit(1) deliberately instead of
// letting Node's default uncaught-exception path handle it.
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n✗ Port ${PORT} is already in use.`);
    console.error(`  Another VNM panel instance (or another process) is already listening on this port.`);
    console.error(`  Run 'lsof -i :${PORT}' or 'ss -ltnp | grep ${PORT}' to identify it, then stop it or set a`);
    console.error(`  different PORT in your .env file before starting again.\n`);
    process.exit(1);
  } else if (err.code === 'EACCES') {
    console.error(`\n✗ Permission denied binding to port ${PORT}. Ports below 1024 need elevated privileges` +
      ` (run as root/Administrator, or use a port >= 1024).\n`);
    process.exit(1);
  } else {
    console.error('\n✗ Failed to start server:', err.message, '\n');
    process.exit(1);
  }
});
server.listen(PORT, async () => {
  try {
    console.log(`[License] ${licenses.licensingEnabled() ? 'Enforcement active (' + licenses.getServerUrl() + ')' : 'Licensing disabled (no LICENSE_SERVER_URL set)'}`);
  } catch (error) {
    console.error('[License] Init error (non-fatal):', error.message);
  }

  // Fix any VMs with invalid CPU models on startup
  const validCpuModels = Object.keys(CPU_MODELS);
  db.all(`SELECT vm_id, cpu_model FROM vms WHERE cpu_model NOT IN (${validCpuModels.map(() => '?').join(',')})`, validCpuModels, (err, vms) => {
    if (!err && vms && vms.length > 0) {
      console.log(`[Startup] Found ${vms.length} VMs with invalid CPU models, fixing...`);
      vms.forEach(vm => {
        console.warn(`[Startup] VM ${vm.vm_id}: CPU model '${vm.cpu_model}' is not available, resetting to 'host'`);
        db.run(`UPDATE vms SET cpu_model = 'host' WHERE vm_id = ?`, [vm.vm_id]);
      });
    }
  });

  rdp.ensureSchema().then(() => {
    rdp.startAutoEnable();
    // After the VM-process reconcile below has run, make sure every running
    // NAT VM with RDP enabled really has its forward (idempotent).
    setTimeout(() => rdp.restoreForwards().catch((e) => console.error('[RDP] restoreForwards failed:', e.message)), 10000).unref();
  });

  // --- Reconcile VM process state with reality on startup (#23) ---
  // vmProcesses/qemuStdins are in-memory and empty right after a restart,
  // even though a VM's QEMU process may still be running (or may have died
  // while the panel was down). Walk every VM the DB thinks is "running" and
  // either re-adopt the live process (so start/stop/console keep working)
  // or correct the DB status if it's actually dead.
  db.all(`SELECT vm_id, status FROM vms WHERE status = 'running'`, (err, runningVms) => {
    if (err || !runningVms) return;
    runningVms.forEach(vm => {
      const pidFile = path.join(VM_DIR, `vm-${vm.vm_id}.pid`);
      let pid = null;
      try {
        if (fs.existsSync(pidFile)) {
          pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim());
        }
      } catch (e) { /* ignore */ }

      const isAlive = pid ? isPidQemu(pid) : false;

      if (isAlive) {
        vmProcesses.set(vm.vm_id, pid);
        console.log(`[Startup] Re-adopted running VM ${vm.vm_id} (PID ${pid})`);
        // Note: qemuStdins can't be recovered after a restart (stdin handle
        // is lost with the old process object), so the console will show
        // "not connected" for write access until the VM is restarted —
        // read-only log tailing still works.
      } else {
        console.warn(`[Startup] VM ${vm.vm_id} marked running but process is gone — marking stopped`);
        db.run(`UPDATE vms SET status = 'stopped' WHERE vm_id = ?`, [vm.vm_id]);
        try { if (fs.existsSync(pidFile)) fs.unlinkSync(pidFile); } catch (e) { /* ignore */ }
      }
    });
  });

  console.log(`
╔════════════════════════════════════════════════════════════╗
║           VNM PANEL v3.0.1  ·  VNM SHIELD                ║
║                 Made by Immortal               ║
║   VM Management + Anti-Tamper · Auto-Recovery · IDS     ║
╚════════════════════════════════════════════════════════════╝

✓ Server: http://localhost:${PORT}
✓ Database: ${dbPath}
✓ VM Directory: ${VM_DIR}
✓ RDP feature: ENABLED (VM Details → RDP tab, host ports ${rdp.portRange})
✓ Platform: Task Engine + Monitoring/Alerts + Snapshots & Backups + Clone/Migrate + API Keys
✓ Shield: Integrity Guard · Error Teller · Backup Vault · Emergency Mode · IDS · Watchdog-Ready

Open http://localhost:${PORT} to begin
  `);
});
}

module.exports = app;