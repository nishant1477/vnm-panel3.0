// =====================================================================
// VNM — shared system-info module
// ---------------------------------------------------------------------
// Real OS/CPU/RAM/disk/virtualization detection. No fake or simulated
// values anywhere - every field here is read from the actual machine
// it's running on. Required identically by:
//   - app.js (to populate/refresh the bootstrapped "Local Node" row)
//   - node-agent/agent.js (to report a remote node's real stats)
// Keeping this in one module means Local and Remote nodes are always
// measured the same way.
// =====================================================================

const os = require('os');
const { execFile } = require('child_process');
const fs = require('fs');

function run(cmd, args, opts) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 5000, ...opts }, (err, stdout) => {
      if (err) return resolve(null);
      resolve(stdout.toString());
    });
  });
}

// CPU usage % sampled over a short window (os.cpus() gives cumulative
// counters, so a single snapshot can't yield a percentage on its own).
function cpuSnapshot() {
  return os.cpus().map((c) => ({ idle: c.times.idle, total: Object.values(c.times).reduce((a, b) => a + b, 0) }));
}
function cpuUsagePercent(sampleMs = 200) {
  return new Promise((resolve) => {
    const start = cpuSnapshot();
    setTimeout(() => {
      const end = cpuSnapshot();
      let idleDelta = 0, totalDelta = 0;
      for (let i = 0; i < end.length; i++) {
        idleDelta += end[i].idle - (start[i] ? start[i].idle : 0);
        totalDelta += end[i].total - (start[i] ? start[i].total : 0);
      }
      const pct = totalDelta > 0 ? Math.max(0, Math.min(100, 100 - (idleDelta / totalDelta) * 100)) : 0;
      resolve(Math.round(pct * 10) / 10);
    }, sampleMs);
  });
}

async function diskUsage(targetPath) {
  // Portable enough for the Linux hosts VNM targets. Falls back to nulls
  // (honest "unknown", never a made-up number) if `df` isn't available.
  const out = await run('df', ['-Pk', targetPath || '/']);
  if (!out) return { totalBytes: null, usedBytes: null, freeBytes: null };
  const lines = out.trim().split('\n');
  const parts = (lines[lines.length - 1] || '').trim().split(/\s+/);
  if (parts.length < 4) return { totalBytes: null, usedBytes: null, freeBytes: null };
  return {
    totalBytes: (parseInt(parts[1], 10) || 0) * 1024,
    usedBytes: (parseInt(parts[2], 10) || 0) * 1024,
    freeBytes: (parseInt(parts[3], 10) || 0) * 1024
  };
}

async function detectKvm() {
  let kvmDevice = false;
  try { fs.accessSync('/dev/kvm', fs.constants.R_OK | fs.constants.W_OK); kvmDevice = true; } catch (e) { kvmDevice = false; }
  let cpuVirt = false;
  try {
    const cpuinfo = fs.readFileSync('/proc/cpuinfo', 'utf8');
    cpuVirt = /\b(vmx|svm)\b/.test(cpuinfo);
  } catch (e) { /* non-Linux or unreadable - leave false, don't guess */ }
  return { kvmDevice, cpuVirt, available: kvmDevice && cpuVirt };
}

async function detectQemu() {
  const candidates = [process.env.QEMU_BIN, 'qemu-system-x86_64', '/usr/bin/qemu-system-x86_64', '/usr/libexec/qemu-kvm'].filter(Boolean);
  for (const bin of candidates) {
    const out = await run(bin, ['--version']);
    if (out) {
      const m = out.match(/version\s+([\d.]+)/i);
      return { available: true, binary: bin, version: m ? m[1] : out.split('\n')[0].trim() };
    }
  }
  return { available: false, binary: null, version: null };
}

async function getSystemInfo(diskPath) {
  const [kvm, qemu, disk, cpuPct] = await Promise.all([
    detectKvm(), detectQemu(), diskUsage(diskPath), cpuUsagePercent()
  ]);
  const cpus = os.cpus();
  return {
    hostname: os.hostname(),
    platform: os.platform(),
    os: `${os.type()} ${os.release()}`,
    kernel: os.release(),
    architecture: os.arch(),
    cpuModel: cpus.length ? cpus[0].model.trim() : null,
    cpuCores: cpus.length,
    cpuUsagePercent: cpuPct,
    ramTotalBytes: os.totalmem(),
    ramFreeBytes: os.freemem(),
    ramUsedBytes: os.totalmem() - os.freemem(),
    diskTotalBytes: disk.totalBytes,
    diskUsedBytes: disk.usedBytes,
    diskFreeBytes: disk.freeBytes,
    kvmAvailable: kvm.available,
    qemuAvailable: qemu.available,
    qemuVersion: qemu.version,
    uptimeSeconds: os.uptime(),
    loadAvg: os.loadavg()
  };
}

// Lighter-weight call for frequent heartbeat/stats polling - skips the
// (slower, less volatile) capability detection and only samples the
// numbers that actually change second to second.
async function getLiveStats(diskPath) {
  const [disk, cpuPct] = await Promise.all([diskUsage(diskPath), cpuUsagePercent()]);
  return {
    cpuUsagePercent: cpuPct,
    ramTotalBytes: os.totalmem(),
    ramFreeBytes: os.freemem(),
    ramUsedBytes: os.totalmem() - os.freemem(),
    diskTotalBytes: disk.totalBytes,
    diskUsedBytes: disk.usedBytes,
    diskFreeBytes: disk.freeBytes,
    uptimeSeconds: os.uptime(),
    loadAvg: os.loadavg()
  };
}

module.exports = { getSystemInfo, getLiveStats, detectKvm, detectQemu, diskUsage, cpuUsagePercent };
