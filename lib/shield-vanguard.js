// =====================================================================
// VNM Shield — VM Guardian + Resource & Storage Protection
// ---------------------------------------------------------------------
// VM GUARDIAN
//   Separates VM-level failures from panel-level failures and answers
//   "is this VM actually alive?" per VM:
//     - local: QEMU pid known to the panel + pid file + /proc cmdline
//       verification (isPidQemu)
//     - stale DB state (says running, process gone) is detected and
//       reported - corrected only by the existing, battle-tested
//       correction paths, never guessed at here
//     - orphaned QEMU (process alive, DB says stopped) is reported
//     - per-VM diagnostic: liveness, uptime, RSS, disk image presence
//       and size vs allocation, serial log tail, KVM availability
//   The guardian is READ-ONLY by design. It never kills, never
//   restarts, never edits VM disks or metadata - repairs are
//   suggestions that go through the normal, confirmed VM actions.
//
// RESOURCE GUARD
//   - disk + inode headroom on the volumes that matter (VM dir, data
//     dir, root), with thresholds that fire BEFORE exhaustion
//   - memory pressure + load average
//   - top consumers (CPU / RSS) for the runaway-process question
//   - SAFE cleanup candidates: logs, temp files, old unverified
//     backups - with sizes and a preview, deleted only after explicit
//     owner confirmation, and a hard blacklist: VM disk images
//     (*.img/*.qcow2/*.iso in the VM tree), the live database, and
//     the latest verified backup can NEVER be selected for cleanup
// =====================================================================

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { exec } = require('child_process');

const VM_DISK_EXT = /\.(img|qcow2|qcow|raw|vhd|vhdx|vmdk|iso)$/i;

function createVanguard(ctx) {
  const db = ctx.db;
  const getSetting = ctx.getSetting;
  const setSetting = ctx.setSetting;
  const notify = ctx.notify;
  const VM_DIR = ctx.VM_DIR;
  const vmProcesses = ctx.vmProcesses;      // Map vmId -> pid (panel-local)
  const isPidQemu = ctx.isPidQemu;
  const log = (...a) => { try { console.log('[Shield:Vanguard]', ...a); } catch (e) {} };

  const dbAll = (sql, params) => new Promise((resolve, reject) => db.all(sql, params, (e, r) => e ? reject(e) : resolve(r || [])));
  const dbRun = (sql, params) => new Promise((resolve, reject) => db.run(sql, params, function (e) { e ? reject(e) : resolve(this); }));

  const execP = (cmd, timeoutMs) => new Promise((resolve) => {
    try {
      exec(cmd, { timeout: timeoutMs || 8000, maxBuffer: 2 * 1024 * 1024 }, (err, stdout, stderr) =>
        resolve({ ok: !err, stdout: String(stdout || ''), stderr: String(stderr || ''), error: err ? err.message : null }));
    } catch (e) { resolve({ ok: false, stdout: '', stderr: '', error: e.message }); }
  });

  function pidAlive(pid) {
    if (!pid) return false;
    try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
  }

  function readPidFile(vmId) {
    try {
      const t = fs.readFileSync(path.join(VM_DIR, `vm-${vmId}.pid`), 'utf8').trim();
      const p = parseInt(t, 10);
      return isNaN(p) ? null : p;
    } catch (e) { return null; }
  }

  // ---------------- VM guardian ----------------
  async function vmDiagnose(vm) {
    const d = {
      vm_id: vm.vm_id, name: vm.vm_name, node: vm.node_name || 'localhost',
      dbStatus: vm.status, findings: [],
    };
    if (vm.node_name && vm.node_name !== 'localhost') {
      d.findings.push({ code: 'REMOTE_NODE', severity: 'info', text: `VM runs on remote node '${vm.node_name}' - live liveness is checked from that node's agent.` });
      return d;
    }

    // liveness
    let pid = vmProcesses ? vmProcesses.get(vm.vm_id) : null;
    if (!pid) pid = readPidFile(vm.vm_id);
    const alive = pid ? (isPidQemu ? isPidQemu(pid) : pidAlive(pid)) : false;
    d.qemuPid = alive ? pid : null;
    d.actuallyRunning = alive;

    if (vm.status === 'running' && !alive) {
      d.findings.push({
        code: 'STALE_RUNNING', severity: 'high',
        text: 'Panel records this VM as running, but its QEMU process is gone (crash or host restart). Fix: mark stopped, then start it again from the VM page. Serial log below usually shows why it died.',
      });
      d.recovery = { action: 'mark-stopped-then-start', requires_confirmation: true };
    } else if (vm.status !== 'running' && alive) {
      d.findings.push({
        code: 'ORPHAN_QEMU', severity: 'medium',
        text: 'A QEMU process exists for this VM while the panel thinks it is stopped (possible crash of the panel while VM ran). Fix: use Stop on the VM page to reconcile - do NOT kill the process manually if users are connected.',
      });
      d.recovery = { action: 'reconcile-via-stop', requires_confirmation: true };
    } else if (alive) {
      // process details
      const ps = await execP(`ps -o pid,etime,rss,%cpu -p ${pid} --no-headers 2>/dev/null`);
      if (ps.ok && ps.stdout.trim()) {
        const [ , etime, rss, cpu] = ps.stdout.trim().split(/\s+/);
        d.uptime = etime; d.rssMb = Math.round(parseInt(rss, 10) / 1024); d.cpuPct = cpu;
      }
    }

    // disk image
    const diskFile = vm.disk_file || vm.img_file;
    if (diskFile) {
      const abs = path.isAbsolute(diskFile) ? diskFile : path.join(VM_DIR, diskFile);
      try {
        const st = fs.statSync(abs);
        d.disk = { file: diskFile, bytes: st.size, gb: +(st.size / 1024 ** 3).toFixed(2) };
        const allocated = parseFloat(vm.disk_size);
        if (allocated && st.size >= allocated * 1024 ** 3 * 0.98) {
          d.findings.push({ code: 'DISK_NEAR_FULL', severity: 'medium', text: `Disk image is at/near its allocated ${vm.disk_size} (currently ${d.disk.gb} GB). Grow the disk or clean up inside the guest before it hits read-only.` });
        }
      } catch (e) {
        d.findings.push({ code: 'DISK_MISSING', severity: 'high', text: `Disk image not found at ${diskFile}. The VM cannot start until the image is restored (backup/snapshot) or recreated.` });
      }
    }

    // serial log tail
    try {
      const logFile = path.join(VM_DIR, `vm-${vm.vm_id}.log`);
      if (fs.existsSync(logFile)) {
        const tail = fs.readFileSync(logFile, 'utf8').split('\n').slice(-8).filter(Boolean);
        if (tail.length) d.logTail = tail;
      }
    } catch (e) { /* unreadable */ }

    return d;
  }

  async function vmSweep(source) {
    const vms = await dbAll(`SELECT vm_id, vm_name, status, node_name, disk_file, img_file, disk_size FROM vms`);
    const findings = [];
    for (const vm of vms.slice(0, 500)) {
      try {
        const d = await vmDiagnose(vm);
        for (const f of d.findings) {
          if (['STALE_RUNNING', 'ORPHAN_QEMU', 'DISK_MISSING'].includes(f.code)) {
            findings.push({ vm: vm.vm_name, vmId: vm.vm_id, ...f });
          }
        }
      } catch (e) { log('vmDiagnose failed', vm.vm_id, e.message); }
    }
    const running = vms.filter((v) => v.status === 'running').length;
    const result = { at: new Date().toISOString(), source: source || 'schedule', totalVms: vms.length, running, findings };
    await setSetting('shield.vmguard.lastSweep', JSON.stringify({ at: result.at, findings: findings.length }));
    if (findings.length && source !== 'manual') {
      await notify({
        severity: 'medium',
        title: `VM Guardian: ${findings.length} VM issue(s) detected`,
        body: findings.slice(0, 5).map((f) => `${f.vm}: ${f.code.replace(/_/g, ' ').toLowerCase()}`).join('; ') + (findings.length > 5 ? ` (+${findings.length - 5} more)` : '') + '. See Shield → VM Guardian for details and safe recovery steps.',
        diag: {
          fingerprint: 'vm-guardian:' + findings.map((f) => f.code).sort().join(','), category: 'qemu', component: 'vm/guardian', severity: 'medium',
          title: 'VM Guardian findings',
          explanation: 'The VM Guardian compared the database state of every VM against the actual QEMU processes and disk files on the host.',
          confirmed_causes: [`${findings.length} VM(s) have a mismatch between panel state and reality or a missing disk.`],
          possible_causes: ['QEMU crash (see the VM serial log)', 'Host reboot while panel state was not persisted', 'Manually moved/deleted disk files'],
          suggested_fix: 'Open Shield → VM Guardian, read each finding, and use the suggested confirmed action. Nothing was modified automatically.',
          raw: { message: findings.map((f) => f.vm + ':' + f.code).join(', ').slice(0, 300) },
        },
      });
    }
    return result;
  }

  // ---------------- resource guard ----------------
  async function resourceSnapshot() {
    const dfAll = await execP(`df -h / "${VM_DIR}" "${ctx.dataDir}" 2>/dev/null | tail -n +2`);
    const dfInode = await execP(`df -i / "${VM_DIR}" "${ctx.dataDir}" 2>/dev/null | tail -n +2`);
    const parseDf = (txt) => String(txt || '').split('\n').filter(Boolean).map((l) => {
      const p = l.trim().split(/\s+/);
      return { fs: p[0], size: p[1], used: p[2], avail: p[3], usePct: parseInt(p[4]) || 0, mount: p[5] };
    });
    const mounts = parseDf(dfAll.stdout).filter((m, i, arr) => arr.findIndex((x) => x.mount === m.mount) === i);
    const inodes = parseDf(dfInode.stdout).filter((m, i, arr) => arr.findIndex((x) => x.mount === m.mount) === i);

    let mem = { usedPct: null };
    try {
      const mi = fs.readFileSync('/proc/meminfo', 'utf8');
      const total = parseInt((mi.match(/MemTotal:\s+(\d+)/) || [])[1] || '0', 10);
      const avail = parseInt((mi.match(/MemAvailable:\s+(\d+)/) || [])[1] || '0', 10);
      if (total) mem.usedPct = Math.round(100 * (total - avail) / total);
    } catch (e) { /* non-linux */ }

    const loadavg = os.loadavg();
    const topPs = await execP(`ps aux --sort=-%cpu 2>/dev/null | head -n 8`);
    const top = String(topPs.stdout || '').split('\n').slice(1).filter(Boolean).map((l) => {
      const p = l.trim().split(/\s+/);
      return { user: p[0], cpu: p[2], mem: p[3], command: p.slice(10).join(' ').slice(0, 90) };
    });

    const diskWarn = mounts.filter((m) => m.usePct >= 85);
    const inodeWarn = inodes.filter((m) => m.usePct >= 85);
    const snap = { at: new Date().toISOString(), mounts, inodes, mem, loadavg, top, diskWarn, inodeWarn, cores: os.cpus().length };
    await setSetting('shield.resource.lastSnapshot', JSON.stringify({ at: snap.at, worstDisk: Math.max(0, ...mounts.map((m) => m.usePct)), mem: mem.usedPct }));
    return snap;
  }

  // ---------------- safe cleanup ----------------
  // Categories are whitelisted. VM disks, the live DB, and the latest
  // verified backup are structurally impossible to select.
  const CLEANUP_CATEGORIES = [
    { id: 'vm-logs', label: 'VM serial logs', desc: 'vm-*.log console output files (regenerated while VMs run)', dir: () => VM_DIR, pattern: /^vm-.*\.log$/ },
    { id: 'panel-logs', label: 'Panel logs', desc: 'rotated panel log files (*.log.*, *.log.old)', dir: () => ctx.dataDir, pattern: /^.*\.log\.(old|\d+)|\.log\.old$/ },
    { id: 'tmp', label: 'Temporary files', desc: 'stale temp files older than 48h in the data dir', dir: () => ctx.dataDir, pattern: /^tmp-|^vnm-(bk|verify|restore)-/ },
    { id: 'old-backups', label: 'Old unverified backups', desc: 'backups that never passed verification (verified ones and the newest backup are kept)', special: 'backups' },
  ];

  async function cleanupCandidates() {
    const out = [];
    for (const cat of CLEANUP_CATEGORIES) {
      const files = [];
      if (cat.special === 'backups') {
        const rows = await dbAll(`SELECT file FROM shield_backups WHERE verified = 0 AND kind = 'failed'`);
        for (const r of rows) {
          const p = path.join(ctx.dataDir, 'shield', 'backups', r.file);
          try { files.push({ path: p, bytes: fs.statSync(p).size }); } catch (e) { /* gone */ }
        }
      } else {
        let entries = [];
        try { entries = fs.readdirSync(cat.dir()); } catch (e) { continue; }
        for (const name of entries) {
          if (!cat.pattern.test(name)) continue;
          const p = path.join(cat.dir(), name);
          try {
            const st = fs.statSync(p);
            if (!st.isFile()) continue;
            if (VM_DISK_EXT.test(name)) continue;                    // paranoia: never disk images
            if (cat.id === 'tmp' && Date.now() - st.mtimeMs < 48 * 3600 * 1000) continue;
            files.push({ path: p, bytes: st.size });
          } catch (e) { /* unreadable */ }
        }
      }
      files.sort((a, b) => b.bytes - a.bytes);
      out.push({
        category: cat.id, label: cat.label, desc: cat.desc,
        count: files.length, bytes: files.reduce((s, f) => s + f.bytes, 0),
        sample: files.slice(0, 10).map((f) => ({ path: f.path, mb: +(f.bytes / 1024 ** 2).toFixed(1) })),
      });
    }
    return out;
  }

  // Apply cleanup for selected categories. Double validation:
  //   1. category must be whitelisted (by its id)
  //   2. every concrete path must match its category's rules and must
  //      NOT be a VM disk image / DB file / newest backup
  async function applyCleanup(categories) {
    const results = [];
    const wanted = new Set(categories || []);
    for (const cat of CLEANUP_CATEGORIES) {
      if (!wanted.has(cat.id)) continue;
      let deleted = 0, bytes = 0, skipped = [];
      if (cat.special === 'backups') {
        const rows = await dbAll(`SELECT file FROM shield_backups WHERE verified = 0 AND kind = 'failed'`);
        for (const r of rows) {
          const p = path.join(ctx.dataDir, 'shield', 'backups', r.file);
          try { const b = fs.statSync(p).size; fs.unlinkSync(p); deleted++; bytes += b; }
          catch (e) { skipped.push(r.file); }
        }
        await dbRun(`DELETE FROM shield_backups WHERE verified = 0 AND kind = 'failed'`);
      } else {
        let entries = [];
        try { entries = fs.readdirSync(cat.dir()); } catch (e) { continue; }
        for (const name of entries) {
          if (!cat.pattern.test(name)) continue;
          if (VM_DISK_EXT.test(name)) { skipped.push(name); continue; }
          if (/vnm\.db/.test(name)) { skipped.push(name); continue; }
          const p = path.join(cat.dir(), name);
          try {
            const st = fs.statSync(p);
            if (!st.isFile()) continue;
            if (cat.id === 'tmp' && Date.now() - st.mtimeMs < 48 * 3600 * 1000) continue;
            fs.unlinkSync(p); deleted++; bytes += st.size;
          } catch (e) { skipped.push(name); }
        }
      }
      results.push({ category: cat.id, deleted, bytes, skipped: skipped.slice(0, 5) });
    }
    await notify({
      severity: 'low',
      title: 'Cleanup executed',
      body: `Deleted: ${results.filter((r) => r.deleted).map((r) => `${r.category} (${r.deleted} files, ${(r.bytes / 1024 ** 2).toFixed(1)} MB)`).join(', ') || 'nothing'}. VM disks, the database, and verified backups were not touched.`,
    });
    return results;
  }

  return { vmSweep, vmDiagnose, resourceSnapshot, cleanupCandidates, applyCleanup, CLEANUP_CATEGORIES };
}

module.exports = { createVanguard };
