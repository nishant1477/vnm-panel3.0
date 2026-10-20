// =====================================================================
// VNM — Monitoring & Alerts
// ---------------------------------------------------------------------
// Collects resource metrics on a fixed tick and stores them in SQLite
// for live dashboards and historical graphs:
//   - node metrics: from the `nodes` table, kept fresh by agent
//     heartbeats (remote nodes) and boot-time refresh (local node)
//   - local VM metrics: ps sampling of each running VM's QEMU PID
//   - remote VM metrics: 'vm.stats' agent command per node
//
// On the same tick, alert rules are evaluated against the latest
// samples. A rule only fires when the condition holds across the whole
// sustain window (default 5 minutes), then enters a cooldown so a
// flapping metric doesn't spam notifications. Notifications go to:
//   - the in-panel alert feed (alert_events table) - always
//   - a Discord webhook (settings key 'alert_discord_webhook') - if set
// Email delivery is intentionally NOT faked: the UI explains that a
// Discord webhook is the supported channel unless an SMTP relay is
// wired up externally.
// =====================================================================

'use strict';

const COLLECT_INTERVAL_MS = parseInt(process.env.VNM_MONITOR_INTERVAL_MS || '20000', 10);
const SAMPLE_RETENTION_HOURS = 24;
const PRUNE_EVERY_MS = 10 * 60 * 1000;

function createMonitoring({ db, nodeManager, VM_DIR, execPromise, axios }) {
  let started = false;
  let lastPrune = 0;
  const http = axios || require('axios');

  const dbGet = (sql, params) => new Promise((resolve, reject) => db.get(sql, params, (e, r) => e ? reject(e) : resolve(r)));
  const dbAll = (sql, params) => new Promise((resolve, reject) => db.all(sql, params, (e, r) => e ? reject(e) : resolve(r || [])));
  const dbRun = (sql, params) => new Promise((resolve, reject) => db.run(sql, params, function (e) { e ? reject(e) : resolve(this); }));

  // ---------------- schema ----------------
  function ensureSchema() {
    return new Promise((resolve) => {
      db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS metric_samples (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          scope TEXT NOT NULL,
          target_id INTEGER NOT NULL,
          cpu REAL,
          mem_used REAL,
          mem_total REAL,
          disk_used REAL,
          disk_total REAL,
          running INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, () => {
          db.run(`CREATE INDEX IF NOT EXISTS idx_metrics_lookup ON metric_samples(scope, target_id, created_at)`, () => {
            db.run(`CREATE TABLE IF NOT EXISTS alert_rules (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              scope TEXT NOT NULL DEFAULT 'node',
              target_id INTEGER,
              metric TEXT NOT NULL,
              comparator TEXT DEFAULT '>',
              threshold REAL NOT NULL,
              for_minutes INTEGER DEFAULT 5,
              severity TEXT DEFAULT 'warning',
              channels TEXT,
              enabled INTEGER DEFAULT 1,
              cooldown_minutes INTEGER DEFAULT 30,
              last_fired_at DATETIME,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`, () => {
              db.run(`CREATE TABLE IF NOT EXISTS alert_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER,
                rule_name TEXT,
                scope TEXT,
                target_id INTEGER,
                target_name TEXT,
                severity TEXT DEFAULT 'warning',
                message TEXT NOT NULL,
                value TEXT,
                status TEXT DEFAULT 'open',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
              )`, () => {
                db.run(`CREATE INDEX IF NOT EXISTS idx_alert_events_open ON alert_events(status, created_at)`, () => resolve());
              });
            });
          });
        });
      });
    });
  }

  // ---------------- collection ----------------
  async function sampleNodeMetrics() {
    const nodes = await dbAll(`SELECT * FROM nodes`, []).catch(() => []);
    for (const n of nodes) {
      const hasStats = n.cpu_usage_percent != null || n.ram_total != null;
      await dbRun(
        `INSERT INTO metric_samples (scope, target_id, cpu, mem_used, mem_total, disk_used, disk_total, running)
         VALUES ('node', ?, ?, ?, ?, ?, ?, ?)`,
        [n.id, n.cpu_usage_percent ?? null, n.ram_used ?? null, n.ram_total ?? null, n.disk_used ?? null, n.disk_total ?? null,
         (n.status === 'online' || n.mode === 'local') ? 1 : 0]
      ).catch(() => {});
      if (!hasStats) { /* row still recorded so uptime/online tracking works */ }
    }
  }

  async function psSample(pids) {
    // pids: Map vmId -> pid. Returns Map vmId -> { cpu, memBytes } or null.
    const out = new Map();
    for (const [vmId, pid] of pids) {
      try {
        const { stdout } = await execPromise(`ps -p ${pid} -o %cpu,rss --no-headers 2>/dev/null || echo ""`, { timeout: 4000 });
        const line = String(stdout || '').trim().split('\n')[0];
        if (!line) { out.set(vmId, null); continue; }
        const parts = line.trim().split(/\s+/);
        out.set(vmId, { cpu: parseFloat(parts[0]) || 0, memBytes: (parseFloat(parts[1]) || 0) * 1024 });
      } catch (e) { out.set(vmId, null); }
    }
    return out;
  }

  async function sampleLocalVmMetrics(localNodeId) {
    const fs = require('fs');
    const path = require('path');
    const vms = await dbAll(
      `SELECT vm_id, memory, status, node_id FROM vms WHERE status = 'running' AND (node_id IS NULL OR node_id = ?)`, [localNodeId]
    ).catch(() => []);
    const pids = new Map();
    for (const vm of vms) {
      const pidFile = path.join(VM_DIR, `vm-${vm.vm_id}.pid`);
      try {
        if (fs.existsSync(pidFile)) {
          const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10);
          if (pid > 0) pids.set(vm.vm_id, pid);
        }
      } catch (e) { /* no pid file */ }
    }
    if (!pids.size) return;
    const samples = await psSample(pids);
    for (const [vmId, s] of samples) {
      const vm = vms.find((v) => v.vm_id === vmId);
      const memTotal = vm && vm.memory ? vm.memory * 1024 * 1024 : null;
      await dbRun(
        `INSERT INTO metric_samples (scope, target_id, cpu, mem_used, mem_total, running) VALUES ('vm', ?, ?, ?, ?, 1)`,
        [vmId, s ? s.cpu : null, s ? s.memBytes : null, memTotal]
      ).catch(() => {});
    }
  }

  async function sampleRemoteVmMetrics() {
    const rows = await dbAll(
      `SELECT v.vm_id, v.memory, v.node_id, n.id AS nid, n.name AS node_name
       FROM vms v JOIN nodes n ON n.id = v.node_id
       WHERE v.status = 'running' AND n.mode = 'remote'`
    ).catch(() => []);
    if (!rows.length) return;
    const byNode = new Map();
    for (const r of rows) {
      if (!byNode.has(r.nid)) byNode.set(r.nid, []);
      byNode.get(r.nid).push(r);
    }
    for (const [nodeId, vmRows] of byNode) {
      try {
        const res = await nodeManager.sendNodeCommand(nodeId, 'vm.stats', { vmIds: vmRows.map((r) => String(r.vm_id)) }, { timeoutMs: 8000 });
        const stats = (res && res.vms) || {};
        for (const r of vmRows) {
          const s = stats[String(r.vm_id)];
          await dbRun(
            `INSERT INTO metric_samples (scope, target_id, cpu, mem_used, mem_total, running) VALUES ('vm', ?, ?, ?, ?, 1)`,
            [r.vm_id, s ? (s.cpu ?? null) : null, s ? (s.memBytes ?? null) : null, r.memory ? r.memory * 1024 * 1024 : null]
          ).catch(() => {});
        }
      } catch (e) { /* node offline - skip this tick */ }
    }
  }

  async function pruneSamples() {
    await dbRun(`DELETE FROM metric_samples WHERE created_at < datetime('now', '-${SAMPLE_RETENTION_HOURS} hours')`, []).catch(() => {});
  }

  // ---------------- alert engine ----------------
  async function getSetting(key) {
    const row = await dbGet(`SELECT setting_value FROM settings WHERE setting_key = ?`, [key]).catch(() => null);
    return row ? row.setting_value : null;
  }

  async function sendDiscord(severity, message) {
    const url = await getSetting('alert_discord_webhook');
    if (!url) return false;
    try {
      const colors = { info: 0x22d3ee, warning: 0xf59e0b, critical: 0xef4444 };
      await http.post(url, {
        username: 'VNM Panel',
        embeds: [{
          title: `VNM Alert - ${severity.toUpperCase()}`,
          description: String(message).slice(0, 3900),
          color: colors[severity] || colors.warning,
          footer: { text: 'VNM Panel Monitoring' },
          timestamp: new Date().toISOString()
        }]
      }, { timeout: 8000 });
      return true;
    } catch (e) {
      console.warn('[Monitoring] Discord webhook delivery failed:', e.message);
      return false;
    }
  }

  function metricValue(sample, metric) {
    if (!sample) return null;
    if (metric === 'cpu') return sample.cpu;
    if (metric === 'mem') {
      if (sample.mem_used == null || !sample.mem_total) return null;
      return (sample.mem_used / sample.mem_total) * 100;
    }
    if (metric === 'disk') {
      if (sample.disk_used == null || !sample.disk_total) return null;
      return (sample.disk_used / sample.disk_total) * 100;
    }
    return null;
  }

  async function latestSamples(scope, targetId, minutes) {
    return dbAll(
      `SELECT * FROM metric_samples WHERE scope = ? AND target_id = ? AND created_at >= datetime('now', '-${parseInt(minutes, 10) || 1} minutes') ORDER BY id ASC`,
      [scope, targetId]
    ).catch(() => []);
  }

  async function evaluateAlerts() {
    const rules = await dbAll(`SELECT * FROM alert_rules WHERE enabled = 1`).catch(() => []);
    for (const rule of rules) {
      try {
        const sustain = Math.max(1, parseInt(rule.for_minutes, 10) || 1);
        const cooldown = Math.max(1, parseInt(rule.cooldown_minutes, 10) || 30);
        if (rule.last_fired_at) {
          const since = Date.now() - new Date(String(rule.last_fired_at).replace(' ', 'T') + 'Z').getTime();
          if (since < cooldown * 60e3) continue;
        }
        // Determine targets: rule.target_id pins one, else every target of scope.
        let targets = [];
        if (rule.target_id != null) {
          targets = [{ id: rule.target_id, name: null }];
        } else {
          const rows = rule.scope === 'node'
            ? await dbAll(`SELECT id, name FROM nodes`, [])
            : await dbAll(`SELECT vm_id AS id, vm_name AS name FROM vms`, []);
          targets = rows.map((r) => ({ id: r.id, name: r.name }));
        }
        for (const t of targets) {
          const samples = await latestSamples(rule.scope, t.id, sustain);
          if (!samples.length) continue;
          const vals = samples.map((s) => metricValue(s, rule.metric)).filter((v) => v != null);
          if (vals.length < Math.min(2, samples.length)) continue;
          const breach = (v) => rule.comparator === '<' ? v < rule.threshold : v > rule.threshold;
          if (!vals.every(breach)) continue; // must hold across the whole sustain window

          // Resolve a friendly target name.
          let targetName = t.name;
          if (!targetName) {
            const row = rule.scope === 'node'
              ? await dbGet(`SELECT name FROM nodes WHERE id = ?`, [t.id]).catch(() => null)
              : await dbGet(`SELECT vm_name FROM vms WHERE vm_id = ?`, [t.id]).catch(() => null);
            targetName = row ? (row.name || row.vm_name) : `#${t.id}`;
          }
          const metricLabel = rule.metric === 'cpu' ? 'CPU' : rule.metric === 'mem' ? 'memory' : 'disk';
          const latest = vals[vals.length - 1].toFixed(1);
          const message = `${metricLabel} usage on ${rule.scope} "${targetName}" is ${latest}% (threshold: ${rule.comparator} ${rule.threshold}%) for ${sustain} min`;
          await dbRun(
            `INSERT INTO alert_events (rule_id, rule_name, scope, target_id, target_name, severity, message, value)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [rule.id, rule.name, rule.scope, t.id, targetName, rule.severity, message, latest]
          );
          await dbRun(`UPDATE alert_rules SET last_fired_at = CURRENT_TIMESTAMP WHERE id = ?`, [rule.id]);
          console.warn(`[Monitoring] ALERT [${rule.severity}] ${message}`);
          sendDiscord(rule.severity, message);
          break; // one target per rule per evaluation (cooldown prevents spam)
        }
      } catch (e) {
        console.warn('[Monitoring] rule evaluation failed:', e.message);
      }
    }
  }

  // ---------------- API-facing queries ----------------
  async function getOverview() {
    const [vmTotals, running, nodeRows] = await Promise.all([
      dbGet(`SELECT COUNT(*) AS c FROM vms`).catch(() => ({ c: 0 })),
      dbGet(`SELECT COUNT(*) AS c FROM vms WHERE status = 'running'`).catch(() => ({ c: 0 })),
      dbAll(`SELECT * FROM nodes`).catch(() => [])
    ]);
    const online = nodeRows.filter((n) => n.mode === 'local' || n.status === 'online');
    let cpuSum = 0, cpuN = 0, memUsed = 0, memTotal = 0, diskUsed = 0, diskTotal = 0;
    for (const n of online) {
      if (n.cpu_usage_percent != null) { cpuSum += n.cpu_usage_percent; cpuN++; }
      memUsed += n.ram_used || 0; memTotal += n.ram_total || 0;
      diskUsed += n.disk_used || 0; diskTotal += n.disk_total || 0;
    }
    return {
      vms: vmTotals.c || 0,
      vmsRunning: running.c || 0,
      nodes: nodeRows.length,
      nodesOnline: online.length,
      cpuPercent: cpuN ? +(cpuSum / cpuN).toFixed(1) : null,
      memUsedBytes: memUsed, memTotalBytes: memTotal,
      diskUsedBytes: diskUsed, diskTotalBytes: diskTotal,
    };
  }

  async function getHistory({ scope, targetId, hours = 1 }) {
    const h = Math.min(Math.max(parseInt(hours, 10) || 1, 1), SAMPLE_RETENTION_HOURS);
    return dbAll(
      `SELECT id, scope, target_id, cpu, mem_used, mem_total, disk_used, disk_total, running, created_at
       FROM metric_samples
       WHERE scope = ? AND target_id = ? AND created_at >= datetime('now', '-${h} hours')
       ORDER BY id ASC`,
      [scope, targetId]
    ).catch(() => []);
  }

  async function getLatestForScope(scope) {
    // Latest sample per target within the last 3 minutes.
    return dbAll(
      `SELECT m.* FROM metric_samples m
       JOIN (SELECT target_id, MAX(id) AS mid FROM metric_samples WHERE scope = ? AND created_at >= datetime('now', '-3 minutes') GROUP BY target_id) latest
       ON m.id = latest.mid`,
      [scope]
    ).catch(() => []);
  }

  async function getLive() {
    const [nodes, vmSamples, vms] = await Promise.all([
      dbAll(`SELECT * FROM nodes ORDER BY (mode='local') DESC, id ASC`).catch(() => []),
      getLatestForScope('vm'),
      dbAll(`SELECT vm_id, vm_name, status, memory, cpus, node_id FROM vms`).catch(() => [])
    ]);
    const overview = await getOverview();
    const vmById = new Map(vms.map((v) => [v.vm_id, v]));
    const liveVms = vmSamples.map((s) => {
      const vm = vmById.get(s.target_id) || {};
      return {
        vm_id: s.target_id, vm_name: vm.vm_name || ('VM #' + s.target_id),
        status: vm.status || 'unknown', cpu: s.cpu,
        mem_used: s.mem_used, mem_total: s.mem_total,
        mem_percent: (s.mem_used != null && s.mem_total) ? +((s.mem_used / s.mem_total) * 100).toFixed(1) : null,
      };
    });
    return { overview, nodes: nodes.map(({ agent_token_hash, ...rest }) => rest), vms: liveVms, ts: new Date().toISOString() };
  }

  // ---------------- tick + lifecycle ----------------
  let busy = false;
  async function tick() {
    if (busy || !started) return;
    busy = true;
    try {
      let localNodeId = null;
      try { const local = await nodeManager.getNodeForVM({}); localNodeId = local ? local.id : null; } catch (e) {}
      await sampleNodeMetrics();
      await sampleLocalVmMetrics(localNodeId);
      await sampleRemoteVmMetrics();
      await evaluateAlerts();
      if (Date.now() - lastPrune > PRUNE_EVERY_MS) { lastPrune = Date.now(); await pruneSamples(); }
    } catch (e) {
      console.warn('[Monitoring] tick failed:', e.message);
    } finally {
      busy = false;
    }
  }

  function start() {
    if (started) return;
    started = true;
    // Seed the first sample quickly, then settle into the interval.
    setTimeout(tick, 3000).unref();
    setInterval(tick, COLLECT_INTERVAL_MS).unref();
    console.log(`[Monitoring] Collector started (every ${Math.round(COLLECT_INTERVAL_MS / 1000)}s, ${SAMPLE_RETENTION_HOURS}h retention, alert engine active)`);
  }

  return {
    ensureSchema, start, tick,
    getOverview, getHistory, getLive,
    sendDiscord,
  };
}

module.exports = createMonitoring;
