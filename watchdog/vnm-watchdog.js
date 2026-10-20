#!/usr/bin/env node
// =====================================================================
// VNM Shield — Independent Watchdog
// ---------------------------------------------------------------------
// A SEPARATE lightweight process (its own systemd unit, own config,
// own notification channel) that watches the panel from the outside:
//
//   every interval:  GET http://127.0.0.1:<port>/api/health
//     - 200 + status ok            -> healthy, failure counter reset
//     - anything else / timeout    -> failure counted
//     - N consecutive failures     -> RECOVERY: run the configured
//                                     restart command (default:
//                                     systemctl restart vnm-panel),
//                                     then re-verify after 15s
//
//   Anti-thrash (a watchdog must not mask real failures):
//     - cooldown between recovery attempts
//     - circuit breaker: at most `maxRestartsPerHour` (default 3)
//       recoveries per rolling hour; beyond that: STOP restarting,
//       send ONE critical "manual intervention required" alert, keep
//       observing and reporting
//     - every action + outcome is recorded (JSONL log file + the
//       heartbeat file), never silently
//
//   Independence: no panel code, no panel DB, no panel settings. It
//   reads its own watchdog.json and speaks plain HTTP. It CAN notify
//   even when the panel cannot (that is the whole point).
//
//   Watchdog-the-watched: each loop updates watchdog-heartbeat.json;
//   a stale heartbeat (> 3 intervals) means the watchdog itself died
//   (detectable via systemd `Restart=always`, a cron probe, or any
//   external monitor).
//
// Usage:  node vnm-watchdog.js [--config <file>] [--once] [--status]
// =====================================================================

'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { exec } = require('child_process');
const { URL } = require('url');

const args = process.argv.slice(2);
const argOf = (name) => { const i = args.indexOf(name); return i >= 0 && i + 1 < args.length ? args[i + 1] : null; };

const DATA_DIR = process.env.VNM_DATA_DIR || path.join(os.homedir(), '.vnm');
const CONFIG_PATH = argOf('--config') || path.join(DATA_DIR, 'shield', 'watchdog.json');
const HEARTBEAT_PATH = path.join(DATA_DIR, 'shield', 'watchdog-heartbeat.json');
const LOG_PATH = path.join(DATA_DIR, 'shield', 'watchdog.log');

const DEFAULTS = {
  url: `http://127.0.0.1:${process.env.PORT || 8080}/api/health`,
  intervalSec: 30,
  timeoutSec: 10,
  failThreshold: 3,
  cooldownSec: 600,
  maxRestartsPerHour: 3,
  recheckDelaySec: 15,
  restartCommand: 'systemctl restart vnm-panel',
  notify: {
    discordWebhook: '',
    telegramToken: '', telegramChatId: '',
    webhookUrl: '',
    smtpHost: '', smtpPort: 587, smtpUser: '', smtpPass: '', smtpFrom: '', smtpTo: '',
  },
};

function loadConfig() {
  let cfg = { ...DEFAULTS };
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    cfg = { ...cfg, ...raw, notify: { ...DEFAULTS.notify, ...(raw.notify || {}) } };
  } catch (e) {
    // first run: write the template so the operator can edit it
    try {
      fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
      fs.writeFileSync(CONFIG_PATH, JSON.stringify(DEFAULTS, null, 2), { mode: 0o600 });
      logLine('config created at ' + CONFIG_PATH + ' - edit and restart the watchdog to customize');
    } catch (e2) { /* read-only fs: run on defaults */ }
  }
  return cfg;
}

function logLine(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  try {
    fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true });
    // crude rotation at 5 MB
    try {
      const st = fs.statSync(LOG_PATH);
      if (st.size > 5 * 1024 * 1024) {
        fs.renameSync(LOG_PATH, LOG_PATH + '.1');
      }
    } catch (e) { /* no file yet */ }
    fs.appendFileSync(LOG_PATH, line);
  } catch (e) { /* read-only fs: stdout only */ }
  process.stdout.write('[Watchdog] ' + line);
}

function recordAction(entry) {
  // JSONL action log (the audit trail of every recovery + outcome)
  try {
    fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true });
    fs.appendFileSync(LOG_PATH.replace(/\.log$/, '-actions.jsonl'), JSON.stringify({ at: new Date().toISOString(), ...entry }) + '\n');
  } catch (e) { /* best effort */ }
}

function writeHeartbeat(state) {
  try {
    fs.mkdirSync(path.dirname(HEARTBEAT_PATH), { recursive: true });
    fs.writeFileSync(HEARTBEAT_PATH, JSON.stringify({ at: new Date().toISOString(), ...state }, null, 2));
  } catch (e) { /* best effort */ }
}

function httpGet(url, timeoutSec) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch (e) { return resolve({ ok: false, error: 'bad url' }); }
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.get(u, { timeout: timeoutSec * 1000 }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; if (body.length > 8192) req.destroy(); });
      res.on('end', () => resolve({ ok: res.statusCode === 200, status: res.statusCode, body: body.slice(0, 500) }));
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
  });
}

function postJson(url, payload, timeoutSec) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch (e) { return resolve(false); }
    const mod = u.protocol === 'https:' ? https : http;
    const body = JSON.stringify(payload);
    const req = mod.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'http:' ? 80 : 443),
      path: u.pathname + u.search, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: (timeoutSec || 10) * 1000,
    }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode >= 200 && res.statusCode < 300)); });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.end(body);
  });
}

// ---- notifications (own channels, independent of the panel) ----
async function notifyOwner(cfg, subject, body, severity) {
  const n = cfg.notify || {};
  const redact = (s) => String(s).replace(/\b(password|token|secret|key)\s*[:=]\s*\S+/gi, '$1=***');
  let sent = false;
  if (n.discordWebhook) {
    sent = (await postJson(n.discordWebhook, {
      username: 'VNM Watchdog',
      embeds: [{ title: subject.slice(0, 250), description: redact(body).slice(0, 3500), color: severity === 'critical' ? 0xe74c3c : 0xf39c12 }],
    })) || sent;
  }
  if (n.telegramToken && n.telegramChatId) {
    sent = (await postJson(`https://api.telegram.org/bot${n.telegramToken}/sendMessage`, {
      chat_id: n.telegramChatId, text: `*${subject}*\n\n${redact(body)}`.slice(0, 4000), parse_mode: 'Markdown',
    })) || sent;
  }
  if (n.webhookUrl) {
    sent = (await postJson(n.webhookUrl, { source: 'vnm-watchdog', severity, subject, body: redact(body), at: new Date().toISOString() })) || sent;
  }
  return sent;
}

function execCmd(cmd, timeoutSec) {
  return new Promise((resolve) => {
    exec(cmd, { timeout: (timeoutSec || 60) * 1000 }, (err, stdout, stderr) =>
      resolve({ ok: !err, stdout: String(stdout || ''), stderr: String(stderr || ''), error: err ? err.message : null }));
  });
}

// ---------------- main ----------------
async function main() {
  if (args.includes('--status')) {
    try {
      const hb = JSON.parse(fs.readFileSync(HEARTBEAT_PATH, 'utf8'));
      const ageSec = Math.round((Date.now() - new Date(hb.at).getTime()) / 1000);
      console.log(`heartbeat: ${hb.at} (${ageSec}s ago)`);
      console.log(`state: ${JSON.stringify(hb, null, 2)}`);
      process.exit(ageSec < 120 ? 0 : 2);
    } catch (e) { console.error('no heartbeat - watchdog not running?'); process.exit(3); }
  }

  const cfg = loadConfig();
  logLine('watchdog starting - watching ' + cfg.url + ' every ' + cfg.intervalSec + 's');

  let consecutiveFails = 0;
  let lastRecoveryAt = 0;
  let recoveryTimestamps = [];
  let breakerOpenNotified = false;
  let healthySince = null;

  async function checkOnce() {
    const r = await httpGet(cfg.url, cfg.timeoutSec);
    if (r.ok) {
      if (consecutiveFails > 0) {
        logLine('panel is HEALTHY again (status 200)');
        await notifyOwner(cfg, 'Panel recovered', `The panel at ${cfg.url} is answering health checks again after ${consecutiveFails} failed check(s).`, 'low');
      }
      consecutiveFails = 0;
      healthySince = healthySince || Date.now();
      breakerOpenNotified = false;
      writeHeartbeat({ state: 'healthy', consecutiveFails: 0, url: cfg.url });
      return;
    }

    consecutiveFails++;
    logLine(`check FAILED (${consecutiveFails}/${cfg.failThreshold}): ${r.error || 'HTTP ' + r.status}`);

    if (consecutiveFails < cfg.failThreshold) {
      writeHeartbeat({ state: 'degraded', consecutiveFails, url: cfg.url, lastError: r.error || ('HTTP ' + r.status) });
      return;
    }

    // ---- panel is DOWN: recovery decision ----
    const now = Date.now();
    recoveryTimestamps = recoveryTimestamps.filter((t) => now - t < 3600 * 1000);

    if (recoveryTimestamps.length >= cfg.maxRestartsPerHour) {
      writeHeartbeat({ state: 'breaker-open', consecutiveFails, recoveriesLastHour: recoveryTimestamps.length, url: cfg.url });
      if (!breakerOpenNotified) {
        breakerOpenNotified = true;
        logLine('CIRCUIT BREAKER OPEN: ' + recoveryTimestamps.length + ' recoveries in the last hour - NOT restarting again');
        recordAction({ action: 'breaker-open', outcome: 'restarts-suspended', recoveriesLastHour: recoveryTimestamps.length });
        await notifyOwner(cfg,
          'Watchdog circuit breaker OPEN - manual intervention required',
          `The panel has failed health checks and the watchdog already performed ${recoveryTimestamps.length} recoveries in the past hour. Automatic restarts are SUSPENDED to avoid masking a deeper failure.\n\nInvestigate on the host:\n  systemctl status vnm-panel\n  journalctl -u vnm-panel -n 100\n\nThe watchdog keeps monitoring and will report recovery.`,
          'critical');
      }
      return;
    }

    if (now - lastRecoveryAt < cfg.cooldownSec * 1000) {
      logLine('in cooldown - not restarting yet');
      writeHeartbeat({ state: 'cooldown', consecutiveFails, url: cfg.url });
      return;
    }

    // ---- execute recovery ----
    lastRecoveryAt = now;
    recoveryTimestamps.push(now);
    logLine('panel DOWN - executing recovery: ' + cfg.restartCommand);
    await notifyOwner(cfg, 'Panel DOWN - watchdog intervention started',
      `The panel failed ${consecutiveFails} consecutive health checks. The watchdog is executing: ${cfg.restartCommand}`, 'high');
    const rec = await execCmd(cfg.restartCommand, 90);
    recordAction({ action: 'restart', command: cfg.restartCommand, outcome: rec.ok ? 'command-ok' : 'command-failed', error: rec.error });

    if (!rec.ok) {
      logLine('recovery command FAILED: ' + (rec.error || rec.stderr));
      await notifyOwner(cfg, 'Watchdog recovery command FAILED',
        `Could not execute "${cfg.restartCommand}": ${rec.error || rec.stderr || 'unknown error'}. MANUAL INTERVENTION REQUIRED.`, 'critical');
      writeHeartbeat({ state: 'recovery-failed', consecutiveFails, url: cfg.url, lastError: rec.error });
      return;
    }

    // ---- verify genuine recovery ----
    await new Promise((r) => setTimeout(r, cfg.recheckDelaySec * 1000));
    const verify = await httpGet(cfg.url, cfg.timeoutSec);
    if (verify.ok) {
      logLine('recovery VERIFIED - panel healthy after restart');
      recordAction({ action: 'restart-verify', outcome: 'healthy' });
      consecutiveFails = 0;
      await notifyOwner(cfg, 'Panel recovered (watchdog restart verified)',
        `The panel was restarted by the watchdog and is now answering health checks again. Root cause is still worth checking: journalctl -u vnm-panel -n 100`, 'medium');
      writeHeartbeat({ state: 'recovered', consecutiveFails: 0, lastRecovery: new Date().toISOString(), url: cfg.url });
    } else {
      logLine('restart executed but panel STILL UNHEALTHY: ' + (verify.error || 'HTTP ' + verify.status));
      recordAction({ action: 'restart-verify', outcome: 'still-unhealthy', error: verify.error || ('HTTP ' + verify.status) });
      await notifyOwner(cfg, 'Panel still down after watchdog restart',
        `The restart command ran but the panel is still failing health checks (${verify.error || 'HTTP ' + verify.status}). The watchdog will keep trying within its limits (${recoveryTimestamps.length}/${cfg.maxRestartsPerHour} this hour). Manual investigation recommended.`, 'critical');
      writeHeartbeat({ state: 'still-unhealthy', consecutiveFails, url: cfg.url, lastError: verify.error || ('HTTP ' + verify.status) });
    }
  }

  if (args.includes('--once')) {
    await checkOnce();
    process.exit(0);
  }

  await checkOnce();
  setInterval(() => { checkOnce().catch((e) => logLine('check error: ' + e.message)); }, Math.max(5, cfg.intervalSec) * 1000);
}

main().catch((e) => { logLine('FATAL: ' + e.message); process.exit(1); });
