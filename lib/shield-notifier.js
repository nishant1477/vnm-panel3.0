// =====================================================================
// VNM Shield — Notifications & Incident Management
// ---------------------------------------------------------------------
// One entry point - notify(event) - that:
//   1. groups duplicate events into incidents using a stable
//      fingerprint (a repeating error updates its incident instead of
//      creating a new notification every time - anti-spam)
//   2. fans the notification out to every configured channel, but
//      only at/above the configured minimum severity:
//        - Discord webhook
//        - Telegram bot
//        - Generic webhook (POST JSON; works with ntfy, Gotify,
//          Slack-compatible endpoints, custom scripts...)
//        - Email via a REAL minimal SMTP client implemented directly
//          on net/tls (STARTTLS 587 / implicit TLS 465 / plain 25,
//          AUTH LOGIN + AUTH PLAIN) - zero new dependencies
//   3. redacts secrets from every outgoing byte (passwords, tokens,
//      private keys, session ids) - see shield-diagnoser.redact
//
// Incidents carry severity, status (open / acknowledged / resolved),
// occurrence counts and full history, and are queryable + exportable
// for the Shield dashboard.
// =====================================================================

'use strict';

const https = require('https');
const http = require('http');
const net = require('net');
const tls = require('tls');
const { URL } = require('url');
const { redact, newIncidentId } = require('./shield-diagnoser');

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];

// ----------------------------------------------------------------------
// Minimal but real SMTP client (RFC 5321 + STARTTLS + AUTH)
// ----------------------------------------------------------------------
async function smtpSend(cfg, message) {
  // cfg: { host, port, security: 'starttls'|'tls'|'none', user, pass, from, to, timeoutMs }
  const host = cfg.host, port = parseInt(cfg.port || 587, 10);
  const security = cfg.security || 'starttls';
  const timeoutMs = parseInt(cfg.timeoutMs || 15000, 10);

  let socket = security === 'tls'
    ? tls.connect({ host, port, servername: host })
    : net.connect({ host, port });
  socket.setTimeout(timeoutMs);

  const state = { socket, buffer: '', secure: security === 'tls' };

  const readReply = () => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('SMTP: timeout waiting for server reply')), timeoutMs);
    const onData = (chunk) => {
      state.buffer += chunk.toString('utf8');
      // A reply can span lines; the last line has a space after the code (e.g. "250-START" continuation vs "250 OK")
      const lines = state.buffer.split('\r\n');
      const last = lines[lines.length - 1];
      if (/^\d{3} /.test(last) || (lines.length && /^\d{3}$/.test(last.trim()))) {
        state.buffer = '';
        clearTimeout(timer);
        socket.removeListener('data', onData);
        socket.removeListener('error', onErr);
        const code = parseInt(last.slice(0, 3), 10);
        resolve({ code, text: lines.join(' ').trim() });
      }
    };
    const onErr = (e) => { clearTimeout(timer); reject(new Error('SMTP: ' + e.message)); };
    socket.on('data', onData);
    socket.on('error', onErr);
  });

  const cmd = async (expect, line) => {
    socket.write(line + '\r\n');
    const r = await readReply();
    if (expect && Math.floor(r.code / 100) !== Math.floor(expect / 100)) {
      throw new Error(`SMTP: expected ${expect}xx after "${line.slice(0, 40)}", got ${r.code} ${r.text.slice(0, 120)}`);
    }
    return r;
  };

  try {
    const greeting = await readReply();        // 220 greeting
    if (Math.floor(greeting.code / 100) !== 2) throw new Error('SMTP: bad greeting ' + greeting.code);
    const hostname = 'vnm-panel.local';
    let r = await cmd(250, `EHLO ${hostname}`);
    const caps = r.text.toUpperCase();
    if (security === 'starttls' && caps.includes('STARTTLS')) {
      await cmd(220, 'STARTTLS');
      // Upgrade the SAME socket
      const upgraded = tls.connect({ socket, servername: host, rejectUnauthorized: cfg.rejectUnauthorized !== false });
      socket = upgraded; state.socket = upgraded; state.secure = true;
      await new Promise((resolve, reject) => {
        upgraded.once('secureConnect', resolve);
        upgraded.once('error', reject);
        setTimeout(() => reject(new Error('SMTP: TLS upgrade timeout')), timeoutMs);
      });
      r = await cmd(250, `EHLO ${hostname}`);
    }
    if (cfg.user && cfg.pass) {
      const caps2 = r.text.toUpperCase();
      if (caps2.includes('AUTH')) {
        const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
        if (caps2.includes('PLAIN') && !caps2.includes('LOGIN')) {
          await cmd(235, 'AUTH PLAIN ' + b64(`\u0000${cfg.user}\u0000${cfg.pass}`));
        } else {
          await cmd(334, 'AUTH LOGIN');
          await cmd(334, b64(cfg.user));
          await cmd(235, b64(cfg.pass));
        }
      }
    }
    await cmd(250, `MAIL FROM:<${cfg.from}>`);
    await cmd(250, `RCPT TO:<${cfg.to}>`);
    await cmd(354, 'DATA');
    const headers = [
      `From: ${cfg.fromName || 'VNM Shield'} <${cfg.from}>`,
      `To: <${cfg.to}>`,
      `Subject: ${message.subject.replace(/[\r\n]/g, ' ')}`,
      `Date: ${new Date().toUTCString()}`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      '',
    ].join('\r\n');
    // Dot-stuffing per RFC 5321
    const body = message.body.replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..');
    socket.write(headers.join('') + body + '\r\n.\r\n');
    const done = await readReply();
    if (Math.floor(done.code / 100) !== 2) throw new Error('SMTP: message rejected ' + done.code);
    try { await cmd(221, 'QUIT'); } catch (e) { /* server may close first */ }
    socket.destroy();
    return { ok: true };
  } catch (e) {
    try { socket.destroy(); } catch (_) {}
    throw e;
  }
}

// ----------------------------------------------------------------------
// HTTPS POST helper (Discord / Telegram / generic webhook) - no axios
// dependency here so the watchdog process can use this module too.
// ----------------------------------------------------------------------
function httpPostJson(url, payload, timeoutMs) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch (e) { return reject(new Error('Invalid webhook URL')); }
    const mod = u.protocol === 'http:' ? http : https;
    const body = JSON.stringify(payload);
    const req = mod.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'http:' ? 80 : 443),
      path: u.pathname + u.search, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: timeoutMs || 10000,
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; if (data.length > 64 * 1024) req.destroy(); });
      res.on('end', () => (res.statusCode >= 200 && res.statusCode < 300)
        ? resolve({ ok: true, status: res.statusCode })
        : reject(new Error(`Webhook returned ${res.statusCode}: ${data.slice(0, 200)}`)));
    });
    req.on('timeout', () => { req.destroy(new Error('Webhook timeout')); });
    req.on('error', reject);
    req.end(body);
  });
}

// ----------------------------------------------------------------------
// Incident store + notifier
// ----------------------------------------------------------------------
module.exports = function createNotifier(ctx) {
  const db = ctx.db;
  const getSetting = ctx.getSetting;   // async (key) => string|null
  const log = (...a) => { try { console.log('[Shield:Notify]', ...a); } catch (e) {} };

  const dbGet = (sql, params) => new Promise((resolve, reject) => db.get(sql, params, (e, r) => e ? reject(e) : resolve(r)));
  const dbRun = (sql, params) => new Promise((resolve, reject) => db.run(sql, params, function (e) { e ? reject(e) : resolve(this); }));

  function ensureSchema() {
    return new Promise((resolve) => {
      db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS shield_incidents (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          incident_id TEXT UNIQUE NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          fingerprint TEXT NOT NULL,
          category TEXT,
          component TEXT,
          severity TEXT NOT NULL DEFAULT 'medium',
          title TEXT NOT NULL,
          explanation TEXT,
          confirmed_causes TEXT,
          possible_causes TEXT,
          suggested_fix TEXT,
          technical TEXT,
          status TEXT NOT NULL DEFAULT 'open',
          occurrences INTEGER DEFAULT 1,
          last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
          acked_by TEXT,
          resolved_at DATETIME,
          context TEXT
        )`, () => {
          db.run(`CREATE INDEX IF NOT EXISTS idx_shield_inc_fp ON shield_incidents(fingerprint)`, () => {
            db.run(`CREATE INDEX IF NOT EXISTS idx_shield_inc_status ON shield_incidents(status)`, () => resolve());
          });
        });
      });
    });
  }

  function severityRank(s) { const i = SEVERITIES.indexOf(String(s || 'info').toLowerCase()); return i < 0 ? 0 : i; }

  // ---- incident grouping ----
  // Groups by fingerprint. Repeats within the dedup window only bump
  // the occurrence counter (and escalate severity if worse); a
  // notification is only SENT when the incident is new or the window
  // has expired.
  async function recordIncident(diag, opts) {
    const options = opts || {};
    const dedupMs = parseInt(options.dedupMs ?? 30 * 60 * 1000, 10);
    const now = new Date().toISOString();
    const existing = await dbGet(
      `SELECT * FROM shield_incidents WHERE fingerprint = ? AND status != 'resolved' ORDER BY id DESC LIMIT 1`,
      [diag.fingerprint]);

    if (existing) {
      const lastSeen = existing.last_seen ? new Date(existing.last_seen.replace(' ', 'T') + (existing.last_seen.includes('Z') ? '' : 'Z')) : null;
      const fresh = lastSeen && (Date.now() - lastSeen.getTime() < dedupMs);
      const occurrences = (existing.occurrences || 1) + 1;
      const severity = severityRank(diag.severity) > severityRank(existing.severity) ? diag.severity : existing.severity;
      await dbRun(`UPDATE shield_incidents SET occurrences = ?, severity = ?, last_seen = ?, updated_at = ?,
        technical = COALESCE(?, technical), status = CASE WHEN status='resolved' THEN 'open' ELSE status END WHERE id = ?`,
        [occurrences, severity, now, now, JSON.stringify(diag.raw) || null, existing.id]);
      return { incident: { ...existing, occurrences, severity }, isNew: false, shouldNotify: !fresh || severityRank(severity) >= severityRank('critical') };
    }

    const incidentId = newIncidentId();
    const result = await dbRun(`INSERT INTO shield_incidents
      (incident_id, fingerprint, category, component, severity, title, explanation, confirmed_causes, possible_causes, suggested_fix, technical, status, occurrences, last_seen, context)
      VALUES (?,?,?,?,?,?,?,?,?,?,?, 'open', 1, ?, ?)`,
      [incidentId, diag.fingerprint, diag.category || 'panel', diag.component || 'panel',
       diag.severity || 'medium', diag.title || 'Untitled event',
       diag.explanation || '', JSON.stringify(diag.confirmed_causes || []),
       JSON.stringify(diag.possible_causes || []), diag.suggested_fix || '',
       JSON.stringify(diag.raw), now, diag.context || null]);
    return { incident: { id: result.lastID, incident_id: incidentId, ...diag }, isNew: true, shouldNotify: true };
  }

  // ---- channel senders ----
  async function sendDiscord(cfg, subject, body, severity) {
    const colors = { info: 0x3498db, low: 0x2ecc71, medium: 0xf39c12, high: 0xe67e22, critical: 0xe74c3c };
    await httpPostJson(cfg.url, {
      username: cfg.username || 'VNM Shield',
      embeds: [{
        title: subject.slice(0, 250),
        description: body.slice(0, 3500),
        color: colors[severity] || colors.medium,
        timestamp: new Date().toISOString(),
        footer: { text: 'VNM Panel - Shield' },
      }],
    });
  }

  async function sendTelegram(cfg, subject, body, severity) {
    const text = `*${subject}*\n(${severity.toUpperCase()})\n\n${body}`.slice(0, 4000);
    await httpPostJson(`https://api.telegram.org/bot${cfg.token}/sendMessage`, {
      chat_id: cfg.chatId, text, parse_mode: 'Markdown',
    });
  }

  async function sendWebhook(cfg, subject, body, severity, extra) {
    await httpPostJson(cfg.url, {
      source: 'vnm-shield', severity, subject, body, at: new Date().toISOString(),
      incident: extra && extra.incidentId, fingerprint: extra && extra.fingerprint,
    });
  }

  async function sendEmail(cfg, subject, body, severity) {
    await smtpSend({ ...cfg, timeoutMs: 15000 }, {
      subject: `[${severity.toUpperCase()}] ${subject}`,
      body: `${body}\n\n--\nVNM Panel Shield\nThis is an automated security/health notification.`,
    });
  }

  // ---- main entry point ----
  // event: { severity, title, body, diag? (a full diagnosis object),
  //          fingerprint?, category?, component?, channels?: ['discord',...] (optional override) }
  async function notify(event) {
    const severity = (event.severity || 'medium').toLowerCase();
    if (!SEVERITIES.includes(severity)) { log('unknown severity', severity); }

    let grouped = null;
    let shouldNotify = true;
    if (event.diag && event.diag.fingerprint) {
      try {
        grouped = await recordIncident(event.diag, { dedupMs: event.dedupMs });
        shouldNotify = grouped.shouldNotify;
      } catch (e) { log('incident recording failed (continuing):', e.message); }
    }

    if (!shouldNotify) return { sent: false, grouped: 'suppressed-duplicate' };

    const threshold = (await getSetting('shield.notify.minSeverity')) || 'low';
    if (severityRank(severity) < severityRank(threshold)) return { sent: false, grouped: grouped && grouped.incident, reason: 'below-threshold' };

    const subject = redact(event.title || 'Shield event').slice(0, 200);
    const body = redact(event.body || '').slice(0, 3800);
    const wanted = event.channels || ['discord', 'telegram', 'webhook', 'email'];
    const results = {};

    for (const channel of wanted) {
      try {
        if (channel === 'discord') {
          const url = await getSetting('shield.notify.discord.webhook');
          if (url) { await sendDiscord({ url }, subject, body, severity); results.discord = 'sent'; }
        } else if (channel === 'telegram') {
          const token = await getSetting('shield.notify.telegram.token');
          const chatId = await getSetting('shield.notify.telegram.chatId');
          if (token && chatId) { await sendTelegram({ token, chatId }, subject, body, severity); results.telegram = 'sent'; }
        } else if (channel === 'webhook') {
          const url = await getSetting('shield.notify.webhook.url');
          if (url) { await sendWebhook({ url }, subject, body, severity, { incidentId: grouped && grouped.incident.incident_id, fingerprint: event.diag && event.diag.fingerprint }); results.webhook = 'sent'; }
        } else if (channel === 'email') {
          const host = await getSetting('shield.notify.email.host');
          if (host) {
            const cfg = {
              host,
              port: await getSetting('shield.notify.email.port'),
              security: await getSetting('shield.notify.email.security') || 'starttls',
              user: await getSetting('shield.notify.email.user'),
              pass: await getSetting('shield.notify.email.pass'),
              from: await getSetting('shield.notify.email.from'),
              to: await getSetting('shield.notify.email.to'),
            };
            await sendEmail(cfg, subject, body, severity);
            results.email = 'sent';
          }
        }
      } catch (e) {
        results[channel] = 'error: ' + e.message.slice(0, 120);
        log(channel, 'failed:', e.message);
      }
    }
    return { sent: Object.values(results).some((r) => r === 'sent'), channels: results, grouped: grouped && grouped.incident };
  }

  // Test a channel from the settings UI (owner only route)
  async function sendTest(channel) {
    const subject = 'VNM Shield - test notification';
    const body = 'This is a test notification sent from the Shield settings page. If you can read this, the channel works.';
    const event = { severity: 'info', title: subject, body, channels: [channel], diag: null };
    return notify(event);
  }

  async function listIncidents(filter) {
    const f = filter || {};
    const where = []; const params = [];
    if (f.status) { where.push('status = ?'); params.push(f.status); }
    if (f.severity) { where.push('severity = ?'); params.push(f.severity); }
    if (f.category) { where.push('category = ?'); params.push(f.category); }
    if (f.q) { where.push('(title LIKE ? OR component LIKE ? OR incident_id LIKE ?)'); const q = `%${f.q}%`; params.push(q, q, q); }
    const sql = `SELECT * FROM shield_incidents ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      ORDER BY (CASE status WHEN 'open' THEN 0 WHEN 'acknowledged' THEN 1 ELSE 2 END) DESC, updated_at DESC LIMIT ? OFFSET ?`;
    params.push(parseInt(f.limit || 100, 10), parseInt(f.offset || 0, 10));
    return new Promise((resolve, reject) => db.all(sql, params, (e, r) => e ? reject(e) : resolve(r || [])));
  }

  async function updateIncidentStatus(id, status, by) {
    const now = new Date().toISOString();
    await dbRun(`UPDATE shield_incidents SET status = ?, acked_by = CASE WHEN ?='acknowledged' THEN ? ELSE acked_by END,
      resolved_at = CASE WHEN ?='resolved' THEN ? ELSE resolved_at END, updated_at = ? WHERE id = ?`,
      [status, status, by || null, status, now, now, id]);
    return dbGet(`SELECT * FROM shield_incidents WHERE id = ?`, [id]);
  }

  function exportIncidents() {
    return new Promise((resolve, reject) => db.all(
      `SELECT incident_id, created_at, updated_at, category, component, severity, title, explanation,
              confirmed_causes, possible_causes, suggested_fix, status, occurrences, last_seen
       FROM shield_incidents ORDER BY updated_at DESC LIMIT 5000`,
      (e, r) => e ? reject(e) : resolve(r || [])));
  }

  return { ensureSchema, notify, sendTest, recordIncident, listIncidents, updateIncidentStatus, exportIncidents, smtpSend, httpPostJson, severityRank, SEVERITIES };
};
