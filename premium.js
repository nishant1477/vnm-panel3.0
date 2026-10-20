/**
 * VNM Panel — Premium Features Licensing
 * ---------------------------------------------------------------------
 * Unlocks the panel's premium feature tier (Auto Backup, Live
 * Migration, Alert Rules, Scheduled Power) with a license key.
 *
 * SECURITY NOTES
 * - The license key itself is NEVER stored in this codebase, the DB,
 *   or any log. Only its SHA-256 digest is embedded below, and the
 *   digest is compared in constant time. The DB stores only a boolean
 *   activation flag + masked tail of the key (last 4 chars) — the same
 *   convention the panel license (licenses.js) uses.
 * - Validation is server-side only; the client just relays the key to
 *   POST /api/premium/activate.
 * - Key format is normalized (case-insensitive, dashes optional) before
 *   hashing so "fluse rrrrrry r32r22" style typos still validate, while
 *   the digest never appears in any client-readable payload.
 */

'use strict';

const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');

// ============= CONFIGURATION =============
// SHA-256 digest of the premium license key AFTER normalization
// (uppercased, all separators stripped) — which is exactly what
// normalizeKey() + digestOf() produce at validation time.
const PREMIUM_KEY_DIGEST = '2466b4a9b04a5b05416096637f7bc9a4ab3333555502b1c5203dff6ef9dff045';

// Premium feature registry — id, human label, one-line description
// used by the UI lock badges and the license modal.
const PREMIUM_FEATURES = [
  { id: 'auto_backup',     label: 'Auto Backup',       desc: 'Scheduled backups with retention windows — set it once, sleep well.' },
  { id: 'live_migration',  label: 'Live Migration',    desc: 'Move running VMs between nodes with no downtime.' },
  { id: 'alert_rules',     label: 'Alert Rules',       desc: 'Threshold alerts over email and Discord webhooks.' },
  { id: 'scheduled_power', label: 'Scheduled Power',   desc: 'Automatic start / stop / restart windows for VMs.' },
];
const PREMIUM_FEATURE_IDS = new Set(PREMIUM_FEATURES.map((f) => f.id));

const MAX_ACTIVATE_ATTEMPTS = 5;          // per rolling window
const ATTEMPT_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const DB_PATH = 'premium.db';

// ============= STATE =============
let _db = null;
let _state = { premium: false, activated_at: null, key_tail: '', activated_by: null };
const _attempts = []; // timestamps of failed activations (rate limit)

function normalizeKey(raw) {
  return String(raw || '')
    .trim()
    .toUpperCase()
    // strip everything that isn't [A-Z0-9] — dashes/spaces/dots all count
    // as separators in the printed key format
    .replace(/[^A-Z0-9]/g, '');
}

function digestOf(normalized) {
  return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex');
}

function timingSafeEq(a, b) {
  const A = Buffer.from(String(a), 'utf8');
  const B = Buffer.from(String(b), 'utf8');
  if (A.length !== B.length) {
    // still burn a comparison so the timing profile doesn't leak length
    crypto.timingSafeEqual(Buffer.alloc(32), Buffer.alloc(32));
    return false;
  }
  return crypto.timingSafeEqual(A, B);
}

// ============= STORAGE =============
const dbRun = (sql, p = []) => new Promise((res) => _db.run(sql, p, () => res()));
const dbGet = (sql, p = []) => new Promise((res, rej) => _db.get(sql, p, (e, r) => (e ? rej(e) : res(r))));

async function initPremiumStorage(customDbPath = null, sharedDb = null) {
  const dbPath = customDbPath || path.join(process.env.VNM_DATA_DIR || path.join(os.homedir(), '.vnm'), DB_PATH);
  try {
    if (sharedDb) {
      _db = sharedDb;
    } else {
      const dir = path.dirname(dbPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const sqlite3 = require('sqlite3').verbose();
      _db = new sqlite3.Database(dbPath);
    }
    await dbRun(`CREATE TABLE IF NOT EXISTS premium_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      premium INTEGER DEFAULT 0,
      activated_at TEXT,
      key_tail TEXT DEFAULT '',
      activated_by TEXT DEFAULT ''
    )`);
    // Seed the singleton row if it doesn't exist yet (fresh DBs) — see the
    // upsert comment by persist() for why this matters.
    await dbRun(`INSERT OR IGNORE INTO premium_state (id, premium, key_tail, activated_by) VALUES (1, 0, '', '')`);
    const row = await dbGet(`SELECT * FROM premium_state WHERE id = 1`).catch(() => null);
    if (row) {
      _state = {
        premium: !!row.premium,
        activated_at: row.activated_at || null,
        key_tail: row.key_tail || '',
        activated_by: row.activated_by || '',
      };
    }
    console.log(`[Premium] ready — tier: ${_state.premium ? 'PRO' : 'Free'}`);
  } catch (err) {
    console.warn('[Premium] DB init error (premium disabled this run):', err.message);
  }
}

async function persist() {
  if (!_db) return;
  // UPSERT, not UPDATE: on a fresh database the singleton row may not exist
  // yet (or was created before the seeding line above existed), in which
  // case a plain UPDATE silently matched 0 rows and the activation was lost
  // on the next panel restart — the exact bug found during verification.
  await dbRun(
    `INSERT INTO premium_state (id, premium, activated_at, key_tail, activated_by)
     VALUES (1, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET premium=excluded.premium, activated_at=excluded.activated_at, key_tail=excluded.key_tail, activated_by=excluded.activated_by`,
    [_state.premium ? 1 : 0, _state.activated_at, _state.key_tail, _state.activated_by]
  );
}

// ============= PUBLIC API =============
function isPremium() { return !!_state.premium; }

function hasFeature(featureId) {
  return PREMIUM_FEATURE_IDS.has(featureId) && _state.premium;
}

async function getStatus() {
  return {
    premium: _state.premium,
    activated_at: _state.activated_at,
    key_tail: _state.key_tail, // masked, last 4 chars only
    features: PREMIUM_FEATURES.map((f) => ({ ...f, unlocked: _state.premium })),
    product: 'VNM Panel Premium',
  };
}

function tooManyAttempts() {
  const now = Date.now();
  while (_attempts.length && now - _attempts[0] > ATTEMPT_WINDOW_MS) _attempts.shift();
  return _attempts.length >= MAX_ACTIVATE_ATTEMPTS;
}

async function activate(keyRaw, activatedBy = 'web') {
  const key = String(keyRaw || '').trim();
  if (!key) return { success: false, message: 'Enter your license key' };
  if (tooManyAttempts()) {
    return { success: false, message: 'Too many attempts. Try again later.' };
  }
  const digest = digestOf(normalizeKey(key));
  if (!timingSafeEq(digest, PREMIUM_KEY_DIGEST)) {
    _attempts.push(Date.now());
    // generic message — never hint at how close the key was
    return { success: false, message: 'That license key is not valid.' };
  }
  _state.premium = true;
  _state.activated_at = new Date().toISOString();
  _state.key_tail = key.replace(/[^A-Za-z0-9]/g, '').slice(-4);
  _state.activated_by = activatedBy;
  await persist();
  console.log(`[Premium] activated (${activatedBy}) — key tail ****${_state.key_tail}`);
  return { success: true, message: 'Premium unlocked. Enjoy the good stuff.', redirect: null };
}

async function deactivate(reason = '') {
  _state = { premium: false, activated_at: null, key_tail: '', activated_by: reason || '' };
  await persist();
  console.log('[Premium] deactivated' + (reason ? `: ${reason}` : ''));
  return true;
}

/**
 * Express middleware factory: blocks a route (or a route-condition) behind
 * a specific premium feature. Responds 402 with a machine-readable body:
 *   { premium_required: '<featureId>', feature: '<label>', message: ... }
 * so the shared frontend helper (vnm-premium.js) can pop the license modal.
 */
function requirePremiumFor(featureId, opts = {}) {
  const feature = PREMIUM_FEATURES.find((f) => f.id === featureId) || { id: featureId, label: featureId };
  return async (req, res, next) => {
    if (hasFeature(featureId)) return next();
    if (opts.condition && !opts.condition(req)) return next(); // feature not involved in this request
    return res.status(402).json({
      premium_required: feature.id,
      feature: feature.label,
      message: `${feature.label} is a premium feature. Unlock it with a VNM license key.`,
    });
  };
}

module.exports = {
  PREMIUM_FEATURES,
  initPremiumStorage,
  isPremium,
  hasFeature,
  getStatus,
  activate,
  deactivate,
  requirePremiumFor,
};
