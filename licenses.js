/**
 * VNM Panel - License Client
 * ---------------------------------------------------------------------
 * Talks to a separately-deployed VNM License Server (see
 * license-server/) over its /v1/activate, /v1/check, /v1/deactivate
 * protocol. Caches the result locally (SQLite) so the panel keeps
 * working through a transient network blip or a license-server
 * restart, re-validating periodically in the background.
 *
 * If LICENSE_SERVER_URL is not set, licensing is treated as disabled
 * and the panel always reports itself activated - this is the safe
 * default so a panel deployed without a license server configured
 * doesn't lock its own admin out.
 */

const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');
const https = require('https');
const http = require('http');

// ============= CONFIGURATION =============
const LICENSE_SERVER_URL = (process.env.LICENSE_SERVER_URL || '').replace(/\/$/, '');
// Kept as "GVM-PANEL" by default intentionally - see license-server/README.txt.
const LICENSE_PRODUCT = process.env.LICENSE_PRODUCT || 'GVM-PANEL';
const RECHECK_INTERVAL = parseInt(process.env.LICENSE_RECHECK_MS || String(12 * 60 * 60 * 1000), 10); // 12h
const MAX_ENVELOPE_AGE = parseInt(process.env.LICENSE_GRACE_MS || String(72 * 60 * 60 * 1000), 10);   // 72h offline grace
const REQUEST_TIMEOUT_MS = 10000;
const PANEL_VERSION = 'VNM-V1.0';
const DB_PATH = 'license.db';

// ============= SIGNATURE VERIFICATION (Ed25519) =============
// If LICENSE_PUBLIC_KEY is set, the license server's response envelope
// must carry a valid signature or it is rejected outright - this closes
// two real gaps the previous unsigned client had: (1) a MITM'd or
// spoofed license server could simply reply {valid:true} and nothing
// stopped it, and (2) a customer could edit license.db's `activated`
// column directly to bypass the license forever. With a public key
// configured, isActivated() re-derives its answer from the stored
// SIGNED envelope every time, not from the plain `activated` column -
// editing that column alone no longer does anything.
//
// If LICENSE_PUBLIC_KEY is not set, the client falls back to the old
// trust-the-response behavior (still the safe default for a dev/test
// license server with no keypair generated yet - see
// license-server/ops_generate_keypair.py to generate one).
const LICENSE_PUBLIC_KEY_HEX = (process.env.LICENSE_PUBLIC_KEY || '').trim();
// RFC 8410 SubjectPublicKeyInfo prefix for a raw 32-byte Ed25519 public key.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
let _verifyPublicKey = null;
// Distinct from "no key configured" - this means an admin SET
// LICENSE_PUBLIC_KEY but it's malformed. That must never silently
// degrade to unsigned trust-mode (that would be a fail-open bug: a
// typo'd/corrupted key would quietly turn signature verification off
// entirely). Both verifyEnvelope() and isActivated() check this flag
// explicitly and refuse to activate/stay activated while it's set.
let _publicKeyConfiguredButInvalid = false;
if (LICENSE_PUBLIC_KEY_HEX) {
  try {
    const raw = Buffer.from(LICENSE_PUBLIC_KEY_HEX, 'hex');
    if (raw.length !== 32) throw new Error('must be 32 raw bytes (64 hex chars)');
    _verifyPublicKey = crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
  } catch (e) {
    _publicKeyConfiguredButInvalid = true;
    logger_bootstrap_error(`LICENSE_PUBLIC_KEY is set but invalid (${e.message}) - failing CLOSED: this panel will refuse to activate or stay activated until LICENSE_PUBLIC_KEY is fixed or removed.`);
  }
}
function logger_bootstrap_error(msg) { console.error('[License]', msg); }

function verifyEnvelope(body) {
  // Returns the parsed, verified envelope object, or null if verification
  // is required and fails (missing key config with a public key set,
  // bad signature, malformed JSON).
  if (_publicKeyConfiguredButInvalid) return { fields: null, verified: false, required: true };
  if (!_verifyPublicKey) return { fields: null, verified: false, required: false };
  if (!body || !body.signed_payload || !body.signature) return { fields: null, verified: false, required: true };
  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(body.signed_payload, 'utf8'), _verifyPublicKey, Buffer.from(body.signature, 'base64'));
  } catch (e) { ok = false; }
  if (!ok) return { fields: null, verified: false, required: true };
  let fields;
  try { fields = JSON.parse(body.signed_payload); } catch (e) { return { fields: null, verified: false, required: true }; }
  return { fields, verified: true, required: true };
}

const licensingEnabled = () => !!LICENSE_SERVER_URL;

// ============= LOGGER =============
const logger = {
  info: (...a) => console.log('[License]', ...a),
  warn: (...a) => console.warn('[License]', ...a),
  error: (...a) => console.error('[License]', ...a)
};

// ============= INSTALLATION ID =============
async function generateMachineIdFromHardware() {
  try {
    const hostname = os.hostname();
    const cpus = os.cpus();
    const cpuModel = (cpus[0] && cpus[0].model) || 'unknown';
    return crypto.createHash('sha256').update(`${hostname}-${cpuModel}-${os.platform()}-${os.arch()}`).digest('hex');
  } catch (e) {
    return 'local-machine-id';
  }
}

// ============= HTTP helper (no new dependency; works on any Node version) =============
function postJson(urlStr, body) {
  return new Promise((resolve, reject) => {
    let target;
    try { target = new URL(urlStr); } catch (e) { return reject(new Error('Invalid LICENSE_SERVER_URL')); }
    const lib = target.protocol === 'https:' ? https : http;
    const payload = Buffer.from(JSON.stringify(body));
    const req = lib.request(target, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length },
      timeout: REQUEST_TIMEOUT_MS
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch (e) { parsed = null; }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on('timeout', () => req.destroy(new Error('License server request timed out')));
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ============= STORAGE =============
let _db;
let _state = { activated: false, license_key: '', installation_id: '', owner: '', status: '', expires_at: null,
                max_activations: null, last_checked: null, last_validated: null, last_error: '',
                signed_envelope: '', envelope_signature: '' };

function dbRun(sql, params) { return new Promise((resolve) => _db.run(sql, params || [], () => resolve())); }
function dbGet(sql, params) { return new Promise((resolve) => _db.get(sql, params || [], (err, row) => resolve(err ? null : row))); }

async function initLicenseStorage(customDbPath = null, sharedDb = null) {
  // DEEP FIX: the same env var was read twice, making the chain a no-op;
  // it now matches app.js's data-dir convention.
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

    await dbRun(`CREATE TABLE IF NOT EXISTS license_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      activated INTEGER DEFAULT 0,
      license_key TEXT DEFAULT '',
      installation_id TEXT DEFAULT '',
      owner TEXT DEFAULT '',
      status TEXT DEFAULT '',
      expires_at TEXT,
      max_activations INTEGER,
      last_checked TEXT,
      last_validated TEXT,
      last_error TEXT
    )`);

    // Additive columns for signed-envelope verification (see verifyEnvelope
    // above) - mirrors the missingColumns ALTER pattern used elsewhere.
    await dbRun(`ALTER TABLE license_state ADD COLUMN signed_envelope TEXT DEFAULT ''`).catch(() => {});
    await dbRun(`ALTER TABLE license_state ADD COLUMN envelope_signature TEXT DEFAULT ''`).catch(() => {});

    const installationId = await generateMachineIdFromHardware();
    await dbRun(`INSERT OR IGNORE INTO license_state (id, installation_id) VALUES (1, ?)`, [installationId]);

    const row = await dbGet(`SELECT * FROM license_state WHERE id = 1`);
    if (row) {
      _state = {
        activated: !!row.activated, license_key: row.license_key || '', installation_id: row.installation_id || installationId,
        owner: row.owner || '', status: row.status || '', expires_at: row.expires_at || null,
        max_activations: row.max_activations, last_checked: row.last_checked, last_validated: row.last_validated,
        last_error: row.last_error || '', signed_envelope: row.signed_envelope || '', envelope_signature: row.envelope_signature || ''
      };
    }

    if (!licensingEnabled()) {
      logger.info('LICENSE_SERVER_URL not set - licensing disabled, panel runs unrestricted.');
    } else {
      logger.info(`Client ready - server=${LICENSE_SERVER_URL} product=${LICENSE_PRODUCT} installation=${_state.installation_id.slice(0, 12)}...`);
    }
  } catch (err) {
    logger.warn('DB init error (non-fatal, licensing disabled for this run):', err.message);
  }
}

async function persist() {
  if (!_db) return;
  await dbRun(
    `UPDATE license_state SET activated=?, license_key=?, owner=?, status=?, expires_at=?, max_activations=?, last_checked=?, last_validated=?, last_error=?, signed_envelope=?, envelope_signature=? WHERE id=1`,
    [_state.activated ? 1 : 0, _state.license_key, _state.owner, _state.status, _state.expires_at,
     _state.max_activations, _state.last_checked, _state.last_validated, _state.last_error,
     _state.signed_envelope || '', _state.envelope_signature || '']
  );
}

// ============= PUBLIC API =============
async function getMachineId() { return _state.installation_id || generateMachineIdFromHardware(); }

function withinGracePeriod(checkedAtIso) {
  if (!checkedAtIso) return false;
  return (Date.now() - new Date(checkedAtIso).getTime()) < MAX_ENVELOPE_AGE;
}

async function isActivated() {
  if (!licensingEnabled()) return true;

  // A misconfigured public key must never silently fall back to
  // trust-mode - see the comment by _publicKeyConfiguredButInvalid above.
  if (_publicKeyConfiguredButInvalid) return false;

  // Secure mode: LICENSE_PUBLIC_KEY is configured. Re-derive the answer
  // from the last SIGNED envelope on every check instead of trusting the
  // plain `activated` column - editing that column (or last_validated,
  // status, expires_at, etc.) directly in license.db no longer has any
  // effect, since none of those fields are consulted here.
  if (_verifyPublicKey) {
    if (!_state.signed_envelope || !_state.envelope_signature) return false;
    let ok = false;
    try {
      ok = crypto.verify(null, Buffer.from(_state.signed_envelope, 'utf8'), _verifyPublicKey, Buffer.from(_state.envelope_signature, 'base64'));
    } catch (e) { ok = false; }
    if (!ok) return false;
    let envelope;
    try { envelope = JSON.parse(_state.signed_envelope); } catch (e) { return false; }
    if (!envelope || envelope.valid !== true || envelope.status !== 'active') return false;
    if (envelope.installation_id !== _state.installation_id) return false;
    if (envelope.expires_at && Date.now() >= new Date(envelope.expires_at).getTime()) return false;
    // The envelope's own signed checked_at bounds how long we trust it
    // offline - this can't be extended by editing an unsigned column.
    return withinGracePeriod(envelope.checked_at);
  }

  // Trust mode (no public key configured yet): fall back to the plain
  // locally-stored state, same as before signing existed.
  return _state.activated && withinGracePeriod(_state.last_validated);
}

async function getState() { return { ..._state }; }

async function getStatusInfo() {
  return {
    activated: await isActivated(),
    owner: _state.owner || (licensingEnabled() ? '' : 'Unlicensed mode (no license server configured)'),
    status: _publicKeyConfiguredButInvalid ? 'invalid_public_key' : _state.status,
    expires_at: _state.expires_at,
    version: PANEL_VERSION,
    licensingEnabled: licensingEnabled(),
    configError: _publicKeyConfiguredButInvalid ? 'LICENSE_PUBLIC_KEY is set but malformed - fix or remove it to restore access.' : null
  };
}

async function activateWithServer(licenseKey, activatedBy = 'web') {
  if (!licensingEnabled()) return { success: true, message: 'Licensing is not enabled on this panel - nothing to activate.' };
  const key = String(licenseKey || '').trim();
  if (!key) return { success: false, message: 'Enter a license key' };

  const installationId = await getMachineId();
  let res;
  try {
    res = await postJson(`${LICENSE_SERVER_URL}/v1/activate`, { license_key: key, installation_id: installationId });
  } catch (e) {
    logger.error('Activation request failed:', e.message);
    return { success: false, message: `Could not reach the license server: ${e.message}` };
  }

  if (!res.body || !res.body.valid) {
    const message = (res.body && res.body.error) || `Activation failed (HTTP ${res.status})`;
    logger.warn(`Activation rejected: ${message}`);
    return { success: false, message };
  }

  const envelope = verifyEnvelope(res.body);
  if (envelope.required && !envelope.verified) {
    logger.error('Activation response failed signature verification - refusing to activate. Check LICENSE_PUBLIC_KEY matches the license server\'s keypair.');
    return { success: false, message: 'Could not verify the license server\'s response signature - activation refused.' };
  }
  if (envelope.verified && envelope.fields.installation_id !== installationId) {
    logger.error('Activation response envelope is for a different installation_id - refusing to activate.');
    return { success: false, message: 'License server response did not match this installation - activation refused.' };
  }

  _state.activated = true;
  _state.license_key = key;
  _state.owner = `License ending in ${key.slice(-4)}`;
  _state.status = res.body.status;
  _state.expires_at = res.body.expires_at || null;
  _state.max_activations = res.body.max_activations ?? null;
  _state.last_checked = new Date().toISOString();
  _state.last_validated = _state.last_checked;
  _state.last_error = '';
  _state.signed_envelope = envelope.verified ? res.body.signed_payload : '';
  _state.envelope_signature = envelope.verified ? res.body.signature : '';
  await persist();
  logger.info(`Activated (${activatedBy}), expires_at=${_state.expires_at || 'never'}${envelope.verified ? ' [signature verified]' : ''}`);
  return { success: true, message: 'License activated', redirect: '/dashboard' };
}

async function revalidateWithServer() {
  if (!licensingEnabled() || !_state.license_key) return { success: !licensingEnabled(), message: 'Nothing to validate' };
  let res;
  try {
    res = await postJson(`${LICENSE_SERVER_URL}/v1/check`, { license_key: _state.license_key, installation_id: _state.installation_id });
  } catch (e) {
    _state.last_error = e.message;
    await persist();
    logger.warn(`Revalidation failed (will retain activation for up to ${Math.round(MAX_ENVELOPE_AGE / 3600000)}h grace period): ${e.message}`);
    return { success: false, message: e.message };
  }

  _state.last_checked = new Date().toISOString();
  if (res.body && res.body.valid) {
    const envelope = verifyEnvelope(res.body);
    if (envelope.required && !envelope.verified) {
      const message = 'Revalidation response failed signature verification';
      _state.last_error = message;
      await persist();
      logger.warn(`${message} - keeping prior state through the grace period, but not extending it.`);
      return { success: false, message };
    }
    if (envelope.verified && envelope.fields.installation_id !== _state.installation_id) {
      const message = 'Revalidation response envelope is for a different installation_id';
      _state.last_error = message;
      await persist();
      logger.warn(message);
      return { success: false, message };
    }
    _state.activated = true;
    _state.status = res.body.status;
    _state.expires_at = res.body.expires_at || null;
    _state.last_validated = _state.last_checked;
    _state.last_error = '';
    if (envelope.verified) { _state.signed_envelope = res.body.signed_payload; _state.envelope_signature = res.body.signature; }
    await persist();
    return { success: true, message: 'License valid' };
  }

  const message = (res.body && res.body.error) || `Revalidation failed (HTTP ${res.status})`;
  _state.activated = false;
  _state.status = 'invalid';
  _state.last_error = message;
  await persist();
  logger.warn(`License no longer valid: ${message}`);
  return { success: false, message };
}

async function deactivateLocal(reason = '') {
  if (licensingEnabled() && _state.license_key) {
    try { await postJson(`${LICENSE_SERVER_URL}/v1/deactivate`, { license_key: _state.license_key, installation_id: _state.installation_id }); }
    catch (e) { logger.warn('Could not notify license server of deactivation:', e.message); }
  }
  _state.activated = false;
  _state.license_key = '';
  _state.owner = '';
  _state.status = 'deactivated';
  _state.last_error = reason;
  _state.signed_envelope = '';
  _state.envelope_signature = '';
  await persist();
  logger.info('Deactivated locally' + (reason ? `: ${reason}` : ''));
  return true;
}

let _revalidateTimer = null;
function startBackgroundRevalidation() {
  if (!licensingEnabled() || _revalidateTimer) return;
  _revalidateTimer = setInterval(() => { revalidateWithServer().catch((e) => logger.error('Background revalidation error:', e.message)); }, RECHECK_INTERVAL);
  _revalidateTimer.unref();
  logger.info(`Background revalidation scheduled every ${Math.round(RECHECK_INTERVAL / 3600000)}h`);
}

// Express middleware: gates authenticated traffic behind an active
// license. Unauthenticated requests (login page, etc.) are untouched -
// see initLicenseMiddleware()'s allowlist for exactly what's exempt.
function requiresLicense() {
  return async (req, res, next) => {
    if (!licensingEnabled()) return next();
    if (await isActivated()) return next();
    if (req.path.startsWith('/api/')) {
      return res.status(403).json({ error: 'License required', redirect: '/license_activation' });
    }
    return res.redirect('/license_activation');
  };
}

const LICENSE_ALLOWLIST = ['/license_activation', '/api/license/activate', '/api/license/status', '/api/logout', '/login', '/api/login', '/api/login/2fa'];

function initLicenseMiddleware(app) {
  if (!licensingEnabled()) {
    logger.info('Licensing disabled - no enforcement middleware active.');
    return;
  }
  const gate = requiresLicense();
  app.use((req, res, next) => {
    // Only gate requests from an already-authenticated session - an
    // unlicensed panel can still show its login page. Static assets and
    // the allowlisted license/auth endpoints are always reachable.
    if (!req.session || !req.session.userId) return next();
    if (LICENSE_ALLOWLIST.some((p) => req.path === p || req.path.startsWith(p))) return next();
    if (req.path.startsWith('/css/') || req.path.startsWith('/images/') || req.path.startsWith('/js/')) return next();
    return gate(req, res, next);
  });
  startBackgroundRevalidation();
  logger.info('Enforcement middleware active.');
}

function getServerUrl() { return LICENSE_SERVER_URL; }
function getPublicKeyFingerprint() { return LICENSE_PRODUCT; }

module.exports = {
  LICENSE_SERVER_URL, RECHECK_INTERVAL, MAX_ENVELOPE_AGE,
  initLicenseStorage, getMachineId, isActivated, getState, getStatusInfo,
  activateWithServer, revalidateWithServer, deactivateLocal,
  startBackgroundRevalidation, requiresLicense, initLicenseMiddleware,
  getServerUrl, getPublicKeyFingerprint, licensingEnabled
};
