// =====================================================================
// VNM — API Key authentication middleware
// ---------------------------------------------------------------------
// Mounted at /api BEFORE the CSRF middleware. Resolves
// `Authorization: Bearer vnmak_...` keys against the api_keys table,
// enforces scopes (read-only keys are rejected on mutating verbs with
// 403), and tags the request with req.bearerApiKey. app.js's patched
// checkAuth then turns a bearer-authenticated request into a synthetic
// per-request session, so every existing route - including per-VM
// ownership checks and admin gates - works unchanged for API clients.
//
// Lives in its own module (not inside platform.js) because it must be
// registered BEFORE the CSRF middleware, which itself is registered
// before the platform router is created.
// =====================================================================

'use strict';

module.exports = function createApiKeyAuth(db) {
  const crypto = require('crypto');

  return function apiKeyAuth(req, res, next) {
    // Already resolved (e.g. mounted twice) or not a Bearer request.
    if (req.bearerApiKey) return next();
    const header = req.get('authorization') || '';
    const m = /^Bearer\s+(vnmak_[A-Za-z0-9_]+)\s*$/i.exec(header);
    if (!m) return next();

    db.get(
      `SELECT k.*, u.username, u.role, u.is_active
       FROM api_keys k JOIN users u ON u.id = k.user_id
       WHERE k.key_hash = ?`,
      [crypto.createHash('sha256').update(m[1]).digest('hex')],
      (err, row) => {
        if (err || !row) {
          return res.status(401).json({ success: false, error: 'INVALID_API_KEY', message: 'Invalid API key' });
        }
        if (row.revoked) {
          return res.status(401).json({ success: false, error: 'API_KEY_REVOKED', message: 'This API key has been revoked' });
        }
        if (row.is_active === 0) {
          return res.status(401).json({ success: false, error: 'ACCOUNT_DISABLED', message: 'The account owning this key is disabled' });
        }
        if (row.expires_at && new Date(String(row.expires_at).replace(' ', 'T') + 'Z') < new Date()) {
          return res.status(401).json({ success: false, error: 'API_KEY_EXPIRED', message: 'This API key has expired' });
        }
        let scopes = ['read'];
        try { scopes = JSON.parse(row.scopes || '["read"]'); } catch (e) {}
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && !scopes.includes('write')) {
          return res.status(403).json({
            success: false, error: 'SCOPE_DENIED',
            message: `This API key is read-only (a "write" scope is required for ${req.method} requests)`
          });
        }
        req.bearerApiKey = { keyId: row.id, userId: row.user_id, username: row.username, role: row.role, scopes };
        db.run(`UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?`, [row.id]);
        next();
      }
    );
  };
};
