// =====================================================================
// VNM — Audit log
// ---------------------------------------------------------------------
// Records who did what, from where, and whether it succeeded, for the
// actions that actually matter for security/troubleshooting: logins,
// VM lifecycle, user management, settings changes, and node
// management. Never logs passwords, tokens, or session secrets - only
// identifiers and outcomes.
// =====================================================================

module.exports = function createAuditLog(db) {
  function ensureSchema() {
    return new Promise((resolve) => {
      db.run(`CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        username TEXT,
        action TEXT NOT NULL,
        target_type TEXT,
        target_id TEXT,
        ip TEXT,
        result TEXT NOT NULL DEFAULT 'success',
        details TEXT
      )`, () => {
        db.run(`CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)`, () => resolve());
      });
    });
  }

  // entry: { userId, username, action, targetType, targetId, ip, result, details }
  function log(entry) {
    const details = entry.details ? String(entry.details).slice(0, 500) : null;
    db.run(
      `INSERT INTO audit_log (user_id, username, action, target_type, target_id, ip, result, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [entry.userId || null, entry.username || null, entry.action, entry.targetType || null,
       entry.targetId !== undefined && entry.targetId !== null ? String(entry.targetId) : null,
       entry.ip || null, entry.result || 'success', details],
      (err) => { if (err) console.error('[Audit] Failed to write audit entry:', err.message); }
    );
  }

  // Convenience: builds { userId, username, ip } from an authenticated request.
  function fromReq(req) {
    return { userId: req.session?.userId || null, username: req.session?.username || null, ip: req.ip };
  }

  function query({ limit, before, action, username } = {}) {
    return new Promise((resolve, reject) => {
      const clauses = [];
      const params = [];
      if (before) { clauses.push('id < ?'); params.push(before); }
      if (action) { clauses.push('action = ?'); params.push(action); }
      if (username) { clauses.push('username = ?'); params.push(username); }
      const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
      const cap = Math.min(parseInt(limit, 10) || 100, 500);
      db.all(`SELECT * FROM audit_log ${where} ORDER BY id DESC LIMIT ?`, [...params, cap], (err, rows) => {
        err ? reject(err) : resolve(rows);
      });
    });
  }

  return { ensureSchema, log, fromReq, query };
};
