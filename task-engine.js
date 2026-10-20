// =====================================================================
// VNM — Task Engine (Automation & Task Manager)
// ---------------------------------------------------------------------
// A small, persistent background job queue that powers the platform's
// long-running operations (backups, restores, clones, migrations,
// scheduled start/stop) with:
//   - progress reporting (0-100 + human text) polled by the UI
//   - cooperative cancellation (queued jobs cancel instantly; running
//     jobs see ctx.isCancelled() and stop at the next safe checkpoint)
//   - retry with backoff for transient failures (attempts < max_attempts)
//   - recurring schedules with a cron-lite spec:
//       'every:30m' | 'every:2h' | 'daily:03:30' | 'weekly:5:03:30'
//   - history retention (succeeded pruned after 14 days, all after 60)
//   - duplicate-job prevention (one RUNNING job per type+target at a
//     time; a second enqueue for the same pair is rejected with 409)
//
// Handlers are registered by platform.js via register(type, fn) so this
// module stays free of VM/QEMU knowledge.
// =====================================================================

'use strict';

const RETRY_BACKOFF_BASE_MS = 20 * 1000;   // attempt 1 waits 20s, attempt 2 waits 40s...
const RUNNER_INTERVAL_MS = 2000;
const SCHEDULER_INTERVAL_MS = 20 * 1000;
const MAX_CONCURRENT = 3;

function createTaskEngine({ db, logVMAction }) {
  const handlers = new Map();
  const running = new Set();          // task ids currently executing in this process
  const listeners = { 'task-completed': [], 'task-failed': [], 'task-cancelled': [] };
  let started = false;

  // ---------- promise-wrapped sqlite ----------
  const dbGet = (sql, params) => new Promise((resolve, reject) => db.get(sql, params, (e, r) => e ? reject(e) : resolve(r)));
  const dbAll = (sql, params) => new Promise((resolve, reject) => db.all(sql, params, (e, r) => e ? reject(e) : resolve(r || [])));
  const dbRun = (sql, params) => new Promise((resolve, reject) => db.run(sql, params, function (e) { e ? reject(e) : resolve(this); }));

  // ---------- schema ----------
  function ensureSchema() {
    return new Promise((resolve) => {
      db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS tasks (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          type TEXT NOT NULL,
          target_type TEXT DEFAULT 'vm',
          target_id INTEGER,
          label TEXT,
          params TEXT,
          status TEXT DEFAULT 'queued',
          progress INTEGER DEFAULT 0,
          progress_text TEXT,
          attempts INTEGER DEFAULT 0,
          max_attempts INTEGER DEFAULT 2,
          cancel_requested INTEGER DEFAULT 0,
          error TEXT,
          result TEXT,
          scheduled_for DATETIME,
          created_by INTEGER,
          created_by_name TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          started_at DATETIME,
          finished_at DATETIME
        )`, () => {
          db.run(`CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, scheduled_for)`, () => {
            db.run(`CREATE TABLE IF NOT EXISTS task_schedules (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              task_type TEXT NOT NULL,
              target_id INTEGER,
              params TEXT,
              schedule TEXT NOT NULL,
              enabled INTEGER DEFAULT 1,
              last_run DATETIME,
              next_run DATETIME,
              created_by INTEGER,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`, () => {
              db.run(`CREATE INDEX IF NOT EXISTS idx_schedules_due ON task_schedules(enabled, next_run)`, () => {
              // Round 5 fix: `result` column was missing from the very first
              // CREATE (found by e2e); additive ALTER keeps existing DBs.
              db.run(`ALTER TABLE tasks ADD COLUMN result TEXT`, (e2) => {
                if (e2 && !String(e2.message || '').includes('duplicate column')) console.log('[Tasks] result column:', e2.message);
                resolve();
              });
            });
            });
          });
        });
      });
    });
  }

  // ---------- events ----------
  function on(event, fn) { if (listeners[event]) listeners[event].push(fn); }
  function emit(event, payload) { (listeners[event] || []).forEach((fn) => { try { fn(payload); } catch (e) {} }); }

  // ---------- registration + enqueue ----------
  function register(type, fn) { handlers.set(type, fn); }
  function hasHandler(type) { return handlers.has(type); }

  async function enqueue({ type, targetType = 'vm', targetId = null, label = null, params = {}, createdBy = null, createdByName = null, scheduledFor = null }) {
    if (!handlers.has(type)) {
      const e = new Error(`Unknown task type "${type}"`);
      e.httpStatus = 400; e.code = 'UNKNOWN_TASK_TYPE';
      throw e;
    }
    // Duplicate-job prevention: reject if an identical type+target job is
    // already queued or running (a finished/cancelled/failed history row
    // never blocks a new run).
    if (targetId != null) {
      const dup = await dbGet(
        `SELECT id FROM tasks WHERE type = ? AND target_id = ? AND status IN ('queued','running') LIMIT 1`,
        [type, targetId]
      );
      if (dup) {
        const e = new Error(`A "${type}" task is already queued or running for this target (task #${dup.id})`);
        e.httpStatus = 409; e.code = 'TASK_ALREADY_RUNNING';
        throw e;
      }
    }
    const r = await dbRun(
      `INSERT INTO tasks (type, target_type, target_id, label, params, status, created_by, created_by_name, scheduled_for)
       VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?)`,
      [type, targetType, targetId, label || type, JSON.stringify(params || {}), createdBy, createdByName, scheduledFor || null]
    );
    tickRunner().catch(() => {});
    return getTask(r.lastID);
  }

  async function getTask(id) {
    const row = await dbGet(`SELECT * FROM tasks WHERE id = ?`, [id]);
    return row ? decorate(row) : null;
  }

  function decorate(row) {
    let params = {};
    try { params = JSON.parse(row.params || '{}'); } catch (e) {}
    return { ...row, params };
  }

  async function listTasks({ status, type, targetId, createdBy, limit = 100 } = {}) {
    const clauses = []; const p = [];
    if (status) { clauses.push('status = ?'); p.push(status); }
    if (type) { clauses.push('type = ?'); p.push(type); }
    if (targetId != null) { clauses.push('target_id = ?'); p.push(targetId); }
    if (createdBy != null) { clauses.push('(created_by = ? OR target_id IN (SELECT vm_id FROM vms WHERE owner_id = ?))'); p.push(createdBy, createdBy); }
    const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
    const cap = Math.min(parseInt(limit, 10) || 100, 500);
    const rows = await dbAll(`SELECT * FROM tasks ${where} ORDER BY id DESC LIMIT ?`, [...p, cap]);
    return rows.map(decorate);
  }

  // ---------- runner ----------
  async function claimDueTasks() {
    // Atomically flip due queued jobs to 'claimed' so only this loop
    // instance owns them (single sqlite writer makes this race-free).
    const due = await dbAll(
      `SELECT id FROM tasks WHERE status = 'queued' AND (scheduled_for IS NULL OR scheduled_for <= datetime('now')) ORDER BY id ASC LIMIT ?`,
      [MAX_CONCURRENT]
    );
    const claimed = [];
    for (const row of due) {
      if (running.has(row.id)) continue; // already executing here
      const r = await dbRun(`UPDATE tasks SET status = 'claimed' WHERE id = ? AND status = 'queued'`, [row.id]);
      if (r.changes === 1) claimed.push(row.id);
    }
    return claimed;
  }

  async function tickRunner() {
    if (!started) return;
    let ids;
    try { ids = await claimDueTasks(); } catch (e) { return; }
    for (const id of ids) executeTask(id).catch(() => {});
  }

  async function executeTask(id) {
    const job = await getTask(id);
    if (!job) return;
    const handler = handlers.get(job.type);
    if (!handler) {
      await dbRun(`UPDATE tasks SET status='failed', error='No handler registered', finished_at=CURRENT_TIMESTAMP WHERE id = ?`, [id]);
      return;
    }

    // Live cancellation between claim and start.
    if (job.cancel_requested) {
      await dbRun(`UPDATE tasks SET status='cancelled', finished_at=CURRENT_TIMESTAMP WHERE id = ?`, [id]);
      emit('task-cancelled', job);
      return;
    }

    running.add(id);
    const attempts = (job.attempts || 0) + 1;
    await dbRun(`UPDATE tasks SET status='running', attempts = ?, started_at=CURRENT_TIMESTAMP, error = NULL WHERE id = ?`, [attempts, id]);

    let lastProgressAt = 0;
    const ctx = {
      setProgress: (pct, text) => {
        const p = Math.max(0, Math.min(100, Math.round(pct)));
        // Rate-limit progress writes to ~1 per 400ms; final (100) always writes.
        const now = Date.now();
        if (p < 100 && now - lastProgressAt < 400) return;
        lastProgressAt = now;
        dbRun(`UPDATE tasks SET progress = ?, progress_text = ? WHERE id = ?`, [p, text ? String(text).slice(0, 200) : null, id]).catch(() => {});
      },
      isCancelled: async () => {
        const row = await dbGet(`SELECT cancel_requested FROM tasks WHERE id = ?`, [id]);
        return !!(row && row.cancel_requested);
      },
      checkCancelled: async () => {
        if (await ctx.isCancelled()) {
          const err = new Error('Task cancelled');
          err.cancelled = true;
          throw err;
        }
      },
      job,
    };

    try {
      const result = await handler(job, ctx);
      await dbRun(
        `UPDATE tasks SET status='succeeded', progress=100, progress_text=?, finished_at=CURRENT_TIMESTAMP, result=? WHERE id = ?`,
        [result && result.message ? String(result.message).slice(0, 200) : null, JSON.stringify(result || {}), id]
      );
      emit('task-completed', { ...job, result });
      if (job.target_type === 'vm' && job.target_id != null && logVMAction) {
        logVMAction(job.target_id, job.type.replace(/\./g, '_'), 'completed', result && result.message ? result.message : `Task ${job.type} completed`);
      }
    } catch (err) {
      if (err && err.cancelled) {
        await dbRun(`UPDATE tasks SET status='cancelled', finished_at=CURRENT_TIMESTAMP, error='Cancelled by user' WHERE id = ?`, [id]);
        emit('task-cancelled', job);
        if (job.target_type === 'vm' && job.target_id != null && logVMAction) {
          logVMAction(job.target_id, job.type.replace(/\./g, '_'), 'cancelled', 'Task cancelled');
        }
        return;
      }
      const canRetry = attempts < (job.max_attempts || 2) && !(err && err.noRetry);
      if (canRetry) {
        const backoffMs = RETRY_BACKOFF_BASE_MS * attempts;
        const next = new Date(Date.now() + backoffMs).toISOString().slice(0, 19).replace('T', ' ');
        await dbRun(
          `UPDATE tasks SET status='queued', error=?, progress=0, scheduled_for=?, progress_text=? WHERE id = ?`,
          [String(err.message || err).slice(0, 500), next, `Retry ${attempts} of ${job.max_attempts || 2} scheduled`, id]
        );
        console.warn(`[Tasks] #${id} (${job.type}) failed (attempt ${attempts}) - retrying in ${Math.round(backoffMs / 1000)}s: ${err.message}`);
      } else {
        await dbRun(
          `UPDATE tasks SET status='failed', error=?, finished_at=CURRENT_TIMESTAMP WHERE id = ?`,
          [String(err.message || err).slice(0, 500), id]
        );
        emit('task-failed', { ...job, error: err.message });
        if (job.target_type === 'vm' && job.target_id != null && logVMAction) {
          logVMAction(job.target_id, job.type.replace(/\./g, '_'), 'failed', err.message);
        }
        console.error(`[Tasks] #${id} (${job.type}) FAILED: ${err.message}`);
      }
    } finally {
      running.delete(id);
    }
  }

  // ---------- cancellation / retry ----------
  async function cancelTask(id) {
    const job = await getTask(id);
    if (!job) { const e = new Error('Task not found'); e.httpStatus = 404; throw e; }
    if (job.status === 'queued' || job.status === 'claimed') {
      await dbRun(`UPDATE tasks SET status='cancelled', finished_at=CURRENT_TIMESTAMP WHERE id = ?`, [id]);
      emit('task-cancelled', job);
      return { cancelled: true, status: 'cancelled' };
    }
    if (job.status === 'running') {
      await dbRun(`UPDATE tasks SET cancel_requested = 1 WHERE id = ?`, [id]);
      return { cancelling: true, status: 'running' };
    }
    const e = new Error(`Task is already ${job.status}`);
    e.httpStatus = 409; e.code = 'TASK_NOT_ACTIVE';
    throw e;
  }

  async function retryTask(id) {
    const job = await getTask(id);
    if (!job) { const e = new Error('Task not found'); e.httpStatus = 404; throw e; }
    if (job.status !== 'failed' && job.status !== 'cancelled') {
      const e = new Error('Only failed or cancelled tasks can be retried');
      e.httpStatus = 409; e.code = 'TASK_NOT_RETRYABLE';
      throw e;
    }
    await dbRun(
      `UPDATE tasks SET status='queued', progress=0, progress_text=NULL, error=NULL, cancel_requested=0, attempts=0, scheduled_for=NULL, finished_at=NULL WHERE id = ?`,
      [id]
    );
    tickRunner().catch(() => {});
    return getTask(id);
  }

  // ---------- schedules ----------
  function parseScheduleSpec(spec) {
    const bad = (msg) => { const e = new Error(msg); e.httpStatus = 400; e.code = 'INVALID_SCHEDULE'; return e; };
    const s = String(spec || '').trim().toLowerCase();
    let m;
    if ((m = /^every:(\d+)(m|h)$/.exec(s))) {
      const n = parseInt(m[1], 10); const unit = m[2];
      const ms = unit === 'h' ? n * 3600e3 : n * 60e3;
      if (ms < 5 * 60e3) throw bad('Minimum schedule interval is 5 minutes');
      return { kind: 'interval', ms, describe: `every ${n}${unit}` };
    }
    if ((m = /^daily:(\d{1,2}):(\d{2})$/.exec(s))) {
      const hh = parseInt(m[1], 10), mm = parseInt(m[2], 10);
      if (hh > 23 || mm > 59) throw bad('Invalid daily time');
      return { kind: 'daily', hh, mm, describe: `daily at ${String(hh).padStart(2, '0')}:${String(mm).padStart(2, '0')}` };
    }
    if ((m = /^weekly:(\d):(\d{1,2}):(\d{2})$/.exec(s))) {
      const d = parseInt(m[1], 10), hh = parseInt(m[2], 10), mm = parseInt(m[3], 10);
      if (d < 1 || d > 7 || hh > 23 || mm > 59) throw bad('Invalid weekly spec (day 1=Monday .. 7=Sunday)');
      const names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
      return { kind: 'weekly', day: d, hh, mm, describe: `weekly on ${names[d - 1]} at ${String(hh).padStart(2, '0')}:${String(mm).padStart(2, '0')}` };
    }
    throw bad(`Invalid schedule "${spec}" - use every:30m, every:2h, daily:03:30 or weekly:5:03:30`);
  }

  function nextRunFor(spec, from = new Date()) {
    const parsed = parseScheduleSpec(spec);
    const d = new Date(from);
    if (parsed.kind === 'interval') return new Date(d.getTime() + parsed.ms);
    if (parsed.kind === 'daily') {
      d.setHours(parsed.hh, parsed.mm, 0, 0);
      if (d <= from) d.setDate(d.getDate() + 1);
      return d;
    }
    // weekly: JS getDay(): Sun=0..Sat=6 -> spec day 1=Mon..7=Sun
    const jsDay = parsed.day === 7 ? 0 : parsed.day;
    d.setHours(parsed.hh, parsed.mm, 0, 0);
    let add = (jsDay - d.getDay() + 7) % 7;
    if (add === 0 && d <= from) add = 7;
    d.setDate(d.getDate() + add);
    return d;
  }

  async function createSchedule({ name, taskType, targetId = null, params = {}, schedule, createdBy = null, enabled = true }) {
    if (!handlers.has(taskType)) {
      const e = new Error(`Unknown task type "${taskType}"`); e.httpStatus = 400; e.code = 'UNKNOWN_TASK_TYPE'; throw e;
    }
    const parsed = parseScheduleSpec(schedule); // validates
    const next = nextRunFor(schedule);
    const r = await dbRun(
      `INSERT INTO task_schedules (name, task_type, target_id, params, schedule, enabled, next_run, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [name, taskType, targetId, JSON.stringify(params || {}), schedule, enabled ? 1 : 0, sqlNow(next), createdBy]
    );
    return getSchedule(r.lastID);
  }

  const sqlNow = (d) => new Date(d).toISOString().slice(0, 19).replace('T', ' ');

  async function getSchedule(id) { return dbGet(`SELECT * FROM task_schedules WHERE id = ?`, [id]); }
  async function listSchedules() {
    const rows = await dbAll(`SELECT s.*, v.vm_name FROM task_schedules s LEFT JOIN vms v ON v.vm_id = s.target_id ORDER BY s.id ASC`, []);
    // ROBUSTNESS: one legacy/invalid spec string in the table (e.g. an old
    // "weekly:0:..." row written before the 1-7 day range was enforced)
    // used to make this whole GET throw, so the Tasks/Backups pages showed
    // "Could not load schedules" for EVERY user. Degrade per-row instead:
    // a bad row gets a human string of "(invalid spec)" and keeps the raw
    // value visible; healthy rows are unaffected.
    return rows.map((r) => {
      let p = {}; try { p = JSON.parse(r.params || '{}'); } catch (e) { p = {}; }
      let schedule_human;
      try { schedule_human = parseScheduleSpec(r.schedule).describe; }
      catch (e) { schedule_human = `(invalid spec: ${String(r.schedule || '').slice(0, 24)})`; }
      return { ...r, params: p, schedule_human };
    });
  }
  async function updateSchedule(id, { name, schedule, enabled, params }) {
    const s = await getSchedule(id);
    if (!s) { const e = new Error('Schedule not found'); e.httpStatus = 404; throw e; }
    const nextSpec = schedule || s.schedule;
    parseScheduleSpec(nextSpec);
    await dbRun(
      `UPDATE task_schedules SET name = ?, schedule = ?, enabled = ?, params = ?, next_run = CASE WHEN ? THEN ? ELSE next_run END WHERE id = ?`,
      [name || s.name, nextSpec, enabled === undefined ? s.enabled : (enabled ? 1 : 0),
       params ? JSON.stringify(params) : s.params,
       schedule ? 1 : 0, sqlNow(nextRunFor(nextSpec)), id]
    );
    return getSchedule(id);
  }
  async function deleteSchedule(id) {
    const r = await dbRun(`DELETE FROM task_schedules WHERE id = ?`, [id]);
    if (!r.changes) { const e = new Error('Schedule not found'); e.httpStatus = 404; throw e; }
  }
  async function runScheduleNow(id) {
    const s = await getSchedule(id);
    if (!s) { const e = new Error('Schedule not found'); e.httpStatus = 404; throw e; }
    let params = {}; try { params = JSON.parse(s.params || '{}'); } catch (e) {}
    return enqueue({
      type: s.task_type, targetId: s.target_id, label: s.name + ' (manual run)',
      params, createdBy: s.created_by, createdByName: 'schedule:' + s.name
    });
  }

  async function tickSchedules() {
    if (!started) return;
    const due = await dbAll(`SELECT * FROM task_schedules WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= datetime('now')`, []);
    for (const s of due) {
      try {
        let params = {}; try { params = JSON.parse(s.params || '{}'); } catch (e) {}
        // Skip if an instance of this schedule's task is already active.
        const active = await dbGet(
          `SELECT id FROM tasks WHERE type = ? AND target_id IS ? AND status IN ('queued','running') LIMIT 1`,
          [s.task_type, s.target_id]
        );
        if (!active) {
          await enqueue({ type: s.task_type, targetId: s.target_id, label: s.name + ' (scheduled)', params, createdBy: s.created_by, createdByName: 'schedule:' + s.name });
        }
        await dbRun(`UPDATE task_schedules SET last_run = datetime('now'), next_run = ? WHERE id = ?`, [sqlNow(nextRunFor(s.schedule)), s.id]);
      } catch (e) {
        console.warn(`[Tasks] Schedule #${s.id} ("${s.name}") could not run: ${e.message}`);
        await dbRun(`UPDATE task_schedules SET next_run = ? WHERE id = ?`, [sqlNow(nextRunFor(s.schedule)), s.id]).catch(() => {});
      }
    }
  }

  // ---------- retention ----------
  async function pruneHistory() {
    await dbRun(`DELETE FROM tasks WHERE status IN ('succeeded','cancelled') AND finished_at < datetime('now', '-14 days')`, []).catch(() => {});
    await dbRun(`DELETE FROM tasks WHERE finished_at < datetime('now', '-60 days')`, []).catch(() => {});
  }

  // ---------- lifecycle ----------
  function start() {
    if (started) return;
    started = true;
    // Recover jobs left 'running' by a previous process crash: retry them.
    db.run(`UPDATE tasks SET status='queued', progress=0, progress_text='Re-queued after panel restart' WHERE status IN ('running','claimed')`, (err) => {
      if (!err && this && this.changes) console.log(`[Tasks] Recovered ${this.changes} interrupted task(s) after restart`);
    });
    setInterval(tickRunner, RUNNER_INTERVAL_MS).unref();
    setInterval(tickSchedules, SCHEDULER_INTERVAL_MS).unref();
    setInterval(pruneHistory, 12 * 3600 * 1000).unref();
    pruneHistory().catch(() => {});
    console.log('[Tasks] Task engine started (runner + scheduler + retention)');
  }

  return {
    ensureSchema, start, register, hasHandler, on,
    enqueue, getTask, listTasks, cancelTask, retryTask,
    createSchedule, getSchedule, listSchedules, updateSchedule, deleteSchedule, runScheduleNow,
    parseScheduleSpec, nextRunFor,
  };
}

module.exports = createTaskEngine;
