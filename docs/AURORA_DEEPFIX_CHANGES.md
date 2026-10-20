# VNM Panel — Aurora Design System + Deep Bug Fix Round (Round 4)

Two work streams in this round: a complete visual redesign with motion
design, and a systematic deep-bug hunt across the whole codebase.

---

## PART 1 — "Aurora" UI/UX Redesign + Motion System

### New files
| File | Purpose |
|------|---------|
| `public/css/vnm-motion.css` (~1,470 lines) | The Aurora design system: full token redefinition (dark + light), glassmorphism components, and the complete motion layer. Loaded AFTER `admin.css` in every view, so zero markup/JS changes were needed and nothing functional could break. |
| `public/js/vnm-motion.js` | Progressive-enhancement motion runtime: ripples, count-up numbers, scroll reveal, 3D card tilt, page-exit transitions, dynamic-card stagger. Zero dependencies, fully degrades, respects `prefers-reduced-motion`. |

### Design language
- **Palette**: pure-black theme replaced by deep-space navy (`#05070f`) with a
  drifting aurora background (cyan → indigo → violet radial fields, 26s loop)
  + SVG noise layer to kill gradient banding. Light theme is a matching
  "frost" variant.
- **Signature gradient**: `#22d3ee → #818cf8 → #c084fc` used on the primary
  buttons, active nav pill, badges, progress bars, and brand text.
- **Glassmorphism**: cards, sidebar, header, modals, toasts and dropdowns all
  use `backdrop-filter: blur(22px) saturate(1.45)` over translucent navy.
- **Aurora hairlines**: 1px gradient lines on card top edges, under the
  header, and along the sidebar's right edge.
- **Brand**: sidebar brand chips now use the aurora treatment (both partials),
  matching the Round-3 VNM logo.

### Motion system (highlights)
- **Entrance choreography**: header slides down, sidebar nav items stagger in,
  content cards rise with sequential delays, login card springs in with a
  rotating conic glow ring behind it.
- **Micro-interactions**: button shine-sweep + material ripple + press scale;
  card hover lift + border glow + icon tilt; nav hover nudge; avatar spin;
  modal-close rotate-90°; toast slide-in with spring + life progress bar.
- **Alive-at-rest**: aurora background drift, status-dot pulse rings, wizard
  step pulse, shimmer skeletons, animated gradient progress bars, blinking
  terminal cursor, floating empty-state icons.
- **3D tilt**: stat/VM/template cards tilt up to 3.2° toward the cursor
  (pointer devices only).
- **Count-up**: stat numbers animate from 0 with easeOutCubic + a cyan flash.
- **Scroll reveal**: below-the-fold cards rise in via IntersectionObserver
  (only elements NOT already covered by the load stagger).
- **Page transitions**: content dips out (200ms) on same-origin navigation.
- **Accessibility**: `prefers-reduced-motion: reduce` disables ALL of the
  above; print styles strip the background effects.

### Views wired
All **30 page views** (admin + users + auth pages) now load
`/css/vnm-motion.css` + `/js/vnm-motion.js` — injected right after
`admin.css` and before `</body>` respectively (idempotent patch script
`scripts/30-wire-theme.js`).

---

## PART 2 — Deep Bug Fix Round (26 confirmed bugs fixed)

Two parallel read-only audits (full app.js line-by-line; every helper module)
confirmed 26 real bugs. All fixed, each verified by automated tests.

### Request-hanging unhandled rejections (4)
1. **start/stop/restart VM** — `await nodeManager.getNodeForVM(vm)` inside
   db callbacks with no catch: a DB error hung the request forever. → guarded,
   now returns 502 `NODE_LOOKUP_FAILED`. (app.js ×3 sites)
2. **POST /api/vms** — top-level awaits (template lookup, local-node lookup)
   unguarded. → both wrapped; failures return 500/`null`-fallback.
3. **GET /api/nodes/agent-package** — token verification unguarded. → guarded.
4. **validateImageFile** — `statSync` TOCTOU (cache cleared mid-poll) threw
   out of a "never-throws" helper. → stat inside try.

### Security (2)
5. **IDOR — GET /api/vms/:id/console**: any authenticated user could read any
   VM's serial log (boot output + every keystroke). → ownership check added.
6. **WS console auth race**: the input handler was registered BEFORE the
   async ownership check completed, so a rejected client could inject
   keystrokes into someone else's QEMU stdin during the check window.
   → client registration + input acceptance now happen only after the check
   passes (verified by an automated race test).
7. **GET /api/admin/templates/:key/status** was missing `checkAdmin`. → added.

### Data loss / wrong behavior (6)
8. **Reinstall was non-atomic** — old disk deleted before the new image was
   built; a failed download = permanent data loss; node-offline left the DB
   claiming a template the disk didn't have. → old artifacts are now staged
   aside (`.reinstall-bak`), every failure path rolls back (files + DB row),
   success discards the backup.
9. **VNC display allocation race** — two concurrent starts won the same
   display. → synchronous reservation before the async probe.
10. **SSH port allocation race** — concurrent creates all claimed the same
    port (no UNIQUE index). → module-level in-flight reservation set; the
    e2e test caught and fixed a first-attempt flaw (handler-scoped Set was
    invisible to other requests).
11. **PUT /api/admin/users/:id with empty body** built `UPDATE users SE
    WHERE...` → 500. → explicit 400.
12. **Console watcher** counted `initialSize` in UTF-16 units but compared
    against byte sizes → duplicated first tick on multi-byte logs. →
    `Buffer.byteLength`.
13. **/api/2fa/status** reported `{enabled:false}` on DB errors. → 500.

### Wedges / reconnect bugs (4)
14. **Agent stopped reconnecting forever** after an HTTP-level WebSocket
    rejection (proxy 502, panel 401) — ws emits neither close nor error when
    `unexpected-response` is handled. → explicit destroy + reconnect, and
    `scheduleReconnect` made idempotent.
15. **Node reconnect leak** — the old connection's stale-heartbeat timer
    survived `removeAllListeners()` and disconnected the NEW connection ≤45s
    later. → timer stored on the entry and cleared on replacement/disconnect.
16. **Agent registration order** — a failed "mark online" DB write left a
    wedged online-looking node with no message listener. → guarded; drops the
    connection on failure.
17. **5-minute "idle" timeouts were hard total caps** — 4 GB uploads over WAN
    were killed mid-transfer. → timers now refresh on activity (true idle).

### Leaks / hygiene (5)
18. **SSH REST sessions** leaked on clean close (ssh2 emits `close`, not
    `error`) → `close` listener added.
19. **migrationJobs map** grew forever → terminal jobs pruned after 30 min.
20. **Agent transfers**: only disk uploads were cleaned on disconnect — file
    uploads leaked streams, vnc/tcp relays leaked QEMU sockets → all kinds
    cleaned.
21. **qemu-launcher log streams** never closed (fd leak → EMFILE) →
    `logStream.end()` on exit.
22. **licenses.js** read `VNM_DATA_DIR || VNM_DATA_DIR` (dead fallback) →
    fixed to match app.js's convention.

### Startup robustness (2)
23. **PRAGMA table_info(users)** callback dereferenced `columns` without an
    err check → guarded.
24. **Template duplicate-key check** ignored DB errors and proceeded to
    INSERT → guarded.

### Verification (all automated, all green)
| Suite | Result |
|-------|--------|
| New deep-fix e2e (`scripts/36-verify-deepfix.js`): IDOR, WS race, 400-on-empty-body, admin-only template status, 4-way concurrent port allocation, agent-package auth, 2FA | **17/17** |
| Node-agent regression e2e (create on node, real SSH relay, ISO stream, delete cleanup, local path) | **50/50** |
| Networking regression e2e (NIC models, port forwards, validation, PORT_IN_USE) | **31/31** |
| EJS compile (all 34 views) | **34/34** |
| `node --check` every JS file | all OK |

### Fresh screenshots (new design)
10 full-page screenshots in `screenshots/` (login, admin dashboard/vms/
create/networking-step/nodes/vm-detail/ssh, user dashboard/vms) — VLM-verified:
deep-navy Aurora theme, glass cards, gradient accents, active-nav glow, no
broken or unstyled elements, 9/10 quality scores across the board.
