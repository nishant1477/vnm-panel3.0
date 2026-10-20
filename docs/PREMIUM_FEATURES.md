# VNM Panel — Premium Features (License Key)

## What is premium?

VNM Panel now has a two-tier model:

| Tier | Included |
|------|----------|
| **Free** | everything core: VMs, console/VNC/RDP/SSH, manual backups + snapshots, ISO library, users, nodes, firewall, file manager, audit log, API keys |
| **Premium (PRO)** | **Auto Backup** (scheduled backups with retention), **Live Migration** (move VMs between nodes), **Alert Rules** (threshold alerts + Discord webhook), **Scheduled Power** (auto start/stop/restart) |

One license key unlocks the whole tier. The key is never stored or logged in
plaintext anywhere — the panel keeps only its SHA-256 digest
(`premium.js`), compares it in constant time, and the database records just a
boolean plus the masked last 4 characters of the key.

## Where premium shows up in the UI

- **Backup Center** — an "Auto Backup" card. While locked it shows a gold
  veil with an **Unlock with license key** button; clicking it opens the
  license modal. Once unlocked the card becomes a full schedule builder
  (VM + rhythm + retention) and lists existing schedules.
- **Task Automation** — schedule task types are marked `· PRO` while locked;
  creating one opens the license modal (the server also answers `402` with a
  machine-readable `premium_required` field, which the frontend intercepts
  globally — so even a forgotten pre-check pops the modal).
- **Monitoring** — "Alert Rules" carries a Premium chip; "New Rule" opens the
  license modal while locked.
- **VM Details → Migrate** — the migrate flow is premium; when unlocked it
  opens a proper node-picker modal (recommended node starred) instead of the
  old text prompt.
- **Header** — a gold **PRO** chip appears next to your username while
  premium is active.
- **User menu → License** — opens the license manager (status, masked key
  tail, deactivate for admins).

## Server-side enforcement (cannot be bypassed from the client)

| Endpoint | Gate |
|----------|------|
| `POST /api/task-schedules` (`vm.backup`) | `auto_backup` |
| `POST /api/task-schedules` (`vm.start/stop/restart`) | `scheduled_power` |
| `PUT /api/task-schedules/:id` (enable) | same as its type |
| `POST /api/task-schedules/:id/run` | same as its type |
| `POST /api/vms/:id/migrate` | `live_migration` |
| `POST /api/alert-rules`, `PUT /api/alert-rules/:id` | `alert_rules` |

All of them respond **HTTP 402** with `{ premium_required, feature, message }`.

## API

- `GET /api/premium/status` — tier state + feature list (works for any
  authenticated user)
- `POST /api/premium/activate` `{ key }` — rate-limited (5 failed attempts per
  hour in addition to the login limiter)
- `POST /api/premium/deactivate` — admin only

Activation is persisted in `premium_state` (upscaled via INSERT … ON CONFLICT
so a fresh DB can never silently drop an activation again) and survives panel
restarts.

## Files

- `premium.js` — server module (digest, feature registry, rate limit, storage)
- `public/js/vnm-premium.js` — client runtime: status cache, 402 interceptor,
  license modal, PRO chip, user-menu entry (loaded on every authenticated
  page via the shared footer partial)
- Gating hooks in `app.js` (routes + bootstrap) and `platform.js`
  (`needPremium()` helper used by the platform endpoints)
