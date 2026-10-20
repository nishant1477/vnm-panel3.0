# VNM Panel — Round 5: The Complete Platform Upgrade

VNM Panel is now a **complete virtualization management platform**, not just a VM panel.
This round implements the full feature roadmap: automation, monitoring & alerting,
snapshots & backups, multi-node fleet management, security (API keys + audit), and a
premium UI layer (command palette, bulk actions, live charts).

All 232 machine-verified assertions pass:
- **134/134** new platform e2e (`scripts/45-verify-platform.js`)
- **50/50** remote-node + SSH regression (`scripts/16-verify-e2e.js`)
- **31/31** networking regression (`scripts/26-verify-networking.js`)
- **17/17** deep-fix regression (`scripts/36-verify-deepfix.js`)

---

## 1. Automation & Task Manager (`task-engine.js` + `/admin/tasks`)

A persistent background job queue powering every long-running operation.

- **Job types**: `vm.start`, `vm.stop`, `vm.restart`, `vm.backup`, `vm.restore-backup`,
  `vm.restore-backup-new` (recovery test), `vm.clone`, `vm.migrate`
- **Live progress** (0-100% + human text like "Streaming disk (412.3 MB)"), rate-limited
  DB writes, polled by the UI with faster refresh while jobs are active
- **Retries with backoff** for transient failures (20s, 40s...), `noRetry` errors for
  permanent ones (checksum mismatch, running VM)
- **Cooperative cancellation** — queued jobs cancel instantly; running jobs stop at the
  next checkpoint via `ctx.checkCancelled()`
- **Duplicate prevention** — one active job per type+target (second enqueue → 409)
- **Crash recovery** — jobs left `running` by a dead process are re-queued at boot
- **Schedules** with a cron-lite spec (`every:30m`, `every:2h`, `daily:03:30`,
  `weekly:5:03:30`), pause/resume, run-now, and no-double-fire protection
- **History retention** — succeeded/cancelled pruned after 14 days, everything after 60

## 2. Monitoring & Alerts (`monitoring.js` + `/admin/monitoring`)

- **Metric collector** every 20s: per-node host stats (from agent heartbeats), local VM
  CPU/RAM (`ps` on each QEMU PID), remote VM stats (agent `vm.stats` command) — 24h
  retention, then pruned
- **Zero-dependency canvas charts** (DPR-aware area charts + sparklines) with gradient
  fills, smoothed curves and live last-point markers
- **Alert rules**: scope = all nodes / one node / all VMs / one VM, metric = cpu|mem|disk,
  comparator, threshold, **sustain window** (must hold N minutes), severity
  (info/warning/critical), **cooldown** per rule to prevent alert spam
- **Alert feed** with acknowledge workflow; failed tasks auto-create alert events
- **Discord webhook notifications** (validated URL, embed-formatted, test button);
  email honestly documented as requiring an external SMTP relay
- **Node Capacity dashboard**: live host usage + VM allocations (vCPUs/RAM committed per
  node) with color-graded meters
- User-scoped: non-admins see only their own VMs' charts; host/node stats are admin-only

## 3. Snapshot & Backup Center (`platform-ops.js`, `node-agent/lib/node-storage.js`)

- **Real qcow2 internal snapshots** (`qemu-img snapshot -c/-a/-d`) for local AND
  remote-node VMs (agent executes on the node); restore/delete per snapshot
- **Full-file backups** via `qemu-img convert` with **SHA-256 checksums** recorded at
  creation, re-verified before every restore
- **Backups on nodes**: agent-side create/restore/verify/delete in the node's backup dir
- **Restore safety**: confirm-token required, integrity check first, current disk staged
  aside (`.pre-restore-*`) and automatically rolled back if the restore fails
- **Recovery testing**: restore any backup into a *fresh clone VM* (`restore-new`) —
  proves recoverability without touching the original
- **Retention** on scheduled backups (keep newest N, older ones deleted file+row)
- **Backup Center page** (`/admin/backups`): fleet-wide list with sizes, node location,
  checksum badges, verify/restore/test-restore actions, plus every VM's snapshots

## 4. Multi-Node Infrastructure

- **Maintenance mode** per node — blocks new VM creation (409 `NODE_MAINTENANCE`),
  excluded from placement, shown as a badge in capacity/monitoring/search
- **Placement recommendations** (`GET /api/nodes/placement`): scores every node by live
  CPU/RAM/disk load + vCPU over-commit limits; the wizard marks the recommended node
  with ★ and explains why in the field hint
- **Capacity dashboard** (`GET /api/nodes/capacity`): per-node host stats, KVM status,
  agent version + allocated vCPUs/RAM/VM counts
- **Drain preview** (`GET /api/nodes/:id/drain-preview`): lists the node's VMs and where
  they could move
- **Live migration** (`vm.migrate` task) with real byte streams both ways:
  - remote → local: new **file-pull relay** (agent streams the qcow2 to the panel,
    SHA-256 verified end-to-end)
  - local → remote / remote → remote: verified, flow-controlled **disk-upload relay**
  - VM stopped for the move, cloud-init seed rebuilt on the target, new SSH port
    allocated per node, source artifacts cleaned, auto-restart if it was running
  - `vm.diskinfo` (with hash), `port.check`, `vm.stats` agent commands added
- Agent version bumped to **1.3.0**

## 5. Security & Access Control

- **API keys** (`api-keys.js` + `/admin/api-keys`): `vnmak_…` Bearer tokens, SHA-256
  hashed at rest, shown exactly once, scoped `read` / `read+write` (403 `SCOPE_DENIED`
  on mutating verbs for read-only keys), revocation takes effect immediately,
  `last_used` tracking, expiry support
- Keys authenticate without a browser session and **bypass CSRF** (the key is the
  authenticator); a synthetic per-request session (with the full express-session method
  surface) carries the owner's identity so **every existing ownership check and role
  gate works unchanged** for API clients
- **Audit log viewer** (`/admin/audit`): filter by action/user, paginate older entries —
  covering logins, VM lifecycle, user management, node maintenance, bulk actions,
  migrations, API-key operations and settings changes
- **Per-VM firewall rule manager**: direction/protocol/port-range/source/action/priority
  with a **safe-default preset** (allow SSH/HTTP/HTTPS, deny rest); the UI documents the
  enforcement model honestly (NAT VMs are protected by QEMU's host boundary — only
  forwarded ports are reachable; bridge VMs should be filtered at the network firewall)
- **IP allocation manager** with **conflict detection** (rejects duplicates and IPs
  already assigned to a VM, with the exact conflicting VM named)

## 6. Advanced VM Management

- **Clone**: full disk copy + fresh cloud-init seed + fresh MAC + **fresh SSH port**
  (never shares the source's host port), works locally and on remote nodes
- **Bulk actions**: select VMs (grid or list view) → Start/Stop/Restart/Delete all;
  destructive delete requires confirm; per-VM results reported
- **Tags, groups & notes** per VM (`PUT /api/vms/:id/meta`), tag chips on cards,
  searchable via the command palette
- **Global search API** (`GET /api/search`) across VMs (name/id/group/tags), nodes,
  users and templates — scoped to the user's own VMs for non-admins

## 7. Premium UI/UX

- **Command palette** (Ctrl/Cmd+K or the header search): quick-jump to every page +
  live global search results with keyboard navigation — the "infrastructure command
  center"
- **Collapsible sidebar** (persisted in localStorage, icon-only rail when collapsed)
- **Dashboard "Platform Pulse"**: host CPU+memory chart, per-node health strip with live
  meters, open-alert feed
- **Task UI**: status pills (queued/running shimmer/succeeded/failed/cancelled),
  animated progress bars, retry/cancel actions
- **New pages**: Monitoring & Alerts, Task Automation, Backup Center, Storage Pools,
  Network Center (3 tabs), API Keys, Audit Log + user-side My Monitoring / My Tasks
- All motion respects `prefers-reduced-motion`; polling pauses when the tab is hidden

## 8. Storage Pools

- Registry + live `df` usage for the panel's VM/Backup/Template dirs
- Remote node pools via the agent (`node.storage.list` / `node.storage.check`),
  including offline-node indication
- Registering a custom pool validates the path exists (local `fs`, remote via agent)
  and rejects `/proc`, `/sys`, `/dev`, `/etc`; **removing a pool never deletes files**

## 9. Files Added / Changed

**New modules**: `task-engine.js`, `monitoring.js`, `platform-ops.js`, `platform.js`,
`api-keys.js`, `node-agent/lib/node-storage.js`

**New frontend**: `public/css/vnm-platform.css`, `public/js/vnm-platform.js` (charts,
palette, bulk, formatters)

**New views**: `admin/{monitoring,tasks,backups,storage,network,api-keys,audit}.ejs`,
`users/{monitoring,tasks}.ejs`

**Patched**: `app.js` (platform mount, API-key auth ahead of CSRF, synthetic session,
maintenance guard, boot sequence), `nodes.js` (file-pull relay),
`node-agent/agent.js` (+14 actions, file-pull handler), both vm-detail views, vms list,
dashboard, wizard, sidebars, header

**Bug fixes found by the verification runs** (in addition to Round 4's 26):
1. `express-session` crashed on synthetic API-key sessions (`touch` not a function) —
   full method surface provided
2. `vm_backups` INSERT referenced a nonexistent `node_name` column — schema-corrected
3. `tasks` table lacked the `result` column — added + additive migration for existing DBs
4. Invalid schedule specs returned 500 — now 400 `INVALID_SCHEDULE`
5. Platform pages mounted before the view-locals middleware — `siteLogo` undefined 500s
6. API routes used the browser-redirecting admin guard — JSON 403 `adminOnly` added
7. Clones/recovery-test VMs shared the source's SSH host port — per-node allocation added
8. vm-detail: `loadBackups`/`loadMeta` rendered into DOM detached by `renderPage`
   (elements re-queried after fetch + refresh hooks)
9. vms list: bulk handler armed before `vnm-platform.js` loaded (ReferenceError) —
   armed on window load
10. Alert e2e was flaky on an idle host — deterministic rule

## 10. How to Try It

```
node app.js
# admin sidebar: Platform section -> Monitoring / Tasks / Backups / Storage /
#                Network / API Keys / Audit Log
# press Ctrl+K anywhere for the command palette
# create an API key (Admin -> API Keys) and:
curl -H "Authorization: Bearer vnmak_..." http://localhost:8080/api/vms
```
