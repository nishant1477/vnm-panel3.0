# VNM Panel — Fix Changelog

All errors from the review pass are fixed below. Every change was verified
against a live boot of the panel: 37 API/behavior smoke tests and 12 page
render checks pass, and all JS files + 34 EJS views compile cleanly.

---

## v3.0.1 - Missing admin/404 template (500 on two admin pages)

- **Fixed**: two admin pages answered `500 Internal server error` instead
  of a clean error page. The code rendered the view `admin/404`, but only
  `views/users/404.ejs` existed in the tree, so Express threw
  `Failed to lookup view "admin/404"` and the VNM Shield error middleware
  answered with a raw 500. Affected routes:
  - `GET /admin/users/<non-numeric-id>/edit` (Invalid User ID)
  - `GET /admin/templates/builtin/<unknown-key>/edit` (Built-in Template
    Not Found)
  Added `views/admin/404.ejs` — admin-flavored, same design language as
  the user 404 page, with defensive locals (renders safely with any
  subset of `{ title, message, code }`, worst case included). Both call
  sites now also pass `code: 400` so the page shows the true HTTP status.
- **Added**: `tests/template-audit.js` — a machine-verified audit of every
  `res.render()` target in first-party code (literal targets plus the
  `platform.js` `page()` registry that feeds its one dynamic render),
  every `include()` path in all views, and a compile check of every
  template. Run it with `node tests/template-audit.js` (50 checks, exit 1
  on any failure). The audit proves `admin/404` was the only missing
  template in v3.0.0.
- **Verified**: fresh-boot A/B — with the template absent the invalid-ID
  route reproduces the 500 byte-for-byte; with it restored both routes
  return 400 + the proper page, the global 404 handler still renders
  `users/404`, and `/admin/users`, `/admin/shield`, `/admin/users/1/edit`
  all still return 200 (9/9 checks).
- Panel `3.0.0 -> 3.0.1`; node agent unchanged (`1.4.1`).

---

## 1. Infinite redirect loop for non-admins (auth)
`checkAdmin` redirected non-admins to `/admin/dashboard` — an admin-only
page — so any non-admin hitting an admin URL bounced between the two
middlewares forever. Non-admins are now sent to `/dashboard`.
Verified: non-admin `GET /admin/dashboard` → 302 `/dashboard`, and
`/dashboard` renders 200 (loop broken).

## 2. Dead dashboard widgets (missing endpoints)
The admin dashboard called `/api/admin/activity` and `/api/system/status`,
which did not exist. Both endpoints are implemented:
- `/api/admin/activity` merges `vm_logs` + the security audit log, newest
  first, respecting the `limit` query param (capped at 50).
- `/api/system/status` reports real host CPU %, memory and disk usage via
  the existing `system-info` module (no fake numbers).
Both are admin-only. Verified live: activity feed shows the login entries;
system status returns CPU % and GB figures.

## 3. 2FA login always failed (CSRF)
The login page sent no `X-CSRF-Token` header, and `/api/login/2fa` is
(rightly) not CSRF-exempt, so the 2FA step could never succeed. The login
page now reads the `csrf_token` cookie and attaches the header on both
login steps.
Verified live with a full round trip: no header → 403; header + wrong
code → 401; header + correct TOTP code → success.

## 4. Wrong "All VMs" sidebar badge
The admin sidebar's "All VMs"/running badges counted from `/api/vms`,
which returns only the logged-in admin's OWN VMs. The sidebar now counts
the whole fleet via `/api/admin/vms` (with a defensive fallback).
Bonus: the header quick-search on admin pages now also searches all VMs
instead of just the admin's own.

## 5. Owner always "Unassigned"
Neither VM list API joined the `users` table, so `owner_username` was
always undefined. Both `/api/vms` and `/api/admin/vms` now join
`users` and return `owner_username`.
Verified live: `owner_username: 'admin'` present in both list responses.

## 6. Discord login flaws
- The OAuth `state` check passed when BOTH values were missing
  (`undefined === undefined`). Both sides must now be present and match.
- Unverified Discord emails were trusted for account matching/creation.
  Discord identities with `verified: false` are now rejected with a clear
  message.
- Bonus (security): Discord-linked login ignored `is_active`, so a
  deactivated user could still sign in with Discord. Fixed.

## 7. Login page defects
- Double submit: pressing Enter dispatched a synthetic `submit` event on
  top of the browser's native implicit submission, firing the login
  handler twice and burning the 8-per-minute rate limit. The shim is
  removed (native Enter submission is enough).
- "Remember me" was never wired to anything server-side; the dead
  checkbox is removed.
- Bonus: `loadLoginBranding()` was defined twice; deduplicated.

## 8. Dead imgur hotlinks + malformed SVG
- The 7 built-in OS template icons hotlinked `i.imgur.com` URLs that 404.
  They now use self-hosted SVGs in `public/images/os/` (ubuntu, debian,
  fedora, centos, almalinux + a generic fallback).
- An idempotent boot migration re-points existing database rows that
  still carry imgur icons.
- All view fallbacks (`onerror` etc.) point at the local generic icon,
  and the "is this a URL?" checks now also accept local absolute paths
  (`/images/os/...`), which they previously rejected.
- Malformed built-in SVG: the "Static Public IPv4" network-type icon had
  SVG path commands (`M12 22.08v-9.53`) inside a `<polyline points>`
  attribute. Split into a proper `<polyline>` + `<line>`.
  Verified via `/api/network-types`: valid markup served.

## 9. Shell-string command execution + RDP validation
- `qemu-img info/resize` went through `execSync` with interpolated
  paths/sizes in a shell string (command-injection surface). Both now use
  `execFileSync` with argv arrays — no shell involved.
- RDP `POST /auto` silently treated any malformed body as "switch off".
  Invalid bodies are now rejected with `400 {"code":"BAD_REQUEST"}`;
  `{enabled: true|false}` (and the string/number variants) still work.
  Verified live: garbage body → 400, `{enabled:false}` → 200.

## 10. Missing Discord link / sign-up pages (were 404)
The OAuth callback redirected to `/link-discord-account` and
`/create-account-discord`, which never existed. Added:
- `GET /link-discord-account` — guides an already-matching account owner
  through linking after signing in.
- `GET /create-account-discord` + `POST /api/create-account-discord` —
  first-time sign-up with username/password validation, clash detection
  (409 on taken username/email), account creation, Discord linking and
  login in one step.
- The Discord handoff (`pendingDiscordAuth`) survives the new session
  rotation (see #11), and a password login mid-flow returns the user to
  the link page instead of the dashboard.

## 11. No session regeneration on login (session fixation)
All four login completion paths (password, 2FA, Discord-linked,
Discord-created) now rotate the session ID and issue a fresh CSRF token,
so a cookie planted before authentication can never become a logged-in
session. Verified live: session cookie value changes across login.

## 12. Guest password leaked to the browser
Both VM list APIs returned the raw `vms.password` column (guest OS
credentials) to any logged-in user. The list endpoints now strip it;
the owner/admin-gated VM detail endpoint still returns it for the
credentials card. Verified live: no `password` key in either list
response.

## 13. "VM stoped successfully" typo
The toast used `` `VM ${action}ed` ``, which only works for start/restart.
All 6 views now map past tenses properly (started / stopped / restarted).

---

## Files touched
- `app.js` — auth, session rotation, Discord, new endpoints + pages,
  icon migration, qemu-img argv execution, list API hardening
- `rdp.js` — `/auto` body validation
- `views/users/login.ejs` — CSRF header, single submit, no Remember me,
  dedup, redirect hint
- `views/users/link-discord.ejs` — NEW
- `views/users/create-account-discord.ejs` — NEW
- `views/partials/admin/sidebar.ejs` — fleet-wide badge counts
- `views/partials/admin/header.ejs` — fleet-wide search on admin pages
- `views/admin/{vms,dashboard,vm-detail,vm-create}.ejs` — local icons,
  past-tense toasts
- `views/users/{vms,dashboard,vm-detail}.ejs` — local icons, past-tense
  toasts
- `public/images/os/*.svg` — NEW: 6 self-hosted OS icons

---

## v2.1.1 - Download resilience fix (mirror 502 on broken-IPv6 hosts)

- **Fixed**: template downloads dying at the TCP layer with no HTTP response
  (`ETIMEDOUT`), surfaced as 502 `TEMPLATE_DOWNLOAD_FAILED`, on hosts with a
  global IPv6 address but broken IPv6 egress - while curl/git worked fine.
  Downloaders now resolve each host into an ordered address list (IPv4 first,
  `VNM_PREFER_IPV6=1` flips) and try each address in sequence, advancing only
  on connect-layer failures. Applies to both the panel and the node agent.
- **Added**: global Happy Eyeballs (`net.setDefaultAutoSelectFamily`) for all
  outbound sockets in both processes - opt out with `VNM_NO_HAPPY_EYEBALLS=1`.
- **Added**: per-address connect deadline in the agent downloader
  (`AGENT_ADDR_CONNECT_TIMEOUT_MS`, default 6s).
- **Improved**: 502 diagnostics now list, per URL, every address + family
  attempted, and call out explicitly when no URL ever returned an HTTP
  response (TCP-level reachability problem, not a mirror outage).
- Panel `2.1.0 -> 2.1.1`; node agent `1.3.0 -> 1.4.0` (agent protocol
  unchanged - purely client-side downloader behavior).

---

## v2.1.2 - VM boot + Remote Desktop fix (no-KVM hosts)

- **Fixed**: VMs failing to start on hosts without usable `/dev/kvm`.
  `startQemuVM()` fell back to TCG software emulation but still passed
  `-cpu host`; real QEMU exits with code 1
  (`qemu-system-x86_64: CPU model 'host' requires KVM or HVF`) before the
  VM ever boots. When KVM is unavailable, any CPU configuration whose base
  is `host` (the panel default, the `host` preset, the implicit base of
  custom CPU names) is now substituted with the TCG-compatible `max`
  model at launch time, preserving any `,model-id=...` suffix. Stored
  settings are untouched - a KVM-capable host keeps using them.
- **Fixed**: CPU presets reaching QEMU under their UI key instead of their
  real QEMU model name (`skylake` -> `Skylake-Client`,
  `cascadelake` -> `Cascadelake-Server`, `corei7` -> `Haswell`); real QEMU
  refuses unknown models at startup.
- **Fixed**: Remote Desktop setup dying with
  `Timed out while waiting for handshake`. QEMU's user-mode forwarder
  accepts the host-side connection long before the guest has sshd up
  (first boots take minutes under TCG), so a single 15s attempt failed
  whole setups. `waitForGuestSsh()` now retries until the guest is really
  reachable (default 10 min, `RDP_SSH_WAIT_MS`), classifying errors
  honestly (refused / handshake / auth) and never retrying bad passwords.
- **Fixed**: RDP setup trusting a stale `status` column. A QEMU that
  crashed after a healthy start left the VM `running` in the DB forever;
  the RDP preflight (and the exit handler) now check the actual QEMU
  process and correct the state instead of hanging on SSH.
- **Improved**: VM start failures now surface QEMU's own diagnostic line
  in the API error (e.g. the `CPU model 'host'` message above) instead of
  a bare exit code; the panel logs the effective CPU model and
  acceleration mode on every start.
- Panel `2.1.1 -> 2.1.2`; node agent `1.4.0 -> 1.4.1` (shared
  rdp-guest.js gained the SSH wait loop; agent protocol unchanged).
