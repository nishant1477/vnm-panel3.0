# VNM Shield — Security, Recovery & Diagnostics Layer

**v3.0.0** · Made by Immortal

VNM Shield turns VNM Panel into a layered, self-diagnosing hosting panel: anti-tamper
file protection, least-privilege lockdown, automatic downtime recovery with circuit
breakers, an automatic Error Teller, an encrypted backup vault, host intrusion
detection, emergency lockdown, verified signed updates, an independent watchdog, and
one professional dashboard — all added **on top of** the existing panel without
replacing anything.

```
┌─────────────────────────────────────────────────────────────────┐
│  Admin → VNM SHIELD (sidebar)                                   │
│  Overview · Integrity · Incidents · Security · Recovery ·       │
│  Backups · Resources · VM Guardian · Updates · Settings         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 1. What each layer does

| Layer | What it does | Destructive? |
|---|---|---|
| **Integrity Guard** | SHA-256 baselines of every security-critical file (code, views, assets, installers, node-agent). Detects modify/add/remove/permission changes. `monitor` mode alerts; `enforce` mode additionally auto-restores from a trusted vault (vault copy re-verified first). | enforce mode restores files — only from hash-verified vault copies |
| **Error Teller** | Classifies Node/Express/SQLite/QEMU/RDP/network/storage/permission/systemd errors into human explanations with **confirmed vs possible causes** and a suggested fix. Creates grouped incidents (repeat errors increment a counter instead of spamming). | never |
| **Auto-Recovery** | Health checks (DB, QEMU, KVM, services, disk, memory). Restarts **dependent services only** (`vnm-agent`, `vnm-watchdog`) with diagnostics captured first and health verified after. Circuit breaker: max attempts per window, cooldown between attempts, opens → manual intervention alert. **Never restarts VMs. Never restarts itself.** | restarts 2 whitelisted services only |
| **Backup Vault** | Encrypted (AES-256-CBC, PBKDF2 200k) versioned backups of panel code + consistent DB snapshot (`VACUUM INTO`) + config. Per-file manifest hashes, outer hash sidecar, plausibility size check, scheduled restore tests, optional rsync/scp to an independent server. **VM disks are never in scope.** | restore replaces code+DB (with pre-restore safety backup) |
| **IDS / Security** | SSH brute-force detection, sshd/sudoers/firewall/systemd/cron config watchers, listening-port diffs, privileged-account changes, new outbound-connection processes, panel login-failure history. | **never** — no auto-blocking by design |
| **Emergency Mode** | Owner-triggered lockdown: all sessions revoked, risky admin ops blocked at the API layer (VM/user/settings/delete/restore/update), evidence snapshot frozen, root-only recovery code for CLI unlock. Read-only access stays available; owner can re-authenticate to act. | blocks operations; deletes nothing |
| **VM Guardian** | Per-VM reality check: QEMU liveness vs DB state, stale/orphan detection, disk image presence + growth, serial log tail, per-VM diagnosis. Read-only. | never |
| **Resource Guard** | Disk/inode/memory/load monitors with pre-exhaustion alerts, top processes, and **safe cleanup** (VM logs, rotated panel logs, stale temp files, failed backups) with preview + explicit confirmation. VM disks, the live DB, and the latest verified backup are structurally un-selectable. | deletes only whitelisted categories after confirm |
| **Secure Updater** | ed25519-signed releases + per-file SHA-256 verification, preflight checks, pre-update vault backup, staged apply with rollback snapshots, post-apply syntax validation, automatic rollback on failure, full update/rollback history. Unsigned releases refused by default. | replaces files after verification (rollback path always kept) |
| **Watchdog** | Independent OS process (`vnm-watchdog.service`) polling `/api/health`. Own config, own notification channel, restarts the panel when it is truly down, verifies recovery, circuit breaker (3/hour) then manual-intervention alert. Heartbeat file proves the watchdog itself is alive. | restarts `vnm-panel` via narrowly-scoped sudo |
| **Notifications** | Discord, Telegram, generic webhook (ntfy/Gotify/…), and **real email via built-in SMTP client** (STARTTLS/TLS/AUTH) — zero new dependencies. Severity thresholds, dedup/grouping, secret redaction on every outgoing byte. | never |

## 2. Roles (RBAC)

| Panel role | Users table value | Shield access |
|---|---|---|
| Owner | `admin` | everything, including settings, restore, update, emergency |
| Staff | `staff` (new, optional) | view dashboards, run diagnostics/scans, ack/resolve incidents — no settings/restore/update/emergency |
| Customer | `user` | none (no Shield routes, no host-level commands — enforced on every endpoint) |

Create a staff account: **Users → Edit → role = staff**. All pre-existing routes keep
their original `admin`-only guards; customers could never reach them and still cannot.

## 3. Installation (on top of an existing v2.x install)

```bash
# 1. update files to v3.0.0 (see §9), then:
cd /opt/vnm-panel

# 2. (recommended) least-privilege lockdown — dedicated service user,
#    read-only code, separated data/VM dirs, watchdog sudo rule:
sudo scripts/lockdown.sh --apply
sudo scripts/lockdown.sh --check        # verify / CI gate

# 3. independent watchdog:
sudo cp watchdog/vnm-watchdog.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now vnm-watchdog
# watchdog config template appears at ~/.vnm/shield/watchdog.json on first run
sudo vi ~vnmpanel/.vnm/shield/watchdog.json   # set YOUR notify channel + panel port
sudo systemctl restart vnm-watchdog
```

Nothing in step 2/3 is required for the in-panel Shield features — they work
immediately after the v3.0.0 files are in place and the panel restarts. On first
boot the Integrity Guard automatically baselines every critical file.

## 4. Configuration

All settings live in **Shield → Settings** (stored in the existing `settings`
table, `shield.*` keys) — nothing to edit by hand:

| Key | Default | Meaning |
|---|---|---|
| `shield.integrity.mode` | `monitor` | `off` / `monitor` / `enforce` |
| `shield.integrity.scheduleMinutes` | `15` | scheduled scan interval |
| `shield.security.sshFailThreshold` | `10` | SSH failures before alert |
| `shield.security.sshWindowMinutes` | `10` | window for the above |
| `shield.recovery.maxAttempts` | `3` | breaker: attempts per 30 min |
| `shield.recovery.cooldownMinutes` | `5` | min spacing between restarts |
| `shield.backup.scheduleHours` | `24` | 0 = off |
| `shield.backup.keep` | `10` | versions kept (never the latest verified) |
| `shield.backup.remote.target` | — | `user@host:/path` for rsync/scp copy |
| `shield.notify.minSeverity` | `low` | notify at/above this severity |
| `shield.notify.discord.webhook` | — | Discord webhook URL |
| `shield.notify.telegram.token/.chatId` | — | Telegram bot |
| `shield.notify.webhook.url` | — | generic JSON webhook |
| `shield.notify.email.*` | — | SMTP host/port/security/user/pass/from/to |
| `shield.update.publicKey` | built-in | your own ed25519 public PEM for private releases |
| `shield.update.allowUnsigned` | `0` | **do not** enable unless you build your own releases |

Backup passphrase: generated on first backup and stored server-side; export
`VNM_BACKUP_PASSPHRASE` to override. **Keep a copy offline — without it encrypted
backups cannot be restored.**

Watchdog config is separate by design: `~/.vnm/shield/watchdog.json` (URL, interval,
thresholds, restart command, its own notify channels).

## 5. Recovery procedures

### Web panel is down
```bash
sudo scripts/vnmctl status            # what state is everything in?
sudo scripts/vnmctl health            # DB + disk checks work offline
sudo scripts/vnmctl logs 100          # panel journal + watchdog log + actions
sudo scripts/vnmctl restart           # systemctl restart vnm-panel
```

### Database corrupted
```bash
sudo vnmctl verify <newest .vnmbackup>   # end-to-end: decrypt+hashes+quick_check
sudo vnmctl restore <newest .vnmbackup>  # code+DB; --skip-db keeps current DB
sudo vnmctl restart
```

### A bad update / want the previous version back
```bash
sudo vnmctl rollback       # restores the last update's rollback snapshot
sudo vnmctl restart
# or from the dashboard: Shield → Updates → Rollback last update
# or full restore from any vault backup (Shield → Backups → Restore)
```

### Emergency mode unlock (panel unreachable or sessions revoked)
```bash
sudo vnmctl status                        # shows lockdown state + code location
sudo cat ~vnmpanel/.vnm/shield/emergency-recovery.txt   # root-only
sudo vnmctl emergency off --code <code>
```

### Permissions broken (e.g. an update ran as root)
```bash
sudo scripts/lockdown.sh --recover
```

## 6. Security model & honest limits

* **Server-side enforcement**: every Shield endpoint re-checks session + role;
  destructive ones additionally require `confirm: true` in the body on top of
  the global CSRF double-submit protection.
* **No shell escape**: the panel never exposes arbitrary command execution.
  The Node Terminal (admin tool) is unchanged and remains owner-only.
* **Secret hygiene**: passwords/tokens/keys/session-ids are redacted from
  incidents, notifications, diagnostics and exports (`***REDACTED***`).
* **VM safety invariants**: auto-recovery never touches VMs; backups and
  cleanup can structurally not reach VM disks; panel-only restore never
  overwrites `~/vms`.
* **Root on the host can always bypass local file protections.** The lockdown
  profile constrains the *service*, *customers*, and *staff* — not a
  compromised root account. Combine with standard host hardening (fail2ban,
  SSH keys only, unattended-upgrades) for defense in depth.
* **Single-event policy**: the IDS never takes a destructive action on one
  unverified observation — it records, classifies, and alerts; a human decides.

## 7. Verification (machine-checked)

* `scripts/70-verify-shield.js` — **97 checks**: boot integration, login history,
  RBAC (customer denied / staff read-only / owner full), CSRF, tamper detect +
  vault restore + enforce auto-restore + maintenance windows, 5 IDS detectors,
  restart policy + circuit breaker engagement, backup create/verify/restore-test/
  restore/corruption-refusal, cleanup blacklists, VM guardian, signed-release
  verify/apply/rollback + unsigned refusal, emergency mode end-to-end (session
  revocation, blocked ops, re-auth, recovery code), diagnoser KB + redaction,
  watchdog healthy-check + breaker, dashboard render, settings round-trip.
* `scripts/71-regression-smoke.js` — **49 checks**: every pre-existing admin/user
  page and core API still 200 after integration; write paths (user create,
  settings) still work; hostile probes produce no 5xx; no FATAL-SAFE catches.
* Run: `node scripts/70-verify-shield.js && node scripts/71-regression-smoke.js`

## 8. Files added by Shield

```
shield.js                    orchestrator: routes, RBAC, schedulers, /api/health
lib/shield-diagnoser.js      error knowledge base + redaction
lib/shield-notifier.js       incidents + Discord/Telegram/webhook + SMTP client
lib/shield-integrity.js      baselines, scans, vault, protection modes
lib/shield-security.js       IDS detectors + login history
lib/shield-recovery.js       health checks + circuit breakers
lib/shield-backup.js         encrypted vault + verification + restore
lib/shield-vanguard.js       VM guardian + resource guard + safe cleanup
lib/shield-updater.js        signed updates + rollback snapshots
lib/shield-emergency.js      lockdown + gate + recovery code
watchdog/vnm-watchdog.js     independent watchdog process (+ .service)
scripts/lockdown.sh          least-privilege deployment profile
scripts/vnmctl               CLI control that works when the web is down
views/admin/shield.ejs       the Shield dashboard
public/css/vnm-shield.css    Shield design system
```

Database: 9 new `shield_*` tables (baseline, events, incidents, security events,
sec baseline, login history, recovery log, backups, updates) — created via
`CREATE TABLE IF NOT EXISTS`, fully backward compatible, no existing table is
altered.

## 9. Updating an existing v2.x deployment

```bash
# from the host, with the v3.0.0 release zip + signed manifest:
sudo scripts/vnmctl update v3.0.0.zip v3.0.0.json   # verify+backup+apply
sudo scripts/vnmctl restart
# rollback if anything looks wrong: sudo scripts/vnmctl rollback
```

Or the classic way (stop, replace files except `data/` and `~/vms`, start), then
re-baseline from **Shield → Integrity → Re-baseline** (legitimately changed files
should never page you). No SQLite migration needed — new tables are created
automatically on first boot.
