#!/usr/bin/env bash
# =====================================================================
# VNM Shield — Panel File Lockdown (least-privilege deployment profile)
# ---------------------------------------------------------------------
# Hardens the file layer of a standard install.sh deployment:
#
#   1. DEDICATED SERVICE ACCOUNT
#      The panel runs as the non-root system user 'vnmpanel' (created
#      here if missing) - never as root.
#
#   2. LEAST-PRIVILEGE OWNERSHIP
#      Application code     root:vnmpanel  dirs 0750  files 0640  (read-only to the service)
#      Static public assets root:vnmpanel  dirs 0755  files 0644  (web-readable)
#      Data dir (DB/vault)  vnmpanel       0750/0600   (service-writable ONLY here)
#      VM disks & logs      vnmpanel       0750        (service-writable)
#      Secrets (.env)       root:vnmpanel  0640        (readable by service, owned by root)
#
#   3. SEPARATION OF CONCERNS
#      code  -> /opt/vnm-panel            (read-only for the service)
#      data  -> /home/vnmpanel/.vnm       (DB, shield vault, watchdog state)
#      VMs   -> /home/vnmpanel/vms        (disks, ISOs, seeds, serial logs)
#      logs  -> journald (vnm-panel.service) + data dir files
#
#   4. WEB-EXPOSED SURFACE
#      Only public/ is ever served. .env, data dir, VM disks are all
#      outside the static root, so no URL can reach them.
#
#   5. SUDO (watchdog restart rights)
#      Installs a sudoers drop-in allowing vnmpanel to restart exactly
#      two units - nothing else.
#
# MODES
#   --apply    apply the profile (default)
#   --check    report deviations without changing anything (exit 1 if wrong)
#   --recover  repair ownership/permissions after an accidental change
#              (e.g. an update that ran as root and left root-owned files)
#
# HONEST LIMITS (read this):
#   * Root on the host can ALWAYS bypass local file protections -
#     that is inherent to root. This profile stops the SERVICE, the
#     CUSTOMERS, and ordinary STAFF from touching host files; it does
#     not defend against a compromised root account.
#   * Customers/staff never get OS accounts; they only hold panel
#     logins, which the app's RBAC confines.
# =====================================================================
set -euo pipefail

PANEL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_USER="${VNM_SERVICE_USER:-vnmpanel}"
DATA_DIR="${VNM_DATA_DIR:-/home/$SERVICE_USER/.vnm}"
VM_DIR="/home/$SERVICE_USER/vms"
MODE="${1:---apply}"

c_red=$'\033[31m'; c_green=$'\033[32m'; c_yellow=$'\033[33m'; c_cyan=$'\033[36m'; c_off=$'\033[0m'
step() { printf '%s[%s]%s %s\n' "$c_cyan" "$1" "$c_off" "$2"; }
ok()   { printf '  %sOK%s  %s\n' "$c_green" "$c_off" "$1"; }
warn() { printf '  %s!!%s  %s\n' "$c_yellow" "$c_off" "$1"; }
fail() { printf '  %sXX%s  %s\n' "$c_red" "$c_off" "$1"; }

[[ $EUID -eq 0 ]] || { echo "Must run as root (sudo $0 $MODE)"; exit 1; }

ensure_user() {
  if id "$SERVICE_USER" &>/dev/null; then
    ok "service user '$SERVICE_USER' exists"
  else
    useradd --system --home-dir "/home/$SERVICE_USER" --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    ok "created system user '$SERVICE_USER' (no login shell)"
  fi
  # KVM access group (harmless when /dev/kvm is absent)
  if getent group kvm >/dev/null 2>&1; then usermod -aG kvm "$SERVICE_USER" 2>/dev/null && ok "added to group kvm" || warn "could not add kvm group"; fi
}

apply_profile() {
  step "1/6" "Service account"
  ensure_user

  step "2/6" "Directory separation"
  mkdir -p "$DATA_DIR" "$DATA_DIR/shield/backups" "$DATA_DIR/shield/vault" "$VM_DIR" "$VM_DIR/templates" "$VM_DIR/iso"
  chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$VM_DIR"
  chmod 0750 "$DATA_DIR" "$VM_DIR"
  chmod 0700 "$DATA_DIR/shield"
  ok "data=$DATA_DIR  vms=$VM_DIR (owner $SERVICE_USER)"

  step "3/6" "Application code -> root-owned, read-only for the service"
  chown -R "root:$SERVICE_USER" "$PANEL_DIR"
  find "$PANEL_DIR" -type d -not -path "*/node_modules*" -not -path "*/public/*" -exec chmod 0750 {} \; 2>/dev/null || true
  find "$PANEL_DIR" -type f -not -path "*/node_modules*" -not -path "*/public/*" -exec chmod 0640 {} \; 2>/dev/null || true
  # node_modules: root-owned, traversable + executable binaries
  if [[ -d "$PANEL_DIR/node_modules" ]]; then
    chown -R "root:$SERVICE_USER" "$PANEL_DIR/node_modules"
    find "$PANEL_DIR/node_modules" -type d -exec chmod 0755 {} \; 2>/dev/null || true
    find "$PANEL_DIR/node_modules" -type f -exec chmod 0644 {} \; 2>/dev/null || true
    find "$PANEL_DIR/node_modules" -type f \( -name '*.node' -o -name '*.bin' \) -exec chmod 0755 {} \; 2>/dev/null || true
  fi
  # scripts stay executable by owner (root), invoked via sudo
  chmod 0750 "$PANEL_DIR/scripts/vnmctl" "$PANEL_DIR/scripts/lockdown.sh" 2>/dev/null || true
  chmod 0755 "$PANEL_DIR/watchdog/vnm-watchdog.js" 2>/dev/null || true
  ok "code tree root-owned; service can read+traverse, cannot write"

  step "4/6" "Web-exposed static assets"
  find "$PANEL_DIR/public" -type d -exec chmod 0755 {} \; 2>/dev/null || true
  find "$PANEL_DIR/public" -type f -exec chmod 0644 {} \; 2>/dev/null || true
  ok "public/ readable (the only web surface)"

  step "5/6" "Secrets"
  if [[ -f "$PANEL_DIR/.env" ]]; then
    chown "root:$SERVICE_USER" "$PANEL_DIR/.env"; chmod 0640 "$PANEL_DIR/.env"
    ok ".env -> root:$SERVICE_USER 0640 (service-readable, root-owned, NOT web-reachable)"
  else
    warn "no .env found (using defaults)"
  fi
  for f in "$DATA_DIR/vnm.db" "$DATA_DIR/vnm.db-wal" "$DATA_DIR/vnm.db-shm"; do
    [[ -f "$f" ]] && { chown "$SERVICE_USER:$SERVICE_USER" "$f"; chmod 0640 "$f"; }
  done
  ok "database + WAL owned by $SERVICE_USER only"

  step "6/6" "Watchdog sudo (restart rights only)"
  if command -v systemctl >/dev/null 2>&1; then
    cat > /etc/sudoers.d/vnm-watchdog <<EOF
# VNM Shield: allow the watchdog service user to restart ONLY these units
$SERVICE_USER ALL=(root) NOPASSWD: /usr/bin/systemctl restart vnm-panel, /usr/bin/systemctl restart vnm-agent, /bin/systemctl restart vnm-panel, /bin/systemctl restart vnm-agent
EOF
    chmod 0440 /etc/sudoers.d/vnm-watchdog
    if visudo -c -f /etc/sudoers.d/vnm-watchdog >/dev/null 2>&1; then
      ok "sudoers drop-in installed (restart vnm-panel + vnm-agent ONLY)"
    else
      rm -f /etc/sudoers.d/vnm-watchdog
      warn "sudoers validation failed - removed; configure watchdog restart rights manually"
    fi
  else
    warn "systemd not present - skipped sudoers"
  fi

  echo
  printf '%sLockdown applied.%s\n' "$c_green" "$c_off"
  cat <<EOF

  Service runs as : $SERVICE_USER (no shell login)
  Code            : $PANEL_DIR (root-owned, read-only for service)
  Data + backups  : $DATA_DIR (service-writable ONLY here)
  VM disks        : $VM_DIR

  If the panel unit does not already run as $SERVICE_USER, update it:
    [Service] User=$SERVICE_USER Group=$SERVICE_USER
  then: systemctl daemon-reload && systemctl restart vnm-panel

  RECOVERY (if permissions ever get mangled, e.g. an update ran as root):
    sudo $0 --recover

  HONEST LIMIT: root on the host can always bypass these file
  protections - this profile constrains the service, customers, and
  staff, not a compromised root account.
EOF
}

check_profile() {
  local bad=0
  step "CHECK" "verifying lockdown profile"
  if id "$SERVICE_USER" >/dev/null 2>&1; then ok "user $SERVICE_USER exists"; else fail "user $SERVICE_USER MISSING"; bad=1; fi
  local owner perm
  owner=$(stat -c '%U' "$PANEL_DIR/app.js" 2>/dev/null || echo '?')
  [[ "$owner" == "root" ]] && ok "app.js owned by root" || { fail "app.js owned by $owner (expected root)"; bad=1; }
  perm=$(stat -c '%a' "$PANEL_DIR/app.js" 2>/dev/null || echo '?')
  [[ "$perm" == "640" ]] && ok "app.js mode 640" || { fail "app.js mode $perm (expected 640)"; bad=1; }
  perm=$(stat -c '%a' "$DATA_DIR" 2>/dev/null || echo '?')
  [[ "$perm" == "750" ]] && ok "data dir mode 750" || { fail "data dir mode $perm (expected 750)"; bad=1; }
  owner=$(stat -c '%U' "$DATA_DIR" 2>/dev/null || echo '?')
  [[ "$owner" == "$SERVICE_USER" ]] && ok "data dir owned by $SERVICE_USER" || { fail "data dir owned by $owner"; bad=1; }
  if [[ -f "$PANEL_DIR/.env" ]]; then
    perm=$(stat -c '%a' "$PANEL_DIR/.env")
    [[ "$perm" == "640" ]] && ok ".env mode 640" || { fail ".env mode $perm (expected 640)"; bad=1; }
  fi
  if [[ -f /etc/sudoers.d/vnm-watchdog ]]; then ok "watchdog sudoers present"; else warn "watchdog sudoers not installed"; fi
  if [[ $bad -eq 0 ]]; then printf '%sAll checks passed.%s\n' "$c_green" "$c_off"; else printf '%sDeviations found - run: sudo %s --recover%s\n' "$c_red" "$0" "$c_off"; exit 1; fi
}

case "$MODE" in
  --apply)   apply_profile ;;
  --check)   check_profile ;;
  --recover) apply_profile; echo "Recovery complete (same as --apply)." ;;
  *) echo "Usage: sudo $0 [--apply|--check|--recover]"; exit 2 ;;
esac
