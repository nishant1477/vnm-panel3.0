#!/usr/bin/env bash
#
#  ██╗   ██╗███╗   ██╗██╗  ██╗██╗   ██╗ ————— VNM PANEL —————
#  ██║   ██║████╗  ██║██║ ██╔╝██║   ██║  Virtualization Management Panel
#  ██║   ██║██╔██╗ ██║█████╔╝██║   ██║  Made by Immortal · v3.0.1
#  ██║   ██║██║╚██╗██║██╔═██╗██║   ██║
#  ╚██████╔╝██║ ╚████║██║  ██╗╚██████╔╝  https://github.com/nishant1477/vnm-panel3.0
#   ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝
#
#  ╔══════════════════════════════════════════════════════════════════╗
#  ║                    ONE-CLICK VPS INSTALLER                        ║
#  ╠══════════════════════════════════════════════════════════════════╣
#  ║  Installs EVERYTHING in one run: Node.js, QEMU/KVM, the panel,   ║
#  ║  config, service + firewall — and prints your admin password.     ║
#  ╠══════════════════════════════════════════════════════════════════╣
#  ║  TWO RUN MODES:                                                   ║
#  ║   • systemd   — auto-start on boot, auto-restart (VPS default)    ║
#  ║   • standalone— no systemd needed; managed via ./vnmctl           ║
#  ║                 (GitHub Codespaces, containers, shared hosts)     ║
#  ╚══════════════════════════════════════════════════════════════════╝
#
#  ─── USAGE ───────────────────────────────────────────────────────────────
#  One-click from GitHub (Ubuntu/Debian VPS, as root):
#      curl -fsSL https://raw.githubusercontent.com/nishant1477/vnm-panel3.0/main/install.sh | sudo bash
#
#  Pick a mode explicitly:
#      curl -fsSL .../install.sh | sudo VNM_MODE=standalone bash
#      curl -fsSL .../install.sh | sudo VNM_MODE=systemd bash
#
#  Offline / from the downloaded zip:
#      sudo bash install.sh
#      sudo VNM_SOURCE=./VNM-Panel-v3.0.1-linux-x64-bundled.zip bash install.sh
#
#  Upgrade any time — data & settings are always kept:
#      (re-run any command above)
#
#  ─── OPTIONS (environment variables) ─────────────────────────────────────
#    VNM_MODE      systemd | standalone | auto   (default: auto-detect)
#    VNM_REPO_URL  repo to clone  (default: nishant1477/vnm-panel3.0)
#    VNM_BRANCH    branch to install (default: repo default / main)
#    VNM_SOURCE    local dir / .zip / .tar.gz instead of git
#    INSTALL_DIR   default /opt/vnm-panel
#    PORT          default 8080
#    NODE_MAJOR    default 22
#    SERVICE_NAME  default vnm-panel
#    SERVICE_USER  default vnm
#    VNM_SKIP_QEMU 1 = skip QEMU/KVM packages (panel-only host)
#    VNM_SKIP_NODE 1 = trust existing Node.js
#    VNM_SKIP_FW   1 = skip UFW rule
#
set -euo pipefail

VNM_VERSION="3.0.1"
VNM_REPO_URL="${VNM_REPO_URL:-https://github.com/nishant1477/vnm-panel3.0.git}"
VNM_BRANCH="${VNM_BRANCH:-}"
VNM_SOURCE="${VNM_SOURCE:-}"
INSTALL_DIR="${INSTALL_DIR:-/opt/vnm-panel}"
PANEL_PORT="${PORT:-8080}"
SERVICE_NAME="${SERVICE_NAME:-vnm-panel}"
SERVICE_USER="${SERVICE_USER:-vnm}"
NODE_MAJOR="${NODE_MAJOR:-22}"
VNM_MODE="${VNM_MODE:-auto}"
VNM_SKIP_QEMU="${VNM_SKIP_QEMU:-0}"
VNM_SKIP_NODE="${VNM_SKIP_NODE:-0}"
VNM_SKIP_FW="${VNM_SKIP_FW:-0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" 2>/dev/null && pwd)" || SCRIPT_DIR="$PWD"
WORK_DIR="$(mktemp -d /tmp/vnm-install.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

# ══════════════════════════════════════════════════════════════════════════
#  DESIGN SYSTEM — terminal UI
# ══════════════════════════════════════════════════════════════════════════
if [ -t 1 ]; then
  R=$'\033[0m';  B=$'\033[1m'; DIM=$'\033[2m'
  RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'
  CYN=$'\033[36m'; MAG=$'\033[35m'; WHT=$'\033[97m'
  # aurora gradient pieces (cyan → indigo → violet)
  A1=$'\033[38;5;81m'; A2=$'\033[38;5;105m'; A3=$'\033[38;5;141m'
else
  R=''; B=''; DIM=''; RED=''; GRN=''; YLW=''; CYN=''; MAG=''; WHT=''; A1=''; A2=''; A3=''
fi

# the step counter
_TOTAL_STEPS=10
_STEP=0

hdr() {  # section header bar (dynamically aligned box)
  _STEP=$((_STEP + 1))
  local left="  STEP ${_STEP}/${_TOTAL_STEPS}  $1"
  local pad=$(( 61 - ${#left} ))
  [ "$pad" -lt 1 ] && pad=1
  printf '\n%s%s┌─────────────────────────────────────────────────────────────┐%s\n' "$B$A1" '' "$R"
  printf '%s│%s%s%*s%s│%s\n' "$B$A1" "$R$B" "$left" "$pad" '' "$A1$B" "$R"
  printf '%s%s└─────────────────────────────────────────────────────────────┘%s\n' "$B$A1" '' "$R"
}

ok()    { printf '   %s%s✔%s  %s\n' "$GRN$B" '' "$R" "$1"; }
warn()  { printf '   %s%s⚠%s  %s%s%s\n' "$YLW$B" '' "$R" "$YLW" "$1" "$R"; }
err()   { printf '   %s%s✘%s  %s%s%s\n' "$RED$B" '' "$R" "$RED" "$1" "$R"; }
info()  { printf '   %s%sℹ%s  %s%s%s\n' "$CYN" '' "$R" "$DIM" "$1" "$R"; }
sub()   { printf '       %s·%s %s\n' "$A3" "$R" "$1"; }

banner() {
  printf '%s' "$A1"
  cat <<'EOF'
  ██╗   ██╗███╗   ██╗██╗  ██╗██╗   ██╗
EOF
  printf '%s' "$A2"
  cat <<'EOF'
  ██║   ██║████╗  ██║██║ ██╔╝██║   ██║
EOF
  printf '%s' "$A3"
  cat <<'EOF'
  ██║   ██║██╔██╗ ██║█████╔╝██║   ██║
  ██║   ██║██║╚██╗██║██╔═██╗██║   ██║
  ╚██████╔╝██║ ╚████║██║  ██╗╚██████╔╝
   ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝
EOF
  printf '%s' "$R"
  printf '  %s%sVirtualization Management Panel%s  %s·%s  %sv%s%s\n' "$B$WHT" '' "$R" "$DIM" "$R" "$B" "$VNM_VERSION" "$R"
  printf '  %sMade by Immortal%s    %shttps://github.com/nishant1477/vnm-panel3.0%s\n' "$B$MAG" "$R" "$DIM" "$R"
  printf '\n'
}

line() { printf '  %s%s────────────────────────────────────────────────────────────%s\n' "$DIM" '──────────' "$R"; }

# ══════════════════════════════════════════════════════════════════════════
banner

# ── STEP 1: pre-flight ─────────────────────────────────────────────────────
hdr "Pre-flight checks"

if [ "${EUID}" -ne 0 ]; then
  err "This installer must run as root. Try:  sudo bash install.sh"
  exit 1
fi
ok "Running as root"

VNM_FORCE_OS="${VNM_FORCE_OS:-0}"
if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian) ok "Supported OS: ${PRETTY_NAME:-$ID}" ;;
    *)
      if [ "$VNM_FORCE_OS" = "1" ]; then
        warn "Untested OS (${PRETTY_NAME:-$ID}) — continuing (VNM_FORCE_OS=1)"
      else
        err "Unsupported OS: ${PRETTY_NAME:-$ID} (targets Ubuntu/Debian)."
        info "If your distro uses apt, retry with:  sudo VNM_FORCE_OS=1 bash install.sh"
        exit 1
      fi
      ;;
  esac
else
  if [ "$VNM_FORCE_OS" = "1" ]; then
    warn "/etc/os-release missing — continuing (VNM_FORCE_OS=1)"
  else
    err "Cannot detect the OS (/etc/os-release missing)."
    info "Retry with:  sudo VNM_FORCE_OS=1 bash install.sh"
    exit 1
  fi
fi

UPGRADE=0
if [ -f "${INSTALL_DIR}/app.js" ]; then
  UPGRADE=1
  ok "Existing install found — this run will ${YLW}UPGRADE${R} it"
else
  ok "Fresh install into ${DIM}${INSTALL_DIR}${R}"
fi

# ── STEP 2: system packages ────────────────────────────────────────────────
hdr "System packages (apt)"

export DEBIAN_FRONTEND=noninteractive
if ! apt-get update -y >/dev/null 2>&1; then
  warn "apt-get update exited non-zero — continuing anyway"
fi

BASE_PKGS=(curl ca-certificates gnupg unzip git rsync openssl)
if [ "$VNM_SKIP_QEMU" != "1" ]; then
  BASE_PKGS+=(build-essential python3 sqlite3 libsqlite3-dev
              qemu-system-x86 qemu-utils cloud-image-utils genisoimage xorriso
              bridge-utils net-tools)
fi
if apt-get install -y -qq "${BASE_PKGS[@]}" >/dev/null 2>&1; then
  ok "Base tools installed"
else
  apt-get install -y "${BASE_PKGS[@]}"
fi
if [ "$VNM_SKIP_QEMU" = "1" ]; then
  warn "VNM_SKIP_QEMU=1 — QEMU/KVM packages skipped (no local VMs on this host)"
else
  ok "QEMU/KVM + disk-image toolchain ready"
fi

# ── STEP 3: Node.js ────────────────────────────────────────────────────────
hdr "Node.js runtime"

node_ok() {
  command -v node >/dev/null 2>&1 || return 1
  local major
  major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  [ "$major" -ge 18 ] 2>/dev/null
}

if node_ok && [ "$VNM_SKIP_NODE" != "1" ]; then
  ok "Node.js $(node -v) already present — keeping it"
elif [ "$VNM_SKIP_NODE" = "1" ]; then
  node_ok || { err "VNM_SKIP_NODE=1 but no usable Node.js (>=18) found"; exit 1; }
  ok "Using existing Node.js $(node -v)"
else
  info "Installing Node.js ${NODE_MAJOR}.x via NodeSource..."
  if curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" -o "$WORK_DIR/nodesource.sh"; then
    bash "$WORK_DIR/nodesource.sh" >/dev/null 2>&1
    apt-get install -y -qq nodejs >/dev/null 2>&1 || apt-get install -y nodejs
  else
    warn "NodeSource unreachable — falling back to distro Node.js"
    apt-get install -y -qq nodejs >/dev/null 2>&1 || apt-get install -y nodejs
  fi
  node_ok || { err "Node.js installation failed"; exit 1; }
  ok "Node.js $(node -v) installed"
fi
ok "npm $(npm -v)"

# ── STEP 4: KVM check ──────────────────────────────────────────────────────
if [ "$VNM_SKIP_QEMU" != "1" ]; then
  hdr "Hardware virtualization (KVM)"
  if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    ok "/dev/kvm usable — VMs get ${GRN}hardware acceleration${R}"
  else
    warn "/dev/kvm not usable — VMs fall back to software emulation (slower)"
    sub "normal on nested VMs / some VPS plans; check VT-x/AMD-V if unexpected"
  fi
fi

# ── STEP 5: service user ───────────────────────────────────────────────────
hdr "Service user '${SERVICE_USER}'"
if id -u "$SERVICE_USER" >/dev/null 2>&1; then
  ok "User ${SERVICE_USER} exists — reusing"
else
  useradd --system --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
  ok "Created system user ${SERVICE_USER}"
fi
if getent group kvm >/dev/null 2>&1; then
  usermod -aG kvm "$SERVICE_USER" 2>/dev/null || true
  ok "Granted /dev/kvm access (kvm group)"
fi

# ── STEP 6: fetch source ───────────────────────────────────────────────────
hdr "Fetch panel source"

SRC_DIR=""
if [ -n "$VNM_SOURCE" ]; then
  if [ -d "$VNM_SOURCE" ]; then
    SRC_DIR="$VNM_SOURCE"
    ok "Local source directory: $SRC_DIR"
  elif [ -f "$VNM_SOURCE" ]; then
    mkdir -p "$WORK_DIR/src"
    case "$VNM_SOURCE" in
      *.zip) unzip -q "$VNM_SOURCE" -d "$WORK_DIR/src" ;;
      *.tar.gz|*.tgz|*.tar.*) tar -xf "$VNM_SOURCE" -C "$WORK_DIR/src" ;;
      *) err "VNM_SOURCE must be a dir, .zip or .tar.gz — got: $VNM_SOURCE"; exit 1 ;;
    esac
    SRC_DIR="$(find "$WORK_DIR/src" -maxdepth 2 -name app.js -printf '%h\n' | head -n1)"
    [ -n "$SRC_DIR" ] && [ -f "$SRC_DIR/app.js" ] || { err "Archive did not contain the panel (app.js missing)"; exit 1; }
    ok "Extracted local archive: ${VNM_SOURCE##*/}"
  else
    err "VNM_SOURCE path not found: $VNM_SOURCE"
    exit 1
  fi
elif [ -n "$SCRIPT_DIR" ] && [ -f "${SCRIPT_DIR}/app.js" ]; then
  SRC_DIR="$SCRIPT_DIR"
  ok "Using source next to install.sh: $SRC_DIR"
else
  OWNER_REPO="${VNM_REPO_URL#https://github.com/}"
  OWNER_REPO="${OWNER_REPO#http://github.com/}"
  OWNER_REPO="${OWNER_REPO%.git}"
  OWNER_REPO="${OWNER_REPO%/}"
  case "$OWNER_REPO" in
    */*) ;;
    *) err "Cannot parse owner/repo from VNM_REPO_URL ('$VNM_REPO_URL')"
       info "Set it:  sudo VNM_REPO_URL=https://github.com/<you>/<repo>.git bash"
       exit 1 ;;
  esac

  if command -v git >/dev/null 2>&1; then
    if [ -n "$VNM_BRANCH" ]; then
      git clone --depth 1 --branch "$VNM_BRANCH" "$VNM_REPO_URL" "$WORK_DIR/repo" >/dev/null 2>&1
    else
      git clone --depth 1 "$VNM_REPO_URL" "$WORK_DIR/repo" >/dev/null 2>&1
    fi
    [ -f "$WORK_DIR/repo/app.js" ] && SRC_DIR="$WORK_DIR/repo"
    [ -n "$SRC_DIR" ] && ok "Cloned ${OWNER_REPO}$( [ -n "$VNM_BRANCH" ] && echo " @ $VNM_BRANCH" )"
  fi
  if [ -z "$SRC_DIR" ]; then
    for BR in ${VNM_BRANCH:-main} master; do
      URL="https://codeload.github.com/${OWNER_REPO}/zip/refs/heads/${BR}"
      info "Trying ${URL} ..."
      if curl -fsSL "$URL" -o "$WORK_DIR/src.zip"; then
        mkdir -p "$WORK_DIR/src"
        unzip -q "$WORK_DIR/src.zip" -d "$WORK_DIR/src" 2>/dev/null || { rm -rf "$WORK_DIR/src"; mkdir -p "$WORK_DIR/src"; unzip -q "$WORK_DIR/src.zip" -d "$WORK_DIR/src"; }
        SRC_DIR="$(find "$WORK_DIR/src" -maxdepth 2 -name app.js -printf '%h\n' | head -n1)"
        [ -n "$SRC_DIR" ] && [ -f "$SRC_DIR/app.js" ] && break
        SRC_DIR=""
      fi
    done
    [ -n "$SRC_DIR" ] || { err "Could not download the panel from ${VNM_REPO_URL}"; exit 1; }
    ok "Downloaded ${OWNER_REPO} (branch ${VNM_BRANCH:-main})"
  fi
fi

BUNDLED_MODULES=0
[ -d "${SRC_DIR}/node_modules" ] && { BUNDLED_MODULES=1; ok "Bundle carries pre-installed node_modules"; }

# ── STEP 7: install files ──────────────────────────────────────────────────
hdr "Install files → ${INSTALL_DIR}"

mkdir -p "${INSTALL_DIR}"
STAMP="$(date +%Y%m%d-%H%M%S)"
if [ "$UPGRADE" = "1" ] && [ -d "${INSTALL_DIR}/data" ]; then
  cp -a "${INSTALL_DIR}/data" "${INSTALL_DIR}/data.bak-${STAMP}" 2>/dev/null || true
  sub "previous data backed up → data.bak-${STAMP}"
fi

rsync -a --delete \
  --exclude 'node_modules' \
  --exclude 'data' \
  --exclude 'data.bak-*' \
  --exclude '.env' \
  --exclude '*.log' \
  --exclude '*.pid' \
  --exclude 'vnm.db*' \
  "${SRC_DIR}/" "${INSTALL_DIR}/"

if [ "$BUNDLED_MODULES" = "1" ]; then
  mkdir -p "${INSTALL_DIR}/node_modules"
  rsync -a "${SRC_DIR}/node_modules/" "${INSTALL_DIR}/node_modules/"
fi
mkdir -p "${INSTALL_DIR}/data"
ok "Files in place ($(du -sh "${INSTALL_DIR}" 2>/dev/null | cut -f1))"

# ── STEP 8: dependencies + config ──────────────────────────────────────────
hdr "Dependencies & configuration"

deps_healthy() {
  ( cd "${INSTALL_DIR}" && node -e "require('express');require('ejs');require('sqlite3');require('ssh2');require('ws');require('busboy');require('bcryptjs');require('dotenv')" >/dev/null 2>&1 )
}

if [ "$BUNDLED_MODULES" = "1" ] && deps_healthy; then
  ok "Bundled dependencies work — skipping npm install"
elif [ "$BUNDLED_MODULES" = "1" ]; then
  warn "Bundled node_modules don't load on this Node/OS — rebuilding"
  ( cd "${INSTALL_DIR}" && npm rebuild --omit=dev >/dev/null 2>&1 ) || true
  deps_healthy || ( cd "${INSTALL_DIR}" && npm install --omit=dev --no-audit --no-fund >/dev/null 2>&1 ) || ( cd "${INSTALL_DIR}" && npm install --omit=dev --no-audit --no-fund )
  deps_healthy || { err "dependency rebuild failed"; exit 1; }
  ok "Dependencies rebuilt for Node $(node -v)"
else
  info "npm install --omit=dev  (1-3 min on first run)..."
  ( cd "${INSTALL_DIR}" && npm install --omit=dev --no-audit --no-fund ) || { err "npm install failed"; exit 1; }
  deps_healthy || { err "dependencies fail to load after npm install"; exit 1; }
  ok "Dependencies installed"
fi

ENV_FILE="${INSTALL_DIR}/.env"
if [ -f "$ENV_FILE" ]; then
  ok "Existing .env kept (edit ${ENV_FILE} to change settings)"
  PANEL_PORT="$(grep -E '^PORT=' "$ENV_FILE" | tail -n1 | cut -d= -f2 | tr -d '[:space:]')"
  PANEL_PORT="${PANEL_PORT:-8080}"
else
  SESSION_SECRET="$(openssl rand -hex 32 2>/dev/null || node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))')"
  cat > "$ENV_FILE" <<EOF
# VNM Panel configuration (generated by install.sh on ${STAMP})
PORT=${PANEL_PORT}
VNM_DATA_DIR=${INSTALL_DIR}/data
PANEL_NAME=VNM
DEFAULT_LOGO_URL=/images/logo-new.svg
NODE_ENV=production
# Keep this secret — it signs session cookies.
SESSION_SECRET=${SESSION_SECRET}
# Optional: Discord OAuth (leave empty to disable)
# DISCORD_CLIENT_ID=
# DISCORD_CLIENT_SECRET=
# Optional: SMTP for alerts (leave empty to disable email alerts)
# SMTP_HOST=
# SMTP_PORT=587
# SMTP_USER=
# SMTP_PASS=
EOF
  chmod 600 "$ENV_FILE"
  ok "Generated .env — random SESSION_SECRET, port ${PANEL_PORT}"
fi

chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}" 2>/dev/null || true
chmod 600 "${ENV_FILE}" 2>/dev/null || true
sub "ownership → ${SERVICE_USER}, .env locked to 600"

# ══════════════════════════════════════════════════════════════════════════
#  STEP 9: RUN MODE — systemd  |  standalone
# ══════════════════════════════════════════════════════════════════════════
hdr "Service setup — choosing run mode"

SYSTEMD_AVAILABLE=0
if command -v systemctl >/dev/null 2>&1 && { [ -d /run/systemd/system ] || [ "$(ps -p 1 -o comm= 2>/dev/null)" = "systemd" ]; }; then
  SYSTEMD_AVAILABLE=1
fi

# --- vnmctl: the standalone manager (ALWAYS installed — useful in both modes)
VNMCTL="${INSTALL_DIR}/vnmctl"
cat > "$VNMCTL" <<VNMCTL_EOF
#!/usr/bin/env bash
# vnmctl — VNM Panel manager (Made by Immortal)
#   start | stop | restart | status | logs | upgrade | mode
set -u
DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="${SERVICE_NAME}"
SERVICE_USER="${SERVICE_USER}"
RUN_FILE="\$DIR/vnm-panel.run"
LOG_FILE="\$DIR/panel.log"
NODE_BIN="\$(command -v node)"
MODE_FILE="\$DIR/.vnm-mode"          # written by install.sh: systemd | standalone
CHOSEN_MODE="\$( [ -f "\$MODE_FILE" ] && cat "\$MODE_FILE" 2>/dev/null || echo auto )"
[ "\$CHOSEN_MODE" = "systemd" ] || [ "\$CHOSEN_MODE" = "standalone" ] || CHOSEN_MODE=auto

is_systemd() { command -v systemctl >/dev/null 2>&1 && { [ -d /run/systemd/system ] || [ "\$(ps -p 1 -o comm= 2>/dev/null)" = "systemd" ]; }; }
use_systemd() {
  if [ "\$CHOSEN_MODE" = "systemd" ]; then return 0; fi
  if [ "\$CHOSEN_MODE" = "standalone" ]; then return 1; fi
  is_systemd
}

panel_pid() { [ -f "\$RUN_FILE" ] && cat "\$RUN_FILE" 2>/dev/null || true; }

do_start() {
  local pid; pid="\$(panel_pid)"
  if [ -n "\$pid" ] && kill -0 "\$pid" 2>/dev/null; then echo "Already running (pid \$pid)"; exit 0; fi
  if use_systemd && systemctl is-active --quiet "\$SERVICE_NAME" 2>/dev/null; then echo "Running under systemd (pid \$(systemctl show -p MainPID --value "\$SERVICE_NAME"))"; exit 0; fi
  ( cd "\$DIR" && set -a && . "\$DIR/.env" 2>/dev/null; set +a; nohup "\$NODE_BIN" app.js >> "\$LOG_FILE" 2>&1 & echo \$! > "\$RUN_FILE" )
  sleep 1
  local newpid; newpid="\$(panel_pid)"
  if [ -n "\$newpid" ] && kill -0 "\$newpid" 2>/dev/null; then
    echo "Started VNM Panel (pid \$newpid)  →  logs: \$LOG_FILE"
  else
    echo "FAILED to start — last log lines:"; tail -n 15 "\$LOG_FILE" 2>/dev/null; exit 1
  fi
}

do_stop() {
  local pid; pid="\$(panel_pid)"
  if [ -n "\$pid" ] && kill -0 "\$pid" 2>/dev/null; then
    kill "\$pid" 2>/dev/null
    for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 "\$pid" 2>/dev/null || break; sleep 1; done
    kill -9 "\$pid" 2>/dev/null || true
    rm -f "\$RUN_FILE"
    echo "Stopped."
  elif use_systemd && systemctl is-active --quiet "\$SERVICE_NAME" 2>/dev/null; then
    systemctl stop "\$SERVICE_NAME"; echo "Stopped (systemd)."
  else
    echo "Not running."
  fi
}

do_status() {
  local pid; pid="\$(panel_pid)"
  if use_systemd; then
    if systemctl is-active --quiet "\$SERVICE_NAME" 2>/dev/null; then
      echo "mode: systemd   status: ACTIVE   pid: \$(systemctl show -p MainPID --value "\$SERVICE_NAME")"
      exit 0
    fi
  else
    if [ -n "\$pid" ] && kill -0 "\$pid" 2>/dev/null; then
      echo "mode: standalone   status: ACTIVE   pid: \$pid"
      exit 0
    fi
  fi
  echo "mode: \$CHOSEN_MODE   status: STOPPED"
  exit 1
}

case "\${1:-help}" in
  start)   do_start ;;
  stop)    do_stop ;;
  restart) do_stop; sleep 1; do_start ;;
  status)  do_status ;;
  logs)    if use_systemd && systemctl is-active --quiet "\$SERVICE_NAME" 2>/dev/null; then journalctl -u "\$SERVICE_NAME" -f; else tail -f "\$LOG_FILE"; fi ;;
  upgrade)
    echo "Upgrading via install.sh (data & .env are kept)..."
    if command -v curl >/dev/null; then
      curl -fsSL "https://raw.githubusercontent.com/nishant1477/vnm-panel3.0/main/install.sh" | INSTALL_DIR="\$DIR" bash
    else
      echo "curl not available — download install.sh and re-run it manually."
      exit 1
    fi ;;
  mode)    if use_systemd; then echo "systemd"; else echo "standalone"; fi ;;
  *) cat <<'USAGE'
vnmctl — VNM Panel manager (Made by Immortal)

  vnmctl start     start the panel (standalone mode)
  vnmctl stop      stop it
  vnmctl restart   restart it
  vnmctl status    mode + pid + health
  vnmctl logs      follow logs (systemd journal or panel.log)
  vnmctl upgrade   one-command upgrade via install.sh
USAGE
  ;;
esac
VNMCTL_EOF
chmod +x "$VNMCTL"
ok "Installed ${INSTALL_DIR}/vnmctl manager"

# --- decide the mode ---
CHOSEN_MODE=""
if [ "$VNM_MODE" = "systemd" ] || [ "$VNM_MODE" = "standalone" ]; then
  CHOSEN_MODE="$VNM_MODE"
elif [ "$VNM_MODE" = "auto" ] || [ -z "$VNM_MODE" ]; then
  if [ "$SYSTEMD_AVAILABLE" = "1" ]; then CHOSEN_MODE="systemd"; else CHOSEN_MODE="standalone"; fi
else
  err "Unknown VNM_MODE '${VNM_MODE}' — use systemd, standalone, or auto"
  exit 1
fi

if [ "$CHOSEN_MODE" = "systemd" ] && [ "$SYSTEMD_AVAILABLE" = "0" ]; then
  warn "systemd requested but NOT available on this system — falling back to standalone"
  CHOSEN_MODE="standalone"
fi

ok "Run mode selected: ${B}${CHOSEN_MODE}${R}"
echo "$CHOSEN_MODE" > "${INSTALL_DIR}/.vnm-mode"   # vnmctl reads this

if [ "$CHOSEN_MODE" = "systemd" ]; then
  # stop a standalone instance if one is running (mode migration)
  if [ -f "${INSTALL_DIR}/vnm-panel.run" ]; then
    OLD_PID="$(cat "${INSTALL_DIR}/vnm-panel.run" 2>/dev/null || true)"
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then kill "$OLD_PID" 2>/dev/null || true; sleep 1; fi
    rm -f "${INSTALL_DIR}/vnm-panel.run"
  fi

  SERVICE_FILE="${VNM_UNIT_DIR:-/etc/systemd/system}/${SERVICE_NAME}.service"
  mkdir -p "$(dirname "$SERVICE_FILE")"
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=VNM Panel - Virtualization Management Panel (Made by Immortal)
Documentation=https://github.com/nishant1477/vnm-panel3.0
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
Environment=NODE_ENV=production
ExecStart=$(command -v node) ${INSTALL_DIR}/app.js
Restart=on-failure
RestartSec=3
KillMode=mixed
TimeoutStopSec=25
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=${INSTALL_DIR}
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
  systemctl restart "${SERVICE_NAME}"
  ok "systemd unit installed — enabled on boot + started"
  sub "manage: systemctl {status|restart|stop} ${SERVICE_NAME}"
else
  # standalone: stop systemd unit if active (mode migration)
  if [ "$SYSTEMD_AVAILABLE" = "1" ]; then
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload 2>/dev/null || true
  fi
  # clean any stale pid
  [ -f "${INSTALL_DIR}/vnm-panel.run" ] && rm -f "${INSTALL_DIR}/vnm-panel.run"

  # launch via the service user (root not required to run, just to install)
  if [ "${EUID}" -eq 0 ]; then
    sudo -u "${SERVICE_USER}" -n true 2>/dev/null && SU_OK=1 || SU_OK=0
    if [ "$SU_OK" = "1" ]; then
      ( cd "${INSTALL_DIR}" && sudo -u "${SERVICE_USER}" sh -c 'set -a; . ./.env 2>/dev/null; set +a; nohup node app.js >> panel.log 2>&1 & echo $! > vnm-panel.run' )
    else
      ( cd "${INSTALL_DIR}" && set -a && . ./.env 2>/dev/null; set +a; nohup "$(command -v node)" app.js >> panel.log 2>&1 & echo $! > vnm-panel.run )
    fi
  else
    ( cd "${INSTALL_DIR}" && set -a && . ./.env 2>/dev/null; set +a; nohup "$(command -v node)" app.js >> panel.log 2>&1 & echo $! > vnm-panel.run )
  fi
  sleep 1
  SPID="$(cat "${INSTALL_DIR}/vnm-panel.run" 2>/dev/null || true)"
  if [ -n "$SPID" ] && kill -0 "$SPID" 2>/dev/null; then
    ok "Panel started in standalone mode (pid ${SPID})"
  else
    warn "standalone start may have failed — check ${INSTALL_DIR}/panel.log"
  fi
  sub "manage: ${INSTALL_DIR}/vnmctl {start|stop|restart|status|logs|upgrade}"

  # auto-start on boot via @reboot cron (best-effort, standalone mode)
  if [ "${EUID}" -eq 0 ] && command -v crontab >/dev/null 2>&1; then
    CRON_LINE="@reboot ${INSTALL_DIR}/vnmctl start >> ${INSTALL_DIR}/panel.log 2>&1"
    (crontab -u "${SERVICE_USER}" -l 2>/dev/null | grep -vF "${INSTALL_DIR}/vnmctl start"; echo "$CRON_LINE") | crontab -u "${SERVICE_USER}" - 2>/dev/null && ok "Boot auto-start: @reboot crontab installed" || warn "could not install @reboot crontab (optional)"
  fi
fi

# ── STEP 10: firewall + health check ───────────────────────────────────────
hdr "Firewall & health check"

if [ "$VNM_SKIP_FW" != "1" ] && command -v ufw >/dev/null 2>&1; then
  if ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "${PANEL_PORT}/tcp" >/dev/null 2>&1 || true
    ok "UFW: TCP ${PANEL_PORT} allowed"
  else
    info "UFW installed but inactive — nothing to open"
  fi
fi

HEALTHY=0
info "Waiting for the panel to answer on :${PANEL_PORT} ..."
for i in $(seq 1 30); do
  if curl -fsS -o /dev/null --max-time 3 "http://127.0.0.1:${PANEL_PORT}/login" 2>/dev/null; then
    HEALTHY=1
    break
  fi
  sleep 2
done
if [ "$HEALTHY" = "1" ]; then
  ok "Panel is healthy — serving http://127.0.0.1:${PANEL_PORT}/login"
else
  err "Panel did not respond within 60 seconds"
  if [ "$CHOSEN_MODE" = "systemd" ]; then
    journalctl -u "${SERVICE_NAME}" --no-pager -n 30 || true
  else
    tail -n 30 "${INSTALL_DIR}/panel.log" 2>/dev/null || true
  fi
  exit 1
fi

# admin password from the right log for the chosen mode
ADMIN_HINT=""
if [ "$CHOSEN_MODE" = "systemd" ]; then
  ADMIN_HINT="$(journalctl -u "${SERVICE_NAME}" --no-pager -n 200 2>/dev/null | grep -oP 'password: \K\S+' | tail -n1 || true)"
else
  ADMIN_HINT="$(grep -oP 'password: \K\S+' "${INSTALL_DIR}/panel.log" 2>/dev/null | tail -n1 || true)"
fi

SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
SERVER_IP="${SERVER_IP:-<your-server-ip>}"

# ══════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════
printf '\n'
line
printf '  %s%s✔  VNM PANEL v%s — INSTALLED & RUNNING%s\n' "$GRN$B" '' "$VNM_VERSION" "$R"
printf '  %sMade by Immortal%s\n' "$MAG$B" "$R"
line
printf '\n'
printf '   %sURL%s          %shttp://%s:%s%s\n' "$WHT$B" "$R" "$B" "$SERVER_IP" "$PANEL_PORT" "$R"
printf '   %sMode%s         %s\n' "$WHT$B" "$R" "$CHOSEN_MODE"
printf '   %sInstall dir%s  %s\n' "$WHT$B" "$R" "$INSTALL_DIR"
printf '   %sConfig%s       %s\n' "$WHT$B" "$R" "$ENV_FILE"
printf '   %sDatabase%s     %s/data/vnm.db\n' "$WHT$B" "$R" "$INSTALL_DIR"
printf '   %sVM disks%s     /home/%s/vms\n' "$WHT$B" "$R" "$SERVICE_USER"
if [ "$CHOSEN_MODE" = "systemd" ]; then
  printf '   %sService%s      systemctl {status|restart|stop} %s\n' "$WHT$B" "$R" "$SERVICE_NAME"
  printf '   %sLogs%s         journalctl -u %s -f\n' "$WHT$B" "$R" "$SERVICE_NAME"
else
  printf '   %sService%s      %s/vnmctl {start|stop|restart|status|logs|upgrade}\n' "$WHT$B" "$R" "$INSTALL_DIR"
  printf '   %sLogs%s         tail -f %s/panel.log\n' "$WHT$B" "$R" "$INSTALL_DIR"
fi
printf '\n'
if [ "$UPGRADE" = "1" ]; then
  printf '   %sThis was an upgrade — your data, users & settings were kept.%s\n' "$GRN" "$R"
else
  printf '   %sFIRST LOGIN%s\n' "$WHT$B" "$R"
  printf '   Username : %sadmin%s\n' "$B" "$R"
  if [ -n "$ADMIN_HINT" ]; then
    printf '   Password : %s%s%s   %s(auto-generated — change it after login!)%s\n' "$B" "$ADMIN_HINT" "$R" "$DIM" "$R"
  else
    printf '   Password : auto-generated on first boot — find it with:\n'
    if [ "$CHOSEN_MODE" = "systemd" ]; then
      printf '              journalctl -u %s | grep -A1 "Default admin"\n' "$SERVICE_NAME"
    else
      printf '              grep -A1 "Default admin" %s/panel.log\n' "$INSTALL_DIR"
    fi
  fi
fi
printf '\n'
printf '   %sNEXT STEPS%s\n' "$WHT$B" "$R"
printf '    1. Open the URL and log in\n'
printf '    2. Change the admin password (Profile page)\n'
printf '    3. Add OS templates and create your first VM\n'
printf '    4. Optional: connect worker nodes (Nodes page → Install Agent)\n'
printf '    5. Premium (Auto Backup / Live Migration / Alert Rules / Scheduled\n'
printf '       Power) unlocks with a VNM license key inside the UI\n'
printf '\n'
printf '   %sUpgrade anytime (data is kept):%s\n' "$DIM" "$R"
printf '   %scurl -fsSL https://raw.githubusercontent.com/nishant1477/vnm-panel3.0/main/install.sh | sudo bash%s\n' "$CYN" "$R"
printf '\n'
line
printf '  %sMade by Immortal · github.com/nishant1477/vnm-panel3.0%s\n' "$DIM" "$R"
line
printf '\n'
