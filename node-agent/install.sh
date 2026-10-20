#!/bin/bash
# =====================================================================
# VNM Node Agent installer — v2 (dual-mode)
# ---------------------------------------------------------------------
# Usage (root, from inside the extracted node-agent/ directory):
#   sudo bash install.sh --panel-url https://your-panel.example.com --token vnm_agent_...
#
# Or without root (GitHub Codespaces, shared hosts) — installs to
# ~/.vnm-agent and runs as your own user:
#   bash install.sh --panel-url https://panel.example.com --token ... --user
#
# Run modes (VNM_AGENT_MODE=auto|systemd|standalone, default auto):
#   systemd     service unit, enabled at boot, journald logging
#   standalone  nohup + pidfile + @reboot crontab + vnmagentctl manager
#               (Codespaces, Docker, LXC, anything without systemd)
# Re-running with the other mode migrates seamlessly (config + VMs kept).
#
# What it does:
#   - Creates a dedicated "vnm-agent" service user (root installs only)
#   - Installs Node.js if missing (Debian/Ubuntu apt)
#   - Installs the agent to /opt/vnm-agent (root) or ~/.vnm-agent (user)
#   - Writes the panel URL + token config (600, private)
#   - Installs and starts the agent in the chosen mode
#   - Installs vnmagentctl (start|stop|restart|status|logs|upgrade|mode)
# =====================================================================
set -euo pipefail

PANEL_URL=""
AGENT_TOKEN=""
INSTALL_DEPS=0
MODE="${VNM_AGENT_MODE:-auto}"
ROOTLESS=0
SERVICE_USER="vnm-agent"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --panel-url) PANEL_URL="$2"; shift 2 ;;
    --token) AGENT_TOKEN="$2"; shift 2 ;;
    --install-deps) INSTALL_DEPS=1; shift ;;
    --user) ROOTLESS=1; shift ;;
    --mode) MODE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [[ -z "$PANEL_URL" || -z "$AGENT_TOKEN" ]]; then
  echo "Usage: sudo bash install.sh --panel-url https://your-panel.example.com --token <token>"
  echo "       bash   install.sh --panel-url ... --token ... --user        # no-root install"
  echo ""
  echo "  --install-deps   also install VM-hosting packages (qemu-system-x86,"
  echo "                   qemu-utils, genisoimage) via apt - Debian/Ubuntu only"
  echo "  --mode M         systemd | standalone | auto (default auto-detect)"
  echo "  --user           install to ~/.vnm-agent and run as current user"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  # Not root: force the rootless layout automatically
  ROOTLESS=1
fi

if [[ "$ROOTLESS" == "1" ]]; then
  INSTALL_DIR="$HOME/.vnm-agent"
  CONFIG_DIR="$HOME/.config/vnm-agent"
  SERVICE_USER="$(id -un)"
else
  INSTALL_DIR="/opt/vnm-agent"
  CONFIG_DIR="/etc/vnm-agent"
fi
MODE_FILE="$INSTALL_DIR/.vnm-mode"
CRON_MARKER="# vnm-agent-autostart"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m ! \033[0m%s\n' "$*"; }

# ---------------------------------------------------------------------
# Mode detection: systemd counts only if it actually works
# ---------------------------------------------------------------------
systemd_works() {
  [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1
}

if [[ "$MODE" != "systemd" && "$MODE" != "standalone" && "$MODE" != "auto" ]]; then
  warn "Unknown VNM_AGENT_MODE '$MODE' - using auto"
  MODE=auto
fi
if [[ "$MODE" == "auto" ]]; then
  if systemd_works && [[ "$ROOTLESS" != "1" ]]; then MODE="systemd"; else MODE="standalone"; fi
fi
if [[ "$MODE" == "systemd" && "$ROOTLESS" == "1" ]]; then
  warn "systemd user services are not managed here - using standalone mode."
  MODE="standalone"
fi
say "Run mode: $MODE"

# ---------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------
say "Checking for Node.js..."
if ! command -v node >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    if [[ $EUID -eq 0 ]]; then
      say "Installing Node.js via apt..."
      apt-get update -y && apt-get install -y nodejs npm
    else
      warn "Node.js missing and we're not root - install Node 18+ yourself and re-run."
      exit 1
    fi
  else
    warn "Node.js missing and this installer only auto-installs it via apt."
    warn "Install Node.js 18+ manually (e.g. from nodejs.org), then re-run."
    exit 1
  fi
fi
say "Node.js: $(node --version)"

if [[ "$INSTALL_DEPS" == "1" ]] && command -v apt-get >/dev/null 2>&1 && [[ $EUID -eq 0 ]]; then
  DEPS=""
  command -v qemu-system-x86_64 >/dev/null 2>&1 || DEPS="$DEPS qemu-system-x86"
  command -v qemu-img         >/dev/null 2>&1 || DEPS="$DEPS qemu-utils"
  if ! command -v cloud-localds >/dev/null 2>&1 \
     && ! command -v genisoimage >/dev/null 2>&1 \
     && ! command -v xorriso     >/dev/null 2>&1 \
     && ! command -v mkisofs     >/dev/null 2>&1; then
    DEPS="$DEPS genisoimage"
  fi
  if [[ -n "$DEPS" ]]; then
    say "Installing VM-hosting packages:$DEPS"
    apt-get update -y && apt-get install -y$DEPS
  else
    say "All VM-hosting tools already present."
  fi
fi
for tool in qemu-system-x86_64 qemu-img; do
  if ! command -v $tool >/dev/null 2>&1; then
    warn "$tool NOT FOUND - VMs can't run here until it's installed (re-run with --install-deps on Debian/Ubuntu). Stats and file relay still work."
  fi
done
if [[ -e /dev/kvm ]]; then say "/dev/kvm present (hardware-accelerated VMs)";
else warn "/dev/kvm NOT present - VMs will run slowly (software emulation)."; fi

# ---------------------------------------------------------------------
# Files + config
# ---------------------------------------------------------------------
if [[ "$ROOTLESS" != "1" ]]; then
  say "Creating service user '$SERVICE_USER'..."
  if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
fi

say "Installing agent to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r "$SCRIPT_DIR"/agent.js "$SCRIPT_DIR"/lib "$SCRIPT_DIR"/package.json "$SCRIPT_DIR"/package-lock.json "$INSTALL_DIR"/ 2>/dev/null \
  || cp -r "$SCRIPT_DIR"/agent.js "$SCRIPT_DIR"/lib "$SCRIPT_DIR"/package.json "$INSTALL_DIR"/
cd "$INSTALL_DIR"
if command -v npm >/dev/null 2>&1; then
  npm install --omit=dev --no-audit --no-fund
fi
mkdir -p "$INSTALL_DIR/vms"
if [[ "$ROOTLESS" != "1" ]]; then
  chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"
fi

say "Writing config to $CONFIG_DIR/agent.env..."
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_DIR/agent.env" <<EOF
PANEL_URL=$PANEL_URL
AGENT_TOKEN=$AGENT_TOKEN
AGENT_VM_DIR=$INSTALL_DIR/vms
EOF
if [[ "$ROOTLESS" != "1" ]]; then
  chown root:"$SERVICE_USER" "$CONFIG_DIR/agent.env"
  chmod 640 "$CONFIG_DIR/agent.env"
else
  chmod 600 "$CONFIG_DIR/agent.env"
fi
echo "$MODE" > "$MODE_FILE"

# ---------------------------------------------------------------------
# vnmagentctl - mode-aware manager, always installed
# ---------------------------------------------------------------------
say "Installing vnmagentctl manager..."
cat > "$INSTALL_DIR/vnmagentctl" <<MANAGER
#!/bin/bash
# vnmagentctl - manage the VNM node agent (mode-aware)
set -u
DIR="$INSTALL_DIR"
CFG="$CONFIG_DIR/agent.env"
PID_FILE="\$DIR/agent.pid"
MODE_FILE="\$DIR/.vnm-mode"
RUN_AS="${SERVICE_USER}"
MODE="\$(cat "\$MODE_FILE" 2>/dev/null || echo standalone)"

agent_pid() {
  [[ -f "\$PID_FILE" ]] || return 1
  local p; p="\$(cat "\$PID_FILE")"
  [[ -n "\$p" ]] && kill -0 "\$p" 2>/dev/null && { echo "\$p"; return 0; }
  return 1
}

is_active() {
  if [[ "\$MODE" == "systemd" ]]; then
    systemctl is-active --quiet vnm-agent
  else
    agent_pid >/dev/null
  fi
}

do_start() {
  if is_active; then echo "vnm-agent already running"; return 0; fi
  if [[ "\$MODE" == "systemd" ]]; then systemctl start vnm-agent; else
    run_env="set -a; source '\$CFG'; set +a"
    if [[ "\$(id -un)" == "\$RUN_AS" ]]; then
      cd "\$DIR" && bash -c "\$run_env; nohup node agent.js >> \$DIR/agent.log 2>&1 & echo \$! > \$PID_FILE"
    else
      sudo -u "\$RUN_AS" bash -c "cd \$DIR && \$run_env && nohup node agent.js >> \$DIR/agent.log 2>&1 & echo \$! > \$PID_FILE"
    fi
  fi
  sleep 1
  is_active && echo "vnm-agent started (mode: \$MODE)" || { echo "FAILED to start - see \$DIR/agent.log"; exit 1; }
}

do_stop() {
  if [[ "\$MODE" == "systemd" ]]; then systemctl stop vnm-agent; echo "vnm-agent stopped"; else
    local p; if p="\$(agent_pid)"; then kill "\$p" 2>/dev/null || true
      for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 "\$p" 2>/dev/null || break; sleep 0.5; done
      kill -0 "\$p" 2>/dev/null && kill -9 "\$p" 2>/dev/null || true
      rm -f "\$PID_FILE"; echo "vnm-agent stopped"
    else echo "vnm-agent not running"; fi
  fi
}

case "\${1:-help}" in
  start)   do_start ;;
  stop)    do_stop ;;
  restart) do_stop; sleep 1; do_start ;;
  status)  if is_active; then
             echo "vnm-agent RUNNING (mode: \$MODE\$( [[ -f "\$PID_FILE" ]] && echo ", pid \$(cat "\$PID_FILE")" ))"
           else echo "vnm-agent STOPPED (mode: \$MODE)"; exit 1; fi ;;
  logs)    if [[ "\$MODE" == "systemd" ]]; then journalctl -u vnm-agent -n "\${2:-50}" --no-pager;
           else tail -n "\${2:-50}" "\$DIR/agent.log"; fi ;;
  mode)    echo "\$MODE" ;;
  upgrade) cd "\$DIR" && git pull --ff-only 2>/dev/null || warn "not a git checkout - upgrade by re-running the panel's agent installer"
           [[ "\${2:-}" == "--restart" ]] && { do_stop; sleep 1; do_start; } ;;
  help|*)  echo "vnmagentctl {start|stop|restart|status|logs [N]|mode|upgrade [--restart]}" ;;
esac
MANAGER
chmod +x "$INSTALL_DIR/vnmagentctl"
mkdir -p /usr/local/bin 2>/dev/null || true
if [[ $EUID -eq 0 ]]; then
  ln -sf "$INSTALL_DIR/vnmagentctl" /usr/local/bin/vnmagentctl
else
  mkdir -p "$HOME/.local/bin"
  ln -sf "$INSTALL_DIR/vnmagentctl" "$HOME/.local/bin/vnmagentctl"
  warn "Add ~/.local/bin to PATH if vnmagentctl isn't found: echo 'export PATH=\$HOME/.local/bin:\$PATH' >> ~/.bashrc"
fi

# ---------------------------------------------------------------------
# Mode-specific install + migration
# ---------------------------------------------------------------------
stop_old_mode() {
  if [[ -f "$MODE_FILE" ]]; then
    OLD="$(cat "$MODE_FILE")"
  else
    OLD="systemd"  # legacy installs were systemd-or-nohup
  fi
  if [[ "$OLD" != "$MODE" ]]; then
    say "Migrating from '$OLD' mode to '$MODE' (config + VMs kept)..."
  fi
  case "$OLD" in
    systemd)
      systemctl stop vnm-agent 2>/dev/null || true
      systemctl disable vnm-agent 2>/dev/null || true
      rm -f /etc/systemd/system/vnm-agent.service
      systemctl daemon-reload 2>/dev/null || true
      ;;
    standalone)
      if [[ -f "$INSTALL_DIR/agent.pid" ]]; then
        p="$(cat "$INSTALL_DIR/agent.pid")"
        [[ -n "$p" ]] && kill "$p" 2>/dev/null || true
        rm -f "$INSTALL_DIR/agent.pid"
      fi
      (crontab -l 2>/dev/null | grep -v "$CRON_MARKER") | crontab - 2>/dev/null || true
      ;;
  esac
}

if [[ "$MODE" == "systemd" ]]; then
  stop_old_mode
  say "Installing systemd service..."
  NODE_BIN="$(command -v node)"
  NODE_BIN="$(readlink -f "$NODE_BIN" 2>/dev/null || echo "$NODE_BIN")"
  say "Using Node at $NODE_BIN"
  case "$NODE_BIN" in
    /root/*|/home/*) warn "Node is under a home directory (nvm?). The unprivileged $SERVICE_USER user may not be able to run it."
                     warn "If the service fails, install Node system-wide and re-run." ;;
  esac
  sed "s|@NODE_BIN@|$NODE_BIN|g" "$SCRIPT_DIR/vnm-agent.service" > /etc/systemd/system/vnm-agent.service
  systemctl daemon-reload
  systemctl enable vnm-agent
  systemctl restart vnm-agent
  sleep 2
  systemctl --no-pager status vnm-agent || true
  echo ""
  say "Done. Follow logs:  journalctl -u vnm-agent -f"
else
  stop_old_mode
  say "Standalone mode: starting with nohup + pidfile..."
  if [[ "$ROOTLESS" != "1" ]]; then
    sudo -u "$SERVICE_USER" bash -c "cd $INSTALL_DIR && set -a && source $CONFIG_DIR/agent.env && set +a && nohup node agent.js >> $INSTALL_DIR/agent.log 2>&1 & echo \$! > $INSTALL_DIR/agent.pid"
    chown "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR/agent.pid" 2>/dev/null || true
  else
    cd "$INSTALL_DIR" && bash -c "set -a && source $CONFIG_DIR/agent.env && set +a && nohup node agent.js >> $INSTALL_DIR/agent.log 2>&1 & echo \$! > $INSTALL_DIR/agent.pid"
  fi
  sleep 1
  if [[ -f "$INSTALL_DIR/agent.pid" ]] && kill -0 "$(cat "$INSTALL_DIR/agent.pid")" 2>/dev/null; then
    say "Agent running (pid $(cat "$INSTALL_DIR/agent.pid"))"
  else
    warn "Agent may have failed to start - check $INSTALL_DIR/agent.log"
    tail -5 "$INSTALL_DIR/agent.log" 2>/dev/null || true
  fi
  # @reboot autostart (root: system crontab; user: user crontab)
  say "Installing @reboot autostart..."
  CRON_LINE="$CRON_MARKER
@reboot cd $INSTALL_DIR && set -a && source $CONFIG_DIR/agent.env && set +a && nohup node agent.js >> $INSTALL_DIR/agent.log 2>&1 & echo \$! >> $INSTALL_DIR/agent.pid"
  if [[ "$ROOTLESS" != "1" ]]; then
    (crontab -l 2>/dev/null | grep -v "$CRON_MARKER"; echo "$CRON_LINE") | crontab -
  else
    (crontab -l 2>/dev/null | grep -v "$CRON_MARKER"; echo "$CRON_LINE") | crontab -
  fi
  echo ""
  say "Done. Logs: $INSTALL_DIR/agent.log   Manage: vnmagentctl {status|restart|stop|logs}"
fi

echo ""
say "Agent installed:  $INSTALL_DIR (mode: $MODE)"
say "Made by Immortal"
