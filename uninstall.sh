#!/usr/bin/env bash
#
# VNM Panel — Uninstaller
#   sudo bash uninstall.sh             # remove service, keep data
#   sudo bash uninstall.sh --purge     # remove EVERYTHING (VM disks too!)
#   sudo bash uninstall.sh --yes       # don't ask for confirmation on purge
#
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/vnm-panel}"
SERVICE_NAME="${SERVICE_NAME:-vnm-panel}"
SERVICE_USER="${SERVICE_USER:-vnm}"
PURGE=0
ASSUME_YES=0

for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
  esac
done

if [ "${EUID}" -ne 0 ]; then
  echo "Please run as root (sudo bash uninstall.sh)"
  exit 1
fi

echo "==> Stopping and disabling ${SERVICE_NAME}"
systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload 2>/dev/null || true

if [ "${PURGE}" -eq 1 ]; then
  echo ""
  echo "!! PURGE MODE — this deletes ALL VM disks, backups, databases and"
  echo "!! settings under ${INSTALL_DIR} and /home/${SERVICE_USER}"
  echo ""
  CONFIRM="yes"
  if [ "${ASSUME_YES}" -eq 0 ]; then
    read -r -p "Type 'yes' to confirm: " CONFIRM
  fi
  if [ "${CONFIRM}" = "yes" ]; then
    rm -rf "${INSTALL_DIR}"
    if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
      # kill anything the service user still runs before removing its home
      pkill -u "${SERVICE_USER}" 2>/dev/null || true
      sleep 1
      userdel -r "${SERVICE_USER}" 2>/dev/null || userdel "${SERVICE_USER}" 2>/dev/null || true
    fi
    echo "Removed. (If you enabled the firewall port: ufw delete allow 8080/tcp)"
  else
    echo "Purge cancelled — install directory left in place."
  fi
else
  echo "==> Service removed."
  echo "    Install directory kept at ${INSTALL_DIR} (databases, VM disks, .env)."
  echo "    Delete it manually, or re-run with --purge to remove everything."
  echo ""
  echo "    Re-install later any time with:"
  echo "      curl -fsSL https://raw.githubusercontent.com/nishant1477/vnm-panel3.0/main/install.sh | sudo bash"
fi
