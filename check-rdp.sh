#!/bin/bash
# =====================================================================
# check-rdp.sh - "I installed the new zip but see no RDP tab"
#
# Finds the VNM panel that is ACTUALLY running on this machine, shows which
# folder it serves from, and tells you whether that copy contains the RDP
# code. Run it from the folder you unzipped the NEW zip into:
#
#     ./check-rdp.sh            # just report
#     sudo ./check-rdp.sh --apply   # copy the new code into the running folder
#                                   # (keeps data/, .env, node_modules) and restart it
# =====================================================================
set -uo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=0; [ "${1:-}" = "--apply" ] && APPLY=1

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }

has_rdp() {   # $1 = panel folder -> 0 if it has the full RDP feature
  [ -f "$1/rdp.js" ] && [ -f "$1/rdp-guest.js" ] \
    && grep -q 'id="tab-rdp"' "$1/views/admin/vm-detail.ejs" 2>/dev/null \
    && grep -q 'id="tab-rdp"' "$1/views/users/vm-detail.ejs" 2>/dev/null \
    && [ -f "$1/views/admin/vm-rdp.ejs" ] && [ -f "$1/views/users/vm-rdp.ejs" ] \
    && grep -q "require('./rdp')" "$1/app.js" 2>/dev/null
}

echo "== 1. The folder you unzipped (the NEW code): $SRC"
if has_rdp "$SRC"; then green "   OK  - contains the RDP feature (rdp.js, RDP tab in admin + user VM pages, app.js hooks)"
else red "   This folder does NOT contain the full RDP feature. Use VNM-Panel-FULL-with-RDP.zip."; exit 1; fi

echo
echo "== 2. Panels running on this machine"
declare -A SEEN=()
FOUND=0; STALE=0
for pid in $(pgrep -f 'app\.js' 2>/dev/null); do
  cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null)" || continue
  [ -f "$cwd/app.js" ] && [ -d "$cwd/views" ] || continue
  grep -q 'VNM' "$cwd/app.js" 2>/dev/null || continue
  [ -n "${SEEN[$cwd]:-}" ] && continue; SEEN[$cwd]=1; FOUND=1
  ports="$(ss -ltnp 2>/dev/null | grep "pid=$pid," | awk '{print $4}' | sed 's/.*://' | sort -u | tr '\n' ' ')"
  unit="$(grep -o '[^/]*\.service' "/proc/$pid/cgroup" 2>/dev/null | tail -1)"
  echo "   PID $pid   folder: $cwd   port(s): ${ports:-?}   service: ${unit:-none/unknown}"
  if has_rdp "$cwd"; then
    green "      -> this running copy HAS the RDP code."
    echo  "         The RDP page is at  /admin/vm/<id>/rdp  (admin)  and  /vm/<id>/rdp  (user); the Create VM wizard has an \"Enable RDP automatically\" switch."
    echo  "         If the tab is still missing: hard-refresh (Ctrl+Shift+R) and open  VM list -> click a VM -> tab bar:"
    echo  "         Overview | Network | RDP | Hardware | Snapshots | Logs"
    echo  "         Its startup log should say:  '✓ RDP feature: ENABLED'"
  else
    STALE=1; red "      -> this running copy is OLD: it has NO RDP code. That is why you see nothing."
    if [ "$APPLY" = 1 ]; then
      [ "$(id -u)" = 0 ] || { red "      --apply needs root: run  sudo ./check-rdp.sh --apply"; exit 1; }
      echo "      Syncing new code into $cwd (keeping data/, .env, node_modules, database) ..."
      rsync -a --exclude node_modules --exclude data --exclude .env --exclude install.sh --exclude '*.db' "$SRC/" "$cwd/" \
        && green "      files updated." || { red "      rsync failed"; exit 1; }
      if [ -n "$unit" ] && command -v systemctl >/dev/null; then
        systemctl restart "$unit" && green "      restarted service: $unit" || red "      could not restart $unit - run: sudo systemctl restart $unit"
      elif command -v pm2 >/dev/null && pm2 pid "$(basename "$cwd")" >/dev/null 2>&1; then pm2 restart all
      else yellow "      Restart the panel yourself now (kill PID $pid and start it again: cd $cwd && node app.js)."; fi
    else
      yellow "      Fix: sudo ./check-rdp.sh --apply      (or: sudo ./install.sh  then restart the service)"
    fi
  fi
done

if [ "$FOUND" = 0 ]; then
  yellow "   No 'node app.js' VNM process found on the host."
  echo   "   The panel may be running in Docker / pm2 / a compiled binary. Check:"
  command -v docker >/dev/null && { echo "     docker ps  ->"; docker ps --format '       {{.Names}}  {{.Image}}' 2>/dev/null | head; echo "     (a container keeps its OWN copy of the code: rebuild/redeploy it from this folder)"; }
  command -v pm2    >/dev/null && { echo "     pm2 list ->"; pm2 list 2>/dev/null | head -12; }
  echo   "     A compiled binary (pkg) has the old pages baked in: it must be rebuilt from this folder."
  echo   "     Or the service is stopped: sudo systemctl status <your-service>"
fi

echo
echo "== 3. After restarting, confirm"
echo "   journalctl -u <service> -n 40 | grep 'RDP'     # expect: ✓ RDP feature: ENABLED (VM Details → RDP tab, host ports 33890-34889)"
echo "   (if you run it by hand, the same line is printed in the terminal when the panel starts)"
[ "$STALE" = 1 ] && [ "$APPLY" = 0 ] && exit 2
exit 0
