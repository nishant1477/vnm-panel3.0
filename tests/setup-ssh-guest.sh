#!/bin/bash
# Turns THIS machine (a Debian/Ubuntu box, run as root) into the SSH side of the
# test rig: sshd on 127.0.0.1:${VNM_TEST_SSH_PORT:-2299}, user "tester" (sudo) and
# "nosudo" (no sudo), plus a no-op systemctl shim for containers without systemd.
# DESTRUCTIVE-ish: only run on a disposable machine/container.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
PORT="${VNM_TEST_SSH_PORT:-2299}"
command -v sshd >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server sudo iproute2 >/dev/null
mkdir -p /run/sshd
id tester >/dev/null 2>&1 || useradd -m -s /bin/bash tester
id nosudo >/dev/null 2>&1 || useradd -m -s /bin/bash nosudo
echo 'tester:Test#Pass123' | chpasswd; echo 'nosudo:Test#Pass123' | chpasswd
usermod -aG sudo tester
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
if ! (ss -ltn | grep -q ":$PORT "); then (setsid /usr/sbin/sshd -p "$PORT" -D >/tmp/vnm-test-sshd.log 2>&1 &); sleep 1; fi
if ! pidof systemd >/dev/null 2>&1 && ! [ -x /usr/local/bin/systemctl ]; then
cat > /usr/local/bin/systemctl <<'S'
#!/bin/bash
case "$1" in
  enable|daemon-reload) exit 0;;
  is-active) pgrep -x xrdp >/dev/null; exit $?;;
  restart|start) shift; for u in "$@"; do case "$u" in
      xrdp-sesman) pkill -x xrdp-sesman 2>/dev/null; rm -f /run/xrdp/xrdp-sesman.pid; sleep 0.5; /usr/sbin/xrdp-sesman;;
      xrdp) pkill -x xrdp 2>/dev/null; rm -f /run/xrdp/xrdp.pid; sleep 0.5; /usr/sbin/xrdp;; esac; done; exit 0;;
esac
exit 0
S
chmod +x /usr/local/bin/systemctl
fi
ss -ltn | grep ":$PORT " >/dev/null && echo "ssh guest ready on 127.0.0.1:$PORT"
