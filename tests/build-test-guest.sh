#!/bin/bash
# Builds a tiny REAL Linux guest for the RDP tests (kernel + busybox initramfs).
# It boots under QEMU in ~5 s (TCG), brings up eth0 at QEMU's NAT address
# (10.0.2.15) and then:
#   - port 3389: answers an RDP X.224 Connection Request with a Connection
#                Confirm (what the first bytes of a real RDP server look like)
#   - port 22:   relays to the HOST's sshd on 10.0.2.2:$SSH_PORT, so the VM's
#                SSH forward works through the real QEMU NAT path
#   - serial:    prints VNM_TEST_GUEST_READY and echoes lines typed on the
#                console as SERIAL_ECHO:<line>
# Needs: apt-get (Debian/Ubuntu), cpio, gzip. Output: $OUT (default /tmp/vnm-rdp-test)
set -euo pipefail
OUT="${VNM_TEST_DIR:-/tmp/vnm-rdp-test}"
SSH_PORT="${VNM_TEST_SSH_PORT:-2299}"
mkdir -p "$OUT" && cd "$OUT"
if [ -f vmlinuz ] && [ -f initrd.img ] && [ -x qemu-system-x86_64 ] && [ "${1:-}" != "--force" ]; then echo "test guest already built in $OUT"; exit 0; fi
command -v cpio >/dev/null || apt-get install -y -qq cpio >/dev/null
W="$(mktemp -d)"; cd "$W"
apt-get download busybox-static >/dev/null 2>&1
K=$(apt-cache depends linux-image-virtual | awk '/Depends:/{print $2}' | grep -E '^linux-image-[0-9]' | head -1)
apt-get download "$K" >/dev/null 2>&1
dpkg-deb -x busybox-static_*.deb bb && dpkg-deb -x linux-image-*.deb kr
cp kr/boot/vmlinuz-* "$OUT/vmlinuz"
mkdir -p rd/bin rd/proc rd/sys rd/dev rd/tmp && cp bb/usr/bin/busybox rd/bin/busybox
cat > rd/bin/rdpresp <<'R'
#!/bin/busybox sh
printf '\003\000\000\023\016\320\000\000\022\064\000\002\001\010\000\002\000\000\000'
sleep 1
R
cat > rd/bin/sshrelay <<R
#!/bin/busybox sh
exec nc 10.0.2.2 $SSH_PORT
R
cat > rd/init <<'R'
#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev
ip link set lo up; ip link set eth0 up
ip addr add 10.0.2.15/24 dev eth0; ip route add default via 10.0.2.2
nc -ll -p 3389 -e /bin/rdpresp &
nc -ll -p 22 -e /bin/sshrelay &
echo "VNM_TEST_GUEST_READY"
while read -r line; do echo "SERIAL_ECHO:$line"; done
exec sleep 100000
R
chmod +x rd/init rd/bin/rdpresp rd/bin/sshrelay
( cd rd && find . | cpio -o -H newc 2>/dev/null | gzip -9 > "$OUT/initrd.img" )
# QEMU wrapper: lets the panel's / agent's REAL launch code boot this guest
# (no KVM, no disk image needed): swaps -cpu, drops -enable-kvm, adds -kernel/-initrd.
cat > "$OUT/qemu-system-x86_64" <<EOF2
#!/bin/bash
args=(); skip=0
for a in "\$@"; do
  if [ \$skip = 1 ]; then args+=(qemu64); skip=0; continue; fi
  case "\$a" in -cpu) args+=(-cpu); skip=1;; -enable-kvm) ;; *) args+=("\$a");; esac
done
exec $(command -v qemu-system-x86_64) "\${args[@]}" -kernel "$OUT/vmlinuz" -initrd "$OUT/initrd.img" -append "console=ttyS0 quiet"
EOF2
chmod +x "$OUT/qemu-system-x86_64"
rm -rf "$W"; echo "built test guest in $OUT"
