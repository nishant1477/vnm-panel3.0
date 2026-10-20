#!/bin/bash
# Runs the whole RDP test suite. Run as root on a DISPOSABLE Debian/Ubuntu machine/container
# (it installs qemu/openssh/freerdp-free tooling and, with MUTATE=1, purges/reinstalls xrdp).
#   tests/run-rdp-tests.sh            # skips tests that modify the host
#   MUTATE=1 tests/run-rdp-tests.sh   # also runs "fresh install" and "unsupported OS"
set -uo pipefail
cd "$(dirname "$0")/.."
command -v qemu-system-x86_64 >/dev/null || { DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-system-x86 qemu-utils genisoimage >/dev/null; }
tests/build-test-guest.sh
tests/setup-ssh-guest.sh
[ "${MUTATE:-0}" = 1 ] && export VNM_TEST_ALLOW_GUEST_MUTATION=1
rc=0
echo "### UI states";            node tests/rdp-ui.js            || rc=1
echo "### Integration";          node tests/rdp-integration.js   || rc=1
echo "### Real-panel end-to-end"; node tests/rdp-panel-e2e.js    || rc=1
[ -n "${JSDOM_PATH:-}" ] && { echo "### Real-DOM UI (needs jsdom: npm i --prefix /tmp/jsd jsdom; JSDOM_PATH=/tmp/jsd/node_modules/jsdom)"; node tests/rdp-browser.js || rc=1; }
exit $rc
