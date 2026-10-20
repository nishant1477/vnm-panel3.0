# Networking Upgrades + Rebrand — what was added

Round 3 of improvements: richer networking configuration for every VM,
premium self-hosted OS icons, and a brand-new VNM logo. Everything is
wired end-to-end (panel -> database -> local QEMU launcher -> remote
node agent launcher) and verified by a 31-assertion e2e run with real
processes (`26-verify-networking.js` style harness: real panel + real
agent + fake QEMU binaries whose argv is asserted).

## 1. Custom Port Forwarding rules (`vm_port_forwards`)

Beyond the automatic SSH (and optional RDP) forward, every VM can now
define up to 16 extra port-forward rules - TCP or UDP:

- **Create**: the Create VM wizard's "Ports" card has a
  "Custom Port Forwards" repeater (label, protocol, host port, guest
  port). `POST /api/vms` accepts `port_forwards: [{label, protocol,
  host_port, guest_port}]`.
- **Edit**: `PUT /api/vms/:id/edit` accepts `port_forwards` with full
  replace-set semantics - send a new array to swap the rule set, an
  empty array to clear all rules, omit the key to leave them untouched.
  A forwards-only edit (no other field changed) is valid too.
- **Validation** (both endpoints): protocol must be tcp/udp, ports must
  be 1-65535 integers, no duplicate protocol+host-port pairs, and a host
  port may not collide with the VM's own SSH forward port. Max 16 rules.
- **Launch (local)**: each rule becomes a QEMU `hostfwd=` entry on the
  user-mode netdev at start time.
- **Launch (remote node)**: the rules ride along with the `vm.start`
  payload over the agent tunnel and the node's launcher attaches them
  the same way. At CREATE time the agent additionally bind-probes every
  TCP host port on the node and fails fast with `409 PORT_IN_USE`
  instead of letting the first boot die on a QEMU bind error. The same
  honest check runs at start.
- **Visibility**: `GET /api/vms/:id` returns the rules; the VM detail
  page (admin + user side) renders a "Port Forwards" card showing each
  rule as `PROTO <node-or-localhost>:<host> -> :<guest>`, node-aware for
  remote VMs.
- **Lifecycle**: deleting a VM removes its rule rows (local and remote
  delete paths, plus the failed-provision cleanup path).

## 2. Selectable NIC model (`vms.nic_model`)

- `virtio-net-pci` (default, fastest), `e1000`, `e1000e`, `rtl8139`,
  `vmxnet3` - selectable per VM in the wizard (Network Type card) and
  via the edit API.
- Wired into BOTH launchers: the panel's local `startQemuVM()` and the
  node agent's `buildArgs()` render `-device <model>,netdev=n0,mac=...`.
  Invalid values are rejected on edit (400) and fall back to virtio on
  create.
- Shown on the VM detail page (Access Information + Network tab).

## 3. New OS icons (all self-hosted SVG)

Redesigned as gradient badges with brand-accurate glyphs, plus two new
ones for custom templates:

- `public/images/os/ubuntu.svg` - circle of friends on Ubuntu orange
- `public/images/os/debian.svg` - open swirl on Debian red
- `public/images/os/fedora.svg` - bold "f" on Fedora blue
- `public/images/os/centos.svg` - colorful compass pinwheel on navy
- `public/images/os/almalinux.svg` - amber "a" on deep navy
- `public/images/os/generic.svg` - server rack on slate
- `public/images/os/windows.svg` - NEW - 4-pane flag
- `public/images/os/arch.svg` - NEW - the arch

## 4. New VNM logo

- `public/images/logo-new.svg` - indigo-to-violet rounded square, bold
  white **V** monogram, a cyan "remote node" dot with ring (the wings
  story), and two layer bars (virtualized machines).
- Every default now points at it: `site_icon_url` default, all
  `siteLogo` fallbacks, the `/favicon.ico` redirect and the login page.
- An idempotent boot migration re-points existing databases that still
  carry the old default (`/images/logo.png` -> `/images/logo-new.svg`).
  A custom logo configured in Settings is never overwritten.

## Verification summary (real processes)

31/31 assertions: remote VM created on a node with `e1000` + a TCP and
a UDP forward -> QEMU argv on the node contains the right `-device` and
both `hostfwd` entries (plus the SSH forward); local VM with `rtl8139`
+ a forward -> local QEMU argv correct; edit swap / clear / forwards-
only all behave; duplicate port, SSH-port collision, bad NIC and bad
protocol rejected with 400; a busy port on the node rejects the create
with `PORT_IN_USE`; deleting a VM removes its rule rows from the
database.
