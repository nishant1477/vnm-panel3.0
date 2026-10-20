# RDP access for VMs

Adds **VM Details → RDP** (admin and user pages). *Enable RDP* installs xrdp and a desktop inside a
running **Debian or Ubuntu** guest, gives the VM a reachable RDP address, and shows a live status.

## Where everything is
| What | Where |
|---|---|
| **Create a VM with RDP** | *Create VM* → step 1, right column → **Remote Desktop (RDP)** → *Enable RDP automatically* (Debian / Ubuntu cloud-init templates). The VM is created stopped; once you start it and it has finished its first boot, xrdp + desktop are installed automatically. After creating, the wizard opens the RDP page. |
| **RDP page** (create / manage / use) | `/admin/vm/<id>/rdp` (admin) and `/vm/<id>/rdp` (user): setup progress, Enable / Re-run / Disable, "set up automatically" switch, connection details, **Download .rdp file**, copy address / `xfreerdp` command, connect guides for Windows / Linux / macOS |
| Shortcuts | **RDP** button in the VM header (next to Console / SSH / Files), **RDP** on every row of the VM lists, and an *RDP* tab on the VM details page |
| `.rdp` file | `GET /api/vms/:id/rdp/file` (address + username only, never a password) |
| Auto-setup switch | `POST /api/vms/:id/rdp/auto` `{ "enabled": true|false }` |

Automatic setup retries every ~20 s (up to `RDP_AUTO_MAX_ATTEMPTS`, default 90 ≈ 30 min) while the VM is still booting;
it stops at once for an unsupported OS. Manual *Enable RDP* always takes over.

## How it works
1. The panel (or, for a remote node, the node agent) connects to the guest over the **existing VM SSH
   mechanism** (same host/port/credentials the file manager uses).
2. It reads `/etc/os-release`. Anything that is not Debian/Ubuntu stops here with
   `Unsupported guest OS: RDP setup is only supported on Debian and Ubuntu VMs.` Nothing is installed.
3. It checks that the VM user is root or can `sudo`, **before** installing anything.
4. A setup script runs in the guest (idempotent - safe to run any number of times):
   installs `xrdp` + `xorgxrdp` only if missing; reuses an installed lightweight desktop, otherwise
   installs XFCE (`xfce4 xfce4-terminal dbus-x11`); writes `~/.xsession` only if it does not exist;
   adds `xrdp` to `ssl-cert`; opens 3389 in `ufw` only if ufw is active; enables/starts xrdp only if it
   is not already running; then verifies that the xrdp service is running **and** listening on 3389.
5. **NAT VMs:** a unique host port is allocated and QEMU forwards `host:PORT -> guest:3389`.
   **VMs with their own address:** no forwarding; the connection address is the VM address on 3389.
6. The panel then performs a real RDP handshake (X.224 Connection Request/Confirm) and every status
   request repeats it. *Online* is only shown when an RDP server actually answers - never because
   database fields exist or the install command succeeded.

### States
`Disabled`, `Installing` (with the current step), `Online`, `Offline` (VM stopped, or xrdp not answering
yet), `Restart Required`, `Error` (with a clear message), `Unsupported OS`.

### NAT forwarding details
* Forward = `-netdev user,...,hostfwd=tcp::<ssh>-:22,hostfwd=tcp::<rdp>-:3389` on every start
  (`startQemuVM` locally, the same code path in the node agent), so it survives stop/start.
* On a **running** VM the forward is hot-added through a private QEMU monitor socket
  (`<VM_DIR>/vm-<id>.hmp`, unix socket, owner-only, never a TCP port). The same monitor is used to
  remove it on *Disable*. Only forwards that target guest port 3389 are ever added/removed; the SSH
  forward is never touched.
* A VM that was started before this feature existed has no monitor socket: Enable still installs xrdp
  and reserves the port, the status is **Restart Required**, and it clears itself after the next VM restart.
* If the reserved port is unexpectedly busy when a VM starts, the VM still boots (without RDP) and the
  status says **Restart Required** instead of lying.
* Panel restart: ports/config are in the database; running VMs keep their QEMU process (and forward);
  a boot-time pass re-asserts forwards (idempotent); a status poll does the same lazily.
* A setup that was interrupted by a restart is reset to an error on boot (never stuck on *Installing*).

### Disable / reinstall
* **Disable** removes the forward, releases the port and sets *Disabled*. xrdp stays installed in the guest.
* **Reinstall** clears all RDP state, releases the port and removes the monitor socket - the new guest is
  a new machine and must be enabled again.

## API
All routes use the normal session auth and CSRF protection; users only reach their own VMs (others get 404).
| Method | Path | Result |
|---|---|---|
| GET | `/api/vms/:id/rdp` | status JSON: `status, enabled, host, port, username, network, guest_os, installed_at, message, warning` |
| POST | `/api/vms/:id/rdp/enable` | `202`, setup runs in the background, poll GET |
| POST | `/api/vms/:id/rdp/disable` | `200` |

Errors: `400` invalid id, `404` unknown/not yours, `409` VM not running / setup busy / no VM address,
`422` unsupported OS, `502` node offline. Responses never contain passwords or stack traces
(details go to the panel log).

## Configuration
| Variable | Default | Meaning |
|---|---|---|
| `RDP_PORT_START` | `33890` | first host port handed out |
| `RDP_PORT_END` | `34889` | last host port handed out |
| `RDP_AUTO_MAX_ATTEMPTS` | `90` | how many times automatic setup retries (about 20 s apart) |
| `RDP_PUBLIC_HOST` | *(unset)* | hostname shown in the connection address; otherwise the address the panel is opened with (local) or the node's address (remote node) |

Ports already used by another VM's SSH/RDP forward, or bound by any other process, are skipped. A unique
database index guarantees two VMs can never share a port.

## Firewall
Open the allocated range on the **host/node**:

    ufw allow 33890:34889/tcp          # or the range you configured
    # firewalld: firewall-cmd --permanent --add-port=33890-34889/tcp && firewall-cmd --reload

The panel never changes the host firewall. QEMU binds forwards on all interfaces (like the existing SSH
forward); restrict the range to trusted source addresses if the host is exposed. The guest's 3389 is only
reachable through the allocated host port. Prefer a regular user over `root` (the tab warns about root).

## Remote nodes
Same flow, executed by the node agent (`rdp.provision`, `rdp.probe`, `rdp.forward`): the agent SSHes to the
guest locally, hot-adds/removes the forward on its own QEMU, bakes the forward into the QEMU command line
when it starts a VM, and answers handshake probes. Ports are allocated by the panel (single database).
The connection address is the node's address (set it on the node) or `RDP_PUBLIC_HOST`. Re-install/restart
the agent after upgrading (`node-agent/lib/rdp-guest.js` must match `rdp-guest.js`). Agent inputs are
validated (digit-only VM ids, IPv4 hosts, port ranges).

## Connecting
* **Windows:** *Remote Desktop Connection* (`mstsc`) -> *Computer*: the address from the tab (e.g.
  `rdp.example.com:33890`) -> sign in with the VM username/password.
* **Linux:** Remmina (protocol RDP, server = the address, same credentials) or
  `xfreerdp /v:rdp.example.com:33890 /u:USER /cert:ignore`.
* **macOS:** Microsoft Remote Desktop / Windows App.
If the login screen shows a session type, choose **Xorg**.

## Troubleshooting
| Symptom | Cause / fix |
|---|---|
| *Restart Required* | The running QEMU has no monitor socket (started before this update) or the port was busy at start. Restart the VM (or free the port). |
| *Offline*, VM running | xrdp not up yet (first boot) or crashed: *Re-run setup*; inside the guest `systemctl status xrdp`, `journalctl -u xrdp`. |
| `Invalid credentials` | The VM user/password stored in the panel is not what the guest accepts over SSH. |
| `cannot use sudo` | Use an account with sudo rights (or root). |
| `xrdp install failed` | The guest has no internet access or broken apt sources. |
| Black screen / instant disconnect after login | No/incompatible desktop: remove a broken `~/.xsession` (then re-run setup) or log in once locally; already logged-in session on the same user blocks a second one. |
| `Connection refused` from the client | Host firewall range not open, or `RDP_PORT_*` changed after allocation (disable/enable to re-allocate). |
| *No free RDP host ports* | Widen `RDP_PORT_START/END`. |

Logs: one JSON object per line prefixed `[RDP]` (events: `enable_started`, `os_detected`, `guest_step`,
`port_allocated`, `forward_added`, `handshake_verification`, `status_change`, `disabled`, `reset`, `error`...).
Credentials are never logged.

## Where to find it
RDP belongs to a **VM**, so you need at least one VM first (Create VM -> start it). Then any of:
* **All VMs** list -> the **RDP** button/icon on the VM's row (opens the VM straight on its RDP tab),
* open the VM -> the **RDP** button in the header (next to Console / SSH / Files), or
* open the VM -> tab bar **Overview | Network | RDP | Hardware | Snapshots | Logs**.
The Create VM page (Review step) also reminds you of this. With zero VMs there is nothing to open.

## "I installed it but there is no RDP tab"
That means the panel process that is serving you is an **old copy** (a different folder, a container, a
compiled binary, or it was never restarted). Run `./check-rdp.sh` from this folder: it finds the running panel,
shows which folder it serves from and whether that copy has the RDP code; `sudo ./check-rdp.sh --apply`
syncs the new code into it (keeping `data/`, `.env`, the database) and restarts the systemd service.
A correct start prints `✓ RDP feature: ENABLED (VM Details → RDP tab, host ports ...)` in the panel log.
The tab is in **VM list → click a VM → tab bar: Overview | Network | RDP | Hardware | Snapshots | Logs**
(it is drawn a moment after the page opens).

## Files
New: `rdp.js`, `rdp-guest.js` (+ identical copy `node-agent/lib/rdp-guest.js`), `tests/*`, this file.
New views: `views/admin/vm-rdp.ejs`, `views/users/vm-rdp.ejs`.
Changed: `views/admin/vm-create.ejs` (RDP switch), `views/admin/vms.ejs`, `views/users/vms.ejs` (RDP links), `app.js` (additive columns, route mount, `hostfwd` + monitor socket in `startQemuVM`, boot hooks,
reinstall hook), `node-agent/agent.js`, `node-agent/lib/qemu-launcher.js`,
`views/admin/vm-detail.ejs`, `views/users/vm-detail.ejs`.
Database: columns `rdp_enabled, rdp_port, rdp_status, rdp_error, rdp_guest_os, rdp_installed_at,
rdp_restart_needed` + unique index `idx_vms_rdp_port` - created automatically on start.

## Tests
`tests/run-rdp-tests.sh` (disposable Debian/Ubuntu root shell; `MUTATE=1` adds the host-modifying cases).
* `rdp-ui.js` - every status rendered by the page's real code.
* `rdp-integration.js` - real QEMU/NAT guests, real SSH provisioning, real RDP handshakes, real node agent.
* `rdp-panel-e2e.js` - the real `node app.js` driven over HTTP (create-with-RDP, start/stop, enable/disable, reinstall, console).
* `rdp-browser.js` - the real pages in a DOM (jsdom): wizard option, RDP page, tab, shortcuts, buttons.
Limits of the rig are listed at the top of each file.
