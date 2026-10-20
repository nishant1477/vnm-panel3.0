# VNM Node Agent

Runs on a node (the same machine as the panel, for a **Local** node, or
a separate VPS, for a **Remote** node) and gives the VNM Panel real
access to that machine: live CPU/RAM/disk stats, VM start/stop/restart
via real QEMU, and file-manager operations against VM guest filesystems
over real SSH/SFTP.

The agent **dials out** to the panel over an authenticated WebSocket
(`wss://your-panel/agent-connect`) rather than the panel dialing in to
it. That means a node behind NAT or a firewall that only allows
outbound traffic still works fine, and the panel never needs inbound
network access into your node's network.

## Requirements

- Node.js 16+
- For VM hosting: `qemu-system-x86_64` (and `/dev/kvm` for hardware
  acceleration) - not required if this node will only run VMs whose
  disks live elsewhere, or if it's being added purely for its own sake
  before QEMU is installed
- For VM **provisioning** (creating VMs on this node from the panel):
  `qemu-img` (the `qemu-utils` package) for disk creation, and one of
  `cloud-localds` / `genisoimage` / `xorriso` / `mkisofs` for building
  cloud-init seed ISOs. On Debian/Ubuntu the installer can install all
  of this for you - add `--install-deps` to the install command.
- Outbound HTTPS/WSS access to your panel

## Installing (Remote Node)

1. In the panel: **Admin → Nodes → Add Node → Remote**, name it, and
   click **Register**. You'll get a one-time install command that
   looks like:
   ```
   curl -fsSL -H "Authorization: Bearer <token>" \
     https://your-panel/api/nodes/agent-package -o vnm-agent.tar.gz \
     && tar xzf vnm-agent.tar.gz && cd node-agent \
     && sudo bash install.sh --panel-url https://your-panel --token <token>
   ```
   Add `--install-deps` (Debian/Ubuntu) to also install the VM-hosting
   packages (`qemu-system-x86`, `qemu-utils`, `genisoimage`) on the
   node in the same run.
2. Run it on the remote server as root (or with sudo).
3. The installer creates a dedicated `vnm-agent` system user, installs
   Node.js if missing (Debian/Ubuntu via apt - other distros: install
   Node 18+ yourself first), copies the agent to `/opt/vnm-agent`,
   writes `/etc/vnm-agent/agent.env`, and starts it - via systemd when
   available, otherwise in standalone mode (see below).
4. Back in the panel, the node should flip to **Online** within about
   15 seconds (the agent's heartbeat interval).

### Run modes (v2 installer)

| | `systemd` (auto on normal servers) | `standalone` |
|---|---|---|
| Best for | Normal Ubuntu/Debian servers | GitHub Codespaces, Docker/LXC, anything without systemd |
| Install as root | yes | yes or **no** (`--user` installs to `~/.vnm-agent`) |
| Auto-start on boot | systemd unit, enabled | `@reboot` crontab |
| Manage | `systemctl {status\|restart\|stop} vnm-agent` | `vnmagentctl {status\|restart\|stop\|logs\|mode\|upgrade}` |
| Logs | `journalctl -u vnm-agent -f` | `/opt/vnm-agent/agent.log` (or `~/.vnm-agent/agent.log`) |

Force a mode with `VNM_AGENT_MODE=systemd|standalone` or `--mode`:

```bash
# Codespaces / container / no systemd, no root:
bash install.sh --panel-url https://panel.example.com --token <token> --user

# Explicit standalone as root:
sudo VNM_AGENT_MODE=standalone bash install.sh --panel-url ... --token ...
```

Re-running with the other mode **migrates seamlessly** - config, token and
VM disks are kept, only the supervisor changes. `vnmagentctl` is installed
in both modes and always knows the active mode (`.vnm-mode`).

## Installing (Local Node)

The panel already has a bootstrapped "Local Node" row the moment it
starts up, and for Local VMs it keeps using its existing direct QEMU/
SSH code paths - **you don't need to install this agent for Local
mode to work.** Only install it locally too if you specifically want
the Local node's stats/lifecycle to also go through the agent protocol
(e.g. for architecture consistency, or to test the agent without a
second server) - same install steps, just run `install.sh` on the
panel's own machine with `--panel-url http://127.0.0.1:<port>`.

## Configuration

Environment variables (or `/etc/vnm-agent/agent.env` when installed
via `install.sh`):

| Variable | Required | Description |
|---|---|---|
| `PANEL_URL` | yes | e.g. `https://panel.example.com` |
| `AGENT_TOKEN` | yes | Per-node secret issued when the node was registered |
| `AGENT_VM_DIR` | no | Where this node keeps VM disks/PID files (default `~/vms`) |
| `QEMU_BIN` | no | Override the `qemu-system-x86_64` path |
| `AGENT_HEARTBEAT_MS` | no | Heartbeat interval (default 15000) |
| `AGENT_SSH_CONNECT_TIMEOUT_MS` | no | Guest SSH connect timeout (default 15000) |
| `AGENT_SFTP_IDLE_MS` | no | Idle guest SFTP session timeout (default 600000) |

## Security notes

- The token is generated once by the panel and shown once at
  registration time. The panel stores only a SHA-256 **hash** of it
  (`nodes.agent_token_hash`) - if your panel database is ever read by
  someone else, they cannot recover a usable agent token from it. If a
  token is compromised, rotate it from **Admin → Nodes → (node) →
  Rotate Token**; the old token stops authenticating immediately.
- Every command the panel sends the agent travels over the same
  connection the agent authenticated with - there's no separate
  unauthenticated control channel.
- The agent never receives your panel's admin credentials, session
  cookies, or CSRF tokens - only its own per-node token.
- VM guest SSH credentials (username/password) are sent to the agent
  per-request, over that same authenticated connection, and are never
  persisted to disk by the agent - only held in memory for the
  duration of the SSH session (which is itself idle-timed-out).
- Run the agent as the dedicated unprivileged `vnm-agent` user the
  installer creates, not as root. It only needs write access to its
  own `AGENT_VM_DIR`.
- Use `https://`/`wss://` for `PANEL_URL` in production. Plain
  `http://`/`ws://` works (and is what this repo's own tests use
  against a local panel) but sends the token and file contents
  unencrypted - fine for `127.0.0.1`, not for the open internet.

## Agent protocol (for reference / troubleshooting)

Once connected and authenticated, the agent sends:
- `{"type":"heartbeat","stats":{...}}` every `AGENT_HEARTBEAT_MS`

...and responds to commands the panel sends:
- `{"type":"command","requestId":"...","action":"system.info","payload":{}}`
  → `{"type":"command-result","requestId":"...","result":{...}}` or
  `{"type":"command-error","requestId":"...","error":"..."}`

Actions implemented: `system.info`, `system.stats`, `vm.start`,
`vm.stop`, `vm.restart`, `vm.status`, `vm.vncinfo`, `vm.provision`
(ensure template + build cloud-init seed + create/resize disk + verify
SSH port - the full "create a VM on this node" pipeline), `vm.createSeed`,
`vm.resizeDisk`, `vm.cleanup`, `vm.clone`, `vm.snapshot.*`,
`vm.stats`, `node.storage.*`, `rdp.provision`, `rdp.probe`,
`rdp.forward`, `host.exec` (Node Terminal - admin-only at the panel
layer, audit-logged, 60 s max), `vm.consoleWrite` / `vm.consoleTail` /
`vm.consoleStatus` (serial-console bridge the panel uses to provision
RDP without sshd in the guest), `file.list`, `file.storage`,
`file.read`, `file.write`, `file.mkdir`, `file.createFile`,
`file.rename`, `file.delete`, `file.compress`, `file.extract`.

The cloud-init seed content itself is always generated BY THE PANEL
(same generators as local VMs) and sent to the agent verbatim - a VM
created on a remote node gets byte-for-byte the same users, passwords,
SSH config and networking as a local one. The agent never invents
credentials.

File upload/download use a small binary relay on the same socket
(control messages `upload-start`/`upload-end`/`download-start`, binary
frames tagged with an 8-byte request ID) so large files are streamed
in bounded-size chunks in both directions rather than buffered whole
in memory anywhere along the path. The same framing carries:

- VM disk migrations (`disk-upload-*`) and streamed templates/ISOs
  (`file-upload-*`) panel -> node, both SHA-256 verified with
  flow control,
- the noVNC console (`vnc-open`) and the SSH web terminal
  (`tcp-open`) as bidirectional byte pipes.

## Creating VMs on this node + SSH access

Once the agent is online, pick this node in **Admin → Create VM →
Target Node**. Provisioning happens on the node: the template is
downloaded (or streamed from the panel when it only exists there), the
cloud-init seed ISO is built locally with the panel-generated config,
the disk is created/converted/resized with `qemu-img`, and the SSH
forward port is verified free on this node.

After the VM boots (first boot applies cloud-init), you get real SSH:

- **From your own machine:** `ssh <user>@<node-address> -p <vm-ssh-port>`
  - the SSH page shows the exact command. The node address is
  auto-detected from the agent connection; set a manual one (FQDN) via
  **Admin → Nodes → Set address** if the auto-detected one isn't what
  users should use.
- **From the panel:** the SSH page's Connect button tunnels
  panel → agent → the VM's forwarded port, so it works even when this
  node is behind NAT with only outbound access.

## Reverse proxy (nginx, Caddy, etc.)

If your panel sits behind a reverse proxy - which is normal for a
production install with HTTPS - the proxy **must** forward WebSocket
upgrade requests, including on the `/agent-connect` path, or the agent
will connect and immediately get disconnected (or never connect at
all) in a loop. This is the single most common reason a Remote node
won't come online.

**nginx** - make sure your server block has this (either globally in
the `location /` block, or specifically for `/agent-connect` and
`/nodes-watch` if you're routing WS separately):

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;   # your panel's actual port
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 3600s;   # keep the long-lived agent socket open
}
```

Without `Upgrade`/`Connection: upgrade`, nginx serves the WebSocket
handshake as a plain HTTP request, which the agent sees as an
"unexpected response" (usually HTTP 200, 400, or 404) instead of the
`101 Switching Protocols` it needs - the agent logs this explicitly
(see below) so it's easy to tell apart from an auth problem.

**Caddy** proxies WebSockets automatically with a plain
`reverse_proxy 127.0.0.1:3000` - no extra config needed.

## Reading agent logs

As of this version, the agent logs *why* a connection attempt failed,
not just that it failed:

- `Panel rejected the WebSocket upgrade with HTTP 404` → almost always
  a reverse-proxy routing/upgrade-forwarding problem, not the agent's
  fault - see above
- `Panel rejected the WebSocket upgrade with HTTP 5xx` → the panel (or
  something in front of it) errored handling the request
- `Panel rejected the WebSocket upgrade with HTTP 401/403` → the token
  doesn't match what the panel has on file for this node - rotate the
  token from **Admin → Nodes** and re-run `install.sh` with the new one
- `Panel rejected the connection: <message>` (after a successful
  handshake) → the panel accepted the TCP/TLS connection but rejected
  the token at the application level (invalid/unknown node, or the
  token was rotated) - same fix as above
- `Disconnected from panel (code 1006, ...)` → an abnormal closure with
  no close frame, typically a proxy/timeout killing the connection
  mid-stream rather than the panel or agent choosing to close it -
  check `proxy_read_timeout` if you're behind nginx

## Troubleshooting

- **Node stays "Offline" in the panel** - check `journalctl -u
  vnm-agent -f` on the node. Most common causes: wrong `PANEL_URL`
  (must be reachable from the node), an expired/rotated token, or a
  firewall blocking outbound 443/80.
- **"QEMU is not available on this node"** when starting a VM - install
  `qemu-system-x86` (or `qemu-kvm`) on that node; this is an honest
  capability check, not a bug - the agent will never pretend a VM
  started when it didn't.
- **File manager says "Node is offline"** - the agent's WebSocket
  connection dropped; it auto-reconnects with backoff, check the
  agent's logs.
- **Re-run the installer** any time to update config or reinstall -
  it's safe to run more than once.

---

## Download resilience (agent 1.4.0)

`lib/vm-provision.js` resolves each template host into an ordered address
list (IPv4 first; `VNM_PREFER_IPV6=1` flips) and tries every address in
sequence, advancing only on connect-layer failures - so a node with broken
IPv6 (or IPv4) egress still downloads from the mirrors curl can reach. Per
address the connect phase is bounded by `AGENT_ADDR_CONNECT_TIMEOUT_MS`
(default 6000 ms). Global family racing is enabled via
`net.setDefaultAutoSelectFamily` (disable with `VNM_NO_HAPPY_EYEBALLS=1`).
See `docs/DOWNLOAD_RESILIENCE_FIX.md` for the full write-up.
