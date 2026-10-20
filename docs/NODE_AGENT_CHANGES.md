# Node Agent Architecture — what was added

Adds Local/Remote node support on top of the existing panel without
rewriting it: the panel's existing local VM/QEMU/SSH code paths are
**untouched**; a new node abstraction routes only Remote-node VM and
file-manager operations through a new standalone Node Agent.

## New files
- `system-info.js` — real CPU/RAM/disk/KVM/QEMU detection (no fake
  values), shared by the panel (Local Node) and the agent (Remote
  nodes) so both are measured identically.
- `sftp-ops.js` — the file-manager's connection-agnostic operation
  logic (list/upload/download/mkdir/save/rename/delete/compress/
  extract/storage), extracted so the panel and the agent share one
  implementation instead of two copies drifting apart.
- `nodes.js` — the node abstraction: `nodes` table bootstrap, per-node
  token auth (SHA-256 hash stored, plaintext shown once at
  registration), the agent WebSocket manager (heartbeat, offline
  detection, JSON command relay, chunked binary upload/download relay),
  node address bookkeeping (auto-detected from the agent's socket +
  admin override), the generic localhost TCP relay (SSH web terminal)
  and the verified file-streaming relay (templates/ISOs panel -> node).
- `node-agent/` — the standalone agent, deployed separately from the
  panel:
  - `agent.js` — connects out to the panel, authenticates, heartbeats,
    dispatches relayed commands (VM lifecycle + provisioning + cleanup,
    RDP, file manager, TCP/SSH + VNC relays)
  - `lib/qemu-launcher.js` — real VM start/stop/restart (spawns actual
    `qemu-system-x86_64`, honest capability-gated - never fakes
    success); attaches the node-local cloud-init seed ISO and prefers
    node-local install ISOs
  - `lib/vm-provision.js` — the on-node VM creation pipeline: template
    cache + download with per-URL fallback (redirect-aware, argv-only
    child processes), cloud-init seed ISO builder
    (cloud-localds/genisoimage/xorriso/mkisofs), disk
    convert/resize/create via qemu-img, disk-space checks, SSH-port
    liveness verification, and full per-VM artifact cleanup
  - `lib/guest-ssh.js` — guest VM SSH/SFTP session cache
  - `lib/system-info.js`, `lib/sftp-ops.js` — synced copies of the
    panel root modules (the agent ships as its own deployable package)
  - `package.json`, `install.sh` (supports `--install-deps`),
    `vnm-agent.service`, `README.md`
- `views/admin/nodes.ejs` — Admin → Nodes page: node cards with live
  CPU/RAM/disk/KVM, Add Node flow, install-command display, Test Node
  health check, token rotation, manual address override, delete.

## Changed files
- `app.js`:
  - DB migration: `nodes` table (+ `manual_address`/`agent_addresses`)
    + `vms.node_id` column (additive, existing `missingColumns` pattern),
    Local Node bootstrap on boot
  - `/agent-connect` WS branch (agent auth + heartbeat + command relay)
    and `/nodes-watch` WS branch (live updates for the Admin Nodes page)
  - `/api/nodes` (list/create/delete/rotate-token/test/**set-address**),
    `/api/nodes/agent-package` (tarball download), `/api/vms/:id/node`
    (reassign a VM's node with real disk migration), `/admin/nodes` page
  - **VM creation is node-aware**: the Create VM wizard has a "Target
    Node" selector. A Remote target provisions everything ON that node
    through the agent (template download or verified streaming from the
    panel, cloud-init seed ISO built there from the panel-generated
    config, disk convert+resize, SSH-port verification) - the VM then
    boots there with that node's QEMU. Local targets use the exact same
    code path as before, unchanged.
  - **Real SSH for remote VMs**: the SSH page prefills the node's
    address and shows the exact `ssh user@node -p port` command; the
    web terminal tunnels panel → agent → the VM's forwarded port
    (works through NAT; the node's own localhost + the VM's stored
    ssh_port are always used, never browser-supplied values).
  - VM start/stop/restart/delete/reinstall/ISO-attach/edit all route
    through the VM's node: remote VMs are delegated (delete and
    reinstall clean up / rebuild artifacts ON the node; ISO attach
    streams the ISO to the node first; config edits regenerate the
    cloud-init seed there), local VMs fall through to the original,
    unmodified code paths.
  - `/api/vms` + `/api/admin/vms` + `/api/vms/:id` now expose
    `node_name` / `node_mode` / `node_address` so the UI can show where
    each VM lives.
- `filemanager.js`: added a node-resolution middleware right after
  the existing VM-ownership check. Local VMs fall through unchanged to
  the exact same routes tested in the earlier File Manager work. Remote
  VMs are fully handled by a new relay function that talks to the
  agent instead of opening an SSH session directly.
- `views/admin/vm-create.ejs`: Target Node selector (offline remote
  nodes disabled), preview + progress text reflect the chosen node.
- `views/admin/vm-ssh.ejs` + `views/users/vm-ssh.ejs`: remote-node
  prefill (node address + SSH port) and a hint showing the exact ssh
  command + the fact that Connect tunnels through the agent.
- `views/partials/admin/sidebar.ejs`: added a "Nodes" nav entry.

## How authentication works
- A per-node token is generated once at registration
  (`vnm_agent_<id>_<32 random hex bytes>`) and shown once. The panel
  stores only `SHA-256(token)` in `nodes.agent_token_hash` - never the
  plaintext - so a database read alone can't recover a usable token.
- The **agent dials out** to the panel's WebSocket (not the other way
  around), presenting the token in its `Authorization` header. This
  means Remote nodes work fine behind NAT/firewalls with only outbound
  access, and the panel never needs inbound network access into a
  remote node's network - directly satisfying "remote node must not
  depend on the panel's localhost."
- Once connected, that same authenticated socket carries heartbeats
  and all relayed VM/file commands - there's no second, separately
  authenticated channel to worry about.
- Guest VM SSH credentials are sent to the agent per-request (over that
  authenticated connection) and never written to disk by the agent -
  only held for the life of the SSH session, which is itself
  idle-timed-out.

## Known, intentional scope boundaries
- **Moving a VM OFF a remote node** back to the panel (reverse disk
  pull) isn't implemented yet - `PUT /api/vms/:id/node` returns 501 for
  it rather than silently re-pointing the VM at a disk that isn't
  there. Moving panel -> remote works (the disk is copied + verified
  first), and VMs can now be CREATED directly on a remote node from
  the Create VM wizard (see below).
- The serial-text console (`/console`) for remote VMs isn't relayed
  yet - a remote VM shows "Console not available". The noVNC graphical
  console, the SSH web terminal, the file manager and RDP all work
  through the agent tunnel.
- The agent's QEMU launcher covers the config every VM needs (memory,
  CPU, root disk, NAT/bridge networking with SSH + optional RDP
  forwards, cloud-init seed ISO, install ISO, serial + VNC consoles)
  but doesn't mirror every advanced option the panel's local launcher
  supports (custom SMBIOS fields, per-VM extra QEMU args). Extending
  `buildArgs()` there is straightforward when needed - nothing about
  the surrounding process/PID-file/stop machinery has to change.
- Command relay timeout is 20s by default (30s for VM start/restart;
  30min for provisioning, which downloads templates and converts
  disks) - operations beyond that time out cleanly with a clear error
  rather than hang.

## Tested end-to-end (real processes, not mocked)
A 50-assertion automated harness (build environment script
`16-verify-e2e.js`) boots the real panel with an isolated data dir,
registers a remote node, runs the REAL agent process against it, and
exercises the full flow with fake `qemu-img` / `genisoimage` /
`qemu-system-x86_64` shims on PATH (the sandbox has no real QEMU -
the shims make every code path fully exercisable and assertable):
1. Local Node bootstraps on boot with real CPU/RAM/disk/KVM values
2. Register a Remote node → token issued → `agent-package` tarball
   downloads correctly using only the node token (no admin session)
3. Real agent process connects, authenticates, heartbeats real stats;
   the node's address is captured from its dial-out socket
4. "Test Node" health check round-trips a real command through the
   authenticated tunnel (reachable / auth / filesystem / QEMU / VM
   subsystem all verified; KVM honestly absent in this sandbox)
5. **VM created ON the remote node**: custom template downloaded by the
   agent from a URL that 302-redirects (fallback + redirect handling
   verified), cloud-init seed ISO built ON the node carrying the exact
   custom username/password the panel generated, disk converted +
   resized on the node, SSH forward port verified free there, zero
   `.part`/seed-dir leftovers, VM row carries node_name/mode/address
6. **VM start on the node**: the spawned QEMU argv contains the
   node-local disk, the cloud-init seed ISO (this is what gives a
   remote cloud-init VM its real SSH credentials on first boot) and
   the SSH hostfwd; PID file written on the node
7. **SSH web terminal through the tunnel**: the panel's ssh2 client
   banner arrives byte-for-byte at a fake server listening on the VM's
   forwarded port ON the node - with deliberately bogus
   browser-supplied host/port, proving the panel uses the agent tunnel
   plus the VM's stored SSH port (works through NAT by construction)
8. Stop delegated to the node; VM edit regenerates the cloud-init seed
   ON the node with the new hostname
9. Node address override set and cleared (auto-detect restored) via
   the new API; the VM API exposes the address users should SSH to
10. ISO attach streams the ISO to the node over the checksum-verified
    relay (byte-identical on arrival)
11. VM delete cleans up disk/seed/pid ON the node and removes the row
12. **Local-node VM creation regression**: the unchanged local path
    still downloads, seeds and creates the VM on the panel's machine
13. File Manager through the remote relay: list, upload, download,
    mkdir, recursive delete (earlier session) - unchanged, and the
    fix for the relayed-upload race condition still holds
14. VM start routed to a node without QEMU fails honestly with
    `QEMU_UNAVAILABLE` (same capability gating as the panel locally)
15. Killing the agent flips the node Offline within ~3s; in-flight
    requests for that node return `NODE_OFFLINE` instead of hanging
16. `/admin/nodes` page renders 200 with live data

Not testable in this sandbox: an actual guest OS booting (no
`/dev/kvm`). Every step up to and including the exact QEMU argv -
with the cloud-init seed ISO and SSH forward attached - is verified
for real; the honest capability gating handles the rest.
