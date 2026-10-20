# VNM Panel v2.1.2 — VM Boot & Remote Desktop Fix

Two related bugs fixed. Both trace back to hosts **without usable
`/dev/kvm`**, and the second is largely a consequence of the first.

---

## BUG 1 — VM fails to start: `CPU model 'host' requires KVM or HVF`

### Symptom (v2.1.1 and earlier)

```
qemu-system-x86_64: CPU model 'host' requires KVM or HVF      <- /home/vnm/vms/vm-1.log
[panel] KVM requested but /dev/kvm is unavailable on this host
[panel] starting with software emulation (tcg) instead of failing to boot
[panel] Using preset CPU: host
[panel] Process exited with code 1, signal null
[panel] QEMU exited immediately (code 1, signal null)
```

The VM never boots; the panel honestly rejects the start (the VM is NOT
marked running), but the API error carries no reason.

### Root cause

`startQemuVM()` already detected missing KVM and switched the machine to
`accel=tcg`, **but still passed `-cpu host`**. `host` (and only `host` —
every other named model is emulatable) requires KVM or HVF, so QEMU
exited during argument parsing, before the VM existed.

Sibling defect found in the same code path: CPU presets were passed to
QEMU under their **UI key** (`-cpu skylake`, `-cpu corei7`) instead of
the real QEMU model name — real QEMU refuses unknown models the same way.

### Fix (app.js, `startQemuVM()`)

1. **Acceleration is resolved first** — `kvmUsable` decides which CPU
   models are even legal.
2. **TCG safety pass**: when KVM is unavailable and the resolved CPU
   model's base (before the first comma) is `host`, it is substituted
   with the TCG-compatible **`max`** model (every feature software
   emulation can provide). Any suffix survives, so a custom CPU
   `host,model-id="My Custom CPU"` becomes `max,model-id="My Custom CPU"`.
   This covers, in one place:
   - the panel default (no `cpu_model` set),
   - the `host` preset,
   - custom CPU configurations whose base is `host`,
   - the unknown-model fallback (which used to rewrite to `host`).
3. **Real model names**: presets and custom bases now reach QEMU as
   `CPU_MODELS[key].features` (`Skylake-Client`, `Cascadelake-Server`,
   `Haswell` for the repaired `corei7` entry), never the UI key.
4. **Stored settings are never modified** — the substitution happens at
   launch time only. If KVM becomes available later (or the VM moves to a
   KVM node), the configured model is used exactly as stored. Existing
   VMs need no SQLite surgery.
5. **Honest lifecycle**:
   - the startup grace window is 1s; if QEMU exits inside it, the start
     API fails with **QEMU's own diagnostic** in the message (the stderr
     tail is captured — e.g. `could not open disk image ...` for other
     boot failures),
   - if QEMU dies *after* a healthy start, the exit handler now flips
     the VM to `stopped` in the DB (previously it stayed `running`
     forever), cleans the pid file and drops it from `vmProcesses`,
   - every start logs `Acceleration: kvm|tcg` and
     `Effective CPU model (-cpu): ...` next to the configured value.

### Behaviour matrix

| Configuration | KVM available | No KVM (TCG) |
|---|---|---|
| no `cpu_model` (default `host`) | `-cpu host` | `-cpu max` |
| preset `host` | `-cpu host` | `-cpu max` |
| custom name, base `host` | `host,model-id=Name` | `max,model-id=Name` |
| preset `skylake` | `-cpu Skylake-Client` | `-cpu Skylake-Client` (unchanged) |
| any other preset / base | as configured | as configured (TCG emulates named models) |

---

## BUG 2 — Remote Desktop: `Timed out while waiting for handshake`

### Symptom

```
Remote Desktop status: ERROR
1. Connect to the VM over SSH
2. Install xrdp and a desktop
3. Open a host port and forward it
4. Verify the RDP connection

Could not reach the VM over SSH (is it fully booted and is sshd running?):
Timed out while waiting for handshake
```

### Why it happened

- QEMU's user-mode forwarder **accepts the host-side TCP connection
  immediately**, even when nothing in the guest listens yet. "Connected"
  therefore proves nothing, and ssh2's `readyTimeout` expires as
  "Timed out while waiting for handshake".
- A first boot — **minutes** under TCG on a KVM-less host, the exact
  environment BUG 1 forces — takes far longer than the single 15s
  connect attempt the RDP setup allowed.
- And when the VM wasn't running at all (BUG 1), a stale
  `status='running'` row (left by pre-v2.1.2 crashes) let the RDP
  preflight believe the VM was up, so the failure surfaced as a confusing
  SSH timeout instead of "the VM is not running".

### Fix

`rdp-guest.js` (shared byte-for-byte by the panel and the node agent):

- **`waitForGuestSsh()`** retries the connection until the guest is
  really reachable — default 10 minutes, `RDP_SSH_WAIT_MS` to override,
  5s between attempts, 15s per-attempt handshake timeout. Live progress
  is reported through the job step (`Waiting for the VM to finish
  booting - sshd is not answering yet (attempt N)`).
- Errors are classified instead of lumped together:
  - `GUEST_SSH_HANDSHAKE` — connected, but sshd never completed the
    handshake (still booting, or something else holds the port),
  - `GUEST_SSH_UNREACHABLE` — nothing answering on the VM SSH port
    (is the VM running?),
  - `GUEST_AUTH_FAILED` — invalid credentials; **never retried** (retrying
    a bad password only gets the account locked out).
- The exhausted-budget error states the wait and what to do next.

`rdp.js` + `app.js`:

- The RDP preflight now performs a **real process-liveness check**
  (`vmRuntime.isQemuAlive`: in-memory pid map + pid file + `isPidQemu`)
  instead of trusting the `status` column. A VM marked running whose
  QEMU is gone is refused up front with
  *"The VM is marked running but its QEMU process is not running (it may
  have crashed). Start the VM again, then retry."* — and the stale row is
  corrected back to `stopped` on the spot.
- The QEMU exit handler (BUG 1 fix) keeps the DB honest from now on, so
  this state can no longer accumulate.

### What the user sees now

| Situation | Result |
|---|---|
| VM booting under TCG (slow first boot) | setup waits, live progress in the UI, completes when sshd is up |
| VM actually down / QEMU crashed | immediate honest refusal; state corrected |
| wrong password | immediate `GUEST_AUTH_FAILED`, no retry |
| port forwarder up but sshd stalled >10 min | clear error with the wait budget + guidance |

---

## Verification (machine-checked)

- `scripts/59-verify-bootfix.js` — **37/37**. A/B against the real panels:
  the **shipped v2.1.1 bundled zip** reproduces the user's exact failure
  (illegal `-cpu host` + `accel=tcg` combo emitted, QEMU diagnostic in the
  VM log, start rejected); the patched panel boots all CPU configurations
  under TCG, preserves stored settings, surfaces diagnostics, flips state
  honestly after a late crash, and refuses RDP on dead VMs.
- `scripts/60-verify-rdpfix.js` — **16/16** with real ssh2 servers /
  mock forwarders: handshake-timeout classification, unreachable
  classification, retry-then-succeed across a silent phase, auth-failure
  fast-fail with exactly one connection, budget exhaustion messaging,
  `provisionGuest` budget wiring.
- Regressions: 16-e2e 50/50, 26-networking 31/31, 45-platform 134/134
  (+1 documented pre-existing task-cancel race), 56-downloadfix 48/48,
  53-agentfix 14/14.

## Upgrade notes

- Panel: `2.1.1 -> 2.1.2`; node agent: `1.4.0 -> 1.4.1` (shared
  rdp-guest.js; agent protocol unchanged). Both zips in `download/`.
- No DB migration, no manual SQLite edits. Existing VMs with
  `cpu_model='host'` boot under TCG automatically.
- Optional env: `RDP_SSH_WAIT_MS` (default 600000). On a KVM host,
  behaviour is byte-identical to v2.1.1 apart from the honest-state and
  diagnostic improvements.
