<div align="center">

<img src="public/images/logo-new.svg" width="96" alt="VNM Panel logo" />

# VNM Panel

**A complete virtualization management platform — QEMU/KVM VMs, multi-node fleets, snapshots & backups, monitoring & alerting, all behind a gorgeous aurora UI.**

Fast, self-hosted, and built for real work: spin up VMs with cloud-init, move them between nodes live, schedule backups, and watch everything from one dashboard.

![Version](https://img.shields.io/badge/version-2.1.0-22d3ee) ![License](https://img.shields.io/badge/license-MIT-818cf8) ![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-c084fc) ![Node](https://img.shields.io/badge/Node.js-%E2%89%A518-339933)

</div>

---

## ⚡ One-click install (Ubuntu / Debian VPS)

```bash
curl -fsSL https://raw.githubusercontent.com/Hopingboyz/VNM-Panel/main/install.sh | sudo bash
```

That's it. The installer downloads Node.js 22 LTS, QEMU/KVM and every dependency, sets up a systemd service, opens the firewall port, and prints your auto-generated admin password — all in ~2–5 minutes.

> **Forked or renamed the repo?** Point the installer at your copy:
> ```bash
> curl -fsSL https://raw.githubusercontent.com/<you>/VNM-Panel/main/install.sh | \
>   sudo VNM_REPO_URL="https://github.com/<you>/VNM-Panel.git" bash
> ```

<details>
<summary><b>Other install methods</b> (manual, offline bundle, upgrade, uninstall)</summary>

```bash
# From an extracted source zip (offline-friendly):
sudo bash install.sh

# From the bundled zip (pre-installed node_modules — no npm install needed):
sudo VNM_SOURCE=./VNM-Panel-v2.1.0-linux-x64-bundled.zip bash install.sh

# Upgrade an existing install (data & settings are always kept):
curl -fsSL https://raw.githubusercontent.com/Hopingboyz/VNM-Panel/main/install.sh | sudo bash

# Uninstall:
sudo bash uninstall.sh            # keeps /opt/vnm-panel data
sudo bash uninstall.sh --purge    # removes EVERYTHING (VM disks too!)
```

**Useful installer flags** (environment variables):

| Variable | Default | What it does |
|---|---|---|
| `INSTALL_DIR` | `/opt/vnm-panel` | Install location |
| `PORT` | `8080` | Web UI port |
| `VNM_SKIP_QEMU` | `0` | `1` = skip QEMU packages (control-panel-only hosts) |
| `VNM_NO_SERVICE` | `0` | `1` = skip systemd (containers) |
| `VNM_BRANCH` | repo default | Install a specific branch |
| `NODE_MAJOR` | `22` | Node.js major version to install |

</details>

---

## ✨ What's inside

| Area | Features |
|---|---|
| **VMs** | Create from OS templates (Ubuntu/Debian/Fedora/CentOS/Alma/Arch/Windows), custom ISOs, cloud-init SSH keys, start/stop/restart/clone/delete, bulk actions, tags, VNC console, web-based SSH terminal, RDP, SFTP file manager |
| **Networking** | 5 NIC models, NAT & bridge modes, up to 16 custom TCP/UDP port-forward rules per VM (with honest port-in-use checks), MAC management, IP allocation pool with conflict detection, firewall rules with safe defaults |
| **Multi-node** | Built-in Node Agent ("wings") — register worker servers, create VMs directly on remote nodes, live migration between nodes, maintenance mode, graceful draining, capacity-aware placement recommendations, health heartbeats |
| **Snapshots & Backups** | Real `qemu-img` snapshots, full-file backups with SHA-256 checksums, verification, recovery-test-into-clone, cross-node restore, export/import |
| **Automation** | Persistent task queue with progress/retry/cancellation, cron-style schedules (daily / weekly / every N minutes), crash recovery |
| **Monitoring** | Live CPU/RAM/disk charts (zero-dependency canvas), 24h history, threshold alert rules with sustain windows, alert events + acknowledgement, Discord webhook notifications |
| **Security** | Role-based access (admin/user), per-VM ownership, 2FA (TOTP), scoped API keys (`vnmak_…`), audit trail, rate limiting, CSRF double-submit, session rotation, request signing |
| **Premium tier** | Auto Backup, Live Migration, Alert Rules, Scheduled Power — unlocked with a license key, enforced **server-side** (keys are only ever stored as SHA-256 digests) |

<div align="center">

| Login | Dashboard |
|:---:|:---:|
| ![Login](docs/screenshots/login.jpg) | ![Dashboard](docs/screenshots/dashboard.jpg) |

| Monitoring | Snapshots & Backups |
|:---:|:---:|
| ![Monitoring](docs/screenshots/monitoring.jpg) | ![Snapshots](docs/screenshots/snapshots.jpg) |

| VM Detail | Command Palette (Ctrl+K) |
|:---:|:---:|
| ![VM Detail](docs/screenshots/vm-detail.jpg) | ![Command Palette](docs/screenshots/command-palette.jpg) |

</div>

---

## 🔑 Free vs Premium

Everything you need to run VMs is **free forever**. One license key unlocks the power tier:

| Free | Premium (PRO) |
|---|---|
| VMs, console/VNC/RDP/SSH, ISO library | **Auto Backup** — scheduled backups with retention |
| Manual snapshots & backups | **Live Migration** — move running VMs between nodes |
| Users, nodes, firewall, file manager | **Alert Rules** — threshold alerts + Discord webhooks |
| Audit log, API keys, task queue | **Scheduled Power** — auto start/stop/restart |

Click any ✨ PRO feature in the UI and the license dialog opens — enter your key once, it's validated server-side against a SHA-256 digest and never stored or transmitted in plaintext again.

---

## 🖥️ Requirements

- **OS:** Ubuntu 20.04+ / Debian 11+ (fresh VPS works great)
- **RAM:** 1 GB minimum (2 GB+ recommended)
- **Disk:** 5 GB for the panel + space for VM disks
- **KVM:** optional — without `/dev/kvm` VMs run under software emulation (slower but functional, e.g. inside nested VMs)

## 🧩 Node Agent (worker nodes)

Turn any other server into a compute node:

1. Panel → **Nodes** → *Install Agent* (downloads a ready agent package with your panel's token baked in), or follow `node-agent/README.md`
2. The agent registers via websocket, appears ONLINE, and VMs can then be **created directly on that node** with real SSH access (cloud-init seed built on-node)
3. Migrate VMs between nodes live from the UI

## ⚙️ Configuration

Everything lives in `/opt/vnm-panel/.env` (auto-generated on install):

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Web UI port |
| `VNM_DATA_DIR` | `/opt/vnm-panel/data` | Database location |
| `PANEL_NAME` | `VNM` | Branding shown in the UI |
| `SESSION_SECRET` | random | Cookie signing key — keep it secret |
| `DISCORD_CLIENT_ID/SECRET` | empty | Enable Discord OAuth login + linking |
| `SMTP_*` | empty | Email alerts for monitoring |

After editing: `sudo systemctl restart vnm-panel`.

## 🛠️ Troubleshooting

| Problem | Fix |
|---|---|
| Panel unreachable | `sudo systemctl status vnm-panel` then `journalctl -u vnm-panel -n 50` |
| Forgot admin password | `sudo journalctl -u vnm-panel \| grep -B1 -A1 "Default admin"` (first boot), or reset via the documented SQLite method in `docs/` |
| VMs extremely slow | Check `egrep -c '(vmx\|svm)' /proc/cpuinfo` — no KVM means software emulation |
| Port already in use | `PORT=9090 sudo -E bash install.sh` or edit `.env` |
| sqlite3 ABI error after Node upgrade | `cd /opt/vnm-panel && sudo npm rebuild sqlite3` |

## 📚 Documentation

Deep-dive docs live in [`docs/`](docs/):

- [`PREMIUM_FEATURES.md`](docs/PREMIUM_FEATURES.md) — the premium tier, UI touchpoints, API enforcement
- [`PLATFORM_CHANGES.md`](docs/PLATFORM_CHANGES.md) — task engine, monitoring, snapshots/backups, migration architecture
- [`NODE_AGENT_CHANGES.md`](docs/NODE_AGENT_CHANGES.md) — agent protocol, remote provisioning, relays
- [`NETWORKING_CHANGES.md`](docs/NETWORKING_CHANGES.md) — NIC models, port forwarding, IP pools, firewall
- [`AURORA_DEEPFIX_CHANGES.md`](docs/AURORA_DEEPFIX_CHANGES.md) — the design system + the 26-bug deep fix round

## 🤝 Contributing

Issues and PRs are welcome. The stack is deliberately boring and dependable: Express, EJS, SQLite, vanilla JS frontends — no build step, no webpack, no drama.

## 📄 License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

**Built with 🤍 by Hopingboyz**

⭐ Star the repo if VNM Panel made your VPS life easier!

</div>
