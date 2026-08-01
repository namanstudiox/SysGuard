# 🛡️ SysGuard

**Full system diagnostics · real-time monitoring · automated security reports** — a cross-platform desktop app for **Windows** and **Linux** (one codebase, built with Electron + Node.js).

![stack](https://img.shields.io/badge/Electron-33-47848f) ![platform](https://img.shields.io/badge/Windows%20%7C%20Linux-supported-22c55e) ![license](https://img.shields.io/badge/license-MIT-blue)

---

## ✨ Features

| Tab | What it does |
| --- | --- |
| **📊 Overview** | Live gauges (CPU, RAM, disk, temperature) + stat cards (uptime, load, processes, battery, security score) + rolling area charts for CPU/RAM, network and disk I/O |
| **🖥️ System** | One-click full inventory: OS & kernel, host/BIOS, CPU (cores, speed, cache), memory & DIMM modules, GPUs, physical disks with **SMART health**, mounted volumes, network adapters, battery, USB devices, installed software, temperatures |
| **📈 Monitor** | Configurable-interval live charts (CPU per-core, RAM/swap, network throughput, disk I/O), per-core load bars, and a **process explorer** with search, sort and kill |
| **🛡️ Security** | Full audit with a **0–100 security score**: open/listening ports, exposed risky services, auto-start services & startup items, firewall state, pending (security) updates, suspicious processes (miner/RAT/stealer signatures, temp-dir executables, odd outbound connections), accounts & password/SSH/UAC policy, plus **network posture** — public IP, geolocation, NAT/VPN/hosting detection, DNS reachability |
| **📄 Reports** | Generate styled **HTML**, **Markdown** or **PDF** reports on demand; **schedule automatic reports** (daily / weekly / every N hours / on app start) with full history kept in-app |
| **⚙️ Settings** | Refresh interval, chart history, dark/light theme, external-check toggle, expected egress country, data directory |

Every security scan is automatically saved to history so you can reopen past results and watch the score trend.

---

## 🚀 Quick start (run from source)

Requires **Node.js ≥ 18** (Node 20/22 recommended).

```bash
cd sysguard
npm install          # installs Electron + systeminformation
npm start            # launches the app
```

> On first `npm install`, Electron downloads its prebuilt binary (~100 MB) — this needs internet. It only happens once.

### Windows notes
- No admin rights are required for most checks. A few (Windows Update query, Defender status) silently fall back to "unknown" if they can't run.
- If Windows Defender SmartScreen warns about the packaged `.exe`, choose *More info → Run anyway* (the app is unsigned).

### Linux notes
- Works on Debian/Ubuntu (apt), Fedora/RHEL (dnf), Arch, etc.
- For **process names on listening ports** and full service details you may need to run as your user (no root needed for the app itself); some deep checks (e.g. `ss -p`) show less detail without root — the app degrades gracefully.
- On headless systems you need a desktop session (X11/Wayland).

---

## 📦 Building installers

### Linux — `AppImage` + `.deb`

```bash
cd sysguard
bash scripts/build-linux.sh        # or: npx electron-builder --linux AppImage deb --x64
```
Artifacts land in `release/`:
- `SysGuard-1.0.2-linux-x64.AppImage` — portable, chmod +x and run
- `SysGuard-1.0.2-linux-x64.deb` — `sudo apt install ./SysGuard-...deb`

### Windows — `.exe` installer

On Windows:
```powershell
cd sysguard
.\scripts\build-windows.ps1        # or: npx electron-builder --win nsis --x64
```
Artifacts land in `release\SysGuard-Setup-1.0.0-win-x64.exe` (NSIS installer with desktop/start-menu shortcuts).

> You can also cross-build the Windows installer from Linux/macOS — electron-builder handles NSIS without Wine for typical setups. Building natively on Windows is the most reliable path.

### 🚀 Publishing a GitHub release (automatic)

The repo includes `.github/workflows/release.yml`. Push a tag and GitHub Actions builds everything and attaches it to a Release.

**One-time setup (first push):**

1. Create the repo on GitHub, then push the project:
   ```bash
   git init
   git add .
   git commit -m "SysGuard 1.0.0"
   git branch -M main
   git remote add origin https://github.com/<you>/sysguard.git
   git push -u origin main
   ```
2. In `package.json`, set `homepage` and `repository.url` to your real repo (they're placeholder `yourname/sysguard` values right now — the `.deb` embeds them).

**Every release:**

```bash
# bump the version in package.json first (e.g. 1.0.0 -> 1.0.1)
npm version patch        # bumps version, commits, tags v1.0.1
git push && git push --tags
```

That's it — the workflow runs on any `v*` tag and produces, **by platform**:

| Platform | Artifact | Built on |
| --- | --- | --- |
| **Windows** | `SysGuard-Setup-<ver>-win-x64.exe` (NSIS installer) | windows-latest |
| **Windows** | `SysGuard-Setup-<ver>-win-x64.zip` (portable, no install) | windows-latest |
| **Linux** | `SysGuard-<ver>-linux-x64.AppImage` (portable) | ubuntu-latest |
| **Linux** | `SysGuard-<ver>-linux-x64.deb` (Debian/Ubuntu package) | ubuntu-latest |
| **macOS** (optional) | `SysGuard-<ver>-mac-x64.dmg` | macos-latest |

- Windows users download the **.exe** (or the zip for a portable copy).
- Linux users download the **.deb** (Ubuntu/Debian) or **.AppImage** (any distro, just chmod +x).
- Everything lands on the **Releases** page (`github.com/<you>/sysguard/releases`), plus `latest*.yml` auto-update metadata. You can also trigger a build manually from **Actions → Release → Run workflow**. Delete the macOS matrix entry if you don't want a `.dmg`.

---

## 🔍 What the security scan checks (platform-aware)

| Category | Checks |
| --- | --- |
| Open Ports | All listening TCP/UDP ports (via `ss`/`netstat`/`Get-NetTCPConnection`), services bound to `0.0.0.0`, risky well-known ports (SMB 445, RDP 3389, VNC 5900, Redis 6379, telnet/FTP…) |
| Services & Startup | Auto-start services, startup registry keys / `~/.config/autostart` / systemd units, and services or entries launching from suspicious (temp) paths |
| Firewall | `netsh advfirewall` (Windows) · `ufw` / `firewalld` / raw `nft`+`iptables` (Linux) |
| Updates & Patching | Pending updates & **security** updates — `apt`/`dnf` (Linux), Microsoft.Update COM searcher + hotfix history (Windows) |
| Processes | Known miner/RAT/stealer/ransomware name signatures, executables running from `/tmp`, `%TEMP%`, recycle bin etc., outbound connections to non-standard ports, sustained high-CPU processes |
| Accounts & Policy | Non-root UID-0 accounts, sudo/administrators group size, guest account, UAC, auto-updates, Defender real-time protection, password age/length policy, SSH `PermitRootLogin`/`PasswordAuthentication` |
| Network | Public IP + ISP/geolocation, **NAT/VPN/hosting detection**, DNS resolvability, egress-country mismatch (when you set an expected country in Settings) |

Score: start at 100, deduct per finding (critical −25, high −12, medium −6, low −2, info 0). Grades A+ … F.

---

## 🗂 Project structure

```
sysguard/
├── app.js                 # Electron main process (window, IPC, monitor, scheduler, PDF)
├── preload.js             # contextBridge API (window.sysguard)
├── renderer/
│   ├── index.html         # 6-tab UI
│   ├── styles.css         # dark/light theme
│   ├── charts.js          # dependency-free canvas line charts + gauges
│   └── app.js             # renderer logic
├── src/
│   ├── constants.js       # settings defaults, suspicious-process signatures, port notes
│   ├── store.js           # JSON persistence (settings, history, last-runs)
│   ├── diagnostics.js     # full system inventory (systeminformation)
│   ├── monitor.js         # real-time sampling engine (ring-buffer history)
│   ├── security.js        # the security scanner (local + policy checks)
│   ├── netcheck.js        # public IP, geolocation, NAT/VPN, DNS reachability
│   ├── report.js          # HTML / Markdown report rendering
│   └── scheduler.js       # daily / weekly / interval / on-start scheduling
├── assets/                # app icon + packaging resources
├── scripts/               # build-linux.sh, build-windows.ps1
├── tests/                 # headless engine tests (no GUI needed)
└── electron-builder.yml   # .exe / AppImage / .deb packaging config
```

### Headless tests (great for CI or quick checks)

```bash
npm run test:diag       # print this machine's full inventory
npm run test:security   # run a real security scan + score
npm run test:report     # write sample HTML/Markdown reports to sample-reports/
```

### Dev / UI verification harnesses

The UI is a custom dark ops-console design (bundled Inter + JetBrains Mono, hand-drawn SVG icon set, canvas charts — no chart libraries, no emoji). For iterating on the UI headlessly there's one env-flag harness in `app.js`:

```bash
SYSGUARD_SCREENSHOT=/tmp/shots xvfb-run -a npx electron . --no-sandbox   # capture every tab as PNG, then exit
```

---

## 🔒 Security hardening

- Renderer runs fully **sandboxed** (`sandbox: true`) with `contextIsolation` + `nodeIntegration: false`; the UI only talks to the main process through a minimal `contextBridge` API (`preload.js`).
- Strict **CSP** (`default-src 'self'`; no inline scripts, `object-src 'none'`, `base-uri 'none'`); navigation and `window.open` are blocked.
- IPC file handlers (`report:open`, `report:reveal`, `sec:load`, `report:delete`) only operate on paths **inside the reports directory** — no arbitrary path traversal.
- Report `include`/`format` values are whitelisted (`full|security|diagnostics`, `html|md|pdf`).
- Diagnostics/scans are **read-only**: no files are modified on the host; reports are written only to the app data dir.

---

## 💾 Data & storage

| What | Where |
| --- | --- |
| Settings & schedules | `<userData>/settings.json` (Electron userData = `%APPDATA%/sysguard` on Windows, `~/.config/sysguard` on Linux) |
| Reports & scan history | `<userData>/reports/` + `history.json` |
| Fallback (no Electron) | `~/.sysguard/` — override with env `SYSGUARD_DATA_DIR` |

---

## 🧰 Troubleshooting

- **Electron won't start: "SUID sandbox helper binary was found, but is not configured correctly"** (common on Ubuntu). Fix the sandbox helper permissions once:
  ```bash
  sudo chown root:root node_modules/electron/dist/chrome-sandbox
  sudo chmod 4755 node_modules/electron/dist/chrome-sandbox
  ```
  …or simply run `npm run start:nosandbox`. Note: re-apply the `chmod` if you ever re-run `npm install`.
- **Packaged app (AppImage/.deb) crashes with "The application SysGuard has closed unexpectedly"** on Ubuntu 23.10+/24.04 (AppArmor blocks unprivileged user namespaces). Fixed in v1.0.2:
  - **.deb** — the installer forces the setuid `chrome-sandbox` helper (`chmod 4755`) via `scripts/after-install.sh`, which works regardless of the user-namespace policy.
  - **AppImage** — the app detects it can't sandbox (AppRun marker / FUSE) and relaunches itself with `--no-sandbox` automatically.
  - If it still crashes: run from a terminal — `./SysGuard-*.AppImage` or `sysguard` — and paste the output. Force the sandbox back with `SYSGUARD_ENABLE_SANDBOX=1` if you prefer and configure the helper yourself.
- **`npm start` does nothing / white window** — run from a desktop session; check `Ctrl+Shift+I` (DevTools) and the console.
- **"Firewall status could not be determined"** on Linux — `ufw`/`firewalld`/`nft` tools are missing; `sudo apt install nftables ufw` (or equivalent).
- **Update count looks stale on Debian** — counts reflect the last `apt update`; run `sudo apt update` and rescan.
- **PDF export produces a blank page** — very old Electron/Chromium builds; update Electron (`npm i -D electron@latest`).
- **Scan is slower than expected** — external checks (public IP/geo/DNS) need internet; disable them in Settings for fully offline use.

---

## ⚖️ License

MIT — free to use, modify and redistribute. SysGuard is a transparency tool: it inspects the machine *it runs on*. It does not upload any data anywhere; all checks run locally (external checks only query public IP/geo/DNS services).
