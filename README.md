# Omarchy Pulse — System Health, Live Telemetry & Security Audit Dashboard

A local-first, zero-dependency system health, package update, live `btop`-style resource monitor, and network security audit dashboard built for [Omarchy](https://omarchy.org/) (Arch Linux + Hyprland).

---

## Features

- **Zero Idle Footprint (On-Demand Server):**
  - Binds strictly to `127.0.0.1:18420` when launched from the Omarchy menu (`Super+Alt+Space > System Health`) and automatically terminates ~1.5 seconds after you close the window.
  - Built entirely on the Python 3 standard library (`http.server`, `tomllib`, `json`, `subprocess`) — zero `pip` packages or virtualenvs that can break across Arch Python upgrades.
- **Dynamic Omarchy Theme & Font Sync:**
  - Reads `~/.local/state/omarchy/current/theme/colors.toml` and `~/.local/state/omarchy/current/theme.name` with in-memory `mtime` caching (0.005 ms check) and live hot-reload when you switch themes.
- **System Pulse Overview & `fastfetch` Hardware Profile:**
  - Displays composite 0–100 health score, actionable findings, Btrfs root health, and a `fastfetch`-style hardware/software breakdown (Host/BIOS, OS, Kernel, Hyprland display resolution/Hz, CPU, GPU, package count, shell/terminal, theme).
- **Real-Time `Live Monitor (btop)` Tab:**
  - Pure-Python `/proc` and `/sys` delta telemetry (~13 ms per poll, zero subprocesses spawned) that runs **only** while the Live Monitor tab is active:
    - **CPU:** Total %, Package Temp (`°C`), Load Avg, and per-core utilization bars with live clocks (`MHz`) and per-core temperatures.
    - **GPU:** Real-time GPU utilization % (Intel i915 RC6 residency delta / AMD `gpu_busy_percent`) and active/requested/max clock speeds.
    - **Memory, Swap & Network:** Live RAM/Cache/Buffers/Swap bars and real-time `↓ RX/s` / `↑ TX/s` interface throughput.
    - **Live Process Table:** Top 25 active processes with real-time per-interval `CPU%`, `MEM%`, `RSS`, `Threads`, and `State` (sortable by CPU% or MEM%).
- **Omarchy Updates (`Accept` / `Defer` Workflow):**
  - Checks `omarchy-update-available`, `checkupdates --nocolor` (official repos), and `yay -Qua` (AUR).
  - **Accept & Install:** Launches `omarchy-update` in Omarchy's floating presentation terminal (preserving Btrfs snapshots and migrations).
  - **Defer Updates (24h / 7d):** Mutes update alerts and clears the top-bar update badge (`omarchy.system-update`) until the deferral expires or a newer Omarchy release drops.
- **Network, Listener & Process Security Audit:**
  - Automatically trusts Loopback (`127.0.0.0/8`, `::1`), Tailscale (`tailscale0`, `100.64.0.0/10`, `fd7a:115c:a1e0::/48`, WireGuard `:41641`), and mDNS (`:5353`).
  - Flags unapproved wildcard/LAN listening ports (`ss -tulnp`) and unexpected external connections (`ss -tunp`) with one-click baseline approval.
  - Audits `/proc` for binaries running from temporary directories (`/tmp`, `/dev/shm`, `/var/tmp`) or deleted paths, tracks `systemctl --failed` (with one-click muting for known hardware/TPM quirks), and monitors newly enabled systemd services.
- **Threat, Malware & Persistence Integrity Scanner:**
  - **SHA-256 File Integrity Monitor (FIM):** Tracks SHA-256 cryptographic hashes and file permissions (~8 ms scan) across `/etc/passwd`, `/etc/group`, `/etc/hosts`, `/etc/ssh/sshd_config*`, `/etc/pam.d/*`, `/usr/local/{bin,sbin,libexec}`, `~/.local/bin`, `~/.ssh/*`, shell startup profiles, and `~/.config/{hypr,autostart,systemd/user}` with one-click baseline approval.
  - **Persistence & Hijack Audit:** Inspects `/etc/ld.so.preload` & `LD_PRELOAD`, `~/.ssh/authorized_keys` permissions, shell startup profiles (`~/.bashrc`, `~/.zshrc`, `~/.profile`), `~/.config/autostart/*.desktop`, and user crontabs.
  - **Dropper & File Heuristics:** Scans `~/Downloads`, `/tmp`, `/var/tmp`, `/dev/shm`, and `~/.local/bin` for hidden ELF binaries, unexpected SUID/SGID files, disguised double-extension scripts, and known cryptominer/malware names.
  - **Core Package Integrity & Config Drift:** Verifies core packages (`sudo`, `openssh`, `systemd`, `glibc`, `pambase`, `polkit`, `shadow`, `hyprland`, `omarchy`) via `pacman -Qk` and detects unmerged `/etc/*.pacnew` files.
  - **On-Demand Deep Malware Scan (ClamAV):** Runs `clamscan` strictly on-demand at lowest CPU/IO priority (`nice -n 19 ionice -c 3`) with `clamav-daemon` and `clamav-freshclam` disabled (0 MB idle RAM).
- **CleanMyMac-Style System Junk & Cache Cleaner:**
  - Prunes Pacman package cache (`paccache -rk2` & `-ruk0` + stale `download-*` folders), safe `~/.cache` build/shader/thumbnail directories, AUR caches (`yay` & `paru`), `~/.local/share/Trash`, systemd core dumps (`/var/lib/systemd/coredump`), systemd journals, and orphaned packages.
- **Omarchy Bar Widget (`chip.pulse`) & Keybinding (`SUPER + H`):**
  - Launches directly via `SUPER + H` or the `chip.pulse` bar icon next to the clock (`centerBegin`), which live-watches `latest_report.json` with zero polling overhead.
- **Weekly Automated `systemd --user` Timer:**
  - Runs `omarchy-pulse.timer` weekly in the background, saves the latest report to `~/.local/state/omarchy-pulse/latest_report.json`, and sends a desktop notification (`notify-send`).

---

## Quick Install (Fresh Omarchy Machine)

```bash
git clone https://github.com/ChipGillespie/omarchy-pulse.git ~/Projects/omarchy-pulse
cd ~/Projects/omarchy-pulse
./install.sh
```

### Commands

```bash
omarchy-pulse-launch         # Launch the on-demand dashboard window
omarchy-pulse-scan           # Run a CLI scan + desktop notification
omarchy-pulse-setup-sudoers  # Install/update the strictly scoped root helper
systemctl --user status omarchy-pulse.timer
```

### Uninstall

```bash
~/Projects/omarchy-pulse/uninstall.sh
```
