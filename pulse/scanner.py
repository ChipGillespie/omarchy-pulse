"""System health, package update, network security, and process audit engine."""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

STATE_DIR = Path.home() / ".local/state/omarchy-pulse"
REPORT_FILE = STATE_DIR / "latest_report.json"
CLAMAV_REPORT_FILE = STATE_DIR / "clamav_report.json"
FIM_BASELINE_FILE = STATE_DIR / "fim_baseline.json"
HISTORY_FILE = STATE_DIR / "history.jsonl"
BASELINE_FILE = STATE_DIR / "baseline.json"
HELPER_BIN = Path("/usr/local/libexec/omarchy-pulse-helper")

TAILSCALE_V4_NET = ipaddress.ip_network("100.64.0.0/10")
TAILSCALE_V6_NET = ipaddress.ip_network("fd7a:115c:a1e0::/48")

EXPECTED_BROWSER_BINS = {
    "chromium",
    "chrome",
    "google-chrome",
    "google-chrome-stable",
    "brave",
    "brave-browser",
    "firefox",
    "zen-browser",
    "vivaldi",
    "msedge",
    "opera",
}

EXPECTED_NETWORK_CLIENTS = EXPECTED_BROWSER_BINS | {
    "tailscaled",
    "NetworkManager",
    "systemd-resolved",
    "systemd-resolve",
    "systemd-timesyncd",
    "systemd-timesyn",
    "wpa_supplicant",
    "iwd",
    "avahi-daemon",
    "cupsd",
    "ssh",
    "git",
    "git-remote-https",
    "curl",
    "wget",
    "pacman",
    "yay",
    "flatpak",
    "fwupd",
    "localsend",
    "syncthing",
    "discord",
    "slack",
    "signal-desktop",
    "spotify",
    "steam",
    "code",
    "cursor",
    "antigravity",
    "agy",
    "codex",
    "claude",
    "opencode",
    "gemini",
    "gh",
    "node",
    "python3",
    "go",
}

CRITICAL_PACKAGES = {
    "omarchy",
    "omarchy-dev",
    "linux",
    "linux-lts",
    "linux-zen",
    "linux-firmware",
    "systemd",
    "hyprland",
    "mesa",
    "nvidia",
    "nvidia-dkms",
    "openssl",
    "openssh",
    "tailscale",
    "sudo",
    "glibc",
    "btrfs-progs",
    "cryptsetup",
}


def _run(
    cmd: list[str],
    timeout: int = 15,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """Execute a subprocess safely with timeout."""
    run_env = os.environ.copy()
    run_env["LC_ALL"] = "C"
    if env:
        run_env.update(env)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=run_env,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Timed out"
    except Exception as exc:
        return 1, "", str(exc)


def helper_available() -> bool:
    """Check if the scoped root helper is installed and authorized via sudo -n."""
    if not HELPER_BIN.is_file():
        return False
    rc, _, _ = _run(["sudo", "-n", str(HELPER_BIN), "status"], timeout=3)
    return rc == 0


def load_baseline() -> dict[str, Any]:
    """Load user-approved baseline configuration."""
    default_baseline: dict[str, Any] = {
        "approved_listeners": [
            "udp:5353:avahi-daemon",
            "udp:53:systemd-resolve",
            "tcp:53:systemd-resolve",
            "tcp:631:cupsd",
            "udp:631:cupsd",
        ],
        "muted_units": [],
        "approved_enabled_services": [],
        "deferred_updates": {
            "until_epoch": 0,
            "reason": "",
            "deferred_at": "",
            "omarchy_target": "",
            "package_count": 0,
        },
    }
    if not BASELINE_FILE.is_file():
        return default_baseline
    try:
        loaded = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
        for k, v in default_baseline.items():
            if k not in loaded:
                loaded[k] = v
        return loaded
    except Exception:
        return default_baseline


def save_baseline(data: dict[str, Any]) -> None:
    """Persist baseline configuration to disk."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    BASELINE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _human_bytes(num_bytes: int | float) -> str:
    val = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(val) < 1024.0 or unit == "TiB":
            return f"{val:.1f} {unit}" if unit != "B" else f"{int(val)} B"
        val /= 1024.0
    return f"{val:.1f} TiB"


def _dir_size_bytes(path: Path, max_depth: int = 3) -> int:
    """Fast directory size calculation using du -sb (tolerates partial permission errors)."""
    if not path.exists():
        return 0
    rc, out, _ = _run(["du", "-sb", str(path)], timeout=8)
    if out and out.strip():
        last_line = out.strip().splitlines()[-1]
        parts = last_line.split()
        if parts and parts[0].isdigit():
            return int(parts[0])
    return 0


def check_system_overview() -> dict[str, Any]:
    """Gather hostname, OS, Omarchy version, kernel, uptime, CPU load, and memory."""
    hostname = socket.gethostname()
    kernel = os.uname().release

    omarchy_ver = "unknown"
    rc, out, _ = _run(["omarchy", "version"], timeout=4)
    if rc == 0 and out.strip():
        omarchy_ver = out.strip()

    uptime_seconds = 0.0
    try:
        uptime_seconds = float(Path("/proc/uptime").read_text().split()[0])
    except Exception:
        pass

    days = int(uptime_seconds // 86400)
    hours = int((uptime_seconds % 86400) // 3600)
    mins = int((uptime_seconds % 3600) // 60)
    uptime_human = f"{days}d {hours}h {mins}m" if days > 0 else f"{hours}h {mins}m"

    load1, load5, load15 = os.getloadavg()
    cpu_count = os.cpu_count() or 1

    mem_total = 0
    mem_avail = 0
    swap_total = 0
    swap_free = 0
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                mem_total = int(line.split()[1]) * 1024
            elif line.startswith("MemAvailable:"):
                mem_avail = int(line.split()[1]) * 1024
            elif line.startswith("SwapTotal:"):
                swap_total = int(line.split()[1]) * 1024
            elif line.startswith("SwapFree:"):
                swap_free = int(line.split()[1]) * 1024
    except Exception:
        pass

    mem_used = max(0, mem_total - mem_avail)
    mem_pct = round((mem_used / mem_total) * 100, 1) if mem_total else 0.0

    # Check if running kernel modules exist on disk (missing means kernel was upgraded)
    modules_dir = Path(f"/usr/lib/modules/{kernel}")
    reboot_required = not modules_dir.is_dir()

    return {
        "hostname": hostname,
        "omarchy_version": omarchy_ver,
        "kernel": kernel,
        "reboot_required": reboot_required,
        "uptime_seconds": int(uptime_seconds),
        "uptime_human": uptime_human,
        "cpu_count": cpu_count,
        "load_avg": [round(load1, 2), round(load5, 2), round(load15, 2)],
        "memory": {
            "total_bytes": mem_total,
            "used_bytes": mem_used,
            "total_human": _human_bytes(mem_total),
            "used_human": _human_bytes(mem_used),
            "percent": mem_pct,
        },
        "swap": {
            "total_bytes": swap_total,
            "used_bytes": max(0, swap_total - swap_free),
            "total_human": _human_bytes(swap_total),
            "used_human": _human_bytes(max(0, swap_total - swap_free)),
        },
    }


def check_updates(baseline: dict[str, Any]) -> dict[str, Any]:
    """Check Omarchy updates, Arch repo updates, and AUR updates with deferral support."""
    # 1. Check omarchy-update-available
    rc_om, out_om, _ = _run(["omarchy-update-available"], timeout=20)
    omarchy_updates: list[str] = []
    if rc_om == 0 and out_om.strip():
        omarchy_updates = [line.strip() for line in out_om.splitlines() if line.strip()]

    # 2. Check official repo updates via checkupdates --nocolor
    rc_cu, out_cu, _ = _run(["checkupdates", "--nocolor"], timeout=30)
    repo_updates: list[dict[str, Any]] = []
    if rc_cu == 0 and out_cu.strip():
        for line in out_cu.splitlines():
            parts = line.strip().split()
            # Format: pkg old_ver -> new_ver
            if len(parts) >= 4 and parts[2] == "->":
                pkg = parts[0]
                repo_updates.append(
                    {
                        "name": pkg,
                        "old_version": parts[1],
                        "new_version": parts[3],
                        "source": "repo",
                        "critical": pkg in CRITICAL_PACKAGES,
                    }
                )

    # 3. Check AUR updates via yay -Qua
    aur_updates: list[dict[str, Any]] = []
    if shutil.which("yay"):
        rc_aur, out_aur, _ = _run(["yay", "-Qua"], timeout=25)
        if rc_aur == 0 and out_aur.strip():
            for line in out_aur.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[2] == "->":
                    pkg = parts[0]
                    aur_updates.append(
                        {
                            "name": pkg,
                            "old_version": parts[1],
                            "new_version": parts[3],
                            "source": "aur",
                            "critical": pkg in CRITICAL_PACKAGES,
                        }
                    )

    total_count = len(repo_updates) + len(aur_updates)
    critical_count = sum(1 for p in repo_updates + aur_updates if p["critical"])
    omarchy_target = omarchy_updates[0] if omarchy_updates else ""

    # Check deferral status
    defer_info = baseline.get("deferred_updates", {})
    until_epoch = float(defer_info.get("until_epoch", 0) or 0)
    now = time.time()
    is_deferred = False
    defer_remaining_human = ""

    if total_count > 0 and until_epoch > now:
        # If deferred for a specific Omarchy version, check if a newer one arrived
        saved_target = defer_info.get("omarchy_target", "")
        if not (omarchy_target and saved_target and omarchy_target != saved_target):
            is_deferred = True
            rem_hours = int((until_epoch - now) // 3600)
            if rem_hours >= 24:
                defer_remaining_human = f"{rem_hours // 24}d {rem_hours % 24}h"
            else:
                defer_remaining_human = f"{max(1, rem_hours)}h"

    return {
        "omarchy_update_available": len(omarchy_updates) > 0,
        "omarchy_update_lines": omarchy_updates,
        "omarchy_target": omarchy_target,
        "repo_count": len(repo_updates),
        "aur_count": len(aur_updates),
        "total_count": total_count,
        "critical_count": critical_count,
        "packages": repo_updates + aur_updates,
        "deferred": {
            "active": is_deferred,
            "until_epoch": int(until_epoch) if is_deferred else 0,
            "remaining_human": defer_remaining_human,
            "deferred_at": defer_info.get("deferred_at", "") if is_deferred else "",
            "reason": defer_info.get("reason", "") if is_deferred else "",
        },
    }


def _classify_ip(addr_str: str, iface: str = "") -> tuple[str, bool]:
    """Classify an IP address into Loopback, Tailscale, Link-Local/LAN, Wildcard, or External."""
    clean_ip = addr_str.strip("[]")
    if "%" in clean_ip:
        clean_ip, s_iface = clean_ip.split("%", 1)
        if not iface:
            iface = s_iface

    if iface == "tailscale0":
        return "Tailscale", True
    if clean_ip in ("*", "0.0.0.0", "::"):
        return "All Interfaces (0.0.0.0/::)", False

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.is_loopback:
            return "Loopback", True
        if (isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in TAILSCALE_V4_NET) or (
            isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj in TAILSCALE_V6_NET
        ):
            return "Tailscale", True
        if ip_obj.is_multicast:
            return "Multicast/mDNS", True
        if ip_obj.is_link_local or ip_obj.is_private:
            return "Local LAN", True
        return "External / Public", False
    except ValueError:
        return "Unknown", False


def _split_host_port(endpoint: str) -> tuple[str, str, str]:
    """Split ss local/peer address:port token into (ip, iface, port)."""
    iface = ""
    # Handle [ipv6]%iface:port or ip%iface:port
    if endpoint.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?:%([^:]+))?:(\*|\d+)$", endpoint)
        if m:
            return m.group(1), m.group(2) or "", m.group(3)
    if ":" in endpoint:
        host_part, port_part = endpoint.rsplit(":", 1)
        if "%" in host_part:
            host_part, iface = host_part.split("%", 1)
        return host_part, iface, port_part
    return endpoint, "", ""


def _parse_ss_users(line: str) -> tuple[str, int | None]:
    """Extract process name and PID from ss users:(("name",pid=123,fd=4)) column."""
    m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
    if m:
        return m.group(1), int(m.group(2))
    return "root / kernel (enable helper for PID)", None


def check_network_and_connections(
    baseline: dict[str, Any], use_helper: bool
) -> dict[str, Any]:
    """Audit listening ports, established external connections, Tailscale, and firewall."""
    # 1. Tailscale status
    ts_active = False
    ts_self_ip = ""
    ts_peers = 0
    if shutil.which("tailscale"):
        rc_ts, out_ts, _ = _run(["tailscale", "status", "--json"], timeout=5)
        if rc_ts == 0 and out_ts.strip():
            try:
                ts_json = json.loads(out_ts)
                ts_active = ts_json.get("BackendState") == "Running"
                ips = ts_json.get("TailscaleIPs") or []
                if ips:
                    ts_self_ip = ips[0]
                peers = ts_json.get("Peer") or {}
                ts_peers = sum(1 for p in peers.values() if p.get("Online"))
            except Exception:
                pass

    # 2. Listening sockets & established connections
    if use_helper:
        rc_l, out_l, _ = _run(
            ["sudo", "-n", str(HELPER_BIN), "sockets-listen"], timeout=8
        )
        rc_e, out_e, _ = _run(
            ["sudo", "-n", str(HELPER_BIN), "sockets-established"], timeout=8
        )
    else:
        rc_l, out_l, _ = _run(["ss", "-tulnp"], timeout=8)
        rc_e, out_e, _ = _run(["ss", "-tunp", "state", "established"], timeout=8)

    approved_set = set(baseline.get("approved_listeners", []))
    listeners: list[dict[str, Any]] = []
    unapproved_listeners_count = 0

    if rc_l == 0 and out_l:
        seen_keys: set[str] = set()
        for line in out_l.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0]
            state = parts[1]
            local_ep = parts[4]
            ip_str, iface, port_str = _split_host_port(local_ep)
            proc_name, pid = _parse_ss_users(line)
            scope_label, auto_trusted = _classify_ip(ip_str, iface)

            sig = f"{proto}:{port_str}:{proc_name}"
            port_only_sig = f"{proto}:{port_str}"
            dedup = f"{proto}:{ip_str}:{port_str}:{proc_name}"
            if dedup in seen_keys:
                continue
            seen_keys.add(dedup)

            # Auto-trust Tailscale WireGuard port (udp:41641) and mDNS printing discovery (udp:5353)
            if proto == "udp" and port_str == "41641" and ts_active:
                scope_label = "Tailscale WireGuard"
                auto_trusted = True
            elif proto == "udp" and port_str == "5353":
                scope_label = "mDNS / Printing"
                auto_trusted = True

            is_approved = sig in approved_set or port_only_sig in approved_set
            # Loopback and Tailscale listeners are trusted by default; wildcard/LAN listeners require baseline approval
            flagged = (not auto_trusted) and (not is_approved)
            if flagged:
                unapproved_listeners_count += 1

            listeners.append(
                {
                    "proto": proto,
                    "state": state,
                    "local_ip": ip_str,
                    "interface": iface,
                    "port": port_str,
                    "process": proc_name,
                    "pid": pid,
                    "scope": scope_label,
                    "signature": sig,
                    "approved": is_approved,
                    "auto_trusted": auto_trusted,
                    "flagged": flagged,
                }
            )

    # 3. Established connections
    connections: list[dict[str, Any]] = []
    suspicious_connections_count = 0

    if rc_e == 0 and out_e:
        for line in out_e.splitlines():
            if line.startswith("Netid") or line.startswith("State"):
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0] if parts[0] in ("tcp", "udp") else "tcp"
            local_ep = parts[3] if parts[0] != "ESTAB" else parts[2]
            peer_ep = parts[4] if parts[0] != "ESTAB" else parts[3]
            if len(parts) >= 5 and ":" in parts[3] and ":" in parts[4]:
                local_ep = parts[3]
                peer_ep = parts[4]

            loc_ip, loc_if, loc_port = _split_host_port(local_ep)
            rem_ip, rem_if, rem_port = _split_host_port(peer_ep)
            proc_name, pid = _parse_ss_users(line)

            rem_scope, rem_trusted = _classify_ip(rem_ip, rem_if or loc_if)
            # Check if Tailscale interface or CGNAT IP
            is_tailscale = rem_scope == "Tailscale" or _classify_ip(loc_ip, loc_if)[0] == "Tailscale"
            if is_tailscale:
                rem_scope = "Tailscale"

            # Flag connection if external and process is unknown/unexpected or non-standard port
            known_client = proc_name in EXPECTED_NETWORK_CLIENTS
            unusual_port = rem_port not in ("80", "443", "53", "853", "123", "22", "41641", "5228")
            flagged = False
            reason = "Expected traffic"

            if is_tailscale:
                reason = "Trusted Tailscale mesh"
            elif rem_scope == "Loopback":
                reason = "Localhost IPC"
            elif rem_scope == "Local LAN":
                reason = "Local network"
            elif not use_helper and proc_name.startswith("root / kernel") and rem_port in ("443", "41641", "853", "53", "123"):
                reason = "Root daemon DNS/HTTPS/DERP (enable helper for PID)"
            elif not known_client:
                flagged = True
                reason = f"Unrecognized process '{proc_name}' holding external connection"
            elif unusual_port and proc_name not in ("tailscaled", "ssh", "git"):
                flagged = True
                reason = f"External connection on non-standard port :{rem_port}"

            if flagged:
                suspicious_connections_count += 1

            connections.append(
                {
                    "proto": proto,
                    "local": f"{loc_ip}:{loc_port}",
                    "remote_ip": rem_ip,
                    "remote_port": rem_port,
                    "process": proc_name,
                    "pid": pid,
                    "scope": rem_scope,
                    "tailscale": is_tailscale,
                    "flagged": flagged,
                    "reason": reason,
                }
            )

    # 4. Firewall status
    fw_status = "Unknown (enable helper to inspect)"
    fw_active = False
    if use_helper:
        rc_fw, out_fw, _ = _run(["sudo", "-n", str(HELPER_BIN), "firewall"], timeout=5)
        if rc_fw == 0:
            if "Status: active" in out_fw:
                fw_status = "UFW Active"
                fw_active = True
            elif "table " in out_fw:
                fw_status = "nftables Active"
                fw_active = True
            else:
                fw_status = "Inactive (no active UFW/nftables rulesets)"
    else:
        rc_ufw, _, _ = _run(["systemctl", "is-active", "ufw"], timeout=3)
        rc_nft, _, _ = _run(["systemctl", "is-active", "nftables"], timeout=3)
        if rc_ufw == 0:
            fw_status = "UFW Service Active"
            fw_active = True
        elif rc_nft == 0:
            fw_status = "nftables Service Active"
            fw_active = True
        else:
            fw_status = "Host Firewall Inactive (Tailscale + NAT)"

    return {
        "tailscale": {
            "active": ts_active,
            "ip": ts_self_ip,
            "online_peers": ts_peers,
        },
        "firewall": {
            "status": fw_status,
            "active": fw_active,
        },
        "listeners": listeners,
        "unapproved_listeners_count": unapproved_listeners_count,
        "connections": connections,
        "suspicious_connections_count": suspicious_connections_count,
    }


def check_processes_and_daemons(
    baseline: dict[str, Any], use_helper: bool
) -> dict[str, Any]:
    """Audit systemd failed units, newly enabled services, suspicious /proc processes, and crashes."""
    muted_units = set(baseline.get("muted_units", []))

    # 1. Failed systemd units (system + user)
    failed_units: list[dict[str, Any]] = []
    for scope, base_cmd in [
        ("system", ["systemctl", "list-units", "--state=failed", "--no-legend", "--plain"]),
        ("user", ["systemctl", "--user", "list-units", "--state=failed", "--no-legend", "--plain"]),
    ]:
        rc, out, _ = _run(base_cmd, timeout=5)
        if rc == 0 and out.strip():
            for line in out.splitlines():
                parts = line.split(None, 4)
                if len(parts) >= 4:
                    unit_name = parts[0]
                    desc = parts[4] if len(parts) >= 5 else ""
                    failed_units.append(
                        {
                            "unit": unit_name,
                            "scope": scope,
                            "description": desc,
                            "muted": unit_name in muted_units,
                        }
                    )

    unmuted_failed_count = sum(1 for u in failed_units if not u["muted"])

    # 2. Enabled services baseline check
    enabled_services: list[str] = []
    for scope, cmd in [
        ("system", ["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend"]),
        ("user", ["systemctl", "--user", "list-unit-files", "--type=service", "--state=enabled", "--no-legend"]),
    ]:
        rc, out, _ = _run(cmd, timeout=5)
        if rc == 0 and out.strip():
            for line in out.splitlines():
                parts = line.split()
                if parts:
                    enabled_services.append(f"{scope}:{parts[0]}")

    enabled_services.sort()
    approved_services = set(baseline.get("approved_enabled_services", []))
    # If baseline has never been initialized, auto-seed on first scan so only future additions flag
    if not approved_services and enabled_services:
        baseline["approved_enabled_services"] = list(enabled_services)
        save_baseline(baseline)
        approved_services = set(enabled_services)

    new_enabled_services = [s for s in enabled_services if s not in approved_services]

    # 3. Suspicious process heuristics in /proc
    process_anomalies: list[dict[str, Any]] = []
    proc_lines: list[str] = []

    if use_helper:
        rc_p, out_p, _ = _run(["sudo", "-n", str(HELPER_BIN), "proc-audit"], timeout=8)
        if rc_p == 0 and out_p.strip():
            proc_lines = out_p.splitlines()
    else:
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                exe = os.readlink(pid_dir / "exe")
                comm = (pid_dir / "comm").read_text().strip()
                proc_lines.append(f"{pid_dir.name}\t{comm}\t{exe}")
            except Exception:
                continue

    for line in proc_lines:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        pid_str, comm, exe_target = parts[0], parts[1], parts[2]
        if any(
            exe_target.startswith(p)
            for p in ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")
        ):
            process_anomalies.append(
                {
                    "pid": int(pid_str),
                    "name": comm,
                    "exe": exe_target,
                    "severity": "high",
                    "reason": "Executable running from temporary/world-writable filesystem",
                }
            )
        elif "(deleted)" in exe_target:
            # Ignore short-lived browser/JIT/pacman self-replacement unless persistent
            process_anomalies.append(
                {
                    "pid": int(pid_str),
                    "name": comm,
                    "exe": exe_target,
                    "severity": "info",
                    "reason": "Running binary was replaced or deleted on disk (restart service/app to use updated binary)",
                }
            )

    # 4. Top CPU & RAM processes
    top_processes: list[dict[str, Any]] = []
    rc_ps, out_ps, _ = _run(
        ["ps", "-eo", "pid,user,pcpu,pmem,rss,comm", "--sort=-pcpu"], timeout=5
    )
    if rc_ps == 0 and out_ps.strip():
        for line in out_ps.splitlines()[1:9]:
            parts = line.split(None, 5)
            if len(parts) == 6:
                top_processes.append(
                    {
                        "pid": int(parts[0]),
                        "user": parts[1],
                        "cpu_pct": float(parts[2]),
                        "mem_pct": float(parts[3]),
                        "rss_human": _human_bytes(int(parts[4]) * 1024),
                        "command": parts[5],
                    }
                )

    # 5. Recent coredumps (past 7 days)
    recent_crashes: list[dict[str, Any]] = []
    since_date = (dt.datetime.now() - dt.timedelta(days=7)).strftime("%Y-%m-%d")
    rc_cd, out_cd, _ = _run(
        ["coredumpctl", "list", "--no-legend", "--since", since_date], timeout=5
    )
    if rc_cd == 0 and out_cd.strip():
        for line in out_cd.splitlines()[-10:]:
            parts = line.split()
            if len(parts) >= 10:
                recent_crashes.append(
                    {
                        "time": f"{parts[0]} {parts[1]} {parts[2]}",
                        "pid": parts[4],
                        "signal": parts[7],
                        "exe": parts[-2] if len(parts) >= 10 else parts[-1],
                    }
                )

    # 6. Recent auth failures (past 7 days)
    auth_failures = 0
    rc_au, out_au, _ = _run(
        [
            "journalctl",
            "--since",
            "7 days ago",
            "-p",
            "warning..emerg",
            "-g",
            "authentication failure|Failed password|NOT in sudoers",
            "--no-pager",
            "-q",
        ],
        timeout=6,
    )
    if rc_au == 0 and out_au.strip():
        auth_failures = len(out_au.splitlines())

    return {
        "failed_units": failed_units,
        "unmuted_failed_count": unmuted_failed_count,
        "enabled_services_count": len(enabled_services),
        "new_enabled_services": new_enabled_services,
        "process_anomalies": process_anomalies,
        "high_severity_anomalies_count": sum(
            1 for a in process_anomalies if a["severity"] == "high"
        ),
        "top_processes": top_processes,
        "recent_crashes": recent_crashes,
        "auth_failures_7d": auth_failures,
    }


def collect_fim_snapshot() -> dict[str, dict[str, Any]]:
    """Collect a fast (~8ms) SHA-256 & permission snapshot of critical system, PAM, SSH, and user files."""
    home = Path.home()
    fixed_files = [
        Path("/etc/passwd"),
        Path("/etc/group"),
        Path("/etc/shells"),
        Path("/etc/hosts"),
        Path("/etc/nsswitch.conf"),
        Path("/etc/ld.so.conf"),
        Path("/etc/ld.so.preload"),
        Path("/etc/environment"),
        Path("/etc/profile"),
        Path("/etc/ssh/sshd_config"),
        home / ".ssh/authorized_keys",
        home / ".ssh/config",
        home / ".bashrc",
        home / ".zshrc",
        home / ".profile",
        home / ".bash_profile",
        home / ".zprofile",
    ]
    dirs_to_scan = [
        Path("/etc/ssh/sshd_config.d"),
        Path("/etc/pam.d"),
        Path("/usr/local/bin"),
        Path("/usr/local/sbin"),
        Path("/usr/local/libexec"),
        home / ".local/bin",
        home / ".config/hypr",
        home / ".config/autostart",
        home / ".config/systemd/user",
    ]
    targets: set[Path] = set()
    for f in fixed_files:
        if f.is_file():
            targets.add(f)
    for d in dirs_to_scan:
        if d.is_dir():
            try:
                for child in d.iterdir():
                    if (
                        child.is_file()
                        and not child.name.endswith(".bak")
                        and ".bak." not in child.name
                    ):
                        targets.add(child)
            except Exception:
                pass

    records: dict[str, dict[str, Any]] = {}
    for p in sorted(targets):
        try:
            st = p.stat()
            if st.st_size > 10 * 1024 * 1024:
                continue
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            records[str(p)] = {
                "sha256": digest,
                "mode": oct(st.st_mode & 0o7777),
                "size": st.st_size,
            }
        except Exception:
            pass
    return records


def save_fim_baseline(records: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Save the current SHA-256 snapshot as the trusted FIM baseline."""
    if records is None:
        records = collect_fim_snapshot()
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S"),
        "files": records,
    }
    FIM_BASELINE_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def check_fim_baseline() -> dict[str, Any]:
    """Compare current SHA-256 hashes and modes against the saved FIM baseline."""
    current = collect_fim_snapshot()
    if not FIM_BASELINE_FILE.is_file():
        saved = save_fim_baseline(current)
        return {
            "total_tracked": len(current),
            "baseline_timestamp": saved["timestamp"],
            "changes_count": 0,
            "changes": [],
            "healthy": True,
        }

    try:
        loaded = json.loads(FIM_BASELINE_FILE.read_text(encoding="utf-8"))
        base_files: dict[str, dict[str, Any]] = loaded.get("files", {})
        base_ts = str(loaded.get("timestamp", "Unknown"))
    except Exception:
        saved = save_fim_baseline(current)
        return {
            "total_tracked": len(current),
            "baseline_timestamp": saved["timestamp"],
            "changes_count": 0,
            "changes": [],
            "healthy": True,
        }

    home_str = str(Path.home())
    changes: list[dict[str, Any]] = []

    # Check modified or added files
    for path_str, cur_meta in current.items():
        short_path = path_str.replace(home_str, "~")
        if path_str not in base_files:
            changes.append(
                {
                    "path": short_path,
                    "change_type": "ADDED",
                    "severity": "warn",
                    "detail": f"New file added to monitored path (sha256: {cur_meta['sha256'][:12]}…, mode {cur_meta['mode']})",
                }
            )
            continue

        old_meta = base_files[path_str]
        if cur_meta["sha256"] != old_meta.get("sha256"):
            is_sys = path_str.startswith(("/etc/", "/usr/"))
            changes.append(
                {
                    "path": short_path,
                    "change_type": "MODIFIED",
                    "severity": "high" if is_sys else "warn",
                    "detail": f"SHA-256 changed ({old_meta.get('sha256', '')[:10]}… → {cur_meta['sha256'][:10]}…)",
                }
            )
        elif cur_meta["mode"] != old_meta.get("mode"):
            changes.append(
                {
                    "path": short_path,
                    "change_type": "PERMS",
                    "severity": "warn",
                    "detail": f"Permissions changed ({old_meta.get('mode')} → {cur_meta['mode']})",
                }
            )

    # Check removed files
    for path_str, old_meta in base_files.items():
        if path_str not in current:
            short_path = path_str.replace(home_str, "~")
            changes.append(
                {
                    "path": short_path,
                    "change_type": "REMOVED",
                    "severity": "warn",
                    "detail": f"Baselined file removed (was sha256: {old_meta.get('sha256', '')[:12]}…)",
                }
            )

    return {
        "total_tracked": len(current),
        "baseline_timestamp": base_ts,
        "changes_count": len(changes),
        "changes": changes,
        "healthy": len(changes) == 0,
    }


def check_malware_and_integrity(
    baseline: dict[str, Any], use_helper: bool
) -> dict[str, Any]:
    """Scan persistence vectors, suspicious files/droppers, package integrity, and ClamAV status."""
    home = Path.home()
    persistence_checks: list[dict[str, Any]] = []
    suspicious_files: list[dict[str, Any]] = []

    # 1. /etc/ld.so.preload & LD_PRELOAD check
    ld_preload_env = os.environ.get("LD_PRELOAD", "").strip()
    ld_preload_file = Path("/etc/ld.so.preload")
    ld_file_content = ""
    if ld_preload_file.is_file():
        try:
            ld_file_content = ld_preload_file.read_text(encoding="utf-8", errors="ignore").strip()
        except Exception:
            pass
    if ld_preload_env or ld_file_content:
        persistence_checks.append(
            {
                "vector": "Dynamic Linker Preload (LD_PRELOAD)",
                "location": "/etc/ld.so.preload",
                "status": "danger",
                "detail": f"Active preload library detected: {ld_preload_env or ld_file_content}",
            }
        )
    else:
        persistence_checks.append(
            {
                "vector": "Dynamic Linker Preload",
                "location": "/etc/ld.so.preload",
                "status": "ok",
                "detail": "No LD_PRELOAD or /etc/ld.so.preload hooks present",
            }
        )

    # 2. SSH authorized_keys & ~/.ssh permissions audit
    ssh_dir = home / ".ssh"
    auth_keys = ssh_dir / "authorized_keys"
    if auth_keys.is_file():
        try:
            st_mode = auth_keys.stat().st_mode & 0o777
            lines = [
                ln.strip()
                for ln in auth_keys.read_text(encoding="utf-8", errors="ignore").splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
            bad_perms = (st_mode & 0o077) != 0
            persistence_checks.append(
                {
                    "vector": "SSH Authorized Keys",
                    "location": "~/.ssh/authorized_keys",
                    "status": "warn" if bad_perms else "ok",
                    "detail": (
                        f"{len(lines)} key(s) configured (mode {oct(st_mode)})"
                        + (" — permissions too open!" if bad_perms else "")
                    ),
                }
            )
        except Exception:
            pass
    else:
        persistence_checks.append(
            {
                "vector": "SSH Authorized Keys",
                "location": "~/.ssh/authorized_keys",
                "status": "ok",
                "detail": "No authorized_keys file present",
            }
        )

    # 3. Shell startup profile inspection
    shell_Suspicious_re = re.compile(
        r"(curl\s+[^|]+\|\s*(ba)?sh|wget\s+[^|]+\|\s*(ba)?sh|base64\s+-d\s*\||/dev/tcp/|nc\s+-e|socat\s+.*exec|/tmp/\.[A-Za-z0-9])",
        re.IGNORECASE,
    )
    rc_files = [".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile"]
    rc_hits: list[str] = []
    rc_checked = 0
    for rc_name in rc_files:
        rc_path = home / rc_name
        if rc_path.is_file():
            rc_checked += 1
            try:
                content = rc_path.read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines():
                    s_line = line.strip()
                    if not s_line or s_line.startswith("#"):
                        continue
                    if shell_Suspicious_re.search(s_line):
                        rc_hits.append(f"~/{rc_name}: {s_line[:80]}")
            except Exception:
                pass
    if rc_hits:
        persistence_checks.append(
            {
                "vector": "Shell Startup Profiles",
                "location": "~/.bashrc, ~/.zshrc, ~/.profile",
                "status": "danger",
                "detail": f"Suspicious command in shell profile: {'; '.join(rc_hits)}",
            }
        )
    else:
        persistence_checks.append(
            {
                "vector": "Shell Startup Profiles",
                "location": f"{rc_checked} profile file(s)",
                "status": "ok",
                "detail": "No pipe-to-shell, reverse shell, or temp-exec payloads found",
            }
        )

    # 4. XDG Autostart & Hyprland autostart inspection
    autostart_dir = home / ".config/autostart"
    autostart_entries = list(autostart_dir.glob("*.desktop")) if autostart_dir.is_dir() else []
    bad_autostart: list[str] = []
    for desk in autostart_entries:
        try:
            txt = desk.read_text(encoding="utf-8", errors="ignore")
            if any(p in txt for p in ("/tmp/", "/var/tmp/", "/dev/shm/", "curl ", "base64")):
                bad_autostart.append(desk.name)
        except Exception:
            pass
    persistence_checks.append(
        {
            "vector": "XDG & Desktop Autostart",
            "location": "~/.config/autostart",
            "status": "danger" if bad_autostart else "ok",
            "detail": (
                f"Suspicious autostart launcher(s): {', '.join(bad_autostart)}"
                if bad_autostart
                else f"{len(autostart_entries)} XDG autostart entry(s) clean"
            ),
        }
    )

    # 5. User Crontab check
    if shutil.which("crontab"):
        rc_cr, out_cr, _ = _run(["crontab", "-l"], timeout=3)
        cron_lines = [
            ln.strip()
            for ln in (out_cr.splitlines() if rc_cr == 0 else [])
            if ln.strip() and not ln.strip().startswith("#")
        ]
        persistence_checks.append(
            {
                "vector": "User Crontab",
                "location": "crontab -l",
                "status": "warn" if cron_lines else "ok",
                "detail": f"{len(cron_lines)} user cron job(s) active" if cron_lines else "No user cron jobs scheduled",
            }
        )

    # 6. Heuristic scan of ~/Downloads, /tmp, /var/tmp, /dev/shm for hidden ELF binaries, droppers, miners
    known_bad_names = {
        "xmrig",
        "minerd",
        "kdevtmpfsi",
        "kinsing",
        "cryptonight",
        "nanominer",
        "nbminer",
        "lolminer",
        "redline",
    }
    disguised_re = re.compile(r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|zip)\.(sh|py|pl|elf|bin|run)$", re.IGNORECASE)

    scan_roots = [
        (home / "Downloads", "Downloads"),
        (Path("/tmp"), "/tmp"),
        (Path("/var/tmp"), "/var/tmp"),
        (Path("/dev/shm"), "/dev/shm"),
        (home / ".local/bin", "~/.local/bin"),
    ]

    for root_path, label in scan_roots:
        if not root_path.is_dir():
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root_path):
                # Limit recursion depth to 2 levels for speed
                rel_depth = len(Path(dirpath).relative_to(root_path).parts)
                if rel_depth >= 2:
                    dirnames[:] = []
                # Skip browser temporary profiles and known build dirs
                dirnames[:] = [
                    d
                    for d in dirnames
                    if not d.startswith(("systemd-private", ".org.chromium", "v8-compile-cache"))
                ]
                for fname in filenames[:200]:
                    fpath = Path(dirpath) / fname
                    try:
                        st = fpath.lstat()
                    except Exception:
                        continue
                    if not os.path.isfile(fpath) or os.path.islink(fpath):
                        continue

                    low_name = fname.lower()
                    is_exec = bool(st.st_mode & 0o111)
                    is_suid = bool(st.st_mode & 0o6000)

                    # Check known miner/malware binary names
                    if low_name in known_bad_names:
                        suspicious_files.append(
                            {
                                "path": str(fpath),
                                "category": "Known Miner / Malware Name",
                                "severity": "high",
                                "detail": f"Matches known malicious binary name '{fname}'",
                            }
                        )
                        continue

                    # Unexpected SUID/SGID in user/temp dirs
                    if is_suid:
                        suspicious_files.append(
                            {
                                "path": str(fpath),
                                "category": "Unexpected SUID/SGID File",
                                "severity": "high",
                                "detail": f"Setuid/setgid bit set on file in {label} ({oct(st.st_mode & 0o7777)})",
                            }
                        )
                        continue

                    # Disguised double extension in Downloads/tmp
                    if disguised_re.search(fname):
                        suspicious_files.append(
                            {
                                "path": str(fpath),
                                "category": "Disguised Executable",
                                "severity": "high",
                                "detail": "Double extension masquerading as document/media",
                            }
                        )
                        continue

                    # Hidden ELF binary in Downloads or temp dirs
                    if (fname.startswith(".") or label in ("/tmp", "/var/tmp", "/dev/shm")) and is_exec:
                        try:
                            with fpath.open("rb") as bf:
                                magic = bf.read(4)
                            if magic == b"\x7fELF":
                                suspicious_files.append(
                                    {
                                        "path": str(fpath),
                                        "category": "Hidden / Temp ELF Binary",
                                        "severity": "high" if fname.startswith(".") else "warn",
                                        "detail": f"Executable ELF binary in {label} ({_human_bytes(st.st_size)})",
                                    }
                                )
                        except Exception:
                            pass
        except Exception:
            pass

    # 7. Core System Package Integrity (pacman -Qk)
    core_pkgs = [
        "sudo",
        "openssh",
        "systemd",
        "glibc",
        "pambase",
        "polkit",
        "shadow",
        "hyprland",
        "omarchy",
    ]
    rc_qk, out_qk, err_qk = _run(["pacman", "-Qk", *core_pkgs], timeout=6)
    integrity_issues: list[str] = []
    verified_pkgs = 0
    for line in (out_qk + "\n" + err_qk).splitlines():
        line_s = line.strip()
        if not line_s:
            continue
        if "0 missing files" in line_s:
            verified_pkgs += 1
        elif "missing file" in line_s and not line_s.startswith("warning:"):
            integrity_issues.append(line_s)

    # 8. Unmerged .pacnew / .pacsave files in /etc
    pacnew_files: list[str] = []
    if use_helper:
        rc_pn, out_pn, _ = _run(["sudo", "-n", str(HELPER_BIN), "pacnew-list"], timeout=5)
        if rc_pn == 0 and out_pn.strip():
            pacnew_files = [ln.strip() for ln in out_pn.splitlines() if ln.strip()]
    else:
        rc_pn, out_pn, _ = _run(
            ["find", "/etc", "-maxdepth", "2", "(", "-name", "*.pacnew", "-o", "-name", "*.pacsave", ")"],
            timeout=5,
        )
        if out_pn.strip():
            pacnew_files = [ln.strip() for ln in out_pn.splitlines() if ln.strip()]

    # 9. ClamAV on-demand scanner status & latest deep scan report
    clamscan_bin = shutil.which("clamscan")
    clamav_installed = bool(clamscan_bin)
    clam_db_dir = Path("/var/lib/clamav")
    db_files = (
        list(clam_db_dir.glob("*.cvd")) + list(clam_db_dir.glob("*.cld"))
        if clam_db_dir.is_dir()
        else []
    )
    db_updated = "Not initialized"
    if db_files:
        newest_mtime = max(f.stat().st_mtime for f in db_files)
        db_updated = dt.datetime.fromtimestamp(newest_mtime).strftime("%Y-%m-%d %H:%M")

    last_clam_scan: dict[str, Any] | None = None
    if CLAMAV_REPORT_FILE.is_file():
        try:
            last_clam_scan = json.loads(CLAMAV_REPORT_FILE.read_text(encoding="utf-8"))
        except Exception:
            last_clam_scan = None

    persistence_alerts = sum(1 for c in persistence_checks if c["status"] in ("warn", "danger"))
    clam_infected = int((last_clam_scan or {}).get("infected_count", 0) or 0)
    fim_status = check_fim_baseline()
    threat_alerts_count = (
        persistence_alerts
        + len(suspicious_files)
        + len(integrity_issues)
        + clam_infected
        + fim_status["changes_count"]
    )

    return {
        "threat_alerts_count": threat_alerts_count,
        "persistence_checks": persistence_checks,
        "suspicious_files": suspicious_files,
        "package_integrity": {
            "verified_packages": verified_pkgs,
            "total_checked": len(core_pkgs),
            "issues": integrity_issues,
            "healthy": len(integrity_issues) == 0,
        },
        "fim": fim_status,
        "pacnew_files": pacnew_files,
        "pacnew_count": len(pacnew_files),
        "clamav": {
            "installed": clamav_installed,
            "db_ready": len(db_files) > 0,
            "db_updated": db_updated,
            "daemon_running": False,
            "last_scan": last_clam_scan,
        },
    }


def run_clamav_scan() -> dict[str, Any]:
    """Run an on-demand, low-priority ClamAV scan on high-risk user and temp directories."""
    if not shutil.which("clamscan"):
        return {
            "ok": False,
            "message": "ClamAV (clamscan) is not installed.",
        }

    home = Path.home()
    targets = [
        str(p)
        for p in (
            home / "Downloads",
            home / ".local/bin",
            home / ".config/autostart",
            Path("/tmp"),
            Path("/var/tmp"),
            Path("/dev/shm"),
        )
        if p.exists()
    ]

    start_ts = time.time()
    cmd = [
        "nice",
        "-n",
        "19",
        "ionice",
        "-c",
        "3",
        "clamscan",
        "--recursive",
        "--infected",
        "--no-summary",
        "--max-filesize=100M",
        "--max-scansize=250M",
        "--exclude-dir=^/tmp/systemd-private",
        "--exclude-dir=^/var/tmp/systemd-private",
        "--exclude-dir=^/tmp/\\.org\\.chromium",
        *targets,
    ]
    rc, out, err = _run(cmd, timeout=300)
    duration_sec = round(time.time() - start_ts, 1)

    infected_lines = [
        ln.strip() for ln in out.splitlines() if ln.strip().endswith("FOUND")
    ]
    now_str = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

    scan_record = {
        "timestamp": now_str,
        "duration_sec": duration_sec,
        "targets": [t.replace(str(home), "~") for t in targets],
        "infected_count": len(infected_lines),
        "infected_files": infected_lines,
        "return_code": rc,
    }
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    CLAMAV_REPORT_FILE.write_text(json.dumps(scan_record, indent=2), encoding="utf-8")
    return {
        "ok": rc in (0, 1, 2) and rc != 124,
        "scan": scan_record,
    }


def check_cleanup_and_storage(use_helper: bool) -> dict[str, Any]:
    """Inspect reclaimable package caches, user caches, Trash, coredumps, journals, orphans, and Btrfs health."""
    home = Path.home()

    # 1. Pacman cache reclaimable bytes via paccache -dvk2 & -dvuk0
    paccache_reclaim_bytes = 0
    paccache_pkg_dir = Path("/var/cache/pacman/pkg")
    paccache_total_bytes = _dir_size_bytes(paccache_pkg_dir)
    for flag in ("-dvk2", "-dvuk0"):
        rc_pcv, out_pcv, _ = _run(["paccache", flag], timeout=10)
        if rc_pcv == 0 and out_pcv:
            for raw_ln in out_pcv.splitlines():
                ln = raw_ln.strip()
                if not ln or ln.startswith("==>"):
                    continue
                cand_path = Path(ln) if ln.startswith("/") else (paccache_pkg_dir / ln)
                try:
                    if cand_path.is_file():
                        paccache_reclaim_bytes += cand_path.stat().st_size
                except Exception:
                    pass

    # 2. AUR cache (~/.cache/yay + ~/.cache/paru)
    yay_cache_bytes = _dir_size_bytes(home / ".cache/yay") + _dir_size_bytes(
        home / ".cache/paru"
    )

    # 3. User ~/.cache breakdown & safe-to-clean caches
    cache_root = home / ".cache"
    user_cache_total_bytes = _dir_size_bytes(cache_root)
    safe_cache_names = {
        "thumbnails",
        "mesa_shader_cache",
        "mesa_shader_cache_db",
        "nvidia",
        "pip",
        "uv",
        "go-build",
        "npm",
        "yarn",
        "pnpm",
        "fontconfig",
        "yay",
        "paru",
        "wine",
        "winetricks",
    }
    user_cache_breakdown: list[dict[str, Any]] = []
    safe_user_cache_bytes = 0
    if cache_root.is_dir():
        try:
            for child in cache_root.iterdir():
                if not child.is_dir() or child.is_symlink():
                    continue
                sz = _dir_size_bytes(child)
                if sz <= 0:
                    continue
                is_safe = child.name in safe_cache_names
                if is_safe:
                    safe_user_cache_bytes += sz
                user_cache_breakdown.append(
                    {
                        "name": child.name,
                        "path": f"~/.cache/{child.name}",
                        "bytes": sz,
                        "human": _human_bytes(sz),
                        "safe_clean": is_safe,
                    }
                )
        except Exception:
            pass
    user_cache_breakdown.sort(key=lambda x: x["bytes"], reverse=True)

    # 4. Trash (~/.local/share/Trash) & Systemd Core Dumps (/var/lib/systemd/coredump)
    trash_bytes = _dir_size_bytes(home / ".local/share/Trash")
    coredump_dir = Path("/var/lib/systemd/coredump")
    coredump_bytes = _dir_size_bytes(coredump_dir)
    coredump_count = (
        len(list(coredump_dir.glob("core.*"))) if coredump_dir.is_dir() else 0
    )

    # 5. Systemd journal usage
    journal_bytes = _dir_size_bytes(Path("/var/log/journal"))

    # 6. Orphan packages (pacman -Qdtq)
    orphans: list[str] = []
    rc_or, out_or, _ = _run(["pacman", "-Qdtq"], timeout=5)
    if rc_or == 0 and out_or.strip():
        orphans = [p.strip() for p in out_or.splitlines() if p.strip()]

    # 7. Root filesystem & Btrfs health
    usage = shutil.disk_usage("/")
    disk_pct = round((usage.used / usage.total) * 100, 1) if usage.total else 0.0

    btrfs_errors = 0
    btrfs_status = "Healthy"
    if use_helper:
        rc_bt, out_bt, _ = _run(["sudo", "-n", str(HELPER_BIN), "btrfs-health"], timeout=5)
        if rc_bt == 0 and out_bt.strip():
            for line in out_bt.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1].isdigit():
                    btrfs_errors += int(parts[1])
            btrfs_status = (
                "0 Device Errors (Healthy)"
                if btrfs_errors == 0
                else f"{btrfs_errors} Btrfs Device Errors Detected!"
            )
    else:
        btrfs_status = "Btrfs Mounted (/dev/mapper/root)"

    # 8. Top directories in $HOME (fast 1-level scan)
    home_breakdown: list[dict[str, Any]] = []
    candidates = [
        home / ".cache",
        home / ".local/share",
        home / "Projects",
        home / "Downloads",
        home / "Documents",
        home / ".config",
    ]
    for d in candidates:
        if d.is_dir():
            sz = _dir_size_bytes(d)
            home_breakdown.append(
                {
                    "path": f"~/{d.relative_to(home)}",
                    "bytes": sz,
                    "human": _human_bytes(sz),
                }
            )
    home_breakdown.sort(key=lambda x: x["bytes"], reverse=True)

    reclaimable_total = (
        paccache_reclaim_bytes + safe_user_cache_bytes + trash_bytes + coredump_bytes
    )

    return {
        "disk": {
            "mount": "/",
            "fs_type": "btrfs (/dev/mapper/root)",
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "total_human": _human_bytes(usage.total),
            "used_human": _human_bytes(usage.used),
            "free_human": _human_bytes(usage.free),
            "percent": disk_pct,
            "btrfs_status": btrfs_status,
            "btrfs_errors": btrfs_errors,
        },
        "cleanup": {
            "paccache_total_bytes": paccache_total_bytes,
            "paccache_total_human": _human_bytes(paccache_total_bytes),
            "paccache_reclaim_bytes": paccache_reclaim_bytes,
            "paccache_reclaim_human": _human_bytes(paccache_reclaim_bytes),
            "yay_cache_bytes": yay_cache_bytes,
            "yay_cache_human": _human_bytes(yay_cache_bytes),
            "user_cache_total_bytes": user_cache_total_bytes,
            "user_cache_total_human": _human_bytes(user_cache_total_bytes),
            "safe_user_cache_bytes": safe_user_cache_bytes,
            "safe_user_cache_human": _human_bytes(safe_user_cache_bytes),
            "user_cache_breakdown": user_cache_breakdown[:8],
            "trash_bytes": trash_bytes,
            "trash_human": _human_bytes(trash_bytes),
            "coredump_bytes": coredump_bytes,
            "coredump_human": _human_bytes(coredump_bytes),
            "coredump_count": coredump_count,
            "journal_bytes": journal_bytes,
            "journal_human": _human_bytes(journal_bytes),
            "orphans": orphans,
            "orphans_count": len(orphans),
            "reclaimable_total_bytes": reclaimable_total,
            "reclaimable_total_human": _human_bytes(reclaimable_total),
        },
        "home_breakdown": home_breakdown,
    }


def compute_health_score(
    overview: dict[str, Any],
    updates: dict[str, Any],
    network: dict[str, Any],
    daemons: dict[str, Any],
    storage: dict[str, Any],
    threats: dict[str, Any] | None = None,
) -> tuple[int, str, list[str]]:
    """Compute a 0-100 health score and list actionable findings."""
    score = 100
    findings: list[str] = []

    if overview.get("reboot_required"):
        score -= 10
        findings.append("Reboot required: running kernel differs from installed kernel modules.")

    if not updates["deferred"]["active"]:
        if updates["omarchy_update_available"]:
            score -= 10
            findings.append("New Omarchy release update is available.")
        elif updates["total_count"] > 20:
            score -= 8
            findings.append(f"{updates['total_count']} package updates pending.")
        elif updates["total_count"] > 0:
            score -= 3
            findings.append(f"{updates['total_count']} package updates available.")

    if network["unapproved_listeners_count"] > 0:
        score -= min(25, network["unapproved_listeners_count"] * 10)
        findings.append(
            f"{network['unapproved_listeners_count']} non-loopback/non-Tailscale listening port(s) not in baseline."
        )

    if network["suspicious_connections_count"] > 0:
        score -= min(30, network["suspicious_connections_count"] * 15)
        findings.append(
            f"{network['suspicious_connections_count']} unexpected external network connection(s) detected."
        )

    if daemons["high_severity_anomalies_count"] > 0:
        score -= 35
        findings.append(
            f"{daemons['high_severity_anomalies_count']} process(es) executing from temporary directories!"
        )

    if daemons["unmuted_failed_count"] > 0:
        score -= min(15, daemons["unmuted_failed_count"] * 5)
        findings.append(
            f"{daemons['unmuted_failed_count']} failed systemd unit(s) require review or muting."
        )

    if daemons["new_enabled_services"]:
        score -= 5
        findings.append(
            f"{len(daemons['new_enabled_services'])} newly enabled systemd service(s) since baseline."
        )

    if threats:
        if threats.get("suspicious_files"):
            score -= min(30, len(threats["suspicious_files"]) * 15)
            findings.append(
                f"{len(threats['suspicious_files'])} suspicious executable/file(s) detected in temp or user folders."
            )
        pers_bad = sum(
            1 for c in threats.get("persistence_checks", []) if c["status"] == "danger"
        )
        if pers_bad > 0:
            score -= 30
            findings.append(f"{pers_bad} high-risk persistence/preload hook(s) flagged!")
        if not threats.get("package_integrity", {}).get("healthy", True):
            score -= 20
            findings.append("Core system package integrity check reported missing/altered files.")
        clam_inf = int(((threats.get("clamav") or {}).get("last_scan") or {}).get("infected_count", 0) or 0)
        if clam_inf > 0:
            score -= 40
            findings.append(f"ClamAV reported {clam_inf} infected file(s) in last deep scan!")
        if threats.get("pacnew_count", 0) > 0:
            score -= 3
            findings.append(
                f"{threats['pacnew_count']} unmerged .pacnew/.pacsave config file(s) in /etc."
            )
        fim_changes = int((threats.get("fim") or {}).get("changes_count", 0) or 0)
        if fim_changes > 0:
            score -= min(20, fim_changes * 5)
            findings.append(
                f"{fim_changes} file(s) changed since SHA-256 FIM baseline (review or re-baseline in Threat Scan)."
            )

    if storage["disk"]["percent"] >= 90:
        score -= 20
        findings.append(f"Root filesystem is {storage['disk']['percent']}% full.")
    elif storage["disk"]["btrfs_errors"] > 0:
        score -= 30
        findings.append("Btrfs device errors reported on root volume.")

    score = max(0, min(100, score))
    if score >= 90:
        status_label = "Optimal"
    elif score >= 75:
        status_label = "Attention Needed"
    else:
        status_label = "Action Required"

    if not findings:
        findings.append("All system, package, daemon, integrity, and network checks passed.")

    return score, status_label, findings


def run_full_scan() -> dict[str, Any]:
    """Run all audit modules, persist report to state directory, and return it."""
    start_ts = time.time()
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    baseline = load_baseline()
    has_helper = helper_available()

    overview = check_system_overview()
    updates = check_updates(baseline)
    network = check_network_and_connections(baseline, has_helper)
    daemons = check_processes_and_daemons(baseline, has_helper)
    threats = check_malware_and_integrity(baseline, has_helper)
    storage = check_cleanup_and_storage(has_helper)

    score, status_label, findings = compute_health_score(
        overview, updates, network, daemons, storage, threats
    )

    now_iso = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    duration_ms = int((time.time() - start_ts) * 1000)

    report: dict[str, Any] = {
        "timestamp": now_iso,
        "duration_ms": duration_ms,
        "helper_active": has_helper,
        "health_score": score,
        "status_label": status_label,
        "findings": findings,
        "overview": overview,
        "updates": updates,
        "network": network,
        "daemons": daemons,
        "threats": threats,
        "storage": storage,
    }

    REPORT_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # Append compact entry to history.jsonl
    history_entry = {
        "timestamp": now_iso,
        "score": score,
        "updates": updates["total_count"],
        "unapproved_listeners": network["unapproved_listeners_count"],
        "failed_units": daemons["unmuted_failed_count"],
        "threat_alerts": threats["threat_alerts_count"],
        "disk_pct": storage["disk"]["percent"],
    }
    with HISTORY_FILE.open("a", encoding="utf-8") as hf:
        hf.write(json.dumps(history_entry) + "\n")

    return report


def get_latest_or_scan() -> dict[str, Any]:
    """Return cached report if recent and schema-complete, otherwise run a scan."""
    if REPORT_FILE.is_file():
        try:
            data = json.loads(REPORT_FILE.read_text(encoding="utf-8"))
            if (
                "fim" in data.get("threats", {})
                and "user_cache_breakdown" in data.get("storage", {}).get("cleanup", {})
            ):
                data["helper_active"] = helper_available()
                return data
        except Exception:
            pass
    return run_full_scan()
