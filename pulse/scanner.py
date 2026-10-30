"""System health, package update, network security, and process audit engine."""

from __future__ import annotations

import datetime as dt
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
    """Fast directory size calculation using du -sb."""
    if not path.exists():
        return 0
    rc, out, _ = _run(["du", "-sb", str(path)], timeout=8)
    if rc == 0 and out.strip():
        parts = out.strip().split()
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


def check_cleanup_and_storage(use_helper: bool) -> dict[str, Any]:
    """Inspect reclaimable package caches, journals, orphans, Btrfs health, and directory sizes."""
    home = Path.home()

    # 1. Pacman cache reclaimable bytes via paccache -dk2
    paccache_reclaim_bytes = 0
    paccache_pkg_dir = Path("/var/cache/pacman/pkg")
    paccache_total_bytes = _dir_size_bytes(paccache_pkg_dir)
    rc_pc, out_pc, _ = _run(["paccache", "-dk2"], timeout=10)
    if rc_pc == 0 and "candidate" in out_pc:
        # Also check uninstalled cache
        pass
    # Estimate reclaimable if more than 2 versions exist
    rc_pcv, out_pcv, _ = _run(["paccache", "-dvk2"], timeout=10)
    if rc_pcv == 0:
        cand_files = [
            line.strip()
            for line in out_pcv.splitlines()
            if line.strip().startswith("/var/cache/pacman/pkg/")
        ]
        for fp in cand_files:
            try:
                paccache_reclaim_bytes += Path(fp).stat().st_size
            except Exception:
                pass

    # 2. AUR cache (~/.cache/yay)
    yay_cache_dir = home / ".cache/yay"
    yay_cache_bytes = _dir_size_bytes(yay_cache_dir)

    # 3. Systemd journal usage
    journal_bytes = _dir_size_bytes(Path("/var/log/journal"))

    # 4. Orphan packages (pacman -Qdtq)
    orphans: list[str] = []
    rc_or, out_or, _ = _run(["pacman", "-Qdtq"], timeout=5)
    if rc_or == 0 and out_or.strip():
        orphans = [p.strip() for p in out_or.splitlines() if p.strip()]

    # 5. Root filesystem & Btrfs health
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

    # 6. Top directories in $HOME (fast 1-level scan)
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

    reclaimable_total = paccache_reclaim_bytes + yay_cache_bytes

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
        findings.append("All system, package, daemon, and network checks passed.")

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
    storage = check_cleanup_and_storage(has_helper)

    score, status_label, findings = compute_health_score(
        overview, updates, network, daemons, storage
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
        "disk_pct": storage["disk"]["percent"],
    }
    with HISTORY_FILE.open("a", encoding="utf-8") as hf:
        hf.write(json.dumps(history_entry) + "\n")

    return report


def get_latest_or_scan() -> dict[str, Any]:
    """Return cached report if recent, otherwise run a scan."""
    if REPORT_FILE.is_file():
        try:
            data = json.loads(REPORT_FILE.read_text(encoding="utf-8"))
            # Refresh helper_active flag dynamically
            data["helper_active"] = helper_available()
            return data
        except Exception:
            pass
    return run_full_scan()
