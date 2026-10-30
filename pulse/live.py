"""Real-time btop-style hardware/process telemetry and fastfetch-style system profile.

Uses pure-Python /proc and /sys reads (zero subprocesses during live polling)
to minimize CPU and memory overhead on Intel N100 hardware.
"""

from __future__ import annotations

import os
import pwd
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from .scanner import _human_bytes
from .theme import get_theme_info

_LOCK = threading.Lock()
_CLK_TCK = os.sysconf(os.sysconf_names.get("SC_CLK_TCK", "SC_CLK_TCK")) or 100
_PAGE_SIZE = os.sysconf("SC_PAGE_SIZE") or 4096

# State for delta calculations across polls
_prev_ts: float = 0.0
_prev_cpu_times: dict[str, tuple[int, int]] = {}
_prev_proc_ticks: dict[int, int] = {}
_prev_rc6_ms: int | None = None
_prev_net_bytes: dict[str, tuple[int, int]] = {}
_uid_cache: dict[int, str] = {}
_cached_fastfetch: dict[str, Any] | None = None
_cached_fastfetch_ts: float = 0.0


def _read_first_line(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()[0].strip()
    except Exception:
        return default


def _read_int(path: Path, default: int = 0) -> int:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except Exception:
        return default


def _uid_to_name(uid: int) -> str:
    if uid in _uid_cache:
        return _uid_cache[uid]
    try:
        name = pwd.getpwuid(uid).pw_name
    except KeyError:
        name = str(uid)
    _uid_cache[uid] = name
    return name


def _find_drm_card() -> Path | None:
    drm_root = Path("/sys/class/drm")
    if not drm_root.is_dir():
        return None
    for card in sorted(drm_root.glob("card[0-9]*")):
        if "-" not in card.name and (card / "device").exists():
            return card
    return None


def _find_coretemp_hwmon() -> Path | None:
    hwmon_root = Path("/sys/class/hwmon")
    if not hwmon_root.is_dir():
        return None
    for hw in sorted(hwmon_root.glob("hwmon*")):
        name = _read_first_line(hw / "name")
        if name in ("coretemp", "k10temp", "zenpower", "cpu_thermal"):
            return hw
    return None


def _detect_gpu_name() -> str:
    try:
        res = subprocess.run(
            ["lspci"], capture_output=True, text=True, timeout=2, check=False
        )
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if any(
                    k in line
                    for k in ("VGA compatible controller:", "3D controller:", "Display controller:")
                ):
                    return line.split(":", 2)[-1].strip()
    except Exception:
        pass
    return "Integrated Graphics"


_DRM_CARD = _find_drm_card()
_CORETEMP_HWMON = _find_coretemp_hwmon()
_GPU_NAME = _detect_gpu_name()


def get_fastfetch_profile(force_refresh: bool = False) -> dict[str, Any]:
    """Gather fastfetch-style hardware & OS summary (cached for 5 minutes)."""
    global _cached_fastfetch, _cached_fastfetch_ts
    now = time.monotonic()
    if not force_refresh and _cached_fastfetch is not None and (now - _cached_fastfetch_ts) < 300:
        return _cached_fastfetch

    # Host / Board
    dmi = Path("/sys/devices/virtual/dmi/id")
    vendor = _read_first_line(dmi / "sys_vendor")
    product = _read_first_line(dmi / "product_name")
    bios_ver = _read_first_line(dmi / "bios_version")
    host_model = f"{vendor} {product}".strip() or socket.gethostname()

    # OS & Omarchy
    os_pretty = "Arch Linux"
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("PRETTY_NAME="):
                os_pretty = line.split("=", 1)[1].strip().strip('"')
                break
    except Exception:
        pass

    omarchy_ver = ""
    try:
        res = subprocess.run(
            ["omarchy", "version"], capture_output=True, text=True, timeout=2, check=False
        )
        if res.returncode == 0 and res.stdout.strip():
            omarchy_ver = res.stdout.strip()
    except Exception:
        pass

    # CPU model
    cpu_model = "Unknown CPU"
    cpu_cores = os.cpu_count() or 1
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    except Exception:
        pass

    max_freq_khz = _read_int(
        Path("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"), 0
    )
    cpu_freq_str = f" @ {max_freq_khz / 1_000_000:.2f} GHz" if max_freq_khz else ""

    # GPU model
    gpu_model = _GPU_NAME

    # Display resolution via hyprctl monitors or sysfs modes
    display_str = "Wayland Display"
    try:
        res = subprocess.run(
            ["hyprctl", "monitors", "-j"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            import json
            mons = json.loads(res.stdout)
            if mons:
                parts = []
                for m in mons:
                    w = m.get("width")
                    h = m.get("height")
                    rr = round(float(m.get("refreshRate", 60)))
                    name = m.get("name", "")
                    parts.append(f"{name}: {w}x{h} @ {rr}Hz")
                display_str = ", ".join(parts)
    except Exception:
        pass

    # Package count (count entries in /var/lib/pacman/local without spawning pacman)
    pkg_count = 0
    local_db = Path("/var/lib/pacman/local")
    if local_db.is_dir():
        try:
            pkg_count = sum(1 for p in local_db.iterdir() if p.is_dir())
        except Exception:
            pass

    theme_info = get_theme_info()
    shell_name = Path(os.environ.get("SHELL", "/bin/bash")).name
    terminal_name = _read_first_line(
        Path.home() / ".config/omarchy/defaults/terminal", "Ghostty / Alacritty"
    )

    profile = {
        "user_host": f"{pwd.getpwuid(os.getuid()).pw_name}@{socket.gethostname()}",
        "host_model": host_model,
        "bios": bios_ver,
        "os": f"{os_pretty} (Omarchy {omarchy_ver})" if omarchy_ver else os_pretty,
        "kernel": os.uname().release,
        "wm": "Hyprland (Wayland)",
        "shell": shell_name,
        "terminal": terminal_name,
        "packages": f"{pkg_count} (pacman)",
        "display": display_str,
        "cpu": f"{cpu_model} ({cpu_cores} cores){cpu_freq_str}",
        "gpu": gpu_model,
        "theme": theme_info.get("theme_name", "Omarchy"),
        "font": theme_info.get("font_family", "Monospace"),
    }
    _cached_fastfetch = profile
    _cached_fastfetch_ts = now
    return profile


def _read_cpu_stat() -> dict[str, tuple[int, int]]:
    """Return {cpu_id: (active_jiffies, total_jiffies)} from /proc/stat."""
    out: dict[str, tuple[int, int]] = {}
    try:
        for line in Path("/proc/stat").read_text(encoding="utf-8").splitlines():
            if not line.startswith("cpu"):
                continue
            parts = line.split()
            label = parts[0]
            vals = [int(x) for x in parts[1:]]
            # user, nice, system, idle, iowait, irq, softirq, steal
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
            total = sum(vals[:8])
            active = max(0, total - idle)
            out[label] = (active, total)
    except Exception:
        pass
    return out


def get_live_metrics(sort_by: str = "cpu") -> dict[str, Any]:
    """Compute real-time CPU, GPU, RAM, Network, and Process utilization via /proc & /sys deltas."""
    global _prev_ts, _prev_cpu_times, _prev_proc_ticks, _prev_rc6_ms, _prev_net_bytes

    with _LOCK:
        now = time.monotonic()
        dt_sec = now - _prev_ts if _prev_ts > 0 else 0.0

        # If first call or stale (>10s since last poll), seed baseline and sleep 120ms for accurate instant delta
        if dt_sec <= 0.05 or dt_sec > 10.0:
            _prev_cpu_times = _read_cpu_stat()
            _prev_proc_ticks = _snapshot_proc_ticks()
            _prev_rc6_ms = _read_gpu_rc6_ms()
            _prev_net_bytes = _read_net_dev()
            _prev_ts = time.monotonic()
            time.sleep(0.12)
            now = time.monotonic()
            dt_sec = max(0.05, now - _prev_ts)

        # 1. CPU Utilization (total + per-core)
        cur_cpu = _read_cpu_stat()
        total_cpu_pct = 0.0
        cores: list[dict[str, Any]] = []

        for label, (act, tot) in cur_cpu.items():
            p_act, p_tot = _prev_cpu_times.get(label, (act, tot))
            d_act = max(0, act - p_act)
            d_tot = max(1, tot - p_tot)
            pct = round(min(100.0, (d_act / d_tot) * 100.0), 1)
            if label == "cpu":
                total_cpu_pct = pct
            elif label.startswith("cpu") and label[3:].isdigit():
                idx = int(label[3:])
                freq_khz = _read_int(
                    Path(f"/sys/devices/system/cpu/cpu{idx}/cpufreq/scaling_cur_freq"), 0
                )
                cores.append(
                    {
                        "core": idx,
                        "percent": pct,
                        "mhz": round(freq_khz / 1000) if freq_khz else 0,
                    }
                )
        cores.sort(key=lambda c: c["core"])
        _prev_cpu_times = cur_cpu

        # CPU Temperatures from coretemp
        pkg_temp_c: float | None = None
        core_temps_c: list[float] = []
        if _CORETEMP_HWMON:
            t1 = _read_int(_CORETEMP_HWMON / "temp1_input", -1)
            if t1 > 0:
                pkg_temp_c = round(t1 / 1000.0, 1)
            for idx in range(2, 10):
                t_val = _read_int(_CORETEMP_HWMON / f"temp{idx}_input", -1)
                if t_val > 0:
                    core_temps_c.append(round(t_val / 1000.0, 1))

        for i, c in enumerate(cores):
            c["temp_c"] = core_temps_c[i] if i < len(core_temps_c) else pkg_temp_c

        # 2. GPU Utilization (Intel i915 RC6 residency delta + clocks, or amdgpu gpu_busy_percent)
        gpu_info = _sample_gpu(dt_sec)

        # 3. Memory & Swap breakdown
        mem_info = _sample_memory()

        # 4. Network RX/TX rates
        cur_net = _read_net_dev()
        net_rates: list[dict[str, Any]] = []
        for iface, (rx, tx) in cur_net.items():
            p_rx, p_tx = _prev_net_bytes.get(iface, (rx, tx))
            rx_rate = max(0.0, (rx - p_rx) / dt_sec)
            tx_rate = max(0.0, (tx - p_tx) / dt_sec)
            net_rates.append(
                {
                    "iface": iface,
                    "rx_kib_s": round(rx_rate / 1024.0, 1),
                    "tx_kib_s": round(tx_rate / 1024.0, 1),
                    "rx_human": f"{_human_bytes(rx_rate)}/s",
                    "tx_human": f"{_human_bytes(tx_rate)}/s",
                    "total_rx_human": _human_bytes(rx),
                    "total_tx_human": _human_bytes(tx),
                }
            )
        _prev_net_bytes = cur_net

        # 5. Live Processes (true per-interval CPU% from /proc/[pid]/stat)
        procs, cur_ticks = _sample_processes(
            dt_sec, mem_info["total_bytes"], sort_by=sort_by
        )
        _prev_proc_ticks = cur_ticks
        _prev_ts = now

        load1, load5, load15 = os.getloadavg()

        return {
            "timestamp": time.time(),
            "cpu": {
                "total_percent": total_cpu_pct,
                "package_temp_c": pkg_temp_c,
                "load_avg": [round(load1, 2), round(load5, 2), round(load15, 2)],
                "cores": cores,
            },
            "gpu": gpu_info,
            "memory": mem_info,
            "network": net_rates,
            "processes": procs,
        }


def _read_gpu_rc6_ms() -> int | None:
    if not _DRM_CARD:
        return None
    for rel in ("gt/gt0/rc6_residency_ms", "power/rc6_residency_ms"):
        p = _DRM_CARD / rel
        if p.is_file():
            return _read_int(p, -1)
    return None


def _sample_gpu(dt_sec: float) -> dict[str, Any]:
    global _prev_rc6_ms
    if not _DRM_CARD:
        return {
            "available": False,
            "name": "Integrated Graphics",
            "percent": 0.0,
            "act_mhz": 0,
            "cur_mhz": 0,
            "max_mhz": 0,
        }

    # Check AMD/generic gpu_busy_percent first
    busy_file = _DRM_CARD / "device/gpu_busy_percent"
    act_mhz = _read_int(_DRM_CARD / "gt_act_freq_mhz", 0)
    cur_mhz = _read_int(_DRM_CARD / "gt_cur_freq_mhz", 0)
    max_mhz = _read_int(_DRM_CARD / "gt_max_freq_mhz", 750)

    gpu_pct = 0.0
    if busy_file.is_file():
        gpu_pct = float(_read_int(busy_file, 0))
    else:
        cur_rc6 = _read_gpu_rc6_ms()
        if cur_rc6 is not None and cur_rc6 >= 0:
            if _prev_rc6_ms is not None and cur_rc6 >= _prev_rc6_ms and dt_sec > 0:
                delta_rc6_ms = cur_rc6 - _prev_rc6_ms
                elapsed_ms = dt_sec * 1000.0
                idle_ratio = min(1.0, max(0.0, delta_rc6_ms / elapsed_ms))
                gpu_pct = round((1.0 - idle_ratio) * 100.0, 1)
            _prev_rc6_ms = cur_rc6
        elif max_mhz > 0:
            gpu_pct = round(min(100.0, (act_mhz / max_mhz) * 100.0), 1)

    return {
        "available": True,
        "name": _GPU_NAME,
        "percent": gpu_pct,
        "act_mhz": act_mhz,
        "cur_mhz": cur_mhz,
        "max_mhz": max_mhz,
    }


def _sample_memory() -> dict[str, Any]:
    info: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                parts = v.strip().split()
                if parts and parts[0].isdigit():
                    info[k] = int(parts[0]) * 1024
    except Exception:
        pass

    total = info.get("MemTotal", 0)
    avail = info.get("MemAvailable", 0)
    free = info.get("MemFree", 0)
    cached = info.get("Cached", 0) + info.get("SReclaimable", 0)
    buffers = info.get("Buffers", 0)
    used = max(0, total - avail)
    swap_total = info.get("SwapTotal", 0)
    swap_free = info.get("SwapFree", 0)
    swap_used = max(0, swap_total - swap_free)

    return {
        "total_bytes": total,
        "used_bytes": used,
        "available_bytes": avail,
        "cached_bytes": cached,
        "buffers_bytes": buffers,
        "free_bytes": free,
        "total_human": _human_bytes(total),
        "used_human": _human_bytes(used),
        "available_human": _human_bytes(avail),
        "cached_human": _human_bytes(cached),
        "buffers_human": _human_bytes(buffers),
        "percent": round((used / total) * 100.0, 1) if total else 0.0,
        "swap_total_human": _human_bytes(swap_total),
        "swap_used_human": _human_bytes(swap_used),
        "swap_percent": round((swap_used / swap_total) * 100.0, 1) if swap_total else 0.0,
    }


def _read_net_dev() -> dict[str, tuple[int, int]]:
    out: dict[str, tuple[int, int]] = {}
    try:
        for line in Path("/proc/net/dev").read_text(encoding="utf-8").splitlines()[2:]:
            if ":" not in line:
                continue
            iface, rest = line.split(":", 1)
            iface = iface.strip()
            if iface in ("lo", "docker0"):
                continue
            cols = rest.split()
            if len(cols) >= 9:
                out[iface] = (int(cols[0]), int(cols[8]))
    except Exception:
        pass
    return out


def _snapshot_proc_ticks() -> dict[int, int]:
    ticks: dict[int, int] = {}
    for pid_dir in Path("/proc").iterdir():
        if not pid_dir.name.isdigit():
            continue
        pid = int(pid_dir.name)
        try:
            raw = (pid_dir / "stat").read_text(encoding="utf-8", errors="ignore")
            rparen = raw.rfind(")")
            if rparen < 0:
                continue
            fields = raw[rparen + 2 :].split()
            # fields[11] = utime, fields[12] = stime
            ticks[pid] = int(fields[11]) + int(fields[12])
        except Exception:
            continue
    return ticks


def _sample_processes(
    dt_sec: float, mem_total_bytes: int, sort_by: str = "cpu"
) -> tuple[list[dict[str, Any]], dict[int, int]]:
    cur_ticks: dict[int, int] = {}
    procs: list[dict[str, Any]] = []
    max_ticks_per_core = max(1.0, dt_sec * _CLK_TCK)

    for pid_dir in Path("/proc").iterdir():
        if not pid_dir.name.isdigit():
            continue
        pid = int(pid_dir.name)
        try:
            st = pid_dir.stat()
            raw = (pid_dir / "stat").read_text(encoding="utf-8", errors="ignore")
            lparen = raw.find("(")
            rparen = raw.rfind(")")
            if lparen < 0 or rparen < 0:
                continue
            comm = raw[lparen + 1 : rparen]
            fields = raw[rparen + 2 :].split()
            state = fields[0]
            utime = int(fields[11])
            stime = int(fields[12])
            num_threads = int(fields[17])
            rss_pages = int(fields[21])

            total_ticks = utime + stime
            cur_ticks[pid] = total_ticks
            prev_t = _prev_proc_ticks.get(pid, total_ticks)
            delta_ticks = max(0, total_ticks - prev_t)

            cpu_pct = round((delta_ticks / max_ticks_per_core) * 100.0, 1)
            rss_bytes = max(0, rss_pages * _PAGE_SIZE)
            mem_pct = (
                round((rss_bytes / mem_total_bytes) * 100.0, 1)
                if mem_total_bytes > 0
                else 0.0
            )

            if cpu_pct == 0.0 and rss_bytes == 0:
                continue

            procs.append(
                {
                    "pid": pid,
                    "name": comm,
                    "user": _uid_to_name(st.st_uid),
                    "state": state,
                    "threads": num_threads,
                    "cpu_pct": cpu_pct,
                    "mem_pct": mem_pct,
                    "rss_bytes": rss_bytes,
                    "rss_human": _human_bytes(rss_bytes),
                }
            )
        except Exception:
            continue

    if sort_by == "mem":
        procs.sort(key=lambda p: (p["rss_bytes"], p["cpu_pct"]), reverse=True)
    else:
        procs.sort(key=lambda p: (p["cpu_pct"], p["rss_bytes"]), reverse=True)

    return procs[:25], cur_ticks
