"""Action handlers for Omarchy Pulse interactive maintenance and baseline updates."""

from __future__ import annotations

import datetime as dt
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .scanner import (
    HELPER_BIN,
    REPORT_FILE,
    _run,
    helper_available,
    load_baseline,
    run_clamav_scan,
    run_full_scan,
    save_baseline,
    save_fim_baseline,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _launch_floating_terminal(command_str: str) -> None:
    """Launch an interactive command in Omarchy's floating presentation terminal."""
    subprocess.Popen(
        ["omarchy-launch-floating-terminal-with-presentation", command_str],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def handle_action(action: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Execute a requested dashboard action and return updated status/report."""
    baseline = load_baseline()

    if action == "install-updates":
        # Clear any deferral before launching omarchy-update
        baseline["deferred_updates"] = {
            "until_epoch": 0,
            "reason": "",
            "deferred_at": "",
            "omarchy_target": "",
            "package_count": 0,
        }
        save_baseline(baseline)
        rescan_cmd = f"omarchy-update; {PROJECT_ROOT}/bin/omarchy-pulse-scan --quiet"
        _launch_floating_terminal(rescan_cmd)
        return {
            "ok": True,
            "message": "Launched Omarchy Update in a floating terminal.",
            "report": run_full_scan(),
        }

    if action == "defer-updates":
        duration_key = str(payload.get("duration", "7d"))
        hours_map = {"24h": 24, "7d": 168, "14d": 336}
        hours = hours_map.get(duration_key, 168)
        until_epoch = int(time.time() + hours * 3600)
        omarchy_target = str(payload.get("omarchy_target", ""))
        pkg_count = int(payload.get("package_count", 0) or 0)

        baseline["deferred_updates"] = {
            "until_epoch": until_epoch,
            "reason": f"Deferred for {duration_key}",
            "deferred_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
            "omarchy_target": omarchy_target,
            "package_count": pkg_count,
        }
        save_baseline(baseline)
        # Clear the Omarchy top-bar update badge while deferred
        _run(["omarchy-shell", "-q", "omarchy.system-update", "clear"], timeout=3)
        return {
            "ok": True,
            "message": f"Updates deferred for {duration_key}.",
            "report": run_full_scan(),
        }

    if action == "undefer-updates":
        baseline["deferred_updates"] = {
            "until_epoch": 0,
            "reason": "",
            "deferred_at": "",
            "omarchy_target": "",
            "package_count": 0,
        }
        save_baseline(baseline)
        _run(["omarchy-update-status"], timeout=10)
        return {
            "ok": True,
            "message": "Update deferral cleared.",
            "report": run_full_scan(),
        }

    if action == "approve-listener":
        sig = str(payload.get("signature", "")).strip()
        if sig:
            approved = list(baseline.get("approved_listeners", []))
            if sig not in approved:
                approved.append(sig)
                baseline["approved_listeners"] = approved
                save_baseline(baseline)
        return {
            "ok": True,
            "message": f"Added listener '{sig}' to trusted baseline.",
            "report": run_full_scan(),
        }

    if action == "unapprove-listener":
        sig = str(payload.get("signature", "")).strip()
        approved = [x for x in baseline.get("approved_listeners", []) if x != sig]
        baseline["approved_listeners"] = approved
        save_baseline(baseline)
        return {
            "ok": True,
            "message": f"Removed listener '{sig}' from baseline.",
            "report": run_full_scan(),
        }

    if action == "mute-unit":
        unit = str(payload.get("unit", "")).strip()
        if unit:
            muted = list(baseline.get("muted_units", []))
            if unit not in muted:
                muted.append(unit)
                baseline["muted_units"] = muted
                save_baseline(baseline)
        return {
            "ok": True,
            "message": f"Muted systemd unit '{unit}'.",
            "report": run_full_scan(),
        }

    if action == "unmute-unit":
        unit = str(payload.get("unit", "")).strip()
        muted = [u for u in baseline.get("muted_units", []) if u != unit]
        baseline["muted_units"] = muted
        save_baseline(baseline)
        return {
            "ok": True,
            "message": f"Unmuted systemd unit '{unit}'.",
            "report": run_full_scan(),
        }

    if action == "approve-services-baseline":
        # Re-read current enabled services and approve all
        enabled: list[str] = []
        for scope, cmd in [
            ("system", ["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend"]),
            ("user", ["systemctl", "--user", "list-unit-files", "--type=service", "--state=enabled", "--no-legend"]),
        ]:
            rc, out, _ = _run(cmd, timeout=5)
            if rc == 0 and out.strip():
                for line in out.splitlines():
                    parts = line.split()
                    if parts:
                        enabled.append(f"{scope}:{parts[0]}")
        baseline["approved_enabled_services"] = sorted(set(enabled))
        save_baseline(baseline)
        return {
            "ok": True,
            "message": "Approved current enabled services as baseline.",
            "report": run_full_scan(),
        }

    if action == "clean-paccache":
        if helper_available():
            rc, out, err = _run(
                ["sudo", "-n", str(HELPER_BIN), "clean-paccache"], timeout=30
            )
            if rc != 0:
                return {"ok": False, "message": f"Pacman cache cleanup failed: {err or out}"}
            return {
                "ok": True,
                "message": "Cleaned old Pacman package cache (kept last 2 versions).",
                "report": run_full_scan(),
            }
        _launch_floating_terminal("sudo paccache -rk2 && sudo paccache -ruk0")
        return {
            "ok": True,
            "message": "Opened terminal to clean Pacman cache.",
            "report": run_full_scan(),
        }

    if action == "vacuum-journal":
        if helper_available():
            rc, out, err = _run(
                ["sudo", "-n", str(HELPER_BIN), "vacuum-journal"], timeout=20
            )
            if rc != 0:
                return {"ok": False, "message": f"Journal vacuum failed: {err or out}"}
            return {
                "ok": True,
                "message": "Vacuumed systemd journal logs older than 14 days.",
                "report": run_full_scan(),
            }
        _launch_floating_terminal("sudo journalctl --vacuum-time=14d")
        return {
            "ok": True,
            "message": "Opened terminal to vacuum systemd journal.",
            "report": run_full_scan(),
        }

    if action == "clean-aur-cache":
        for cache_sub in (".cache/yay", ".cache/paru"):
            c_dir = Path.home() / cache_sub
            if c_dir.is_dir():
                for child in c_dir.iterdir():
                    try:
                        if child.is_dir():
                            shutil.rmtree(child)
                        else:
                            child.unlink()
                    except Exception:
                        pass
        return {
            "ok": True,
            "message": "Cleared ~/.cache/yay and ~/.cache/paru build caches.",
            "report": run_full_scan(),
        }

    if action == "clean-safe-user-cache":
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
            "yay",
            "paru",
        }
        cache_root = Path.home() / ".cache"
        cleaned_count = 0
        if cache_root.is_dir():
            for name in safe_cache_names:
                target_dir = cache_root / name
                if target_dir.is_dir() and not target_dir.is_symlink():
                    try:
                        shutil.rmtree(target_dir)
                        cleaned_count += 1
                    except Exception:
                        pass
        return {
            "ok": True,
            "message": f"Cleaned {cleaned_count} safe build, shader, and thumbnail cache directory(s).",
            "report": run_full_scan(),
        }

    if action == "empty-trash":
        trash_dir = Path.home() / ".local/share/Trash"
        if trash_dir.is_dir():
            for sub in ("files", "info", "expunged"):
                sub_p = trash_dir / sub
                if sub_p.is_dir():
                    for item in sub_p.iterdir():
                        try:
                            if item.is_dir() and not item.is_symlink():
                                shutil.rmtree(item)
                            else:
                                item.unlink()
                        except Exception:
                            pass
        return {
            "ok": True,
            "message": "Emptied ~/.local/share/Trash.",
            "report": run_full_scan(),
        }

    if action == "clean-coredumps":
        if helper_available():
            rc, out, err = _run(
                ["sudo", "-n", str(HELPER_BIN), "clean-coredumps"], timeout=15
            )
            if rc == 0:
                return {
                    "ok": True,
                    "message": "Cleared old systemd core dumps (/var/lib/systemd/coredump).",
                    "report": run_full_scan(),
                }
        _launch_floating_terminal("sudo rm -vf /var/lib/systemd/coredump/core.*")
        return {
            "ok": True,
            "message": "Opened terminal to clear systemd core dumps.",
            "report": run_full_scan(),
        }

    if action == "approve-fim-baseline":
        saved = save_fim_baseline()
        count = len(saved.get("files", {}))
        return {
            "ok": True,
            "message": f"Updated SHA-256 FIM baseline ({count} critical files hashed).",
            "report": run_full_scan(),
        }

    if action == "run-clamav-scan":
        clam_res = run_clamav_scan()
        if not clam_res.get("ok"):
            return {
                "ok": False,
                "message": clam_res.get("message", "ClamAV scan failed."),
                "report": run_full_scan(),
            }
        scan_info = clam_res["scan"]
        inf = scan_info.get("infected_count", 0)
        msg = (
            f"ClamAV scan clean: 0 threats found in {scan_info['duration_sec']}s."
            if inf == 0
            else f"WARNING: ClamAV detected {inf} infected file(s)!"
        )
        return {
            "ok": True,
            "message": msg,
            "report": run_full_scan(),
        }

    if action == "update-clamav-db":
        if not shutil.which("freshclam"):
            return {
                "ok": False,
                "message": "ClamAV (freshclam) is not installed.",
                "report": run_full_scan(),
            }
        if helper_available():
            rc, out, err = _run(
                ["sudo", "-n", str(HELPER_BIN), "freshclam-update"], timeout=120
            )
            if rc == 0:
                combined = f"{out}\n{err}".lower()
                if "updated (" in combined or "downloaded" in combined:
                    msg = "Updated ClamAV virus signature database (freshclam)."
                else:
                    msg = "ClamAV virus signature database is already up to date."
                return {
                    "ok": True,
                    "message": msg,
                    "report": run_full_scan(),
                }
            err_lower = f"{err}\n{out}".lower()
            if "password is required" not in err_lower and "not allowed" not in err_lower:
                detail = (err or out or "unknown error").strip().splitlines()[-1]
                return {
                    "ok": False,
                    "message": f"ClamAV DB update failed: {detail}",
                    "report": run_full_scan(),
                }
        _launch_floating_terminal(
            f"sudo freshclam; {PROJECT_ROOT}/bin/omarchy-pulse-scan --quiet"
        )
        return {
            "ok": True,
            "message": "Launched freshclam signature update in floating terminal.",
            "report": run_full_scan(),
        }

    if action == "remove-orphans":
        _launch_floating_terminal("omarchy-update-orphan-pkgs")
        return {
            "ok": True,
            "message": "Launched orphan package removal in floating terminal.",
            "report": run_full_scan(),
        }

    if action == "install-sudoers":
        setup_script = PROJECT_ROOT / "bin/omarchy-pulse-setup-sudoers"
        _launch_floating_terminal(str(setup_script))
        return {
            "ok": True,
            "message": "Launched sudoers helper installer in floating terminal.",
        }

    return {"ok": False, "message": f"Unknown action: {action}"}
