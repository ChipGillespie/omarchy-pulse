"""Dynamic Omarchy theme and font loader with in-memory mtime caching."""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path
from typing import Any

DEFAULT_COLORS: dict[str, str] = {
    "mode": "dark",
    "accent": "#e78a4e",
    "selection": "#4a3828",
    "muted": "#6e5a48",
    "background": "#231a13",
    "dark_background": "#1a130e",
    "darker_background": "#120d09",
    "lighter_background": "#382b1f",
    "foreground": "#e8d5b7",
    "dark_foreground": "#8a7460",
    "light_foreground": "#cdb693",
    "bright_foreground": "#f3e2c5",
    "red": "#d95d43",
    "yellow": "#dfa657",
    "orange": "#e78a4e",
    "green": "#a9b665",
    "cyan": "#8ba98a",
    "blue": "#8fa7b3",
    "magenta": "#c58c94",
    "brown": "#8a5a3c",
    "bright_red": "#e57258",
    "bright_yellow": "#eab86e",
    "bright_green": "#b8c47a",
    "bright_cyan": "#9dbb9c",
    "bright_blue": "#a1b8c4",
    "bright_magenta": "#d4a0a8",
}

_HOME = Path.home()
_COLORS_PATH = _HOME / ".local/state/omarchy/current/theme/colors.toml"
_THEME_NAME_PATH = _HOME / ".local/state/omarchy/current/theme.name"

_cached_mtime: int = -1
_cached_theme: dict[str, Any] | None = None


def get_theme_mtime() -> int:
    """Return nanosecond mtime of colors.toml (single stat syscall, 0 subprocesses)."""
    try:
        return _COLORS_PATH.stat().st_mtime_ns
    except OSError:
        return 0


def _read_theme_name() -> str:
    """Read and title-case theme.name directly without spawning bash/sed."""
    try:
        raw = _THEME_NAME_PATH.read_text(encoding="utf-8").strip()
        if raw:
            return " ".join(part.capitalize() for part in raw.replace("_", "-").split("-"))
    except OSError:
        pass
    return "Omarchy"


def get_theme_info() -> dict[str, Any]:
    """Read current Omarchy theme colors and font settings, cached by file mtime."""
    global _cached_mtime, _cached_theme

    current_mtime = get_theme_mtime()
    if _cached_theme is not None and current_mtime == _cached_mtime:
        return _cached_theme

    colors = dict(DEFAULT_COLORS)
    if _COLORS_PATH.is_file():
        try:
            with _COLORS_PATH.open("rb") as f:
                loaded = tomllib.load(f)
            for k, v in loaded.items():
                if isinstance(v, str):
                    colors[k] = v
        except Exception:
            pass

    theme_name = _read_theme_name()

    font_family = "JetBrainsMono Nerd Font"
    try:
        res = subprocess.run(
            ["fc-match", "monospace", "-f", "%{family}\\n"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            font_family = res.stdout.splitlines()[0].split(",")[0].strip()
    except Exception:
        pass

    _cached_mtime = current_mtime
    _cached_theme = {
        "theme_name": theme_name,
        "font_family": font_family,
        "colors": colors,
        "theme_mtime": current_mtime,
    }
    return _cached_theme
