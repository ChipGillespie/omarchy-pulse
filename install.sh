#!/usr/bin/env bash
# Installer for Omarchy Pulse (System Health & Security Audit Dashboard)
set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
PROJECT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"

echo "==> Installing Omarchy Pulse from $PROJECT_DIR..."

chmod +x "$PROJECT_DIR"/bin/*

# 1. Symlink CLI binaries into ~/.local/bin
mkdir -p "$HOME/.local/bin"
ln -sf "$PROJECT_DIR/bin/omarchy-pulse-launch" "$HOME/.local/bin/omarchy-pulse-launch"
ln -sf "$PROJECT_DIR/bin/omarchy-pulse-scan" "$HOME/.local/bin/omarchy-pulse-scan"
ln -sf "$PROJECT_DIR/bin/omarchy-pulse-setup-sudoers" "$HOME/.local/bin/omarchy-pulse-setup-sudoers"

# 2. Install Desktop Entry for Omarchy Apps menu & launcher
mkdir -p "$HOME/.local/share/applications"
cat >"$HOME/.local/share/applications/omarchy-pulse.desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=System Health
GenericName=System Health & Security Audit
Comment=Omarchy Pulse system health, updates, and network security dashboard
Exec=$HOME/.local/bin/omarchy-pulse-launch
Icon=utilities-system-monitor
Terminal=false
Categories=System;Monitor;Security;
Keywords=health;pulse;security;updates;network;clean;audit;omarchy;
StartupNotify=false
EOF

# 3. Add to Omarchy Quickshell Menu (~/.config/omarchy/extensions/omarchy-menu.jsonc)
MENU_EXT="$HOME/.config/omarchy/extensions/omarchy-menu.jsonc"
if [[ -f "$MENU_EXT" ]] && ! grep -q '"system-health"' "$MENU_EXT"; then
  cp "$MENU_EXT" "${MENU_EXT}.bak.$(date +%s)"
  python3 - "$MENU_EXT" "$HOME/.local/bin/omarchy-pulse-launch" <<'PY'
import pathlib, sys
menu_path = pathlib.Path(sys.argv[1])
launch_bin = sys.argv[2]
text = menu_path.read_text(encoding="utf-8")
rbrace = text.rfind("}")
if rbrace != -1:
    entry = f'  "system-health": {{"icon":"󰓦","label":"System Health","aliases":["health","pulse"],"description":"System health, updates, and security audit dashboard","action":"{launch_bin}"}},\n'
    text = text[:rbrace] + entry + text[rbrace:]
    menu_path.write_text(text, encoding="utf-8")
PY
fi

if command -v omarchy >/dev/null 2>&1; then
  omarchy menu refresh >/dev/null 2>&1 || true
fi

# 4. Install and enable weekly systemd --user timer
mkdir -p "$HOME/.config/systemd/user"
cp "$PROJECT_DIR/systemd/omarchy-pulse.service" "$HOME/.config/systemd/user/"
cp "$PROJECT_DIR/systemd/omarchy-pulse.timer" "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now omarchy-pulse.timer

# 5. Optional scoped root helper installation
if [[ "${1:-}" != "--no-sudo" ]]; then
  echo ""
  read -r -p "Install strictly scoped sudoers root helper for deep socket/cache inspection? [Y/n] " ans
  if [[ "${ans:-Y}" =~ ^[Yy]$ ]]; then
    "$PROJECT_DIR/bin/omarchy-pulse-setup-sudoers"
  fi
fi

# 6. Run initial background scan
"$HOME/.local/bin/omarchy-pulse-scan" --quiet || true

echo ""
echo "==> Omarchy Pulse installed!"
echo "    Launch via Omarchy Menu -> System Health, or run: omarchy-pulse-launch"
