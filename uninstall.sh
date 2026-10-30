#!/usr/bin/env bash
# Uninstaller for Omarchy Pulse
set -euo pipefail

echo "==> Uninstalling Omarchy Pulse..."

systemctl --user disable --now omarchy-pulse.timer >/dev/null 2>&1 || true
rm -f "$HOME/.config/systemd/user/omarchy-pulse.service" \
      "$HOME/.config/systemd/user/omarchy-pulse.timer"
systemctl --user daemon-reload >/dev/null 2>&1 || true

rm -f "$HOME/.local/bin/omarchy-pulse-launch" \
      "$HOME/.local/bin/omarchy-pulse-scan" \
      "$HOME/.local/bin/omarchy-pulse-setup-sudoers" \
      "$HOME/.local/share/applications/omarchy-pulse.desktop"

if [[ -f /etc/sudoers.d/omarchy-pulse || -f /usr/local/libexec/omarchy-pulse-helper ]]; then
  read -r -p "Remove root helper (/usr/local/libexec/omarchy-pulse-helper) and /etc/sudoers.d/omarchy-pulse? [y/N] " ans
  if [[ "${ans:-N}" =~ ^[Yy]$ ]]; then
    sudo rm -f /etc/sudoers.d/omarchy-pulse /usr/local/libexec/omarchy-pulse-helper
  fi
fi

echo "==> Uninstalled. State files in ~/.local/state/omarchy-pulse were preserved."
