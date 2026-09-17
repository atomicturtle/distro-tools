#!/usr/bin/env bash
# Install/update sshinn linger user units on db1 (catalog, pgdump, workers, CSAF).
# Run on db1 as sshinn (linger must already be enabled).
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
mkdir -p "$UNIT_DIR" "$HOME/apollo/logs" "$HOME/apollo/backups" "$HOME/apollo/csaf/v2"
chmod 700 "$HOME/apollo/backups"

UNITS=(
  apollo-catalog.service apollo-catalog.timer
  apollo-pgdump.service apollo-pgdump.timer
  apollo-rhworker.service apollo-rpmworker.service
  apollo-csaf-publish.service apollo-csaf-publish.timer
)

for u in "${UNITS[@]}"; do
  if [[ -f "$SRC/$u" ]]; then
    install -m 0644 "$SRC/$u" "$UNIT_DIR/"
  else
    echo "skip missing $u"
  fi
done

chmod 755 "$SRC/start-catalog.sh" "$SRC/pgdump.sh" 2>/dev/null || true
chmod 755 /home/sshinn/apollo/distro-tools/apollo/scripts/publish-csaf-tree.sh 2>/dev/null || true

systemctl --user daemon-reload
if [[ -f "$UNIT_DIR/apollo-csaf-publish.timer" ]]; then
  systemctl --user enable --now apollo-csaf-publish.timer
fi
# Best-effort for other units already managed on the host
systemctl --user enable apollo-rhworker.service apollo-rpmworker.service 2>/dev/null || true
systemctl --user enable --now apollo-catalog.timer apollo-pgdump.timer 2>/dev/null || true

echo "User timers:"
systemctl --user --no-pager list-timers 'apollo-*.timer' || true
