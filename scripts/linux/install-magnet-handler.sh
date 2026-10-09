#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
apps="${XDG_DATA_HOME:-$HOME/.local/share}/applications"

mkdir -p "$apps"
cp "$here/torrust.desktop" "$apps/torrust.desktop"

xdg-mime default torrust.desktop x-scheme-handler/magnet application/x-bittorrent
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$apps"
fi

echo "Installed $apps/torrust.desktop (magnet: links and .torrent files now open with 'torrust add')."
command -v torrust >/dev/null 2>&1 || echo "Warning: 'torrust' is not on PATH; the handler will fail until it is." >&2
