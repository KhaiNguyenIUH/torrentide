#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
apps="${XDG_DATA_HOME:-$HOME/.local/share}/applications"

mkdir -p "$apps"
cp "$here/torrentide.desktop" "$apps/torrentide.desktop"

xdg-mime default torrentide.desktop x-scheme-handler/magnet application/x-bittorrent
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$apps"
fi

echo "Installed $apps/torrentide.desktop (magnet: links and .torrent files now open with 'torrentide add')."
command -v torrentide >/dev/null 2>&1 || echo "Warning: 'torrentide' is not on PATH; the handler will fail until it is." >&2
