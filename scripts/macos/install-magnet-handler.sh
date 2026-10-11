#!/usr/bin/env bash
set -euo pipefail

bin="$(command -v torrentide || true)"
if [ -z "$bin" ]; then
  echo "torrentide not found on PATH; run 'cargo install --path .' first." >&2
  exit 1
fi

app="$HOME/Applications/Torrentide Magnet Handler.app"
plist="$app/Contents/Info.plist"
src="$(mktemp -t torrentide-handler).applescript"
trap 'rm -f "$src"' EXIT

bin_q="${bin//\\/\\\\}"
bin_q="${bin_q//\"/\\\"}"

cat >"$src" <<APPLESCRIPT
property torrentideBin : "$bin_q"

on run
	display dialog "Torrentide Magnet Handler opens magnet: links and .torrent files with torrentide." buttons {"OK"} default button "OK"
end run

on addSource(theSource)
	try
		do shell script (quoted form of torrentideBin) & " add " & quoted form of theSource
	on error errMsg
		display notification errMsg with title "torrentide"
	end try
end addSource

on open location theURL
	addSource(theURL)
end open location

on open theFiles
	repeat with f in theFiles
		addSource(POSIX path of f)
	end repeat
end open
APPLESCRIPT

mkdir -p "$HOME/Applications"
rm -rf "$app"
osacompile -o "$app" "$src"

pb=/usr/libexec/PlistBuddy
"$pb" -c "Delete :CFBundleIdentifier" "$plist" 2>/dev/null || true
"$pb" -c "Add :CFBundleIdentifier string org.torrentide.MagnetHandler" "$plist"
"$pb" -c "Delete :LSUIElement" "$plist" 2>/dev/null || true
"$pb" -c "Add :LSUIElement bool true" "$plist"
"$pb" -c "Delete :CFBundleURLTypes" "$plist" 2>/dev/null || true
"$pb" -c "Add :CFBundleURLTypes array" "$plist"
"$pb" -c "Add :CFBundleURLTypes:0 dict" "$plist"
"$pb" -c "Add :CFBundleURLTypes:0:CFBundleURLName string BitTorrent magnet link" "$plist"
"$pb" -c "Add :CFBundleURLTypes:0:CFBundleURLSchemes array" "$plist"
"$pb" -c "Add :CFBundleURLTypes:0:CFBundleURLSchemes:0 string magnet" "$plist"
"$pb" -c "Delete :CFBundleDocumentTypes" "$plist" 2>/dev/null || true
"$pb" -c "Add :CFBundleDocumentTypes array" "$plist"
"$pb" -c "Add :CFBundleDocumentTypes:0 dict" "$plist"
"$pb" -c "Add :CFBundleDocumentTypes:0:CFBundleTypeName string BitTorrent file" "$plist"
"$pb" -c "Add :CFBundleDocumentTypes:0:CFBundleTypeRole string Viewer" "$plist"
"$pb" -c "Add :CFBundleDocumentTypes:0:CFBundleTypeExtensions array" "$plist"
"$pb" -c "Add :CFBundleDocumentTypes:0:CFBundleTypeExtensions:0 string torrent" "$plist"
"$pb" -c "Add :CFBundleDocumentTypes:0:CFBundleTypeMIMETypes array" "$plist"
"$pb" -c "Add :CFBundleDocumentTypes:0:CFBundleTypeMIMETypes:0 string application/x-bittorrent" "$plist"

codesign --force --sign - "$app" >/dev/null 2>&1 || true
lsregister=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
"$lsregister" -f "$app"

echo "Installed $app (torrentide: $bin)"
echo "To make it the default: open a magnet: link once and pick 'Torrentide Magnet Handler' when asked,"
echo "or right-click a .torrent file > Get Info > Open with > Torrentide Magnet Handler > Change All."
