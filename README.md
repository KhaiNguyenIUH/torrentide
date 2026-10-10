# torrust

A BitTorrent client written from scratch in Rust, with a terminal UI (ratatui) and a plain-text mode. It is both a library crate (`torrust`) and a binary.

## Features

- `.torrent` files and magnet links (metadata fetched from peers, including via the DHT)
- HTTP, HTTPS and UDP trackers
- Kademlia DHT for trackerless peer discovery
- Rarest-first piece selection with endgame mode
- Resume: existing data in the output directory is rechecked against the piece hashes
- Seeds verified pieces to other peers while still downloading
- File skipping and pause from the TUI
- Import half-finished downloads from other clients, including qBittorrent's `.!qB` files

## Build

    cargo build --release

The binary is `target/release/torrust`.

## Usage

    torrust download <file.torrent|magnet:?...> [-o DIR] [--exit-when-done] [--no-tui]
    torrust inspect <file.torrent>
    torrust magnet <uri>            # alias: m
    torrust import <file.torrent> --from DIR [-o DIR] [--mode copy|move|link] [--no-verify] [--start] [--exit-when-done] [--no-tui]

- `download`: `-o/--output` is the save directory (default `.`). `--no-tui` prints progress to stdout. `--exit-when-done` quits on completion; otherwise the finished state stays on screen until you press `q`. The engine stops (and stops seeding) once the download completes.
- `inspect`: prints the parsed torrent without downloading.
- `magnet`: prints what a magnet URI contains.
- `import`: adopts another client's files for the same torrent (stop that client first). It tolerates the `.!qB` suffix and no-subfolder layouts, transfers the files into `-o` by copy, move or hard-link, and verifies them unless `--no-verify`. With `--start` it begins downloading right after.

## Creating torrents

    torrust create <file|dir> [-o out.torrent] [-t URL]... [--web-seed URL]... [--private] \
        [--piece-size KiB] [--comment TEXT] [--source TEXT] [--no-date] [--force] [--seed]

Builds a v1 `.torrent` from a file or directory (files sorted by path, symlinks skipped; a symlink as the top-level input is refused), hashing pieces on all CPU cores. The piece size is chosen automatically (about 1000-2000 pieces) unless `--piece-size` is given. The output defaults to `<name>.torrent` in the current directory and is not overwritten without `--force`. It prints the infohash and a magnet link. `--seed` hands the torrent to the running session (or queues it) with the parent of `<path>` as the download directory, so it seeds at once.

## Session mode

    torrust                      # multi-torrent TUI (starts the background service if needed)
    torrust stop                 # stop the background service
    torrust session --no-tui     # headless, prints a summary every few seconds; Ctrl-C quits
    torrust add <file.torrent|magnet:?...> [-o DIR]
    torrust webui-password       # enable the web UI and set its password from stdin

`torrust` with no subcommand attaches the TUI to a background session, starting one first if none is running (Unix; the service logs to `torrust.log` in the data directory). `q` or Ctrl-C closes the TUI and leaves downloads and the web UI running; `Q` or `torrust stop` stops the session. On Windows the session runs inside the TUI process instead. The session runs many torrents at once behind one listening port and one DHT node. Finished torrents keep seeding until the ratio target (default 2.0; 0 seeds forever) is reached, then stop. The ratio is cumulative across restarts and applies to torrents started after you change it.

- `torrust add` hands a torrent to the running session over a Unix socket (`torrust.sock` in the data directory), starting the background session first if none is running. On Windows it is queued and starts the next time `torrust` runs.
- Dropping `.torrent` files (or pasting a magnet link) onto the TUI adds them straight away; inside the add prompt (`a`) a dropped path fills the field.
- Settings, torrents and their state live in the data directory: `~/Library/Application Support/torrust` on macOS, `$XDG_DATA_HOME/torrust` (or `~/.local/share/torrust`) on Linux, `%APPDATA%\torrust` on Windows. Set `TORRUST_HOME` to use another directory.
- Speed limits (bytes per second, 0 = unlimited) can be set globally and per torrent. Uploads use tit-for-tat choking: 4 unchoke slots plus one optimistic, re-evaluated every 10 s.
- The listen port (default 6881, falling back to a free port if busy) is forwarded through the router with NAT-PMP, then UPnP, when port forwarding is on. Changes to the port, DHT and forwarding settings apply after a restart.
- `scripts/macos` and `scripts/linux` install handlers that open `magnet:` links and `.torrent` files with `torrust add`.

## Encryption and uTP

Session mode prefers encrypted peer connections (Message Stream Encryption) and tries uTP (BEP 29) before TCP, on the same port number over UDP. Both are settings: encryption is `disabled`, `prefer` (default: encrypt when the peer can, otherwise plaintext) or `require` (encrypted peers only). Single-torrent `torrust download` stays plaintext TCP. Changes apply after a restart.

## RSS feeds

Subscribe to RSS or Atom feeds (`http(s)` only) and torrents matching your include/exclude words (case-insensitive, matched against the item title) are added automatically, into the feed's folder if one is set. Feeds are polled every 15 minutes, or on demand with a refresh.

- Items already in the feed when you subscribe are not downloaded; only items that show up later are. The session logs `watching N existing items`.
- Feeds and the items already seen are kept in `feeds.bencode` in the data directory, so a restart never re-adds anything.
- A session also adds an `http(s)` link to a `.torrent` (up to 10 MiB), which is how feed items and the web UI's add box deliver torrents. `torrust add` accepts them too. Links, feeds, redirects and web seeds that resolve to loopback, private (LAN), link-local, CGNAT or other non-public addresses are refused with "address not allowed" unless you turn on "Allow local network URLs" in settings (`allow_local_urls`). Peers learned through peer exchange on those addresses are skipped too, and local peer discovery only accepts announces from your own network.

## Block list, schedule and notifications

- **Block list**: set `blocklist` in the settings to a text file of IP ranges (PeerGuardian `name:1.2.3.4-1.2.3.9`, eMule `1.2.3.4 - 1.2.3.9 , 100 , name` or `a-b` lines, IPv4 and IPv6; `#` comments; gzip not supported). Inbound connections from listed addresses are dropped before the handshake. Torrents already running use the new list after they restart. Load results and skipped lines show in the log; a missing file is logged as an error and no list is applied.
- **Schedule**: a 7x24 grid of slots, `normal`, `limited` (uses the schedule's own down/up limits), `seedonly` (downloads pause, seeding continues) and `off` (every torrent stops). Rules read `<days> <HH-HH> <slot>`, for example `weekdays 09-18 limited`, `sat,sun 00-24 normal`, `mon-fri 22-06 off` (end hour exclusive, a start after the end runs past midnight). Days are `mon`..`sun`, ranges such as `fri-mon`, lists, `weekdays`, `weekend` or `all`. Times use the UTC offset stored with the schedule, filled from the system on first start. Only torrents the schedule paused or stopped are resumed or restarted when the slot ends; ones you paused or stopped stay as they are. Slot changes are logged.
- **Notifications**: when a torrent finishes downloading, a desktop notification is shown (`osascript` on macOS, `notify-send` on Linux if installed, nothing on Windows). Turn off with `notifications` in the settings. Torrents that were already complete when the session started do not notify.
- **Super-seeding**: for a torrent you are the first seeder of, `SetSuperSeed` makes the engine reveal pieces one peer at a time so each uploaded piece spreads before the next is offered. The setting is kept per torrent across restarts.
- **Adding trackers**: `AddTracker` and `RemoveTracker` change a torrent's tracker list while it runs; the changed list is saved and replaces the one from the .torrent on restart. Stopped torrents ignore the command.
- **Peer flags**: `E` encrypted, `P` uTP, `I` incoming, `X` found via PEX, `L` local discovery, `H` DHT, `F` fast extension, `W` web seed.

## Web UI

A small browser interface for the session, off by default. It never shows or accepts local paths or folders.

- Without a password it listens on `127.0.0.1` only and needs an access token: the session creates a random 128-bit token (kept in `webui.token` in the data directory, readable by you alone), logs the one-time URL `http://127.0.0.1:PORT/?token=...` and prints it when `torrust session` starts. Opening that URL stores the token in an HttpOnly cookie and redirects to `/`. Scripts can send `Authorization: Bearer <token>` instead. With a password it still listens on `127.0.0.1` only, and asks for the password (HTTP Basic, any user name) on every request; the `Host` header must be an IP address or `localhost`, which blocks DNS rebinding. The settings screen has "Web UI on LAN (needs password)" (`webui_lan`): only with that on and a password set does it listen on all interfaces, and the session then logs a warning, because the connection is plain HTTP. After five wrong passwords from one address it answers 429 for a growing time (up to 15 minutes). To reach it from another machine prefer an SSH tunnel over LAN mode: `ssh -L 8080:127.0.0.1:8080 host`, then open `http://127.0.0.1:8080/` locally. Use a reverse proxy with TLS if you must expose it beyond that.
- Besides links and magnets it takes a `.torrent` file from the "Choose .torrent" button or dropped anywhere on the page (up to 10 MiB, `POST /api/upload` with the raw bytes).
- The optional folder box picks where an add, upload or drop is saved. A plain name such as `Movies/2024` is a subfolder of the download folder (created if missing). A full path is accepted only inside the download folder or inside one of the "Web UI extra save folders" set in the TUI settings (`webui_save_roots`, `;` separated, e.g. `/Volumes/Media`), so the browser can reach another drive but never an arbitrary place. `..`, backslashes and links that point out of an allowed folder are refused, and a refused folder is never created.
- Enable it and set the password without putting the password in shell history:

      torrust webui-password        # type the password and press Enter
      torrust session --no-tui      # daemon mode: runs headless, serves the web UI, Ctrl-C quits

  The password is stored only as a salted, iterated SHA-1 hash (`torrust-sha1$100000$salt$hash`) in `settings.bencode`, which is readable by you alone. The default port is 8080 (`webui.port` in the settings). The session logs the URL it listens on. `webui-password` refuses to run while a session is running, since the session writes its own settings when it quits.
- Settings, feeds and web UI changes made while the session runs are saved at once and take effect after a restart.

## TUI keys

| Key | Action |
| --- | --- |
| `q`, `Esc`, `Ctrl-C` | quit |
| `Tab` | switch focus between peers and files |
| `j`/`Down`, `k`/`Up` | move selection |
| `Space` | skip or re-want the selected file (files pane) |
| `p` | pause / resume |
| `PgUp`/`PgDn`, `Home`/`End` | scroll the log |
| `?` | toggle help |
| `r` | redraw |

## Logging

Logging uses `tracing`; set the level with `RUST_LOG` (default `torrust=info,warn`), e.g. `RUST_LOG=torrust=debug`. In TUI mode, logs are written to `torrust.log` in the data directory (owner-only, mode 0600; a symlink there is refused) so they do not corrupt the display; with `--no-tui` they go to stderr.

## Testing

    cargo test

`tests/download.rs` runs the real engine against a local seeder and a mock HTTP tracker; it does not need network access.

## Modules

- `bencode`: bencode encoding and decoding
- `metainfo`: `.torrent` parsing, infohash, magnet URIs
- `storage`: maps the payload onto files; SHA-1 piece checks
- `peer`: wire protocol (`wire`), per-peer connections (`connection`), peer pool and listener (`pool`)
- `tracker`: HTTP/HTTPS/UDP announces
- `dht`: Kademlia DHT and metadata exchange
- `scheduler`: rarest-first piece selection, endgame
- `engine`: orchestration of the above
- `state`: snapshots and commands shared with the UI
- `tui`: terminal interface
- `import`: adopting other clients' partial downloads
