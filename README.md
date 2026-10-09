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

Logging uses `tracing`; set the level with `RUST_LOG` (default `torrust=info,warn`), e.g. `RUST_LOG=torrust=debug`. In TUI mode, logs are written to `torrust.log` in the system temp directory so they do not corrupt the display; with `--no-tui` they go to stderr.

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
