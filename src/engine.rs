//! The download engine: owns the scheduler, peer pool, and storage, and wires
//! them together.
//!
//! Control flow for a local `.torrent`:
//!   1. parse metainfo and prepare the download directory
//!   2. recheck any data already on disk so a restart resumes instead of
//!      restarting
//!   3. announce to trackers, dial peers, request blocks, verify pieces
//!
//! For a magnet link the only difference is step 1: we begin with just an
//! infohash and must fetch the metadata itself before anything else can happen.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::sync::{mpsc, RwLock};

use crate::metainfo::{Magnet, Metainfo, SocketAddrLite};
use crate::peer::connection::{FromPeer, BLOCK_SIZE};
use crate::peer::pool::PeerPool;
use crate::scheduler::{BlockRequest, Scheduler};
use crate::state::{Command, DownloadState, FileSummary, Level, PeerSummary, TorrentSummary, UiState};
use crate::storage::Storage;
use crate::tracker;

/// Port we advertise to peers and announce to trackers.
pub const LOCAL_PORT: u16 = 6881;

/// How often we ask the peer pool to fill the request pipeline.
const PIPELINE_INTERVAL: Duration = Duration::from_millis(250);

/// How often to prune dead peers.
const REAP_INTERVAL: Duration = Duration::from_secs(15);

/// How often to compute the speed/ETA figures for the TUI.
const STATS_INTERVAL: Duration = Duration::from_millis(500);

/// Minimum gap between DHT peer lookups; each one fans out many UDP queries.
const DHT_LOOKUP_INTERVAL: Duration = Duration::from_secs(60);

/// Cap on outstanding requests across all peers. Each in-flight block holds up
/// to 16 KiB in memory, so this bounds our worst-case buffering.
const MAX_IN_FLIGHT: usize = 200;

pub struct Engine {
    pub meta: Arc<Metainfo>,
    pub state: Arc<RwLock<UiState>>,
    commands: mpsc::UnboundedReceiver<Command>,
}

impl Engine {
    /// The `state` snapshot is shared with the TUI: the engine writes progress
    /// here and the UI reads it. It must be the *same* `Arc`, not a copy —
    /// a private state object would leave the TUI frozen on its placeholder.
    ///
    /// `commands` carries [`Command`]s from the TUI (pause, file selection).
    /// The engine drains it once per tick; the TUI never blocks on it.
    pub fn new(
        meta: Arc<Metainfo>,
        state: Arc<RwLock<UiState>>,
        commands: mpsc::UnboundedReceiver<Command>,
    ) -> Self {
        Engine {
            meta,
            state,
            commands,
        }
    }

    /// Run until the download completes or `shutdown` is triggered.
    pub async fn run(mut self, download_dir: PathBuf) -> Result<()> {
        let storage = Arc::new(
            Storage::prepare(&self.meta, &download_dir)
                .context("preparing download directory")?,
        );
        let mut scheduler = Scheduler::new(&self.meta);

        self.log(Level::Info, format!("preparing {}", download_dir.display()))
            .await;

        // Resume support: verify what is already on disk so we neither
        // re-download finished pieces nor trust unverified bytes.
        let verified = self.recheck_existing(&storage, &mut scheduler).await;
        self.log(
            Level::Info,
            format!(
                "rechecked {verified}/{} pieces already on disk",
                self.meta.piece_count()
            ),
        )
        .await;

        let summary = TorrentSummary {
            name: self.meta.name.clone(),
            infohash: self.meta.infohash.to_hex(),
            total_length: self.meta.total_length,
            downloaded: scheduler.block_map().bytes_downloaded(&self.meta),
            piece_length: self.meta.piece_length,
            piece_count: self.meta.piece_count() as u32,
            verified_pieces: scheduler.block_map().verified_count(),
            progress: scheduler.progress(),
            state: DownloadState::Downloading,
            download_dir: download_dir.display().to_string(),
            trackers: self.meta.announce_list.clone(),
            files: file_summaries(
                &self.meta,
                &scheduler,
                &vec![true; self.meta.files.iter().count()],
            ),
            ..Default::default()
        };
        self.state.write().await.torrent = Some(summary);

        // Peer events land in one channel; a single task turns them into
        // scheduler and storage updates so there is a single writer.
        let (peer_tx, mut peer_rx) = mpsc::unbounded_channel::<(SocketAddr, FromPeer)>();

        // Keep a sender for inbound peers: the listener has its own channel,
        // and its events are forwarded into the one the engine loop reads.
        let inbound_forward = peer_tx.clone();

        // If we already hold verified data (a resume, or a finished download),
        // we can serve it. Share the one Storage with the upload path.
        let seeder = build_seeder(
            Arc::clone(&storage),
            &self.meta,
            &scheduler.block_map().verified_pieces(),
        );
        let can_seed = seeder.is_some();

        let mut pool = PeerPool::new(
            Arc::clone(&self.meta),
            seeder,
            LOCAL_PORT,
            peer_tx,
            crate::ratelimit::Limits::default(),
            crate::peer::pool::MAX_PEERS,
            true,
        );

        if can_seed {
            let (listen_tx, mut listen_rx) =
                mpsc::unbounded_channel::<(SocketAddr, FromPeer)>();
            tokio::spawn(async move {
                while let Some(ev) = listen_rx.recv().await {
                    if inbound_forward.send(ev).is_err() {
                        break;
                    }
                }
            });

            match crate::peer::pool::listen(
                Arc::clone(&self.meta),
                pool.seeder().cloned(),
                LOCAL_PORT,
                listen_tx,
            )
            .await
            {
                Ok((addr, _handle)) => {
                    self.log(
                        Level::Info,
                        format!("seeding: listening on {addr} for inbound peers"),
                    )
                    .await;
                }
                Err(e) => {
                    self.log(
                        Level::Warn,
                        format!("could not listen for inbound peers: {e}"),
                    )
                    .await;
                }
            }
        }

        // Announces run in their own task so slow trackers (timeouts of tens
        // of seconds) never stall the loop; results come back on this channel.
        let (announce_tx, mut announce_rx) =
            mpsc::unbounded_channel::<(Vec<SocketAddrLite>, Vec<String>)>();
        let mut announce_in_flight = false;

        // BEP 27: private torrents must never touch the DHT.
        let (dht_tx, mut dht_rx) = if self.meta.private {
            (None, None)
        } else {
            let (tx, rx) = spawn_dht_lookups(self.meta.infohash);
            (Some(tx), Some(rx))
        };
        let mut dht_in_flight = false;
        let mut last_dht_lookup: Option<Instant> = None;

        let mut last_announce = Instant::now() - Duration::from_secs(3600);
        let announce_interval = Duration::from_secs(1800);
        // Set when we are starved of peers, to re-announce on the next tick
        // instead of waiting out the full interval.
        let mut force_announce = true;
        let mut last_reap = Instant::now();
        let mut last_stats = Instant::now();
        let mut last_fill = Instant::now() - PIPELINE_INTERVAL;
        let mut last_down: u64 = 0;
        let mut last_up: u64 = 0;
        let mut upload_rate = 0.0f64;
        let mut last_rate_sample = Instant::now();
        let mut current_rate = 0.0f64;

        // TUI-controllable state. `wanted[i]` mirrors the file list; every
        // file starts wanted and the user can skip any subset (but not all —
        // toggling the last wanted file off is refused).
        let mut paused = false;
        let mut wanted = vec![true; self.meta.files.iter().count()];

        let mut ticker = tokio::time::interval(Duration::from_millis(50));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                // Inbound peer messages get priority over periodic work.
                biased;

                Some((addr, ev)) = peer_rx.recv() => {
                    handle_peer_event(&mut scheduler, &storage, &self.meta, &ev);
                    pool.on_event(addr, ev).await;
                }

                Some((peers, errors)) = announce_rx.recv() => {
                    announce_in_flight = false;
                    if errors.is_empty() {
                        self.state.write().await.warning = None;
                    } else {
                        let msg = errors.join("; ");
                        self.log(Level::Warn, format!("tracker: {msg}")).await;
                        self.state.write().await.warning = Some(msg);
                    }
                    if !peers.is_empty() {
                        let fresh = pool.discover(&peers);
                        if !fresh.is_empty() {
                            pool.dial(&fresh);
                        }
                    }
                }

                Some(addrs) = async {
                    match dht_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    dht_in_flight = false;
                    if !addrs.is_empty() {
                        self.log(Level::Info, format!("DHT returned {} peers", addrs.len())).await;
                        let lite: Vec<SocketAddrLite> = addrs
                            .iter()
                            .map(|a| SocketAddrLite { ip: a.ip(), port: a.port() })
                            .collect();
                        let fresh = pool.discover(&lite);
                        if !fresh.is_empty() {
                            pool.dial(&fresh);
                        }
                    }
                }

                _ = ticker.tick() => {
                    // ---- commands from the TUI (pause, file selection) ----
                    while let Ok(cmd) = self.commands.try_recv() {
                        match cmd {
                            Command::Pause => {
                                if !paused {
                                    paused = true;
                                    self.log(Level::Info, "paused — press p to resume").await;
                                }
                            }
                            Command::Resume => {
                                if paused {
                                    paused = false;
                                    self.log(Level::Info, "resumed").await;
                                }
                            }
                            Command::Stop => {
                                if let Some(t) = &mut self.state.write().await.torrent {
                                    t.state = DownloadState::Stopped;
                                    t.download_rate = 0.0;
                                    t.upload_rate = 0.0;
                                }
                                self.log(Level::Info, "stopped").await;
                                return Ok(());
                            }
                            Command::ToggleFile(i) => {
                                apply_file_toggle(
                                    &self.meta,
                                    &mut wanted,
                                    &mut scheduler,
                                    &self.state,
                                    i,
                                )
                                .await;
                            }
                        }
                    }

                    // ---- periodically refill the request pipeline ----
                    // A pause stops new requests. Blocks already on the wire
                    // still land and verify, so resuming never loses data.
                    if !paused && last_fill.elapsed() >= PIPELINE_INTERVAL {
                        last_fill = Instant::now();
                        let mut rarity: HashMap<u32, u32> = HashMap::new();
                        for p in 0..self.meta.piece_count() as u32 {
                            rarity.insert(p, pool.seeders_for(p));
                        }

                        let budget = MAX_IN_FLIGHT.saturating_sub(scheduler.in_flight_count());
                        let batch = scheduler.fill_batch(&rarity, budget);
                        for req in batch {
                            if !pool.request_block(req.piece, req.begin, req.length).await {
                                // Nobody could take it; make it available again.
                                scheduler.on_timeout(req.key());
                            }
                        }
                    }

                    // ---- announce to trackers periodically ----
                    if !announce_in_flight
                        && (force_announce || last_announce.elapsed() >= announce_interval)
                    {
                        force_announce = false;
                        announce_in_flight = true;
                        last_announce = Instant::now();
                        let meta = Arc::clone(&self.meta);
                        let uploaded = pool.total_uploaded().await;
                        let downloaded = scheduler.block_map().bytes_downloaded(&meta);
                        let left = meta.total_length.saturating_sub(downloaded);
                        let tx = announce_tx.clone();
                        tokio::spawn(async move {
                            let res = tracker::announce_all(
                                &meta.announce_list,
                                &meta,
                                LOCAL_PORT,
                                uploaded,
                                downloaded,
                                left,
                            )
                            .await;
                            let _ = tx.send(res);
                        });
                    }

                    // ---- DHT peer lookup ----
                    // Trackerless torrents rely on it; otherwise it tops up a
                    // thin swarm. At most one lookup in flight, once a minute.
                    if let Some(tx) = &dht_tx {
                        let starved = self.meta.announce_list.is_empty()
                            || pool.connected() < crate::peer::MIN_PEERS;
                        let due = last_dht_lookup.map_or(true, |t| t.elapsed() >= DHT_LOOKUP_INTERVAL);
                        if starved && due && !dht_in_flight && tx.send(()).is_ok() {
                            dht_in_flight = true;
                            last_dht_lookup = Some(Instant::now());
                        }
                    }

                    // ---- prune dead peers ----
                    if last_reap.elapsed() >= REAP_INTERVAL {
                        last_reap = Instant::now();
                        let n = pool.reap().await;
                        if n > 0 {
                            self.log(Level::Debug, format!("reaped {n} dead peers")).await;
                        }
                        if pool.connected() < crate::peer::MIN_PEERS && !self.meta.announce_list.is_empty() {
                            // Re-announce promptly while we are still short of
                            // peers. The previous arithmetic here set the
                            // elapsed time to `interval - 5s`, which is short
                            // of the trigger and so never fired.
                            force_announce = true;
                        }
                    }

                    // ---- verify any fully-downloaded pieces ----
                    let ready = scheduler.ready_pieces();
                    if !ready.is_empty() {
                        let mut confirmed = 0u32;
                        let mut corrupt = Vec::new();
                        for piece in ready {
                            match storage.verify_piece(&self.meta, piece) {
                                Ok(true) => {
                                    scheduler.block_map_mut().mark_verified(piece);
                                    confirmed += 1;
                                }
                                Ok(false) => {
                                    // Discard the bad data and re-request it.
                                    scheduler.block_map_mut().invalidate_piece(piece);
                                    corrupt.push(piece);
                                }
                                Err(e) => {
                                    self.log(Level::Error, format!("piece {piece}: {e}")).await;
                                    scheduler.block_map_mut().invalidate_piece(piece);
                                }
                            }
                        }
                        if confirmed > 0 {
                            self.log(Level::Debug, format!("verified {confirmed} pieces")).await;
                            // Our upload capability grows as we verify data, so a
                            // partial downloader becomes useful to the swarm
                            // instead of staying invisible.
                            pool.set_seeder(build_seeder(
                                Arc::clone(&storage),
                                &self.meta,
                                &scheduler.block_map().verified_pieces(),
                            ));
                        }
                        if !corrupt.is_empty() {
                            self.log(
                                Level::Warn,
                                format!("hash mismatch on {} pieces, re-fetching", corrupt.len()),
                            )
                            .await;
                        }
                    }

                    // ---- publish stats to the TUI ----
                    if last_stats.elapsed() >= STATS_INTERVAL {
                        last_stats = Instant::now();
                        let downloaded = scheduler.block_map().bytes_downloaded(&self.meta);

                        let dt = last_rate_sample.elapsed().as_secs_f64();
                        if dt > 0.0 {
                            let delta = downloaded.saturating_sub(last_down) as f64;
                            current_rate = delta / dt;
                        }
                        last_down = downloaded;
                        let uploaded = pool.total_uploaded().await;
                        if dt > 0.0 {
                            upload_rate = uploaded.saturating_sub(last_up) as f64 / dt;
                        }
                        last_up = uploaded;
                        last_rate_sample = Instant::now();

                        let left = self.meta.total_length.saturating_sub(downloaded);
                        let eta = if current_rate > 1.0 {
                            Some(left as f64 / current_rate)
                        } else {
                            None
                        };

                        let peers = snapshot_peers(&pool).await;
                        let connected = peers.len() as u32;

                        let mut st = self.state.write().await;
                        if let Some(t) = &mut st.torrent {
                            t.downloaded = downloaded;
                            t.verified_pieces = scheduler.block_map().verified_count();
                            t.progress = scheduler.progress();
                            t.download_rate = current_rate;
                            t.upload_rate = upload_rate;
                            t.eta_secs = eta;
                            if paused {
                                t.state = DownloadState::Paused;
                            } else if t.state == DownloadState::Paused {
                                t.state = DownloadState::Downloading;
                            }
                            t.files = file_summaries(&self.meta, &scheduler, &wanted);
                        }
                        st.peers = peers;
                        let _ = connected;
                    }

                    // ---- completion check ----
                    if scheduler.is_complete() {
                        // Publish the final figures BEFORE logging completion:
                        // the TUI renders log and stats from the same snapshot,
                        // so logging first would let a frame show "complete"
                        // next to a stale 99.x% gauge.
                        if let Some(t) = &mut self.state.write().await.torrent {
                            t.state = DownloadState::Complete;
                            t.progress = 1.0;
                            // The stats branch runs every 500ms, which the
                            // download can beat. Publish final figures here so
                            // the summary never reports a completed download
                            // as 0 bytes.
                            t.downloaded = self.meta.total_length;
                            t.verified_pieces = scheduler.block_map().verified_count();
                            t.eta_secs = Some(0.0);
                        }
                        self.log(
                            Level::Info,
                            format!(
                                "download complete: {} in {}",
                                crate::state::human_bytes(self.meta.total_length),
                                download_dir.display()
                            ),
                        )
                        .await;
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Verify every piece on disk and mark the good ones complete, so a resumed
    /// download does not start over.
    async fn recheck_existing(&self, storage: &Storage, scheduler: &mut Scheduler) -> u32 {
        let mut good = 0;
        for i in 0..self.meta.piece_count() {
            if i % 64 == 0 {
                self.log(
                    Level::Debug,
                    format!("rechecking piece {i}/{}", self.meta.piece_count()),
                )
                .await;
            }
            match storage.verify_piece(&self.meta, i as u32) {
                Ok(true) => {
                    scheduler.block_map_mut().mark_verified(i as u32);
                    good += 1;
                }
                _ => {
                    // Bad or missing: drop any partial state so it gets refetched.
                    scheduler.block_map_mut().invalidate_piece(i as u32);
                }
            }
        }
        good
    }

    pub async fn log(&self, level: Level, msg: impl Into<String>) {
        let msg = msg.into();
        match level {
            Level::Error => tracing::error!("{msg}"),
            Level::Warn => tracing::warn!("{msg}"),
            Level::Info => tracing::info!("{msg}"),
            Level::Debug => tracing::debug!("{msg}"),
            Level::Trace => tracing::trace!("{msg}"),
        }
        self.state.write().await.log(level, msg);
    }
}

/// Start the background DHT worker for `infohash`.
///
/// The node is created and bootstrapped lazily on the first request, inside
/// the worker, so a slow or offline network never blocks the engine loop. A
/// failed setup or lookup still answers with an empty list (clearing the
/// engine's in-flight flag) and is retried on the next request.
fn spawn_dht_lookups(
    infohash: crate::metainfo::InfoHash,
) -> (mpsc::UnboundedSender<()>, mpsc::UnboundedReceiver<Vec<SocketAddr>>) {
    let (req_tx, mut req_rx) = mpsc::unbounded_channel::<()>();
    let (res_tx, res_rx) = mpsc::unbounded_channel::<Vec<SocketAddr>>();
    tokio::spawn(async move {
        let mut node: Option<crate::dht::DhtNode> = None;
        while req_rx.recv().await.is_some() {
            if node.is_none() {
                match crate::dht::DhtNode::new(None).await {
                    Ok(n) => {
                        let routers: Vec<String> = crate::dht::DEFAULT_ROUTERS
                            .iter()
                            .map(|s| (*s).to_owned())
                            .collect();
                        let up = n.bootstrap(&routers).await;
                        tracing::debug!(routers_up = up, "dht bootstrapped");
                        node = Some(n);
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "could not start DHT node");
                        let _ = res_tx.send(Vec::new());
                        continue;
                    }
                }
            }
            let Some(n) = node.as_ref() else { continue };
            match n.get_peers(infohash).await {
                Ok(addrs) => {
                    let ok = !addrs.is_empty();
                    let _ = res_tx.send(addrs);
                    if ok {
                        if let Err(e) = n.announce(infohash, LOCAL_PORT).await {
                            tracing::debug!(error = %e, "dht announce failed");
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "dht get_peers failed");
                    let _ = res_tx.send(Vec::new());
                }
            }
        }
    });
    (req_tx, res_rx)
}

/// Apply an inbound piece to the scheduler's block map.
fn handle_peer_event(
    scheduler: &mut Scheduler,
    storage: &Storage,
    meta: &Metainfo,
    ev: &FromPeer,
) {
    if let FromPeer::Piece {
        index,
        begin,
        block,
    } = ev
    {
        // Persist the block BEFORE telling the scheduler we have it. If the
        // write fails we must not mark the block as held, or the piece would
        // look complete and get "verified" against whatever stale bytes are on
        // disk.
        let offset = *index as u64 * meta.piece_length as u64 + *begin as u64;
        match storage.write_at(offset, block) {
            Ok(()) => {
                let block_index = (begin / BLOCK_SIZE) as usize;
                scheduler.on_block(BlockRequest {
                    piece: *index,
                    block: block_index,
                    begin: *begin,
                    length: block.len() as u32,
                });
            }
            Err(e) => {
                tracing::error!(piece = *index, begin = *begin, error = %e, "failed to write block");
                // Drop the request so the block is retried rather than lost.
                let block_index = (begin / BLOCK_SIZE) as usize;
                scheduler.on_timeout((*index, block_index));
            }
        }
    } else if let FromPeer::Disconnected(reason) = ev {
        tracing::debug!("peer disconnected: {reason}");
    }
}

/// Build TUI-facing peer summaries.
async fn snapshot_peers(pool: &PeerPool) -> Vec<PeerSummary> {
    let mut out = Vec::new();
    for (addr, st) in pool.states().await {
        out.push(PeerSummary {
            addr,
            downloaded: st.downloaded,
            uploaded: st.uploaded,
            progress: if pool.piece_count() > 0 {
                st.bitfield.count() as f64 / pool.piece_count() as f64
            } else {
                0.0
            },
            choked_by_us: st.am_choking,
            choking_us: st.they_choke,
            outstanding: st.outstanding.len(),
        });
    }
    out.sort_by(|a, b| b.downloaded.cmp(&a.downloaded));
    out
}

/// Per-file progress summaries in torrent file order.
fn file_summaries(meta: &Metainfo, scheduler: &Scheduler, wanted: &[bool]) -> Vec<FileSummary> {
    let downloaded = crate::scheduler::file_downloaded(meta, scheduler.block_map());
    meta.files
        .iter()
        .enumerate()
        .map(|(i, (path, len))| {
            let got = downloaded.get(i).copied().unwrap_or(0);
            FileSummary {
                index: i,
                path: path
                    .iter()
                    .map(|c| c.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/"),
                length: len,
                downloaded: got.min(len),
                wanted: wanted.get(i).copied().unwrap_or(true),
            }
        })
        .collect()
}

/// Flip whether a file is downloaded, refusing to skip the last wanted file.
///
/// Skipping recomputes the scheduler's excluded-piece set from the whole
/// wanted vector (not incrementally), so the two can never drift apart.
async fn apply_file_toggle(
    meta: &Metainfo,
    wanted: &mut Vec<bool>,
    scheduler: &mut Scheduler,
    state: &Arc<RwLock<UiState>>,
    i: usize,
) {
    if i >= wanted.len() {
        return;
    }
    if wanted[i] && wanted.iter().filter(|w| **w).count() == 1 {
        state
            .write()
            .await
            .log(Level::Warn, "cannot skip the only remaining file");
        return;
    }
    wanted[i] = !wanted[i];
    let now_wanted = wanted[i];
    scheduler.set_excluded(&crate::scheduler::excluded_pieces(meta, wanted));

    let name = meta
        .files
        .iter()
        .nth(i)
        .map(|(p, _)| p.display().to_string())
        .unwrap_or_else(|| format!("file {i}"));
    state.write().await.log(
        Level::Info,
        if now_wanted {
            format!("downloading {name}")
        } else {
            format!("skipping {name}")
        },
    );
}
/// Build an upload capability from the pieces we have verified.
///
/// Returns `None` when we hold nothing, because advertising an all-zero
/// bitfield would make us useless to peers while still costing connections.
pub fn build_seeder(
    storage: Arc<Storage>,
    meta: &Metainfo,
    verified: &[bool],
) -> Option<crate::peer::connection::Seeder> {
    let mut bitfield = crate::peer::Bitfield::with_pieces(meta.piece_count());
    let mut any = false;
    for (i, ok) in verified.iter().enumerate() {
        if *ok {
            bitfield.set(i as u32);
            any = true;
        }
    }
    if !any {
        return None;
    }
    Some(crate::peer::connection::Seeder {
        storage,
        bitfield,
        piece_count: meta.piece_count(),
        piece_len: meta.piece_length,
        last_piece_len: meta.last_piece_length() as u32,
    })
}

/// Resolve a magnet link's `info` dict.
///
/// Two independent peer sources are tried, in the order real clients use:
///
/// 1. The magnet's own trackers. These are HTTP/UDP *tracker* URLs, not DHT
///    node addresses, so they must be announced to with the tracker client
///    rather than passed to the DHT bootstrapper.
/// 2. The DHT, using the well-known public bootstrap routers, for magnets that
///    carry no trackers or whose trackers are unreachable.
///
/// Either way the returned bytes are the raw bencoded `info` dictionary, whose
/// SHA-1 must equal the magnet's infohash.
async fn fetch_magnet_metadata(
    magnet: &Magnet,
    state: &Arc<RwLock<UiState>>,
) -> Result<Vec<u8>> {
    const PEER_PHASE_TIMEOUT: Duration = Duration::from_secs(60);

    let mut tried = 0usize;

    // ---- 1. trackers listed in the magnet ----
    if !magnet.trackers.is_empty() {
        let (peers, errors) = crate::tracker::announce_all(
            &magnet.trackers,
            &placeholder_meta(magnet),
            LOCAL_PORT,
            0,
            0,
            0,
        )
        .await;

        for e in &errors {
            state.write().await.log(Level::Warn, format!("tracker: {e}"));
        }
        if !peers.is_empty() {
            state
                .write()
                .await
                .log(Level::Info, format!("trackers returned {} peers", peers.len()));

            tried = peers.len();
            let addrs = peers.iter().map(|p| SocketAddr::new(p.ip, p.port)).collect();
            match crate::dht::fetch_metadata_from_peers(addrs, magnet.infohash, PEER_PHASE_TIMEOUT)
                .await
            {
                Ok(info) => {
                    state
                        .write()
                        .await
                        .log(Level::Info, "fetched metadata from a tracker peer");
                    return Ok(info);
                }
                Err(e) => tracing::debug!(error = %e, "tracker peers did not supply metadata"),
            }
        }
    }

    // ---- 2. the DHT ----
    state
        .write()
        .await
        .log(Level::Info, "asking the DHT for peers");

    let routers: Vec<String> = crate::dht::DEFAULT_ROUTERS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();

    match crate::dht::fetch_metadata(magnet.infohash, &routers, Duration::from_secs(60)).await {
        Ok(info) => Ok(info),
        Err(e) => {
            let mut st = state.write().await;
            st.log(Level::Warn, format!("DHT lookup failed: {e:#}"));
            st.log(
                Level::Error,
                format!(
                    "could not fetch metadata (tried {tried} peers). \
                     A magnet needs at least one reachable tracker or an active DHT."
                ),
            );
            Err(anyhow::anyhow!("fetching metadata for magnet link: {e:#}"))
        }
    }
}

/// A stand-in metainfo so the tracker client can announce a magnet, which has
/// an infohash but no info dict yet. Only the infohash is used for announcing.
fn placeholder_meta(magnet: &Magnet) -> Metainfo {
    Metainfo {
        infohash: magnet.infohash,
        name: magnet
            .display_name
            .clone()
            .unwrap_or_else(|| magnet.infohash.to_hex()),
        piece_length: 0,
        pieces: Vec::new(),
        files: crate::metainfo::Files::Single {
            name: String::new(),
            length: 0,
        },
        total_length: 0,
        private: false,
        announce: None,
        announce_list: magnet.trackers.clone(),
    }
}

/// Fetch metadata for a magnet link, then run the engine on the result.
pub async fn run_magnet(
    magnet: Magnet,
    download_dir: PathBuf,
    state: Arc<RwLock<UiState>>,
    commands: mpsc::UnboundedReceiver<Command>,
) -> Result<()> {
    {
        let mut st = state.write().await;
        st.torrent = Some(TorrentSummary {
            name: magnet
                .display_name
                .clone()
                .unwrap_or_else(|| magnet.infohash.to_hex()),
            infohash: magnet.infohash.to_hex(),
            state: DownloadState::FetchingMetadata,
            ..Default::default()
        });
        st.log(Level::Info, "magnet link: locating peers for metadata");
    }

    let raw_info = fetch_magnet_metadata(&magnet, &state).await?;

    // Re-encode the fetched info dict so it round-trips through Metainfo, and
    // confirm the hash matches what the magnet claimed.
    let doc = bencode_dict_with_info(raw_info.clone());
    let bytes = crate::bencode::encode(&doc);
    let meta = Metainfo::from_bytes(&bytes).context("parsing fetched metadata")?;

    if meta.infohash != magnet.infohash {
        anyhow::bail!(
            "fetched metadata hashes to {} but magnet declared {}",
            meta.infohash,
            magnet.infohash
        );
    }

    {
        let mut st = state.write().await;
        st.log(
            Level::Info,
            format!("fetched metadata: {} ({} peers seeded)", meta.name, meta.piece_count()),
        );
    }

    // Merge magnet trackers into the metainfo's list.
    let mut meta = meta;
    meta.announce_list.extend(magnet.trackers.iter().cloned());
    meta.announce_list.sort();
    meta.announce_list.dedup();

    let engine = Engine::new(Arc::new(meta), state, commands);
    engine.run(download_dir).await
}

/// Wrap a bare info dict in a minimal torrent file so `Metainfo` can parse it.
fn bencode_dict_with_info(info: Vec<u8>) -> crate::bencode::Value {
    use crate::bencode::Value;
    let mut d = std::collections::BTreeMap::new();
    d.insert(b"announce".to_vec(), Value::Bytes(b"".to_vec()));
    // Splice the raw info bytes in after "4:info" rather than re-encoding, to
    // keep the exact bytes the infohash was computed over.
    let mut raw = b"d8:announce0:4:info".to_vec();
    raw.extend_from_slice(&info);
    raw.extend_from_slice(b"e");

    // Parse to validate, then return the parsed value; encoding it again must
    // be byte-identical for any canonical info dict.
    crate::bencode::decode(&raw).unwrap_or(Value::Dict(d))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn block_request_key_roundtrip() {
        let r = BlockRequest {
            piece: 5,
            block: 2,
            begin: 2 * BLOCK_SIZE,
            length: BLOCK_SIZE,
        };
        assert_eq!(r.key(), (5, 2));
    }

    #[test]
    fn piece_event_maps_begin_to_block_index() {
        let meta = Metainfo {
            infohash: crate::metainfo::InfoHash([0; 20]),
            name: "t".into(),
            piece_length: BLOCK_SIZE * 4,
            pieces: vec![[0u8; 20]; 4],
            files: crate::metainfo::Files::Single {
                name: "t".into(),
                length: BLOCK_SIZE as u64 * 4 * 4,
            },
            total_length: BLOCK_SIZE as u64 * 4 * 4,
            private: false,
            announce: None,
            announce_list: vec![],
        };
        let mut s = Scheduler::new(&meta);

        let dir = std::env::temp_dir().join(format!("torrust-engine-{}", std::process::id()));
        let store = Storage::prepare(&meta, &dir).unwrap();

        // begin = 3 * BLOCK_SIZE => block index 3
        handle_peer_event(
            &mut s,
            &store,
            &meta,
            &FromPeer::Piece {
                index: 1,
                begin: 3 * BLOCK_SIZE,
                block: vec![0u8; 16],
            },
        );
        assert!(s.block_map().have_block(1, 3));
        assert!(!s.block_map().have_block(1, 0));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn incomplete_piece_is_not_verified() {
        let meta = Metainfo {
            infohash: crate::metainfo::InfoHash([0; 20]),
            name: "t".into(),
            piece_length: BLOCK_SIZE * 4,
            pieces: vec![[0u8; 20]; 4],
            files: crate::metainfo::Files::Single {
                name: "t".into(),
                length: BLOCK_SIZE as u64 * 4 * 4,
            },
            total_length: BLOCK_SIZE as u64 * 4 * 4,
            private: false,
            announce: None,
            announce_list: vec![],
        };
        let mut s = Scheduler::new(&meta);
        let dir = std::env::temp_dir().join(format!("torrust-engine2-{}", std::process::id()));
        let store = Storage::prepare(&meta, &dir).unwrap();
        for b in 0..3u32 {
            handle_peer_event(
                &mut s,
                &store,
                &meta,
                &FromPeer::Piece {
                    index: 0,
                    begin: b * BLOCK_SIZE,
                    block: vec![0u8; 16],
                },
            );
        }
        assert!(s.ready_pieces().is_empty());
        assert!(!s.is_complete());
        let _ = fs::remove_dir_all(&dir);
    }
}