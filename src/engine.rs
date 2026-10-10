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

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::sync::{mpsc, oneshot, RwLock};

use crate::dht::DhtNode;
use crate::peer::wire::Handshake;
use crate::peer::PeerStream;
use crate::utp::UtpSocket;
use crate::ratelimit::Limits;

use crate::metainfo::{Magnet, Metainfo, SocketAddrLite};
use crate::peer::connection::{FromPeer, BLOCK_SIZE};
use crate::peer::pool::{PeerPool, Source};
use crate::scheduler::{BlockRequest, Scheduler};
use crate::state::{
    Command, EncryptionMode, DownloadState, FilePriority, FileSummary, Level, PeerSummary, TorrentSummary, UiState,
};
use crate::storage::Storage;
use crate::tracker::{self, Event, TrackerSet};
use crate::webseed::{self, WebSeed};

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

/// How often a session engine re-runs tit-for-tat choking.
const RECHOKE_INTERVAL: Duration = Duration::from_secs(10);

/// Budget for the best-effort `completed` / `stopped` announces: shutting
/// down must not hang on a dead tracker.
const EVENT_TIMEOUT: Duration = Duration::from_secs(3);

/// Knobs a session sets per torrent. The default is the single-torrent CLI
/// behaviour: finish and return, own listener, own DHT node, auto-unchoke.
pub struct EngineOptions {
    /// Keep uploading after the download completes instead of returning.
    pub seed_after_complete: bool,
    /// Stop seeding once uploaded / size reaches this; 0 means never.
    pub ratio_target: f64,
    /// Bytes uploaded in earlier runs, so the ratio survives restarts.
    pub uploaded_so_far: u64,
    pub limits: Limits,
    pub max_peers: usize,
    pub auto_unchoke: bool,
    pub dht: Option<Arc<DhtNode>>,
    /// False keeps this torrent off the DHT entirely.
    pub dht_enabled: bool,
    /// Peers the session listener already handshook for this torrent. When
    /// set the engine does not bind a listener of its own.
    pub inbound: Option<mpsc::UnboundedReceiver<(PeerStream, SocketAddr, Handshake)>>,
    /// Encryption policy for outbound dials. Disabled keeps plaintext.
    pub encryption: EncryptionMode,
    /// uTP socket to dial through before falling back to TCP.
    pub utp: Option<Arc<UtpSocket>>,
    /// Port announced to trackers, the DHT and peers.
    pub port: u16,
    /// Per-file priorities to restore; ignored if its length does not match
    /// or it skips every file.
    pub file_priorities: Option<Vec<FilePriority>>,
    /// Extra peer addresses from session-level discovery (local peer
    /// discovery). Dialled like tracker peers.
    pub extra_peers: Option<mpsc::UnboundedReceiver<Vec<SocketAddr>>>,
    /// Start in sequential (in-order) download mode.
    pub sequential: bool,
    /// Peers in these ranges are never dialled or accepted.
    pub blocklist: Option<Arc<crate::blocklist::BlockList>>,
    /// Trackers this torrent should use instead of the metainfo's list
    /// (after the user added or removed some); `None` keeps the metainfo's.
    pub trackers: Option<Vec<String>>,
    /// Start in super-seeding mode.
    pub super_seed: bool,
}

impl Default for EngineOptions {
    fn default() -> Self {
        EngineOptions {
            seed_after_complete: false,
            ratio_target: 0.0,
            uploaded_so_far: 0,
            limits: Limits::default(),
            max_peers: crate::peer::pool::MAX_PEERS,
            auto_unchoke: true,
            dht: None,
            dht_enabled: true,
            inbound: None,
            encryption: EncryptionMode::Disabled,
            utp: None,
            port: LOCAL_PORT,
            file_priorities: None,
            extra_peers: None,
            sequential: false,
            blocklist: None,
            trackers: None,
            super_seed: false,
        }
    }
}

struct AbortOnDrop(Vec<tokio::task::JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for h in &self.0 {
            h.abort();
        }
    }
}

/// Whether cumulative uploads have reached the ratio target.
pub fn ratio_reached(uploaded: u64, total_length: u64, target: f64) -> bool {
    target > 0.0 && total_length > 0 && uploaded as f64 / total_length as f64 >= target
}

pub struct Engine {
    pub meta: Arc<Metainfo>,
    pub state: Arc<RwLock<UiState>>,
    commands: mpsc::UnboundedReceiver<Command>,
    opts: EngineOptions,
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
        Self::with_options(meta, state, commands, EngineOptions::default())
    }

    pub fn with_options(
        meta: Arc<Metainfo>,
        state: Arc<RwLock<UiState>>,
        commands: mpsc::UnboundedReceiver<Command>,
        opts: EngineOptions,
    ) -> Self {
        Engine {
            meta,
            state,
            commands,
            opts,
        }
    }

    /// Run until the download completes or `shutdown` is triggered.
    pub async fn run(mut self, download_dir: PathBuf) -> Result<()> {
        let storage = Arc::new(
            Storage::prepare(&self.meta, &download_dir)
                .context("preparing download directory")?,
        );
        let mut scheduler = Scheduler::new(&self.meta);
        let mut sequential = self.opts.sequential;
        scheduler.set_sequential(sequential);
        let port = self.opts.port;
        let mut inbound = self.opts.inbound.take();
        let mut extra_peers = self.opts.extra_peers.take().filter(|_| !self.meta.private);
        let mut trackers = TrackerSet::new(
            match self.opts.trackers.take() {
                Some(list) => list.iter().filter_map(|u| clean_tracker(u)).collect(),
                None => self.meta.announce_list.clone(),
            }
            .into_iter()
            .map(|u| vec![u])
            .collect(),
        );
        let file_count = self.meta.files.iter().count();
        let mut priorities = initial_priorities(file_count, self.opts.file_priorities.take());

        self.log(Level::Info, format!("preparing {}", download_dir.display()))
            .await;

        // Resume support: verify what is already on disk so we neither
        // re-download finished pieces nor trust unverified bytes. The hashing
        // runs off the async threads and the torrent shows as Checking; a
        // Stop is honoured at once and any other command waits its turn.
        self.state.write().await.torrent = Some(TorrentSummary {
            name: self.meta.name.clone(),
            infohash: self.meta.infohash.to_hex(),
            total_length: self.meta.total_length,
            piece_length: self.meta.piece_length,
            piece_count: self.meta.piece_count() as u32,
            state: DownloadState::Checking,
            download_dir: download_dir.display().to_string(),
            trackers: trackers.urls(),
            uploaded: self.opts.uploaded_so_far,
            sequential,
            files: file_summaries(&self.meta, &scheduler, &priorities),
            ..Default::default()
        });
        let mut backlog: VecDeque<Command> = VecDeque::new();
        let mut startup_check = spawn_check(Arc::clone(&storage), Arc::clone(&self.meta));
        let verified = loop {
            tokio::select! {
                ev = startup_check.recv() => match ev {
                    Some(CheckEvent::Progress { checked, good }) => self.publish_check(checked, good).await,
                    Some(CheckEvent::Done(v)) => break v,
                    None => break vec![false; self.meta.piece_count()],
                },
                Some(cmd) = self.commands.recv() => {
                    if cmd == Command::Stop {
                        if let Some(t) = &mut self.state.write().await.torrent {
                            t.state = DownloadState::Stopped;
                        }
                        self.log(Level::Info, "stopped while checking").await;
                        return Ok(());
                    }
                    backlog.push_back(cmd);
                }
            }
        };
        let good = apply_verified(&mut scheduler, &verified);
        self.log(
            Level::Info,
            format!(
                "rechecked {good}/{} pieces already on disk",
                self.meta.piece_count()
            ),
        )
        .await;

        scheduler.set_piece_priorities(crate::scheduler::piece_priorities(&self.meta, &priorities));

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
            trackers: trackers.urls(),
            uploaded: self.opts.uploaded_so_far,
            sequential,
            files: file_summaries(&self.meta, &scheduler, &priorities),
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
            port,
            peer_tx,
            self.opts.limits.clone(),
            self.opts.max_peers,
            self.opts.auto_unchoke,
        );
        pool.set_transport(self.opts.encryption, self.opts.utp.clone());
        pool.set_blocklist(self.opts.blocklist.clone());
        pool.set_super_seed(self.opts.super_seed);

        let mut listener_tasks = AbortOnDrop(Vec::new());
        if can_seed && inbound.is_none() {
            let (listen_tx, mut listen_rx) =
                mpsc::unbounded_channel::<(SocketAddr, FromPeer)>();
            listener_tasks.0.push(tokio::spawn(async move {
                while let Some(ev) = listen_rx.recv().await {
                    if inbound_forward.send(ev).is_err() {
                        break;
                    }
                }
            }));

            match pool.listen(port, listen_tx).await {
                Ok((addr, handle)) => {
                    listener_tasks.0.push(handle);
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
            mpsc::unbounded_channel::<(tracker::AnnounceOutcome, bool)>();
        let mut announce_in_flight = false;

        // BEP 27: private torrents must never touch the DHT.
        let (dht_tx, mut dht_rx) = if self.meta.private || !self.opts.dht_enabled {
            (None, None)
        } else {
            let (tx, rx) = spawn_dht_lookups(self.meta.infohash, self.opts.dht.clone(), port);
            (Some(tx), Some(rx))
        };
        let mut dht_in_flight = false;
        let mut last_dht_lookup: Option<Instant> = None;

        // Set when we are starved of peers, to re-announce as soon as a
        // tracker's minimum interval allows instead of waiting out the full one.
        let mut force_announce = false;
        // Bytes received from peers and web seeds during this run, for the
        // trackers' `downloaded`: data resumed from disk is not counted.
        let mut session_down: u64 = 0;
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
        let mut seeding = false;
        // `Some` while a forced recheck is hashing in the background.
        let mut check_rx: Option<mpsc::UnboundedReceiver<CheckEvent>> = None;
        // Lifecycle event for the next announce. A torrent that is already
        // complete on resume has no download to report finishing.
        let mut next_event = Some(Event::Started);
        let mut completed_sent = scheduler.is_complete();
        let mut last_rechoke = Instant::now();
        let mut last_super_seed = Instant::now();
        let uploaded_so_far = self.opts.uploaded_so_far;

        let mut web_seeds: Vec<WebSeed> = Vec::new();
        for u in self.meta.web_seeds.iter().take(webseed::MAX_WEB_SEEDS) {
            web_seeds.push(WebSeed::new(u.clone()));
        }
        let mut ws_jobs = tokio::task::JoinSet::new();
        let (ws_tx, mut ws_rx) = mpsc::unbounded_channel::<webseed::Done>();
        let mut ws_pieces: HashMap<u32, usize> = HashMap::new();

        let mut ticker = tokio::time::interval(Duration::from_millis(50));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                Some((addr, ev)) = peer_rx.recv() => {
                    if let FromPeer::PexPeers(addrs) = &ev {
                        tracing::debug!(peer = %addr, count = addrs.len(), "pex peers");
                        dial_addrs(&mut pool, addrs, Source::Pex);
                        continue;
                    }
                    if let FromPeer::Piece { block, .. } = &ev {
                        session_down += block.len() as u64;
                    }
                    handle_peer_event(&mut scheduler, &storage, &self.meta, &ev);
                    pool.on_event(addr, ev).await;
                }

                Some((stream, from, hs)) = async {
                    match inbound.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    pool.adopt_inbound(stream, from, hs).await;
                }

                Some(done) = ws_rx.recv() => {
                    let webseed::Done { seed, piece, result } = done;
                    web_seeds[seed].busy = false;
                    match result {
                        Ok(data) if !scheduler.block_map().is_verified(piece) => {
                            session_down += data.len() as u64;
                            for (i, chunk) in data.chunks(BLOCK_SIZE as usize).enumerate() {
                                let ev = FromPeer::Piece {
                                    index: piece,
                                    begin: i as u32 * BLOCK_SIZE,
                                    block: chunk.to_vec(),
                                };
                                handle_peer_event(&mut scheduler, &storage, &self.meta, &ev);
                            }
                            ws_pieces.insert(piece, seed);
                            web_seeds[seed].succeeded(data.len() as u64);
                        }
                        Ok(_) => {}
                        Err(webseed::WsError::Gone(file)) => {
                            scheduler.release_piece(piece);
                            web_seeds[seed].mark_file_dead(file);
                            self.log(
                                Level::Warn,
                                format!("web seed {}: file {file} not found", web_seeds[seed].host),
                            )
                            .await;
                        }
                        Err(e) => {
                            scheduler.release_piece(piece);
                            web_seeds[seed].failed();
                            self.log(
                                Level::Warn,
                                format!("web seed {}: {e}", web_seeds[seed].host),
                            )
                            .await;
                        }
                    }
                }

                Some((outcome, periodic)) = announce_rx.recv() => {
                    if periodic {
                        announce_in_flight = false;
                    }
                    let tracker::AnnounceOutcome { peers, errors, seeders, leechers, reports } = outcome;
                    trackers.record(&reports, Instant::now());
                    {
                        let mut st = self.state.write().await;
                        if let Some(t) = &mut st.torrent {
                            t.seeders_known = seeders.unwrap_or(t.seeders_known);
                            t.leecher_known = leechers.unwrap_or(t.leecher_known);
                        }
                        if errors.is_empty() {
                            st.warning = None;
                        }
                    }
                    if !errors.is_empty() {
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
                    match extra_peers.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    dial_addrs(&mut pool, &addrs, Source::Lsd);
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
                        let fresh = pool.discover_from(&lite, Source::Dht);
                        if !fresh.is_empty() {
                            pool.dial(&fresh);
                        }
                    }
                }

                Some(ev) = async {
                    match check_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match ev {
                        CheckEvent::Progress { checked, good } => self.publish_check(checked, good).await,
                        CheckEvent::Done(verified) => {
                            check_rx = None;
                            scheduler = Scheduler::new(&self.meta);
                            scheduler.set_sequential(sequential);
                            let good = apply_verified(&mut scheduler, &verified);
                            scheduler.set_piece_priorities(crate::scheduler::piece_priorities(
                                &self.meta,
                                &priorities,
                            ));
                            pool.set_seeder(build_seeder(Arc::clone(&storage), &self.meta, &verified));
                            if seeding && !scheduler.is_complete() {
                                seeding = false;
                            }
                            if let Some(t) = &mut self.state.write().await.torrent {
                                t.state = if paused {
                                    DownloadState::Paused
                                } else if seeding {
                                    DownloadState::Seeding
                                } else {
                                    DownloadState::Downloading
                                };
                                t.downloaded = scheduler.block_map().bytes_downloaded(&self.meta);
                                t.verified_pieces = scheduler.block_map().verified_count();
                                t.progress = scheduler.progress();
                                t.files = file_summaries(&self.meta, &scheduler, &priorities);
                            }
                            self.log(
                                Level::Info,
                                format!("recheck done: {good}/{} pieces verified", self.meta.piece_count()),
                            )
                            .await;
                        }
                    }
                }

                _ = ticker.tick() => {
                    // ---- commands from the TUI (pause, file selection) ----
                    while let Some(cmd) = backlog.pop_front().or_else(|| self.commands.try_recv().ok()) {
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
                                let session_up = pool.total_uploaded().await;
                                let total = uploaded_so_far + session_up;
                                if let Some(t) = &mut self.state.write().await.torrent {
                                    t.state = DownloadState::Stopped;
                                    t.download_rate = 0.0;
                                    t.upload_rate = 0.0;
                                    t.uploaded = total;
                                }
                                pool.disconnect_all().await;
                                self.log(Level::Info, "stopped").await;
                                self.announce_event(&trackers, Event::Stopped, port, session_up, session_down, &scheduler).await;
                                return Ok(());
                            }
                            Command::SetMaxPeers(n) => pool.set_max_peers(n),
                            Command::SetSuperSeed(on) => {
                                pool.set_super_seed(on);
                                let effective = pool.super_seeding();
                                if let Some(t) = &mut self.state.write().await.torrent {
                                    t.super_seeding = effective;
                                }
                                self.log(
                                    Level::Info,
                                    match (on, effective) {
                                        (false, _) => "super-seeding off",
                                        (true, true) => "super-seeding on",
                                        (true, false) => "super-seeding will start once the torrent is complete",
                                    },
                                )
                                .await;
                            }
                            Command::AddTracker(url) => match clean_tracker(&url) {
                                None => {
                                    self.log(Level::Warn, format!("not a tracker URL (need http, https or udp): {}", crate::redact::url(&url)))
                                        .await;
                                }
                                Some(u) if trackers.contains(&u) => {
                                    self.log(Level::Info, format!("tracker already listed: {}", crate::redact::url(&u))).await;
                                }
                                Some(u) => {
                                    trackers.add(u.clone());
                                    if let Some(t) = &mut self.state.write().await.torrent {
                                        t.trackers = trackers.urls();
                                    }
                                    self.log(Level::Info, format!("added tracker {}", crate::redact::url(&u))).await;
                                    spawn_announce(
                                        vec![vec![u]],
                                        Arc::clone(&self.meta),
                                        port,
                                        pool.total_uploaded().await,
                                        session_down,
                                        left_bytes(&self.meta, &scheduler),
                                        Some(Event::Started),
                                        announce_tx.clone(),
                                        false,
                                    );
                                }
                            },
                            Command::RemoveTracker(url) => {
                                let url = url.trim();
                                if trackers.contains(url) {
                                    trackers.remove(url);
                                    if let Some(t) = &mut self.state.write().await.torrent {
                                        t.trackers = trackers.urls();
                                    }
                                    self.log(Level::Info, format!("removed tracker {}", crate::redact::url(url))).await;
                                }
                            }
                            Command::SetSequential(on) => {
                                sequential = on;
                                scheduler.set_sequential(on);
                                if let Some(t) = &mut self.state.write().await.torrent {
                                    t.sequential = on;
                                }
                            }
                            Command::Recheck => {
                                if check_rx.is_none() {
                                    // Stop serving while the data is in doubt: a
                                    // peer must never be sent a corrupt piece.
                                    pool.set_seeder(None);
                                    check_rx = Some(spawn_check(Arc::clone(&storage), Arc::clone(&self.meta)));
                                    if let Some(t) = &mut self.state.write().await.torrent {
                                        t.state = DownloadState::Checking;
                                        t.progress = 0.0;
                                    }
                                    self.log(Level::Info, "rechecking all pieces").await;
                                }
                            }
                            Command::SetFilePriority(i, p) => {
                                apply_file_priority(
                                    &self.meta,
                                    &mut priorities,
                                    &mut scheduler,
                                    &self.state,
                                    i,
                                    p,
                                )
                                .await;
                            }
                            Command::ToggleFile(i) => {
                                let flipped = match priorities.get(i) {
                                    Some(FilePriority::Skip) => FilePriority::Normal,
                                    _ => FilePriority::Skip,
                                };
                                apply_file_priority(
                                    &self.meta,
                                    &mut priorities,
                                    &mut scheduler,
                                    &self.state,
                                    i,
                                    flipped,
                                )
                                .await;
                            }
                        }
                    }

                    // ---- periodically refill the request pipeline ----
                    // A pause stops new requests. Blocks already on the wire
                    // still land and verify, so resuming never loses data.
                    if !paused && !seeding && check_rx.is_none() && last_fill.elapsed() >= PIPELINE_INTERVAL {
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

                    // ---- web seeds: one whole piece in flight per seed ----
                    while ws_jobs.try_join_next().is_some() {}
                    if !paused
                        && !seeding
                        && check_rx.is_none()
                        && web_seeds.iter().any(|w| w.ready())
                    {
                        let rarity: HashMap<u32, u32> = (0..self.meta.piece_count() as u32)
                            .map(|p| (p, pool.seeders_for(p)))
                            .collect();
                        for (i, ws) in web_seeds.iter_mut().enumerate() {
                            if !ws.ready() {
                                continue;
                            }
                            let meta = &self.meta;
                            let Some((piece, _)) = scheduler
                                .claim_piece_for_webseed(&rarity, |p| ws.can_serve(meta, p))
                            else {
                                break;
                            };
                            ws.busy = true;
                            webseed::spawn_fetch(
                                &mut ws_jobs,
                                Arc::clone(&self.meta),
                                ws.base.clone(),
                                i,
                                piece,
                                self.opts.limits.clone(),
                                ws_tx.clone(),
                            );
                        }
                    }

                    // ---- announce to trackers periodically ----
                    if !announce_in_flight {
                        let tiers = trackers.plan(Instant::now(), force_announce, next_event);
                        if !tiers.is_empty() {
                            force_announce = false;
                            announce_in_flight = true;
                            spawn_announce(
                                tiers,
                                Arc::clone(&self.meta),
                                port,
                                pool.total_uploaded().await,
                                session_down,
                                left_bytes(&self.meta, &scheduler),
                                next_event.take(),
                                announce_tx.clone(),
                                true,
                            );
                        }
                    }

                    // ---- DHT peer lookup ----
                    // Trackerless torrents rely on it; otherwise it tops up a
                    // thin swarm. At most one lookup in flight, once a minute.
                    if let Some(tx) = &dht_tx {
                        let starved = trackers.is_empty()
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
                        force_announce = !seeding
                            && pool.connected() < crate::peer::MIN_PEERS
                            && !trackers.is_empty();
                    }

                    // ---- verify any fully-downloaded pieces ----
                    let ready = if check_rx.is_none() { scheduler.ready_pieces() } else { Vec::new() };
                    if !ready.is_empty() {
                        let mut confirmed = 0u32;
                        let mut corrupt = Vec::new();
                        let hashed = {
                            let (storage, meta) = (Arc::clone(&storage), Arc::clone(&self.meta));
                            tokio::task::spawn_blocking(move || {
                                ready
                                    .into_iter()
                                    .map(|piece| (piece, storage.verify_piece(&meta, piece)))
                                    .collect::<Vec<_>>()
                            })
                            .await
                            .context("piece verification task")?
                        };
                        for (piece, verdict) in hashed {
                            match verdict {
                                Ok(true) => {
                                    ws_pieces.remove(&piece);
                                    scheduler.block_map_mut().mark_verified(piece);
                                    confirmed += 1;
                                }
                                Ok(false) => {
                                    // Discard the bad data and re-request it.
                                    scheduler.block_map_mut().invalidate_piece(piece);
                                    if let Some(i) = ws_pieces.remove(&piece) {
                                        web_seeds[i].failed();
                                    }
                                    corrupt.push(piece);
                                }
                                Err(e) => {
                                    self.log(Level::Error, format!("piece {piece}: {e}")).await;
                                    ws_pieces.remove(&piece);
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

                    if last_super_seed.elapsed() >= Duration::from_secs(1) {
                        last_super_seed = Instant::now();
                        pool.super_seed_tick();
                    }

                    // ---- tit-for-tat choking (session engines) ----
                    if !self.opts.auto_unchoke && last_rechoke.elapsed() >= RECHOKE_INTERVAL {
                        last_rechoke = Instant::now();
                        pool.rechoke(seeding).await;
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

                        let mut peers = snapshot_peers(&pool).await;
                        peers.extend(web_seeds.iter().map(|w| PeerSummary {
                            addr: format!("web: {}", w.host),
                            downloaded: w.downloaded,
                            uploaded: 0,
                            progress: 1.0,
                            choked_by_us: false,
                            choking_us: w.backing_off(),
                            outstanding: usize::from(w.busy),
                            flags: "W".to_string(),
                        }));
                        let connected = peers.len() as u32;

                        let total_up = uploaded_so_far + uploaded;
                        let reached = seeding
                            && ratio_reached(total_up, self.meta.total_length, self.opts.ratio_target);

                        let mut st = self.state.write().await;
                        if let Some(t) = &mut st.torrent {
                            let checking = check_rx.is_some();
                            t.uploaded = total_up;
                            t.sequential = sequential;
                            t.super_seeding = pool.super_seeding();
                            t.download_rate = current_rate;
                            t.upload_rate = upload_rate;
                            t.eta_secs = eta;
                            if !checking {
                                t.downloaded = downloaded;
                                t.verified_pieces = scheduler.block_map().verified_count();
                                t.progress = scheduler.progress();
                                t.files = file_summaries(&self.meta, &scheduler, &priorities);
                            }
                            if checking {
                                t.state = DownloadState::Checking;
                            } else if reached {
                                t.state = DownloadState::Stopped;
                                t.upload_rate = 0.0;
                            } else if paused {
                                t.state = DownloadState::Paused;
                            } else if t.state == DownloadState::Paused {
                                t.state = if seeding {
                                    DownloadState::Seeding
                                } else {
                                    DownloadState::Downloading
                                };
                            }
                        }
                        st.peers = peers;
                        st.stats_at = Some(Instant::now());
                        let _ = connected;
                        drop(st);
                        if reached {
                            pool.disconnect_all().await;
                            self.announce_event(&trackers, Event::Stopped, port, uploaded, session_down, &scheduler).await;
                            self.log(
                                Level::Info,
                                format!("ratio reached ({:.2}), stopping", self.opts.ratio_target),
                            )
                            .await;
                            return Ok(());
                        }
                    }

                    // ---- completion check ----
                    if !seeding && check_rx.is_none() && scheduler.is_complete() {
                        // Publish the final figures BEFORE logging completion:
                        // the TUI renders log and stats from the same snapshot,
                        // so logging first would let a frame show "complete"
                        // next to a stale 99.x% gauge.
                        if let Some(t) = &mut self.state.write().await.torrent {
                            t.state = if self.opts.seed_after_complete {
                                DownloadState::Seeding
                            } else {
                                DownloadState::Complete
                            };
                            t.progress = 1.0;
                            t.sequential = sequential;
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
                        if !self.opts.seed_after_complete {
                            if !completed_sent {
                                let up = pool.total_uploaded().await;
                                self.announce_event(&trackers, Event::Completed, port, up, session_down, &scheduler).await;
                            }
                            return Ok(());
                        }
                        if !completed_sent {
                            completed_sent = true;
                            next_event = Some(Event::Completed);
                        }
                        seeding = true;
                        last_rechoke = Instant::now() - RECHOKE_INTERVAL;
                    }
                }
            }
        }
    }

    /// Publish hashing progress while the torrent is in the Checking state.
    async fn publish_check(&self, checked: usize, good: u32) {
        let total = self.meta.piece_count().max(1);
        if let Some(t) = &mut self.state.write().await.torrent {
            t.state = DownloadState::Checking;
            t.progress = checked as f64 / total as f64;
            t.verified_pieces = good;
        }
    }

    /// Best-effort lifecycle announce (`completed`, `stopped`) that gives up
    /// after [`EVENT_TIMEOUT`] so a dead tracker cannot delay shutdown.
    async fn announce_event(
        &self,
        trackers: &TrackerSet,
        event: Event,
        port: u16,
        uploaded: u64,
        downloaded: u64,
        scheduler: &Scheduler,
    ) {
        let tiers = trackers.plan(Instant::now(), false, Some(event));
        if tiers.is_empty() {
            return;
        }
        let left = left_bytes(&self.meta, scheduler);
        let _ = tokio::time::timeout(
            EVENT_TIMEOUT,
            tracker::announce_tiers(
                &tiers,
                &self.meta,
                port,
                uploaded,
                downloaded,
                left,
                Some(event),
            ),
        )
        .await;
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

/// What the background hashing task reports.
enum CheckEvent {
    Progress { checked: usize, good: u32 },
    Done(Vec<bool>),
}

/// Hash every piece on a blocking thread so a multi-gigabyte recheck never
/// stalls the engine loop. The task stops early when the receiver is dropped.
fn spawn_check(storage: Arc<Storage>, meta: Arc<Metainfo>) -> mpsc::UnboundedReceiver<CheckEvent> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::task::spawn_blocking(move || {
        let total = meta.piece_count();
        let step = (total / 100).max(1);
        let mut verified = vec![false; total];
        let mut good = 0u32;
        for i in 0..total {
            let ok = matches!(storage.verify_piece(&meta, i as u32), Ok(true));
            verified[i] = ok;
            good += u32::from(ok);
            if (i + 1) % step == 0
                && tx.send(CheckEvent::Progress { checked: i + 1, good }).is_err()
            {
                return;
            }
        }
        let _ = tx.send(CheckEvent::Done(verified));
    });
    rx
}

/// Mark the pieces that hashed correctly and drop partial state for the rest,
/// so bad or missing data gets refetched. Returns the verified count.
fn apply_verified(scheduler: &mut Scheduler, verified: &[bool]) -> u32 {
    let mut good = 0;
    for (i, ok) in verified.iter().enumerate() {
        if *ok {
            scheduler.block_map_mut().mark_verified(i as u32);
            good += 1;
        } else {
            scheduler.block_map_mut().invalidate_piece(i as u32);
        }
    }
    good
}

/// Pick the starting per-file priorities. A stored selection that does not
/// fit this torrent, or that skips every file, is ignored.
fn initial_priorities(files: usize, stored: Option<Vec<FilePriority>>) -> Vec<FilePriority> {
    match stored {
        Some(p) if p.len() == files && p.iter().any(|x| *x != FilePriority::Skip) => p,
        _ => vec![FilePriority::Normal; files],
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
    shared: Option<Arc<DhtNode>>,
    port: u16,
) -> (mpsc::UnboundedSender<()>, mpsc::UnboundedReceiver<Vec<SocketAddr>>) {
    let (req_tx, mut req_rx) = mpsc::unbounded_channel::<()>();
    let (res_tx, res_rx) = mpsc::unbounded_channel::<Vec<SocketAddr>>();
    tokio::spawn(async move {
        let mut node: Option<Arc<DhtNode>> = shared;
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
                        node = Some(Arc::new(n));
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
                    let _ = res_tx.send(addrs);
                    if let Err(e) = n.announce(infohash, port).await {
                        tracing::debug!(error = %e, "dht announce failed");
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

/// Dial whichever of `addrs` the pool has not seen yet.
fn dial_addrs(pool: &mut PeerPool, addrs: &[SocketAddr], source: Source) {
    let lite: Vec<SocketAddrLite> = addrs
        .iter()
        .map(|a| SocketAddrLite { ip: a.ip(), port: a.port() })
        .collect();
    let fresh = pool.discover_from(&lite, source);
    if !fresh.is_empty() {
        pool.dial(&fresh);
    }
}

/// Accept only http, https and udp tracker URLs with a host.
fn clean_tracker(url: &str) -> Option<String> {
    let url = url.trim();
    let parsed = url::Url::parse(url).ok()?;
    (matches!(parsed.scheme(), "http" | "https" | "udp") && parsed.host().is_some()).then(|| url.to_owned())
}

/// Bytes still needed for the wanted files: unverified pieces not excluded by
/// file priorities.
fn left_bytes(meta: &Metainfo, scheduler: &Scheduler) -> u64 {
    (0..meta.piece_count())
        .filter(|&i| !scheduler.excluded().contains(&(i as u32)) && !scheduler.block_map().is_verified(i as u32))
        .map(|i| meta.piece_size(i))
        .sum()
}

/// Announce to `tiers` on its own task so a slow tracker never stalls the
/// loop; the outcome comes back on `tx` tagged with whether it was the
/// periodic announce.
#[allow(clippy::too_many_arguments)]
fn spawn_announce(
    tiers: Vec<Vec<String>>,
    meta: Arc<Metainfo>,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<Event>,
    tx: mpsc::UnboundedSender<(tracker::AnnounceOutcome, bool)>,
    periodic: bool,
) {
    tokio::spawn(async move {
        let res = tracker::announce_tiers(&tiers, &meta, port, uploaded, downloaded, left, event).await;
        let _ = tx.send((res, periodic));
    });
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
        let end = *begin as u64 + block.len() as u64;
        if *index as usize >= meta.piece_count()
            || scheduler.block_map().is_verified(*index)
            || begin % BLOCK_SIZE != 0
            || block.is_empty()
            || block.len() > BLOCK_SIZE as usize
            || end > meta.piece_size(*index as usize)
        {
            tracing::debug!(piece = *index, begin = *begin, len = block.len(), "dropping unsolicited block");
            return;
        }
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
    } else if let FromPeer::Rejected { index, begin, .. } = ev {
        scheduler.on_timeout((*index, (begin / BLOCK_SIZE) as usize));
    } else if let FromPeer::Disconnected(reason) = ev {
        tracing::debug!("peer disconnected: {reason}");
    }
}

/// Build TUI-facing peer summaries.
async fn snapshot_peers(pool: &PeerPool) -> Vec<PeerSummary> {
    let mut out = Vec::new();
    for (addr, st, flags) in pool.states().await {
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
            flags,
        });
    }
    out.sort_by(|a, b| b.downloaded.cmp(&a.downloaded));
    out
}

/// Per-file progress summaries in torrent file order.
fn file_summaries(
    meta: &Metainfo,
    scheduler: &Scheduler,
    priorities: &[FilePriority],
) -> Vec<FileSummary> {
    let downloaded = crate::scheduler::file_downloaded(meta, scheduler.block_map());
    meta.files
        .iter()
        .enumerate()
        .map(|(i, (path, len))| {
            let got = downloaded.get(i).copied().unwrap_or(0);
            let priority = priorities.get(i).copied().unwrap_or_default();
            FileSummary {
                index: i,
                path: path
                    .iter()
                    .map(|c| c.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/"),
                length: len,
                downloaded: got.min(len),
                wanted: priority != FilePriority::Skip,
                priority,
            }
        })
        .collect()
}

/// Set one file's priority, refusing to skip the last file still wanted.
///
/// The scheduler's per-piece priorities (and with them the excluded-piece
/// set) are recomputed from the whole priority vector, not incrementally, so
/// the two can never drift apart.
async fn apply_file_priority(
    meta: &Metainfo,
    priorities: &mut [FilePriority],
    scheduler: &mut Scheduler,
    state: &Arc<RwLock<UiState>>,
    i: usize,
    priority: FilePriority,
) {
    if i >= priorities.len() || priorities[i] == priority {
        return;
    }
    if priority == FilePriority::Skip
        && priorities.iter().filter(|p| **p != FilePriority::Skip).count() == 1
    {
        state
            .write()
            .await
            .log(Level::Warn, "cannot skip the only remaining file");
        return;
    }
    let was_skipped = priorities[i] == FilePriority::Skip;
    priorities[i] = priority;
    scheduler.set_piece_priorities(crate::scheduler::piece_priorities(meta, priorities));

    let name = meta
        .files
        .iter()
        .nth(i)
        .map(|(p, _)| p.display().to_string())
        .unwrap_or_else(|| format!("file {i}"));
    state.write().await.log(
        Level::Info,
        match priority {
            FilePriority::Skip => format!("skipping {name}"),
            p if was_skipped => format!("downloading {name} ({} priority)", p.label()),
            p => format!("{name}: {} priority", p.label()),
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
        super_seed: false,
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
    port: u16,
    dht_enabled: bool,
    shared_dht: Option<&DhtNode>,
    encryption: EncryptionMode,
) -> Result<Vec<u8>> {
    const PEER_PHASE_TIMEOUT: Duration = Duration::from_secs(60);

    let mut tried = 0usize;

    // ---- 1. trackers listed in the magnet ----
    if !magnet.trackers.is_empty() {
        let tracker::AnnounceOutcome { peers, errors, .. } = tracker::announce_all(
            &magnet.trackers,
            &placeholder_meta(magnet),
            port,
            0,
            0,
            0,
            Some(Event::Started),
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
            match crate::dht::fetch_metadata_from_peers(addrs, magnet.infohash, PEER_PHASE_TIMEOUT, encryption)
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
    if !dht_enabled {
        anyhow::bail!("tried {tried} tracker peers and the DHT is off in settings");
    }

    state
        .write()
        .await
        .log(Level::Info, "asking the DHT for peers");

    let routers: Vec<String> = crate::dht::DEFAULT_ROUTERS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();

    let timeout = Duration::from_secs(60);
    let fetched = match shared_dht {
        Some(node) => crate::dht::fetch_metadata_with_node(node, magnet.infohash, timeout, encryption).await,
        None => crate::dht::fetch_metadata(magnet.infohash, &routers, timeout, encryption).await,
    };
    match fetched {
        Ok(info) => Ok(info),
        Err(e) => Err(anyhow::anyhow!("tried {tried} tracker peers, then the DHT: {e:#}")),
    }
}

/// Wait before the first metadata retry; it doubles up to the maximum.
const METADATA_RETRY_FIRST: Duration = Duration::from_secs(15);
const METADATA_RETRY_MAX: Duration = Duration::from_secs(300);

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
        web_seeds: Vec::new(),
        info_bytes: vec![],
    }
}

/// Fetch metadata for a magnet link, then run the engine on the result.
pub async fn run_magnet(
    magnet: Magnet,
    download_dir: PathBuf,
    state: Arc<RwLock<UiState>>,
    commands: mpsc::UnboundedReceiver<Command>,
) -> Result<()> {
    run_magnet_with_options(magnet, download_dir, state, commands, EngineOptions::default(), None).await
}

/// [`run_magnet`] with session options. The fetched raw `info` dict is sent
/// on `info_sink` so the caller can persist it. A `Stop` while the metadata
/// is still being located ends the run with the torrent marked stopped.
pub async fn run_magnet_with_options(
    magnet: Magnet,
    download_dir: PathBuf,
    state: Arc<RwLock<UiState>>,
    mut commands: mpsc::UnboundedReceiver<Command>,
    opts: EngineOptions,
    info_sink: Option<oneshot::Sender<Vec<u8>>>,
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

    // Keep trying until it works or the torrent is stopped: right after a
    // start the DHT may still be filling, and peers come and go.
    let fetch = async {
        let mut wait = METADATA_RETRY_FIRST;
        loop {
            match fetch_magnet_metadata(&magnet, &state, opts.port, opts.dht_enabled, opts.dht.as_deref(), opts.encryption).await {
                Ok(info) => {
                    state.write().await.warning = None;
                    break Ok::<_, anyhow::Error>(info);
                }
                Err(e) => {
                    let msg = format!("no metadata yet ({e:#}); retrying in {}s", wait.as_secs());
                    let mut st = state.write().await;
                    st.log(Level::Warn, msg.clone());
                    st.warning = Some(msg);
                    drop(st);
                    tokio::time::sleep(wait).await;
                    wait = (wait * 2).min(METADATA_RETRY_MAX);
                }
            }
        }
    };
    let wait_stop = async {
        while let Some(cmd) = commands.recv().await {
            if cmd == Command::Stop {
                return;
            }
        }
        std::future::pending::<()>().await
    };
    let raw_info = tokio::select! {
        r = fetch => r?,
        _ = wait_stop => {
            if let Some(t) = &mut state.write().await.torrent {
                t.state = DownloadState::Stopped;
            }
            return Ok(());
        }
    };
    if let Some(tx) = info_sink {
        let _ = tx.send(raw_info.clone());
    }

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
    for u in &magnet.webseeds {
        if crate::metainfo::is_http_url(u) && !meta.web_seeds.contains(u) {
            meta.web_seeds.push(u.clone());
        }
    }

    let engine = Engine::with_options(Arc::new(meta), state, commands, opts);
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
    fn ratio_reached_needs_target_and_size() {
        assert!(!ratio_reached(1000, 100, 0.0));
        assert!(!ratio_reached(1000, 0, 1.0));
        assert!(!ratio_reached(199, 100, 2.0));
        assert!(ratio_reached(200, 100, 2.0));
    }

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
            web_seeds: vec![],
            info_bytes: vec![],
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
    fn blocks_that_do_not_belong_to_an_unverified_piece_are_never_written() {
        let meta = Metainfo {
            infohash: crate::metainfo::InfoHash([0; 20]),
            name: "t".into(),
            piece_length: BLOCK_SIZE * 2,
            pieces: vec![[0u8; 20]; 3],
            files: crate::metainfo::Files::Single {
                name: "t".into(),
                length: BLOCK_SIZE as u64 * 5,
            },
            total_length: BLOCK_SIZE as u64 * 5,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
            info_bytes: vec![],
        };
        let mut s = Scheduler::new(&meta);
        let dir = std::env::temp_dir().join(format!("torrust-engine4-{}", std::process::id()));
        let store = Storage::prepare(&meta, &dir).unwrap();
        store.write_at(0, &vec![0x11; BLOCK_SIZE as usize * 5]).unwrap();
        s.block_map_mut().mark_verified(0);

        let mut give = |index: u32, begin: u32, len: usize| {
            handle_peer_event(&mut s, &store, &meta, &FromPeer::Piece { index, begin, block: vec![0xEE; len] });
        };
        give(0, 0, BLOCK_SIZE as usize);
        give(1, 1, 16);
        give(1, 0, BLOCK_SIZE as usize * 2);
        give(2, 0, BLOCK_SIZE as usize * 2);
        give(2, BLOCK_SIZE, 0);
        give(3, 0, 16);
        let on_disk = store.read_at(0, BLOCK_SIZE as u64 * 5).unwrap();
        assert!(on_disk.iter().all(|b| *b == 0x11), "an unsolicited block reached the disk");

        give(2, 0, BLOCK_SIZE as usize);
        assert_eq!(store.read_at(BLOCK_SIZE as u64 * 4, 4).unwrap(), vec![0xEE; 4]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejected_request_frees_the_block_for_an_immediate_retry() {
        let meta = Metainfo {
            infohash: crate::metainfo::InfoHash([0; 20]),
            name: "t".into(),
            piece_length: BLOCK_SIZE * 4,
            pieces: vec![[0u8; 20]; 8],
            files: crate::metainfo::Files::Single {
                name: "t".into(),
                length: BLOCK_SIZE as u64 * 4 * 8,
            },
            total_length: BLOCK_SIZE as u64 * 4 * 8,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
            info_bytes: vec![],
        };
        let mut s = Scheduler::new(&meta);
        let dir = std::env::temp_dir().join(format!("torrust-engine3-{}", std::process::id()));
        let store = Storage::prepare(&meta, &dir).unwrap();
        let rarity: HashMap<u32, u32> = (0..8).map(|p| (p, 1)).collect();

        let all = s.fill_batch(&rarity, 1000);
        assert_eq!(all.len(), 32);
        assert!(s.fill_batch(&rarity, 1).is_empty(), "everything is in flight");

        let victim = &all[5];
        handle_peer_event(
            &mut s,
            &store,
            &meta,
            &FromPeer::Rejected { index: victim.piece, begin: victim.begin, length: victim.length },
        );
        let retry = s.fill_batch(&rarity, 5);
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].key(), victim.key());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tracker_urls_must_be_http_https_or_udp_with_a_host() {
        for ok in ["http://t.example/announce", " https://t.example:443/a ", "udp://127.0.0.1:6969/announce", "UDP://t.example:80"] {
            assert!(clean_tracker(ok).is_some(), "{ok}");
        }
        for bad in ["", "ftp://t.example/a", "t.example/announce", "http://", "udp:///x", "file:///etc/passwd", "javascript:alert(1)"] {
            assert!(clean_tracker(bad).is_none(), "{bad}");
        }
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
            web_seeds: vec![],
            info_bytes: vec![],
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