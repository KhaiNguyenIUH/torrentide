//! Session mode: many torrents behind one listener, one DHT node and shared
//! rate limiters, persisted across restarts.
//!
//! One task (the core) owns every torrent entry and handles every
//! [`SessionCommand`]; each running torrent is an [`Engine`] in its own task
//! with its own [`UiState`]. Every 250 ms the core folds those into the
//! [`SessionState`] the TUI reads.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use rand::Rng;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::{oneshot, watch, RwLock, Semaphore};
use tokio::task::JoinHandle;

use crate::bencode::{self, Value};
use crate::blocklist::BlockList;
use crate::dht::DhtNode;
use crate::engine::{self, Engine, EngineOptions};
use crate::lsd::Lsd;
use crate::metainfo::{InfoHash, Magnet, Metainfo};
use crate::peer::wire::{handshake_incoming, Handshake};
use crate::peer::{mse, PeerStream};
use crate::portmap;
use crate::ratelimit::{Limits, RateLimiter};
use crate::rss::{self, FeedState, ParsedFeed};
use crate::schedule::{self, Effective};
use crate::state::{
    human_bytes, Command, DownloadState, EncryptionMode, FeedId, FeedView, FilePriority, FileSummary, Level, SessionCommand,
    SessionState, Settings, TorrentSummary, TorrentView, UiState,
};
use crate::utp::UtpSocket;
use crate::store::{Record, Snapshot, Store, StoredFeed};

const TICK: Duration = Duration::from_millis(250);
const PERSIST_EVERY: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_HANDSHAKES: usize = 64;
const MAPPING_LIFETIME: Duration = Duration::from_secs(3600);
const SUMMARY_EVERY: Duration = Duration::from_secs(5);
const FEED_INTERVAL: Duration = Duration::from_secs(15 * 60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
const FETCH_SLOTS: usize = 2;
const FEED_FETCH_SLOTS: usize = 1;
const MAX_PENDING_FETCHES: usize = 32;
const MAX_TORRENT_BYTES: usize = 10 * 1024 * 1024;
const MAX_FEED_BYTES: usize = 2 * 1024 * 1024;
const MAX_FEEDS: usize = 64;
const MAX_RECENT: usize = 10;
const MAX_TITLE: usize = 200;
const RATE_HISTORY: usize = 300;

type Inbound = (PeerStream, SocketAddr, Handshake);
type Routes = Arc<Mutex<HashMap<[u8; 20], UnboundedSender<Inbound>>>>;
type SharedBlocklist = Arc<Mutex<Option<Arc<BlockList>>>>;
type MappingRx = watch::Receiver<Option<std::result::Result<portmap::Mapping, String>>>;

struct Running {
    cmd: UnboundedSender<Command>,
    handle: JoinHandle<Result<()>>,
    info: Option<oneshot::Receiver<Vec<u8>>>,
}

struct Feed {
    id: FeedId,
    state: FeedState,
    title: Option<String>,
    /// The items already in the feed have been recorded as seen.
    primed: bool,
    last_fetch: Option<u64>,
    last_error: Option<String>,
    recent: Vec<String>,
    next_poll: Instant,
    fetching: bool,
}

struct PendingFetch(Arc<AtomicUsize>);

impl Drop for PendingFetch {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A network fetch finished; handled on the core task so only it touches entries.
enum Fetched {
    Torrent { source: String, dir: Option<PathBuf>, result: Result<Vec<u8>> },
    Feed { id: FeedId, result: Result<ParsedFeed> },
}

struct Entry {
    rec: Record,
    ih: InfoHash,
    meta: Option<Arc<Metainfo>>,
    magnet: Option<Magnet>,
    ui: Arc<RwLock<UiState>>,
    run: Option<Running>,
    down: Arc<RateLimiter>,
    up: Arc<RateLimiter>,
}

pub struct SessionHandle {
    state: Arc<RwLock<SessionState>>,
    tx: UnboundedSender<SessionCommand>,
    port: u16,
    webui: Option<SocketAddr>,
    webui_url: Option<String>,
    join: JoinHandle<Result<()>>,
}

impl SessionHandle {
    pub fn state(&self) -> Arc<RwLock<SessionState>> {
        Arc::clone(&self.state)
    }

    pub fn command(&self) -> UnboundedSender<SessionCommand> {
        self.tx.clone()
    }

    /// The TCP port the session actually listens on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Where the web UI listens, when it is enabled and bound.
    pub fn webui_addr(&self) -> Option<SocketAddr> {
        self.webui
    }

    /// The one-time URL (with the access token) of a web UI that has no password.
    pub fn webui_url(&self) -> Option<&str> {
        self.webui_url.as_deref()
    }

    /// Resolves once the session has shut down.
    pub async fn wait(self) -> Result<()> {
        self.join.await.context("session task panicked")?
    }
}

pub struct Session;

impl Session {
    /// Run a session until quit. With `ui` the TUI owns the terminal;
    /// otherwise a summary line is printed periodically and Ctrl-C quits.
    pub async fn run(settings: Settings, ui: bool) -> Result<()> {
        let mut handle = Self::start(settings).await?;
        let state = handle.state();
        let tx = handle.command();
        if let Some(url) = handle.webui_url() {
            println!("web UI: open {url}");
        }
        if ui {
            let thread = std::thread::spawn(move || {
                if let Err(e) = crate::tui::run_session_tui(state) {
                    tracing::error!("TUI exited with an error: {e}");
                }
            });
            let quit = tx.clone();
            let watcher = tokio::task::spawn_blocking(move || {
                let _ = thread.join();
                let _ = quit.send(SessionCommand::Quit);
            });
            let result = handle.wait().await;
            let _ = watcher.await;
            return result;
        }
        let mut every = tokio::time::interval(SUMMARY_EVERY);
        loop {
            tokio::select! {
                r = &mut handle.join => return r.context("session task panicked")?,
                _ = tokio::signal::ctrl_c() => { let _ = tx.send(SessionCommand::Quit); }
                _ = every.tick() => println!("{}", summary_line(&*state.read().await)),
            }
        }
    }

    pub async fn start(settings: Settings) -> Result<SessionHandle> {
        Self::start_in(Store::open(), settings).await
    }

    pub async fn start_in(store: Store, mut settings: Settings) -> Result<SessionHandle> {
        secure_password(&mut settings);
        if settings.schedule.utc_offset_minutes == 0 {
            if let Some(offset) = schedule::system_utc_offset_minutes() {
                settings.schedule.utc_offset_minutes = offset;
                if let Err(e) = store.save_settings(&settings) {
                    tracing::warn!("saving settings: {e:#}");
                }
            }
        }
        let (tx, rx) = unbounded_channel();
        let state = Arc::new(RwLock::new(SessionState {
            settings: settings.clone(),
            command_tx: Some(tx.clone()),
            ..Default::default()
        }));

        let ipc = crate::ipc::listen(&store, tx.clone())?;

        let (mut listener, mut port, ephemeral) = match TcpListener::bind(("0.0.0.0", settings.listen_port)).await {
            Ok(l) => {
                let port = l.local_addr()?.port();
                (l, port, settings.listen_port == 0)
            }
            Err(e) if settings.listen_port != 0 => {
                let l = TcpListener::bind(("0.0.0.0", 0))
                    .await
                    .with_context(|| format!("binding a listen port (port {} failed: {e})", settings.listen_port))?;
                let port = l.local_addr()?.port();
                state.write().await.log(
                    Level::Warn,
                    format!("port {} busy, listening on {port}", settings.listen_port),
                );
                (l, port, true)
            }
            Err(e) => return Err(e).context("binding a listen port"),
        };

        let mut udp = None;
        if settings.utp {
            let mut bound = UdpSocket::bind(("0.0.0.0", port)).await;
            for _ in 0..8 {
                if bound.is_ok() || !ephemeral {
                    break;
                }
                let l = TcpListener::bind(("0.0.0.0", 0)).await.context("binding a listen port")?;
                port = l.local_addr()?.port();
                listener = l;
                bound = UdpSocket::bind(("0.0.0.0", port)).await;
            }
            udp = Some(bound);
        }

        let router = Router {
            routes: Arc::default(),
            pending: Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES)),
            encryption: settings.encryption,
            blocklist: Arc::default(),
        };
        let blocklist = Arc::clone(&router.blocklist);
        let routes = Arc::clone(&router.routes);
        let mut accepts = vec![tokio::spawn(accept_loop(listener, router.clone()))];
        match bind_v6(port) {
            Ok(l) => accepts.push(tokio::spawn(accept_loop(l, router.clone()))),
            Err(e) => tracing::debug!(error = %e, "no separate IPv6 listener"),
        }

        let utp = match udp {
            Some(Ok(udp)) => {
                let sock = Arc::new(UtpSocket::bind(udp));
                accepts.push(tokio::spawn(utp_accept_loop(Arc::clone(&sock), router.clone())));
                Some(sock)
            }
            Some(Err(e)) => {
                state.write().await.log(Level::Warn, format!("uTP unavailable on UDP port {port}: {e}"));
                None
            }
            None => None,
        };

        let mut webui = None;
        let mut webui_url = None;
        let access = match (settings.webui.enabled, settings.webui.password.clone()) {
            (false, _) => None,
            (true, Some(pw)) => Some(crate::webui::Access::Password(pw)),
            (true, None) => match store.web_token() {
                Ok(t) => Some(crate::webui::Access::Token(t)),
                Err(e) => {
                    state.write().await.log(Level::Warn, format!("web UI disabled, cannot create its access token: {e:#}"));
                    None
                }
            },
        };
        if let Some(access) = access {
            match TcpListener::bind(crate::webui::bind_addr(&settings.webui)).await {
                Ok(l) => {
                    let addr = l.local_addr()?;
                    let msg = match &access {
                        crate::webui::Access::Password(_) => {
                            format!("web UI on port {} (all interfaces, password required): http://localhost:{}", addr.port(), addr.port())
                        }
                        crate::webui::Access::Token(t) => {
                            let url = format!("http://127.0.0.1:{}/?token={t}", addr.port());
                            webui_url = Some(url.clone());
                            format!("web UI (this machine only; set a password to allow other machines): open {url}")
                        }
                    };
                    accepts.push(tokio::spawn(crate::webui::serve(l, Arc::clone(&state), access)));
                    tracing::info!("{msg}");
                    state.write().await.log(Level::Info, msg);
                    webui = Some(addr);
                }
                Err(e) => {
                    let msg = format!("web UI unavailable on port {}: {e}", settings.webui.port);
                    tracing::warn!("{msg}");
                    state.write().await.log(Level::Warn, msg);
                }
            }
        }

        let lsd = if settings.lsd {
            match Lsd::start(port).await {
                Ok(l) => Some(l),
                Err(e) => {
                    state.write().await.log(Level::Warn, format!("local peer discovery unavailable: {e:#}"));
                    None
                }
            }
        } else {
            None
        };

        let dht = if settings.dht {
            match DhtNode::new(None).await {
                Ok(n) => {
                    let n = Arc::new(n);
                    let bg = Arc::clone(&n);
                    tokio::spawn(async move {
                        let routers: Vec<String> =
                            crate::dht::DEFAULT_ROUTERS.iter().map(|s| (*s).to_owned()).collect();
                        let up = bg.bootstrap(&routers).await;
                        tracing::info!(routers_up = up, "dht bootstrapped");
                    });
                    Some(n)
                }
                Err(e) => {
                    state.write().await.log(Level::Warn, format!("could not start DHT: {e}"));
                    None
                }
            }
        } else {
            None
        };

        let (mapper, pm_rx) = if settings.port_forwarding {
            let (h, rx) = portmap::spawn_renewal(port, MAPPING_LIFETIME);
            (Some(h), Some(rx))
        } else {
            (None, None)
        };

        {
            let mut st = state.write().await;
            st.port_status = if settings.port_forwarding {
                format!("port {port} · mapping...")
            } else {
                format!("port {port}")
            };
        }

        let (fetch_tx, fetch_rx) = unbounded_channel();
        let mut core = Core {
            gdown: RateLimiter::new(settings.download_limit),
            gup: RateLimiter::new(settings.upload_limit),
            store,
            settings,
            entries: Vec::new(),
            state: Arc::clone(&state),
            routes,
            port,
            utp,
            dht,
            lsd,
            mapping: None,
            feeds: Vec::new(),
            next_feed_id: 1,
            fetch_tx,
            fetch_slots: Arc::new(Semaphore::new(FETCH_SLOTS)),
            feed_slots: Arc::new(Semaphore::new(FEED_FETCH_SLOTS)),
            pending_fetches: Arc::new(AtomicUsize::new(0)),
            blocklist,
            last_eff: None,
            sched_paused: BTreeSet::new(),
            last_sample: Instant::now(),
            tasks: accepts.into_iter().chain(mapper).chain(ipc).collect(),
        };
        core.init().await;

        let join = tokio::spawn(core.run(rx, pm_rx, fetch_rx));
        Ok(SessionHandle { state, tx, port, webui, webui_url, join })
    }
}

fn bind_v6(port: u16) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    s.set_only_v6(true)?;
    s.set_reuse_address(true)?;
    s.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())?;
    s.listen(1024)?;
    s.set_nonblocking(true)?;
    TcpListener::from_std(s.into())
}

/// What the inbound classifiers share: the per-torrent routes, one bound on
/// handshakes in flight across every transport, and the encryption policy.
#[derive(Clone)]
struct Router {
    routes: Routes,
    pending: Arc<Semaphore>,
    encryption: EncryptionMode,
    blocklist: SharedBlocklist,
}

impl Router {
    fn spawn_classify(&self, stream: PeerStream, addr: SocketAddr, transport: &'static str) {
        let blocked = self.blocklist.lock().unwrap().as_ref().is_some_and(|b| b.contains(addr.ip()));
        if blocked {
            tracing::debug!(peer = %addr, transport, "inbound refused: blocked address");
            return;
        }
        let Ok(permit) = Arc::clone(&self.pending).try_acquire_owned() else {
            return;
        };
        let router = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let done = tokio::time::timeout(HANDSHAKE_TIMEOUT, router.classify(stream, addr, transport)).await;
            match done {
                Ok(Err(e)) => tracing::debug!(peer = %addr, transport, error = %e, "inbound refused"),
                Err(_) => tracing::debug!(peer = %addr, transport, "inbound handshake timed out"),
                Ok(Ok(())) => {}
            }
        });
    }

    /// A plaintext BitTorrent handshake starts with 0x13 and the protocol
    /// string; anything else is treated as the start of an MSE exchange.
    async fn classify(&self, mut stream: PeerStream, addr: SocketAddr, transport: &'static str) -> Result<()> {
        let mut prefix = [0u8; 20];
        stream.read_exact(&mut prefix).await?;
        let mode = self.encryption;
        let (stream, mut hs, crypto) = if prefix[0] == 19 && prefix[1..] == *b"BitTorrent protocol" {
            anyhow::ensure!(mode != EncryptionMode::Require, "plaintext peer refused: encryption required");
            let hs = handshake_incoming(&mut (&prefix[..]).chain(&mut stream)).await?;
            (stream, hs, "plain")
        } else {
            anyhow::ensure!(mode != EncryptionMode::Disabled, "encrypted peer refused: encryption disabled");
            let known: Vec<InfoHash> = self.routes.lock().unwrap().keys().map(|k| InfoHash(*k)).collect();
            let (mut s, ih) = mse::accept(stream, prefix.to_vec(), &known, mode).await?;
            let hs = handshake_incoming(&mut s).await?;
            anyhow::ensure!(hs.infohash == ih.0, "handshake names a different infohash than the encrypted exchange");
            let stream: PeerStream = Box::new(s);
            (stream, hs, "rc4")
        };
        let tx = self.routes.lock().unwrap().get(&hs.infohash).cloned();
        let tx = tx.context("no torrent for that infohash")?;
        tracing::debug!(peer = %addr, transport, crypto, "inbound classified");
        hs.utp = transport == "utp";
        hs.encrypted = crypto == "rc4";
        let _ = tx.send((stream, addr, hs));
        Ok(())
    }
}

async fn accept_loop(listener: TcpListener, router: Router) {
    loop {
        let Ok((stream, addr)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        let _ = stream.set_nodelay(true);
        router.spawn_classify(Box::new(stream), addr, "tcp");
    }
}

async fn utp_accept_loop(utp: Arc<UtpSocket>, router: Router) {
    loop {
        match utp.accept().await {
            Ok((stream, addr)) => router.spawn_classify(Box::new(stream), addr, "utp"),
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

struct Core {
    store: Store,
    settings: Settings,
    entries: Vec<Entry>,
    state: Arc<RwLock<SessionState>>,
    routes: Routes,
    port: u16,
    utp: Option<Arc<UtpSocket>>,
    dht: Option<Arc<DhtNode>>,
    lsd: Option<Lsd>,
    gdown: Arc<RateLimiter>,
    gup: Arc<RateLimiter>,
    mapping: Option<portmap::Mapping>,
    feeds: Vec<Feed>,
    next_feed_id: FeedId,
    fetch_tx: UnboundedSender<Fetched>,
    /// Bounds concurrent torrent downloads started by an add.
    fetch_slots: Arc<Semaphore>,
    /// Feed polls have their own slot so manual adds cannot starve them.
    feed_slots: Arc<Semaphore>,
    /// Add downloads waiting or running, capped at `MAX_PENDING_FETCHES`.
    pending_fetches: Arc<AtomicUsize>,
    blocklist: SharedBlocklist,
    /// What the schedule last applied.
    last_eff: Option<Effective>,
    /// Torrents the schedule paused, so only those are resumed when the slot ends.
    sched_paused: BTreeSet<String>,
    last_sample: Instant,
    /// Accept loop, port-mapping renewal and IPC listener.
    tasks: Vec<JoinHandle<()>>,
}

impl Core {
    async fn log(&self, level: Level, msg: impl Into<String>) {
        let msg = msg.into();
        match level {
            Level::Error => tracing::error!("{msg}"),
            Level::Warn => tracing::warn!("{msg}"),
            _ => tracing::info!("{msg}"),
        }
        self.state.write().await.log(level, msg);
    }

    async fn init(&mut self) {
        let (records, warnings) = self.store.load_records();
        for w in warnings {
            self.log(Level::Warn, w).await;
        }
        for rec in records {
            let id = rec.id.clone();
            match self.entry_from_record(rec) {
                Ok(e) => self.entries.push(e),
                Err(err) => self.log(Level::Warn, format!("skipping stored torrent {id}: {err:#}")).await,
            }
        }
        self.load_blocklist().await;
        self.apply_schedule().await;
        for e in &self.entries {
            let state = if e.rec.stopped { DownloadState::Stopped } else { DownloadState::Queued };
            stub_ui(e, state).await;
        }
        let (next, stored) = self.store.load_feeds();
        self.next_feed_id = next;
        for f in stored {
            let mut state = FeedState::with_seen(f.url, f.seen);
            state.include = f.include;
            state.exclude = f.exclude;
            state.dir = f.dir;
            self.feeds.push(Feed {
                id: f.id,
                state,
                title: f.title,
                primed: f.primed,
                last_fetch: None,
                last_error: None,
                recent: Vec::new(),
                next_poll: Instant::now() + Duration::from_secs(rand::thread_rng().gen_range(5..60)),
                fetching: false,
            });
        }
        self.rebalance().await;
        for q in self.store.take_queue() {
            self.add(q.source, q.dir).await;
        }
        self.aggregate().await;
    }

    fn entry_from_record(&self, mut rec: Record) -> Result<Entry> {
        let meta = match self.store.load_torrent(&rec.id) {
            Some(raw) => {
                rec.magnet = None;
                Some(Arc::new(Metainfo::from_bytes(&raw).context("parsing stored .torrent")?))
            }
            None => None,
        };
        let magnet = match (&meta, &rec.magnet) {
            (None, Some(uri)) => Some(Magnet::parse(uri).context("parsing stored magnet")?),
            _ => None,
        };
        let ih = match (&meta, &magnet) {
            (Some(m), _) => m.infohash,
            (None, Some(m)) => m.infohash,
            _ => anyhow::bail!("no metadata"),
        };
        Ok(make_entry(rec, ih, meta, magnet))
    }

    async fn run(
        mut self,
        mut rx: UnboundedReceiver<SessionCommand>,
        mut pm_rx: Option<MappingRx>,
        mut fetch_rx: UnboundedReceiver<Fetched>,
    ) -> Result<()> {
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_persist = std::time::Instant::now();
        loop {
            tokio::select! {
                cmd = rx.recv() => match cmd {
                    Some(SessionCommand::Quit) | None => break,
                    Some(cmd) => self.handle(cmd).await,
                },
                Some(done) = fetch_rx.recv() => self.on_fetched(done).await,
                _ = ticker.tick() => {
                    self.poll_feeds();
                    self.poll_entries().await;
                    self.apply_schedule().await;
                    self.rebalance().await;
                    if last_persist.elapsed() >= PERSIST_EVERY {
                        last_persist = std::time::Instant::now();
                        self.save_all().await;
                    }
                    self.aggregate().await;
                }
                changed = async {
                    match pm_rx.as_mut() {
                        Some(r) => r.changed().await.is_ok(),
                        None => std::future::pending().await,
                    }
                } => {
                    if changed {
                        let latest = pm_rx.as_ref().and_then(|r| r.borrow().clone());
                        self.on_mapping(latest).await;
                    } else {
                        pm_rx = None;
                    }
                }
            }
        }
        self.shutdown().await;
        Ok(())
    }

    async fn on_mapping(&mut self, latest: Option<std::result::Result<portmap::Mapping, String>>) {
        let status = match latest {
            Some(Ok(m)) => {
                let s = format!("port {} · {m}", self.port);
                self.mapping = Some(m);
                s
            }
            Some(Err(e)) => format!("port {} · not forwarded ({e})", self.port),
            None => return,
        };
        let changed = self.state.read().await.port_status != status;
        if changed {
            self.log(Level::Info, status.clone()).await;
            self.state.write().await.port_status = status;
        }
    }

    async fn handle(&mut self, cmd: SessionCommand) {
        match cmd {
            SessionCommand::AddFeed { url, include, exclude, dir } => self.add_feed(url, include, exclude, dir).await,
            SessionCommand::RemoveFeed(id) => {
                if let Some(i) = self.feeds.iter().position(|f| f.id == id) {
                    let f = self.feeds.remove(i);
                    self.save_feeds().await;
                    self.log(Level::Info, format!("unsubscribed from {}", redacted(&f.state.url))).await;
                }
            }
            SessionCommand::RefreshFeeds => {
                let now = Instant::now();
                for f in &mut self.feeds {
                    f.next_poll = now;
                }
            }
            SessionCommand::Add { source, dir } => self.add(source, dir).await,
            SessionCommand::Remove { id, delete_data } => self.remove(&id, delete_data).await,
            SessionCommand::MoveQueue { id, up } => self.move_queue(&id, up).await,
            SessionCommand::SetLabel { id, label } => {
                if let Some(i) = self.find(&id) {
                    self.entries[i].rec.label = label.map(|l| l.trim().to_owned()).filter(|l| !l.is_empty());
                    self.save(i).await;
                }
            }
            SessionCommand::MoveData { id, dir } => {
                if let Some(i) = self.find(&id) {
                    self.move_data(i, dir).await;
                }
            }
            SessionCommand::Start(id) => {
                if let Some(i) = self.find(&id) {
                    if self.entries[i].run.is_none() {
                        let queued = !self.entries[i].rec.stopped
                            && matches!(self.entries[i].ui.read().await.torrent.as_ref().map(|t| t.state), Some(DownloadState::Queued));
                        self.entries[i].rec.force = queued;
                        self.entries[i].rec.stopped = false;
                        stub_ui(&self.entries[i], DownloadState::Queued).await;
                        self.rebalance().await;
                        self.save(i).await;
                    }
                }
            }
            SessionCommand::Stop(id) | SessionCommand::Torrent(id, Command::Stop) => {
                if let Some(i) = self.find(&id) {
                    self.stop_entry(i, true).await;
                    self.save(i).await;
                    self.rebalance().await;
                }
            }
            SessionCommand::Torrent(id, c) => {
                if let Some(i) = self.find(&id) {
                    match &self.entries[i].run {
                        Some(run) => {
                            let _ = run.cmd.send(c);
                        }
                        None if c == Command::Recheck => {
                            self.log(Level::Info, "recheck needs a running torrent; start it first").await;
                        }
                        None => {}
                    }
                }
            }
            SessionCommand::SetTorrentLimits { id, download, upload } => {
                if let Some(i) = self.find(&id) {
                    let e = &mut self.entries[i];
                    e.down.set_rate(download);
                    e.up.set_rate(upload);
                    e.rec.download_limit = download;
                    e.rec.upload_limit = upload;
                    self.save(i).await;
                }
            }
            SessionCommand::SetSettings(s) => self.set_settings(s).await,
            SessionCommand::Quit => {}
        }
        self.rebalance().await;
    }

    fn find(&self, id: &str) -> Option<usize> {
        self.entries.iter().position(|e| e.rec.id == id)
    }

    async fn add(&mut self, source: String, dir: Option<PathBuf>) {
        if is_http(&source) {
            let pending = Arc::clone(&self.pending_fetches);
            if pending.fetch_add(1, Ordering::AcqRel) >= MAX_PENDING_FETCHES {
                pending.fetch_sub(1, Ordering::AcqRel);
                self.log(Level::Warn, format!("too many pending downloads, not adding {}", shown(&source))).await;
                return;
            }
            let guard = PendingFetch(pending);
            let shown_source = source.clone();
            self.spawn_fetch(Arc::clone(&self.fetch_slots), shown_source, MAX_TORRENT_BYTES, move |tx, result| {
                drop(guard);
                let _ = tx.send(Fetched::Torrent { source, dir, result });
            });
            return;
        }
        self.add_loaded(source, None, dir).await;
    }

    /// Add a torrent from a path, magnet, or the bytes already downloaded from `source`.
    async fn add_loaded(&mut self, source: String, raw: Option<Vec<u8>>, dir: Option<PathBuf>) {
        let dir = dir.unwrap_or_else(|| self.settings.download_dir.clone());
        match self.prepare_add(&source, raw, dir) {
            Ok(entry) => {
                let name = match (&entry.meta, &entry.magnet) {
                    (Some(m), _) => m.name.clone(),
                    (_, Some(m)) => m.display_name.clone().unwrap_or_else(|| entry.rec.id.clone()),
                    _ => entry.rec.id.clone(),
                };
                self.entries.push(entry);
                let i = self.entries.len() - 1;
                self.entries[i].rec.queue = i as u64;
                stub_ui(&self.entries[i], DownloadState::Queued).await;
                self.rebalance().await;
                self.save(i).await;
                self.log(Level::Info, format!("added {name}")).await;
            }
            Err(e) => self.log(Level::Error, format!("cannot add {}: {e:#}", shown(&source))).await,
        }
    }

    /// Download `url` (at most `max` bytes, `slots` at a time) off the core task.
    fn spawn_fetch(&self, slots: Arc<Semaphore>, url: String, max: usize, done: impl FnOnce(UnboundedSender<Fetched>, Result<Vec<u8>>) + Send + 'static) {
        let tx = self.fetch_tx.clone();
        tokio::spawn(async move {
            let _slot = slots.acquire_owned().await;
            let result = match tokio::time::timeout(FETCH_TIMEOUT, crate::webseed::get_capped(&url, max)).await {
                Ok(r) => r.map_err(|e| anyhow!("{e}")),
                Err(_) => Err(anyhow!("timed out")),
            };
            done(tx, result);
        });
    }

    async fn on_fetched(&mut self, done: Fetched) {
        match done {
            Fetched::Torrent { source, dir, result } => match result {
                Ok(raw) => self.add_loaded(source, Some(raw), dir).await,
                Err(e) => self.log(Level::Error, format!("cannot add {}: {e:#}", shown(&source))).await,
            },
            Fetched::Feed { id, result } => self.on_feed_fetched(id, result).await,
        }
    }

    async fn add_feed(&mut self, url: String, include: Vec<String>, exclude: Vec<String>, dir: Option<PathBuf>) {
        let url = url.trim().to_owned();
        let valid = is_http(&url) && url::Url::parse(&url).is_ok_and(|u| u.host_str().is_some());
        if !valid {
            self.log(Level::Error, format!("cannot subscribe to {}: not an http(s) URL", shown(&url))).await;
            return;
        }
        if self.feeds.iter().any(|f| f.state.url == url) {
            self.log(Level::Warn, format!("already subscribed to {}", redacted(&url))).await;
            return;
        }
        if self.feeds.len() >= MAX_FEEDS {
            self.log(Level::Error, format!("cannot subscribe: at most {MAX_FEEDS} feeds")).await;
            return;
        }
        let clean = |l: Vec<String>| l.into_iter().map(|t| t.trim().to_owned()).filter(|t| !t.is_empty()).collect();
        let mut state = FeedState::new(url.clone());
        state.include = clean(include);
        state.exclude = clean(exclude);
        state.dir = dir;
        let id = self.next_feed_id;
        self.next_feed_id += 1;
        self.feeds.push(Feed {
            id,
            state,
            title: None,
            primed: false,
            last_fetch: None,
            last_error: None,
            recent: Vec::new(),
            next_poll: Instant::now() + feed_delay(),
            fetching: true,
        });
        self.save_feeds().await;
        self.fetch_feed(id, url.clone());
        self.log(Level::Info, format!("subscribed to {}", redacted(&url))).await;
    }

    fn fetch_feed(&self, id: FeedId, url: String) {
        self.spawn_fetch(Arc::clone(&self.feed_slots), url.clone(), MAX_FEED_BYTES, move |tx, result| {
            let result = result.and_then(|body| rss::parse_at(&String::from_utf8_lossy(&body), &url));
            let _ = tx.send(Fetched::Feed { id, result });
        });
    }

    fn poll_feeds(&mut self) {
        let now = Instant::now();
        for i in 0..self.feeds.len() {
            let f = &mut self.feeds[i];
            if f.fetching || f.next_poll > now {
                continue;
            }
            f.fetching = true;
            f.next_poll = now + feed_delay();
            let (id, url) = (f.id, f.state.url.clone());
            self.fetch_feed(id, url);
        }
    }

    async fn on_feed_fetched(&mut self, id: FeedId, result: Result<ParsedFeed>) {
        let Some(i) = self.feeds.iter().position(|f| f.id == id) else {
            return;
        };
        let f = &mut self.feeds[i];
        f.fetching = false;
        let name = redacted(&f.state.url);
        let mut matches = Vec::new();
        let mut note = None;
        match result {
            Err(e) => {
                note = Some((Level::Warn, format!("feed {name}: {e:#}")));
                f.last_error = Some(format!("{e:#}"));
            }
            Ok(parsed) => {
                f.last_error = None;
                f.last_fetch = Some(unix_now());
                if let Some(t) = parsed.title.filter(|t| !t.trim().is_empty()) {
                    f.title = Some(clip(t.trim()));
                }
                if f.primed {
                    matches = f.state.new_matches(&parsed.items);
                    for (title, _) in &matches {
                        f.recent.insert(0, clip(title));
                    }
                    f.recent.truncate(MAX_RECENT);
                } else {
                    let (include, exclude) = (std::mem::take(&mut f.state.include), std::mem::take(&mut f.state.exclude));
                    let n = f.state.new_matches(&parsed.items).len();
                    f.state.include = include;
                    f.state.exclude = exclude;
                    f.primed = true;
                    note = Some((Level::Info, format!("feed {name}: watching {n} existing items")));
                }
            }
        }
        let dir = f.state.dir.clone();
        self.save_feeds().await;
        if let Some((level, msg)) = note {
            self.log(level, msg).await;
        }
        for (title, source) in matches {
            if source.starts_with("magnet:") || is_http(&source) {
                self.log(Level::Info, format!("feed {name}: new item {}", clip(&title))).await;
                self.add(source, dir.clone()).await;
            } else {
                self.log(Level::Warn, format!("feed {name}: ignoring item {} with a non-web link", clip(&title))).await;
            }
        }
    }

    async fn save_feeds(&self) {
        let stored: Vec<StoredFeed> = self
            .feeds
            .iter()
            .map(|f| StoredFeed {
                id: f.id,
                url: f.state.url.clone(),
                include: f.state.include.clone(),
                exclude: f.state.exclude.clone(),
                dir: f.state.dir.clone(),
                title: f.title.clone(),
                primed: f.primed,
                seen: f.state.seen().map(str::to_owned).collect(),
            })
            .collect();
        if let Err(e) = self.store.save_feeds(self.next_feed_id, &stored) {
            self.log(Level::Error, format!("saving feeds: {e:#}")).await;
        }
    }

    fn prepare_add(&self, source: &str, raw: Option<Vec<u8>>, dir: PathBuf) -> Result<Entry> {
        let mut rec = Record {
            id: String::new(),
            dir,
            added_at: unix_now(),
            stopped: false,
            uploaded: 0,
            download_limit: 0,
            upload_limit: 0,
            priorities: None,
            queue: 0,
            force: false,
            snapshot: None,
            magnet: None,
            label: None,
            sequential: false,
            moved: false,
            trackers: None,
            super_seed: false,
        };
        let (ih, meta, magnet) = if source.starts_with("magnet:") {
            let m = Magnet::parse(source)?;
            rec.magnet = Some(source.to_owned());
            (m.infohash, None, Some(m))
        } else {
            let raw = match raw {
                Some(raw) => raw,
                None => std::fs::read(source).with_context(|| format!("reading {source}"))?,
            };
            let meta = Metainfo::from_bytes(&raw).context("parsing .torrent file")?;
            rec.id = meta.infohash.to_hex();
            if self.find(&rec.id).is_none() {
                self.store.save_torrent(&rec.id, &raw)?;
            }
            (meta.infohash, Some(Arc::new(meta)), None)
        };
        rec.id = ih.to_hex();
        if self.find(&rec.id).is_some() {
            anyhow::bail!("already in the session");
        }
        Ok(make_entry(rec, ih, meta, magnet))
    }

    async fn start_entry(&mut self, i: usize) {
        let e = &mut self.entries[i];
        if e.run.is_some() {
            return;
        }
        e.rec.stopped = false;
        if e.meta.is_some() {
            stub_ui(e, DownloadState::Connecting).await;
        }
        let (cmd_tx, cmd_rx) = unbounded_channel();
        let (in_tx, in_rx) = unbounded_channel();
        let opts = EngineOptions {
            seed_after_complete: true,
            ratio_target: self.settings.ratio_target,
            uploaded_so_far: e.rec.uploaded,
            limits: Limits {
                down: vec![Arc::clone(&self.gdown), Arc::clone(&e.down)],
                up: vec![Arc::clone(&self.gup), Arc::clone(&e.up)],
            },
            max_peers: self.settings.max_peers,
            auto_unchoke: false,
            dht: self.dht.clone(),
            dht_enabled: self.settings.dht,
            inbound: Some(in_rx),
            encryption: self.settings.encryption,
            utp: self.utp.clone(),
            port: self.port,
            file_priorities: e.rec.priorities.clone(),
            extra_peers: match &self.lsd {
                Some(l) if e.meta.as_ref().is_none_or(|m| !m.private) => Some(l.register(e.ih.0)),
                _ => None,
            },
            sequential: e.rec.sequential,
            blocklist: self.blocklist.lock().unwrap().clone(),
            trackers: e.rec.trackers.clone(),
            super_seed: e.rec.super_seed,
        };
        let ui = Arc::clone(&e.ui);
        let dir = e.rec.dir.clone();
        let (handle, info) = match (&e.meta, &e.magnet) {
            (Some(meta), _) => {
                let engine = Engine::with_options(Arc::clone(meta), ui, cmd_rx, opts);
                (tokio::spawn(engine.run(dir)), None)
            }
            (None, Some(m)) => {
                let (itx, irx) = oneshot::channel();
                let fut = engine::run_magnet_with_options(m.clone(), dir, ui, cmd_rx, opts, Some(itx));
                (tokio::spawn(fut), Some(irx))
            }
            (None, None) => return,
        };
        self.routes.lock().unwrap().insert(e.ih.0, in_tx);
        e.run = Some(Running { cmd: cmd_tx, handle, info });
    }

    /// Ask the engine to stop and wait for it. `mark` records the stop so the
    /// torrent stays stopped across restarts; a quit does not.
    async fn stop_entry(&mut self, i: usize, mark: bool) {
        let e = &mut self.entries[i];
        if let Some(run) = e.run.take() {
            let _ = run.cmd.send(Command::Stop);
            self.routes.lock().unwrap().remove(&e.ih.0);
            if let Some(l) = &self.lsd {
                l.unregister(&e.ih.0);
            }
            let mut handle = run.handle;
            if tokio::time::timeout(STOP_TIMEOUT, &mut handle).await.is_err() {
                handle.abort();
                if let Some(t) = &mut e.ui.write().await.torrent {
                    t.state = DownloadState::Stopped;
                }
            }
        }
        refresh(e).await;
        if mark {
            e.rec.stopped = true;
            e.rec.force = false;
        }
    }

    async fn is_candidate(e: &Entry) -> bool {
        !e.rec.stopped
            && !matches!(e.ui.read().await.torrent.as_ref().map(|t| t.state), Some(DownloadState::Error))
    }

    async fn is_complete(e: &Entry) -> bool {
        let ui = e.ui.read().await;
        let done = ui.torrent.as_ref().is_some_and(|t| {
            matches!(t.state, DownloadState::Seeding | DownloadState::Complete)
                || (t.piece_count > 0 && t.verified_pieces == t.piece_count)
        });
        done || (e.run.is_none() && e.rec.snapshot.as_ref().is_some_and(|s| s.complete))
    }

    /// Start and stop torrents so the queue limits hold: forced torrents
    /// always run and use no slot, the rest run in queue order while slots remain.
    async fn rebalance(&mut self) {
        let (max_dl, max_all) = (self.settings.max_active_downloads, self.settings.max_active_torrents);
        let n = self.entries.len();
        let off = self.last_eff.is_some_and(|e| e.uploads_paused);
        let (mut cand, mut done, mut plan) = (vec![false; n], vec![false; n], vec![false; n]);
        let (mut dl, mut all) = (0, 0);
        for i in 0..n {
            let e = &self.entries[i];
            cand[i] = !off && Self::is_candidate(e).await;
            if !cand[i] {
                continue;
            }
            done[i] = Self::is_complete(e).await;
            if e.rec.force {
                plan[i] = true;
            }
        }
        for i in 0..n {
            if !cand[i] || plan[i] {
                continue;
            }
            let fits = (max_all == 0 || all < max_all) && (done[i] || max_dl == 0 || dl < max_dl);
            if fits {
                plan[i] = true;
                all += 1;
                dl += !done[i] as usize;
            }
        }
        for i in 0..n {
            if !cand[i] {
                continue;
            }
            let running = self.entries[i].run.is_some();
            if plan[i] && !running {
                self.start_entry(i).await;
                self.save(i).await;
            } else if !plan[i] {
                if running {
                    self.stop_entry(i, false).await;
                    self.save(i).await;
                }
                stub_ui(&self.entries[i], DownloadState::Queued).await;
            }
        }
    }

    /// Move a torrent's files to `dir` and keep it going from there. The
    /// engine is stopped for the move and rebalance restarts it afterwards.
    async fn move_data(&mut self, i: usize, dir: PathBuf) {
        let id = self.entries[i].rec.id.clone();
        let Some(meta) = self.entries[i].meta.clone() else {
            self.log(Level::Warn, format!("cannot move {id}: no metadata yet, wait until it has been fetched")).await;
            return;
        };
        let from = self.entries[i].rec.dir.clone();
        if dir == from {
            return;
        }
        self.stop_entry(i, false).await;
        let (src, dst) = (from.clone(), dir.clone());
        let moved = tokio::task::spawn_blocking(move || move_files(&meta, &src, &dst))
            .await
            .map_err(anyhow::Error::from)
            .and_then(|r| r);
        match moved {
            Ok(()) => {
                let e = &mut self.entries[i];
                e.rec.dir = dir.clone();
                if let Some(t) = &mut e.ui.write().await.torrent {
                    t.download_dir = dir.display().to_string();
                }
                self.save(i).await;
                self.log(Level::Info, format!("moved {id} to {}", dir.display())).await;
            }
            Err(err) => self.log(Level::Error, format!("cannot move {id} to {}: {err:#}", dir.display())).await,
        }
        self.rebalance().await;
    }

    async fn move_queue(&mut self, id: &str, up: bool) {
        let Some(i) = self.find(id) else { return };
        if self.entries[i].rec.stopped {
            return;
        }
        let mut others = self.entries.iter().enumerate().filter(|(_, e)| !e.rec.stopped).map(|(j, _)| j);
        let j = if up {
            others.take_while(|j| *j < i).last()
        } else {
            others.find(|j| *j > i)
        };
        let Some(j) = j else { return };
        self.entries.swap(i, j);
        for k in 0..self.entries.len() {
            self.entries[k].rec.queue = k as u64;
            self.save(k).await;
        }
        self.rebalance().await;
    }

    async fn remove(&mut self, id: &str, delete_data: bool) {
        let Some(i) = self.find(id) else { return };
        self.stop_entry(i, false).await;
        let e = self.entries.remove(i);
        if delete_data {
            if let Some(meta) = &e.meta {
                delete_files(meta, &e.rec.dir);
            }
        }
        self.store.remove(id);
        self.rebalance().await;
        self.log(
            Level::Info,
            format!("removed {}{}", e.rec.id, if delete_data { " and its files" } else { "" }),
        )
        .await;
    }

    async fn set_settings(&mut self, mut new: Settings) {
        secure_password(&mut new);
        let old = std::mem::replace(&mut self.settings, new.clone());
        if new.max_peers != old.max_peers {
            for e in &self.entries {
                if let Some(run) = &e.run {
                    let _ = run.cmd.send(Command::SetMaxPeers(new.max_peers));
                }
            }
        }
        if let Err(e) = self.store.save_settings(&new) {
            self.log(Level::Error, format!("saving settings: {e:#}")).await;
        }
        if new.listen_port != old.listen_port || new.dht != old.dht || new.lsd != old.lsd || new.port_forwarding != old.port_forwarding {
            self.log(Level::Info, "port, DHT, local discovery and port forwarding changes take effect after restart").await;
        }
        if new.encryption != old.encryption || new.utp != old.utp || new.webui != old.webui {
            self.log(Level::Info, "web UI, encryption and uTP changes take effect after restart").await;
        }
        if new.ratio_target != old.ratio_target {
            self.log(Level::Info, "ratio target applies to torrents started from now on").await;
        }
        self.state.write().await.settings = new;
        if self.settings.blocklist != old.blocklist {
            self.load_blocklist().await;
            self.log(Level::Info, "block list applies to inbound peers now and to running torrents after they restart").await;
        }
        self.apply_schedule().await;
        self.rebalance().await;
    }

    async fn load_blocklist(&mut self) {
        let Some(path) = self.settings.blocklist.clone() else {
            *self.blocklist.lock().unwrap() = None;
            self.state.write().await.blocklist_ranges = 0;
            return;
        };
        let p = path.clone();
        let loaded = tokio::task::spawn_blocking(move || BlockList::load(p))
            .await
            .map_err(anyhow::Error::from)
            .and_then(|r| r);
        let list = match loaded {
            Ok((list, stats)) => {
                self.log(
                    Level::Info,
                    format!(
                        "block list {}: {} ranges, {} lines skipped",
                        path.display(),
                        stats.ranges,
                        stats.skipped_lines
                    ),
                )
                .await;
                Some(Arc::new(list))
            }
            Err(e) => {
                self.log(Level::Error, format!("block list not loaded: {e:#}")).await;
                None
            }
        };
        self.state.write().await.blocklist_ranges = list.as_ref().map_or(0, |l| l.len());
        *self.blocklist.lock().unwrap() = list;
    }

    /// Apply the schedule's current slot: global rates, plus pausing downloads or
    /// stopping every engine, remembering only what the schedule itself paused.
    async fn apply_schedule(&mut self) {
        let sched = &self.settings.schedule;
        let eff = sched.effective_limits(unix_now(), self.settings.download_limit, self.settings.upload_limit);
        self.gdown.set_rate(eff.down);
        self.gup.set_rate(eff.up);
        let prev = self.last_eff.replace(eff);
        if prev != Some(eff) && (prev.is_some() || self.settings.schedule.enabled) {
            self.log(Level::Info, format!("schedule: {}", describe(&eff))).await;
        }
        for i in 0..self.entries.len() {
            let id = self.entries[i].rec.id.clone();
            let running = self.entries[i].run.is_some();
            if !running {
                self.sched_paused.remove(&id);
            }
            let facts = TorrentFacts {
                running,
                complete: Self::is_complete(&self.entries[i]).await,
                state: self.entries[i].ui.read().await.torrent.as_ref().map(|t| t.state),
                sched_paused: self.sched_paused.contains(&id),
            };
            match schedule_action(&eff, &facts) {
                ScheduleAction::None => {}
                ScheduleAction::Pause => {
                    if let Some(run) = &self.entries[i].run {
                        let _ = run.cmd.send(Command::Pause);
                        self.sched_paused.insert(id);
                    }
                }
                ScheduleAction::Resume => {
                    if let Some(run) = &self.entries[i].run {
                        let _ = run.cmd.send(Command::Resume);
                    }
                    self.sched_paused.remove(&id);
                }
                ScheduleAction::Stop => {
                    self.stop_entry(i, false).await;
                    stub_ui(&self.entries[i], DownloadState::Queued).await;
                    self.sched_paused.remove(&id);
                }
            }
        }
    }

    async fn poll_entries(&mut self) {
        for i in 0..self.entries.len() {
            let mut dirty = false;
            let e = &mut self.entries[i];

            let fetched = match e.run.as_mut().and_then(|r| r.info.as_mut()) {
                Some(rx) => match rx.try_recv() {
                    Ok(info) => Some(Some(info)),
                    Err(oneshot::error::TryRecvError::Closed) => Some(None),
                    Err(oneshot::error::TryRecvError::Empty) => None,
                },
                None => None,
            };
            if let Some(info) = fetched {
                if let Some(r) = &mut e.run {
                    r.info = None;
                }
                if let Some(info) = info {
                    let trackers = e.magnet.as_ref().map(|m| m.trackers.clone()).unwrap_or_default();
                    match store_metadata(&self.store, &e.rec.id, &info, &trackers) {
                        Ok(meta) => {
                            if meta.private {
                                if let Some(l) = &self.lsd {
                                    l.unregister(&e.ih.0);
                                }
                            }
                            e.meta = Some(Arc::new(meta));
                            e.rec.magnet = None;
                            dirty = true;
                        }
                        Err(err) => tracing::warn!("keeping fetched metadata in memory only: {err:#}"),
                    }
                }
            }

            if e.run.as_ref().is_some_and(|r| r.handle.is_finished()) {
                let run = e.run.take().unwrap();
                self.routes.lock().unwrap().remove(&e.ih.0);
                if let Some(l) = &self.lsd {
                    l.unregister(&e.ih.0);
                }
                let result = run.handle.await;
                let mut ui = e.ui.write().await;
                match result {
                    Ok(Ok(())) => {
                        if ui.torrent.as_ref().is_some_and(|t| t.state == DownloadState::Stopped) {
                            e.rec.stopped = true;
                            e.rec.force = false;
                        }
                    }
                    other => {
                        let why = match other {
                            Ok(Err(err)) => format!("{err:#}"),
                            Err(join) => join.to_string(),
                            Ok(Ok(())) => unreachable!(),
                        };
                        ui.log(Level::Error, why);
                        if let Some(t) = &mut ui.torrent {
                            t.state = DownloadState::Error;
                        }
                    }
                }
                drop(ui);
                dirty = true;
            }

            let before = (e.rec.priorities.clone(), e.rec.sequential, e.rec.trackers.clone(), e.rec.super_seed);
            refresh(e).await;
            let finished = !e.rec.moved
                && e.run.is_some()
                && matches!(
                    e.ui.read().await.torrent.as_ref().map(|t| t.state),
                    Some(DownloadState::Seeding | DownloadState::Complete)
                );
            if finished {
                e.rec.moved = true;
            }
            if dirty
                || finished
                || (e.rec.priorities.clone(), e.rec.sequential, e.rec.trackers.clone(), e.rec.super_seed) != before
            {
                self.save(i).await;
            }
            if finished {
                if self.settings.notifications {
                    let name = self.entries[i].ui.read().await.torrent.as_ref().map(|t| t.name.clone());
                    notify_complete(name.as_deref().unwrap_or(&self.entries[i].rec.id));
                }
                if let Some(to) = self.settings.move_completed_dir.clone() {
                    self.move_data(i, to).await;
                }
            }
        }
    }

    async fn aggregate(&mut self) {
        let mut views = Vec::with_capacity(self.entries.len());
        let (mut down, mut up) = (0.0, 0.0);
        let mut position = 0;
        for e in &self.entries {
            let mut ui = e.ui.read().await.clone();
            ui.command_tx = None;
            let total = ui.torrent.as_ref().map_or(0, |t| t.total_length);
            if let Some(t) = &ui.torrent {
                down += t.download_rate;
                up += t.upload_rate;
            }
            views.push(TorrentView {
                id: e.rec.id.clone(),
                ui,
                uploaded: e.rec.uploaded,
                ratio: if total > 0 { e.rec.uploaded as f64 / total as f64 } else { 0.0 },
                download_limit: e.rec.download_limit,
                upload_limit: e.rec.upload_limit,
                added_at: e.rec.added_at,
                queue_position: if e.rec.stopped {
                    None
                } else {
                    position += 1;
                    Some(position - 1)
                },
                label: e.rec.label.clone(),
            });
        }
        let mut st = self.state.write().await;
        st.feeds = self
            .feeds
            .iter()
            .map(|f| FeedView {
                id: f.id,
                url: f.state.url.clone(),
                title: f.title.clone(),
                include: f.state.include.clone(),
                exclude: f.state.exclude.clone(),
                dir: f.state.dir.clone(),
                last_fetch: f.last_fetch,
                last_error: f.last_error.clone(),
                recent: f.recent.clone(),
            })
            .collect();
        st.torrents = views;
        st.download_rate = down;
        st.upload_rate = up;
        if self.last_sample.elapsed() >= Duration::from_secs(1) {
            self.last_sample = Instant::now();
            push_sample(&mut st.rate_history, (down, up));
        }
    }

    async fn save(&self, i: usize) {
        if let Err(e) = self.store.save_record(&self.entries[i].rec) {
            self.log(Level::Error, format!("saving {}: {e:#}", self.entries[i].rec.id)).await;
        }
    }

    async fn save_all(&mut self) {
        for i in 0..self.entries.len() {
            refresh(&mut self.entries[i]).await;
            self.save(i).await;
        }
    }

    async fn shutdown(&mut self) {
        for e in &self.entries {
            if let Some(run) = &e.run {
                let _ = run.cmd.send(Command::Stop);
            }
        }
        for i in 0..self.entries.len() {
            self.stop_entry(i, false).await;
        }
        self.save_all().await;
        let settings = self.settings.clone();
        if let Err(e) = self.store.save_settings(&settings) {
            tracing::error!("saving settings: {e:#}");
        }
        if let Some(m) = &self.mapping {
            let _ = tokio::time::timeout(Duration::from_secs(3), portmap::unmap(m, self.port)).await;
        }
        for t in &self.tasks {
            t.abort();
        }
        let _ = std::fs::remove_file(self.store.socket_path());
        self.aggregate().await;
        self.state.write().await.shutdown = true;
    }
}

fn push_sample(history: &mut Vec<(f64, f64)>, sample: (f64, f64)) {
    history.push(sample);
    if history.len() > RATE_HISTORY {
        history.drain(..history.len() - RATE_HISTORY);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ScheduleAction {
    None,
    Pause,
    Resume,
    Stop,
}

struct TorrentFacts {
    running: bool,
    complete: bool,
    state: Option<DownloadState>,
    sched_paused: bool,
}

/// What the current slot asks of one torrent. Idempotent, so it can run every tick.
fn schedule_action(eff: &Effective, t: &TorrentFacts) -> ScheduleAction {
    if eff.uploads_paused {
        return if t.running { ScheduleAction::Stop } else { ScheduleAction::None };
    }
    if eff.downloads_paused {
        let pausable = t.running && !t.complete && t.state == Some(DownloadState::Downloading) && !t.sched_paused;
        return if pausable { ScheduleAction::Pause } else { ScheduleAction::None };
    }
    if t.sched_paused {
        ScheduleAction::Resume
    } else {
        ScheduleAction::None
    }
}

fn describe(e: &Effective) -> String {
    let rate = |n: u64| if n == 0 { "unlimited".to_owned() } else { format!("{}/s", human_bytes(n)) };
    if e.uploads_paused {
        "all transfers off".to_owned()
    } else if e.downloads_paused {
        format!("seed only, up {}", rate(e.up))
    } else {
        format!("down {}, up {}", rate(e.down), rate(e.up))
    }
}

/// An AppleScript string literal body: backslash and quote escaped, line breaks and other control characters flattened to spaces.
fn applescript_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

fn notify_complete(name: &str) {
    const TITLE: &str = "torrust: download complete";
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("osascript");
        c.arg("-e").arg(format!(
            "display notification \"{}\" with title \"{TITLE}\"",
            applescript_escape(name)
        ));
        c
    } else if cfg!(target_os = "linux") {
        let mut c = std::process::Command::new("notify-send");
        c.arg("--").arg(TITLE).arg(name.replace(|c: char| c.is_control(), " "));
        c
    } else {
        return;
    };
    cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    if let Ok(mut child) = cmd.spawn() {
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}

fn make_entry(rec: Record, ih: InfoHash, meta: Option<Arc<Metainfo>>, magnet: Option<Magnet>) -> Entry {
    Entry {
        down: RateLimiter::new(rec.download_limit),
        up: RateLimiter::new(rec.upload_limit),
        ui: Arc::default(),
        run: None,
        rec,
        ih,
        meta,
        magnet,
    }
}

/// Give a torrent that is not publishing a row to show, from its last
/// known progress if it has any.
async fn stub_ui(e: &Entry, state: DownloadState) {
    let mut ui = e.ui.write().await;
    if let Some(t) = &mut ui.torrent {
        t.state = state;
        return;
    }
    let mut t = TorrentSummary {
        infohash: e.rec.id.clone(),
        state,
        download_dir: e.rec.dir.display().to_string(),
        uploaded: e.rec.uploaded,
        sequential: e.rec.sequential,
        super_seeding: e.rec.super_seed,
        ..Default::default()
    };
    let snap = e.rec.snapshot.as_ref();
    match (&e.meta, &e.magnet) {
        (Some(meta), _) => {
            t.name = meta.name.clone();
            t.total_length = meta.total_length;
            t.piece_length = meta.piece_length;
            t.piece_count = meta.piece_count() as u32;
            t.trackers = e.rec.trackers.clone().unwrap_or_else(|| meta.announce_list.clone());
            let snap = snap.filter(|s| s.piece_count == t.piece_count);
            t.files = meta
                .files
                .iter()
                .enumerate()
                .map(|(i, (path, length))| FileSummary {
                    index: i,
                    path: path.iter().map(|c| c.to_string_lossy().into_owned()).collect::<Vec<_>>().join("/"),
                    length,
                    downloaded: snap.and_then(|s| s.files.get(i).copied()).unwrap_or(0).min(length),
                    wanted: priority_at(e, i) != FilePriority::Skip,
                    priority: priority_at(e, i),
                })
                .collect();
            if let Some(s) = snap {
                t.verified_pieces = s.verified_pieces;
                t.downloaded = s.downloaded;
                t.progress = s.progress;
            }
        }
        (_, Some(m)) => t.name = m.display_name.clone().unwrap_or_else(|| e.rec.id.clone()),
        _ => return,
    }
    ui.torrent = Some(t);
}

fn priority_at(e: &Entry, i: usize) -> FilePriority {
    e.rec.priorities.as_ref().and_then(|p| p.get(i).copied()).unwrap_or_default()
}

/// Pull the engine's upload total, file priorities and progress into the record.
async fn refresh(e: &mut Entry) {
    let ui = e.ui.read().await;
    if let Some(t) = &ui.torrent {
        e.rec.uploaded = e.rec.uploaded.max(t.uploaded);
        e.rec.sequential = t.sequential;
        e.rec.super_seed = t.super_seeding;
        if let Some(meta) = &e.meta {
            e.rec.trackers = Some(t.trackers.clone()).filter(|l| *l != meta.announce_list);
        }
        if !t.files.is_empty() {
            e.rec.priorities = Some(t.files.iter().map(|f| f.priority).collect());
            e.rec.snapshot = Some(Snapshot {
                name: t.name.clone(),
                total_length: t.total_length,
                piece_count: t.piece_count,
                verified_pieces: t.verified_pieces,
                downloaded: t.downloaded,
                progress: t.progress,
                complete: matches!(t.state, DownloadState::Seeding | DownloadState::Complete)
                    || (t.piece_count > 0 && t.verified_pieces == t.piece_count),
                files: t.files.iter().map(|f| f.downloaded).collect(),
            });
        }
    }
}

/// Persist a magnet's fetched info dict as a `.torrent`, keeping the magnet's
/// trackers, and parse it back.
fn store_metadata(store: &Store, id: &str, info: &[u8], trackers: &[String]) -> Result<Metainfo> {
    let mut d = BTreeMap::new();
    d.insert(b"info".to_vec(), bencode::decode(info).context("decoding fetched info")?);
    if !trackers.is_empty() {
        let list = trackers
            .iter()
            .map(|t| Value::List(vec![Value::Bytes(t.as_bytes().to_vec())]))
            .collect();
        d.insert(b"announce-list".to_vec(), Value::List(list));
    }
    let raw = bencode::encode(&Value::Dict(d));
    let meta = Metainfo::from_bytes(&raw).context("parsing fetched metadata")?;
    store.save_torrent(id, &raw)?;
    Ok(meta)
}

/// Delete exactly the files the torrent describes under `dir`, then any
/// directories that leave empty. Nothing else is touched.
fn delete_files(meta: &Metainfo, dir: &Path) {
    for (path, _) in meta.files.iter() {
        if is_plain(path) {
            let _ = std::fs::remove_file(dir.join(path));
        }
    }
    prune_dirs(meta, dir);
}

fn is_plain(path: &Path) -> bool {
    path.components().all(|c| matches!(c, Component::Normal(_)))
}

/// Remove the directories the torrent's files lived in under `dir` that are now empty.
fn prune_dirs(meta: &Metainfo, dir: &Path) {
    let mut parents = BTreeSet::new();
    for (path, _) in meta.files.iter() {
        if !is_plain(path) {
            continue;
        }
        let full = dir.join(path);
        for anc in full.ancestors().skip(1) {
            if anc == dir || !anc.starts_with(dir) {
                break;
            }
            parents.insert(anc.to_path_buf());
        }
    }
    let mut parents: Vec<PathBuf> = parents.into_iter().collect();
    parents.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for p in parents {
        let _ = std::fs::remove_dir(p);
    }
}

/// Move exactly the torrent's own files from `from` to `to`, keeping the
/// layout. Fails before touching anything if a different file is already at a
/// destination; a failure midway puts the moved files back.
fn move_files(meta: &Metainfo, from: &Path, to: &Path) -> Result<()> {
    let mut pairs = Vec::new();
    for (path, _) in meta.files.iter() {
        if !is_plain(path) {
            continue;
        }
        let src = from.join(path);
        if !std::fs::symlink_metadata(&src).is_ok_and(|m| m.is_file()) {
            continue;
        }
        let dst = to.join(path);
        if std::fs::symlink_metadata(&dst).is_ok() && !same_content(&src, &dst)? {
            anyhow::bail!("{} already exists and differs", dst.display());
        }
        pairs.push((src, dst));
    }
    let mut done: Vec<&(PathBuf, PathBuf)> = Vec::new();
    for pair in &pairs {
        if let Err(e) = move_file(&pair.0, &pair.1) {
            for (s, d) in done.iter().rev() {
                let _ = move_file(d, s);
            }
            return Err(e);
        }
        done.push(pair);
    }
    prune_dirs(meta, from);
    Ok(())
}

fn move_file(src: &Path, dst: &Path) -> Result<()> {
    if dst.exists() {
        return std::fs::remove_file(src).with_context(|| format!("removing {}", src.display()));
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    if std::fs::rename(src, dst).is_ok() {
        return Ok(());
    }
    let mut part = dst.as_os_str().to_owned();
    part.push(".torrust-part");
    let part = PathBuf::from(part);
    let copied = std::fs::copy(src, &part)
        .and_then(|_| std::fs::File::open(&part)?.sync_all())
        .and_then(|_| std::fs::rename(&part, dst));
    if let Err(e) = copied {
        let _ = std::fs::remove_file(&part);
        return Err(e).with_context(|| format!("copying {} to {}", src.display(), dst.display()));
    }
    std::fs::remove_file(src).with_context(|| format!("removing {}", src.display()))
}

fn same_content(a: &Path, b: &Path) -> Result<bool> {
    use std::io::Read;
    let (mut fa, mut fb) = (std::fs::File::open(a)?, std::fs::File::open(b)?);
    if fa.metadata()?.len() != fb.metadata()?.len() {
        return Ok(false);
    }
    let (mut ba, mut bb) = (vec![0u8; 64 * 1024], vec![0u8; 64 * 1024]);
    loop {
        let n = fa.read(&mut ba)?;
        if n == 0 {
            return Ok(true);
        }
        fb.read_exact(&mut bb[..n])?;
        if ba[..n] != bb[..n] {
            return Ok(false);
        }
    }
}

/// Never keep the web UI password in plaintext once the session has it.
fn secure_password(settings: &mut Settings) {
    settings.webui.password = settings.webui.password.take().filter(|p| !p.is_empty()).map(|p| crate::store::hashed(&p));
}

fn is_http(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() > 8 && (b[..7].eq_ignore_ascii_case(b"http://") || b[..8].eq_ignore_ascii_case(b"https://"))
}

/// A URL without credentials, query or fragment, for logs: feed and download
/// links often carry tokens.
fn redacted(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut u) => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => "(invalid url)".to_owned(),
    }
}

fn shown(source: &str) -> String {
    if is_http(source) {
        redacted(source)
    } else {
        source.to_owned()
    }
}

fn clip(s: &str) -> String {
    s.chars().take(MAX_TITLE).collect()
}

fn feed_delay() -> Duration {
    FEED_INTERVAL.mul_f64(rand::thread_rng().gen_range(0.9..1.1))
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn summary_line(st: &SessionState) -> String {
    let seeding = st
        .torrents
        .iter()
        .filter(|t| t.ui.torrent.as_ref().is_some_and(|t| t.state == DownloadState::Seeding))
        .count();
    format!(
        "{} torrents ({seeding} seeding) | down {}/s up {}/s | {}",
        st.torrents.len(),
        human_bytes(st.download_rate as u64),
        human_bytes(st.upload_rate as u64),
        st.port_status
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::sha1_bytes;

    #[test]
    fn applescript_escaping() {
        assert_eq!(applescript_escape(r#"a "b" \c"#), r#"a \"b\" \\c"#);
        assert_eq!(applescript_escape("x\ny\r\tz"), "x y  z");
        assert_eq!(applescript_escape("日本語 ✓ é"), "日本語 ✓ é");
        assert_eq!(applescript_escape(r#"\" ; do shell script "rm""#), r#"\\\" ; do shell script \"rm\""#);
    }

    #[test]
    fn rate_history_caps() {
        let mut h = Vec::new();
        for i in 0..RATE_HISTORY + 7 {
            push_sample(&mut h, (i as f64, 0.0));
        }
        assert_eq!(h.len(), RATE_HISTORY);
        assert_eq!(h[0].0, 7.0);
        assert_eq!(h[RATE_HISTORY - 1].0, (RATE_HISTORY + 6) as f64);
    }

    #[test]
    fn schedule_actions_follow_the_slot() {
        let eff = |dp, up| Effective { down: 0, up: 0, downloads_paused: dp, uploads_paused: up };
        let t = |running, complete, state, sched_paused| TorrentFacts { running, complete, state, sched_paused };
        let dl = Some(DownloadState::Downloading);
        let seed_only = eff(true, false);
        assert_eq!(schedule_action(&seed_only, &t(true, false, dl, false)), ScheduleAction::Pause);
        assert_eq!(schedule_action(&seed_only, &t(true, false, dl, true)), ScheduleAction::None);
        assert_eq!(schedule_action(&seed_only, &t(true, false, Some(DownloadState::Paused), false)), ScheduleAction::None);
        assert_eq!(schedule_action(&seed_only, &t(true, true, Some(DownloadState::Seeding), false)), ScheduleAction::None);
        assert_eq!(schedule_action(&seed_only, &t(false, false, dl, false)), ScheduleAction::None);
        let off = eff(true, true);
        assert_eq!(schedule_action(&off, &t(true, true, Some(DownloadState::Seeding), false)), ScheduleAction::Stop);
        assert_eq!(schedule_action(&off, &t(false, false, None, false)), ScheduleAction::None);
        let normal = eff(false, false);
        assert_eq!(schedule_action(&normal, &t(true, false, Some(DownloadState::Paused), true)), ScheduleAction::Resume);
        assert_eq!(schedule_action(&normal, &t(true, false, Some(DownloadState::Paused), false)), ScheduleAction::None);
    }

    #[test]
    fn fetched_info_becomes_a_torrent_with_the_magnet_trackers() {
        let piece = vec![7u8; 16];
        let info = bencode::encode(&Value::Dict(BTreeMap::from([
            (b"length".to_vec(), Value::Int(16)),
            (b"name".to_vec(), Value::Bytes(b"f".to_vec())),
            (b"piece length".to_vec(), Value::Int(16384)),
            (b"pieces".to_vec(), Value::Bytes(sha1_bytes(&piece).to_vec())),
        ])));
        let dir = std::env::temp_dir().join(format!("ts-meta-{}", std::process::id()));
        let store = Store::at(&dir);
        let meta = store_metadata(&store, "id", &info, &["http://t/announce".to_owned()]).unwrap();
        assert_eq!(meta.announce_list, vec!["http://t/announce".to_owned()]);
        let again = Metainfo::from_bytes(&store.load_torrent("id").unwrap()).unwrap();
        assert_eq!(again.infohash, meta.infohash);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
