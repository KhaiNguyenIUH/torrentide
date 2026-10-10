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
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::{oneshot, watch, RwLock, Semaphore};
use tokio::task::JoinHandle;

use crate::bencode::{self, Value};
use crate::dht::DhtNode;
use crate::engine::{self, Engine, EngineOptions};
use crate::lsd::Lsd;
use crate::metainfo::{InfoHash, Magnet, Metainfo};
use crate::peer::wire::{handshake_incoming, Handshake};
use crate::portmap;
use crate::ratelimit::{Limits, RateLimiter};
use crate::state::{
    human_bytes, Command, DownloadState, FilePriority, FileSummary, Level, SessionCommand, SessionState, Settings,
    TorrentSummary, TorrentView, UiState,
};
use crate::store::{Record, Snapshot, Store};

const TICK: Duration = Duration::from_millis(250);
const PERSIST_EVERY: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_HANDSHAKES: usize = 64;
const MAPPING_LIFETIME: Duration = Duration::from_secs(3600);
const SUMMARY_EVERY: Duration = Duration::from_secs(5);

type Inbound = (TcpStream, Handshake);
type Routes = Arc<Mutex<HashMap<[u8; 20], UnboundedSender<Inbound>>>>;
type MappingRx = watch::Receiver<Option<std::result::Result<portmap::Mapping, String>>>;

struct Running {
    cmd: UnboundedSender<Command>,
    handle: JoinHandle<Result<()>>,
    info: Option<oneshot::Receiver<Vec<u8>>>,
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

    pub async fn start_in(store: Store, settings: Settings) -> Result<SessionHandle> {
        let (tx, rx) = unbounded_channel();
        let state = Arc::new(RwLock::new(SessionState {
            settings: settings.clone(),
            command_tx: Some(tx.clone()),
            ..Default::default()
        }));

        let ipc = crate::ipc::listen(&store, tx.clone())?;

        let (listener, port) = match TcpListener::bind(("0.0.0.0", settings.listen_port)).await {
            Ok(l) => {
                let port = l.local_addr()?.port();
                (l, port)
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
                (l, port)
            }
            Err(e) => return Err(e).context("binding a listen port"),
        };

        let routes: Routes = Arc::default();
        let mut accepts = vec![tokio::spawn(accept_loop(listener, Arc::clone(&routes)))];
        match bind_v6(port) {
            Ok(l) => accepts.push(tokio::spawn(accept_loop(l, Arc::clone(&routes)))),
            Err(e) => tracing::debug!(error = %e, "no separate IPv6 listener"),
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

        let mut core = Core {
            gdown: RateLimiter::new(settings.download_limit),
            gup: RateLimiter::new(settings.upload_limit),
            store,
            settings,
            entries: Vec::new(),
            state: Arc::clone(&state),
            routes,
            port,
            dht,
            lsd,
            mapping: None,
            tasks: accepts.into_iter().chain(mapper).chain(ipc).collect(),
        };
        core.init().await;

        let join = tokio::spawn(core.run(rx, pm_rx));
        Ok(SessionHandle { state, tx, port, join })
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

async fn accept_loop(listener: TcpListener, routes: Routes) {
    let pending = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        let Ok(permit) = Arc::clone(&pending).try_acquire_owned() else {
            continue;
        };
        let routes = Arc::clone(&routes);
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(hs)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake_incoming(&mut stream)).await
            else {
                return;
            };
            let tx = routes.lock().unwrap().get(&hs.infohash).cloned();
            if let Some(tx) = tx {
                let _ = tx.send((stream, hs));
            }
        });
    }
}

struct Core {
    store: Store,
    settings: Settings,
    entries: Vec<Entry>,
    state: Arc<RwLock<SessionState>>,
    routes: Routes,
    port: u16,
    dht: Option<Arc<DhtNode>>,
    lsd: Option<Lsd>,
    gdown: Arc<RateLimiter>,
    gup: Arc<RateLimiter>,
    mapping: Option<portmap::Mapping>,
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
        for e in &self.entries {
            let state = if e.rec.stopped { DownloadState::Stopped } else { DownloadState::Queued };
            stub_ui(e, state).await;
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
                _ = ticker.tick() => {
                    self.poll_entries().await;
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
            SessionCommand::Add { source, dir } => self.add(source, dir).await,
            SessionCommand::Remove { id, delete_data } => self.remove(&id, delete_data).await,
            SessionCommand::MoveQueue { id, up } => self.move_queue(&id, up).await,
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
        let dir = dir.unwrap_or_else(|| self.settings.download_dir.clone());
        match self.prepare_add(&source, dir) {
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
            Err(e) => self.log(Level::Error, format!("cannot add {source}: {e:#}")).await,
        }
    }

    fn prepare_add(&self, source: &str, dir: PathBuf) -> Result<Entry> {
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
        };
        let (ih, meta, magnet) = if source.starts_with("magnet:") {
            let m = Magnet::parse(source)?;
            rec.magnet = Some(source.to_owned());
            (m.infohash, None, Some(m))
        } else {
            let raw = std::fs::read(source).with_context(|| format!("reading {source}"))?;
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
            port: self.port,
            file_priorities: e.rec.priorities.clone(),
            extra_peers: match &self.lsd {
                Some(l) if e.meta.as_ref().is_none_or(|m| !m.private) => Some(l.register(e.ih.0)),
                _ => None,
            },
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
        let (mut cand, mut done, mut plan) = (vec![false; n], vec![false; n], vec![false; n]);
        let (mut dl, mut all) = (0, 0);
        for i in 0..n {
            let e = &self.entries[i];
            cand[i] = Self::is_candidate(e).await;
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

    async fn set_settings(&mut self, new: Settings) {
        let old = std::mem::replace(&mut self.settings, new.clone());
        self.gdown.set_rate(new.download_limit);
        self.gup.set_rate(new.upload_limit);
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
        if new.ratio_target != old.ratio_target {
            self.log(Level::Info, "ratio target applies to torrents started from now on").await;
        }
        self.state.write().await.settings = new;
        self.rebalance().await;
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

            let before = e.rec.priorities.clone();
            refresh(e).await;
            if dirty || e.rec.priorities != before {
                self.save(i).await;
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
            });
        }
        let mut st = self.state.write().await;
        st.torrents = views;
        st.download_rate = down;
        st.upload_rate = up;
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
        ..Default::default()
    };
    let snap = e.rec.snapshot.as_ref();
    match (&e.meta, &e.magnet) {
        (Some(meta), _) => {
            t.name = meta.name.clone();
            t.total_length = meta.total_length;
            t.piece_length = meta.piece_length;
            t.piece_count = meta.piece_count() as u32;
            t.trackers = meta.announce_list.clone();
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
    let mut parents = BTreeSet::new();
    for (path, _) in meta.files.iter() {
        if !path.components().all(|c| matches!(c, Component::Normal(_))) {
            continue;
        }
        let full = dir.join(path);
        let _ = std::fs::remove_file(&full);
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
