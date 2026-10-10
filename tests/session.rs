use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use torrust::bencode::{encode, Value};
use torrust::engine::{build_seeder, Engine};
use torrust::session::{Session, SessionHandle};
use torrust::state::{Command, DownloadState, FilePriority, SessionCommand, SessionState, Settings, UiState};
use torrust::storage::{sha1_bytes, Storage};
use torrust::store::Store;
use torrust::Metainfo;

const PIECE_LEN: usize = 16 * 1024;
const FILES: [(&str, usize); 3] = [("a.bin", 100_000), ("sub/b.bin", 40_000), ("sub/c.bin", 131_077)];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ts-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn payload(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (x >> 33) as u8
        })
        .collect()
}

fn key(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn bytes(s: &[u8]) -> Value {
    Value::Bytes(s.to_vec())
}

struct Fixture {
    name: &'static str,
    contents: Vec<Vec<u8>>,
}

impl Fixture {
    fn new(name: &'static str, seed: u64) -> Self {
        let contents = FILES
            .iter()
            .enumerate()
            .map(|(i, (_, len))| payload(seed * 10 + i as u64, *len))
            .collect();
        Fixture { name, contents }
    }

    fn torrent(&self, announce: &str) -> Vec<u8> {
        let all: Vec<u8> = self.contents.concat();
        let pieces: Vec<u8> = all.chunks(PIECE_LEN).flat_map(|c| sha1_bytes(c)).collect();
        let files = FILES
            .iter()
            .zip(&self.contents)
            .map(|((path, _), data)| {
                let segs = path.split('/').map(|s| bytes(s.as_bytes())).collect();
                Value::Dict(BTreeMap::from([
                    (key("length"), Value::Int(data.len() as i64)),
                    (key("path"), Value::List(segs)),
                ]))
            })
            .collect();
        let info = Value::Dict(BTreeMap::from([
            (key("name"), bytes(self.name.as_bytes())),
            (key("piece length"), Value::Int(PIECE_LEN as i64)),
            (key("pieces"), Value::Bytes(pieces)),
            (key("files"), Value::List(files)),
        ]));
        encode(&Value::Dict(BTreeMap::from([
            (key("announce"), bytes(announce.as_bytes())),
            (key("info"), info),
        ])))
    }

    fn write_to(&self, root: &Path) {
        for ((path, _), data) in FILES.iter().zip(&self.contents) {
            let p = root.join(self.name).join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, data).unwrap();
        }
    }

    fn assert_on_disk(&self, root: &Path) {
        for ((path, _), data) in FILES.iter().zip(&self.contents) {
            let got = std::fs::read(root.join(self.name).join(path)).unwrap();
            assert!(got == *data, "{}/{path} differs", self.name);
        }
    }
}

struct Tracker {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Tracker {
    fn saw_port(&self, port: u16) -> bool {
        let needle = format!("port={port}&");
        self.requests.lock().unwrap().iter().any(|r| r.contains(&needle))
    }
}

async fn mock_tracker(peer: Option<SocketAddr>) -> Tracker {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut peers = Vec::new();
    if let Some(p) = peer {
        peers.extend_from_slice(&[127, 0, 0, 1]);
        peers.extend_from_slice(&p.port().to_be_bytes());
    }
    let body = encode(&Value::Dict(BTreeMap::from([
        (key("interval"), Value::Int(1800)),
        (key("peers"), Value::Bytes(peers)),
    ])));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let body = body.clone();
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]);
                log.lock().unwrap().push(head.lines().next().unwrap_or("").to_owned());
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    Tracker { addr, requests }
}

async fn seeder_for(fx: &Fixture) -> SocketAddr {
    let seed_dir = temp_dir("seed");
    fx.write_to(&seed_dir);
    let meta = Metainfo::from_bytes(&fx.torrent("http://127.0.0.1:1/announce")).unwrap();
    let storage = Arc::new(Storage::prepare(&meta, &seed_dir).unwrap());
    let seeder = build_seeder(storage, &meta, &vec![true; meta.piece_count()]);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (addr, _h) = torrust::peer::pool::listen(Arc::new(meta), seeder, 0, tx).await.unwrap();
    tokio::spawn(async move {
        let mut live = vec![];
        while let Some((_, ev)) = rx.recv().await {
            if let torrust::peer::connection::FromPeer::Connected(h) = ev {
                live.push(h);
            }
        }
    });
    addr
}

fn settings(dir: &Path) -> Settings {
    Settings {
        download_dir: dir.to_path_buf(),
        listen_port: 0,
        ratio_target: 0.0,
        dht: false,
        port_forwarding: false,
        lsd: false,
        notifications: false,
        allow_local_urls: true,
        ..Settings::default()
    }
}

fn write_torrent(fx: &Fixture, tracker: &Tracker) -> (PathBuf, String) {
    let raw = fx.torrent(&format!("http://{}/announce", tracker.addr));
    let id = Metainfo::from_bytes(&raw).unwrap().infohash.to_hex();
    let path = temp_dir("tor").join(format!("{}.torrent", fx.name));
    std::fs::write(&path, raw).unwrap();
    (path, id)
}

fn add(h: &SessionHandle, path: &Path, dir: &Path) {
    h.command()
        .send(SessionCommand::Add { source: path.display().to_string(), dir: Some(dir.to_path_buf()) })
        .unwrap();
}

fn torrent_state(st: &SessionState, id: &str) -> Option<DownloadState> {
    st.torrents.iter().find(|t| t.id == id)?.ui.torrent.as_ref().map(|t| t.state)
}

async fn wait_for(h: &SessionHandle, what: &str, secs: u64, pred: impl Fn(&SessionState) -> bool) {
    let state = h.state();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        {
            let st = state.read().await;
            if pred(&st) {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                let torrents: Vec<_> = st
                    .torrents
                    .iter()
                    .map(|t| (t.id.clone(), t.ui.torrent.as_ref().map(|t| (t.state, t.progress)), t.ui.warning.clone()))
                    .collect();
                let log: Vec<_> = st.log.iter().map(|l| l.message.clone()).collect();
                panic!("timed out waiting for {what}; torrents={torrents:?}; log={log:#?}");
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn is_done(s: Option<DownloadState>) -> bool {
    matches!(s, Some(DownloadState::Seeding | DownloadState::Complete))
}

async fn quit(h: SessionHandle) {
    h.command().send(SessionCommand::Quit).unwrap();
    h.wait().await.unwrap();
}

async fn leech(fx: &Fixture, session_port: u16, dest: &Path) -> Arc<RwLock<UiState>> {
    let tracker = mock_tracker(Some(SocketAddr::from(([127, 0, 0, 1], session_port)))).await;
    let meta = Arc::new(Metainfo::from_bytes(&fx.torrent(&format!("http://{}/announce", tracker.addr))).unwrap());
    let ui = Arc::new(RwLock::new(UiState::default()));
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let engine = Engine::new(meta, Arc::clone(&ui), cmd_rx);
    let dest = dest.to_path_buf();
    tokio::spawn(async move {
        let _keep = cmd_tx;
        let _ = engine.run(dest).await;
    });
    ui
}

#[tokio::test]
async fn two_torrents_download_and_seed() {
    let (one, two) = (Fixture::new("one", 1), Fixture::new("two", 2));
    let (s1, s2) = (seeder_for(&one).await, seeder_for(&two).await);
    let (t1, t2) = (mock_tracker(Some(s1)).await, mock_tracker(Some(s2)).await);
    let (p1, id1) = write_torrent(&one, &t1);
    let (p2, id2) = write_torrent(&two, &t2);

    let home = temp_dir("home");
    let dl = temp_dir("dl");
    let h = Session::start_in(Store::at(&home), settings(&dl)).await.unwrap();
    add(&h, &p1, &dl);
    add(&h, &p2, &dl);

    wait_for(&h, "both torrents done", 60, |st| {
        is_done(torrent_state(st, &id1)) && is_done(torrent_state(st, &id2))
    })
    .await;
    one.assert_on_disk(&dl);
    two.assert_on_disk(&dl);

    let port = h.port();
    assert!(t1.saw_port(port), "tracker 1 saw {:?}, expected port {port}", t1.requests.lock().unwrap());
    assert!(t2.saw_port(port), "tracker 2 saw {:?}, expected port {port}", t2.requests.lock().unwrap());
    quit(h).await;
}

#[tokio::test]
async fn uploaded_torrent_bytes_are_added_once() {
    let fx = Fixture::new("up", 5);
    let dl = temp_dir("dl");
    fx.write_to(&dl);
    let t = mock_tracker(None).await;
    let raw = fx.torrent(&format!("http://{}/announce", t.addr));
    let id = Metainfo::from_bytes(&raw).unwrap().infohash.to_hex();

    let h = Session::start_in(Store::at(&temp_dir("home")), settings(&dl)).await.unwrap();
    h.command().send(SessionCommand::AddTorrent { bytes: b"d3:bar".to_vec(), dir: None }).unwrap();
    h.command().send(SessionCommand::AddTorrent { bytes: raw.clone(), dir: None }).unwrap();
    h.command().send(SessionCommand::AddTorrent { bytes: raw, dir: None }).unwrap();
    wait_for(&h, "uploaded torrent seeding", 30, |st| is_done(torrent_state(st, &id))).await;
    assert_eq!(h.state().read().await.torrents.len(), 1);
    quit(h).await;
}

#[tokio::test]
async fn restart_keeps_uploaded_and_stopped() {
    let (one, two) = (Fixture::new("one", 3), Fixture::new("two", 4));
    let dl = temp_dir("dl");
    one.write_to(&dl);
    two.write_to(&dl);
    let t = mock_tracker(None).await;
    let (p1, id1) = write_torrent(&one, &t);
    let (p2, id2) = write_torrent(&two, &t);

    let home = temp_dir("home");
    let h = Session::start_in(Store::at(&home), settings(&dl)).await.unwrap();
    add(&h, &p1, &dl);
    add(&h, &p2, &dl);
    wait_for(&h, "both seeding", 30, |st| {
        is_done(torrent_state(st, &id1)) && is_done(torrent_state(st, &id2))
    })
    .await;

    let leech_dir = temp_dir("leech");
    let ui = leech(&one, h.port(), &leech_dir).await;
    wait_for(&h, "uploaded bytes", 60, |st| st.torrents.iter().any(|t| t.id == id1 && t.uploaded > 0)).await;
    assert_eq!(
        ui.read().await.torrent.as_ref().map(|t| t.state).filter(|s| *s == DownloadState::Error),
        None
    );

    h.command().send(SessionCommand::Stop(id2.clone())).unwrap();
    wait_for(&h, "second stopped", 15, |st| torrent_state(st, &id2) == Some(DownloadState::Stopped)).await;
    let uploaded = h.state().read().await.torrents.iter().find(|t| t.id == id1).unwrap().uploaded;
    assert!(uploaded > 0);
    quit(h).await;

    let h = Session::start_in(Store::at(&home), settings(&dl)).await.unwrap();
    {
        let st = h.state();
        let st = st.read().await;
        assert_eq!(st.torrents.len(), 2);
        let v1 = st.torrents.iter().find(|t| t.id == id1).unwrap();
        assert!(v1.uploaded >= uploaded, "{} < {uploaded}", v1.uploaded);
        assert_eq!(torrent_state(&st, &id2), Some(DownloadState::Stopped));
    }
    wait_for(&h, "first seeding again", 30, |st| is_done(torrent_state(st, &id1))).await;
    assert_eq!(torrent_state(&*h.state().read().await, &id2), Some(DownloadState::Stopped));
    quit(h).await;
}

#[tokio::test]
async fn ratio_target_stops_seeding() {
    let fx = Fixture::new("one", 5);
    let dl = temp_dir("dl");
    fx.write_to(&dl);
    let t = mock_tracker(None).await;
    let (p, id) = write_torrent(&fx, &t);

    let home = temp_dir("home");
    let mut s = settings(&dl);
    s.ratio_target = 0.01;
    let h = Session::start_in(Store::at(&home), s).await.unwrap();
    add(&h, &p, &dl);
    wait_for(&h, "seeding", 30, |st| is_done(torrent_state(st, &id))).await;

    let _ui = leech(&fx, h.port(), &temp_dir("leech")).await;
    wait_for(&h, "ratio stop", 60, |st| torrent_state(st, &id) == Some(DownloadState::Stopped)).await;
    quit(h).await;

    let (records, _) = Store::at(&home).load_records();
    assert!(records.iter().any(|r| r.id == id && r.stopped && r.uploaded > 0));
}

#[tokio::test]
async fn remove_with_delete_data_touches_only_that_torrent() {
    let (one, two) = (Fixture::new("one", 6), Fixture::new("two", 7));
    let dl = temp_dir("dl");
    one.write_to(&dl);
    two.write_to(&dl);
    std::fs::write(dl.join("keep.txt"), b"mine").unwrap();
    std::fs::write(dl.join("one").join("extra.txt"), b"mine too").unwrap();
    let t = mock_tracker(None).await;
    let (p1, id1) = write_torrent(&one, &t);
    let (p2, id2) = write_torrent(&two, &t);

    let home = temp_dir("home");
    let h = Session::start_in(Store::at(&home), settings(&dl)).await.unwrap();
    add(&h, &p1, &dl);
    add(&h, &p2, &dl);
    wait_for(&h, "both seeding", 30, |st| {
        is_done(torrent_state(st, &id1)) && is_done(torrent_state(st, &id2))
    })
    .await;

    h.command()
        .send(SessionCommand::Remove { id: id1.clone(), delete_data: true })
        .unwrap();
    wait_for(&h, "removal", 15, |st| st.torrents.len() == 1).await;

    for (path, _) in FILES {
        assert!(!dl.join("one").join(path).exists(), "one/{path} should be gone");
    }
    assert!(!dl.join("one/sub").exists());
    assert_eq!(std::fs::read(dl.join("one/extra.txt")).unwrap(), b"mine too");
    assert_eq!(std::fs::read(dl.join("keep.txt")).unwrap(), b"mine");
    two.assert_on_disk(&dl);
    let store = Store::at(&home);
    assert!(store.load_torrent(&id1).is_none());
    assert_eq!(store.load_records().0.len(), 1);
    quit(h).await;
}

#[cfg(unix)]
#[tokio::test]
async fn ipc_add_delivers_to_running_session_and_queues_otherwise() {
    use torrust::ipc::{send_add_to, Delivery};

    let fx = Fixture::new("one", 8);
    let dl = temp_dir("dl");
    let t = mock_tracker(None).await;
    let (p, id) = write_torrent(&fx, &t);

    let home = temp_dir("h");
    let store = Store::at(&home);
    let h = Session::start_in(store.clone(), settings(&dl)).await.unwrap();
    assert_eq!(send_add_to(&store, &p.display().to_string(), Some(&dl)).await.unwrap(), Delivery::Delivered);
    wait_for(&h, "ipc add", 15, |st| st.torrents.iter().any(|t| t.id == id)).await;
    assert!(send_add_to(&store, "/no/such/file.torrent", None).await.is_err());
    quit(h).await;
    assert!(!store.socket_path().exists());

    let home2 = temp_dir("h");
    let store2 = Store::at(&home2);
    assert_eq!(send_add_to(&store2, &p.display().to_string(), Some(&dl)).await.unwrap(), Delivery::Queued);
    let h = Session::start_in(store2, settings(&dl)).await.unwrap();
    assert!(h.state().read().await.torrents.iter().any(|t| t.id == id));
    quit(h).await;
}

fn queued(st: &SessionState, id: &str) -> bool {
    torrent_state(st, id) == Some(DownloadState::Queued)
}

fn position(st: &SessionState, id: &str) -> Option<usize> {
    st.torrents.iter().find(|t| t.id == id)?.queue_position
}

#[tokio::test]
async fn queue_runs_one_download_at_a_time_and_advances() {
    let fxs = [Fixture::new("q1", 11), Fixture::new("q2", 12), Fixture::new("q3", 13)];
    let dl = temp_dir("dl");
    let mut ids = Vec::new();
    let mut paths = Vec::new();
    for fx in &fxs {
        let t = mock_tracker(Some(seeder_for(fx).await)).await;
        let (p, id) = write_torrent(fx, &t);
        paths.push(p);
        ids.push(id);
    }
    let mut s = settings(&dl);
    s.max_active_downloads = 1;
    let h = Session::start_in(Store::at(temp_dir("home")), s).await.unwrap();
    for p in &paths {
        add(&h, p, &dl);
    }
    wait_for(&h, "one running, two queued", 20, |st| {
        st.torrents.len() == 3 && !queued(st, &ids[0]) && queued(st, &ids[1]) && queued(st, &ids[2])
    })
    .await;
    wait_for(&h, "first done", 60, |st| is_done(torrent_state(st, &ids[0]))).await;
    wait_for(&h, "all done in turn", 60, |st| ids.iter().all(|id| is_done(torrent_state(st, id)))).await;
    for fx in &fxs {
        fx.assert_on_disk(&dl);
    }
    quit(h).await;
}

#[tokio::test]
async fn move_queue_and_force_start() {
    let fxs = [Fixture::new("m1", 21), Fixture::new("m2", 22), Fixture::new("m3", 23)];
    let dl = temp_dir("dl");
    let t = mock_tracker(None).await;
    let mut ids = Vec::new();
    let mut paths = Vec::new();
    for fx in &fxs {
        let (p, id) = write_torrent(fx, &t);
        paths.push(p);
        ids.push(id);
    }
    let mut s = settings(&dl);
    s.max_active_downloads = 1;
    let h = Session::start_in(Store::at(temp_dir("home")), s).await.unwrap();
    for p in &paths {
        add(&h, p, &dl);
    }
    wait_for(&h, "initial queue", 20, |st| {
        st.torrents.len() == 3 && !queued(st, &ids[0]) && queued(st, &ids[1]) && queued(st, &ids[2])
    })
    .await;
    {
        let st = h.state();
        let st = st.read().await;
        assert_eq!(ids.iter().map(|id| position(&st, id)).collect::<Vec<_>>(), vec![Some(0), Some(1), Some(2)]);
    }

    let mv = |id: &str| h.command().send(SessionCommand::MoveQueue { id: id.to_owned(), up: true }).unwrap();
    mv(&ids[2]);
    wait_for(&h, "third moved to slot 1", 10, |st| position(st, &ids[2]) == Some(1) && position(st, &ids[1]) == Some(2)).await;
    assert!(queued(&*h.state().read().await, &ids[2]));
    mv(&ids[2]);
    wait_for(&h, "third now runs, first queued", 20, |st| {
        position(st, &ids[2]) == Some(0) && !queued(st, &ids[2]) && queued(st, &ids[0]) && queued(st, &ids[1])
    })
    .await;

    h.command().send(SessionCommand::Start(ids[1].clone())).unwrap();
    wait_for(&h, "force start alongside", 20, |st| {
        !queued(st, &ids[1]) && !queued(st, &ids[2]) && queued(st, &ids[0])
    })
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!queued(&*h.state().read().await, &ids[1]), "forced torrent was re-queued");

    h.command().send(SessionCommand::SetSettings(Settings { max_active_downloads: 0, ..settings(&dl) })).unwrap();
    wait_for(&h, "unlimited starts the rest", 20, |st| !queued(st, &ids[0])).await;
    quit(h).await;
}

#[tokio::test]
async fn restart_restores_saved_progress_and_priorities() {
    let fx = Fixture::new("p1", 31);
    let dl = temp_dir("dl");
    fx.write_to(&dl);
    let t = mock_tracker(None).await;
    let (p, id) = write_torrent(&fx, &t);
    let home = temp_dir("home");

    let h = Session::start_in(Store::at(&home), settings(&dl)).await.unwrap();
    add(&h, &p, &dl);
    wait_for(&h, "seeding", 30, |st| is_done(torrent_state(st, &id))).await;
    let set = |i, p| h.command().send(SessionCommand::Torrent(id.clone(), Command::SetFilePriority(i, p))).unwrap();
    set(0, FilePriority::High);
    set(1, FilePriority::Skip);
    let published = |st: &SessionState| {
        st.torrents.iter().find(|t| t.id == id).and_then(|t| t.ui.torrent.as_ref()).is_some_and(|t| {
            t.files.len() == 3 && t.files[0].priority == FilePriority::High && t.files[1].priority == FilePriority::Skip
        })
    };
    wait_for(&h, "priorities published", 15, published).await;
    h.command().send(SessionCommand::Stop(id.clone())).unwrap();
    wait_for(&h, "stopped", 15, |st| torrent_state(st, &id) == Some(DownloadState::Stopped)).await;
    quit(h).await;

    let (records, _) = Store::at(&home).load_records();
    let snap = records[0].snapshot.clone().expect("snapshot saved");
    assert!(snap.verified_pieces > 0 && snap.progress > 0.0);

    let h = Session::start_in(Store::at(&home), settings(&dl)).await.unwrap();
    {
        let st = h.state();
        let st = st.read().await;
        let t = st.torrents[0].ui.torrent.as_ref().unwrap();
        assert_eq!(t.state, DownloadState::Stopped);
        assert!(t.progress > 0.0 && t.verified_pieces == snap.verified_pieces, "stopped torrent shows {}", t.progress);
        assert_eq!(t.files[0].priority, FilePriority::High);
        assert_eq!(t.files[1].priority, FilePriority::Skip);
        assert_eq!(st.torrents[0].queue_position, None);
    }
    h.command().send(SessionCommand::Start(id.clone())).unwrap();
    wait_for(&h, "engine publishes restored priorities", 30, |st| {
        is_done(torrent_state(st, &id)) && published(st)
    })
    .await;
    quit(h).await;
}

#[tokio::test]
async fn peers_find_each_other_through_local_discovery_alone() {
    let fx = Fixture::new("lsd", 7);
    let dead = mock_tracker(None).await;
    let (path, id) = write_torrent(&fx, &dead);

    let (seed_dl, leech_dl) = (temp_dir("lsd-seed"), temp_dir("lsd-leech"));
    fx.write_to(&seed_dl);
    let lsd_on = |dir: &Path| Settings { lsd: true, ..settings(dir) };
    let seeder = Session::start_in(Store::at(temp_dir("lsd-home-a")), lsd_on(&seed_dl)).await.unwrap();
    let leecher = Session::start_in(Store::at(temp_dir("lsd-home-b")), lsd_on(&leech_dl)).await.unwrap();
    if seeder.state().read().await.log.iter().any(|l| l.message.contains("local peer discovery unavailable")) {
        eprintln!("multicast unavailable, skipping");
        return;
    }
    add(&seeder, &path, &seed_dl);
    wait_for(&seeder, "seeding", 30, |st| is_done(torrent_state(st, &id))).await;
    add(&leecher, &path, &leech_dl);
    wait_for(&leecher, "download via LSD", 60, |st| is_done(torrent_state(st, &id))).await;
    fx.assert_on_disk(&leech_dl);
    quit(seeder).await;
    quit(leecher).await;
}

fn view_label(st: &SessionState, id: &str) -> Option<String> {
    st.torrents.iter().find(|t| t.id == id)?.label.clone()
}

fn download_dir(st: &SessionState, id: &str) -> Option<String> {
    st.torrents.iter().find(|t| t.id == id)?.ui.torrent.as_ref().map(|t| t.download_dir.clone())
}

fn at(st: &SessionState, id: &str, dir: &Path) -> bool {
    is_done(torrent_state(st, id)) && download_dir(st, id) == Some(dir.display().to_string())
}

async fn seeding_session(fx: &Fixture, dl: &Path) -> (SessionHandle, PathBuf, String) {
    fx.write_to(dl);
    let t = mock_tracker(None).await;
    let (p, id) = write_torrent(fx, &t);
    let home = temp_dir("home");
    let h = Session::start_in(Store::at(&home), settings(dl)).await.unwrap();
    add(&h, &p, dl);
    wait_for(&h, "seeding", 30, |st| is_done(torrent_state(st, &id))).await;
    (h, home, id)
}

#[tokio::test]
async fn labels_and_sequential_persist_across_restart() {
    let fx = Fixture::new("lab", 41);
    let dl = temp_dir("dl");
    let (h, home, id) = seeding_session(&fx, &dl).await;
    h.command().send(SessionCommand::SetLabel { id: id.clone(), label: Some("  linux ".into()) }).unwrap();
    h.command().send(SessionCommand::Torrent(id.clone(), Command::SetSequential(true))).unwrap();
    let seq = |st: &SessionState| {
        st.torrents.iter().find(|t| t.id == id).and_then(|t| t.ui.torrent.as_ref()).is_some_and(|t| t.sequential)
    };
    wait_for(&h, "label and sequential", 15, |st| view_label(st, &id).as_deref() == Some("linux") && seq(st)).await;
    quit(h).await;

    let (records, _) = Store::at(&home).load_records();
    assert_eq!(records[0].label.as_deref(), Some("linux"));
    assert!(records[0].sequential);

    let h = Session::start_in(Store::at(&home), settings(&dl)).await.unwrap();
    assert_eq!(view_label(&*h.state().read().await, &id).as_deref(), Some("linux"));
    wait_for(&h, "seeding with sequential restored", 30, |st| is_done(torrent_state(st, &id)) && seq(st)).await;
    h.command().send(SessionCommand::SetLabel { id: id.clone(), label: None }).unwrap();
    wait_for(&h, "label cleared", 15, |st| view_label(st, &id).is_none()).await;
    quit(h).await;
    assert_eq!(Store::at(&home).load_records().0[0].label, None);
}

#[tokio::test]
async fn move_data_relocates_only_the_torrent_files() {
    let fx = Fixture::new("mv", 42);
    let dl = temp_dir("dl");
    let (h, home, id) = seeding_session(&fx, &dl).await;
    std::fs::write(dl.join("mv/extra.txt"), b"mine").unwrap();
    let dest = temp_dir("dest");

    h.command().send(SessionCommand::MoveData { id: id.clone(), dir: dest.clone() }).unwrap();
    wait_for(&h, "seeding at the new place", 30, |st| at(st, &id, &dest)).await;

    fx.assert_on_disk(&dest);
    for (path, _) in FILES {
        assert!(!dl.join("mv").join(path).exists(), "mv/{path} should be gone from the old dir");
    }
    assert!(!dl.join("mv/sub").exists());
    assert_eq!(std::fs::read(dl.join("mv/extra.txt")).unwrap(), b"mine");
    quit(h).await;
    assert_eq!(Store::at(&home).load_records().0[0].dir, dest);

    let h = Session::start_in(Store::at(&home), settings(&dl)).await.unwrap();
    wait_for(&h, "seeding at the new place after restart", 30, |st| at(st, &id, &dest)).await;
    quit(h).await;
}

#[tokio::test]
async fn move_data_refuses_to_overwrite_a_different_file() {
    let fx = Fixture::new("mvx", 43);
    let dl = temp_dir("dl");
    let (h, home, id) = seeding_session(&fx, &dl).await;
    let dest = temp_dir("dest");
    std::fs::create_dir_all(dest.join("mvx/sub")).unwrap();
    std::fs::write(dest.join("mvx/sub/b.bin"), b"someone else's").unwrap();

    h.command().send(SessionCommand::MoveData { id: id.clone(), dir: dest.clone() }).unwrap();
    wait_for(&h, "error logged", 15, |st| st.log.iter().any(|l| l.message.contains("cannot move"))).await;
    wait_for(&h, "seeding again in place", 30, |st| at(st, &id, &dl)).await;

    fx.assert_on_disk(&dl);
    assert_eq!(std::fs::read(dest.join("mvx/sub/b.bin")).unwrap(), b"someone else's");
    assert!(!dest.join("mvx/a.bin").exists());
    quit(h).await;
    assert_eq!(Store::at(&home).load_records().0[0].dir, dl);
}

#[tokio::test]
async fn move_completed_runs_once_per_torrent() {
    let fx = Fixture::new("mc", 44);
    let seeder = seeder_for(&fx).await;
    let tracker = mock_tracker(Some(seeder)).await;
    let (p, id) = write_torrent(&fx, &tracker);
    let (dl, done, other) = (temp_dir("dl"), temp_dir("done"), temp_dir("other"));
    let home = temp_dir("home");
    let with = |d: &Path| Settings { move_completed_dir: Some(d.to_path_buf()), ..settings(&dl) };

    let h = Session::start_in(Store::at(&home), with(&done)).await.unwrap();
    add(&h, &p, &dl);
    wait_for(&h, "downloaded and moved", 60, |st| at(st, &id, &done)).await;
    fx.assert_on_disk(&done);
    assert!(!dl.join("mc").join("a.bin").exists());
    quit(h).await;
    assert_eq!(Store::at(&home).load_records().0[0].dir, done);

    let h = Session::start_in(Store::at(&home), with(&other)).await.unwrap();
    wait_for(&h, "seeding after restart", 30, |st| at(st, &id, &done)).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(at(&*h.state().read().await, &id, &done), "moved again after restart");
    assert!(!other.join("mc").exists());
    quit(h).await;
}

async fn handshake_reply_len(port: u16, id: &str) -> usize {
    let mut hs = vec![19u8];
    hs.extend_from_slice(b"BitTorrent protocol");
    hs.extend_from_slice(&[0u8; 8]);
    hs.extend_from_slice(&hex::decode(id).unwrap());
    hs.extend_from_slice(&[7u8; 20]);
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let _ = s.write_all(&hs).await;
    let mut buf = [0u8; 68];
    let mut n = 0;
    while n < buf.len() {
        match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf[n..])).await {
            Ok(Ok(k)) if k > 0 => n += k,
            _ => break,
        }
    }
    n
}

#[tokio::test]
async fn blocklist_refuses_inbound_peers_and_reports_ranges() {
    let fx = Fixture::new("blk", 51);
    let dl = temp_dir("dl");
    let (h, home, id) = seeding_session(&fx, &dl).await;
    assert_eq!(handshake_reply_len(h.port(), &id).await, 68);

    let list = temp_dir("bl").join("list.txt");
    std::fs::write(&list, "# comment\nloopback:127.0.0.1-127.0.0.1\nnot a range\n").unwrap();
    let mut s = h.state().read().await.settings.clone();
    s.blocklist = Some(list.clone());
    h.command().send(SessionCommand::SetSettings(s)).unwrap();
    wait_for(&h, "block list loaded", 10, |st| st.blocklist_ranges == 1).await;
    assert!(h.state().read().await.log.iter().any(|l| l.message.contains("1 ranges, 1 lines skipped")));
    assert_eq!(handshake_reply_len(h.port(), &id).await, 0);
    quit(h).await;

    let mut again = settings(&dl);
    again.blocklist = Some(list);
    let h = Session::start_in(Store::at(&home), again).await.unwrap();
    wait_for(&h, "block list restored", 10, |st| st.blocklist_ranges == 1).await;
    quit(h).await;
}

#[tokio::test]
async fn missing_blocklist_file_logs_an_error() {
    let dl = temp_dir("dl");
    let mut s = settings(&dl);
    s.blocklist = Some(dl.join("nope.txt"));
    let h = Session::start_in(Store::at(temp_dir("home")), s).await.unwrap();
    {
        let st = h.state();
        let st = st.read().await;
        assert_eq!(st.blocklist_ranges, 0);
        assert!(st.log.iter().any(|l| l.level == torrust::state::Level::Error && l.message.contains("block list")));
    }
    quit(h).await;
}

#[tokio::test]
async fn schedule_off_stops_running_torrents_and_disabling_restarts_them() {
    let fx = Fixture::new("sch", 52);
    let dl = temp_dir("dl");
    let (h, _home, id) = seeding_session(&fx, &dl).await;
    let mut s = h.state().read().await.settings.clone();
    s.schedule.enabled = true;
    s.schedule.grid = torrust::schedule::Schedule::parse_grid(&"O".repeat(168)).unwrap();
    h.command().send(SessionCommand::SetSettings(s.clone())).unwrap();
    wait_for(&h, "stopped by schedule", 15, |st| torrent_state(st, &id) == Some(DownloadState::Queued)).await;
    assert!(h.state().read().await.log.iter().any(|l| l.message.contains("schedule: all transfers off")));
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(torrent_state(&*h.state().read().await, &id), Some(DownloadState::Queued));

    s.schedule.enabled = false;
    h.command().send(SessionCommand::SetSettings(s)).unwrap();
    wait_for(&h, "restarted", 30, |st| is_done(torrent_state(st, &id))).await;
    quit(h).await;
}

#[tokio::test]
async fn rate_history_grows_one_sample_a_second() {
    let dl = temp_dir("dl");
    let h = Session::start_in(Store::at(temp_dir("home")), settings(&dl)).await.unwrap();
    wait_for(&h, "three samples", 10, |st| st.rate_history.len() >= 3).await;
    assert!(h.state().read().await.rate_history.len() <= 300);
    quit(h).await;
}
