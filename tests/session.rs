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
use torrust::state::{DownloadState, SessionCommand, SessionState, Settings, UiState};
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
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    addr
}

fn settings(dir: &Path) -> Settings {
    Settings {
        download_dir: dir.to_path_buf(),
        listen_port: 0,
        ratio_target: 0.0,
        dht: false,
        port_forwarding: false,
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
