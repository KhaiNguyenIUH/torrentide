use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use torrentide::bencode::{encode, Value};
use torrentide::engine::{Engine, EngineOptions};
use torrentide::peer::connection::connect;
use torrentide::peer::wire::{handshake_incoming, local_peer_id};
use torrentide::state::{Command, UiState};
use torrentide::storage::sha1_bytes;
use torrentide::Metainfo;

const PIECE_LEN: usize = 16 * 1024;
const PIECES: usize = 4;

fn temp_dir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("torrentide-tb-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn content() -> Vec<u8> {
    (0..PIECE_LEN * PIECES).map(|i| (i * 31 % 251) as u8).collect()
}

fn torrent(announce: &str, private: bool) -> Metainfo {
    let data = content();
    let pieces: Vec<u8> = data.chunks(PIECE_LEN).flat_map(|c| sha1_bytes(c)).collect();
    let mut info = BTreeMap::from([
        (b"name".to_vec(), Value::Bytes(b"p.bin".to_vec())),
        (b"length".to_vec(), Value::Int(data.len() as i64)),
        (b"piece length".to_vec(), Value::Int(PIECE_LEN as i64)),
        (b"pieces".to_vec(), Value::Bytes(pieces)),
    ]);
    if private {
        info.insert(b"private".to_vec(), Value::Int(1));
    }
    let raw = encode(&Value::Dict(BTreeMap::from([
        (b"announce".to_vec(), Value::Bytes(announce.as_bytes().to_vec())),
        (b"info".to_vec(), Value::Dict(info)),
    ])));
    Metainfo::from_bytes(&raw).unwrap()
}

type Seen = Arc<Mutex<Vec<String>>>;

async fn tracker() -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let body = encode(&Value::Dict(BTreeMap::from([
        (b"interval".to_vec(), Value::Int(1800)),
        (b"complete".to_vec(), Value::Int(1)),
        (b"incomplete".to_vec(), Value::Int(1)),
        (b"peers".to_vec(), Value::Bytes(vec![])),
    ])));
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let log = log.clone();
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let line = String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_owned();
                log.lock().unwrap().push(line);
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (format!("http://{addr}/announce"), seen)
}

fn param<'a>(line: &'a str, name: &str) -> &'a str {
    let query = line.split_whitespace().nth(1).unwrap().split_once('?').unwrap().1;
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(name).and_then(|v| v.strip_prefix('=')))
        .unwrap_or_else(|| panic!("no {name} in {line}"))
}

fn announces(seen: &Seen) -> Vec<String> {
    seen.lock().unwrap().iter().filter(|l| l.contains("/announce?")).cloned().collect()
}

async fn wait_for(seen: &Seen, count: usize) {
    for _ in 0..200 {
        if announces(seen).len() >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("tracker never saw {count} announces: {:?}", seen.lock().unwrap());
}

fn resumed_half(dir: &std::path::Path) {
    let mut data = content();
    for b in &mut data[PIECE_LEN * 2..] {
        *b = 0;
    }
    std::fs::write(dir.join("p.bin"), data).unwrap();
}

struct Running {
    cmd: mpsc::UnboundedSender<Command>,
    done: tokio::task::JoinHandle<anyhow::Result<()>>,
}

fn start(meta: Metainfo, dir: PathBuf, opts: EngineOptions) -> Running {
    let (cmd, rx) = mpsc::unbounded_channel();
    let engine = Engine::with_options(Arc::new(meta), Arc::new(RwLock::new(UiState::default())), rx, opts);
    Running { cmd, done: tokio::spawn(engine.run(dir)) }
}

impl Running {
    async fn stop(self) {
        self.cmd.send(Command::Stop).unwrap();
        tokio::time::timeout(Duration::from_secs(15), self.done).await.unwrap().unwrap().unwrap();
    }
}

#[tokio::test]
async fn announces_count_only_this_runs_bytes_and_the_real_left() {
    let (url, seen) = tracker().await;
    let dir = temp_dir("acct");
    resumed_half(&dir);
    let run = start(torrent(&url, false), dir, EngineOptions { dht_enabled: false, ..Default::default() });
    wait_for(&seen, 1).await;
    run.stop().await;

    let reqs = announces(&seen);
    assert_eq!(reqs.len(), 2, "{reqs:?}");
    for (req, event) in reqs.iter().zip(["started", "stopped"]) {
        assert_eq!(param(req, "event"), event, "{req}");
        assert_eq!(param(req, "downloaded"), "0", "resumed bytes must not count: {req}");
        assert_eq!(param(req, "left"), (PIECE_LEN * 2).to_string(), "{req}");
        assert_eq!(param(req, "uploaded"), "0", "{req}");
    }
}

#[tokio::test]
async fn one_peer_id_for_every_announce_and_the_handshake() {
    let (url, seen) = tracker().await;
    let dir = temp_dir("pid");
    resumed_half(&dir);
    let run = start(torrent(&url, false), dir, EngineOptions { dht_enabled: false, ..Default::default() });
    wait_for(&seen, 1).await;
    run.stop().await;

    let id: String = local_peer_id()
        .iter()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(b) { (*b as char).to_string() } else { format!("%{b:02X}") })
        .collect();
    assert!(id.starts_with("-TU0100-"), "{id}");
    let reqs = announces(&seen);
    assert_eq!(reqs.len(), 2);
    for req in &reqs {
        assert_eq!(param(req, "peer_id"), id, "{req}");
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    for _ in 0..2 {
        let (tx, _rx) = mpsc::unbounded_channel();
        let client = tokio::spawn(connect(addr, torrentide::metainfo::InfoHash([5; 20]), 2, Arc::new(std::sync::RwLock::new(None)), tx, Default::default(), true, Some(1)));
        let (mut s, _) = listener.accept().await.unwrap();
        let hs = handshake_incoming(&mut s).await.unwrap();
        assert_eq!(&hs.peer_id, local_peer_id());
        client.abort();
    }
}

#[tokio::test]
async fn starved_torrent_does_not_reannounce_inside_the_tracker_min_interval() {
    let (url, seen) = tracker().await;
    let dir = temp_dir("starved");
    resumed_half(&dir);
    let run = start(torrent(&url, false), dir, EngineOptions { dht_enabled: false, ..Default::default() });
    wait_for(&seen, 1).await;
    tokio::time::sleep(Duration::from_secs(17)).await;
    assert_eq!(announces(&seen).len(), 1, "{:?}", seen.lock().unwrap());
    run.stop().await;
}

#[tokio::test]
async fn handshakes_on_private_torrents_never_set_the_dht_bit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    for (ext, dht) in [(None, false), (Some(1u16), true)] {
        let (tx, _rx) = mpsc::unbounded_channel();
        let client = tokio::spawn(connect(addr, torrentide::metainfo::InfoHash([5; 20]), 2, Arc::new(std::sync::RwLock::new(None)), tx, Default::default(), true, ext));
        let (mut s, _) = listener.accept().await.unwrap();
        let hs = handshake_incoming(&mut s).await.unwrap();
        assert_eq!(hs.supports_dht(), dht, "ext {ext:?}");
        client.abort();
    }
}

async fn dialled_by_lsd_peers(private: bool) -> bool {
    let (url, _seen) = tracker().await;
    let dir = temp_dir("lsd");
    resumed_half(&dir);
    let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr: SocketAddr = peer.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let opts = EngineOptions { dht_enabled: false, extra_peers: Some(rx), ..Default::default() };
    let run = start(torrent(&url, private), dir, opts);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = tx.send(vec![peer_addr]);
    let dialled = tokio::time::timeout(Duration::from_secs(3), peer.accept()).await.is_ok();
    run.stop().await;
    dialled
}

#[tokio::test]
async fn private_torrents_never_dial_lsd_peers() {
    assert!(dialled_by_lsd_peers(false).await, "control: a public torrent dials LSD peers");
    assert!(!dialled_by_lsd_peers(true).await, "a private torrent must not dial LSD peers");
}
