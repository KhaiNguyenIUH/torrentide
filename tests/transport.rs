use std::collections::BTreeMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use torrust::bencode::{encode, Value};
use torrust::session::{Session, SessionHandle};
use torrust::state::{DownloadState, EncryptionMode, SessionCommand, Settings};
use torrust::storage::sha1_bytes;
use torrust::store::Store;
use torrust::Metainfo;

use EncryptionMode::{Disabled, Prefer, Require};

const PIECE_LEN: usize = 16 * 1024;
const NAME: &str = "payload.bin";

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tt-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn key(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn payload() -> Vec<u8> {
    let mut x: u64 = 0x9e3779b97f4a7c15;
    (0..PIECE_LEN * 9 + 777)
        .map(|_| {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (x >> 33) as u8
        })
        .collect()
}

fn torrent(data: &[u8], announce: &str) -> Vec<u8> {
    let pieces: Vec<u8> = data.chunks(PIECE_LEN).flat_map(|c| sha1_bytes(c)).collect();
    let info = Value::Dict(BTreeMap::from([
        (key("name"), Value::Bytes(NAME.as_bytes().to_vec())),
        (key("length"), Value::Int(data.len() as i64)),
        (key("piece length"), Value::Int(PIECE_LEN as i64)),
        (key("pieces"), Value::Bytes(pieces)),
    ]));
    encode(&Value::Dict(BTreeMap::from([
        (key("announce"), Value::Bytes(announce.as_bytes().to_vec())),
        (key("info"), info),
    ])))
}

async fn mock_tracker(peer: Option<SocketAddr>) -> SocketAddr {
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
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    addr
}

fn settings(dir: &Path, encryption: EncryptionMode, utp: bool) -> Settings {
    Settings {
        download_dir: dir.to_path_buf(),
        listen_port: 0,
        ratio_target: 0.0,
        dht: false,
        port_forwarding: false,
        lsd: false,
        encryption,
        utp,
        ..Settings::default()
    }
}

static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl Write for LogWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture_logs() -> Arc<Mutex<Vec<u8>>> {
    LOGS.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let w = Arc::clone(&buf);
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_env_filter("torrust=debug")
                .with_ansi(false)
                .with_writer(move || LogWriter(Arc::clone(&w)))
                .finish(),
        );
        buf
    })
    .clone()
}

struct Swarm {
    seeder: SessionHandle,
    leecher: SessionHandle,
    leech_id: String,
    data: Vec<u8>,
    leech_dir: PathBuf,
}

fn quit_cmd(h: &SessionHandle) {
    let _ = h.command().send(SessionCommand::Quit);
}

async fn done(h: &SessionHandle, id: &str, secs: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        let finished = h
            .state()
            .read()
            .await
            .torrents
            .iter()
            .find(|t| t.id == id)
            .and_then(|t| t.ui.torrent.as_ref().map(|t| t.state))
            .is_some_and(|s| matches!(s, DownloadState::Seeding | DownloadState::Complete));
        if finished {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

async fn start_swarm(seed: (EncryptionMode, bool), leech: (EncryptionMode, bool)) -> Swarm {
    let data = payload();
    let seed_dir = temp_dir("seed");
    std::fs::write(seed_dir.join(NAME), &data).unwrap();
    let leech_dir = temp_dir("leech");

    let seed_tracker = mock_tracker(None).await;
    let seed_raw = torrent(&data, &format!("http://{seed_tracker}/announce"));
    let id = Metainfo::from_bytes(&seed_raw).unwrap().infohash.to_hex();
    let seed_path = temp_dir("tor").join("seed.torrent");
    std::fs::write(&seed_path, &seed_raw).unwrap();

    let seeder = Session::start_in(Store::at(&temp_dir("home")), settings(&seed_dir, seed.0, seed.1))
        .await
        .unwrap();
    seeder
        .command()
        .send(SessionCommand::Add { source: seed_path.display().to_string(), dir: Some(seed_dir) })
        .unwrap();
    assert!(done(&seeder, &id, 30).await, "seeder never started seeding");

    let leech_tracker = mock_tracker(Some(SocketAddr::from(([127, 0, 0, 1], seeder.port())))).await;
    let leech_raw = torrent(&data, &format!("http://{leech_tracker}/announce"));
    let leech_path = temp_dir("tor").join("leech.torrent");
    std::fs::write(&leech_path, &leech_raw).unwrap();
    let leecher = Session::start_in(Store::at(&temp_dir("home")), settings(&leech_dir, leech.0, leech.1))
        .await
        .unwrap();
    leecher
        .command()
        .send(SessionCommand::Add { source: leech_path.display().to_string(), dir: Some(leech_dir.clone()) })
        .unwrap();
    Swarm { seeder, leecher, leech_id: id, data, leech_dir }
}

impl Swarm {
    async fn finish(self, buf: &Arc<Mutex<Vec<u8>>>) -> (Vec<u8>, PathBuf, String) {
        quit_cmd(&self.seeder);
        quit_cmd(&self.leecher);
        let _ = self.seeder.wait().await;
        let _ = self.leecher.wait().await;
        let logs = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
        (self.data, self.leech_dir, logs)
    }
}

async fn download(seed: (EncryptionMode, bool), leech: (EncryptionMode, bool), want: &[&str]) {
    let buf = capture_logs();
    let swarm = start_swarm(seed, leech).await;
    let ok = done(&swarm.leecher, &swarm.leech_id, 40).await;
    let peer = format!("peer=127.0.0.1:{}", swarm.seeder.port());
    let (data, dir, logs) = swarm.finish(&buf).await;
    assert!(ok, "download did not complete; logs:\n{logs}");
    assert_eq!(std::fs::read(dir.join(NAME)).unwrap(), data);
    for w in want {
        assert!(
            logs.lines().any(|l| l.contains("connected") && l.contains(&peer) && l.contains(w)),
            "no `connected` line with {w}; logs:\n{logs}"
        );
    }
}

async fn no_download(seed: (EncryptionMode, bool), leech: (EncryptionMode, bool)) {
    let buf = capture_logs();
    let swarm = start_swarm(seed, leech).await;
    let ok = done(&swarm.leecher, &swarm.leech_id, 8).await;
    swarm.finish(&buf).await;
    assert!(!ok, "download unexpectedly completed");
}

#[tokio::test]
async fn tcp_plain() {
    download((Disabled, false), (Disabled, false), &["transport=\"tcp\"", "crypto=\"plain\""]).await;
}

#[tokio::test]
async fn tcp_rc4() {
    download((Prefer, false), (Require, false), &["transport=\"tcp\"", "crypto=\"rc4\""]).await;
}

#[tokio::test]
async fn utp_plain() {
    download((Disabled, true), (Disabled, true), &["transport=\"utp\"", "crypto=\"plain\""]).await;
}

#[tokio::test]
async fn utp_rc4() {
    download((Prefer, true), (Require, true), &["transport=\"utp\"", "crypto=\"rc4\""]).await;
}

#[tokio::test]
async fn prefer_leecher_falls_back_to_plaintext_against_disabled_seeder() {
    download((Disabled, false), (Prefer, false), &["transport=\"tcp\"", "crypto=\"plain\""]).await;
}

#[tokio::test]
async fn prefer_leecher_falls_back_to_plaintext_over_utp() {
    download((Disabled, true), (Prefer, true), &["transport=\"utp\"", "crypto=\"plain\""]).await;
}

#[tokio::test]
async fn require_leecher_never_downgrades() {
    no_download((Disabled, false), (Require, false)).await;
}

#[tokio::test]
async fn require_seeder_refuses_plaintext_inbound() {
    no_download((Require, false), (Disabled, false)).await;
}

#[tokio::test]
async fn missing_utp_peer_falls_back_to_tcp() {
    download((Disabled, false), (Disabled, true), &["transport=\"tcp\"", "crypto=\"plain\""]).await;
}

#[tokio::test]
async fn require_seeder_closes_a_raw_plaintext_handshake() {
    let swarm = start_swarm((Require, false), (Disabled, false)).await;
    let ih = hex_to_20(&swarm.leech_id);
    let mut s = TcpStream::connect(("127.0.0.1", swarm.seeder.port())).await.unwrap();
    let mut hs = vec![19u8];
    hs.extend_from_slice(b"BitTorrent protocol");
    hs.extend_from_slice(&[0u8; 8]);
    hs.extend_from_slice(&ih);
    hs.extend_from_slice(&[7u8; 20]);
    s.write_all(&hs).await.unwrap();
    let mut buf = [0u8; 68];
    let r = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap();
    assert!(matches!(r, Ok(0) | Err(_)), "seeder answered a plaintext handshake: {r:?}");
    quit_cmd(&swarm.seeder);
    quit_cmd(&swarm.leecher);
}

fn hex_to_20(h: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}
