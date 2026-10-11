use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use torrentide::bencode::{encode, Value};
use torrentide::engine::{build_seeder, Engine, EngineOptions};
use torrentide::state::{Command, DownloadState, UiState};
use torrentide::storage::{sha1_bytes, Storage};
use torrentide::Metainfo;

const PIECE_LEN: usize = 16 * 1024;
const FILES: [(&str, usize); 3] = [("a.bin", 100_000), ("sub/b.bin", 40_000), ("sub/c.bin", 131_077)];

fn temp_dir(tag: &str) -> PathBuf {
    // Tests run in parallel and the clock can return the same value twice, so
    // a counter keeps two calls from sharing a directory.
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("torrentide-{tag}-{}-{nanos}-{n}", std::process::id()));
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

fn build_torrent(announce: &str, contents: &[Vec<u8>]) -> Vec<u8> {
    let all: Vec<u8> = contents.concat();
    let pieces: Vec<u8> = all.chunks(PIECE_LEN).flat_map(|c| sha1_bytes(c)).collect();
    let files = FILES
        .iter()
        .zip(contents)
        .map(|((path, _), data)| {
            let segs = path.split('/').map(|s| bytes(s.as_bytes())).collect();
            Value::Dict(BTreeMap::from([
                (key("length"), Value::Int(data.len() as i64)),
                (key("path"), Value::List(segs)),
            ]))
        })
        .collect();
    let info = Value::Dict(BTreeMap::from([
        (key("name"), bytes(b"payload")),
        (key("piece length"), Value::Int(PIECE_LEN as i64)),
        (key("pieces"), Value::Bytes(pieces)),
        (key("files"), Value::List(files)),
    ]));
    encode(&Value::Dict(BTreeMap::from([
        (key("announce"), bytes(announce.as_bytes())),
        (key("info"), info),
    ])))
}

async fn mock_tracker(seeder: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut peers = vec![127, 0, 0, 1];
    peers.extend_from_slice(&seeder.port().to_be_bytes());
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

fn write_files(root: &Path, contents: &[Vec<u8>]) {
    for ((path, _), data) in FILES.iter().zip(contents) {
        let p = root.join("payload").join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }
}


async fn wait_for(ui: &Arc<RwLock<UiState>>, what: &str, pred: impl Fn(&UiState) -> bool) {
    let start = std::time::Instant::now();
    loop {
        {
            let st = ui.read().await;
            if pred(&st) {
                return;
            }
            if start.elapsed() > Duration::from_secs(60) {
                let log: Vec<String> = st.log.iter().map(|l| l.message.clone()).collect();
                panic!("timed out waiting for {what}; log={log:#?}");
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn state_of(st: &UiState) -> Option<DownloadState> {
    st.torrent.as_ref().map(|t| t.state)
}

#[tokio::test]
async fn recheck_finds_corruption_and_redownloads() {
    let contents: Vec<Vec<u8>> = FILES
        .iter()
        .enumerate()
        .map(|(i, (_, len))| payload(i as u64 + 1, *len))
        .collect();
    let seed_dir = temp_dir("rc-seed");
    let leech_dir = temp_dir("rc-leech");
    write_files(&seed_dir, &contents);

    let placeholder = Metainfo::from_bytes(&build_torrent("http://127.0.0.1:1/announce", &contents)).unwrap();
    let pieces = placeholder.piece_count();
    let storage = Arc::new(Storage::prepare(&placeholder, &seed_dir).unwrap());
    let seeder = build_seeder(storage, &placeholder, &vec![true; pieces]);
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let (seed_addr, _h) = torrentide::peer::pool::listen(Arc::new(placeholder), seeder, 0, events_tx)
        .await
        .unwrap();
    tokio::spawn(async move {
        let mut live = vec![];
        while let Some((_, ev)) = events_rx.recv().await {
            if let torrentide::peer::connection::FromPeer::Connected(h) = ev {
                live.push(h);
            }
        }
    });

    let tracker = mock_tracker(seed_addr).await;
    let raw = build_torrent(&format!("http://{tracker}/announce"), &contents);
    let meta = Arc::new(Metainfo::from_bytes(&raw).unwrap());
    let ui = Arc::new(RwLock::new(UiState::default()));
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let opts = EngineOptions {
        seed_after_complete: true,
        dht_enabled: false,
        ..Default::default()
    };
    let engine = Engine::with_options(meta, ui.clone(), cmd_rx, opts);
    let dir = leech_dir.clone();
    let run = tokio::spawn(engine.run(dir));

    wait_for(&ui, "initial download", |st| state_of(st) == Some(DownloadState::Seeding)).await;

    let a_path = leech_dir.join("payload/a.bin");
    let mut a = std::fs::read(&a_path).unwrap();
    for b in a.iter_mut().skip(PIECE_LEN + 5).take(100) {
        *b ^= 0xff;
    }
    std::fs::write(&a_path, &a).unwrap();
    assert!(a != contents[0]);

    cmd_tx.send(Command::Recheck).unwrap();
    let expect = format!("recheck done: {}/{pieces} pieces verified", pieces - 1);
    wait_for(&ui, "recheck to find the bad piece", |st| st.log.iter().any(|l| l.message == expect)).await;

    wait_for(&ui, "re-download", |st| {
        state_of(st) == Some(DownloadState::Seeding)
            && st.torrent.as_ref().is_some_and(|t| t.verified_pieces as usize == pieces)
    })
    .await;
    assert!(std::fs::read(&a_path).unwrap() == contents[0], "corrupt piece was not repaired");

    cmd_tx.send(Command::Stop).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(10), run).await;
    let _ = std::fs::remove_dir_all(&seed_dir);
    let _ = std::fs::remove_dir_all(&leech_dir);
}
