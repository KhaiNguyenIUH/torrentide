use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use torrust::bencode::{encode, Value};
use torrust::engine::{build_seeder, Engine};
use torrust::state::{DownloadState, UiState};
use torrust::storage::{sha1_bytes, Storage};
use torrust::Metainfo;

const PIECE_LEN: usize = 16 * 1024;
const FILES: [(&str, usize); 3] = [("a.bin", 100_000), ("sub/b.bin", 40_000), ("sub/c.bin", 131_077)];

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("torrust-{tag}-{}-{nanos}", std::process::id()));
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

async fn download(preplace: impl FnOnce(&Path, &[Vec<u8>])) {
    let contents: Vec<Vec<u8>> = FILES
        .iter()
        .enumerate()
        .map(|(i, (_, len))| payload(i as u64 + 1, *len))
        .collect();
    let seed_dir = temp_dir("seed");
    let leech_dir = temp_dir("leech");
    write_files(&seed_dir, &contents);
    preplace(&leech_dir.join("payload"), &contents);

    let placeholder = Metainfo::from_bytes(&build_torrent("http://127.0.0.1:1/announce", &contents)).unwrap();
    let storage = Arc::new(Storage::prepare(&placeholder, &seed_dir).unwrap());
    let seeder = build_seeder(storage, &placeholder, &vec![true; placeholder.piece_count()]);
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let (seed_addr, _h) = torrust::peer::pool::listen(Arc::new(placeholder), seeder, 0, events_tx)
        .await
        .unwrap();
    tokio::spawn(async move { while events_rx.recv().await.is_some() {} });

    let tracker = mock_tracker(seed_addr).await;
    let raw = build_torrent(&format!("http://{tracker}/announce"), &contents);
    let meta = Arc::new(Metainfo::from_bytes(&raw).unwrap());
    let ui = Arc::new(RwLock::new(UiState::default()));
    let (_cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let engine = Engine::new(meta, ui.clone(), cmd_rx);

    let res = match tokio::time::timeout(Duration::from_secs(60), engine.run(leech_dir.clone())).await {
        Ok(r) => r,
        Err(_) => {
            let st = ui.read().await;
            let log: Vec<String> = st.log.iter().map(|l| l.message.clone()).collect();
            panic!("download timed out; warning={:?}; log={log:#?}", st.warning);
        }
    };
    res.expect("engine failed");

    for ((path, _), data) in FILES.iter().zip(&contents) {
        let got = std::fs::read(leech_dir.join("payload").join(path)).unwrap();
        assert!(got == *data, "{path} differs");
    }
    let state = ui.read().await.torrent.as_ref().unwrap().state;
    assert_eq!(state, DownloadState::Complete);

    let _ = std::fs::remove_dir_all(&seed_dir);
    let _ = std::fs::remove_dir_all(&leech_dir);
}

#[tokio::test]
async fn downloads_from_local_seeder() {
    download(|_, _| {}).await;
}

#[tokio::test]
async fn resumes_over_partial_and_corrupt_files() {
    download(|root, contents| {
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let mut a = contents[0].clone();
        a.truncate(PIECE_LEN * 2);
        a.resize(contents[0].len(), 0);
        std::fs::write(root.join("a.bin"), a).unwrap();
        let mut c = contents[2].clone();
        for b in c.iter_mut().skip(PIECE_LEN + 5).take(1000) {
            *b ^= 0xff;
        }
        std::fs::write(root.join("sub/c.bin"), c).unwrap();
    })
    .await;
}
