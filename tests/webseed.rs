use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use torrust::bencode::{encode, Value};
use torrust::engine::{Engine, EngineOptions};
use torrust::state::{DownloadState, UiState};
use torrust::storage::sha1_bytes;
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

fn build_torrent(urls: &[String], contents: &[Vec<u8>]) -> Vec<u8> {
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
    let list = urls.iter().map(|u| bytes(u.as_bytes())).collect();
    encode(&Value::Dict(BTreeMap::from([
        (key("info"), info),
        (key("url-list"), Value::List(list)),
    ])))
}

async fn http_server(files: HashMap<String, Vec<u8>>, corrupt: bool, hits: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let files = Arc::new(files);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let files = Arc::clone(&files);
            let hits = Arc::clone(&hits);
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut buf = [0u8; 2048];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&req).into_owned();
                let path = text.split_whitespace().nth(1).unwrap_or("").to_owned();
                let Some(data) = files.get(&path) else {
                    let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
                    return;
                };
                let range = text
                    .lines()
                    .find_map(|l| l.strip_prefix("Range: bytes="))
                    .and_then(|r| r.split_once('-'))
                    .and_then(|(a, b)| Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?)));
                let Some((a, b)) = range.filter(|(a, b)| a <= b && *b < data.len()) else {
                    let _ = s.write_all(b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n").await;
                    return;
                };
                hits.fetch_add(1, Ordering::SeqCst);
                let mut body = data[a..=b].to_vec();
                if corrupt {
                    body[0] ^= 0xff;
                }
                let head = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {a}-{b}/{}\r\nContent-Length: {}\r\n\r\n",
                    data.len(),
                    body.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    addr
}

fn served(contents: &[Vec<u8>]) -> HashMap<String, Vec<u8>> {
    FILES
        .iter()
        .zip(contents)
        .map(|((path, _), data)| (format!("/payload/{path}"), data.clone()))
        .collect()
}

async fn run(corrupt_first: bool) -> usize {
    let contents: Vec<Vec<u8>> = FILES
        .iter()
        .enumerate()
        .map(|(i, (_, len))| payload(i as u64 + 1, *len))
        .collect();
    let bad_hits = Arc::new(AtomicUsize::new(0));
    let good_hits = Arc::new(AtomicUsize::new(0));
    let first = http_server(served(&contents), corrupt_first, Arc::clone(&bad_hits)).await;
    let mut urls = vec![format!("http://{first}/")];
    if corrupt_first {
        let second = http_server(served(&contents), false, Arc::clone(&good_hits)).await;
        urls.push(format!("http://{second}/"));
    }

    let meta = Arc::new(Metainfo::from_bytes(&build_torrent(&urls, &contents)).unwrap());
    assert_eq!(meta.web_seeds, urls);
    let dir = temp_dir("webseed");
    let ui = Arc::new(RwLock::new(UiState::default()));
    let (_cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let opts = EngineOptions {
        dht_enabled: false,
        port: 0,
        ..Default::default()
    };
    let engine = Engine::with_options(meta, ui.clone(), cmd_rx, opts);
    match tokio::time::timeout(Duration::from_secs(60), engine.run(dir.clone())).await {
        Ok(r) => r.expect("engine failed"),
        Err(_) => {
            let st = ui.read().await;
            let log: Vec<String> = st.log.iter().map(|l| l.message.clone()).collect();
            panic!("download timed out; log={log:#?}");
        }
    }
    for ((path, _), data) in FILES.iter().zip(&contents) {
        let got = std::fs::read(dir.join("payload").join(path)).unwrap();
        assert!(got == *data, "{path} differs");
    }
    assert_eq!(ui.read().await.torrent.as_ref().unwrap().state, DownloadState::Complete);
    let _ = std::fs::remove_dir_all(&dir);
    bad_hits.load(Ordering::SeqCst)
}

#[tokio::test]
async fn downloads_from_web_seed_alone() {
    assert!(run(false).await > 0);
}

#[tokio::test]
async fn corrupt_web_seed_is_retried_via_a_good_one() {
    assert!(run(true).await > 0);
}
