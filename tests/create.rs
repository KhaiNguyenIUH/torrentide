use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use torrust::bencode::{self, encode, Value};
use torrust::create::{auto_piece_len, build, CreateOptions, MAX_PIECE_LEN, MIN_PIECE_LEN};
use torrust::engine::{build_seeder, Engine};
use torrust::state::{DownloadState, UiState};
use torrust::storage::{sha1_bytes, Storage};
use torrust::Metainfo;

const PIECE: u32 = 16 * 1024;

fn temp_dir(tag: &str) -> PathBuf {
    // Tests run in parallel and the clock can return the same value twice, so
    // a counter keeps two calls from sharing a directory.
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("torrust-{tag}-{}-{nanos}-{n}", std::process::id()));
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

const TREE: [(&str, usize); 5] = [
    ("b.bin", 40_000),
    ("a/z.bin", 100_003),
    ("a/empty", 0),
    ("a/y/deep.bin", 5),
    ("c.bin", 32_768),
];

fn make_tree(root: &Path) -> Vec<(&'static str, Vec<u8>)> {
    TREE.iter()
        .enumerate()
        .map(|(i, (p, len))| {
            let data = payload(i as u64 + 1, *len);
            let full = root.join(p);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, &data).unwrap();
            (*p, data)
        })
        .collect()
}

fn opts(path: &Path) -> CreateOptions {
    CreateOptions { path: path.to_path_buf(), piece_len: Some(PIECE), ..Default::default() }
}

fn info_hash_of(raw: &[u8]) -> [u8; 20] {
    let root = bencode::decode(raw).unwrap();
    sha1_bytes(&encode(root.get("info").unwrap()))
}

fn verify_pieces(meta: &Metainfo, flat: &[u8]) {
    assert_eq!(meta.pieces.len(), flat.len().div_ceil(meta.piece_length as usize));
    for (i, chunk) in flat.chunks(meta.piece_length as usize).enumerate() {
        assert_eq!(meta.pieces[i], sha1_bytes(chunk), "piece {i}");
    }
}

#[test]
fn single_file() {
    let dir = temp_dir("create-single");
    let data = payload(9, 50_001);
    let path = dir.join("one.bin");
    std::fs::write(&path, &data).unwrap();

    let mut o = opts(&path);
    o.comment = Some("hello".into());
    let t = build(&o).unwrap();
    let meta = Metainfo::from_bytes(&t.bytes).unwrap();
    assert_eq!(meta.infohash.0, info_hash_of(&t.bytes));
    assert_eq!(meta.infohash, t.infohash);
    assert_eq!(meta.name, "one.bin");
    assert_eq!(t.total, 50_001);
    assert_eq!(t.pieces, 4);
    assert!(matches!(meta.files, torrust::metainfo::Files::Single { length: 50_001, .. }));
    verify_pieces(&meta, &data);
    assert!(!meta.private);
    assert!(t.magnet.starts_with(&format!("magnet:?xt=urn:btih:{}&dn=one%2Ebin", t.infohash.to_hex())));

    let root = bencode::decode(&t.bytes).unwrap();
    assert_eq!(root.get("comment").unwrap().as_str().unwrap(), "hello");
    assert!(root.get_opt("creation date").is_some());
    assert!(root.get("created by").unwrap().as_str().unwrap().starts_with("torrust "));
    assert!(root.get_opt("announce").is_none());
}

#[test]
fn nested_multi_file() {
    let dir = temp_dir("create-multi");
    let root = dir.join("tree");
    let files = make_tree(&root);

    let mut o = opts(&root);
    o.trackers = vec!["http://t1/announce".into(), "udp://t2:80/announce".into()];
    o.web_seeds = vec!["http://ws.example/data/".into()];
    o.private = true;
    o.source = Some("SRC".into());
    o.no_date = true;
    let t = build(&o).unwrap();
    let meta = Metainfo::from_bytes(&t.bytes).unwrap();
    assert_eq!(meta.infohash.0, info_hash_of(&t.bytes));
    assert_eq!(meta.name, "tree");
    assert!(meta.private);

    let mut sorted: Vec<_> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.split('/').cmp(b.0.split('/')));
    let listed: Vec<(String, u64)> = meta
        .files
        .iter()
        .map(|(p, l)| (p.strip_prefix("tree").unwrap().to_string_lossy().replace('\\', "/"), l))
        .collect();
    let expected: Vec<(String, u64)> = sorted.iter().map(|(p, d)| (p.to_string(), d.len() as u64)).collect();
    assert_eq!(listed, expected);
    let flat: Vec<u8> = sorted.iter().flat_map(|(_, d)| d.iter().copied()).collect();
    assert_eq!(meta.total_length, flat.len() as u64);
    verify_pieces(&meta, &flat);

    assert_eq!(meta.announce.as_deref(), Some("http://t1/announce"));
    let raw = bencode::decode(&t.bytes).unwrap();
    let tiers = raw.get("announce-list").unwrap().as_list().unwrap();
    assert_eq!(tiers.len(), 2);
    assert_eq!(tiers[1].as_list().unwrap()[0].as_str().unwrap(), "udp://t2:80/announce");
    assert_eq!(meta.web_seeds, vec!["http://ws.example/data/"]);
    assert_eq!(raw.get("info").unwrap().get("source").unwrap().as_str().unwrap(), "SRC");
    assert!(raw.get_opt("creation date").is_none());
    assert!(t.magnet.contains("&tr=http%3A%2F%2Ft1%2Fannounce"));
    assert!(t.magnet.contains("&ws=http%3A%2F%2Fws%2Eexample%2Fdata%2F"));
}

#[test]
fn auto_piece_size_in_bounds() {
    for total in [1u64, 16 * 1024, 1 << 20, 100 << 20, 5 << 30, 1 << 50] {
        let p = auto_piece_len(total);
        assert!(p.is_power_of_two() && (MIN_PIECE_LEN..=MAX_PIECE_LEN).contains(&p), "{total} -> {p}");
        let pieces = total.div_ceil(p as u64);
        if total >= 32 << 20 && total <= 1 << 40 {
            assert!((1000..=2000).contains(&pieces), "{total}: {pieces}");
        }
    }
}

#[test]
fn rejects_bad_input() {
    let dir = temp_dir("create-bad");
    let f = dir.join("f");
    std::fs::write(&f, b"x").unwrap();
    for bad in [0, 1000, 8 * 1024, 32 * 1024 * 1024, 3 * 16 * 1024] {
        let mut o = opts(&f);
        o.piece_len = Some(bad);
        assert!(build(&o).is_err(), "{bad}");
    }
    let empty = dir.join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    assert!(build(&opts(&empty)).is_err());
}

#[test]
fn cli_refuses_overwrite_without_force() {
    let dir = temp_dir("create-cli");
    std::fs::write(dir.join("f.bin"), payload(1, 1000)).unwrap();
    let exe = env!("CARGO_BIN_EXE_torrust");
    let run = |force: bool| {
        let mut c = std::process::Command::new(exe);
        c.current_dir(&dir).args(["create", "f.bin", "--no-date"]);
        if force {
            c.arg("--force");
        }
        c.output().unwrap()
    };
    assert!(run(false).status.success());
    let first = std::fs::read(dir.join("f.bin.torrent")).unwrap();
    let again = run(false);
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("already exists"));
    assert!(run(true).status.success());
    assert_eq!(std::fs::read(dir.join("f.bin.torrent")).unwrap(), first);
}

fn key(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
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

#[tokio::test]
async fn created_torrent_downloads_identically() {
    let seed_dir = temp_dir("create-seed");
    let leech_dir = temp_dir("create-leech");
    let root = seed_dir.join("tree");
    let files = make_tree(&root);

    let bare = build(&opts(&root)).unwrap();
    let placeholder = Metainfo::from_bytes(&bare.bytes).unwrap();
    let storage = Arc::new(Storage::prepare(&placeholder, &seed_dir).unwrap());
    let seeder = build_seeder(storage, &placeholder, &vec![true; placeholder.piece_count()]);
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let (seed_addr, _h) = torrust::peer::pool::listen(Arc::new(placeholder), seeder, 0, events_tx)
        .await
        .unwrap();
    tokio::spawn(async move {
        let mut live = vec![];
        while let Some((_, ev)) = events_rx.recv().await {
            if let torrust::peer::connection::FromPeer::Connected(h) = ev {
                live.push(h);
            }
        }
    });

    let tracker = mock_tracker(seed_addr).await;
    let mut o = opts(&root);
    o.trackers = vec![format!("http://{tracker}/announce")];
    let created = build(&o).unwrap();
    assert_eq!(created.infohash, bare.infohash);
    let meta = Arc::new(Metainfo::from_bytes(&created.bytes).unwrap());

    let ui = Arc::new(RwLock::new(UiState::default()));
    let (_cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let engine = Engine::new(meta, ui.clone(), cmd_rx);
    tokio::time::timeout(Duration::from_secs(60), engine.run(leech_dir.clone()))
        .await
        .expect("download timed out")
        .expect("engine failed");

    for (p, data) in &files {
        assert!(std::fs::read(leech_dir.join("tree").join(p)).unwrap() == *data, "{p} differs");
    }
    assert_eq!(ui.read().await.torrent.as_ref().unwrap().state, DownloadState::Complete);
}
