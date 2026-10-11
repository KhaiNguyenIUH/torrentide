use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, RwLock};
use torrentide::bencode::{encode, Value};
use torrentide::engine::{build_seeder, Engine, EngineOptions};
use torrentide::state::{Command, DownloadState, UiState};
use torrentide::storage::{sha1_bytes, Storage};
use torrentide::Metainfo;

const PIECE_LEN: usize = 16 * 1024;

fn key(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

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

fn torrent(data: &[u8]) -> Vec<u8> {
    let pieces: Vec<u8> = data.chunks(PIECE_LEN).flat_map(|c| sha1_bytes(c)).collect();
    let info = Value::Dict(BTreeMap::from([
        (key("name"), Value::Bytes(b"seq.bin".to_vec())),
        (key("length"), Value::Int(data.len() as i64)),
        (key("piece length"), Value::Int(PIECE_LEN as i64)),
        (key("pieces"), Value::Bytes(pieces)),
    ]));
    encode(&Value::Dict(BTreeMap::from([(key("info"), info)])))
}

#[tokio::test]
async fn sequential_mode_is_published_and_toggles_live() {
    let data: Vec<u8> = (0..PIECE_LEN * 20 + 123).map(|i| (i * 31 % 251) as u8).collect();
    let meta = Arc::new(Metainfo::from_bytes(&torrent(&data)).unwrap());

    let seed_dir = temp_dir("seq-seed");
    std::fs::write(seed_dir.join("seq.bin"), &data).unwrap();
    let storage = Arc::new(Storage::prepare(&meta, &seed_dir).unwrap());
    let seeder = build_seeder(storage, &meta, &vec![true; meta.piece_count()]);
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let (seed_addr, _h) = torrentide::peer::pool::listen(Arc::clone(&meta), seeder, 0, events_tx)
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

    let (peers_tx, peers_rx) = mpsc::unbounded_channel();
    peers_tx.send(vec![format!("127.0.0.1:{}", seed_addr.port()).parse().unwrap()]).unwrap();
    let opts = EngineOptions {
        seed_after_complete: true,
        dht_enabled: false,
        extra_peers: Some(peers_rx),
        sequential: true,
        ..Default::default()
    };
    let ui = Arc::new(RwLock::new(UiState::default()));
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let leech_dir = temp_dir("seq-leech");
    let engine = Engine::with_options(Arc::clone(&meta), ui.clone(), cmd_rx, opts);
    let task = tokio::spawn(engine.run(leech_dir.clone()));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut seen_sequential = false;
    loop {
        let t = ui.read().await.torrent.clone();
        if let Some(t) = t {
            seen_sequential |= t.sequential;
            if t.state == DownloadState::Seeding {
                break;
            }
        }
        assert!(tokio::time::Instant::now() < deadline, "download timed out");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(seen_sequential, "sequential never published true");
    assert_eq!(std::fs::read(leech_dir.join("seq.bin")).unwrap(), data);

    cmd_tx.send(Command::SetSequential(false)).unwrap();
    loop {
        if ui.read().await.torrent.as_ref().is_some_and(|t| !t.sequential) {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "toggle never published");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    cmd_tx.send(Command::Stop).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    let _ = std::fs::remove_dir_all(&seed_dir);
    let _ = std::fs::remove_dir_all(&leech_dir);
}
