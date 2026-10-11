use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use torrentide::bencode::{encode, Value};
use torrentide::engine::{build_seeder, Engine, EngineOptions};
use torrentide::peer::connection::FromPeer;
use torrentide::peer::pool::{listen, listen_with};
use torrentide::peer::wire::{self, handshake_incoming, handshake_outgoing, Message};
use torrentide::ratelimit::Limits;
use torrentide::state::{Command, UiState};
use torrentide::storage::{sha1_bytes, Storage};
use torrentide::Metainfo;

const PIECE_LEN: usize = 16 * 1024;
const FLOODERS: usize = 4;
const BURSTS: usize = 8;
const WAIT: Duration = Duration::from_secs(10);

fn temp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tt-inb-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn key(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn payload(pieces: usize) -> Vec<u8> {
    let mut x: u64 = 0x9e3779b97f4a7c15;
    (0..pieces * PIECE_LEN - 500)
        .map(|_| {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (x >> 33) as u8
        })
        .collect()
}

fn meta_for(data: &[u8]) -> Arc<Metainfo> {
    let pieces: Vec<u8> = data.chunks(PIECE_LEN).flat_map(|c| sha1_bytes(c)).collect();
    let info = Value::Dict(BTreeMap::from([
        (key("name"), Value::Bytes(b"payload.bin".to_vec())),
        (key("length"), Value::Int(data.len() as i64)),
        (key("piece length"), Value::Int(PIECE_LEN as i64)),
        (key("pieces"), Value::Bytes(pieces)),
    ]));
    let raw = encode(&Value::Dict(BTreeMap::from([(key("info"), info)])));
    Arc::new(Metainfo::from_bytes(&raw).unwrap())
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

async fn next(stream: &mut (impl AsyncReadExt + Unpin)) -> Message {
    loop {
        match tokio::time::timeout(WAIT, wire::read_message(stream)).await {
            Ok(Ok(Message::KeepAlive)) => continue,
            Ok(Ok(m)) => return m,
            other => panic!("expected a message, got {other:?}"),
        }
    }
}

async fn send(stream: &mut (impl AsyncWriteExt + Unpin), m: &Message) {
    stream.write_all(&wire::encode_framed(m)).await.unwrap();
}

async fn raw_peer(addr: SocketAddr, meta: &Metainfo) -> TcpStream {
    let mut s = TcpStream::connect(addr).await.unwrap();
    handshake_outgoing(&mut s, &meta.infohash.0, false, false, false).await.unwrap();
    handshake_incoming(&mut s).await.unwrap();
    s
}

async fn closed_within(s: &mut TcpStream, wait: Duration) -> bool {
    let mut buf = [0u8; 64];
    let deadline = Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, s.read(&mut buf)).await {
            Err(_) => return false,
            Ok(Ok(0)) | Ok(Err(_)) => return true,
            Ok(Ok(_)) => {}
        }
    }
}

struct Drained {
    rx: mpsc::UnboundedReceiver<(SocketAddr, FromPeer)>,
    live: Vec<Box<torrentide::peer::connection::PeerHandle>>,
}

impl Drained {
    async fn event(&mut self) -> FromPeer {
        loop {
            let (_, ev) = tokio::time::timeout(WAIT, self.rx.recv()).await.unwrap().unwrap();
            match ev {
                FromPeer::Connected(h) => self.live.push(h),
                FromPeer::Accepted(_) => {}
                other => return other,
            }
        }
    }
}

#[tokio::test]
async fn idle_inbound_socket_is_closed_after_the_handshake_timeout() {
    let meta = meta_for(&payload(3));
    let (tx, _rx) = mpsc::unbounded_channel();
    let (addr, _h) = listen(Arc::clone(&meta), None, 0, tx).await.unwrap();
    let mut idle = TcpStream::connect(loopback(addr.port())).await.unwrap();
    assert!(!closed_within(&mut idle, Duration::from_secs(5)).await, "still inside the timeout");
    assert!(closed_within(&mut idle, Duration::from_secs(8)).await, "idle socket never closed");
}

#[tokio::test]
async fn pending_handshakes_are_capped() {
    let meta = meta_for(&payload(3));
    let (tx, _rx) = mpsc::unbounded_channel();
    let (addr, _h) = listen(Arc::clone(&meta), None, 0, tx).await.unwrap();
    let mut socks = Vec::new();
    for _ in 0..40 {
        socks.push(TcpStream::connect(loopback(addr.port())).await.unwrap());
    }
    let mut closed = 0;
    for s in &mut socks {
        if closed_within(s, Duration::from_millis(300)).await {
            closed += 1;
        }
    }
    assert_eq!(closed, 8, "40 idle sockets, 32 handshake slots");
}

#[tokio::test]
async fn live_inbound_connections_are_capped_by_max_peers() {
    let data = payload(3);
    let meta = meta_for(&data);
    let shared = Arc::new(std::sync::RwLock::new(None));
    let (tx, rx) = mpsc::unbounded_channel();
    let (addr, _h) = listen_with(Arc::clone(&meta), shared, Limits::default(), true, 2, 0, tx)
        .await
        .unwrap();
    let mut drained = Drained { rx, live: Vec::new() };
    let _a = raw_peer(loopback(addr.port()), &meta).await;
    let _b = raw_peer(loopback(addr.port()), &meta).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut third = TcpStream::connect(loopback(addr.port())).await.unwrap();
    assert!(closed_within(&mut third, Duration::from_secs(2)).await, "third connection above the cap was kept");
    let _ = tokio::time::timeout(Duration::from_millis(100), drained.event()).await;
}

fn engine_opts(port: u16) -> EngineOptions {
    EngineOptions { dht_enabled: false, port, ..Default::default() }
}

#[tokio::test]
async fn listener_task_ends_when_the_engine_returns() {
    let data = payload(3);
    let meta = meta_for(&data);
    let dir = temp_dir("done");
    std::fs::write(dir.join("payload.bin"), &data).unwrap();
    let port = free_port();
    let (_cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let engine = Engine::with_options(
        Arc::clone(&meta),
        Arc::new(RwLock::new(UiState::default())),
        cmd_rx,
        engine_opts(port),
    );
    tokio::time::timeout(Duration::from_secs(20), engine.run(dir)).await.unwrap().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(loopback(port)).await.is_err() {
            break;
        }
        assert!(Instant::now() < deadline, "listener still accepting after the engine returned");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_inbound_peer_sees_pieces_verified_after_it_connected() {
    const N: usize = 8;
    let data = payload(N);
    let meta = meta_for(&data);

    let seed_dir = temp_dir("sd");
    std::fs::write(seed_dir.join("payload.bin"), &data).unwrap();
    let storage = Arc::new(Storage::prepare(&meta, &seed_dir).unwrap());
    let seeder = build_seeder(storage, &meta, &vec![true; N]);
    let (stx, srx) = mpsc::unbounded_channel();
    let (seed_addr, _h) = listen(Arc::clone(&meta), seeder, 0, stx).await.unwrap();
    let mut seed_events = Drained { rx: srx, live: Vec::new() };
    tokio::spawn(async move { loop { seed_events.event().await; } });

    let leech_dir = temp_dir("ld");
    let mut partial = vec![0u8; data.len()];
    partial[..4 * PIECE_LEN].copy_from_slice(&data[..4 * PIECE_LEN]);
    std::fs::write(leech_dir.join("payload.bin"), &partial).unwrap();

    let port = free_port();
    let (peers_tx, peers_rx) = mpsc::unbounded_channel();
    let (_cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let opts = EngineOptions { seed_after_complete: true, extra_peers: Some(peers_rx), ..engine_opts(port) };
    let engine = Engine::with_options(Arc::clone(&meta), Arc::new(RwLock::new(UiState::default())), cmd_rx, opts);
    let task = tokio::spawn(engine.run(leech_dir));

    let mut peer = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    while peer.is_none() {
        match TcpStream::connect(loopback(port)).await {
            Ok(mut s) => {
                handshake_outgoing(&mut s, &meta.infohash.0, false, false, false).await.unwrap();
                handshake_incoming(&mut s).await.unwrap();
                peer = Some(s);
            }
            Err(_) => {
                assert!(Instant::now() < deadline, "leecher never listened");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    let mut peer = peer.unwrap();

    match next(&mut peer).await {
        Message::Bitfield { bits } => assert_eq!(bits, vec![0b1111_0000]),
        other => panic!("expected Bitfield, got {other:?}"),
    }
    send(&mut peer, &Message::Interested).await;
    peers_tx.send(vec![loopback(seed_addr.port())]).unwrap();

    let mut haves = [false; N];
    let mut unchoked = false;
    while !(unchoked && haves[4..].iter().all(|h| *h)) {
        match next(&mut peer).await {
            Message::Have { index } => haves[index as usize] = true,
            Message::Unchoke => unchoked = true,
            _ => {}
        }
    }

    send(&mut peer, &Message::Request { index: 7, begin: 0, length: 1000 }).await;
    loop {
        if let Message::Piece { index, block, .. } = next(&mut peer).await {
            assert_eq!(index, 7);
            assert_eq!(block, data[7 * PIECE_LEN..7 * PIECE_LEN + 1000]);
            break;
        }
    }
    task.abort();
}

async fn adopted_peer(meta: &Metainfo) -> (TcpStream, (torrentide::peer::PeerStream, SocketAddr, wire::Handshake)) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::spawn({
        let ih = meta.infohash.0;
        async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            handshake_outgoing(&mut c, &ih, false, false, false).await.unwrap();
            c
        }
    });
    let (mut server, from) = listener.accept().await.unwrap();
    let hs = handshake_incoming(&mut server).await.unwrap();
    let c = client.await.unwrap();
    let boxed: torrentide::peer::PeerStream = Box::new(server);
    let item = (boxed, from, hs);
    (c, item)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn event_flood_does_not_delay_a_stop_command() {
    let data = payload(4);
    let meta = meta_for(&data);
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let opts = EngineOptions { inbound: Some(inbound_rx), ..engine_opts(free_port()) };
    let engine = Engine::with_options(Arc::clone(&meta), Arc::new(RwLock::new(UiState::default())), cmd_rx, opts);
    let task = tokio::spawn(engine.run(temp_dir("flood")));
    tokio::time::sleep(Duration::from_millis(500)).await;

    let burst = Arc::new(wire::encode_framed(&Message::Have { index: 0 }).repeat(100_000));
    let mut floods = Vec::new();
    for _ in 0..FLOODERS {
        let (mut client, item) = adopted_peer(&meta).await;
        inbound_tx.send(item).unwrap();
        handshake_incoming(&mut client).await.unwrap();
        let burst = Arc::clone(&burst);
        floods.push(tokio::spawn(async move {
            for _ in 0..BURSTS {
                if client.write_all(&burst).await.is_err() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let started = Instant::now();
    cmd_tx.send(Command::Stop).unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(10), task).await;
    for f in &floods {
        f.abort();
    }
    assert!(ended.is_ok(), "engine never stopped");
    assert!(started.elapsed() < Duration::from_secs(1), "stop took {:?}", started.elapsed());
}

fn partial_seeder_pieces() -> (Arc<Metainfo>, Vec<u8>) {
    let data = payload(17);
    (meta_for(&data), data)
}

#[tokio::test]
async fn have_beyond_the_piece_count_closes_the_connection() {
    let (meta, _data) = partial_seeder_pieces();
    let (tx, rx) = mpsc::unbounded_channel();
    let (addr, _h) = listen(Arc::clone(&meta), None, 0, tx).await.unwrap();
    let mut drained = Drained { rx, live: Vec::new() };
    let mut peer = raw_peer(loopback(addr.port()), &meta).await;

    send(&mut peer, &Message::Have { index: 17 }).await;
    loop {
        match drained.event().await {
            FromPeer::Have(i) => panic!("forwarded out-of-range have {i}"),
            FromPeer::Disconnected(_) => break,
            _ => {}
        }
    }
    assert!(closed_within(&mut peer, Duration::from_secs(2)).await);
}

#[tokio::test]
async fn bitfield_length_must_be_exact() {
    let (meta, _data) = partial_seeder_pieces();
    let (tx, rx) = mpsc::unbounded_channel();
    let (addr, _h) = listen(Arc::clone(&meta), None, 0, tx).await.unwrap();
    let mut drained = Drained { rx, live: Vec::new() };

    let mut short = raw_peer(loopback(addr.port()), &meta).await;
    send(&mut short, &Message::Bitfield { bits: vec![0xff] }).await;
    loop {
        match drained.event().await {
            FromPeer::Bitfield(_) => panic!("accepted a short bitfield"),
            FromPeer::Disconnected(_) => break,
            _ => {}
        }
    }
    let mut long = raw_peer(loopback(addr.port()), &meta).await;
    send(&mut long, &Message::Bitfield { bits: vec![0xff; 4] }).await;
    loop {
        match drained.event().await {
            FromPeer::Bitfield(_) => panic!("accepted a long bitfield"),
            FromPeer::Disconnected(_) => break,
            _ => {}
        }
    }

    let mut exact = raw_peer(loopback(addr.port()), &meta).await;
    send(&mut exact, &Message::Bitfield { bits: vec![0xff, 0xff, 0x80] }).await;
    loop {
        if let FromPeer::Bitfield(bf) = drained.event().await {
            assert_eq!(bf.count(), 17);
            break;
        }
    }
}

#[tokio::test]
async fn our_bitfield_is_exactly_ceil_pieces_over_eight_bytes() {
    let (meta, data) = partial_seeder_pieces();
    let dir = temp_dir("bf");
    std::fs::write(dir.join("payload.bin"), &data).unwrap();
    let storage = Arc::new(Storage::prepare(&meta, &dir).unwrap());
    let mut have = vec![false; 17];
    have[0] = true;
    let seeder = build_seeder(storage, &meta, &have);
    let (tx, _rx) = mpsc::unbounded_channel();
    let (addr, _h) = listen(Arc::clone(&meta), seeder, 0, tx).await.unwrap();
    let mut peer = raw_peer(loopback(addr.port()), &meta).await;
    match next(&mut peer).await {
        Message::Bitfield { bits } => assert_eq!(bits, vec![0x80, 0, 0]),
        other => panic!("expected Bitfield, got {other:?}"),
    }
}
