use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock as StdRwLock};
use std::time::Duration;

use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use torrust::bencode::{self, encode, Value};
use torrust::blocklist::BlockList;
use torrust::engine::{build_seeder, Engine, EngineOptions};
use torrust::peer::connection::{accept, connect, FromPeer, ToPeer};
use torrust::peer::wire::{self, handshake_incoming, handshake_outgoing, Message};
use torrust::peer::PeerStream;
use torrust::ratelimit::Limits;
use torrust::session::Session;
use torrust::state::{Command, DownloadState, EncryptionMode, SessionCommand, Settings, UiState};
use torrust::store::Store;
use torrust::storage::{sha1_bytes, Storage};
use torrust::{InfoHash, Metainfo};

const PIECE_LEN: usize = 16 * 1024;
const WAIT: Duration = Duration::from_secs(10);

fn temp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tt-proto-{tag}-{}-{n}", std::process::id()));
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

fn torrent_with(data_len: usize, pieces: Vec<u8>, announce: &str, private: bool) -> Vec<u8> {
    let mut info = BTreeMap::from([
        (key("name"), Value::Bytes(b"payload.bin".to_vec())),
        (key("length"), Value::Int(data_len as i64)),
        (key("piece length"), Value::Int(PIECE_LEN as i64)),
        (key("pieces"), Value::Bytes(pieces)),
    ]);
    if private {
        info.insert(key("private"), Value::Int(1));
    }
    encode(&Value::Dict(BTreeMap::from([
        (key("announce"), Value::Bytes(announce.as_bytes().to_vec())),
        (key("info"), Value::Dict(info)),
    ])))
}

fn torrent(data: &[u8], announce: &str) -> Vec<u8> {
    let pieces = data.chunks(PIECE_LEN).flat_map(|c| sha1_bytes(c)).collect();
    torrent_with(data.len(), pieces, announce, false)
}

fn fake_torrent(pieces: usize, private: bool) -> Metainfo {
    let hashes: Vec<u8> = (0..pieces * 20).map(|i| (i * 7) as u8).collect();
    let raw = torrent_with(pieces * PIECE_LEN, hashes, "http://127.0.0.1:1/announce", private);
    Metainfo::from_bytes(&raw).unwrap()
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

async fn raw_peer(addr: SocketAddr, ih: InfoHash, fast: bool, ext: bool) -> (TcpStream, wire::Handshake) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    handshake_outgoing(&mut s, &ih.0, false, fast, ext).await.unwrap();
    let hs = handshake_incoming(&mut s).await.unwrap();
    (s, hs)
}

fn loopback(addr: SocketAddr) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], addr.port()))
}

struct Seed {
    addr: SocketAddr,
    meta: Arc<Metainfo>,
    data: Vec<u8>,
    _dir: PathBuf,
}

async fn seed_listener(pieces: usize, complete: bool) -> Seed {
    let data = payload(pieces);
    let dir = temp_dir("seed");
    std::fs::write(dir.join("payload.bin"), &data).unwrap();
    let meta = Arc::new(Metainfo::from_bytes(&torrent(&data, "http://127.0.0.1:1/announce")).unwrap());
    let storage = Arc::new(Storage::prepare(&meta, &dir).unwrap());
    let seeder = complete.then(|| build_seeder(storage, &meta, &vec![true; pieces]).unwrap());
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (addr, _h) = torrust::peer::pool::listen(Arc::clone(&meta), seeder, 0, tx).await.unwrap();
    tokio::spawn(async move {
        let mut live = vec![];
        while let Some((_, ev)) = rx.recv().await {
            if let torrust::peer::connection::FromPeer::Connected(h) = ev {
                live.push(h);
            }
        }
    });
    Seed { addr: loopback(addr), meta, data, _dir: dir }
}

fn no_seeder() -> Arc<StdRwLock<Option<torrust::peer::connection::Seeder>>> {
    Arc::new(StdRwLock::new(None))
}

// ------------------------------------------------------------ BEP 9

#[tokio::test]
async fn ut_metadata_client_fetches_the_info_dict_from_a_running_peer() {
    let meta = fake_torrent(2000, false);
    assert!(meta.info_bytes.len() > 2 * 16 * 1024 - 1, "needs three metadata pieces");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (addr, _h) = torrust::peer::pool::listen(Arc::new(meta.clone()), None, 0, tx).await.unwrap();
    tokio::spawn(async move {
        let mut live = vec![];
        while let Some((_, ev)) = rx.recv().await {
            if let torrust::peer::connection::FromPeer::Connected(h) = ev {
                live.push(h);
            }
        }
    });

    let got = torrust::dht::fetch_metadata_from_peer(loopback(addr), meta.infohash, WAIT, EncryptionMode::Disabled)
        .await
        .unwrap();
    assert_eq!(got, meta.info_bytes);

    assert_eq!(InfoHash(sha1_bytes(&got)), meta.infohash);
}

fn ext_handshake(metadata_id: i64) -> Message {
    let m = Value::Dict(BTreeMap::from([(key("ut_metadata"), Value::Int(metadata_id))]));
    Message::Extended {
        ext_id: 0,
        payload: encode(&Value::Dict(BTreeMap::from([(key("m"), m)]))),
    }
}

fn ut_request(id: u8, piece: i64) -> Message {
    Message::Extended {
        ext_id: id,
        payload: encode(&Value::Dict(BTreeMap::from([
            (key("msg_type"), Value::Int(0)),
            (key("piece"), Value::Int(piece)),
        ]))),
    }
}

async fn metadata_reply_type(s: &mut TcpStream, our_id: u8) -> i64 {
    loop {
        if let Message::Extended { ext_id, payload } = next(s).await {
            if ext_id == our_id {
                let (v, _) = bencode::decode_partial(&payload).unwrap();
                return v.get_int_opt("msg_type").unwrap();
            }
        }
    }
}

#[tokio::test]
async fn metadata_requests_are_bounded_and_rate_limited() {
    let meta = fake_torrent(400, false);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (addr, _h) = torrust::peer::pool::listen(Arc::new(meta.clone()), None, 0, tx).await.unwrap();
    tokio::spawn(async move {
        let mut live = vec![];
        while let Some((_, ev)) = rx.recv().await {
            if let torrust::peer::connection::FromPeer::Connected(h) = ev {
                live.push(h);
            }
        }
    });
    let (mut s, hs) = raw_peer(loopback(addr), meta.infohash, false, true).await;
    assert!(hs.supports_extended());
    send(&mut s, &ext_handshake(7)).await;

    send(&mut s, &ut_request(2, 9999)).await;
    assert_eq!(metadata_reply_type(&mut s, 7).await, 2, "out of range piece is rejected");

    let mut types = Vec::new();
    for _ in 0..70 {
        send(&mut s, &ut_request(2, 0)).await;
    }
    for _ in 0..70 {
        types.push(metadata_reply_type(&mut s, 7).await);
    }
    assert_eq!(types.iter().filter(|t| **t == 1).count(), 63, "one request was spent on the reject");
    assert_eq!(types.iter().filter(|t| **t == 2).count(), 7);
}

#[tokio::test]
async fn private_torrents_do_not_offer_the_extension_protocol() {
    let meta = fake_torrent(4, true);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (addr, _h) = torrust::peer::pool::listen(Arc::new(meta.clone()), None, 0, tx).await.unwrap();
    tokio::spawn(async move {
        let mut live = vec![];
        while let Some((_, ev)) = rx.recv().await {
            if let torrust::peer::connection::FromPeer::Connected(h) = ev {
                live.push(h);
            }
        }
    });
    let (_s, hs) = raw_peer(loopback(addr), meta.infohash, false, true).await;
    assert!(!hs.supports_extended());
}

// ------------------------------------------------------------ BEP 6

#[tokio::test]
async fn fast_peers_get_have_all_or_have_none_and_plain_peers_a_bitfield() {
    let full = seed_listener(4, true).await;
    let (mut s, hs) = raw_peer(full.addr, full.meta.infohash, true, false).await;
    assert!(hs.supports_fast());
    assert!(matches!(next(&mut s).await, Message::HaveAll));

    let (mut s, _) = raw_peer(full.addr, full.meta.infohash, false, false).await;
    match next(&mut s).await {
        Message::Bitfield { bits } => assert_eq!(bits[0] & 0xf0, 0xf0),
        m => panic!("expected a bitfield, got {m:?}"),
    }
    send(&mut s, &Message::HaveAll).await;
    let closed = tokio::time::timeout(WAIT, wire::read_message(&mut s)).await.unwrap();
    assert!(closed.is_err(), "fast message without negotiation must end the connection");

    let empty = seed_listener(4, false).await;
    let (mut s, _) = raw_peer(empty.addr, empty.meta.infohash, true, false).await;
    assert!(matches!(next(&mut s).await, Message::HaveNone));
    let (mut s, _) = raw_peer(empty.addr, empty.meta.infohash, false, false).await;
    assert!(tokio::time::timeout(Duration::from_millis(400), wire::read_message(&mut s)).await.is_err());
}

#[tokio::test]
async fn requests_we_cannot_serve_are_rejected_under_fast_and_ignored_otherwise() {
    let seed = seed_listener(4, true).await;
    let req = |index| Message::Request { index, begin: 0, length: PIECE_LEN as u32 };

    let (mut s, _) = raw_peer(seed.addr, seed.meta.infohash, true, false).await;
    assert!(matches!(next(&mut s).await, Message::HaveAll));
    send(&mut s, &req(1)).await;
    match next(&mut s).await {
        Message::RejectRequest { index: 1, begin: 0, .. } => {}
        m => panic!("expected a reject while choking, got {m:?}"),
    }
    send(&mut s, &Message::Interested).await;
    assert!(matches!(next(&mut s).await, Message::Unchoke));
    send(&mut s, &req(1)).await;
    match next(&mut s).await {
        Message::Piece { index: 1, block, .. } => assert_eq!(block, seed.data[PIECE_LEN..2 * PIECE_LEN]),
        m => panic!("expected the piece, got {m:?}"),
    }
    send(&mut s, &req(99)).await;
    assert!(matches!(next(&mut s).await, Message::RejectRequest { index: 99, .. }));

    let (mut s, _) = raw_peer(seed.addr, seed.meta.infohash, false, false).await;
    assert!(matches!(next(&mut s).await, Message::Bitfield { .. }));
    send(&mut s, &req(1)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(400), wire::read_message(&mut s)).await.is_err(),
        "a peer without fast gets silence, as before"
    );
}

async fn client_to_raw_server(
    fast_server: bool,
) -> (
    torrust::peer::PeerHandle,
    mpsc::UnboundedReceiver<FromPeer>,
    TcpStream,
) {
    let ih = InfoHash([5; 20]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (c_tx, c_rx) = mpsc::unbounded_channel();
    let client = tokio::spawn(connect(addr, ih, 8, no_seeder(), c_tx, Limits::default(), true, None));
    let (mut s, _) = listener.accept().await.unwrap();
    let hs = handshake_incoming(&mut s).await.unwrap();
    assert!(hs.supports_fast());
    handshake_outgoing(&mut s, &ih.0, false, fast_server, false).await.unwrap();
    (client.await.unwrap().unwrap(), c_rx, s)
}

async fn event(rx: &mut mpsc::UnboundedReceiver<FromPeer>, mut want: impl FnMut(&FromPeer) -> bool) -> FromPeer {
    loop {
        let ev = tokio::time::timeout(WAIT, rx.recv()).await.expect("timed out").expect("closed");
        if want(&ev) {
            return ev;
        }
    }
}

#[tokio::test]
async fn reject_request_frees_the_block_and_choke_keeps_requests_under_fast() {
    let (client, mut rx, mut s) = client_to_raw_server(true).await;
    assert!(client.state.lock().await.fast);
    send(&mut s, &Message::HaveAll).await;
    send(&mut s, &Message::Unchoke).await;
    event(&mut rx, |e| matches!(e, FromPeer::Choking(false))).await;

    client.tx.send(ToPeer::Request { index: 3, begin: 0, length: PIECE_LEN as u32 }).unwrap();
    loop {
        if let Message::Request { index: 3, .. } = next(&mut s).await {
            break;
        }
    }
    send(&mut s, &Message::Choke).await;
    event(&mut rx, |e| matches!(e, FromPeer::Choking(true))).await;
    assert_eq!(client.state.lock().await.outstanding.len(), 1, "choke does not drop requests under fast");

    send(&mut s, &Message::RejectRequest { index: 3, begin: 0, length: PIECE_LEN as u32 }).await;
    event(&mut rx, |e| matches!(e, FromPeer::Rejected { index: 3, begin: 0, .. })).await;
    assert!(client.state.lock().await.outstanding.is_empty());

    send(&mut s, &Message::RejectRequest { index: 6, begin: 0, length: 1 }).await;
    send(&mut s, &Message::Unchoke).await;
    let ev = event(&mut rx, |e| matches!(e, FromPeer::Rejected { .. } | FromPeer::Choking(false))).await;
    assert!(matches!(ev, FromPeer::Choking(false)), "a reject for a block never asked for is ignored");
}

#[tokio::test]
async fn allowed_fast_pieces_can_be_requested_while_choked() {
    let (client, mut rx, mut s) = client_to_raw_server(true).await;
    send(&mut s, &Message::HaveAll).await;
    send(&mut s, &Message::AllowedFast { index: 3 }).await;
    send(&mut s, &Message::AllowedFast { index: 1000 }).await;
    event(&mut rx, |e| matches!(e, FromPeer::Bitfield(_))).await;
    for _ in 0..50 {
        if client.state.lock().await.allowed_fast.contains(&3) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(client.state.lock().await.they_choke);
    assert!(client.can_request(3).await);
    assert!(!client.can_request(4).await);
    assert!(!client.state.lock().await.allowed_fast.contains(&1000));
}

#[tokio::test]
async fn without_fast_choke_drops_requests_and_fast_messages_are_errors() {
    let (client, mut rx, mut s) = client_to_raw_server(false).await;
    assert!(!client.state.lock().await.fast);
    send(&mut s, &Message::Unchoke).await;
    event(&mut rx, |e| matches!(e, FromPeer::Choking(false))).await;
    client.tx.send(ToPeer::Request { index: 3, begin: 0, length: PIECE_LEN as u32 }).unwrap();
    loop {
        if let Message::Request { .. } = next(&mut s).await {
            break;
        }
    }
    send(&mut s, &Message::Choke).await;
    event(&mut rx, |e| matches!(e, FromPeer::Choking(true))).await;
    assert!(client.state.lock().await.outstanding.is_empty());

    send(&mut s, &Message::HaveAll).await;
    event(&mut rx, |e| matches!(e, FromPeer::Disconnected(_))).await;
}

#[tokio::test]
async fn two_of_our_peers_negotiate_fast_and_use_have_all() {
    let ih = InfoHash([6; 20]);
    let data = payload(4);
    let dir = temp_dir("pair");
    std::fs::write(dir.join("payload.bin"), &data).unwrap();
    let meta = Metainfo::from_bytes(&torrent(&data, "http://127.0.0.1:1/announce")).unwrap();
    let storage = Arc::new(Storage::prepare(&meta, &dir).unwrap());
    let seeder = build_seeder(storage, &meta, &[true; 4]);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (c_tx, mut c_rx) = mpsc::unbounded_channel();
    let client = tokio::spawn(connect(addr, ih, 4, no_seeder(), c_tx, Limits::default(), true, None));
    let (stream, _) = listener.accept().await.unwrap();
    let (s_tx, _s_rx) = mpsc::unbounded_channel();
    let server = accept(stream, ih, 4, Arc::new(StdRwLock::new(seeder)), s_tx, Limits::default(), true, None)
        .await
        .unwrap();
    let client = client.await.unwrap().unwrap();
    assert!(client.state.lock().await.fast && server.state.lock().await.fast);
    match event(&mut c_rx, |e| matches!(e, FromPeer::Bitfield(_))).await {
        FromPeer::Bitfield(bf) => assert!(bf.full(4)),
        _ => unreachable!(),
    }
}

// --------------------------------------------------------- engine harness

type Inbound = mpsc::UnboundedSender<(PeerStream, SocketAddr, wire::Handshake)>;

struct Running {
    ui: Arc<RwLock<UiState>>,
    cmd: mpsc::UnboundedSender<Command>,
    join: tokio::task::JoinHandle<anyhow::Result<()>>,
}

fn run_engine(meta: Arc<Metainfo>, dir: PathBuf, opts: EngineOptions) -> Running {
    let ui = Arc::new(RwLock::new(UiState::default()));
    let (cmd, cmd_rx) = mpsc::unbounded_channel();
    let engine = Engine::with_options(meta, ui.clone(), cmd_rx, opts);
    let join = tokio::spawn(engine.run(dir));
    Running { ui, cmd, join }
}

async fn wait_for(what: &str, mut cond: impl AsyncFnMut() -> bool) {
    for _ in 0..300 {
        if cond().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn wait_seeding(ui: &Arc<RwLock<UiState>>) {
    wait_for("seeding", async || {
        ui.read().await.torrent.as_ref().is_some_and(|t| t.state == DownloadState::Seeding)
    })
    .await;
}

fn feed(listener: TcpListener, tx: Inbound) {
    tokio::spawn(async move {
        loop {
            let Ok((mut s, addr)) = listener.accept().await else { return };
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Ok(hs) = handshake_incoming(&mut s).await {
                    let _ = tx.send((Box::new(s), addr, hs));
                }
            });
        }
    });
}

async fn seed_engine(pieces: usize, mut opts: EngineOptions) -> (Running, SocketAddr, Arc<Metainfo>, Vec<u8>) {
    let data = payload(pieces);
    let dir = temp_dir("engine-seed");
    std::fs::write(dir.join("payload.bin"), &data).unwrap();
    let meta = Arc::new(Metainfo::from_bytes(&torrent(&data, "http://127.0.0.1:1/announce")).unwrap());
    let (in_tx, in_rx) = mpsc::unbounded_channel();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    feed(listener, in_tx);
    opts.seed_after_complete = true;
    opts.dht_enabled = false;
    opts.inbound = Some(in_rx);
    let running = run_engine(Arc::clone(&meta), dir, opts);
    wait_seeding(&running.ui).await;
    (running, addr, meta, data)
}

// ---------------------------------------------------------------- BEP 16

struct Leech {
    w: tokio::io::WriteHalf<TcpStream>,
    first: Option<u32>,
    empty_start: bool,
    interested: bool,
    unchoked: bool,
    wanted: Vec<u32>,
    requested: HashSet<u32>,
    got: HashMap<u32, Vec<u8>>,
}

#[tokio::test]
async fn super_seeding_reveals_a_different_piece_to_each_peer_and_still_completes() {
    const N: usize = 6;
    let (running, addr, meta, data) = seed_engine(N, EngineOptions::default()).await;
    let (obs, _) = raw_peer(addr, meta.infohash, false, false).await;
    let (mut obs_r, mut observer) = split(obs);
    tokio::spawn(async move { while wire::read_message(&mut obs_r).await.is_ok() {} });
    running.cmd.send(Command::SetSuperSeed(true)).unwrap();
    wait_for("super_seeding flag", async || {
        running.ui.read().await.torrent.as_ref().is_some_and(|t| t.super_seeding)
    })
    .await;

    let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<(usize, Message)>();
    let mut leeches = Vec::new();
    for (i, fast) in [false, true].into_iter().enumerate() {
        let (s, hs) = raw_peer(addr, meta.infohash, fast, false).await;
        assert_eq!(hs.supports_fast(), true);
        let (mut r, w) = split(s);
        let tx = msg_tx.clone();
        tokio::spawn(async move {
            while let Ok(m) = wire::read_message(&mut r).await {
                if tx.send((i, m)).is_err() {
                    return;
                }
            }
        });
        leeches.push(Leech {
            w,
            first: None,
            empty_start: false,
            interested: false,
            unchoked: false,
            wanted: Vec::new(),
            requested: HashSet::new(),
            got: HashMap::new(),
        });
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    while leeches.iter().any(|l| l.got.len() < N) {
        let (i, m) = tokio::time::timeout_at(deadline, msg_rx.recv())
            .await
            .expect("super-seeded download stalled")
            .unwrap();
        match m {
            Message::Bitfield { bits } => {
                assert!(bits.iter().all(|b| *b == 0), "super-seeder must start with an empty bitfield");
                leeches[i].empty_start = true;
            }
            Message::HaveNone => leeches[i].empty_start = true,
            Message::Have { index } => {
                let l = &mut leeches[i];
                assert!(l.empty_start, "no Have before the empty announcement");
                l.first.get_or_insert(index);
                l.wanted.push(index);
                if !l.interested {
                    l.interested = true;
                    send(&mut l.w, &Message::Interested).await;
                }
            }
            Message::Unchoke => leeches[i].unchoked = true,
            Message::Piece { index, begin, block } => {
                let start = index as usize * PIECE_LEN + begin as usize;
                assert_eq!(block, data[start..start + block.len()]);
                leeches[i].got.insert(index, block);
                send(&mut observer, &Message::Have { index }).await;
            }
            _ => {}
        }
        let l = &mut leeches[i];
        if l.unchoked {
            for index in l.wanted.clone() {
                if l.requested.insert(index) {
                    let length = if index as usize + 1 == N { PIECE_LEN - 500 } else { PIECE_LEN } as u32;
                    send(&mut l.w, &Message::Request { index, begin: 0, length }).await;
                }
            }
        }
    }
    assert_ne!(leeches[0].first, leeches[1].first, "each peer is first shown a different piece");
    assert!(leeches.iter().all(|l| l.got.len() == N));
    let _ = running.cmd.send(Command::Stop);
}

#[tokio::test]
async fn super_seeding_toggles_with_the_command_and_follows_completeness() {
    let (running, addr, meta, _data) = seed_engine(3, EngineOptions::default()).await;
    let flag = || async { running.ui.read().await.torrent.as_ref().unwrap().super_seeding };
    assert!(!flag().await);

    running.cmd.send(Command::SetSuperSeed(true)).unwrap();
    wait_for("super seeding on", async || flag().await).await;
    let (mut s, _) = raw_peer(addr, meta.infohash, true, false).await;
    assert!(matches!(next(&mut s).await, Message::HaveNone));
    assert!(matches!(next(&mut s).await, Message::Have { .. }));

    running.cmd.send(Command::SetSuperSeed(false)).unwrap();
    wait_for("super seeding off", async || !flag().await).await;
    let mut have = 0;
    while have < 2 {
        if let Message::Have { .. } = next(&mut s).await {
            have += 1;
        }
    }
    let (mut s2, _) = raw_peer(addr, meta.infohash, true, false).await;
    assert!(matches!(next(&mut s2).await, Message::HaveAll));
    let _ = running.cmd.send(Command::Stop);
}

// -------------------------------------------------------------- trackers

async fn counting_tracker(peer: Option<SocketAddr>) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&hits);
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
            let (body, seen) = (body.clone(), Arc::clone(&seen));
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let line = String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string();
                seen.lock().unwrap().push(line);
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (addr, hits)
}

fn count(hits: &Arc<Mutex<Vec<String>>>, event: &str) -> usize {
    hits.lock().unwrap().iter().filter(|l| l.contains(&format!("event={event}"))).count()
}

#[tokio::test]
async fn add_and_remove_tracker_announce_to_the_current_list() {
    let (t1, hits1) = counting_tracker(None).await;
    let (t2, hits2) = counting_tracker(None).await;
    let data = payload(4);
    let url1 = format!("http://{t1}/announce");
    let url2 = format!("http://{t2}/announce");
    let meta = Arc::new(Metainfo::from_bytes(&torrent(&data, &url1)).unwrap());
    let running = run_engine(meta, temp_dir("leech"), EngineOptions { dht_enabled: false, ..Default::default() });
    wait_for("first announce", async || count(&hits1, "started") == 1).await;
    assert!(hits2.lock().unwrap().is_empty());

    running.cmd.send(Command::AddTracker(url2.clone())).unwrap();
    wait_for("announce to the new tracker", async || count(&hits2, "started") == 1).await;
    wait_for("trackers published", async || {
        running.ui.read().await.torrent.as_ref().unwrap().trackers == [url1.clone(), url2.clone()]
    })
    .await;

    for bad in ["ftp://example.com/announce", "not a url", "http://", "udp:///x", "", "file:///etc/passwd"] {
        running.cmd.send(Command::AddTracker(bad.into())).unwrap();
    }
    running.cmd.send(Command::AddTracker(url2.clone())).unwrap();
    running.cmd.send(Command::AddTracker("UDP://127.0.0.1:9/announce".into())).unwrap();
    wait_for("udp tracker accepted", async || {
        running.ui.read().await.torrent.as_ref().unwrap().trackers.len() == 3
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let listed = running.ui.read().await.torrent.as_ref().unwrap().trackers.clone();
    assert_eq!(listed.len(), 3, "bad schemes and duplicates are rejected: {listed:?}");

    running.cmd.send(Command::RemoveTracker(url2.clone())).unwrap();
    running.cmd.send(Command::RemoveTracker("UDP://127.0.0.1:9/announce".into())).unwrap();
    wait_for("tracker removed", async || {
        running.ui.read().await.torrent.as_ref().unwrap().trackers == [url1.clone()]
    })
    .await;
    running.cmd.send(Command::Stop).unwrap();
    tokio::time::timeout(Duration::from_secs(15), running.join).await.unwrap().unwrap().unwrap();
    assert_eq!(count(&hits1, "stopped"), 1, "the remaining tracker hears about the stop");
    assert_eq!(count(&hits2, "stopped"), 0, "the removed tracker is not announced to");
    let seen = hits2.lock().unwrap().clone();
    assert_eq!(seen.iter().filter(|l| l.contains("/announce")).count(), 1, "{seen:?}");
}

#[tokio::test]
async fn engine_trackers_option_replaces_the_metainfo_list() {
    let (t1, hits1) = counting_tracker(None).await;
    let (t2, hits2) = counting_tracker(None).await;
    let data = payload(4);
    let meta = Arc::new(Metainfo::from_bytes(&torrent(&data, &format!("http://{t1}/announce"))).unwrap());
    let url2 = format!("http://{t2}/announce");
    let opts = EngineOptions {
        dht_enabled: false,
        trackers: Some(vec![url2.clone(), url2.clone(), "gopher://x/y".into()]),
        ..Default::default()
    };
    let running = run_engine(meta, temp_dir("leech"), opts);
    wait_for("announce", async || count(&hits2, "started") == 1).await;
    assert_eq!(running.ui.read().await.torrent.as_ref().unwrap().trackers, [url2]);
    assert!(hits1.lock().unwrap().is_empty());
    let _ = running.cmd.send(Command::Stop);
}

// ------------------------------------------------------------- block list

fn blocklist() -> Option<Arc<BlockList>> {
    Some(Arc::new(BlockList::parse("127.0.0.1 - 127.0.0.1").0))
}

async fn dialled_by_leecher(blocked: bool) -> usize {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = target.accept().await {
            counter.fetch_add(1, Ordering::Relaxed);
            held.push(s);
        }
    });
    let (tracker, hits) = counting_tracker(Some(target_addr)).await;
    let data = payload(4);
    let meta = Arc::new(Metainfo::from_bytes(&torrent(&data, &format!("http://{tracker}/announce"))).unwrap());
    let opts = EngineOptions {
        dht_enabled: false,
        blocklist: if blocked { blocklist() } else { None },
        ..Default::default()
    };
    let running = run_engine(meta, temp_dir("leech"), opts);
    wait_for("announce", async || count(&hits, "started") == 1).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = running.cmd.send(Command::Stop);
    accepted.load(Ordering::Relaxed)
}

#[tokio::test]
async fn a_blocked_address_is_never_dialled() {
    assert!(dialled_by_leecher(false).await >= 1, "control: an unblocked peer is dialled");
    assert_eq!(dialled_by_leecher(true).await, 0);
}

#[tokio::test]
async fn blocked_inbound_connections_are_dropped() {
    let (running, addr, meta, _) =
        seed_engine(3, EngineOptions { blocklist: blocklist(), ..Default::default() }).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    handshake_outgoing(&mut s, &meta.infohash.0, false, false, false).await.unwrap();
    let mut buf = [0u8; 68];
    let r = tokio::time::timeout(WAIT, s.read_exact(&mut buf)).await.unwrap();
    assert!(r.is_err(), "a blocked peer must not get our handshake");
    let _ = running.cmd.send(Command::Stop);

    let (running, addr, meta, _) = seed_engine(3, EngineOptions::default()).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    handshake_outgoing(&mut s, &meta.infohash.0, false, false, false).await.unwrap();
    tokio::time::timeout(WAIT, s.read_exact(&mut buf)).await.unwrap().unwrap();
    let _ = running.cmd.send(Command::Stop);
}

// ------------------------------------------------------------ peer flags

async fn flags_of(h: &torrust::session::SessionHandle, id: &str) -> Vec<String> {
    for _ in 0..600 {
        let flags: Vec<String> = h
            .state()
            .read()
            .await
            .torrents
            .iter()
            .find(|t| t.id == id)
            .map(|t| t.ui.peers.iter().map(|p| p.flags.clone()).collect())
            .unwrap_or_default();
        if !flags.is_empty() {
            return flags;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no peers appeared");
}

async fn flags_run(encryption: EncryptionMode, utp: bool) -> (Vec<String>, Vec<String>) {
    let settings = |dir: &PathBuf| Settings {
        download_dir: dir.clone(),
        listen_port: 0,
        ratio_target: 0.0,
        dht: false,
        port_forwarding: false,
        lsd: false,
        encryption,
        utp,
        ..Settings::default()
    };
    let data = payload(9);
    let seed_dir = temp_dir("flags-seed");
    std::fs::write(seed_dir.join("payload.bin"), &data).unwrap();
    let leech_dir = temp_dir("flags-leech");
    let (seed_tracker, _h) = counting_tracker(None).await;
    let raw = torrent(&data, &format!("http://{seed_tracker}/announce"));
    let id = Metainfo::from_bytes(&raw).unwrap().infohash.to_hex();
    let seed_path = temp_dir("flags-tor").join("seed.torrent");
    std::fs::write(&seed_path, &raw).unwrap();

    let seeder = Session::start_in(Store::at(&temp_dir("flags-home")), settings(&seed_dir)).await.unwrap();
    seeder
        .command()
        .send(SessionCommand::Add { source: seed_path.display().to_string(), dir: Some(seed_dir) })
        .unwrap();
    wait_for("seeder seeding", async || {
        seeder
            .state()
            .read()
            .await
            .torrents
            .iter()
            .find(|t| t.id == id)
            .and_then(|t| t.ui.torrent.as_ref().map(|t| t.state))
            .is_some_and(|s| s == DownloadState::Seeding)
    })
    .await;

    let (leech_tracker, _h) = counting_tracker(Some(SocketAddr::from(([127, 0, 0, 1], seeder.port())))).await;
    let leech_raw = torrent(&data, &format!("http://{leech_tracker}/announce"));
    let leech_path = temp_dir("flags-tor").join("leech.torrent");
    std::fs::write(&leech_path, &leech_raw).unwrap();
    let leecher = Session::start_in(Store::at(&temp_dir("flags-home")), settings(&leech_dir)).await.unwrap();
    leecher
        .command()
        .send(SessionCommand::Add { source: leech_path.display().to_string(), dir: Some(leech_dir) })
        .unwrap();
    let out = (flags_of(&leecher, &id).await, flags_of(&seeder, &id).await);
    let _ = leecher.command().send(SessionCommand::Quit);
    let _ = seeder.command().send(SessionCommand::Quit);
    let _ = leecher.wait().await;
    let _ = seeder.wait().await;
    out
}

#[tokio::test]
async fn peer_flags_show_transport_encryption_direction_and_fast() {
    let (leech, seed) = flags_run(EncryptionMode::Disabled, false).await;
    assert_eq!(leech, ["F"], "outbound plain TCP");
    assert!(seed.iter().all(|f| f.contains('I') && f.contains('F')), "inbound: {seed:?}");

    let (leech, _) = flags_run(EncryptionMode::Require, true).await;
    assert_eq!(leech, ["EPF"], "outbound encrypted uTP");
}
