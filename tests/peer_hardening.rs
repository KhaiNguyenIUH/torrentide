use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc;
use torrentide::metainfo::{Files, InfoHash, Metainfo};
use torrentide::peer::connection::{accept, connect, FromPeer, PeerHandle, Seeder, ToPeer};
use torrentide::peer::wire::{self, handshake_incoming, handshake_outgoing, Message};
use torrentide::peer::Bitfield;
use torrentide::ratelimit::Limits;
use torrentide::storage::Storage;

const WAIT: Duration = Duration::from_secs(10);
const PL: u32 = 128 * 1024;
const PIECES: usize = 8;
const IH: InfoHash = InfoHash([7; 20]);

fn temp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tt-harden-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn seeder() -> Seeder {
    let total = PL as u64 * PIECES as u64;
    let meta = Metainfo {
        infohash: IH,
        name: "t".into(),
        piece_length: PL,
        pieces: vec![[0; 20]; PIECES],
        files: Files::Single { name: "t".into(), length: total },
        total_length: total,
        private: false,
        announce: None,
        announce_list: vec![],
        web_seeds: vec![],
        info_bytes: vec![],
    };
    let storage = Arc::new(Storage::prepare(&meta, &temp_dir("seed")).unwrap());
    storage.write_at(0, &vec![0xAB; total as usize]).unwrap();
    Seeder { storage, bitfield: Bitfield::all(PIECES), piece_count: PIECES, piece_len: PL, last_piece_len: PL, super_seed: false }
}

fn shared(s: Option<Seeder>) -> Arc<StdRwLock<Option<Seeder>>> {
    Arc::new(StdRwLock::new(s))
}

struct Stalled {
    handle: PeerHandle,
    rx: mpsc::UnboundedReceiver<FromPeer>,
    attacker: TcpStream,
}

async fn stalled_peer() -> Stalled {
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_send_buffer_size(4096).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(8).unwrap();
    let addr = listener.local_addr().unwrap();

    let client = TcpSocket::new_v4().unwrap();
    client.set_recv_buffer_size(4096).unwrap();
    let (server, client) = tokio::join!(listener.accept(), client.connect(addr));
    let (stream, _) = server.unwrap();
    let mut attacker = client.unwrap();

    let (tx, rx) = mpsc::unbounded_channel();
    let accepting = tokio::spawn(accept(stream, IH, PIECES, shared(Some(seeder())), tx, Limits::default(), true, None));
    handshake_outgoing(&mut attacker, &IH.0, false, false, false).await.unwrap();
    let handle = accepting.await.unwrap().unwrap();
    send(&mut attacker, &Message::Interested).await;
    wait_until("unchoked", || async { !handle.state.lock().await.am_choking }).await;
    Stalled { handle, rx, attacker }
}

async fn wait_until(what: &str, mut cond: impl AsyncFnMut() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !cond().await {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

async fn send(stream: &mut TcpStream, m: &Message) {
    stream.write_all(&wire::encode_framed(m)).await.unwrap();
}

#[tokio::test]
async fn request_flood_from_a_peer_that_never_reads_stays_bounded_and_uncredited() {
    let mut p = stalled_peer().await;
    for i in 0..2000u32 {
        send(&mut p.attacker, &Message::Request { index: i % PIECES as u32, begin: 0, length: PL }).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let st = p.handle.state.lock().await;
    assert!(st.serve_queue.len() <= 64, "queued {}", st.serve_queue.len());
    assert!(st.uploaded < 16 << 20, "credited {} bytes that were never sent", st.uploaded);
    drop(st);
    drop(p.rx);
}

#[tokio::test]
async fn cancel_removes_a_queued_request() {
    let mut p = stalled_peer().await;
    for i in 0..8u32 {
        send(&mut p.attacker, &Message::Request { index: i, begin: 0, length: PL }).await;
    }
    wait_until("requests queued", || async { p.handle.state.lock().await.serve_queue.len() >= 5 }).await;
    send(&mut p.attacker, &Message::Cancel { index: 7, begin: 0, length: PL }).await;
    wait_until("cancel applied", || async {
        !p.handle.state.lock().await.serve_queue.iter().any(|r| r.0 == 7)
    })
    .await;
    assert!(p.handle.state.lock().await.serve_queue.iter().any(|r| r.0 == 6));
}

#[tokio::test]
async fn a_writer_stuck_on_a_peer_that_never_reads_times_out_and_closes() {
    let mut p = stalled_peer().await;
    for i in 0..4u32 {
        send(&mut p.attacker, &Message::Request { index: i, begin: 0, length: PL }).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(61)).await;
    let gone = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(ev) = p.rx.recv().await {
            if matches!(ev, FromPeer::Disconnected(_)) {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(gone, Ok(true));
    assert_eq!(p.handle.state.lock().await.uploaded < 16 << 20, true);
}

async fn idle_pair() -> (PeerHandle, mpsc::UnboundedReceiver<FromPeer>, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let accepting = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        accept(stream, IH, PIECES, shared(None), tx, Limits::default(), true, None).await.unwrap()
    });
    let mut c = TcpStream::connect(addr).await.unwrap();
    handshake_outgoing(&mut c, &IH.0, false, false, false).await.unwrap();
    (accepting.await.unwrap(), rx, c)
}

async fn reaches_eof(s: &mut TcpStream) -> bool {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut buf = [0u8; 256];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn dropping_the_handle_closes_the_socket() {
    let (handle, _rx, mut c) = idle_pair().await;
    drop(handle);
    assert!(reaches_eof(&mut c).await);
}

#[tokio::test]
async fn close_closes_the_socket() {
    let (handle, _rx, mut c) = idle_pair().await;
    handle.tx.send(ToPeer::Close).unwrap();
    assert!(reaches_eof(&mut c).await);
}

async fn leecher_and_raw_server() -> (PeerHandle, mpsc::UnboundedReceiver<FromPeer>, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let client = tokio::spawn(connect(addr, IH, PIECES, shared(None), tx, Limits::default(), true, None));
    let (mut s, _) = listener.accept().await.unwrap();
    handshake_incoming(&mut s).await.unwrap();
    handshake_outgoing(&mut s, &IH.0, false, false, false).await.unwrap();
    (client.await.unwrap().unwrap(), rx, s)
}

async fn next_request(s: &mut TcpStream) {
    loop {
        let m = tokio::time::timeout(WAIT, wire::read_message(s)).await.unwrap().unwrap();
        if matches!(m, Message::Request { .. }) {
            return;
        }
    }
}

async fn pieces_until_marker(rx: &mut mpsc::UnboundedReceiver<FromPeer>) -> Vec<(u32, u32, usize)> {
    let mut got = vec![];
    loop {
        match tokio::time::timeout(WAIT, rx.recv()).await.unwrap().unwrap() {
            FromPeer::Piece { index, begin, block } => got.push((index, begin, block.len())),
            FromPeer::Have(7) => return got,
            _ => {}
        }
    }
}

#[tokio::test]
async fn only_requested_blocks_of_the_requested_length_reach_the_engine() {
    let (client, mut rx, mut s) = leecher_and_raw_server().await;
    send(&mut s, &Message::Unchoke).await;
    client.tx.send(ToPeer::SetInterested(true)).unwrap();
    client.tx.send(ToPeer::Request { index: 2, begin: 0, length: 16 * 1024 }).unwrap();
    next_request(&mut s).await;

    let piece = |index, begin, len: usize| Message::Piece { index, begin, block: vec![9; len] };
    send(&mut s, &piece(5, 0, 16 * 1024)).await;
    send(&mut s, &piece(2, 16 * 1024, 16 * 1024)).await;
    send(&mut s, &piece(2, 0, 100)).await;
    send(&mut s, &piece(2, 0, 16 * 1024)).await;
    send(&mut s, &piece(2, 0, 16 * 1024)).await;
    send(&mut s, &Message::Have { index: 7 }).await;

    assert_eq!(pieces_until_marker(&mut rx).await, vec![(2, 0, 16 * 1024)]);
}
