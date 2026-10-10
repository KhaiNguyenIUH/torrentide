//! A single peer connection: handshake, state tracking, request pipelining,
//! block reassembly, and — when we hold data — serving blocks to others.
//!
//! Both roles share one implementation. The only difference is who dials:
//! [`connect`] dials out as a leecher, [`accept`] takes an inbound socket as a
//! seeder. Both end up with identical reader/writer tasks.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use tokio::io::{split, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, Notify};

use super::wire::{self, Bitfield, Message};
use crate::metainfo::InfoHash;
use crate::ratelimit::Limits;
use crate::storage::Storage;

/// Standard request block size. 16 KiB is what most clients use and keeps the
/// per-request overhead small relative to the payload.
pub const BLOCK_SIZE: u32 = 16 * 1024;

/// How many blocks to keep in flight toward a single peer. Too few wastes
/// bandwidth on high-latency links; too many wastes memory and causes peers to
/// throttle us.
pub const PIPELINE_DEPTH: usize = 16;

/// Idle timeout before we drop a peer that has sent nothing.
const PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Largest block we will serve in one request. A peer asking for more than this
/// is either buggy or trying to make us allocate without bound.
const MAX_UPLOAD_BLOCK: u32 = 128 * 1024;

/// Commands the scheduler sends to a peer.
#[derive(Debug)]
pub enum ToPeer {
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
    SetInterested(bool),
    SetChoking(bool),
    Have(u32),
    /// Shut the connection down: the writer closes its half and the reader ends.
    Close,
    /// Send a raw Bitfield message. Sent internally when the connection comes up.
    SendBitfield(Vec<u8>),
    /// A block we read from local storage in response to a peer's `Request`.
    /// Sent internally; callers should not need this.
    Serve {
        index: u32,
        begin: u32,
        block: Vec<u8>,
    },
}

/// Events a peer reports back to the engine.
#[derive(Debug)]
pub enum FromPeer {
    /// A block of a piece arrived.
    Piece {
        index: u32,
        begin: u32,
        block: Vec<u8>,
    },
    Bitfield(Bitfield),
    Have(u32),
    /// The peer choked (`true`) or unchoked (`false`) us.
    Choking(bool),
    /// The peer became interested in what we have.
    Interested(bool),
    /// Bytes we sent to this peer.
    Uploaded(u32),
    /// An inbound peer connected (only reported for accepted connections).
    Accepted(SocketAddr),
    /// A dialled peer completed its handshake. Carries the live handle so the
    /// pool can adopt it without the engine having to await the connect.
    Connected(Box<PeerHandle>),
    /// A dialled peer failed before or during the handshake.
    ConnectFailed(SocketAddr, String),
    Disconnected(String),
    /// Addresses a peer told us about through peer exchange (BEP 11).
    PexPeers(Vec<SocketAddr>),
}

/// Mutable state shared between the engine and the connection's reader task.
#[derive(Debug, Clone)]
pub struct PeerState {
    pub bitfield: Bitfield,
    /// True when *we* are choking this peer.
    pub am_choking: bool,
    /// True when *we* have told them we want their pieces.
    pub interested: bool,
    /// True when *they* are choking us.
    pub they_choke: bool,
    /// True when *they* have told us they want our pieces.
    pub peer_interested: bool,
    /// Bytes received from this peer since the last rechoke.
    pub window_down: u64,
    /// Bytes sent to this peer since the last rechoke.
    pub window_up: u64,
    /// Blocks requested but not yet received.
    pub outstanding: HashMap<(u32, u32), Instant>,
    pub downloaded: u64,
    pub uploaded: u64,
    pub connected_at: Instant,
    pub last_activity: Instant,
}

impl PeerState {
    pub fn new(piece_count: usize) -> Self {
        PeerState {
            bitfield: Bitfield::with_pieces(piece_count),
            am_choking: true,
            interested: false,
            they_choke: true,
            peer_interested: false,
            window_down: 0,
            window_up: 0,
            outstanding: HashMap::new(),
            downloaded: 0,
            uploaded: 0,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        }
    }

    pub fn idle_for(&self) -> Duration {
        self.last_activity.elapsed()
    }

    pub fn is_dead(&self) -> bool {
        self.idle_for() > PEER_IDLE_TIMEOUT
    }
}

#[derive(Debug)]
pub struct PeerHandle {
    pub addr: SocketAddr,
    pub peer_id: [u8; 20],
    pub state: Arc<Mutex<PeerState>>,
    pub tx: mpsc::UnboundedSender<ToPeer>,
    /// True for a connection we accepted rather than dialled.
    pub inbound: bool,
}

impl PeerHandle {
    /// True if this peer currently has the given piece and is willing to send it.
    pub async fn can_request(&self, index: u32) -> bool {
        let s = self.state.lock().await;
        !s.they_choke && s.interested && s.bitfield.has(index)
    }
}

/// What we are able to serve to other peers.
///
/// Present only when we hold at least one verified piece. `None` means this
/// instance is a pure leecher and will refuse every upload request.
#[derive(Clone)]
pub struct Seeder {
    pub storage: Arc<Storage>,
    /// Pieces we hold and have verified.
    pub bitfield: Bitfield,
    /// Total number of pieces in the torrent, so we know which is the last.
    pub piece_count: usize,
    pub piece_len: u32,
    pub last_piece_len: u32,
}

impl Seeder {
    fn length_of_piece(&self, index: u32) -> u32 {
        if index as usize + 1 == self.piece_count {
            self.last_piece_len
        } else {
            self.piece_len
        }
    }

    /// Read a requested block, refusing anything that runs outside the piece.
    pub fn read_requested(
        &self,
        index: u32,
        begin: u32,
        length: u32,
    ) -> Option<(u32, u32, Vec<u8>)> {
        // Reject requests for pieces we do not have.
        if !self.bitfield.has(index) {
            return None;
        }
        // Reject oversized blocks outright rather than allocating them.
        if length == 0 || length > MAX_UPLOAD_BLOCK {
            return None;
        }
        let piece_len = self.length_of_piece(index);
        if begin >= piece_len {
            return None;
        }
        // Clamp to the piece boundary: a peer asking past the end gets the
        // remainder, never bytes from the following piece.
        let len = std::cmp::min(length, piece_len - begin);
        let offset = index as u64 * self.piece_len as u64 + begin as u64;
        match self.storage.read_at(offset, len as u64) {
            Ok(data) => Some((index, begin, data)),
            Err(e) => {
                tracing::debug!(index, begin, len, error = %e, "cannot serve block");
                None
            }
        }
    }
}

/// The seeder shared between the pool and every live connection, so pieces
/// verified after a connection was made can still be served over it.
pub type SharedSeeder = Arc<RwLock<Option<Seeder>>>;

/// Dial a peer and complete the handshake as the initiating side.
pub async fn connect(
    addr: SocketAddr,
    infohash: InfoHash,
    piece_count: usize,
    seeder: SharedSeeder,
    inbound_tx: mpsc::UnboundedSender<FromPeer>,
    limits: Limits,
    auto_unchoke: bool,
) -> Result<PeerHandle> {
    // A short connect timeout matters: a tracker can hand back many dead peers,
    // and each one that lingers for the full timeout delays the next attempt.
    let stream = tokio::time::timeout(Duration::from_secs(6), TcpStream::connect(addr))
        .await
        .with_context(|| format!("connecting to {addr}"))?
        .with_context(|| format!("connecting to {addr}"))?;

    let _ = stream.set_nodelay(true);
    let (mut rd, mut wr) = split(stream);

    wire::handshake_outgoing(&mut wr, &infohash.0, true, false, false).await?;
    let hs = wire::handshake_incoming(&mut rd).await?;
    if hs.infohash != infohash.0 {
        return Err(anyhow!(
            "peer {addr} served a different infohash ({}) than requested",
            hex::encode(hs.infohash)
        ));
    }

    let handle = spawn_tasks(
        rd,
        wr,
        addr,
        hs.peer_id,
        piece_count,
        seeder,
        inbound_tx,
        false,
        limits,
        auto_unchoke,
    )
    .await?;

    // As the initiator we say up front that we want their data.
    let _ = handle.tx.send(ToPeer::SetInterested(true));
    tracing::debug!(peer = %addr, "handshake complete (outbound)");
    Ok(handle)
}

/// Complete the handshake on an inbound socket and start serving.
pub async fn accept(
    mut stream: TcpStream,
    infohash: InfoHash,
    piece_count: usize,
    seeder: SharedSeeder,
    inbound_tx: mpsc::UnboundedSender<FromPeer>,
    limits: Limits,
    auto_unchoke: bool,
) -> Result<PeerHandle> {
    let hs = wire::handshake_incoming(&mut stream).await?;
    accept_handshaken(
        stream,
        hs,
        infohash,
        piece_count,
        seeder,
        inbound_tx,
        limits,
        auto_unchoke,
    )
    .await
}

/// Like [`accept`], for a socket whose peer handshake was already read (for
/// example by a session listener routing on the infohash).
pub async fn accept_handshaken(
    stream: TcpStream,
    hs: wire::Handshake,
    infohash: InfoHash,
    piece_count: usize,
    seeder: SharedSeeder,
    inbound_tx: mpsc::UnboundedSender<FromPeer>,
    limits: Limits,
    auto_unchoke: bool,
) -> Result<PeerHandle> {
    let addr = stream
        .peer_addr()
        .context("reading peer address of inbound connection")?;
    let _ = stream.set_nodelay(true);
    if hs.infohash != infohash.0 {
        return Err(anyhow!(
            "peer {addr} wants infohash {} but we are serving {}",
            hex::encode(hs.infohash),
            infohash
        ));
    }
    let (rd, mut wr) = split(stream);
    // The dialer waits for our half of the handshake before sending anything.
    wire::handshake_outgoing(&mut wr, &infohash.0, true, false, false).await?;

    // Announce acceptance before the tasks take ownership of the sender.
    let _ = inbound_tx.send(FromPeer::Accepted(addr));
    tracing::info!(peer = %addr, "accepted inbound peer");

    spawn_tasks(
        rd,
        wr,
        addr,
        hs.peer_id,
        piece_count,
        seeder,
        inbound_tx,
        true,
        limits,
        auto_unchoke,
    )
    .await
}

/// Create the per-connection channels and spawn the reader and writer tasks.
async fn spawn_tasks<S>(
    mut rd: tokio::io::ReadHalf<S>,
    mut wr: tokio::io::WriteHalf<S>,
    addr: SocketAddr,
    peer_id: [u8; 20],
    piece_count: usize,
    seeder: SharedSeeder,
    inbound_tx: mpsc::UnboundedSender<FromPeer>,
    inbound: bool,
    limits: Limits,
    auto_unchoke: bool,
) -> Result<PeerHandle>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (peer_tx, mut peer_rx) = mpsc::unbounded_channel::<ToPeer>();
    let state = Arc::new(Mutex::new(PeerState::new(piece_count)));
    let reader_state = Arc::clone(&state);
    let reader_tx = peer_tx.clone();
    let close = Arc::new(Notify::new());
    let reader_close = Arc::clone(&close);
    let reader_limits = limits.clone();
    let reader_seeder = Arc::clone(&seeder);

    // ---- reader ----
    tokio::spawn(async move {
        let mut err_msg: Option<String> = None;
        loop {
            let next_msg = tokio::select! {
                _ = reader_close.notified() => {
                    err_msg = Some("closed locally".into());
                    break;
                }
                m = tokio::time::timeout(PEER_IDLE_TIMEOUT, wire::read_message(&mut rd)) => m,
            };

            match next_msg {
                Err(_) => {
                    err_msg = Some("idle timeout".into());
                    break;
                }
                Ok(Err(e)) => {
                    err_msg = Some(e.to_string());
                    break;
                }
                Ok(Ok(msg)) => {
                    let mut st = reader_state.lock().await;
                    st.last_activity = Instant::now();

                    let mut forward: Option<FromPeer> = None;
                    let mut reply: Option<ToPeer> = None;
                    let mut charge_down = 0usize;

                    match msg {
                        Message::KeepAlive => {}
                        Message::Choke => {
                            st.they_choke = true;
                            st.outstanding.clear();
                            forward = Some(FromPeer::Choking(true));
                        }
                        Message::Unchoke => {
                            st.they_choke = false;
                            forward = Some(FromPeer::Choking(false));
                        }
                        Message::Have { index } => {
                            st.bitfield.set(index);
                            forward = Some(FromPeer::Have(index));
                        }
                        Message::Bitfield { bits } => {
                            // Clamp to the real piece count: a peer may claim
                            // more pieces than the torrent has.
                            let bf = Bitfield::from_wire(&bits, piece_count);
                            st.bitfield = bf.clone();
                            forward = Some(FromPeer::Bitfield(bf));
                        }
                        Message::Interested => {
                            st.peer_interested = true;
                            forward = Some(FromPeer::Interested(true));
                            // Without a choker, a peer that wants data from us
                            // is simply served.
                            // The writer flips `am_choking` when it sends the
                            // unchoke; flipping it here made the writer skip it.
                            if auto_unchoke && st.am_choking {
                                reply = Some(ToPeer::SetChoking(false));
                            }
                        }
                        Message::NotInterested => {
                            st.peer_interested = false;
                            forward = Some(FromPeer::Interested(false));
                        }
                        Message::Piece {
                            index,
                            begin,
                            block,
                        } => {
                            st.outstanding.remove(&(index, begin));
                            st.downloaded += block.len() as u64;
                            st.window_down += block.len() as u64;
                            charge_down = block.len();
                            forward = Some(FromPeer::Piece {
                                index,
                                begin,
                                block,
                            });
                        }
                        Message::Request {
                            index,
                            begin,
                            length,
                        } => {
                            if !st.am_choking {
                                let hit = reader_seeder
                                    .read()
                                    .unwrap()
                                    .as_ref()
                                    .and_then(|s| s.read_requested(index, begin, length));
                                if let Some((i, b, data)) = hit {
                                    st.uploaded += data.len() as u64;
                                    st.window_up += data.len() as u64;
                                    reply = Some(ToPeer::Serve {
                                        index: i,
                                        begin: b,
                                        block: data,
                                    });
                                }
                            }
                        }
                        Message::Cancel { .. } => {}
                        Message::Port { .. } => {}
                        Message::Extended { .. } => {}
                    }

                    drop(st);

                    // ponytail: backpressure only. The kernel socket buffers of
                    // every peer still fill, so real rate overshoots the limit
                    // by about peers x buffer size; shape reads per peer if
                    // that ever matters.
                    if charge_down > 0 {
                        reader_limits.acquire_down(charge_down).await;
                    }

                    if let Some(ev) = forward {
                        if inbound_tx.send(ev).is_err() {
                            break;
                        }
                    }
                    if let Some(cmd) = reply {
                        if reader_tx.send(cmd).is_err() {
                            break;
                        }
                    }
                }
            }
        }

        let _ = inbound_tx.send(FromPeer::Disconnected(
            err_msg.unwrap_or_else(|| "connection closed".into()),
        ));
    });

    // ---- writer ----
    let writer_state = Arc::clone(&state);
    // Queue the initial Bitfield before the loop starts so it is always the
    // first thing the peer sees from us.
    if let Some(s) = seeder.read().unwrap().as_ref() {
        let _ = peer_tx.send(ToPeer::SendBitfield(encode_bitfield(&s.bitfield)));
    }
    tokio::spawn(async move {
        while let Some(cmd) = peer_rx.recv().await {
            let msg = match cmd {
                ToPeer::Request {
                    index,
                    begin,
                    length,
                } => {
                    writer_state
                        .lock()
                        .await
                        .outstanding
                        .insert((index, begin), Instant::now());
                    Message::Request {
                        index,
                        begin,
                        length,
                    }
                }
                ToPeer::Cancel {
                    index,
                    begin,
                    length,
                } => {
                    writer_state.lock().await.outstanding.remove(&(index, begin));
                    Message::Cancel {
                        index,
                        begin,
                        length,
                    }
                }
                ToPeer::SetInterested(true) => {
                    let mut st = writer_state.lock().await;
                    if st.interested {
                        continue;
                    }
                    st.interested = true;
                    Message::Interested
                }
                ToPeer::SetInterested(false) => {
                    let mut st = writer_state.lock().await;
                    if !st.interested {
                        continue;
                    }
                    st.interested = false;
                    st.outstanding.clear();
                    Message::NotInterested
                }
                ToPeer::SetChoking(false) => {
                    let mut st = writer_state.lock().await;
                    if !st.am_choking {
                        continue;
                    }
                    st.am_choking = false;
                    Message::Unchoke
                }
                ToPeer::SetChoking(true) => {
                    let mut st = writer_state.lock().await;
                    if st.am_choking {
                        continue;
                    }
                    st.am_choking = true;
                    Message::Choke
                }
                ToPeer::Have(index) => Message::Have { index },
                ToPeer::Close => break,
                ToPeer::SendBitfield(bytes) => Message::Bitfield { bits: bytes },
                ToPeer::Serve { index, begin, block } => {
                    limits.acquire_up(block.len()).await;
                    Message::Piece {
                        index,
                        begin,
                        block,
                    }
                }
            };

            let framed = wire::encode_framed(&msg);
            if wr.write_all(&framed).await.is_err() {
                break;
            }
            let _ = wr.flush().await;
        }
        let _ = wr.shutdown().await;
        close.notify_one();
    });

    Ok(PeerHandle {
        addr,
        peer_id,
        state,
        tx: peer_tx,
        inbound,
    })
}

/// Encode a bitfield for the wire, trimming any trailing all-zero byte.
fn encode_bitfield(bf: &Bitfield) -> Vec<u8> {
    let mut bytes = bf.as_bytes().to_vec();
    while bytes.len() > 1 && *bytes.last().unwrap() == 0 {
        bytes.pop();
    }
    bytes
}

/// Number of blocks in a piece of the given length.
pub fn block_count(piece_len: u32) -> u32 {
    piece_len.div_ceil(BLOCK_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metainfo::{Files, Metainfo};
    use crate::storage::Storage as S;
    use std::path::Path;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "torrust-conn-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn test_meta(piece_len: u32, total: u64) -> Metainfo {
        let pieces = ((total + piece_len as u64 - 1) / piece_len as u64) as usize;
        Metainfo {
            infohash: InfoHash([7u8; 20]),
            name: "t.bin".into(),
            piece_length: piece_len,
            pieces: vec![[0u8; 20]; pieces],
            files: Files::Single {
                name: "t.bin".into(),
                length: total,
            },
            total_length: total,
            private: false,
            announce: None,
            announce_list: vec![],
        }
    }

    fn seeded_seeder(dir: &Path, meta: &Metainfo, payload: &[u8]) -> Seeder {
        let store = S::prepare(meta, dir).unwrap();
        store.write_at(0, payload).unwrap();
        let mut bf = Bitfield::with_pieces(meta.piece_count());
        for i in 0..meta.piece_count() as u32 {
            bf.set(i);
        }
        Seeder {
            storage: Arc::new(store),
            bitfield: bf,
            piece_count: meta.piece_count(),
            piece_len: meta.piece_length,
            last_piece_len: meta.last_piece_length() as u32,
        }
    }

    #[tokio::test]
    async fn seeder_refuses_blocks_outside_the_piece() {
        let dir = tmpdir("bounds");
        let meta = test_meta(BLOCK_SIZE, BLOCK_SIZE as u64 * 2);
        let s = seeded_seeder(&dir, &meta, &vec![0u8; BLOCK_SIZE as usize * 2]);

        // A read past the end of a piece must be clamped, not allowed to spill
        // into the next piece.
        let (i, b, data) = s.read_requested(0, BLOCK_SIZE - 10, BLOCK_SIZE).unwrap();
        assert_eq!((i, b), (0, BLOCK_SIZE - 10));
        assert_eq!(data.len(), 10, "must clamp to the piece boundary");

        // Past the end of the piece entirely.
        assert!(s.read_requested(0, BLOCK_SIZE, 16).is_none());

        // Absurd length.
        assert!(s.read_requested(0, 0, 10 * 1024 * 1024).is_none());

        // Zero length.
        assert!(s.read_requested(0, 0, 0).is_none());

        // A piece we do not have.
        let mut empty = Bitfield::with_pieces(2);
        empty.set(0);
        let s2 = Seeder { bitfield: empty, ..s.clone() };
        assert!(s2.read_requested(1, 0, 16).is_none());
        assert!(s2.read_requested(0, 0, 16).is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn seeder_last_piece_uses_short_length() {
        let dir = tmpdir("lastpiece");
        // 10 bytes total, one piece of declared length 16384.
        let meta = test_meta(BLOCK_SIZE, 10);
        let s = seeded_seeder(&dir, &meta, b"0123456789");
        assert_eq!(s.length_of_piece(0), 10, "last piece is short");
        let (_, _, data) = s.read_requested(0, 0, BLOCK_SIZE).unwrap();
        assert_eq!(data.len(), 10);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn encode_bitfield_trims_trailing_zero_bytes() {
        let mut bf = Bitfield::with_pieces(8);
        bf.set(0);
        assert_eq!(encode_bitfield(&bf), vec![0b1000_0000]);
        // All-zero bitfield still encodes as one byte, since a zero-length
        // bitfield message is invalid.
        let empty = Bitfield::with_pieces(8);
        assert_eq!(encode_bitfield(&empty), vec![0]);
    }

    #[tokio::test]
    async fn peer_state_tracks_interest_and_choke() {
        let s = PeerState::new(16);
        assert!(s.they_choke, "peers start choked");
        assert!(s.am_choking, "we start choked");
        assert!(!s.interested);
    }

    #[test]
    fn block_count_rounds_up() {
        assert_eq!(block_count(BLOCK_SIZE), 1);
        assert_eq!(block_count(BLOCK_SIZE + 1), 2);
        assert_eq!(block_count(1), 1);
    }

    #[test]
    fn idle_detection() {
        let s = PeerState::new(4);
        assert!(!s.is_dead());
        assert!(s.idle_for() < Duration::from_secs(5));
    }
}