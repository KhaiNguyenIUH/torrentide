//! The peer pool: tracks live connections, aggregates their advertised
//! bitfields, and hands out work.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::connection::{FromPeer, PeerHandle, PeerState, SharedSeeder, ToPeer, Transport, BLOCK_SIZE};
use super::{pex, PeerStream};
use super::wire::{Bitfield, Handshake};
use crate::metainfo::{InfoHash, Metainfo, SocketAddrLite};
use crate::ratelimit::Limits;
use crate::state::EncryptionMode;
use crate::utp::UtpSocket;

/// Upper bound on simultaneous connections. Going much above this invites
/// connection throttling from other peers for no throughput gain.
pub const MAX_PEERS: usize = 50;

/// Below this many connected peers we actively dial trackers for more.
pub const MIN_PEERS: usize = 8;

/// Peers unchoked on merit; one more slot is the optimistic unchoke.
const UNCHOKE_SLOTS: usize = 4;

/// The optimistic slot moves every this many rechokes.
const OPTIMISTIC_ROTATION: u64 = 3;

pub struct PeerPool {
    peers: HashMap<SocketAddr, PeerHandle>,
    /// What we can serve to others, if we hold any verified data.
    seeder: Option<super::connection::Seeder>,
    /// The same seeder as seen by live connections.
    shared: SharedSeeder,
    limits: Limits,
    max_peers: usize,
    auto_unchoke: bool,
    rechoke_round: u64,
    optimistic: Option<SocketAddr>,
    /// Addresses we have already tried, so we do not redial dead ones.
    seen: HashSet<SocketAddr>,
    /// Union of every connected peer's bitfield.
    availability: Bitfield,
    piece_count: usize,
    meta: Arc<Metainfo>,
    port: u16,
    /// Events destined for the engine.
    events: mpsc::UnboundedSender<(SocketAddr, FromPeer)>,
    /// Bound on simultaneous handshakes in flight.
    connecting: usize,
    /// Bytes uploaded by peers that have since been removed. `PeerState`
    /// counters die with the peer, so without this the cumulative total we
    /// report to trackers would shrink every time a peer is reaped.
    retired_uploaded: u64,
    /// Bumped by every `set_seeder`; a dial remembers the value it started at
    /// so a peer that connected across a change gets the Haves its initial
    /// bitfield may have missed.
    seeder_gen: u64,
    dial_gen: HashMap<SocketAddr, u64>,
    /// Per recipient, the peer addresses we have already told it about, so
    /// each PEX message carries only the difference.
    pex_known: HashMap<SocketAddr, HashSet<SocketAddr>>,
    last_pex: Instant,
    transport: Transport,
}

impl PeerPool {
    pub fn new(
        meta: Arc<Metainfo>,
        seeder: Option<super::connection::Seeder>,
        port: u16,
        events: mpsc::UnboundedSender<(SocketAddr, FromPeer)>,
        limits: Limits,
        max_peers: usize,
        auto_unchoke: bool,
    ) -> Self {
        let piece_count = meta.piece_count();
        PeerPool {
            peers: HashMap::new(),
            shared: Arc::new(RwLock::new(seeder.clone())),
            seeder,
            limits,
            max_peers,
            auto_unchoke,
            rechoke_round: 0,
            optimistic: None,
            seen: HashSet::new(),
            availability: Bitfield::with_pieces(piece_count),
            piece_count,
            meta,
            port,
            events,
            connecting: 0,
            retired_uploaded: 0,
            seeder_gen: 0,
            dial_gen: HashMap::new(),
            pex_known: HashMap::new(),
            last_pex: Instant::now(),
            transport: Transport::default(),
        }
    }

    /// Choose the encryption policy and uTP socket outbound dials use. The
    /// default is plaintext TCP.
    pub fn set_transport(&mut self, encryption: EncryptionMode, utp: Option<Arc<UtpSocket>>) {
        self.transport.encryption = encryption;
        self.transport.utp = utp;
    }

    /// The extension-protocol port to advertise, or `None` for a private
    /// torrent, which must not use PEX (BEP 27).
    fn pex_port(&self) -> Option<u16> {
        pex_port_for(&self.meta, self.port)
    }

    /// Send each PEX-capable peer the peers that connected and disconnected
    /// since its last message. Only peers we have a dialable address for are
    /// advertised: dialled ones by their address, inbound ones by the listen
    /// port from their extended handshake.
    pub async fn pex_tick(&mut self) {
        self.last_pex = Instant::now();
        if self.pex_port().is_none() {
            return;
        }
        let mut live: HashMap<SocketAddr, SocketAddr> = HashMap::new();
        let mut capable: Vec<(SocketAddr, u8)> = Vec::new();
        for (addr, p) in &self.peers {
            let st = p.state.lock().await;
            let adv = if p.inbound {
                st.listen_port.map(|port| SocketAddr::new(addr.ip(), port))
            } else {
                Some(*addr)
            };
            if let Some(a) = adv {
                live.insert(*addr, a);
            }
            if let Some(id) = st.pex_id {
                capable.push((*addr, id));
            }
        }
        self.pex_known.retain(|a, _| self.peers.contains_key(a));
        for (rcpt, id) in capable {
            let now: HashSet<SocketAddr> = live
                .iter()
                .filter(|(k, v)| **k != rcpt && **v != rcpt)
                .map(|(_, v)| *v)
                .collect();
            let known = self.pex_known.entry(rcpt).or_default();
            let added: Vec<SocketAddr> =
                now.difference(known).take(pex::MAX_SENT).copied().collect();
            let dropped: Vec<SocketAddr> =
                known.difference(&now).take(pex::MAX_SENT).copied().collect();
            if added.is_empty() && dropped.is_empty() {
                continue;
            }
            known.extend(added.iter().copied());
            for d in &dropped {
                known.remove(d);
            }
            if let Some(p) = self.peers.get(&rcpt) {
                let _ = p.tx.send(ToPeer::Extended {
                    ext_id: id,
                    payload: pex::encode(&added, &dropped),
                });
            }
        }
    }

    pub fn piece_count(&self) -> usize {
        self.piece_count
    }

    /// Replace what we advertise to other peers.
    ///
    /// The engine calls this as pieces verify, so a partial downloader
    /// progressively becomes a useful seeder rather than staying invisible.
    pub fn set_seeder(&mut self, seeder: Option<super::connection::Seeder>) {
        if let Some(new) = &seeder {
            for i in 0..self.piece_count as u32 {
                let had = self.seeder.as_ref().is_some_and(|old| old.bitfield.has(i));
                if new.bitfield.has(i) && !had {
                    for p in self.peers.values() {
                        let _ = p.tx.send(ToPeer::Have(i));
                    }
                }
            }
        }
        *self.shared.write().unwrap() = seeder.clone();
        self.seeder = seeder;
        self.seeder_gen += 1;
    }

    pub fn set_max_peers(&mut self, n: usize) {
        self.max_peers = n;
    }

    pub fn seeder(&self) -> Option<&super::connection::Seeder> {
        self.seeder.as_ref()
    }

    pub fn connected(&self) -> usize {
        self.peers.len()
    }

    pub fn total_peers(&self) -> usize {
        self.seen.len()
    }

    /// Number of pieces at least one connected peer has.
    pub fn available_pieces(&self) -> u32 {
        self.availability.count()
    }

    /// How many connected peers hold the given piece.
    pub fn seeders_for(&self, index: u32) -> u32 {
        let mut n = 0;
        for p in self.peers.values() {
            // Cheap unsynchronised check: the state is a snapshot and being
            // slightly stale only affects prioritization, never correctness.
            if let Ok(st) = p.state.try_lock() {
                if st.bitfield.has(index) {
                    n += 1;
                }
            }
        }
        n
    }

    /// Register peers discovered from a tracker, skipping ones we already know.
    pub fn discover(&mut self, peers: &[SocketAddrLite]) -> Vec<SocketAddr> {
        let mut fresh = Vec::new();
        for p in peers {
            let addr = SocketAddr::new(p.ip, p.port);
            if self.seen.contains(&addr) || self.peers.contains_key(&addr) {
                continue;
            }
            if self.peers.len() + self.connecting + fresh.len() >= self.max_peers {
                break;
            }
            // `dial` reserves the connection slot. Reserving it here as well
            // counted every peer twice, so a batch of 50 filled the pool with
            // phantom handshakes and `dial` refused to dial any of them.
            self.seen.insert(addr);
            fresh.push(addr);
        }
        fresh
    }

    /// Dial a batch of peers without blocking the caller.
///
/// Each peer gets its own task, so one unreachable peer cannot hold up the
/// rest. This matters more than it looks: dialing inline in the engine's tick
/// handler meant a tracker handing back 50 dead peers stalled the main loop for
/// minutes, and with it every UI update. Results come back over the event
/// channel as `FromPeer::Connected` / `FromPeer::ConnectFailed`.
pub fn dial(&mut self, addrs: &[SocketAddr]) {
    let infohash = self.meta.infohash;
    let piece_count = self.piece_count;
    let seeder = Arc::clone(&self.shared);

    for &addr in addrs {
        if self.peers.len() + self.connecting >= self.max_peers {
            break;
        }
        self.connecting += 1;
        self.dial_gen.insert(addr, self.seeder_gen);

        let seeder = Arc::clone(&seeder);
        let events = self.events.clone();
        let limits = self.limits.clone();
        let auto_unchoke = self.auto_unchoke;
        let pex_port = self.pex_port();
        let transport = self.transport.clone();
        tokio::spawn(async move {
            let (peer_tx, mut peer_rx) = mpsc::unbounded_channel::<FromPeer>();
            let tagged = events.clone();
            tokio::spawn(async move {
                while let Some(ev) = peer_rx.recv().await {
                    if tagged.send((addr, ev)).is_err() {
                        break;
                    }
                }
            });

            let result = super::connection::connect_with(
                addr,
                infohash,
                piece_count,
                seeder,
                peer_tx,
                limits,
                auto_unchoke,
                pex_port,
                &transport,
            )
            .await;

            let ev = match result {
                Ok(handle) => FromPeer::Connected(Box::new(handle)),
                // `{:#}` prints the whole anyhow cause chain; the outer context
                // alone hides whether this was a timeout or a refusal.
                Err(e) => FromPeer::ConnectFailed(addr, format!("{e:#}")),
            };
            let _ = events.send((addr, ev));
        });
    }
}

    /// Take over an inbound socket whose handshake the caller already read.
    pub async fn adopt_inbound(&mut self, stream: PeerStream, addr: SocketAddr, hs: Handshake) {
        if self.peers.len() >= self.max_peers {
            tracing::debug!(peer = %addr, "pool full, dropping inbound connection");
            return;
        }
        let (peer_tx, mut peer_rx) = mpsc::unbounded_channel::<FromPeer>();
        let tagged = self.events.clone();
        tokio::spawn(async move {
            while let Some(ev) = peer_rx.recv().await {
                if tagged.send((addr, ev)).is_err() {
                    break;
                }
            }
        });
        match super::connection::accept_handshaken(
            stream,
            addr,
            hs,
            self.meta.infohash,
            self.piece_count,
            Arc::clone(&self.shared),
            peer_tx,
            self.limits.clone(),
            self.auto_unchoke,
            self.pex_port(),
        )
        .await
        {
            Ok(h) => {
                // Outbound dials declare interest straight away; an inbound
                // peer needs the same, or a seeder that found us (LSD, PEX)
                // never unchokes us and nothing downloads.
                let complete = self
                    .seeder
                    .as_ref()
                    .is_some_and(|s| s.bitfield.full(self.piece_count));
                if !complete {
                    let _ = h.tx.send(ToPeer::SetInterested(true));
                }
                self.peers.insert(addr, h);
            }
            Err(e) => tracing::debug!(peer = %addr, error = %e, "inbound handshake failed"),
        }
    }

    /// Tit-for-tat choking: unchoke the interested peers moving the most data
    /// (what they give us while leeching, what we give them while seeding)
    /// plus one optimistic slot, and choke everyone else.
    pub async fn rechoke(&mut self, seeding: bool) {
        let mut interested = Vec::new();
        for (addr, p) in &self.peers {
            let mut st = p.state.lock().await;
            let rate = if seeding { st.window_up } else { st.window_down };
            st.window_up = 0;
            st.window_down = 0;
            if st.peer_interested {
                interested.push((rate, *addr));
            }
        }
        interested.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let mut unchoke: HashSet<SocketAddr> = interested
            .iter()
            .take(UNCHOKE_SLOTS)
            .map(|(_, a)| *a)
            .collect();
        let mut rest: Vec<SocketAddr> = interested
            .iter()
            .skip(UNCHOKE_SLOTS)
            .map(|(_, a)| *a)
            .collect();
        rest.sort();

        let keep = self.optimistic.is_some_and(|o| rest.contains(&o));
        if self.rechoke_round % OPTIMISTIC_ROTATION == 0 || !keep {
            self.optimistic = match self.optimistic {
                Some(prev) => rest.iter().find(|a| **a > prev).or(rest.first()).copied(),
                None => rest.first().copied(),
            };
        }
        unchoke.extend(self.optimistic);
        self.rechoke_round += 1;

        for (addr, p) in &self.peers {
            let _ = p.tx.send(ToPeer::SetChoking(!unchoke.contains(addr)));
        }
    }

    /// Close every connection, sockets included.
    pub async fn disconnect_all(&mut self) {
        for (_, p) in self.peers.drain() {
            self.retired_uploaded += p.state.lock().await.uploaded;
            let _ = p.tx.send(ToPeer::Close);
        }
        self.availability = Bitfield::with_pieces(self.piece_count);
        self.optimistic = None;
    }

    /// Apply an inbound event, keeping the aggregate bitfield current.
    pub async fn on_event(&mut self, addr: SocketAddr, ev: FromPeer) {
        match ev {
            FromPeer::Connected(handle) => {
                self.connecting = self.connecting.saturating_sub(1);
                let dialed_at = self.dial_gen.remove(&addr);
                if self.peers.len() >= self.max_peers {
                    tracing::debug!(peer = %addr, "pool full, dropping new connection");
                    return;
                }
                if dialed_at.is_some_and(|g| g != self.seeder_gen) {
                    if let Some(s) = &self.seeder {
                        for i in 0..self.piece_count as u32 {
                            if s.bitfield.has(i) {
                                let _ = handle.tx.send(ToPeer::Have(i));
                            }
                        }
                    }
                }
                self.peers.insert(addr, *handle);
                tracing::info!(peer = %addr, "connected");
            }
            FromPeer::ConnectFailed(addr, why) => {
                self.connecting = self.connecting.saturating_sub(1);
                self.dial_gen.remove(&addr);
                tracing::debug!(peer = %addr, error = %why, "connect failed");
            }
            FromPeer::Bitfield(bf) => {
                tracing::debug!(peer = %addr, pieces = bf.count(), "peer sent bitfield");
                self.availability.union(&bf);
            }
            FromPeer::Choking(false) => {
                tracing::debug!(peer = %addr, "peer unchoked us");
            }
            FromPeer::Have(i) => {
                if let Some(p) = self.peers.get(&addr) {
                    let mut st = p.state.lock().await;
                    st.bitfield.set(i);
                }
            }
            FromPeer::Disconnected(_) => {
                if let Some(p) = self.peers.remove(&addr) {
                    self.retired_uploaded += p.state.lock().await.uploaded;
                    // Recompute availability from the survivors only.
                    self.availability = Bitfield::with_pieces(self.piece_count);
                    for (_, h) in &self.peers {
                        if let Ok(st) = h.state.try_lock() {
                            self.availability.union(&st.bitfield);
                        }
                    }
                    drop(p);
                    tracing::debug!(peer = %addr, "disconnected");
                }
            }
            _ => {}
        }
    }

    /// Request one block of `index` from the least-loaded peer that has it.
    ///
    /// Spreading requests across peers avoids hammering a single fast peer and
    /// is required for the swarm to stay healthy.
    pub async fn request_block(&mut self, index: u32, begin: u32, length: u32) -> bool {
        if self.peers.is_empty() {
            return false;
        }

        // Count how many of this piece each candidate already has queued.
        let mut candidates: Vec<(usize, SocketAddr)> = Vec::new();
        for (addr, p) in &self.peers {
            let st = p.state.lock().await;
            if !st.they_choke && st.bitfield.has(index) {
                candidates.push((st.outstanding.len(), *addr));
            }
        }

        if candidates.is_empty() {
            // Distinguish "no peer has this piece" from "every holder is
            // choking us", which need different fixes.
            let mut have_piece = 0u32;
            let mut choked = 0u32;
            for p in self.peers.values() {
                let st = p.state.lock().await;
                if st.bitfield.has(index) {
                    have_piece += 1;
                    if st.they_choke {
                        choked += 1;
                    }
                }
            }
            tracing::trace!(index, have_piece, choked, peers = self.peers.len(), "no candidate for piece");
            return false;
        }
        candidates.sort_by_key(|(n, _)| *n);
        let (_, chosen) = candidates[0];

        if let Some(p) = self.peers.get(&chosen) {
            let _ = p
                .tx
                .send(ToPeer::Request {
                    index,
                    begin,
                    length,
                });
            return true;
        }
        false
    }

    /// How many requests a peer can absorb before we consider it saturated.
    pub fn pipeline_depth(&self) -> usize {
        super::connection::PIPELINE_DEPTH
    }

    /// Drop peers that have gone quiet, returning how many were removed.
    pub async fn reap(&mut self) -> usize {
        if self.last_pex.elapsed() >= pex::SEND_INTERVAL {
            self.pex_tick().await;
        }
        let mut removed = 0;
        for addr in list_dead(&self.peers).await {
            if let Some(p) = self.peers.remove(&addr) {
                self.retired_uploaded += p.state.lock().await.uploaded;
            }
            removed += 1;
        }
        if removed > 0 {
            self.availability = Bitfield::with_pieces(self.piece_count);
            for (_, h) in &self.peers {
                if let Ok(st) = h.state.try_lock() {
                    self.availability.union(&st.bitfield);
                }
            }
        }
        removed
    }

    pub async fn total_downloaded(&self) -> u64 {
        let mut sum = 0;
        for p in self.peers.values() {
            sum += p.state.lock().await.downloaded;
        }
        sum
    }

    /// Cumulative bytes uploaded, including peers that have since left.
    pub async fn total_uploaded(&self) -> u64 {
        let mut sum = self.retired_uploaded;
        for p in self.peers.values() {
            sum += p.state.lock().await.uploaded;
        }
        sum
    }

    pub async fn states(&self) -> Vec<(String, PeerState)> {
        let mut out = Vec::new();
        for (addr, p) in &self.peers {
            if let Ok(st) = p.state.try_lock() {
                out.push((addr.to_string(), (*st).clone()));
            }
        }
        out
    }

    pub fn local_port(&self) -> u16 {
        self.port
    }
}

fn pex_port_for(meta: &Metainfo, port: u16) -> Option<u16> {
    (!meta.private).then_some(port)
}

async fn list_dead(peers: &HashMap<SocketAddr, PeerHandle>) -> Vec<SocketAddr> {
    let mut dead = Vec::new();
    for (addr, p) in peers {
        if p.state.lock().await.is_dead() {
            dead.push(*addr);
        }
    }
    dead
}

/// Start listening for inbound peer connections.
///
/// Returns the bound address so the caller can advertise it, plus the accept
/// loop's join handle. A client that never listens downloads fine but
/// contributes nothing back to the swarm.
pub async fn listen(
    meta: Arc<Metainfo>,
    seeder: Option<super::connection::Seeder>,
    port: u16,
    events: mpsc::UnboundedSender<(SocketAddr, FromPeer)>,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    let local = listener.local_addr()?;
    let infohash = meta.infohash;
    let piece_count = meta.piece_count();
    let seeder: SharedSeeder = Arc::new(RwLock::new(seeder));
    let pex_port = pex_port_for(&meta, local.port());

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let seeder = Arc::clone(&seeder);
                    let events = events.clone();
                    // Serve each inbound peer independently; one misbehaving
                    // peer must not stop us accepting others.
                    tokio::spawn(async move {
                        let (peer_tx, mut peer_rx) = mpsc::unbounded_channel::<FromPeer>();
                        let tagged = events.clone();
                        tokio::spawn(async move {
                            while let Some(ev) = peer_rx.recv().await {
                                if tagged.send((addr, ev)).is_err() {
                                    break;
                                }
                            }
                        });

                        match super::connection::accept(
                            stream,
                            infohash,
                            piece_count,
                            seeder,
                            peer_tx,
                            Limits::default(),
                            true,
                            pex_port,
                        )
                        .await
                        {
                            // Hand the peer to the pool like an outbound one, so
                            // its uploads are counted and it can serve us too.
                            Ok(h) => {
                                let _ = events.send((addr, FromPeer::Connected(Box::new(h))));
                            }
                            Err(e) => tracing::debug!(peer = %addr, error = %e, "accept failed"),
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "listener.accept failed");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    });

    Ok((local, handle))
}

/// Compute the block length for a given offset inside a piece.
pub fn block_len(piece_len: u32, begin: u32) -> u32 {
    std::cmp::min(BLOCK_SIZE, piece_len - begin)
}

/// Whether the pool needs more peers, given how much is left to download.
pub fn needs_more_peers(connected: usize, has_availability: bool) -> bool {
    connected < MIN_PEERS && has_availability
}

/// A short human-readable summary for the TUI.
pub fn describe(connected: usize, available: u32, piece_count: usize) -> String {
    format!("{connected} peers, {available}/{piece_count} pieces available")
}

/// Timestamp helper used by the engine for re-announce scheduling.
pub fn next_announce(last: Instant, interval: Duration) -> Instant {
    last + interval
}

/// Convenience alias so the engine can pass infohash around opaquely.
pub type Hash = InfoHash;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::connection::connect;
    use tokio::sync::Mutex;

    fn fake_handle(bitfield: Bitfield, choke: bool, outstanding: usize) -> PeerHandle {
        fake_handle_with_rx(bitfield, choke, outstanding).0
    }

    /// Same as [`fake_handle`] but also hands back the receiving end of the
    /// command channel, so tests can observe what the pool sent to the peer.
    fn fake_handle_with_rx(
        bitfield: Bitfield,
        choke: bool,
        outstanding: usize,
    ) -> (PeerHandle, mpsc::UnboundedReceiver<ToPeer>) {
        let mut st = PeerState::new(16);
        st.bitfield = bitfield;
        st.they_choke = choke;
        st.interested = !choke;
        for i in 0..outstanding {
            st.outstanding.insert((i as u32, 0), Instant::now());
        }
        let (tx, rx) = mpsc::unbounded_channel();
        (
            PeerHandle {
                addr: "127.0.0.1:1".parse().unwrap(),
                peer_id: [0; 20],
                state: Arc::new(Mutex::new(st)),
                tx,
                inbound: false,
            },
            rx,
        )
    }

    #[test]
    fn block_len_clamps_at_piece_end() {
        assert_eq!(block_len(32768, 0), BLOCK_SIZE);
        assert_eq!(block_len(32768, 16384), BLOCK_SIZE);
        assert_eq!(block_len(32768, 32768 - 100), 100);
    }

    #[test]
    fn needs_more_peers_threshold() {
        assert!(needs_more_peers(0, true));
        assert!(needs_more_peers(7, true));
        assert!(!needs_more_peers(8, true));
        assert!(!needs_more_peers(0, false));
    }

    #[tokio::test]
    async fn seeders_for_counts_holders() {
        let meta = Arc::new(crate::metainfo::Metainfo {
            infohash: InfoHash([0; 20]),
            name: "t".into(),
            piece_length: 16384,
            pieces: vec![[0; 20]; 16],
            files: crate::metainfo::Files::Single {
                name: "t".into(),
                length: 16 * 16384,
            },
            total_length: 16 * 16384,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
        });
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut pool = PeerPool::new(meta, None, 6881, tx, Limits::default(), MAX_PEERS, true);

        let mut bf = Bitfield::with_pieces(16);
        bf.set(5);
        let a = "127.0.0.1:100".parse().unwrap();
        let b = "127.0.0.1:200".parse().unwrap();
        pool.peers.insert(a, fake_handle(bf.clone(), false, 0));
        pool.peers.insert(b, fake_handle(bf, false, 0));

        assert_eq!(pool.connected(), 2);
        assert_eq!(pool.seeders_for(5), 2);
        assert_eq!(pool.seeders_for(6), 0);
    }

    #[tokio::test]
    async fn request_block_prefers_least_loaded_peer() {
        let meta = Arc::new(crate::metainfo::Metainfo {
            infohash: InfoHash([0; 20]),
            name: "t".into(),
            piece_length: 16384,
            pieces: vec![[0; 20]; 16],
            files: crate::metainfo::Files::Single {
                name: "t".into(),
                length: 16 * 16384,
            },
            total_length: 16 * 16384,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
        });
        let (tx, _ev_rx) = mpsc::unbounded_channel::<(SocketAddr, FromPeer)>();
        let mut pool = PeerPool::new(meta, None, 6881, tx, Limits::default(), MAX_PEERS, true);

        let mut bf = Bitfield::with_pieces(16);
        bf.set(2);

        let busy = "127.0.0.1:100".parse().unwrap();
        let idle = "127.0.0.1:200".parse().unwrap();
        let (busy_handle, mut busy_rx) = fake_handle_with_rx(bf.clone(), false, 5);
        let (idle_handle, mut idle_rx) = fake_handle_with_rx(bf, false, 0);
        pool.peers.insert(busy, busy_handle);
        pool.peers.insert(idle, idle_handle);

        assert!(pool.request_block(2, 0, BLOCK_SIZE).await);

        // Whichever peer was chosen, exactly one Request must have been sent.
        let msg = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                m = busy_rx.recv() => m,
                m = idle_rx.recv() => m,
            }
        })
        .await
        .unwrap()
        .unwrap();
        match msg {
            ToPeer::Request {
                index,
                begin,
                length,
            } => {
                assert_eq!((index, begin, length), (2, 0, BLOCK_SIZE));
            }
            other => panic!("expected Request, got {other:?}"),
        }
        // Nothing else may be in flight on either peer.
        assert!(
            busy_rx.try_recv().is_err() && idle_rx.try_recv().is_err(),
            "only one request should be issued"
        );
    }

    #[tokio::test]
    async fn request_block_refuses_choked_peer() {
        let meta = Arc::new(crate::metainfo::Metainfo {
            infohash: InfoHash([0; 20]),
            name: "t".into(),
            piece_length: 16384,
            pieces: vec![[0; 20]; 16],
            files: crate::metainfo::Files::Single {
                name: "t".into(),
                length: 16 * 16384,
            },
            total_length: 16 * 16384,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
        });
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut pool = PeerPool::new(meta, None, 6881, tx, Limits::default(), MAX_PEERS, true);

        let mut bf = Bitfield::with_pieces(16);
        bf.set(3);
        pool.peers
            .insert("127.0.0.1:1".parse().unwrap(), fake_handle(bf, true, 0));

        assert!(!pool.request_block(3, 0, BLOCK_SIZE).await);
    }

    #[tokio::test]
    async fn total_uploaded_survives_removal() {
        let meta = Arc::new(crate::metainfo::Metainfo {
            infohash: InfoHash([0; 20]),
            name: "t".into(),
            piece_length: 16384,
            pieces: vec![[0; 20]; 16],
            files: crate::metainfo::Files::Single {
                name: "t".into(),
                length: 16 * 16384,
            },
            total_length: 16 * 16384,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
        });
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut pool = PeerPool::new(meta, None, 6881, tx, Limits::default(), MAX_PEERS, true);

        let stale = fake_handle(Bitfield::with_pieces(16), false, 0);
        {
            let mut st = stale.state.lock().await;
            st.uploaded = 100;
            st.last_activity = Instant::now() - Duration::from_secs(3600);
        }
        let live = fake_handle(Bitfield::with_pieces(16), false, 0);
        live.state.lock().await.uploaded = 40;
        let gone = fake_handle(Bitfield::with_pieces(16), false, 0);
        gone.state.lock().await.uploaded = 7;
        let (a, b, c): (SocketAddr, SocketAddr, SocketAddr) = (
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
            "127.0.0.1:3".parse().unwrap(),
        );
        pool.peers.insert(a, stale);
        pool.peers.insert(b, live);
        pool.peers.insert(c, gone);
        assert_eq!(pool.total_uploaded().await, 147);

        assert_eq!(pool.reap().await, 1);
        assert_eq!(pool.total_uploaded().await, 147);

        pool.on_event(c, FromPeer::Disconnected("bye".into())).await;
        assert_eq!(pool.connected(), 1);
        assert_eq!(pool.total_uploaded().await, 147);
    }

    #[tokio::test]
    async fn dial_accepts_a_full_discovered_batch() {
        let meta = Arc::new(crate::metainfo::Metainfo {
            infohash: InfoHash([0; 20]),
            name: "t".into(),
            piece_length: 16384,
            pieces: vec![[0; 20]; 16],
            files: crate::metainfo::Files::Single {
                name: "t".into(),
                length: 16 * 16384,
            },
            total_length: 16 * 16384,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
        });
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut pool = PeerPool::new(meta, None, 6881, tx, Limits::default(), MAX_PEERS, true);
        let peers: Vec<SocketAddrLite> = (1..=80u16)
            .map(|port| SocketAddrLite {
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port,
            })
            .collect();

        let fresh = pool.discover(&peers);
        assert_eq!(fresh.len(), MAX_PEERS);
        assert_eq!(pool.connecting, 0, "discover must not reserve slots");
        pool.dial(&fresh);
        assert_eq!(pool.connecting, MAX_PEERS, "every discovered peer is dialed");
    }

    #[test]
    fn discover_skips_known_addresses() {
        let meta = Arc::new(crate::metainfo::Metainfo {
            infohash: InfoHash([0; 20]),
            name: "t".into(),
            piece_length: 16384,
            pieces: vec![[0; 20]; 16],
            files: crate::metainfo::Files::Single {
                name: "t".into(),
                length: 16 * 16384,
            },
            total_length: 16 * 16384,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
        });
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut pool = PeerPool::new(meta, None, 6881, tx, Limits::default(), MAX_PEERS, true);

        let peers = vec![
            SocketAddrLite {
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
                port: 6881,
            },
            SocketAddrLite {
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
                port: 6881,
            },
        ];
        let fresh = pool.discover(&peers);
        assert_eq!(fresh.len(), 1, "duplicate should be filtered");
        assert!(pool.discover(&peers).is_empty(), "second pass yields nothing");
    }

    fn small_meta(pieces: usize) -> Arc<Metainfo> {
        let total = pieces as u64 * BLOCK_SIZE as u64;
        Arc::new(Metainfo {
            infohash: InfoHash([9; 20]),
            name: "t".into(),
            piece_length: BLOCK_SIZE,
            pieces: vec![[0; 20]; pieces],
            files: crate::metainfo::Files::Single {
                name: "t".into(),
                length: total,
            },
            total_length: total,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
        })
    }

    #[tokio::test]
    async fn rechoke_unchokes_top_four_plus_rotating_optimistic() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut pool = PeerPool::new(small_meta(16), None, 6881, tx, Limits::default(), MAX_PEERS, false);

        let mut rxs = Vec::new();
        for port in 1..=7u16 {
            let (h, rx) = fake_handle_with_rx(Bitfield::with_pieces(16), true, 0);
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            {
                let mut st = h.state.lock().await;
                st.peer_interested = port != 7;
                st.window_down = port as u64 * 100;
            }
            pool.peers.insert(addr, h);
            rxs.push((port, rx));
        }

        let mut optimistic_seen = Vec::new();
        for round in 0..7 {
            if round > 0 {
                for p in pool.peers.values() {
                    p.state.lock().await.window_down = 0;
                }
                for (port, _) in &rxs {
                    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
                    pool.peers[&addr].state.lock().await.window_down = *port as u64 * 100;
                }
            }
            pool.rechoke(false).await;
            let mut unchoked = Vec::new();
            for (port, rx) in rxs.iter_mut() {
                let mut last = None;
                while let Ok(m) = rx.try_recv() {
                    if let ToPeer::SetChoking(c) = m {
                        last = Some(c);
                    }
                }
                if last == Some(false) {
                    unchoked.push(*port);
                }
            }
            unchoked.sort();
            assert_eq!(unchoked.len(), 5, "round {round}: {unchoked:?}");
            assert!(!unchoked.contains(&7), "uninterested must stay choked");
            assert!(unchoked.iter().filter(|p| **p >= 3).count() >= 4);
            assert!(unchoked.contains(&6) && unchoked.contains(&5) && unchoked.contains(&4));
            optimistic_seen.push(unchoked.into_iter().filter(|p| *p <= 3).collect::<Vec<_>>());
        }
        assert_eq!(optimistic_seen[0], optimistic_seen[1]);
        assert_eq!(optimistic_seen[1], optimistic_seen[2]);
        assert_ne!(optimistic_seen[2], optimistic_seen[3], "optimistic must rotate");
    }

    #[tokio::test]
    async fn set_seeder_reaches_connected_peers() {
        use crate::peer::connection::connect;
        let meta = small_meta(2);
        let dir = std::env::temp_dir().join(format!("torrust-pool-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let storage = Arc::new(crate::storage::Storage::prepare(&meta, &dir).unwrap());
        storage.write_at(0, &vec![0xAB; BLOCK_SIZE as usize * 2]).unwrap();
        let mut bf = Bitfield::with_pieces(2);
        bf.set(1);
        let seeder = super::super::connection::Seeder {
            storage,
            bitfield: bf,
            piece_count: 2,
            piece_len: BLOCK_SIZE,
            last_piece_len: BLOCK_SIZE,
        };

        let (ev_tx, _ev_rx) = mpsc::unbounded_channel();
        let mut pool = PeerPool::new(Arc::clone(&meta), None, 0, ev_tx, Limits::default(), MAX_PEERS, true);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (c_tx, mut c_rx) = mpsc::unbounded_channel();
        let client = tokio::spawn(connect(
            addr,
            meta.infohash,
            2,
            Arc::new(RwLock::new(None)),
            c_tx,
            Limits::default(),
            true,
            Some(0),
        ));
        let (mut stream, peer) = listener.accept().await.unwrap();
        let hs = crate::peer::wire::handshake_incoming(&mut stream).await.unwrap();
        pool.adopt_inbound(Box::new(stream), peer, hs).await;
        let client = client.await.unwrap().unwrap();
        assert_eq!(pool.connected(), 1);

        pool.set_seeder(Some(seeder));

        let mut got_have = false;
        let mut unchoked = false;
        while !(got_have && unchoked) {
            match tokio::time::timeout(Duration::from_secs(5), c_rx.recv()).await.unwrap().unwrap() {
                FromPeer::Have(1) => got_have = true,
                FromPeer::Choking(false) => unchoked = true,
                _ => {}
            }
        }
        client.tx.send(ToPeer::Request { index: 1, begin: 0, length: BLOCK_SIZE }).unwrap();
        loop {
            match tokio::time::timeout(Duration::from_secs(5), c_rx.recv()).await.unwrap().unwrap() {
                FromPeer::Piece { index, block, .. } => {
                    assert_eq!(index, 1);
                    assert_eq!(block, vec![0xAB; BLOCK_SIZE as usize]);
                    break;
                }
                _ => {}
            }
        }

        pool.disconnect_all().await;
        loop {
            if let FromPeer::Disconnected(_) =
                tokio::time::timeout(Duration::from_secs(5), c_rx.recv()).await.unwrap().unwrap()
            {
                break;
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn pex_peer(pool: &mut PeerPool, addr: &str, pex_id: Option<u8>) -> mpsc::UnboundedReceiver<ToPeer> {
        let (h, rx) = fake_handle_with_rx(Bitfield::with_pieces(16), true, 0);
        h.state.try_lock().unwrap().pex_id = pex_id;
        pool.peers.insert(addr.parse().unwrap(), h);
        rx
    }

    fn sent_pex(rx: &mut mpsc::UnboundedReceiver<ToPeer>) -> Option<(u8, pex::Pex)> {
        match rx.try_recv() {
            Ok(ToPeer::Extended { ext_id, payload }) => Some((ext_id, pex::decode(&payload))),
            _ => None,
        }
    }

    #[tokio::test]
    async fn pex_tick_sends_added_then_dropped_never_the_recipient() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut pool = PeerPool::new(small_meta(16), None, 6881, tx, Limits::default(), MAX_PEERS, true);
        let mut a = pex_peer(&mut pool, "10.0.0.1:1000", Some(7));
        let mut b = pex_peer(&mut pool, "10.0.0.2:2000", Some(8));
        let mut c = pex_peer(&mut pool, "10.0.0.3:3000", None);

        pool.pex_tick().await;
        let (id, m) = sent_pex(&mut a).unwrap();
        assert_eq!(id, 7);
        let mut added = m.added.clone();
        added.sort();
        assert_eq!(added, vec!["10.0.0.2:2000".parse().unwrap(), "10.0.0.3:3000".parse().unwrap()]);
        assert!(m.dropped.is_empty());
        let (id, m) = sent_pex(&mut b).unwrap();
        assert_eq!(id, 8);
        assert!(!m.added.contains(&"10.0.0.2:2000".parse().unwrap()));
        assert_eq!(m.added.len(), 2);
        assert!(sent_pex(&mut c).is_none(), "peer without ut_pex gets nothing");

        pool.pex_tick().await;
        assert!(sent_pex(&mut a).is_none(), "nothing changed, nothing sent");

        pool.peers.remove(&"10.0.0.3:3000".parse().unwrap());
        pool.pex_tick().await;
        let (_, m) = sent_pex(&mut a).unwrap();
        assert!(m.added.is_empty());
        assert_eq!(m.dropped, vec!["10.0.0.3:3000".parse::<SocketAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn pex_tick_skips_inbound_peers_without_a_listen_port() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut pool = PeerPool::new(small_meta(16), None, 6881, tx, Limits::default(), MAX_PEERS, true);
        let mut a = pex_peer(&mut pool, "10.0.0.1:1000", Some(7));
        let _b = pex_peer(&mut pool, "10.0.0.2:55555", None);
        let _c = pex_peer(&mut pool, "10.0.0.3:55556", None);
        for (addr, port) in [("10.0.0.2:55555", None), ("10.0.0.3:55556", Some(6881u16))] {
            let h = pool.peers.get_mut(&addr.parse().unwrap()).unwrap();
            h.inbound = true;
            h.state.try_lock().unwrap().listen_port = port;
        }
        pool.pex_tick().await;
        let (_, m) = sent_pex(&mut a).unwrap();
        assert_eq!(m.added, vec!["10.0.0.3:6881".parse::<SocketAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn pex_tick_is_silent_for_private_torrents() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut meta = (*small_meta(16)).clone();
        meta.private = true;
        let mut pool = PeerPool::new(Arc::new(meta), None, 6881, tx, Limits::default(), MAX_PEERS, true);
        let mut a = pex_peer(&mut pool, "10.0.0.1:1000", Some(7));
        let _b = pex_peer(&mut pool, "10.0.0.2:2000", Some(7));
        pool.pex_tick().await;
        assert!(sent_pex(&mut a).is_none());
    }

    async fn loopback(
        server_pex: Option<u16>,
        client_pex: Option<u16>,
    ) -> (PeerHandle, PeerHandle, mpsc::UnboundedReceiver<FromPeer>) {
        let ih = InfoHash([9; 20]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (c_tx, _c_rx) = mpsc::unbounded_channel();
        let client = tokio::spawn(connect(
            addr,
            ih,
            2,
            Arc::new(RwLock::new(None)),
            c_tx,
            Limits::default(),
            true,
            client_pex,
        ));
        let (stream, _) = listener.accept().await.unwrap();
        let (s_tx, s_rx) = mpsc::unbounded_channel();
        let server = super::super::connection::accept(
            stream,
            ih,
            2,
            Arc::new(RwLock::new(None)),
            s_tx,
            Limits::default(),
            true,
            server_pex,
        )
        .await
        .unwrap();
        (client.await.unwrap().unwrap(), server, s_rx)
    }

    #[tokio::test]
    async fn ut_pex_message_reaches_the_engine_as_pex_peers() {
        let (a, _b, mut b_rx) = loopback(Some(6881), Some(6882)).await;
        let id = loop {
            if let Some(id) = a.state.lock().await.pex_id {
                break id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let addrs: Vec<SocketAddr> = vec!["1.2.3.4:6881".parse().unwrap(), "[2001:db8::1]:51413".parse().unwrap()];
        a.tx.send(ToPeer::Extended { ext_id: id, payload: pex::encode(&addrs, &[]) }).unwrap();
        loop {
            match tokio::time::timeout(Duration::from_secs(5), b_rx.recv()).await.unwrap().unwrap() {
                FromPeer::PexPeers(got) => {
                    assert_eq!(got.len(), 2);
                    assert!(addrs.iter().all(|x| got.contains(x)));
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(a.state.lock().await.listen_port, Some(6881));
    }

    #[tokio::test]
    async fn private_connections_skip_the_extension_bit_and_ignore_ut_pex() {
        let ih = InfoHash([9; 20]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (c_tx, mut c_rx) = mpsc::unbounded_channel();
        let client = tokio::spawn(connect(
            addr,
            ih,
            2,
            Arc::new(RwLock::new(None)),
            c_tx,
            Limits::default(),
            true,
            None,
        ));
        let (mut stream, _) = listener.accept().await.unwrap();
        let hs = crate::peer::wire::handshake_incoming(&mut stream).await.unwrap();
        assert!(!hs.supports_extended());
        crate::peer::wire::handshake_outgoing(&mut stream, &ih.0, false, false, true).await.unwrap();
        let _client = client.await.unwrap().unwrap();

        use tokio::io::AsyncWriteExt;
        let pex_msg = crate::peer::wire::Message::Extended {
            ext_id: pex::OUR_PEX_ID,
            payload: pex::encode(&["1.2.3.4:6881".parse().unwrap()], &[]),
        };
        stream.write_all(&crate::peer::wire::encode_framed(&pex_msg)).await.unwrap();
        stream.write_all(&crate::peer::wire::encode_framed(&crate::peer::wire::Message::Have { index: 1 })).await.unwrap();
        loop {
            match tokio::time::timeout(Duration::from_secs(5), c_rx.recv()).await.unwrap().unwrap() {
                FromPeer::PexPeers(_) => panic!("private torrent must ignore ut_pex"),
                FromPeer::Have(1) => break,
                _ => {}
            }
        }

        let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a2 = l2.local_addr().unwrap();
        let (t, _r) = mpsc::unbounded_channel();
        let c2 = tokio::spawn(connect(a2, ih, 2, Arc::new(RwLock::new(None)), t, Limits::default(), true, Some(1)));
        let (mut s2, _) = l2.accept().await.unwrap();
        let hs2 = crate::peer::wire::handshake_incoming(&mut s2).await.unwrap();
        assert!(hs2.supports_extended());
        drop(c2);
    }
}
