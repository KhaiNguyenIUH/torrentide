//! One uTP connection: an actor task owning the protocol state, and the
//! `UtpStream` handle that talks to it through a shared byte pipe.

use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket,
    sync::{mpsc, Notify},
    time::{sleep_until, Instant},
};

use super::packet::{seq_diff, Header, Kind};

pub const MSS: usize = 1400;
pub const RECV_CAP: usize = 256 * 1024;
const SEND_CAP: usize = 256 * 1024;
const MAX_REORDER: i16 = 256;
const MAX_CWND: usize = 1024 * 1024;
const MIN_RTO: Duration = Duration::from_millis(500);
const INIT_RTO: Duration = Duration::from_secs(1);
const MAX_RTO: Duration = Duration::from_secs(5);
const LINGER: Duration = Duration::from_secs(5);
const MAX_INFLIGHT: usize = 1024;
const MAX_HELD_BYTES: usize = MAX_CWND;
const MAX_HALF_OPEN: usize = 128;
const MAX_HALF_OPEN_PER_IP: usize = 8;
const HALF_OPEN_REAP: Duration = Duration::from_secs(10);
pub const RX_QUEUE: usize = 512;

pub type Registry = Arc<Mutex<HashMap<(SocketAddr, u16), mpsc::Sender<Incoming>>>>;
type Failure = (io::ErrorKind, &'static str);

#[derive(Default)]
pub struct HalfOpenCounts {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

pub type HalfOpenTable = Arc<Mutex<HalfOpenCounts>>;

pub struct HalfOpen {
    table: HalfOpenTable,
    ip: IpAddr,
}

impl HalfOpenCounts {
    #[cfg(test)]
    pub fn total(&self) -> usize {
        self.total
    }
}

impl HalfOpen {
    pub fn try_new(table: &HalfOpenTable, ip: IpAddr) -> Option<HalfOpen> {
        let mut c = table.lock().unwrap();
        let from_ip = c.per_ip.get(&ip).copied().unwrap_or(0);
        if c.total >= MAX_HALF_OPEN || from_ip >= MAX_HALF_OPEN_PER_IP {
            return None;
        }
        c.total += 1;
        c.per_ip.insert(ip, from_ip + 1);
        Some(HalfOpen { table: table.clone(), ip })
    }
}

impl Drop for HalfOpen {
    fn drop(&mut self) {
        let mut c = self.table.lock().unwrap();
        c.total -= 1;
        if let Some(n) = c.per_ip.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                c.per_ip.remove(&self.ip);
            }
        }
    }
}

struct Handshake {
    _slot: HalfOpen,
    reap_at: Instant,
    first_ack: u16,
}

pub struct Incoming {
    pub header: Header,
    pub payload: Vec<u8>,
    pub sack: Vec<u8>,
}

pub fn now_us() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u32)
        .unwrap_or(0)
}

#[derive(Default)]
struct Pipe {
    send: VecDeque<u8>,
    recv: VecDeque<u8>,
    reader: Option<Waker>,
    writer: Option<Waker>,
    fin_requested: bool,
    dropped: bool,
    eof: bool,
    exited: bool,
    error: Option<Failure>,
}

#[derive(Default)]
struct Link {
    pipe: Mutex<Pipe>,
    wake: Notify,
}

/// A reliable, ordered byte stream over uTP. Dropping it flushes what was
/// written, sends FIN, and lets the connection state wind down.
pub struct UtpStream {
    link: Arc<Link>,
    peer: SocketAddr,
}

impl UtpStream {
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
}

impl AsyncRead for UtpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut p = self.link.pipe.lock().unwrap();
        if !p.recv.is_empty() {
            let n = buf.remaining().min(p.recv.len());
            let (a, b) = p.recv.as_slices();
            let k = n.min(a.len());
            buf.put_slice(&a[..k]);
            buf.put_slice(&b[..n - k]);
            p.recv.drain(..n);
            drop(p);
            self.link.wake.notify_one();
            return Poll::Ready(Ok(()));
        }
        if p.eof || (p.exited && p.error.is_none()) {
            return Poll::Ready(Ok(()));
        }
        if let Some((kind, msg)) = p.error {
            return Poll::Ready(Err(io::Error::new(kind, msg)));
        }
        p.reader = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for UtpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut p = self.link.pipe.lock().unwrap();
        if let Some((kind, msg)) = p.error {
            return Poll::Ready(Err(io::Error::new(kind, msg)));
        }
        if p.fin_requested || p.exited {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let space = SEND_CAP - p.send.len();
        if space == 0 {
            p.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = space.min(buf.len());
        p.send.extend(&buf[..n]);
        drop(p);
        self.link.wake.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.link.pipe.lock().unwrap().fin_requested = true;
        self.link.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for UtpStream {
    fn drop(&mut self) {
        let mut p = self.link.pipe.lock().unwrap();
        p.dropped = true;
        p.fin_requested = true;
        p.recv.clear();
        drop(p);
        self.link.wake.notify_one();
    }
}

pub struct Params {
    pub udp: Arc<UdpSocket>,
    pub registry: Registry,
    pub remote: SocketAddr,
    pub send_id: u16,
    pub recv_id: u16,
    pub seq_nr: u16,
    pub ack_nr: u16,
    pub peer_wnd: u32,
    pub idle: Duration,
    pub rx: mpsc::Receiver<Incoming>,
    pub respond: bool,
    pub half_open: Option<HalfOpen>,
}

pub fn spawn(p: Params) -> UtpStream {
    let link = Arc::new(Link::default());
    let stream = UtpStream { link: link.clone(), peer: p.remote };
    let respond = p.respond;
    let handshake = p.half_open.map(|slot| Handshake {
        _slot: slot,
        reap_at: Instant::now() + HALF_OPEN_REAP.min(p.idle),
        first_ack: p.seq_nr.wrapping_sub(1),
    });
    let mut actor = Actor {
        udp: p.udp,
        registry: p.registry,
        remote: p.remote,
        send_id: p.send_id,
        recv_id: p.recv_id,
        link,
        seq_nr: p.seq_nr,
        ack_nr: p.ack_nr,
        inflight: VecDeque::new(),
        flight_bytes: 0,
        held_bytes: 0,
        handshake,
        reorder: HashMap::new(),
        reorder_bytes: 0,
        cwnd: 2 * MSS,
        ssthresh: MAX_CWND,
        peer_wnd: p.peer_wnd as usize,
        srtt: None,
        rttvar: Duration::ZERO,
        rto: INIT_RTO,
        dup_acks: 0,
        recover: p.seq_nr.wrapping_sub(1),
        fin_sent: false,
        fin_acked: false,
        peer_fin: false,
        last_recv: Instant::now(),
        idle: p.idle,
        ts_diff: 0,
        last_wnd: RECV_CAP,
        failure: None,
    };
    let rx = p.rx;
    tokio::spawn(async move {
        if respond {
            actor.send_state();
        }
        actor.run(rx).await;
    });
    stream
}

struct Out {
    seq: u16,
    fin: bool,
    payload: Vec<u8>,
    sent: Instant,
    retransmits: u32,
    sacked: bool,
}

struct Actor {
    udp: Arc<UdpSocket>,
    registry: Registry,
    remote: SocketAddr,
    send_id: u16,
    recv_id: u16,
    link: Arc<Link>,
    seq_nr: u16,
    ack_nr: u16,
    inflight: VecDeque<Out>,
    flight_bytes: usize,
    held_bytes: usize,
    handshake: Option<Handshake>,
    reorder: HashMap<u16, (bool, Vec<u8>)>,
    reorder_bytes: usize,
    cwnd: usize,
    ssthresh: usize,
    peer_wnd: usize,
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
    dup_acks: u32,
    recover: u16,
    fin_sent: bool,
    fin_acked: bool,
    peer_fin: bool,
    last_recv: Instant,
    idle: Duration,
    ts_diff: u32,
    last_wnd: usize,
    failure: Option<Failure>,
}

impl Actor {
    async fn run(&mut self, mut rx: mpsc::Receiver<Incoming>) {
        loop {
            if self.handshake.is_some() && self.link.pipe.lock().unwrap().dropped {
                break;
            }
            self.pump();
            if self.failure.is_some() || (self.fin_acked && self.peer_fin) {
                break;
            }
            let deadline = self.deadline();
            tokio::select! {
                packet = rx.recv() => match packet {
                    Some(p) => self.on_packet(p),
                    None => self.failure = Some((io::ErrorKind::ConnectionAborted, "socket closed")),
                },
                _ = self.link.wake.notified() => {}
                _ = sleep_until(deadline) => self.on_timer(),
            }
        }
        self.registry.lock().unwrap().remove(&(self.remote, self.recv_id));
        let mut p = self.link.pipe.lock().unwrap();
        p.exited = true;
        p.error = self.failure;
        let wakers = [p.reader.take(), p.writer.take()];
        drop(p);
        for w in wakers.into_iter().flatten() {
            w.wake();
        }
    }

    fn lingering(&self) -> bool {
        self.fin_acked && self.link.pipe.lock().unwrap().dropped
    }

    fn deadline(&self) -> Instant {
        let idle = if self.lingering() { LINGER.min(self.idle) } else { self.idle };
        let idle_at = self.last_recv + idle;
        let idle_at = match &self.handshake {
            Some(h) => idle_at.min(h.reap_at),
            None => idle_at,
        };
        match self.inflight.front() {
            Some(f) => idle_at.min(f.sent + self.rto),
            None => idle_at,
        }
    }

    fn window(&self) -> usize {
        let queued = self.link.pipe.lock().unwrap().recv.len();
        RECV_CAP.saturating_sub(queued + self.reorder_bytes)
    }

    fn send_raw(&mut self, kind: Kind, seq: u16, payload: &[u8]) {
        let wnd = self.window();
        self.last_wnd = wnd;
        let header = Header {
            kind,
            conn_id: self.send_id,
            timestamp: now_us(),
            timestamp_diff: self.ts_diff,
            wnd_size: wnd as u32,
            seq_nr: seq,
            ack_nr: self.ack_nr,
        };
        let sack = if kind == Kind::State { self.sack_mask() } else { Vec::new() };
        let _ = self.udp.try_send_to(&header.encode_sack(&sack, payload), self.remote);
    }

    /// Bit `i` (LSB first) says seq `ack_nr + 2 + i` sits in the reorder buffer.
    fn sack_mask(&self) -> Vec<u8> {
        let diffs = || self.reorder.keys().map(|&s| seq_diff(s, self.ack_nr)).filter(|&d| d >= 2);
        let Some(top) = diffs().max() else {
            return Vec::new();
        };
        let mut mask = vec![0u8; (top as usize - 1).div_ceil(32) * 4];
        for d in diffs() {
            let i = d as usize - 2;
            mask[i / 8] |= 1 << (i % 8);
        }
        mask
    }

    fn send_state(&mut self) {
        self.send_raw(Kind::State, self.seq_nr, &[]);
    }

    fn transmit_new(&mut self, fin: bool, payload: Vec<u8>) {
        let seq = self.seq_nr;
        self.seq_nr = seq.wrapping_add(1);
        self.send_raw(if fin { Kind::Fin } else { Kind::Data }, seq, &payload);
        self.flight_bytes += payload.len();
        self.held_bytes += payload.len();
        self.inflight.push_back(Out { seq, fin, payload, sent: Instant::now(), retransmits: 0, sacked: false });
    }

    fn retransmit(&mut self, index: usize) {
        let Some(f) = self.inflight.get_mut(index) else { return };
        f.retransmits += 1;
        f.sent = Instant::now();
        let (kind, seq, payload) = (if f.fin { Kind::Fin } else { Kind::Data }, f.seq, f.payload.clone());
        self.send_raw(kind, seq, &payload);
    }

    fn pump(&mut self) {
        while !self.fin_sent {
            let limit = self.cwnd.min(self.peer_wnd);
            if !(self.inflight.is_empty() || self.flight_bytes < limit) {
                break;
            }
            if self.inflight.len() >= MAX_INFLIGHT || self.held_bytes >= MAX_HELD_BYTES {
                break;
            }
            let mut p = self.link.pipe.lock().unwrap();
            let n = p.send.len().min(MSS);
            if n == 0 {
                let fin = p.fin_requested;
                drop(p);
                if fin {
                    self.fin_sent = true;
                    self.transmit_new(true, Vec::new());
                }
                break;
            }
            let payload: Vec<u8> = p.send.drain(..n).collect();
            let writer = p.writer.take();
            drop(p);
            if let Some(w) = writer {
                w.wake();
            }
            self.transmit_new(false, payload);
        }
        if self.last_wnd < MSS && self.window() >= MSS {
            self.send_state();
        }
    }

    fn on_packet(&mut self, mut packet: Incoming) {
        let h = packet.header;
        let payload = std::mem::take(&mut packet.payload);
        self.last_recv = Instant::now();
        self.ts_diff = now_us().wrapping_sub(h.timestamp);
        match h.kind {
            Kind::Reset => {
                self.failure = Some((io::ErrorKind::ConnectionReset, "connection reset by peer"));
                return;
            }
            Kind::Syn => {
                self.send_state();
                return;
            }
            _ => {}
        }
        self.peer_wnd = h.wnd_size as usize;
        if matches!(h.kind, Kind::Data | Kind::Fin) && self.handshake_complete(h.ack_nr) {
            self.handshake = None;
        }
        self.on_ack(h.ack_nr, h.kind == Kind::State, &packet.sack);
        if matches!(h.kind, Kind::Data | Kind::Fin) {
            self.on_data(&h, payload);
        }
    }

    fn handshake_complete(&self, ack: u16) -> bool {
        self.handshake.as_ref().is_some_and(|h| {
            seq_diff(ack, h.first_ack) >= 0 && seq_diff(ack, self.seq_nr.wrapping_sub(1)) <= 0
        })
    }

    fn on_ack(&mut self, ack: u16, pure: bool, sack: &[u8]) {
        let Some(front) = self.inflight.front() else { return };
        let before = front.seq.wrapping_sub(1);
        if seq_diff(ack, before) < 0 || seq_diff(ack, self.seq_nr.wrapping_sub(1)) > 0 {
            return;
        }
        let mut acked = 0;
        if ack == before {
            if pure && sack.is_empty() {
                self.dup_acks += 1;
                if self.dup_acks == 3 {
                    self.loss();
                    self.retransmit(0);
                }
            }
        } else {
            while let Some(f) = self.inflight.front() {
                if seq_diff(f.seq, ack) > 0 {
                    break;
                }
                let f = self.inflight.pop_front().unwrap();
                self.held_bytes -= f.payload.len();
                if !f.sacked {
                    acked += f.payload.len();
                    self.flight_bytes -= f.payload.len();
                }
                if f.retransmits == 0 {
                    self.sample_rtt(f.sent.elapsed());
                }
                self.fin_acked |= f.fin;
            }
            self.dup_acks = 0;
        }
        if !sack.is_empty() {
            acked += self.apply_sack(ack, sack);
            self.retransmit_sack_holes();
        }
        if acked > 0 {
            // ponytail: plain AIMD (slow start, then +1 MSS per window, halve on loss);
            // upgrade to LEDBAT (BEP 29, 100 ms target delay from timestamp_diff) to yield to other traffic
            if self.cwnd < self.ssthresh {
                self.cwnd += acked;
            } else {
                self.cwnd += (MSS * acked / self.cwnd).max(1);
            }
            self.cwnd = self.cwnd.min(MAX_CWND);
        }
    }

    fn apply_sack(&mut self, ack: u16, sack: &[u8]) -> usize {
        let Some(front) = self.inflight.front() else { return 0 };
        let front_seq = front.seq;
        let mut newly = 0;
        for (byte, &bits) in sack.iter().enumerate() {
            for bit in 0..8 {
                if bits >> bit & 1 == 0 {
                    continue;
                }
                let seq = ack.wrapping_add(2 + (byte * 8 + bit) as u16);
                let idx = seq_diff(seq, front_seq);
                if let Some(f) = usize::try_from(idx).ok().and_then(|i| self.inflight.get_mut(i)) {
                    if !f.sacked {
                        f.sacked = true;
                        self.flight_bytes -= f.payload.len();
                        newly += f.payload.len();
                    }
                }
            }
        }
        newly
    }

    /// A packet with three selectively-acked packets after it is presumed lost;
    /// a retransmission is retried only once a couple of RTTs have passed.
    fn retransmit_sack_holes(&mut self) {
        let stale = self.srtt.unwrap_or(self.rto) * 2;
        let mut above = 0;
        let mut lost = Vec::new();
        for (i, f) in self.inflight.iter().enumerate().rev() {
            if f.sacked {
                above += 1;
            } else if above >= 3 && (f.retransmits == 0 || f.sent.elapsed() >= stale) {
                lost.push(i);
            }
        }
        let Some(&newest) = lost.first() else { return };
        if seq_diff(self.inflight[newest].seq, self.recover) > 0 {
            self.loss();
            self.recover = self.seq_nr.wrapping_sub(1);
        }
        for i in lost.into_iter().rev() {
            self.retransmit(i);
        }
    }

    fn loss(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(2 * MSS);
        self.cwnd = self.ssthresh;
    }

    fn sample_rtt(&mut self, r: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(s) => {
                let err = if s > r { s - r } else { r - s };
                self.rttvar = self.rttvar * 3 / 4 + err / 4;
                self.srtt = Some(s * 7 / 8 + r / 8);
            }
        }
        self.rto = (self.srtt.unwrap() + self.rttvar * 4).clamp(MIN_RTO, MAX_RTO);
    }

    fn on_data(&mut self, h: &Header, payload: Vec<u8>) {
        let fin = h.kind == Kind::Fin;
        let diff = seq_diff(h.seq_nr, self.ack_nr);
        if diff == 1 {
            if !self.peer_fin {
                // the hole-filling packet must be accepted even when the reorder buffer has
                // eaten the advertised window, or the transfer deadlocks
                if self.link.pipe.lock().unwrap().recv.len() >= RECV_CAP {
                    self.send_state();
                    return;
                }
                self.accept(fin, payload);
                while !self.peer_fin {
                    let Some((fin, data)) = self.reorder.remove(&self.ack_nr.wrapping_add(1)) else { break };
                    self.reorder_bytes -= data.len();
                    self.accept(fin, data);
                }
            }
        } else if diff > 1 && diff <= MAX_REORDER {
            if payload.len() <= self.window() && !self.reorder.contains_key(&h.seq_nr) {
                self.reorder_bytes += payload.len();
                self.reorder.insert(h.seq_nr, (fin, payload));
            }
        }
        self.send_state();
    }

    fn accept(&mut self, fin: bool, data: Vec<u8>) {
        self.ack_nr = self.ack_nr.wrapping_add(1);
        let mut p = self.link.pipe.lock().unwrap();
        if !p.dropped {
            p.recv.extend(&data);
        }
        if fin {
            self.peer_fin = true;
            p.eof = true;
            self.reorder.clear();
            self.reorder_bytes = 0;
        }
        let reader = p.reader.take();
        drop(p);
        if let Some(w) = reader {
            w.wake();
        }
    }

    fn on_timer(&mut self) {
        let now = Instant::now();
        if self.handshake.as_ref().is_some_and(|h| now >= h.reap_at) {
            self.failure = Some((io::ErrorKind::TimedOut, "no data after handshake"));
            return;
        }
        let idle = if self.lingering() { LINGER.min(self.idle) } else { self.idle };
        if now >= self.last_recv + idle {
            self.failure = Some((io::ErrorKind::TimedOut, "connection idle"));
            return;
        }
        let Some(front) = self.inflight.front() else { return };
        if now >= front.sent + self.rto {
            if self.peer_wnd >= MSS {
                self.ssthresh = (self.cwnd / 2).max(2 * MSS);
                self.cwnd = 2 * MSS;
                self.rto = (self.rto * 2).min(MAX_RTO);
            }
            self.dup_acks = 0;
            self.retransmit(0);
        }
    }
}
