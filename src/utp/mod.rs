//! uTP (BEP 29): a reliable ordered stream over UDP.
//!
//! One background task reads the UDP socket and dispatches each datagram by
//! `(remote address, connection id)` to a per-connection actor in [`conn`].
//! Anything that does not parse as uTP is dropped, so the socket can be
//! shared with other UDP protocols later.

mod conn;
mod packet;
#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    net::UdpSocket,
    sync::mpsc,
    time::{timeout_at, Instant},
};

use conn::{HalfOpen, HalfOpenTable, Incoming, Params, Registry, MSS, RX_QUEUE};
pub use conn::UtpStream;
use packet::{decode_sack, Header, Kind};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const SYN_RETRY: Duration = Duration::from_secs(1);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const ACCEPT_BACKLOG: usize = 32;
const MAX_DATAGRAM: usize = 1500;

#[derive(Clone, Copy)]
struct Config {
    idle: Duration,
    first_seq: Option<u16>,
}

struct Inner {
    udp: Arc<UdpSocket>,
    registry: Registry,
    half_open: HalfOpenTable,
    accept_tx: mpsc::Sender<(UtpStream, SocketAddr)>,
    config: Config,
}

pub struct UtpSocket {
    inner: Arc<Inner>,
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<(UtpStream, SocketAddr)>>,
    reader: tokio::task::JoinHandle<()>,
}

impl UtpSocket {
    pub fn bind(socket: UdpSocket) -> UtpSocket {
        Self::bind_with(socket, Config { idle: IDLE_TIMEOUT, first_seq: None })
    }

    pub fn bind_std(socket: std::net::UdpSocket) -> io::Result<UtpSocket> {
        socket.set_nonblocking(true)?;
        Ok(Self::bind(UdpSocket::from_std(socket)?))
    }

    fn bind_with(socket: UdpSocket, config: Config) -> UtpSocket {
        let (accept_tx, accept_rx) = mpsc::channel(ACCEPT_BACKLOG);
        let inner = Arc::new(Inner {
            udp: Arc::new(socket),
            registry: Arc::new(Mutex::new(HashMap::new())),
            half_open: HalfOpenTable::default(),
            accept_tx,
            config,
        });
        let reader = tokio::spawn(read_loop(inner.clone()));
        UtpSocket { inner, accept_rx: tokio::sync::Mutex::new(accept_rx), reader }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.udp.local_addr()
    }

    pub async fn accept(&self) -> io::Result<(UtpStream, SocketAddr)> {
        self.accept_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::ErrorKind::ConnectionAborted.into())
    }

    /// Sends SYN once a second for up to 4 s, then gives up with `TimedOut`.
    pub async fn connect(&self, remote: SocketAddr) -> io::Result<UtpStream> {
        let inner = &self.inner;
        let (tx, mut rx) = mpsc::channel(RX_QUEUE);
        let recv_id = loop {
            let id: u16 = rand::random();
            let mut reg = inner.registry.lock().unwrap();
            if !reg.contains_key(&(remote, id)) {
                reg.insert((remote, id), tx);
                break id;
            }
        };
        let forget = || {
            inner.registry.lock().unwrap().remove(&(remote, recv_id));
        };
        let syn = Header {
            kind: Kind::Syn,
            conn_id: recv_id,
            timestamp: conn::now_us(),
            timestamp_diff: 0,
            wnd_size: conn::RECV_CAP as u32,
            seq_nr: 1,
            ack_nr: 0,
        };
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let reply = loop {
            if Instant::now() >= deadline {
                forget();
                return Err(io::Error::new(io::ErrorKind::TimedOut, "uTP connect timed out"));
            }
            if let Err(e) = inner.udp.send_to(&syn.encode(&[]), remote).await {
                forget();
                return Err(e);
            }
            let wait = (Instant::now() + SYN_RETRY).min(deadline);
            let got = timeout_at(wait, async {
                loop {
                    let p = rx.recv().await?;
                    match p.header.kind {
                        Kind::State if p.header.ack_nr == 1 => return Some(Ok(p.header)),
                        Kind::Reset => return Some(Err(())),
                        _ => {}
                    }
                }
            })
            .await;
            match got {
                Ok(Some(Ok(h))) => break h,
                Ok(Some(Err(()))) => {
                    forget();
                    return Err(io::ErrorKind::ConnectionRefused.into());
                }
                Ok(None) => {
                    forget();
                    return Err(io::ErrorKind::ConnectionAborted.into());
                }
                Err(_) => {}
            }
        };
        Ok(conn::spawn(Params {
            udp: inner.udp.clone(),
            registry: inner.registry.clone(),
            remote,
            send_id: recv_id.wrapping_add(1),
            recv_id,
            seq_nr: 2,
            ack_nr: reply.seq_nr.wrapping_sub(1),
            peer_wnd: reply.wnd_size,
            idle: inner.config.idle,
            rx,
            respond: false,
            half_open: None,
        }))
    }
}

impl Drop for UtpSocket {
    fn drop(&mut self) {
        self.reader.abort();
        self.inner.registry.lock().unwrap().clear();
    }
}

async fn read_loop(inner: Arc<Inner>) {
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, addr) = match inner.udp.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        if n > MAX_DATAGRAM {
            continue;
        }
        let Some((header, payload, sack)) = decode_sack(&buf[..n]) else { continue };
        let id = if header.kind == Kind::Syn { header.conn_id.wrapping_add(1) } else { header.conn_id };
        let target = inner.registry.lock().unwrap().get(&(addr, id)).cloned();
        match target {
            Some(tx) => {
                let _ = tx.try_send(Incoming { header, payload: payload.to_vec(), sack: sack.to_vec() });
            }
            None if header.kind == Kind::Syn => accept_syn(&inner, addr, header),
            None => {}
        }
    }
}

fn accept_syn(inner: &Inner, remote: SocketAddr, syn: Header) {
    let Ok(permit) = inner.accept_tx.try_reserve() else { return };
    let Some(half_open) = HalfOpen::try_new(&inner.half_open, remote.ip()) else { return };
    let (tx, rx) = mpsc::channel(RX_QUEUE);
    let recv_id = syn.conn_id.wrapping_add(1);
    inner.registry.lock().unwrap().insert((remote, recv_id), tx);
    let stream = conn::spawn(Params {
        udp: inner.udp.clone(),
        registry: inner.registry.clone(),
        remote,
        send_id: syn.conn_id,
        recv_id,
        seq_nr: inner.config.first_seq.unwrap_or_else(rand::random),
        ack_nr: syn.seq_nr,
        peer_wnd: syn.wnd_size,
        idle: inner.config.idle,
        rx,
        respond: true,
        half_open: Some(half_open),
    });
    permit.send((stream, remote));
}

const _: () = assert!(MSS + packet::HEADER_LEN <= MAX_DATAGRAM);
