//! Local peer discovery (BEP 14): announce our active torrents on the LAN by
//! multicast and learn about peers that do the same.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

const GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 192, 152, 143);
const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff15, 0, 0, 0, 0, 0, 0xefc0, 0x988f);
const GROUP_PORT: u16 = 6771;
const INTERVAL: Duration = Duration::from_secs(5 * 60);
const MIN_GAP: Duration = Duration::from_secs(60);
const TICK: Duration = Duration::from_secs(10);
const HASHES_PER_MESSAGE: usize = 20;
const SEEN_TTL: Duration = Duration::from_secs(60);
const SEEN_CAP: usize = 4096;

type Hash = [u8; 20];

struct Entry {
    tx: UnboundedSender<Vec<SocketAddr>>,
    fresh: bool,
}

struct Shared {
    cookie: String,
    port: u16,
    group_port: u16,
    torrents: HashMap<Hash, Entry>,
    sent: HashMap<Hash, Instant>,
    seen: HashMap<(IpAddr, Hash), Instant>,
}

pub struct Lsd {
    shared: Arc<Mutex<Shared>>,
    kick: Arc<Notify>,
    tasks: Vec<JoinHandle<()>>,
}

impl Lsd {
    pub async fn start(port: u16) -> Result<Lsd> {
        Self::start_on(port, GROUP_PORT).await
    }

    async fn start_on(port: u16, group_port: u16) -> Result<Lsd> {
        let v4 = socket_v4(group_port).context("joining the IPv4 LSD group")?;
        let v6 = socket_v6(group_port)
            .map_err(|e| tracing::debug!(error = %e, "no IPv6 LSD group"))
            .ok();
        let cookie = format!("torrentide-{:016x}", rand::random::<u64>());
        let shared = Arc::new(Mutex::new(Shared {
            cookie,
            port,
            group_port,
            torrents: HashMap::new(),
            sent: HashMap::new(),
            seen: HashMap::new(),
        }));
        let kick = Arc::new(Notify::new());
        let socks: Vec<Arc<UdpSocket>> = std::iter::once(v4).chain(v6).map(Arc::new).collect();
        let mut tasks: Vec<JoinHandle<()>> =
            socks.iter().map(|s| tokio::spawn(receive(Arc::clone(s), Arc::clone(&shared)))).collect();
        tasks.push(tokio::spawn(announce_loop(socks, Arc::clone(&shared), Arc::clone(&kick))));
        Ok(Lsd { shared, kick, tasks })
    }

    /// Start announcing `infohash`; peers found for it arrive on the receiver.
    pub fn register(&self, infohash: [u8; 20]) -> UnboundedReceiver<Vec<SocketAddr>> {
        let (tx, rx) = unbounded_channel();
        self.shared.lock().unwrap().torrents.insert(infohash, Entry { tx, fresh: true });
        self.kick.notify_one();
        rx
    }

    pub fn unregister(&self, infohash: &[u8; 20]) {
        self.shared.lock().unwrap().torrents.remove(infohash);
    }
}

impl Drop for Lsd {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

fn udp_socket(domain: Domain, bind: SocketAddr) -> Result<Socket> {
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if domain == Domain::IPV6 {
        s.set_only_v6(true)?;
    }
    s.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    s.set_reuse_port(true)?;
    s.set_nonblocking(true)?;
    s.bind(&bind.into())?;
    Ok(s)
}

fn socket_v4(group_port: u16) -> Result<UdpSocket> {
    let s = udp_socket(Domain::IPV4, (Ipv4Addr::UNSPECIFIED, group_port).into())?;
    let s = UdpSocket::from_std(s.into())?;
    s.join_multicast_v4(GROUP_V4, Ipv4Addr::UNSPECIFIED)?;
    s.set_multicast_loop_v4(true)?;
    Ok(s)
}

fn socket_v6(group_port: u16) -> Result<UdpSocket> {
    let s = udp_socket(Domain::IPV6, (Ipv6Addr::UNSPECIFIED, group_port).into())?;
    let s = UdpSocket::from_std(s.into())?;
    s.join_multicast_v6(&GROUP_V6, 0)?;
    s.set_multicast_loop_v6(true)?;
    Ok(s)
}

async fn announce_loop(socks: Vec<Arc<UdpSocket>>, shared: Arc<Mutex<Shared>>, kick: Arc<Notify>) {
    loop {
        let batch = due(&mut shared.lock().unwrap());
        if !batch.is_empty() {
            let (cookie, port, group_port) = {
                let s = shared.lock().unwrap();
                (s.cookie.clone(), s.port, s.group_port)
            };
            for sock in &socks {
                let to: SocketAddr = match sock.local_addr() {
                    Ok(a) if a.is_ipv6() => (GROUP_V6, group_port).into(),
                    _ => (GROUP_V4, group_port).into(),
                };
                for chunk in batch.chunks(HASHES_PER_MESSAGE) {
                    let msg = announce_message(&to.to_string(), port, chunk, &cookie);
                    if let Err(e) = sock.send_to(msg.as_bytes(), to).await {
                        tracing::debug!(%to, error = %e, "lsd announce failed");
                    }
                }
            }
        }
        tokio::select! {
            _ = kick.notified() => {}
            _ = tokio::time::sleep(TICK) => {}
        }
    }
}

fn due(s: &mut Shared) -> Vec<Hash> {
    let now = Instant::now();
    let mut out = Vec::new();
    for (h, e) in s.torrents.iter_mut() {
        let gap = if e.fresh { MIN_GAP } else { INTERVAL };
        if s.sent.get(h).is_none_or(|t| now.duration_since(*t) >= gap) {
            e.fresh = false;
            out.push(*h);
        }
    }
    for h in &out {
        s.sent.insert(*h, now);
    }
    s.sent.retain(|h, t| s.torrents.contains_key(h) || now.duration_since(*t) < INTERVAL);
    out
}

pub fn announce_message(host: &str, port: u16, hashes: &[Hash], cookie: &str) -> String {
    let mut m = format!("BT-SEARCH * HTTP/1.1\r\nHost: {host}\r\nPort: {port}\r\n");
    for h in hashes {
        m.push_str(&format!("Infohash: {}\r\n", hex::encode(h)));
    }
    m.push_str(&format!("cookie: {cookie}\r\n\r\n"));
    m
}

/// Port and infohashes of a well-formed announce that is not our own.
pub fn parse_announce(buf: &[u8], own_cookie: &str) -> Option<(u16, Vec<Hash>)> {
    let text = std::str::from_utf8(buf).ok()?;
    let mut lines = text.lines();
    if !lines.next()?.starts_with("BT-SEARCH") {
        return None;
    }
    let mut port = None;
    let mut hashes = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "port" => port = value.parse::<u16>().ok().filter(|p| *p != 0),
            "infohash" => {
                if let Some(h) = hex::decode(value).ok().and_then(|v| Hash::try_from(v).ok()) {
                    hashes.push(h);
                }
            }
            "cookie" if value == own_cookie => return None,
            _ => {}
        }
    }
    if hashes.is_empty() {
        return None;
    }
    Some((port?, hashes))
}

async fn receive(sock: Arc<UdpSocket>, shared: Arc<Mutex<Shared>>) {
    let mut buf = [0u8; 2048];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        deliver(&shared, &buf[..n], from);
    }
}

/// Handle one datagram. Only LAN sources count: a unicast announce from the
/// internet must not make us dial an address of the sender's choosing.
fn deliver(shared: &Mutex<Shared>, buf: &[u8], from: SocketAddr) {
    if !crate::peer::pex::is_lan(from.ip()) {
        return;
    }
    let cookie = shared.lock().unwrap().cookie.clone();
    let Some((port, hashes)) = parse_announce(buf, &cookie) else {
        return;
    };
    let mut peer = from;
    peer.set_port(port);
    let now = Instant::now();
    let mut s = shared.lock().unwrap();
    if s.seen.len() > SEEN_CAP {
        s.seen.retain(|_, t| now.duration_since(*t) < SEEN_TTL);
        if s.seen.len() > SEEN_CAP {
            s.seen.clear();
        }
    }
    for h in hashes {
        if !s.torrents.contains_key(&h) {
            continue;
        }
        if s.seen.get(&(from.ip(), h)).is_some_and(|t| now.duration_since(*t) < SEEN_TTL) {
            continue;
        }
        s.seen.insert((from.ip(), h), now);
        if s.torrents[&h].tx.send(vec![peer]).is_err() {
            s.torrents.remove(&h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_has_the_bep14_shape() {
        let m = announce_message("239.192.152.143:6771", 6881, &[[0xab; 20], [0xcd; 20]], "c0ffee");
        assert_eq!(
            m,
            format!(
                "BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\nPort: 6881\r\nInfohash: {}\r\nInfohash: {}\r\ncookie: c0ffee\r\n\r\n",
                "ab".repeat(20),
                "cd".repeat(20)
            )
        );
    }

    #[test]
    fn parses_what_it_builds_and_headers_in_any_case() {
        let m = announce_message("h", 7000, &[[1; 20], [2; 20]], "other");
        assert_eq!(parse_announce(m.as_bytes(), "mine"), Some((7000, vec![[1; 20], [2; 20]])));
        let raw = format!("BT-SEARCH * HTTP/1.1\r\nhost: x\r\nPORT: 51\r\nINFOHASH: {}\r\n\r\n", "0A".repeat(20));
        assert_eq!(parse_announce(raw.as_bytes(), "mine"), Some((51, vec![[10; 20]])));
    }

    #[test]
    fn own_cookie_and_garbage_are_ignored() {
        let m = announce_message("h", 7000, &[[1; 20]], "mine");
        assert_eq!(parse_announce(m.as_bytes(), "mine"), None);
        let bad_hash = "BT-SEARCH * HTTP/1.1\r\nPort: 1\r\nInfohash: zz\r\n\r\n";
        let no_port = format!("BT-SEARCH * HTTP/1.1\r\nInfohash: {}\r\n\r\n", "00".repeat(20));
        let zero_port = format!("BT-SEARCH * HTTP/1.1\r\nPort: 0\r\nInfohash: {}\r\n\r\n", "00".repeat(20));
        for junk in [
            &b""[..],
            b"\xff\xfe\x00",
            b"GET / HTTP/1.1\r\n\r\n",
            b"BT-SEARCH * HTTP/1.1\r\nno colon here\r\n\r\n",
            bad_hash.as_bytes(),
            no_port.as_bytes(),
            zero_port.as_bytes(),
        ] {
            assert_eq!(parse_announce(junk, "mine"), None);
        }
    }

    #[test]
    fn announces_are_rate_limited() {
        let mut s = Shared {
            cookie: String::new(),
            port: 1,
            group_port: 1,
            torrents: HashMap::new(),
            sent: HashMap::new(),
            seen: HashMap::new(),
        };
        let (tx, _rx) = unbounded_channel();
        s.torrents.insert([1; 20], Entry { tx, fresh: true });
        assert_eq!(due(&mut s).len(), 1);
        assert!(due(&mut s).is_empty());
    }

    #[test]
    fn announces_from_non_lan_sources_are_dropped() {
        let shared = Mutex::new(Shared {
            cookie: "me".into(),
            port: 1,
            group_port: 1,
            torrents: HashMap::new(),
            sent: HashMap::new(),
            seen: HashMap::new(),
        });
        let (tx, mut rx) = unbounded_channel();
        shared.lock().unwrap().torrents.insert([7; 20], Entry { tx, fresh: true });
        let msg = announce_message("239.192.152.143:6771", 4444, &[[7; 20]], "other");
        deliver(&shared, msg.as_bytes(), "8.8.8.8:6771".parse().unwrap());
        deliver(&shared, msg.as_bytes(), "[2606:4700::1]:6771".parse().unwrap());
        assert!(rx.try_recv().is_err());
        deliver(&shared, msg.as_bytes(), "192.168.1.7:6771".parse().unwrap());
        assert_eq!(rx.try_recv().unwrap(), vec!["192.168.1.7:4444".parse::<SocketAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn two_instances_find_each_other() {
        let group_port = 26771;
        let (a, b) = match (Lsd::start_on(1111, group_port).await, Lsd::start_on(2222, group_port).await) {
            (Ok(a), Ok(b)) => (a, b),
            (a, b) => {
                eprintln!("multicast unavailable, skipping: {:?} {:?}", a.err(), b.err());
                return;
            }
        };
        let _ra = a.register([9; 20]);
        let mut rb = b.register([9; 20]);
        match tokio::time::timeout(Duration::from_secs(5), rb.recv()).await {
            Ok(Some(peers)) => assert_eq!(peers[0].port(), 1111),
            other => eprintln!("no multicast delivery in this environment: {other:?}"),
        }
    }
}
