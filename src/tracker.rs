//! Tracker clients: HTTP(S) announce per BEP 3 and the two-step UDP protocol
//! from BEP 15, plus scrape for swarm counts.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::{TcpStream, UdpSocket};

use crate::bencode;
use crate::metainfo::{InfoHash, Metainfo, SocketAddrLite};

/// Lifecycle event reported to a tracker. Regular re-announces carry none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Started,
    Completed,
    Stopped,
}

impl Event {
    fn http_name(self) -> &'static str {
        match self {
            Event::Started => "started",
            Event::Completed => "completed",
            Event::Stopped => "stopped",
        }
    }
}

/// BEP 15 event codes: none 0, completed 1, started 2, stopped 3.
fn udp_event_code(event: Option<Event>) -> i32 {
    match event {
        None => 0,
        Some(Event::Completed) => 1,
        Some(Event::Started) => 2,
        Some(Event::Stopped) => 3,
    }
}

#[derive(Debug, Clone)]
pub struct AnnounceResult {
    pub interval: Duration,
    /// Minimum announce interval some trackers request.
    pub min_interval: Option<Duration>,
    pub peers: Vec<SocketAddrLite>,
    /// Human-readable tracker warnings, e.g. "torrent not registered".
    pub warning: Option<String>,
    /// Swarm counts when the tracker volunteered them (`complete` /
    /// `incomplete`, or the seeders/leechers fields of a UDP reply).
    pub seeders: Option<u32>,
    pub leechers: Option<u32>,
}

/// Swarm statistics from a scrape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrapeResult {
    pub complete: u32,
    pub incomplete: u32,
    pub downloaded: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum TrackerError {
    #[error("tracker returned failure reason: {0}")]
    Failure(String),
    #[error("tracker response was not valid bencode: {0}")]
    BadResponse(String),
    #[error("unsupported tracker url scheme: {0}")]
    UnsupportedScheme(String),
    #[error("tracker unreachable: {0}")]
    Unreachable(String),
}

/// BEP 15 magic constant sent as the connection id of a connect request.
const UDP_PROTOCOL_ID: i64 = 0x0417_2710_1980;

struct AnnounceParams {
    infohash: InfoHash,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<Event>,
    numwant: usize,
    compact: bool,
}

/// Announce to a tracker URL, dispatching on scheme.
#[allow(clippy::too_many_arguments)]
pub async fn announce(
    url: &str,
    infohash: InfoHash,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<Event>,
    numwant: usize,
    compact: bool,
) -> Result<AnnounceResult, TrackerError> {
    let params = AnnounceParams {
        infohash,
        port,
        uploaded,
        downloaded,
        left,
        event,
        numwant,
        compact,
    };
    if url.starts_with("udp://") {
        announce_udp(url, &params).await
    } else if url.starts_with("http://") || url.starts_with("https://") {
        announce_http(url, &params).await
    } else {
        Err(TrackerError::UnsupportedScheme(crate::redact::url(url)))
    }
}

/// Ask a tracker for swarm counts without announcing.
pub async fn scrape(url: &str, infohash: InfoHash) -> Result<ScrapeResult, TrackerError> {
    if url.starts_with("udp://") {
        scrape_udp(url, infohash).await
    } else if url.starts_with("http://") || url.starts_with("https://") {
        let scrape = scrape_url(url)
            .ok_or_else(|| TrackerError::BadResponse("tracker url has no scrape form".into()))?;
        let sep = if scrape.contains('?') { '&' } else { '?' };
        let full = format!("{scrape}{sep}info_hash={}", percent_encode(&infohash.0));
        let body = http_fetch(&full).await?;
        parse_scrape_response(&body, infohash)
    } else {
        Err(TrackerError::UnsupportedScheme(crate::redact::url(url)))
    }
}

/// Derive the HTTP scrape URL from an announce URL: by convention the last
/// path segment must start with `announce`, and that prefix becomes `scrape`.
/// Anything else (a passkey-only path, a bare host) has no scrape form.
pub fn scrape_url(announce: &str) -> Option<String> {
    let mut parsed = url::Url::parse(announce).ok()?;
    let path = parsed.path().to_owned();
    let (dir, last) = path.rsplit_once('/')?;
    let rest = last.strip_prefix("announce")?;
    parsed.set_path(&format!("{dir}/scrape{rest}"));
    Some(parsed.to_string())
}

/// Everything [`announce_all`] learned from the trackers that answered.
#[derive(Debug, Clone, Default)]
pub struct AnnounceOutcome {
    pub peers: Vec<SocketAddrLite>,
    pub errors: Vec<String>,
    /// Largest seeder / leecher counts any tracker reported.
    pub seeders: Option<u32>,
    pub leechers: Option<u32>,
}

/// Ask every tracker for peers concurrently, swallowing individual failures.
///
/// A tracker being down should not stop a download, so this returns the
/// aggregate of everything that worked along with the errors encountered.
/// Trackers are contacted in parallel so one that hangs until its timeout
/// costs only its own wait, not the sum of all of them. `uploaded` is the real
/// cumulative byte count; private trackers use it for ratio accounting.
///
/// Swarm counts come from the announce reply when it carries them; only a
/// tracker that left them out is scraped. Across trackers the largest count
/// wins, since each one only sees the peers that announced to it. A `Stopped`
/// announce asks for no peers and skips the scrape.
pub async fn announce_all(
    urls: &[String],
    meta: &Metainfo,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<Event>,
) -> AnnounceOutcome {
    let stopping = event == Some(Event::Stopped);
    let results = futures::future::join_all(urls.iter().filter(|u| !u.is_empty()).map(|url| async move {
        let res = announce(
            url,
            meta.infohash,
            port,
            uploaded,
            downloaded,
            left,
            event,
            if stopping { 0 } else { 200 },
            true,
        )
        .await;
        let res = match res {
            Ok(mut r) if !stopping && (r.seeders.is_none() || r.leechers.is_none()) => {
                match scrape(url, meta.infohash).await {
                    Ok(s) => {
                        r.seeders = r.seeders.or(Some(s.complete));
                        r.leechers = r.leechers.or(Some(s.incomplete));
                    }
                    Err(e) => tracing::debug!(tracker = %crate::redact::url(url), error = %e, "scrape failed"),
                }
                Ok(r)
            }
            other => other,
        };
        (url, res)
    }))
    .await;

    let mut found: HashSet<SocketAddrLite> = HashSet::new();
    let mut out = AnnounceOutcome::default();
    for (url, res) in results {
        match res {
            Ok(r) => {
                if let Some(w) = &r.warning {
                    tracing::warn!(tracker = %crate::redact::url(url), warning = %w, "tracker warning");
                }
                found.extend(r.peers);
                out.seeders = out.seeders.max(r.seeders);
                out.leechers = out.leechers.max(r.leechers);
            }
            Err(e) => {
                let shown = crate::redact::url(url);
                tracing::debug!(tracker = %shown, error = %e, "announce failed");
                out.errors.push(format!("{shown}: {e}"));
            }
        }
    }
    out.peers = found.into_iter().collect();
    out
}

fn count(v: i64) -> u32 {
    u32::try_from(v.max(0)).unwrap_or(u32::MAX)
}

// ---------------------------------------------------------------- HTTP tracker

/// The announce query string, starting with `?` or `&` as `base` requires.
/// `event` is omitted for a regular re-announce.
fn http_announce_url(base: &str, p: &AnnounceParams, peer_id: &[u8; 20]) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let mut url = format!(
        "{base}{sep}info_hash={}&peer_id={}&port={}&uploaded={}\
         &downloaded={}&left={}&compact={}&numwant={}",
        percent_encode(&p.infohash.0),
        percent_encode(peer_id),
        p.port,
        p.uploaded,
        p.downloaded,
        p.left,
        i32::from(p.compact),
        p.numwant,
    );
    if let Some(e) = p.event {
        url.push_str("&event=");
        url.push_str(e.http_name());
    }
    url
}

async fn announce_http(base: &str, p: &AnnounceParams) -> Result<AnnounceResult, TrackerError> {
    let url = http_announce_url(base, p, &random_peer_id());
    let body = http_fetch(&url).await?;
    parse_http_response(&body)
}

/// GET `url` over http or https and return the raw response bytes.
async fn http_fetch(url: &str) -> Result<Vec<u8>, TrackerError> {
    let parsed = url::Url::parse(url).map_err(|e| TrackerError::BadResponse(e.to_string()))?;
    let tls = match parsed.scheme() {
        "https" => true,
        "http" => false,
        other => {
            return Err(TrackerError::UnsupportedScheme(format!(
                "{other}:// tracker"
            )))
        }
    };
    let host = parsed
        .host_str()
        .ok_or_else(|| TrackerError::BadResponse("no host in url".into()))?
        .to_owned();
    let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });
    let path_and_query = match parsed.query() {
        Some(q) => format!("{}?{}", parsed.path(), q),
        None => parsed.path().to_owned(),
    };

    let addr = resolve(&host, port).await?;
    let tcp = connect_with_timeout(addr, Duration::from_secs(15))
        .await
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;

    // TLS is negotiated on top of the same TCP connection; everything after
    // this point is identical for http and https.
    if tls {
        let connector = tls_connector();
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|_| TrackerError::BadResponse(format!("bad TLS server name: {host}")))?;
        let mut tls_stream = tokio::time::timeout(Duration::from_secs(15), connector.connect(server_name, tcp))
            .await
            .map_err(|_| TrackerError::Unreachable("TLS handshake timed out".into()))?
            .map_err(|e| TrackerError::Unreachable(format!("TLS handshake failed: {e}")))?;
        http_get(&mut tls_stream, &host, &path_and_query).await
    } else {
        let mut plain = tcp;
        http_get(&mut plain, &host, &path_and_query).await
    }
}

/// Build a TLS client that trusts the roots bundled with webpki-roots.
///
/// Cached in a `OnceLock` because building the root store parses hundreds of
/// certificates, and we would otherwise redo that on every announce.
pub(crate) fn tls_connector() -> tokio_rustls::TlsConnector {
    use std::sync::OnceLock;
    static CONNECTOR: OnceLock<tokio_rustls::TlsConnector> = OnceLock::new();
    CONNECTOR
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
        })
        .clone()
}

/// Issue the announce GET over an already-established stream and read the
/// whole response. Works identically over plaintext TCP and TLS, so there is
/// only one copy of the HTTP code.
async fn http_get<S>(stream: &mut S, host: &str, path: &str) -> Result<Vec<u8>, TrackerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: torrust/0.1\r\n\
         Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut raw))
        .await
        .map_err(|_| TrackerError::Unreachable("tracker read timed out".into()))?
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;
    Ok(raw)
}

/// Decode the bencoded body of an HTTP tracker response, surfacing a
/// `failure reason` as an error.
///
/// Trackers signal errors both by HTTP status and by a bencoded `failure
/// reason`, so the status is ignored and the bencode parser produces the real
/// message.
fn decode_http_body(raw: &[u8]) -> Result<bencode::Value, TrackerError> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| TrackerError::BadResponse("no header/body separator".into()))?;
    let body = &raw[sep + 4..];

    let value = bencode::decode(body)
        .map_err(|e| TrackerError::BadResponse(e.to_string()))?;

    if let Ok(failure) = value.get("failure reason").and_then(|v| v.as_str()) {
        return Err(TrackerError::Failure(failure.to_owned()));
    }
    Ok(value)
}

fn parse_scrape_response(raw: &[u8], infohash: InfoHash) -> Result<ScrapeResult, TrackerError> {
    let value = decode_http_body(raw)?;
    let files = value
        .get("files")
        .and_then(|f| f.as_dict())
        .map_err(|e| TrackerError::BadResponse(e.to_string()))?;
    let entry = files
        .get(infohash.0.as_slice())
        .ok_or_else(|| TrackerError::BadResponse("scrape reply omits our infohash".into()))?;
    let field = |k: &str| count(entry.get_int_opt(k).unwrap_or(0));
    Ok(ScrapeResult {
        complete: field("complete"),
        incomplete: field("incomplete"),
        downloaded: field("downloaded"),
    })
}

fn parse_http_response(raw: &[u8]) -> Result<AnnounceResult, TrackerError> {
    let value = decode_http_body(raw)?;

    let interval = value
        .get_int_opt("interval")
        .unwrap_or(1800)
        .max(60) as u64;
    let min_interval = value
        .get_int_opt("min interval")
        .map(|v| Duration::from_secs(v.max(0) as u64));

    let warning = value
        .get_str_opt("warning message")
        .map(|s| s.to_owned());

    let mut peers = Vec::new();
    if let Ok(p) = value.get("peers") {
        match p {
            // Compact form: 6 bytes per peer, big-endian IP then port.
            bencode::Value::Bytes(raw) => {
                for chunk in raw.chunks_exact(6) {
                    let ip = std::net::Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                    let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                    if port > 0 {
                        peers.push(SocketAddrLite {
                            ip: IpAddr::V4(ip),
                            port,
                        });
                    }
                }
            }
            // Dictionary form: a list of {"ip": ..., "port": ...} entries.
            bencode::Value::List(items) => {
                for it in items {
                    let ip_s = it.get_str_opt("ip").unwrap_or("");
                    let pt = it.get_int_opt("port").unwrap_or(0);
                    if let Ok(ip) = ip_s.parse::<IpAddr>() {
                        if pt > 0 && pt <= 65535 {
                            peers.push(SocketAddrLite {
                                ip,
                                port: pt as u16,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if let Ok(bencode::Value::Bytes(raw)) = value.get("peers6") {
        peers.extend(compact_peers(raw, true));
    }

    Ok(AnnounceResult {
        interval: Duration::from_secs(interval),
        min_interval,
        peers,
        warning,
        seeders: value.get_int_opt("complete").map(count),
        leechers: value.get_int_opt("incomplete").map(count),
    })
}

// ----------------------------------------------------------------- UDP tracker

/// Resolve `url`, bind a socket, and run the BEP 15 connect step. BEP 15
/// requires the fixed protocol id there; trackers silently drop anything else.
/// A random transaction id ties the response to us.
async fn udp_connect(url: &str) -> Result<(UdpSocket, i64), TrackerError> {
    let parsed = url::Url::parse(url)
        .map_err(|e| TrackerError::BadResponse(format!("bad udp url: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| TrackerError::BadResponse("no host".into()))?
        .to_owned();
    let tp = parsed.port().unwrap_or(80);

    let server = resolve(&host, tp).await?;
    let sock = UdpSocket::bind(if server.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" })
        .await
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;
    sock.connect(server)
        .await
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;

    let tx: i32 = rand::random();
    let mut req = Vec::with_capacity(16);
    req.extend_from_slice(&UDP_PROTOCOL_ID.to_be_bytes());
    req.extend_from_slice(&0i32.to_be_bytes()); // action = connect
    req.extend_from_slice(&tx.to_be_bytes());

    sock.send(&req)
        .await
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;

    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(10), sock.recv(&mut buf))
        .await
        .map_err(|_| TrackerError::Unreachable("udp connect timed out".into()))?
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;

    if n < 16 {
        return Err(TrackerError::BadResponse("short udp connect reply".into()));
    }
    let action = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if action != 0 {
        let code = i32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        return Err(TrackerError::Failure(format!(
            "udp tracker refused connect (code {code})"
        )));
    }
    // Reply layout: action (0..4), transaction id (4..8), connection id (8..16).
    let rtx = i32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if rtx != tx {
        return Err(TrackerError::BadResponse(
            "udp transaction id mismatch (possible spoof)".into(),
        ));
    }
    let conn_id = i64::from_be_bytes(buf[8..16].try_into().unwrap());
    Ok((sock, conn_id))
}

/// The 98-byte BEP 15 announce request.
fn udp_announce_packet(conn_id: i64, tx: i32, p: &AnnounceParams, peer_id: &[u8; 20], key: u32) -> Vec<u8> {
    let mut a = Vec::with_capacity(98);
    a.extend_from_slice(&conn_id.to_be_bytes());
    a.extend_from_slice(&1i32.to_be_bytes()); // action = announce
    a.extend_from_slice(&tx.to_be_bytes());
    a.extend_from_slice(&p.infohash.0);
    a.extend_from_slice(peer_id);
    a.extend_from_slice(&(p.downloaded as i64).to_be_bytes());
    a.extend_from_slice(&(p.left as i64).to_be_bytes());
    a.extend_from_slice(&(p.uploaded as i64).to_be_bytes());
    a.extend_from_slice(&udp_event_code(p.event).to_be_bytes());
    a.extend_from_slice(&0u32.to_be_bytes()); // IP: default
    a.extend_from_slice(&key.to_be_bytes());
    // BEP 15 uses -1 for "tracker default"; a caller-supplied value is
    // honoured but clamped so a silly numwant cannot stall the response.
    let want = if p.numwant == 0 { -1i32 } else { (p.numwant as i32).clamp(1, 500) };
    a.extend_from_slice(&want.to_be_bytes());
    a.extend_from_slice(&p.port.to_be_bytes());
    a
}

fn compact_peers(raw: &[u8], v6: bool) -> Vec<SocketAddrLite> {
    let size = if v6 { 18 } else { 6 };
    raw.chunks_exact(size)
        .filter_map(|c| {
            let (ip, port) = c.split_at(size - 2);
            let port = u16::from_be_bytes([port[0], port[1]]);
            let ip = match <[u8; 16]>::try_from(ip) {
                Ok(b) => IpAddr::from(b),
                Err(_) => IpAddr::from(<[u8; 4]>::try_from(ip).ok()?),
            };
            (port > 0).then_some(SocketAddrLite { ip, port })
        })
        .collect()
}

fn parse_udp_announce(buf: &[u8], tx: i32, v6: bool) -> Result<AnnounceResult, TrackerError> {
    if buf.len() < 20 {
        return Err(TrackerError::BadResponse("short udp announce reply".into()));
    }
    let action = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if action == 3 {
        let msg = String::from_utf8_lossy(&buf[8..]).into_owned();
        return Err(TrackerError::Failure(msg));
    }
    if action != 1 {
        return Err(TrackerError::BadResponse(format!("unexpected udp action {action}")));
    }
    // Reply layout: action, transaction id, interval, leechers, seeders (4
    // bytes each), then packed (ipv4, port) pairs.
    let rtx = i32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if rtx != tx {
        return Err(TrackerError::BadResponse("udp announce txid mismatch".into()));
    }

    let word = |at: usize| i32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
    let interval = word(8).max(0) as u64;
    let peers = compact_peers(&buf[20..], v6);

    Ok(AnnounceResult {
        interval: Duration::from_secs(interval.clamp(60, 3600)),
        min_interval: None,
        peers,
        warning: None,
        leechers: Some(count(word(12) as i64)),
        seeders: Some(count(word(16) as i64)),
    })
}

async fn announce_udp(url: &str, p: &AnnounceParams) -> Result<AnnounceResult, TrackerError> {
    let (sock, conn_id) = udp_connect(url).await?;

    let tx: i32 = rand::random();
    let packet = udp_announce_packet(conn_id, tx, p, &random_peer_id(), rand::random());
    sock.send(&packet)
        .await
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;

    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(10), sock.recv(&mut buf))
        .await
        .map_err(|_| TrackerError::Unreachable("udp announce timed out".into()))?
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;
    parse_udp_announce(&buf[..n], tx, sock.peer_addr().is_ok_and(|a| a.is_ipv6()))
}

/// The 36-byte BEP 15 scrape request for one infohash.
fn udp_scrape_packet(conn_id: i64, tx: i32, infohash: InfoHash) -> Vec<u8> {
    let mut a = Vec::with_capacity(36);
    a.extend_from_slice(&conn_id.to_be_bytes());
    a.extend_from_slice(&2i32.to_be_bytes()); // action = scrape
    a.extend_from_slice(&tx.to_be_bytes());
    a.extend_from_slice(&infohash.0);
    a
}

/// Scrape reply: action, transaction id, then per torrent seeders, completed
/// and leechers (4 bytes each).
fn parse_udp_scrape(buf: &[u8], tx: i32) -> Result<ScrapeResult, TrackerError> {
    if buf.len() < 8 {
        return Err(TrackerError::BadResponse("short udp scrape reply".into()));
    }
    let action = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if action == 3 {
        let msg = String::from_utf8_lossy(&buf[8..]).into_owned();
        return Err(TrackerError::Failure(msg));
    }
    if action != 2 || buf.len() < 20 {
        return Err(TrackerError::BadResponse(format!(
            "unexpected udp scrape reply (action {action}, {} bytes)",
            buf.len()
        )));
    }
    let rtx = i32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if rtx != tx {
        return Err(TrackerError::BadResponse("udp scrape txid mismatch".into()));
    }
    let word = |at: usize| count(i32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]) as i64);
    Ok(ScrapeResult {
        complete: word(8),
        downloaded: word(12),
        incomplete: word(16),
    })
}

async fn scrape_udp(url: &str, infohash: InfoHash) -> Result<ScrapeResult, TrackerError> {
    let (sock, conn_id) = udp_connect(url).await?;

    let tx: i32 = rand::random();
    sock.send(&udp_scrape_packet(conn_id, tx, infohash))
        .await
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;

    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(10), sock.recv(&mut buf))
        .await
        .map_err(|_| TrackerError::Unreachable("udp scrape timed out".into()))?
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;
    parse_udp_scrape(&buf[..n], tx)
}

// -------------------------------------------------------------------- helpers

/// Resolve a host, preferring IPv4 when it has both families.
async fn resolve(host: &str, port: u16) -> Result<SocketAddr, TrackerError> {
    use tokio::net::lookup_host;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<SocketAddr> = lookup_host((host, port))
        .await
        .map_err(|e| TrackerError::Unreachable(format!("dns lookup for {host} failed: {e}")))?
        .collect();
    addrs
        .iter()
        .copied()
        .find(SocketAddr::is_ipv4)
        .or_else(|| addrs.first().copied())
        .ok_or_else(|| TrackerError::Unreachable(format!("{host} has no address")))
}

async fn connect_with_timeout(addr: SocketAddr, timeout: Duration) -> Result<TcpStream> {
    tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .with_context(|| format!("connect to {addr}"))?
        .with_context(|| format!("connect to {addr}"))
}

/// Percent-encode bytes for a URL query parameter. `info_hash` is raw binary,
/// so every byte needs escaping.
fn percent_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        // Unreserved set per RFC 3986. Everything else is escaped.
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            s.push(b as char);
        } else {
            s.push('%');
            s.push_str(&format!("{b:02X}"));
        }
    }
    s
}

fn random_peer_id() -> [u8; 20] {
    use rand::RngCore;
    let mut id = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compact_peer_list() {
        let mut peers = Vec::new();
        peers.extend_from_slice(&[1, 2, 3, 4]);
        peers.extend_from_slice(&6881u16.to_be_bytes());
        peers.extend_from_slice(&[5, 6, 7, 8]);
        peers.extend_from_slice(&6882u16.to_be_bytes());

        let mut body = bencode::encode(&bencode::Value::Dict(std::collections::BTreeMap::from([
            (b"interval".to_vec(), bencode::Value::Int(1800)),
            (b"peers".to_vec(), bencode::Value::Bytes(peers.clone())),
        ])));

        // Build the response from raw bytes: the compact peer list is binary, so
        // routing it through a String would corrupt it via lossy UTF-8
        // replacement characters.
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n".to_vec();
        resp.append(&mut body);

        let res = parse_http_response(&resp).unwrap();
        assert_eq!(res.interval, Duration::from_secs(1800));
        assert_eq!(res.peers.len(), 2);
        assert_eq!(res.peers[0].port, 6881);
        assert_eq!(res.peers[0].ip.to_string(), "1.2.3.4");
        assert_eq!(res.peers[1].port, 6882);
    }

    #[test]
    fn parses_dictionary_peer_list() {
        let body = bencode::encode(&bencode::Value::Dict(std::collections::BTreeMap::from([
            (b"interval".to_vec(), bencode::Value::Int(900)),
            (
                b"peers".to_vec(),
                bencode::Value::List(vec![bencode::Value::Dict(
                    std::collections::BTreeMap::from([
                        (b"ip".to_vec(), bencode::Value::Bytes(b"10.0.0.5".to_vec())),
                        (b"port".to_vec(), bencode::Value::Int(6881)),
                    ]),
                )]),
            ),
        ])));
        let resp = format!(
            "HTTP/1.1 200 OK\r\n\r\n{}",
            String::from_utf8_lossy(&body)
        );
        let res = parse_http_response(resp.as_bytes()).unwrap();
        assert_eq!(res.peers.len(), 1);
        assert_eq!(res.peers[0].ip.to_string(), "10.0.0.5");
    }

    fn v6_entry(last: u8, port: u16) -> Vec<u8> {
        let mut e = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last as u16).octets().to_vec();
        e.extend_from_slice(&port.to_be_bytes());
        e
    }

    #[test]
    fn http_peers6_mixes_with_v4_and_skips_junk() {
        let mut v4 = vec![1, 2, 3, 4];
        v4.extend_from_slice(&6881u16.to_be_bytes());
        let mut v6 = v6_entry(1, 7000);
        v6.extend(v6_entry(2, 0));
        v6.extend(v6_entry(3, 7002));
        v6.extend_from_slice(&[9, 9, 9]);
        let mut body = bencode::encode(&bencode::Value::Dict(std::collections::BTreeMap::from([
            (b"peers".to_vec(), bencode::Value::Bytes(v4)),
            (b"peers6".to_vec(), bencode::Value::Bytes(v6)),
        ])));
        let mut resp = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        resp.append(&mut body);
        let res = parse_http_response(&resp).unwrap();
        let got: Vec<String> = res.peers.iter().map(|p| format!("{}:{}", p.ip, p.port)).collect();
        assert_eq!(got, ["1.2.3.4:6881", "2001:db8::1:7000", "2001:db8::3:7002"]);
    }

    #[test]
    fn http_dict_model_accepts_ipv6() {
        let body = b"d5:peersld2:ip11:2001:db8::94:porti6881eeee";
        let mut resp = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        resp.extend_from_slice(body);
        let res = parse_http_response(&resp).unwrap();
        assert_eq!(res.peers[0].ip.to_string(), "2001:db8::9");
    }

    #[test]
    fn udp_reply_follows_the_address_family() {
        let mut reply = 1i32.to_be_bytes().to_vec();
        reply.extend_from_slice(&5i32.to_be_bytes());
        reply.extend_from_slice(&900i32.to_be_bytes());
        reply.extend_from_slice(&[0; 8]);
        reply.extend(v6_entry(1, 7000));
        reply.extend(v6_entry(2, 7001));
        reply.extend_from_slice(&[1, 2]);
        let res = parse_udp_announce(&reply, 5, true).unwrap();
        assert_eq!(res.peers.len(), 2);
        assert_eq!(res.peers[1].ip.to_string(), "2001:db8::2");
    }

    #[tokio::test]
    async fn udp_announce_over_ipv6() {
        let Ok(sock) = tokio::net::UdpSocket::bind("[::1]:0").await else { return };
        let url = format!("udp://{}/announce", sock.local_addr().unwrap());
        let tracker = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (_, from) = sock.recv_from(&mut buf).await.unwrap();
            let mut reply = 0i32.to_be_bytes().to_vec();
            reply.extend_from_slice(&buf[12..16]);
            reply.extend_from_slice(&42i64.to_be_bytes());
            sock.send_to(&reply, from).await.unwrap();
            let (_, from) = sock.recv_from(&mut buf).await.unwrap();
            let mut reply = 1i32.to_be_bytes().to_vec();
            reply.extend_from_slice(&buf[12..16]);
            reply.extend_from_slice(&900i32.to_be_bytes());
            reply.extend_from_slice(&[0; 8]);
            reply.extend(v6_entry(7, 6881));
            sock.send_to(&reply, from).await.unwrap();
        });
        let res = announce(&url, InfoHash([7; 20]), 6881, 0, 0, 100, None, 50, true).await.unwrap();
        tracker.await.unwrap();
        assert_eq!(res.peers[0].ip.to_string(), "2001:db8::7");
    }

    #[test]
    fn surfaces_failure_reason() {
        let body = b"d14:failure reason15:torrent missinge";
        let resp = format!("HTTP/1.1 200 OK\r\n\r\n{}", String::from_utf8_lossy(body));
        match parse_http_response(resp.as_bytes()) {
            Err(TrackerError::Failure(m)) => assert_eq!(m, "torrent missing"),
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn clamps_interval_to_sane_minimum() {
        let body = b"d8:intervali1e5:peers0:e";
        let resp = format!("HTTP/1.1 200 OK\r\n\r\n{}", String::from_utf8_lossy(body));
        let res = parse_http_response(resp.as_bytes()).unwrap();
        assert_eq!(res.interval, Duration::from_secs(60));
    }

    #[test]
    fn rejects_malformed_body() {
        let resp = "HTTP/1.1 200 OK\r\n\r\nnot bencode at all";
        assert!(parse_http_response(resp.as_bytes()).is_err());
    }

    #[test]
    fn percent_encoding_escapes_binary() {
        // 0x00, 0xFF and a safe alphanumeric byte.
        assert_eq!(percent_encode(&[0x00, b'a', 0xff]), "%00a%FF");
    }

    #[test]
    fn rejects_unsupported_scheme() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let hash = InfoHash([0u8; 20]);
        let err = rt
            .block_on(announce("wss://x/announce", hash, 6881, 0, 0, 0, None, 50, true))
            .unwrap_err();
        assert!(matches!(err, TrackerError::UnsupportedScheme(_)));
    }

    #[test]
    fn https_is_attempted_rather_than_downgraded() {
        // Previously this scheme returned UnsupportedScheme outright. Now HTTPS
        // is negotiated, so an unreachable host must surface as a connection or
        // TLS failure. Crucially it must NOT be silently downgraded to
        // plaintext: a tracker that requires TLS must never receive a cleartext
        // request carrying the infohash.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let hash = InfoHash([0u8; 20]);
        // Reserved .invalid TLD: guaranteed never to resolve, so this cannot
        // accidentally open a real connection.
        let err = rt
            .block_on(announce(
                "https://tracker.invalid/announce",
                hash,
                6881,
                0,
                0,
                0,
                None,
                50,
                true,
            ))
            .unwrap_err();
        assert!(
            matches!(
                err,
                TrackerError::Unreachable(_) | TrackerError::BadResponse(_)
            ),
            "expected an unreachable/bad-response error, got {err:?}"
        );
        assert!(
            !matches!(err, TrackerError::UnsupportedScheme(_)),
            "HTTPS must be supported now, not rejected"
        );
    }

    #[test]
    fn unknown_schemes_are_still_rejected() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let hash = InfoHash([0u8; 20]);
        for bad in ["wss://x/announce", "ftp://x/announce", "file:///tmp/x"] {
            let err = rt
                .block_on(announce(bad, hash, 6881, 0, 0, 0, None, 50, true))
                .unwrap_err();
            assert!(
                matches!(err, TrackerError::UnsupportedScheme(_)),
                "{bad} should be UnsupportedScheme, got {err:?}"
            );
        }
    }

    #[test]
    fn tls_connector_builds_and_caches() {
        // Building the root store must not panic, and the cached connector
        // must be reusable across calls.
        let a = tls_connector();
        let b = tls_connector();
        drop(a);
        drop(b);
    }

    fn test_meta() -> Metainfo {
        Metainfo {
            infohash: InfoHash([7; 20]),
            name: "t".into(),
            piece_length: 16384,
            pieces: vec![[0; 20]; 1],
            files: crate::metainfo::Files::Single {
                name: "t".into(),
                length: 16384,
            },
            total_length: 16384,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
            info_bytes: vec![],
        }
    }

    /// Serve one HTTP response per connection after `delay`, returning a
    /// compact peer list with a single peer on `peer_port`.
    async fn mock_tracker(
        delay: Duration,
        peer_port: u16,
        seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap();
                    seen.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&buf[..n]).into_owned());
                    tokio::time::sleep(delay).await;
                    let mut peers = vec![127, 0, 0, 1];
                    peers.extend_from_slice(&peer_port.to_be_bytes());
                    let mut body = b"d8:completei1e10:incompletei1e8:intervali1800e5:peers6:".to_vec();
                    body.extend_from_slice(&peers);
                    body.push(b'e');
                    let mut resp = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
                    resp.extend_from_slice(&body);
                    let _ = s.write_all(&resp).await;
                });
            }
        });
        format!("http://{addr}/announce")
    }

    #[tokio::test]
    async fn announce_all_runs_trackers_concurrently_and_reports_uploaded() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let delay = Duration::from_millis(600);
        let a = mock_tracker(delay, 1111, seen.clone()).await;
        let b = mock_tracker(delay, 2222, seen.clone()).await;
        let dead = "http://127.0.0.1:1/announce".to_owned();

        let start = std::time::Instant::now();
        let AnnounceOutcome { mut peers, errors, .. } =
            announce_all(&[a, b, dead.clone()], &test_meta(), 6881, 1234, 55, 100, None).await;
        let elapsed = start.elapsed();

        peers.sort_by_key(|p| p.port);
        assert_eq!(peers.iter().map(|p| p.port).collect::<Vec<_>>(), [1111, 2222]);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].starts_with(&crate::redact::url(&dead)));
        assert!(elapsed < Duration::from_millis(1100), "serial: {elapsed:?}");

        let reqs = seen.lock().unwrap();
        assert_eq!(reqs.len(), 2);
        for r in reqs.iter() {
            assert!(r.contains("uploaded=1234&downloaded=55"), "{r}");
        }
    }

    #[tokio::test]
    async fn udp_announce_follows_bep15() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let url = format!("udp://{}/announce", sock.local_addr().unwrap());
        let tracker = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (n, from) = sock.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 16);
            assert_eq!(i64::from_be_bytes(buf[0..8].try_into().unwrap()), UDP_PROTOCOL_ID);
            assert_eq!(&buf[8..12], &0i32.to_be_bytes());
            let mut reply = 0i32.to_be_bytes().to_vec();
            reply.extend_from_slice(&buf[12..16]);
            reply.extend_from_slice(&42i64.to_be_bytes());
            sock.send_to(&reply, from).await.unwrap();

            let (n, from) = sock.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 98);
            assert_eq!(i64::from_be_bytes(buf[0..8].try_into().unwrap()), 42);
            assert_eq!(&buf[8..12], &1i32.to_be_bytes());
            let field = |at: usize| i64::from_be_bytes(buf[at..at + 8].try_into().unwrap());
            assert_eq!((field(56), field(64), field(72)), (55, 100, 1234));
            assert_eq!(&buf[80..84], &0i32.to_be_bytes());
            let mut reply = 1i32.to_be_bytes().to_vec();
            reply.extend_from_slice(&buf[12..16]);
            reply.extend_from_slice(&900i32.to_be_bytes());
            reply.extend_from_slice(&3i32.to_be_bytes());
            reply.extend_from_slice(&7i32.to_be_bytes());
            reply.extend_from_slice(&[10, 0, 0, 1, 0x1a, 0xe1, 10, 0, 0, 2, 0x1a, 0xe2]);
            sock.send_to(&reply, from).await.unwrap();
        });

        let res = announce(&url, InfoHash([7; 20]), 6881, 1234, 55, 100, None, 50, true)
            .await
            .unwrap();
        tracker.await.unwrap();
        assert_eq!(res.interval, Duration::from_secs(900));
        let ports: Vec<u16> = res.peers.iter().map(|p| p.port).collect();
        assert_eq!(ports, [6881, 6882]);
        assert_eq!((res.seeders, res.leechers), (Some(7), Some(3)));
    }

    fn params(event: Option<Event>) -> AnnounceParams {
        AnnounceParams {
            infohash: InfoHash([7; 20]),
            port: 6881,
            uploaded: 1,
            downloaded: 2,
            left: 3,
            event,
            numwant: 50,
            compact: true,
        }
    }

    #[test]
    fn http_query_carries_each_event_and_omits_none() {
        let id = [1u8; 20];
        for (event, expect) in [
            (Some(Event::Started), Some("&event=started")),
            (Some(Event::Completed), Some("&event=completed")),
            (Some(Event::Stopped), Some("&event=stopped")),
            (None, None),
        ] {
            let url = http_announce_url("http://t/announce", &params(event), &id);
            match expect {
                Some(e) => assert!(url.ends_with(e), "{url}"),
                None => assert!(!url.contains("event="), "{url}"),
            }
            assert!(url.contains("?info_hash="), "{url}");
        }
        let url = http_announce_url("http://t/announce?key=v", &params(None), &id);
        assert!(url.starts_with("http://t/announce?key=v&info_hash="), "{url}");
    }

    #[test]
    fn udp_packet_encodes_event_codes() {
        let id = [1u8; 20];
        for (event, code) in [
            (None, 0i32),
            (Some(Event::Completed), 1),
            (Some(Event::Started), 2),
            (Some(Event::Stopped), 3),
        ] {
            let pkt = udp_announce_packet(42, 9, &params(event), &id, 5);
            assert_eq!(pkt.len(), 98);
            assert_eq!(&pkt[80..84], &code.to_be_bytes());
            assert_eq!(&pkt[96..98], &6881u16.to_be_bytes());
        }
    }

    #[tokio::test]
    async fn http_announce_sends_the_event() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let url = mock_tracker(Duration::ZERO, 1111, seen.clone()).await;
        announce(&url, InfoHash([7; 20]), 6881, 0, 0, 0, Some(Event::Completed), 50, true)
            .await
            .unwrap();
        announce(&url, InfoHash([7; 20]), 6881, 0, 0, 0, None, 50, true)
            .await
            .unwrap();
        let reqs = seen.lock().unwrap();
        assert!(reqs[0].contains("&event=completed "), "{}", reqs[0]);
        assert!(!reqs[1].contains("event="), "{}", reqs[1]);
    }

    #[test]
    fn scrape_url_replaces_the_announce_segment() {
        let cases = [
            ("http://t.example/announce", Some("http://t.example/scrape")),
            ("http://t.example:8080/x/announce.php?k=1", Some("http://t.example:8080/x/scrape.php?k=1")),
            ("https://t.example/pass/announce", Some("https://t.example/pass/scrape")),
            ("http://t.example/tracker", None),
            ("http://t.example/announce/pass", None),
            ("http://announce", None),
        ];
        for (input, want) in cases {
            assert_eq!(scrape_url(input).as_deref(), want, "{input}");
        }
    }

    fn scrape_body(hash: &[u8], complete: i64, downloaded: i64, incomplete: i64) -> Vec<u8> {
        use bencode::Value;
        let entry = Value::Dict(std::collections::BTreeMap::from([
            (b"complete".to_vec(), Value::Int(complete)),
            (b"downloaded".to_vec(), Value::Int(downloaded)),
            (b"incomplete".to_vec(), Value::Int(incomplete)),
        ]));
        let files = Value::Dict(std::collections::BTreeMap::from([(hash.to_vec(), entry)]));
        let mut resp = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        resp.extend(bencode::encode(&Value::Dict(std::collections::BTreeMap::from([(
            b"files".to_vec(),
            files,
        )]))));
        resp
    }

    #[test]
    fn parses_http_scrape_reply() {
        let hash = InfoHash([7; 20]);
        let got = parse_scrape_response(&scrape_body(&hash.0, 5, 50, 10), hash).unwrap();
        assert_eq!(
            got,
            ScrapeResult { complete: 5, incomplete: 10, downloaded: 50 }
        );
        assert!(parse_scrape_response(&scrape_body(&[9; 20], 5, 50, 10), hash).is_err());
        let neg = parse_scrape_response(&scrape_body(&hash.0, -1, 0, 0), hash).unwrap();
        assert_eq!(neg.complete, 0);
        assert!(parse_scrape_response(b"HTTP/1.1 200 OK\r\n\r\nd5:filesi1ee", hash).is_err());
    }

    #[test]
    fn http_announce_reply_counts_are_parsed() {
        let resp = b"HTTP/1.1 200 OK\r\n\r\nd8:completei12e10:incompletei34e8:intervali900e5:peers0:e";
        let res = parse_http_response(resp).unwrap();
        assert_eq!((res.seeders, res.leechers), (Some(12), Some(34)));
        let res = parse_http_response(b"HTTP/1.1 200 OK\r\n\r\nd8:intervali900e5:peers0:e").unwrap();
        assert_eq!((res.seeders, res.leechers), (None, None));
    }

    #[test]
    fn udp_scrape_encodes_and_parses() {
        let pkt = udp_scrape_packet(42, 9, InfoHash([7; 20]));
        assert_eq!(pkt.len(), 36);
        assert_eq!(&pkt[8..12], &2i32.to_be_bytes());
        assert_eq!(&pkt[16..36], &[7u8; 20]);

        let mut reply = 2i32.to_be_bytes().to_vec();
        reply.extend_from_slice(&9i32.to_be_bytes());
        for v in [5i32, 50, 10] {
            reply.extend_from_slice(&v.to_be_bytes());
        }
        assert_eq!(
            parse_udp_scrape(&reply, 9).unwrap(),
            ScrapeResult { complete: 5, downloaded: 50, incomplete: 10 }
        );
        assert!(parse_udp_scrape(&reply, 8).is_err());
        assert!(parse_udp_scrape(&reply[..12], 9).is_err());
        assert!(parse_udp_scrape(&[], 9).is_err());
        let mut err = 3i32.to_be_bytes().to_vec();
        err.extend_from_slice(&9i32.to_be_bytes());
        err.extend_from_slice(b"nope");
        assert!(matches!(parse_udp_scrape(&err, 9), Err(TrackerError::Failure(_))));
    }

    /// Answers announces with `announce_counts` (if any) and scrapes with
    /// `(complete, incomplete)`, recording each request line.
    async fn counting_tracker(
        announce_counts: Option<(i64, i64)>,
        scrape_counts: (i64, i64),
        seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> String {
        use bencode::Value;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap();
                    let line = String::from_utf8_lossy(&buf[..n]).lines().next().unwrap().to_owned();
                    seen.lock().unwrap().push(line.clone());
                    let resp = if line.contains("/scrape?") {
                        scrape_body(&[7; 20], scrape_counts.0, 0, scrape_counts.1)
                    } else {
                        let mut d = std::collections::BTreeMap::from([
                            (b"interval".to_vec(), Value::Int(1800)),
                            (b"peers".to_vec(), Value::Bytes(vec![])),
                        ]);
                        if let Some((c, i)) = announce_counts {
                            d.insert(b"complete".to_vec(), Value::Int(c));
                            d.insert(b"incomplete".to_vec(), Value::Int(i));
                        }
                        let mut r = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
                        r.extend(bencode::encode(&Value::Dict(d)));
                        r
                    };
                    let _ = s.write_all(&resp).await;
                });
            }
        });
        format!("http://{addr}/announce")
    }

    #[tokio::test]
    async fn announce_all_prefers_announce_counts_and_scrapes_only_when_missing() {
        let seen_a = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_b = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let with_counts = counting_tracker(Some((3, 4)), (99, 99), seen_a.clone()).await;
        let without = counting_tracker(None, (10, 2), seen_b.clone()).await;

        let out = announce_all(&[with_counts], &test_meta(), 6881, 0, 0, 0, None).await;
        assert_eq!((out.seeders, out.leechers), (Some(3), Some(4)));
        assert_eq!(seen_a.lock().unwrap().len(), 1, "no scrape needed");

        let out = announce_all(&[without.clone()], &test_meta(), 6881, 0, 0, 0, None).await;
        assert_eq!((out.seeders, out.leechers), (Some(10), Some(2)));
        assert_eq!(seen_b.lock().unwrap().len(), 2);

        let both = counting_tracker(Some((3, 4)), (99, 99), seen_a.clone()).await;
        let out = announce_all(&[both, without], &test_meta(), 6881, 0, 0, 0, None).await;
        assert_eq!((out.seeders, out.leechers), (Some(10), Some(4)), "max across trackers");
    }

    #[derive(Clone, Default)]
    struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Capture {
            self.clone()
        }
    }

    #[tokio::test]
    async fn announce_logs_and_errors_never_contain_the_passkey() {
        let cap = Capture::default();
        let sub = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(cap.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(sub);

        let url = "http://user:SECRETPW@127.0.0.1:1/SECRETPASSKEY/announce?k=SECRETQ".to_owned();
        let out = announce_all(&[url, "ftp://h/SECRETPASSKEY".to_owned()], &test_meta(), 6881, 0, 0, 0, None).await;

        assert_eq!(out.errors.len(), 2);
        let logged = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("announce failed"), "{logged}");
        for text in out.errors.iter().map(String::as_str).chain([logged.as_str()]) {
            assert!(!text.contains("SECRET"), "{text}");
        }
    }

    #[tokio::test]
    async fn stopped_announce_skips_scrape_and_asks_for_no_peers() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let url = counting_tracker(None, (10, 2), seen.clone()).await;
        let out = announce_all(&[url], &test_meta(), 6881, 0, 0, 0, Some(Event::Stopped)).await;
        assert_eq!(out.seeders, None);
        let reqs = seen.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        assert!(reqs[0].contains("numwant=0") && reqs[0].contains("event=stopped"), "{}", reqs[0]);
    }
}
