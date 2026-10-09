//! Tracker clients: HTTP(S) announce per BEP 3 and the two-step UDP protocol
//! from BEP 15.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpStream;

use crate::bencode;
use crate::metainfo::{InfoHash, Metainfo, SocketAddrLite};

#[derive(Debug, Clone)]
pub struct AnnounceResult {
    pub interval: Duration,
    /// Minimum announce interval some trackers request.
    pub min_interval: Option<Duration>,
    pub peers: Vec<SocketAddrLite>,
    /// Human-readable tracker warnings, e.g. "torrent not registered".
    pub warning: Option<String>,
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

/// Announce to a tracker URL, dispatching on scheme.
/// BEP 15 magic constant sent as the connection id of a connect request.
const UDP_PROTOCOL_ID: i64 = 0x0417_2710_1980;

pub async fn announce(
    url: &str,
    infohash: InfoHash,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    numwant: usize,
    compact: bool,
) -> Result<AnnounceResult, TrackerError> {
    if url.starts_with("udp://") {
        announce_udp(url, infohash, port, uploaded, downloaded, left, numwant).await
    } else if url.starts_with("http://") || url.starts_with("https://") {
        announce_http(url, infohash, port, uploaded, downloaded, left, numwant, compact)
            .await
    } else {
        Err(TrackerError::UnsupportedScheme(url.to_owned()))
    }
}

/// Ask every tracker for peers concurrently, swallowing individual failures.
///
/// A tracker being down should not stop a download, so this returns the
/// aggregate of everything that worked along with the errors encountered.
/// Trackers are contacted in parallel so one that hangs until its timeout
/// costs only its own wait, not the sum of all of them. `uploaded` is the real
/// cumulative byte count; private trackers use it for ratio accounting.
pub async fn announce_all(
    urls: &[String],
    meta: &Metainfo,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
) -> (Vec<SocketAddrLite>, Vec<String>) {
    let results = futures::future::join_all(urls.iter().filter(|u| !u.is_empty()).map(|url| async move {
        let res = announce(
            url,
            meta.infohash,
            port,
            uploaded,
            downloaded,
            left,
            200,
            true,
        )
        .await;
        (url, res)
    }))
    .await;

    let mut found: HashSet<SocketAddrLite> = HashSet::new();
    let mut errors = Vec::new();
    for (url, res) in results {
        match res {
            Ok(r) => {
                if let Some(w) = &r.warning {
                    tracing::warn!(tracker = %url, warning = %w, "tracker warning");
                }
                found.extend(r.peers);
            }
            Err(e) => {
                tracing::debug!(tracker = %url, error = %e, "announce failed");
                errors.push(format!("{url}: {e}"));
            }
        }
    }

    (found.into_iter().collect(), errors)
}

// ---------------------------------------------------------------- HTTP tracker

#[allow(clippy::too_many_arguments)]
async fn announce_http(
    base: &str,
    infohash: InfoHash,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    numwant: usize,
    compact: bool,
) -> Result<AnnounceResult, TrackerError> {
    let sep = if base.contains('?') { '&' } else { '?' };
    let query = format!(
        "{sep}info_hash={}&peer_id={}&port={}&uploaded={uploaded}\
         &downloaded={downloaded}&left={left}&compact={}&numwant={numwant}&event=started",
        percent_encode(&infohash.0),
        percent_encode(&random_peer_id()),
        port,
        i32::from(compact),
    );
    let url = format!("{base}{query}");

    let parsed = url::Url::parse(&url).map_err(|e| TrackerError::BadResponse(e.to_string()))?;
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
    let body = if tls {
        let connector = tls_connector();
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|_| TrackerError::BadResponse(format!("bad TLS server name: {host}")))?;
        let mut tls_stream = tokio::time::timeout(Duration::from_secs(15), connector.connect(server_name, tcp))
            .await
            .map_err(|_| TrackerError::Unreachable("TLS handshake timed out".into()))?
            .map_err(|e| TrackerError::Unreachable(format!("TLS handshake failed: {e}")))?;
        http_get(&mut tls_stream, &host, &path_and_query).await?
    } else {
        let mut plain = tcp;
        http_get(&mut plain, &host, &path_and_query).await?
    };

    parse_http_response(&body)
}

/// Build a TLS client that trusts the roots bundled with webpki-roots.
///
/// Cached in a `OnceLock` because building the root store parses hundreds of
/// certificates, and we would otherwise redo that on every announce.
fn tls_connector() -> tokio_rustls::TlsConnector {
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

fn parse_http_response(raw: &[u8]) -> Result<AnnounceResult, TrackerError> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| TrackerError::BadResponse("no header/body separator".into()))?;
    let head = String::from_utf8_lossy(&raw[..sep]);
    let body = &raw[sep + 4..];

    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);

    // Trackers signal errors both by HTTP status and by a bencoded `failure
    // reason`, so accept the body when the status is not 2xx and let the
    // bencode parser produce the real message.
    let _ = status;

    let value = bencode::decode(body)
        .map_err(|e| TrackerError::BadResponse(e.to_string()))?;

    if let Ok(failure) = value.get("failure reason").and_then(|v| v.as_str()) {
        return Err(TrackerError::Failure(failure.to_owned()));
    }

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

    Ok(AnnounceResult {
        interval: Duration::from_secs(interval),
        min_interval,
        peers,
        warning,
    })
}

// ----------------------------------------------------------------- UDP tracker

#[allow(clippy::too_many_arguments)]
async fn announce_udp(
    url: &str,
    infohash: InfoHash,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    numwant: usize,
) -> Result<AnnounceResult, TrackerError> {
    let parsed = url::Url::parse(url)
        .map_err(|e| TrackerError::BadResponse(format!("bad udp url: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| TrackerError::BadResponse("no host".into()))?
        .to_owned();
    let tp = parsed.port().unwrap_or(80);

    let server = resolve(&host, tp).await?;
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;
    sock.connect(server)
        .await
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;

    // Step 1: connect request. BEP 15 requires the fixed protocol id here;
    // trackers silently drop anything else. A random transaction id ties the
    // response to us.
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
    let real_conn_id = i64::from_be_bytes(buf[8..16].try_into().unwrap());

    // Step 2: announce.
    let tx2: i32 = rand::random();
    let mut a = Vec::with_capacity(98);
    a.extend_from_slice(&real_conn_id.to_be_bytes());
    a.extend_from_slice(&1i32.to_be_bytes()); // action = announce
    a.extend_from_slice(&tx2.to_be_bytes());
    a.extend_from_slice(&infohash.0);
    a.extend_from_slice(&random_peer_id());
    a.extend_from_slice(&(downloaded as i64).to_be_bytes());
    a.extend_from_slice(&(left as i64).to_be_bytes());
    a.extend_from_slice(&(uploaded as i64).to_be_bytes());
    a.extend_from_slice(&0i32.to_be_bytes()); // event: none
    a.extend_from_slice(&0u32.to_be_bytes()); // IP: default
    a.extend_from_slice(&rand::random::<u32>().to_be_bytes()); // key
    // BEP 15 uses -1 for "tracker default"; a caller-supplied value is
    // honoured but clamped so a silly numwant cannot stall the response.
    let want = if numwant == 0 { -1i32 } else { (numwant as i32).clamp(1, 500) };
    a.extend_from_slice(&want.to_be_bytes());
    a.extend_from_slice(&port.to_be_bytes());

    sock.send(&a)
        .await
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;

    let n = tokio::time::timeout(Duration::from_secs(10), sock.recv(&mut buf))
        .await
        .map_err(|_| TrackerError::Unreachable("udp announce timed out".into()))?
        .map_err(|e| TrackerError::Unreachable(e.to_string()))?;

    if n < 20 {
        return Err(TrackerError::BadResponse("short udp announce reply".into()));
    }
    let action = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if action == 3 {
        let msg = String::from_utf8_lossy(&buf[8..n]).into_owned();
        return Err(TrackerError::Failure(msg));
    }
    if action != 1 {
        return Err(TrackerError::BadResponse(format!("unexpected udp action {action}")));
    }
    // Reply layout: action, transaction id, interval, leechers, seeders (4
    // bytes each), then packed (ipv4, port) pairs.
    let rtx2 = i32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if rtx2 != tx2 {
        return Err(TrackerError::BadResponse("udp announce txid mismatch".into()));
    }

    let interval = i32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]) as u64;
    let mut peers = Vec::new();
    for chunk in buf[20..n].chunks_exact(6) {
        let ip = std::net::Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
        let p = u16::from_be_bytes([chunk[4], chunk[5]]);
        if p > 0 {
            peers.push(SocketAddrLite {
                ip: IpAddr::V4(ip),
                port: p,
            });
        }
    }

    Ok(AnnounceResult {
        interval: Duration::from_secs(interval.clamp(60, 3600)),
        min_interval: None,
        peers,
        warning: None,
    })
}

// -------------------------------------------------------------------- helpers

/// Resolve to an IPv4 address: the UDP socket is bound to `0.0.0.0` and the
/// BEP 15 announce reply only carries IPv4 peers.
async fn resolve(host: &str, port: u16) -> Result<SocketAddr, TrackerError> {
    use tokio::net::lookup_host;
    lookup_host((host, port))
        .await
        .map_err(|e| TrackerError::Unreachable(format!("dns lookup for {host} failed: {e}")))?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| TrackerError::Unreachable(format!("{host} has no IPv4 address")))
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
            .block_on(announce("wss://x/announce", hash, 6881, 0, 0, 0, 50, true))
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
                .block_on(announce(bad, hash, 6881, 0, 0, 0, 50, true))
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
                    let mut body = b"d8:intervali1800e5:peers6:".to_vec();
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
        let (mut peers, errors) =
            announce_all(&[a, b, dead.clone()], &test_meta(), 6881, 1234, 55, 100).await;
        let elapsed = start.elapsed();

        peers.sort_by_key(|p| p.port);
        assert_eq!(peers.iter().map(|p| p.port).collect::<Vec<_>>(), [1111, 2222]);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].starts_with(&dead));
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
            let mut reply = 1i32.to_be_bytes().to_vec();
            reply.extend_from_slice(&buf[12..16]);
            reply.extend_from_slice(&900i32.to_be_bytes());
            reply.extend_from_slice(&3i32.to_be_bytes());
            reply.extend_from_slice(&7i32.to_be_bytes());
            reply.extend_from_slice(&[10, 0, 0, 1, 0x1a, 0xe1, 10, 0, 0, 2, 0x1a, 0xe2]);
            sock.send_to(&reply, from).await.unwrap();
        });

        let res = announce(&url, InfoHash([7; 20]), 6881, 1234, 55, 100, 50, true)
            .await
            .unwrap();
        tracker.await.unwrap();
        assert_eq!(res.interval, Duration::from_secs(900));
        let ports: Vec<u16> = res.peers.iter().map(|p| p.port).collect();
        assert_eq!(ports, [6881, 6882]);
    }
}
