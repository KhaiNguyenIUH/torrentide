//! Tracker clients: HTTP(S) announce per BEP 3 and the two-step UDP protocol
//! from BEP 15, plus scrape for swarm counts.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;
use tokio::net::UdpSocket;

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

const MAX_HTTP_BODY: usize = 2 * 1024 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(60);
const MIN_INTERVAL: Duration = Duration::from_secs(60);
const MAX_INTERVAL: Duration = Duration::from_secs(2 * 3600);
const DEFAULT_MIN_INTERVAL: Duration = Duration::from_secs(300);
const BACKOFF_BASE: Duration = Duration::from_secs(60);
const BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);
#[cfg(test)]
const UDP_BASE_TIMEOUT: Duration = Duration::from_millis(200);
#[cfg(not(test))]
const UDP_BASE_TIMEOUT: Duration = Duration::from_secs(15);
const UDP_ATTEMPTS: u32 = 2;
const UDP_CONN_TTL: Duration = Duration::from_secs(60);
const UDP_CONN_CACHE_MAX: usize = 64;

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

/// What one tracker told us, or that it failed; the engine feeds these to
/// [`TrackerSet::record`].
#[derive(Debug, Clone)]
pub struct TrackerReport {
    pub url: String,
    /// `(interval, min interval)` from a successful reply.
    pub reply: Option<(Duration, Option<Duration>)>,
}

/// Everything [`announce_tiers`] learned from the trackers that answered.
#[derive(Debug, Clone, Default)]
pub struct AnnounceOutcome {
    pub peers: Vec<SocketAddrLite>,
    pub errors: Vec<String>,
    /// Largest seeder / leecher counts any tracker reported.
    pub seeders: Option<u32>,
    pub leechers: Option<u32>,
    pub reports: Vec<TrackerReport>,
}

/// Announce to every tracker at once, each as its own tier.
pub async fn announce_all(
    urls: &[String],
    meta: &Metainfo,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<Event>,
) -> AnnounceOutcome {
    let tiers: Vec<Vec<String>> = urls.iter().map(|u| vec![u.clone()]).collect();
    announce_tiers(&tiers, meta, port, uploaded, downloaded, left, event).await
}

/// BEP 12: within each tier try the trackers in order and stop at the first
/// that answers; tiers run concurrently, swallowing individual failures.
///
/// A tracker being down should not stop a download, so this returns the
/// aggregate of everything that worked along with the errors encountered.
/// `uploaded` and `downloaded` are byte counts since this run's `started`
/// event; private trackers use them for ratio accounting.
///
/// Swarm counts come from the announce reply when it carries them; only a
/// tracker that left them out is scraped. Across tiers the largest count
/// wins, since each tracker only sees the peers that announced to it. A
/// `Stopped` announce asks for no peers and skips the scrape.
pub async fn announce_tiers(
    tiers: &[Vec<String>],
    meta: &Metainfo,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<Event>,
) -> AnnounceOutcome {
    let stopping = event == Some(Event::Stopped);
    let results = futures::future::join_all(tiers.iter().map(|tier| async move {
        let mut tried = Vec::new();
        for url in tier.iter().filter(|u| !u.is_empty()) {
            let res = announce_and_count(url, meta, port, uploaded, downloaded, left, event, stopping).await;
            let ok = res.is_ok();
            tried.push((url, res));
            if ok {
                break;
            }
        }
        tried
    }))
    .await;

    let mut found: HashSet<SocketAddrLite> = HashSet::new();
    let mut out = AnnounceOutcome::default();
    for (url, res) in results.into_iter().flatten() {
        match res {
            Ok(r) => {
                if let Some(w) = &r.warning {
                    tracing::warn!(tracker = %crate::redact::url(url), warning = %w, "tracker warning");
                }
                out.reports.push(TrackerReport {
                    url: url.clone(),
                    reply: Some((r.interval, r.min_interval)),
                });
                found.extend(r.peers);
                out.seeders = out.seeders.max(r.seeders);
                out.leechers = out.leechers.max(r.leechers);
            }
            Err(e) => {
                let shown = crate::redact::url(url);
                tracing::debug!(tracker = %shown, error = %e, "announce failed");
                out.errors.push(format!("{shown}: {e}"));
                out.reports.push(TrackerReport { url: url.clone(), reply: None });
            }
        }
    }
    out.peers = found.into_iter().collect();
    out
}

/// One announce outcome from [`announce_stream`]; `Err` is already redacted.
#[derive(Debug)]
pub struct TrackerUpdate {
    pub url: String,
    pub result: Result<AnnounceResult, String>,
}

const STREAM_MIN_INTERVAL: Duration = Duration::from_secs(60);
const STREAM_MAX_INTERVAL: Duration = Duration::from_secs(300);
const STREAM_RETRY_BASE: Duration = Duration::from_secs(15);

/// Wait before a tracker's next announce: its own interval clamped to
/// 60s..5min after a reply, doubling from 15s up to 5min after failures.
fn stream_delay(reply: Option<Duration>, failures: u32) -> Duration {
    match reply {
        Some(i) => i.clamp(STREAM_MIN_INTERVAL, STREAM_MAX_INTERVAL),
        None => (STREAM_RETRY_BASE * 2u32.saturating_pow(failures.saturating_sub(1)).min(64)).min(STREAM_MAX_INTERVAL),
    }
}

/// Announce to every tracker independently and forever, sending each outcome
/// as soon as that tracker answers. Each tracker re-announces on its own
/// clamped interval and retries with backoff after a failure. The tasks end
/// when the receiver is dropped.
pub fn announce_stream(
    urls: &[String],
    infohash: InfoHash,
    port: u16,
    left: u64,
) -> tokio::sync::mpsc::UnboundedReceiver<TrackerUpdate> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    for url in urls.iter().filter(|u| !u.is_empty()).cloned() {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut event = Some(Event::Started);
            let mut failures = 0u32;
            loop {
                let res = announce(&url, infohash, port, 0, 0, left, event, 200, true).await;
                let delay = match &res {
                    Ok(r) => {
                        event = None;
                        failures = 0;
                        stream_delay(Some(r.interval), 0)
                    }
                    Err(_) => {
                        failures += 1;
                        stream_delay(None, failures)
                    }
                };
                let result = res.map_err(|e| format!("{}: {e}", crate::redact::url(&url)));
                if tx.send(TrackerUpdate { url: url.clone(), result }).is_err() {
                    return;
                }
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = tx.closed() => return,
                }
            }
        });
    }
    rx
}

#[allow(clippy::too_many_arguments)]
async fn announce_and_count(
    url: &str,
    meta: &Metainfo,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<Event>,
    stopping: bool,
) -> Result<AnnounceResult, TrackerError> {
    let mut r = announce(
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
    .await?;
    if !stopping && (r.seeders.is_none() || r.leechers.is_none()) {
        match scrape(url, meta.infohash).await {
            Ok(s) => {
                r.seeders = r.seeders.or(Some(s.complete));
                r.leechers = r.leechers.or(Some(s.incomplete));
            }
            Err(e) => tracing::debug!(tracker = %crate::redact::url(url), error = %e, "scrape failed"),
        }
    }
    Ok(r)
}

struct Entry {
    url: String,
    last: Option<Instant>,
    interval: Duration,
    min_interval: Duration,
    failures: u32,
    retry_at: Option<Instant>,
}

impl Entry {
    fn new(url: String) -> Self {
        Entry {
            url,
            last: None,
            interval: Duration::from_secs(1800),
            min_interval: DEFAULT_MIN_INTERVAL,
            failures: 0,
            retry_at: None,
        }
    }

    fn due(&self, now: Instant, force: bool, event: Option<Event>) -> bool {
        if event.is_some() {
            return true;
        }
        let Some(last) = self.last else { return true };
        let since = now.saturating_duration_since(last);
        since >= self.min_interval && (force || since >= self.interval)
    }
}

/// Per-tracker announce schedule over BEP 12 tiers: when each tracker may be
/// contacted next, which one of a tier is currently preferred, and failure
/// backoff.
pub struct TrackerSet {
    tiers: Vec<Vec<Entry>>,
}

impl TrackerSet {
    pub fn new(tiers: Vec<Vec<String>>) -> Self {
        let mut set = Self::ordered(tiers);
        for tier in &mut set.tiers {
            tier.shuffle(&mut rand::thread_rng());
        }
        set
    }

    fn ordered(tiers: Vec<Vec<String>>) -> Self {
        let mut seen = HashSet::new();
        let tiers = tiers
            .into_iter()
            .map(|t| t.into_iter().filter(|u| seen.insert(u.clone())).map(Entry::new).collect::<Vec<_>>())
            .filter(|t| !t.is_empty())
            .collect();
        TrackerSet { tiers }
    }

    pub fn urls(&self) -> Vec<String> {
        self.tiers.iter().flatten().map(|e| e.url.clone()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.tiers.is_empty()
    }

    pub fn contains(&self, url: &str) -> bool {
        self.tiers.iter().flatten().any(|e| e.url == url)
    }

    /// A tracker added later forms its own tier. The caller announces to it
    /// right away, so it counts as just contacted.
    pub fn add(&mut self, url: String) {
        let mut e = Entry::new(url);
        e.last = Some(Instant::now());
        self.tiers.push(vec![e]);
    }

    pub fn remove(&mut self, url: &str) {
        for tier in &mut self.tiers {
            tier.retain(|e| e.url != url);
        }
        self.tiers.retain(|t| !t.is_empty());
    }

    /// The tiers to announce to now, each as the trackers to try in order.
    ///
    /// A tier waits while its preferred tracker is inside its interval: the
    /// regular `interval`, or only its `min interval` when `force` (starved of
    /// peers). Trackers in failure backoff are passed over. An `event`
    /// announce bypasses both.
    pub fn plan(&self, now: Instant, force: bool, event: Option<Event>) -> Vec<Vec<String>> {
        self.tiers
            .iter()
            .filter_map(|tier| {
                let mut live = tier
                    .iter()
                    .filter(|e| event.is_some() || e.retry_at.map_or(true, |t| now >= t));
                let first = live.next()?;
                if !first.due(now, force, event) {
                    return None;
                }
                Some(std::iter::once(first).chain(live).map(|e| e.url.clone()).collect())
            })
            .collect()
    }

    /// Apply the results of an announce: schedule from the tracker's own
    /// intervals, move the one that answered to the front of its tier, and
    /// back failures off exponentially.
    pub fn record(&mut self, reports: &[TrackerReport], now: Instant) {
        for r in reports {
            for tier in &mut self.tiers {
                let Some(i) = tier.iter().position(|e| e.url == r.url) else { continue };
                let e = &mut tier[i];
                match r.reply {
                    Some((interval, min)) => {
                        e.last = Some(now);
                        e.interval = interval.clamp(MIN_INTERVAL, MAX_INTERVAL);
                        e.min_interval = min.unwrap_or(DEFAULT_MIN_INTERVAL).max(MIN_INTERVAL);
                        e.failures = 0;
                        e.retry_at = None;
                        let e = tier.remove(i);
                        tier.insert(0, e);
                    }
                    None => {
                        e.failures += 1;
                        let wait = BACKOFF_BASE * 2u32.pow((e.failures - 1).min(5));
                        e.retry_at = Some(now + wait.min(BACKOFF_MAX));
                    }
                }
            }
        }
    }
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
    let url = http_announce_url(base, p, crate::peer::wire::local_peer_id());
    let body = http_fetch(&url).await?;
    parse_http_response(&body)
}

/// GET `url` over http or https and return the response body, capped at
/// [`MAX_HTTP_BODY`]. Follows redirects, decodes chunked bodies and rejects
/// non-200 statuses. Non-public addresses are refused unless the tracker
/// itself is at one (a LAN tracker), so a public tracker cannot redirect us
/// into the local network.
async fn http_fetch(url: &str) -> Result<Vec<u8>, TrackerError> {
    let allow_local = url::Url::parse(url).is_ok_and(|u| match u.host() {
        Some(url::Host::Ipv4(ip)) => !crate::webseed::address_allowed(ip.into()),
        Some(url::Host::Ipv6(ip)) => !crate::webseed::address_allowed(ip.into()),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    });
    match tokio::time::timeout(HTTP_TIMEOUT, crate::webseed::get_capped(url, MAX_HTTP_BODY, allow_local)).await {
        Ok(Ok(body)) => Ok(body),
        Ok(Err(e)) => Err(TrackerError::Unreachable(e.to_string())),
        Err(_) => Err(TrackerError::Unreachable("tracker read timed out".into())),
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

/// Decode the bencoded body of an HTTP tracker response, surfacing a
/// `failure reason` as an error.
fn decode_http_body(body: &[u8]) -> Result<bencode::Value, TrackerError> {
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
        .clamp(60, 7200) as u64;
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

fn unreachable(e: std::io::Error) -> TrackerError {
    TrackerError::Unreachable(e.to_string())
}

/// Send `req` and wait for a reply, retransmitting with BEP 15's doubling
/// timeout (`UDP_BASE_TIMEOUT * 2^n`) for [`UDP_ATTEMPTS`] tries.
async fn udp_roundtrip(sock: &UdpSocket, req: &[u8], what: &str) -> Result<Vec<u8>, TrackerError> {
    let mut buf = [0u8; 2048];
    for n in 0..UDP_ATTEMPTS {
        sock.send(req).await.map_err(unreachable)?;
        match tokio::time::timeout(UDP_BASE_TIMEOUT * 2u32.pow(n), sock.recv(&mut buf)).await {
            Ok(Ok(len)) => return Ok(buf[..len].to_vec()),
            Ok(Err(e)) => return Err(unreachable(e)),
            Err(_) => {}
        }
    }
    Err(TrackerError::Unreachable(format!("udp {what} timed out")))
}

async fn udp_server(url: &str) -> Result<SocketAddr, TrackerError> {
    let parsed = url::Url::parse(url)
        .map_err(|e| TrackerError::BadResponse(format!("bad udp url: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| TrackerError::BadResponse("no host".into()))?;
    resolve(host, parsed.port().unwrap_or(80)).await
}

/// Bind a socket and run the BEP 15 connect step. BEP 15 requires the fixed
/// protocol id there; trackers silently drop anything else. A random
/// transaction id ties the response to us.
async fn udp_connect(server: SocketAddr) -> Result<(UdpSocket, i64), TrackerError> {
    let sock = UdpSocket::bind(if server.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" })
        .await
        .map_err(unreachable)?;
    sock.connect(server).await.map_err(unreachable)?;

    let tx: i32 = rand::random();
    let mut req = Vec::with_capacity(16);
    req.extend_from_slice(&UDP_PROTOCOL_ID.to_be_bytes());
    req.extend_from_slice(&0i32.to_be_bytes()); // action = connect
    req.extend_from_slice(&tx.to_be_bytes());

    let buf = udp_roundtrip(&sock, &req, "connect").await?;
    if buf.len() < 16 {
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

type UdpConn = (UdpSocket, i64, Instant);

fn udp_conns() -> &'static Mutex<HashMap<SocketAddr, UdpConn>> {
    static CONNS: OnceLock<Mutex<HashMap<SocketAddr, UdpConn>>> = OnceLock::new();
    CONNS.get_or_init(Default::default)
}

/// One BEP 15 request/reply against `url`. The connection id (with the socket
/// it was issued to) is kept for [`UDP_CONN_TTL`] and reused by the next
/// request to the same tracker; a cached one the tracker no longer accepts is
/// replaced by a fresh connect once. Returns the reply, the transaction id
/// the packet carried, and whether the tracker is IPv6.
async fn udp_transact(
    url: &str,
    what: &str,
    packet: impl Fn(i64, i32) -> Vec<u8>,
) -> Result<(Vec<u8>, i32, bool), TrackerError> {
    let server = udp_server(url).await?;
    let mut cached = udp_conns()
        .lock()
        .unwrap()
        .remove(&server)
        .filter(|(_, _, born)| born.elapsed() < UDP_CONN_TTL);
    loop {
        let reused = cached.is_some();
        let (sock, id, born) = match cached.take() {
            Some(c) => c,
            None => {
                let (sock, id) = udp_connect(server).await?;
                (sock, id, Instant::now())
            }
        };
        let tx: i32 = rand::random();
        let refused = |r: &[u8]| r.len() >= 4 && r[..4] == 3i32.to_be_bytes();
        match udp_roundtrip(&sock, &packet(id, tx), what).await {
            Ok(reply) if reused && refused(&reply) => continue,
            Err(_) if reused => continue,
            Err(e) => return Err(e),
            Ok(reply) => {
                if !refused(&reply) {
                    let mut conns = udp_conns().lock().unwrap();
                    if conns.len() >= UDP_CONN_CACHE_MAX {
                        conns.clear();
                    }
                    conns.insert(server, (sock, id, born));
                }
                return Ok((reply, tx, server.is_ipv6()));
            }
        }
    }
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
        interval: Duration::from_secs(interval.clamp(60, 7200)),
        min_interval: None,
        peers,
        warning: None,
        leechers: Some(count(word(12) as i64)),
        seeders: Some(count(word(16) as i64)),
    })
}

async fn announce_udp(url: &str, p: &AnnounceParams) -> Result<AnnounceResult, TrackerError> {
    let peer_id = crate::peer::wire::local_peer_id();
    let key = u32::from_be_bytes(peer_id[16..].try_into().unwrap());
    let (reply, tx, v6) =
        udp_transact(url, "announce", |id, tx| udp_announce_packet(id, tx, p, peer_id, key)).await?;
    parse_udp_announce(&reply, tx, v6)
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
    let (reply, tx, _) = udp_transact(url, "scrape", |id, tx| udp_scrape_packet(id, tx, infohash)).await?;
    parse_udp_scrape(&reply, tx)
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
        let mut resp = Vec::new();
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
            "{}",
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
        let mut resp = Vec::new();
        resp.append(&mut body);
        let res = parse_http_response(&resp).unwrap();
        let got: Vec<String> = res.peers.iter().map(|p| format!("{}:{}", p.ip, p.port)).collect();
        assert_eq!(got, ["1.2.3.4:6881", "2001:db8::1:7000", "2001:db8::3:7002"]);
    }

    #[test]
    fn http_dict_model_accepts_ipv6() {
        let body = b"d5:peersld2:ip11:2001:db8::94:porti6881eeee";
        let mut resp = Vec::new();
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
        let resp = format!("{}", String::from_utf8_lossy(body));
        match parse_http_response(resp.as_bytes()) {
            Err(TrackerError::Failure(m)) => assert_eq!(m, "torrent missing"),
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn clamps_interval_to_sane_minimum() {
        let body = b"d8:intervali1e5:peers0:e";
        let resp = format!("{}", String::from_utf8_lossy(body));
        let res = parse_http_response(resp.as_bytes()).unwrap();
        assert_eq!(res.interval, Duration::from_secs(60));
    }

    #[test]
    fn rejects_malformed_body() {
        let resp = "not bencode at all";
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

    #[test]
    fn stream_delay_clamps_and_backs_off() {
        assert_eq!(stream_delay(Some(Duration::from_secs(5)), 0), Duration::from_secs(60));
        assert_eq!(stream_delay(Some(Duration::from_secs(1800)), 0), Duration::from_secs(300));
        assert_eq!(stream_delay(None, 1), Duration::from_secs(15));
        assert_eq!(stream_delay(None, 3), Duration::from_secs(60));
        assert_eq!(stream_delay(None, 50), Duration::from_secs(300));
    }

    #[tokio::test]
    async fn announce_stream_delivers_each_tracker_as_it_answers() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let fast = mock_tracker(Duration::ZERO, 1111, seen.clone()).await;
        let slow = mock_tracker(Duration::from_millis(800), 2222, seen.clone()).await;
        let dead = "http://127.0.0.1:1/announce".to_owned();
        let mut rx = announce_stream(&[slow.clone(), dead.clone(), fast.clone()], InfoHash([7; 20]), 6881, 16384);

        let mut order = Vec::new();
        for _ in 0..3 {
            let u = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
            order.push((u.url, u.result.map(|r| r.peers[0].port)));
        }
        assert_eq!(order[2], (slow, Ok(2222)));
        let fast_pos = order.iter().position(|(u, _)| *u == fast).unwrap();
        assert_eq!(order[fast_pos].1, Ok(1111));
        let dead_pos = order.iter().position(|(u, _)| *u == dead).unwrap();
        assert!(order[dead_pos].1.is_err());
        assert!(seen.lock().unwrap().iter().all(|r| r.contains("left=16384")));
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
        let mut resp = Vec::new();
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
        assert!(parse_scrape_response(b"d5:filesi1ee", hash).is_err());
    }

    #[test]
    fn http_announce_reply_counts_are_parsed() {
        let resp = b"d8:completei12e10:incompletei34e8:intervali900e5:peers0:e";
        let res = parse_http_response(resp).unwrap();
        assert_eq!((res.seeders, res.leechers), (Some(12), Some(34)));
        let res = parse_http_response(b"d8:intervali900e5:peers0:e").unwrap();
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
                        let mut r = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
                        r.extend(scrape_body(&[7; 20], scrape_counts.0, 0, scrape_counts.1));
                        r
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

    type Log = std::sync::Arc<Mutex<Vec<String>>>;

    /// Answers each connection with `reply(request)`, logging the request.
    async fn raw_server(reply: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static) -> (SocketAddr, Log) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = Log::default();
        let seen = log.clone();
        let reply = std::sync::Arc::new(reply);
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let (seen, reply) = (seen.clone(), reply.clone());
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap();
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let out = reply(&req);
                    seen.lock().unwrap().push(req);
                    let _ = s.write_all(&out).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        (addr, log)
    }

    fn announce_body() -> Vec<u8> {
        b"d8:intervali900e5:peers6:\x01\x02\x03\x04\x1a\xe1e".to_vec()
    }

    fn ok(body: &[u8]) -> Vec<u8> {
        let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        r.extend_from_slice(body);
        r
    }

    async fn announce_to(url: &str) -> Result<AnnounceResult, TrackerError> {
        announce(url, InfoHash([7; 20]), 6881, 0, 0, 0, None, 50, true).await
    }

    #[tokio::test]
    async fn http_announce_sends_one_stable_peer_id() {
        let (addr, log) = raw_server(|_| ok(&announce_body())).await;
        let url = format!("http://{addr}/announce");
        announce_to(&url).await.unwrap();
        announce_to(&url).await.unwrap();
        let want = format!("peer_id={}&", percent_encode(crate::peer::wire::local_peer_id()));
        let reqs = log.lock().unwrap();
        assert!(reqs.iter().all(|r| r.contains(&want)), "{reqs:?}");
        assert!(want.starts_with("peer_id=-TU0100-"), "{want}");
    }

    #[tokio::test]
    async fn http_body_is_capped() {
        let big = vec![b'x'; MAX_HTTP_BODY + 1];
        let (addr, _) = raw_server(move |_| ok(&big)).await;
        let err = announce_to(&format!("http://{addr}/announce")).await.unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");

        let (addr, _) = raw_server(|_| {
            let mut r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            r.extend_from_slice(format!("{:x}\r\n", MAX_HTTP_BODY + 1).as_bytes());
            r.extend(vec![b'x'; 64]);
            r
        })
        .await;
        let err = announce_to(&format!("http://{addr}/announce")).await.unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
    }

    #[tokio::test]
    async fn http_chunked_reply_is_decoded() {
        let (addr, _) = raw_server(|_| {
            let body = announce_body();
            let (a, b) = body.split_at(10);
            let mut r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            for part in [a, b] {
                r.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                r.extend_from_slice(part);
                r.extend_from_slice(b"\r\n");
            }
            r.extend_from_slice(b"0\r\n\r\n");
            r
        })
        .await;
        let res = announce_to(&format!("http://{addr}/announce")).await.unwrap();
        assert_eq!(res.interval, Duration::from_secs(900));
        assert_eq!(res.peers[0].port, 6881);
    }

    #[tokio::test]
    async fn http_redirect_is_followed_and_host_carries_the_port() {
        let (target, target_log) = raw_server(|_| ok(&announce_body())).await;
        let location = format!("http://{target}/moved");
        let (addr, log) = raw_server(move |_| {
            format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n").into_bytes()
        })
        .await;
        let res = announce_to(&format!("http://{addr}/announce")).await.unwrap();
        assert_eq!(res.peers.len(), 1);
        assert!(log.lock().unwrap()[0].contains(&format!("Host: {addr}\r\n")), "{:?}", log.lock().unwrap());
        let seen = target_log.lock().unwrap();
        assert!(seen[0].starts_with("GET /moved"), "{seen:?}");
        assert!(seen[0].contains(&format!("Host: {target}\r\n")), "{seen:?}");
    }

    #[tokio::test]
    async fn http_redirect_to_another_scheme_or_loop_is_refused() {
        let (addr, _) = raw_server(|_| b"HTTP/1.1 302 Found\r\nLocation: ftp://x/y\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
        assert!(announce_to(&format!("http://{addr}/announce")).await.is_err());
        let (addr, _) = raw_server(|_| b"HTTP/1.1 302 Found\r\nLocation: /announce\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
        let err = announce_to(&format!("http://{addr}/announce")).await.unwrap_err();
        assert!(err.to_string().contains("redirects"), "{err}");
    }

    #[tokio::test]
    async fn http_error_status_is_an_error() {
        let (addr, _) = raw_server(|_| b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
        let err = announce_to(&format!("http://{addr}/announce")).await.unwrap_err();
        assert!(err.to_string().contains("500"), "{err}");
    }

    async fn udp_tracker(
        drop_first_connect: bool,
        connects: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        announces: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> String {
        use std::sync::atomic::Ordering::SeqCst;
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let url = format!("udp://{}/announce", sock.local_addr().unwrap());
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut dropped = !drop_first_connect;
            loop {
                let (n, from) = sock.recv_from(&mut buf).await.unwrap();
                let mut reply;
                if n == 16 {
                    if !dropped {
                        dropped = true;
                        continue;
                    }
                    connects.fetch_add(1, SeqCst);
                    reply = 0i32.to_be_bytes().to_vec();
                    reply.extend_from_slice(&buf[12..16]);
                    reply.extend_from_slice(&42i64.to_be_bytes());
                } else {
                    announces.fetch_add(1, SeqCst);
                    assert_eq!(i64::from_be_bytes(buf[0..8].try_into().unwrap()), 42);
                    reply = 1i32.to_be_bytes().to_vec();
                    reply.extend_from_slice(&buf[12..16]);
                    reply.extend_from_slice(&900i32.to_be_bytes());
                    reply.extend_from_slice(&[0; 8]);
                    reply.extend_from_slice(&[10, 0, 0, 1, 0x1a, 0xe1]);
                }
                sock.send_to(&reply, from).await.unwrap();
            }
        });
        url
    }

    #[tokio::test]
    async fn udp_retransmits_a_lost_connect_then_succeeds() {
        let n = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = udp_tracker(true, n.clone(), n.clone()).await;
        let started = std::time::Instant::now();
        let res = announce_to(&url).await.unwrap();
        assert_eq!(res.peers[0].port, 6881);
        assert!(started.elapsed() >= UDP_BASE_TIMEOUT, "no retransmit wait");
    }

    #[tokio::test]
    async fn udp_gives_up_after_the_retransmit_budget() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let url = format!("udp://{}/announce", sock.local_addr().unwrap());
        let started = std::time::Instant::now();
        assert!(announce_to(&url).await.is_err());
        assert!(started.elapsed() >= UDP_BASE_TIMEOUT * 3);
    }

    #[tokio::test]
    async fn udp_connection_id_is_reused_between_requests() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let (connects, announces) = (std::sync::Arc::new(AtomicUsize::new(0)), std::sync::Arc::new(AtomicUsize::new(0)));
        let url = udp_tracker(false, connects.clone(), announces.clone()).await;
        announce_to(&url).await.unwrap();
        announce_to(&url).await.unwrap();
        assert_eq!((connects.load(SeqCst), announces.load(SeqCst)), (1, 2));
    }

    fn tiers(t: &[&[&str]]) -> Vec<Vec<String>> {
        t.iter().map(|t| t.iter().map(|u| (*u).to_owned()).collect()).collect()
    }

    fn ok_report(url: &str, interval: u64, min: Option<u64>) -> TrackerReport {
        TrackerReport {
            url: url.into(),
            reply: Some((Duration::from_secs(interval), min.map(Duration::from_secs))),
        }
    }

    fn fail(url: &str) -> TrackerReport {
        TrackerReport { url: url.into(), reply: None }
    }

    #[test]
    fn tracker_set_never_reannounces_inside_min_interval_even_when_starved() {
        let t0 = Instant::now();
        let mut set = TrackerSet::ordered(tiers(&[&["http://a/announce"]]));
        assert_eq!(set.plan(t0, false, Some(Event::Started)).len(), 1);
        set.record(&[ok_report("http://a/announce", 1800, Some(600))], t0);
        let mut announces = 0;
        for secs in (15..=1800).step_by(15) {
            if !set.plan(t0 + Duration::from_secs(secs), true, None).is_empty() {
                announces += 1;
                assert!(secs >= 600, "re-announced after {secs}s");
                set.record(&[ok_report("http://a/announce", 1800, Some(600))], t0 + Duration::from_secs(secs));
            }
        }
        assert_eq!(announces, 3, "forced every 600s, not every 15s");
        let fresh = TrackerSet::ordered(tiers(&[&["http://a/announce"]]));
        assert!(fresh.plan(t0, true, None).len() == 1);
    }

    #[test]
    fn tracker_set_uses_the_default_min_interval_and_clamps_the_regular_one() {
        let t0 = Instant::now();
        let mut set = TrackerSet::ordered(tiers(&[&["http://a/announce"]]));
        set.record(&[ok_report("http://a/announce", 10, None)], t0);
        assert!(set.plan(t0 + Duration::from_secs(299), true, None).is_empty());
        assert!(!set.plan(t0 + Duration::from_secs(300), true, None).is_empty());
        set.record(&[ok_report("http://a/announce", 999_999, Some(1))], t0);
        assert!(set.plan(t0 + Duration::from_secs(7199), false, None).is_empty());
        assert!(!set.plan(t0 + Duration::from_secs(7200), false, None).is_empty());
        assert!(!set.plan(t0 + Duration::from_secs(1), false, Some(Event::Completed)).is_empty());
    }

    #[test]
    fn tracker_set_backs_failures_off_exponentially_up_to_thirty_minutes() {
        let t0 = Instant::now();
        let mut set = TrackerSet::ordered(tiers(&[&["http://a/announce"]]));
        let mut now = t0;
        for wait in [60, 120, 240, 480, 960, 1800, 1800] {
            set.record(&[fail("http://a/announce")], now);
            assert!(set.plan(now + Duration::from_secs(wait - 1), false, None).is_empty(), "{wait}");
            now += Duration::from_secs(wait);
            assert!(!set.plan(now, false, None).is_empty(), "{wait}");
        }
        set.record(&[ok_report("http://a/announce", 1800, None)], now);
        set.record(&[fail("http://a/announce")], now);
        assert!(!set.plan(now + Duration::from_secs(60), true, Some(Event::Stopped)).is_empty());
    }

    #[test]
    fn tracker_set_promotes_the_tracker_that_answered_and_skips_failed_ones() {
        let t0 = Instant::now();
        let mut set = TrackerSet::ordered(tiers(&[&["http://a/x", "http://b/x", "http://c/x"], &["http://d/x"]]));
        assert_eq!(set.plan(t0, false, None), tiers(&[&["http://a/x", "http://b/x", "http://c/x"], &["http://d/x"]]));
        set.record(&[fail("http://a/x"), ok_report("http://b/x", 1800, None), ok_report("http://d/x", 1800, None)], t0);
        let later = t0 + Duration::from_secs(1800);
        assert_eq!(set.plan(later, false, None), tiers(&[&["http://b/x", "http://a/x", "http://c/x"], &["http://d/x"]]));
        let soon = t0 + Duration::from_secs(61);
        assert!(set.plan(soon, false, None).is_empty());
    }

    #[test]
    fn tracker_set_new_shuffles_within_tiers_only_and_dedups() {
        let set = TrackerSet::new(tiers(&[&["http://a/x", "http://b/x"], &["http://a/x", "http://c/x"], &[]]));
        let plan = set.plan(Instant::now(), false, None);
        assert_eq!(plan.len(), 2);
        let mut first = plan[0].clone();
        first.sort();
        assert_eq!(first, ["http://a/x", "http://b/x"]);
        assert_eq!(plan[1], ["http://c/x"]);
    }

    #[tokio::test]
    async fn announce_tiers_try_the_next_tracker_only_after_a_failure() {
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let good_a = mock_tracker(Duration::ZERO, 1111, seen.clone()).await;
        let good_b = mock_tracker(Duration::ZERO, 2222, seen.clone()).await;
        let spare = mock_tracker(Duration::ZERO, 3333, seen.clone()).await;
        let dead = "http://127.0.0.1:1/announce".to_owned();
        let plan = vec![
            vec![dead.clone(), good_a.clone(), spare.clone()],
            vec![good_b.clone(), spare],
        ];
        let out = announce_tiers(&plan, &test_meta(), 6881, 0, 0, 0, None).await;
        let mut ports: Vec<u16> = out.peers.iter().map(|p| p.port).collect();
        ports.sort();
        assert_eq!(ports, [1111, 2222]);
        assert_eq!(seen.lock().unwrap().len(), 2, "the spare trackers must not be contacted");
        let urls: Vec<(&str, bool)> = out.reports.iter().map(|r| (r.url.as_str(), r.reply.is_some())).collect();
        assert_eq!(urls, [(dead.as_str(), false), (good_a.as_str(), true), (good_b.as_str(), true)]);

        let mut set = TrackerSet::ordered(vec![vec![dead.clone(), good_a.clone()], vec![good_b.clone()]]);
        set.record(&out.reports, Instant::now());
        let next = set.plan(Instant::now() + Duration::from_secs(3600), false, None);
        assert_eq!(next[0], [good_a, dead]);
    }
}
