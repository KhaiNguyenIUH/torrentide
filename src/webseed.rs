//! HTTP web seeds (BEP 19, GetRight style `url-list`).
//!
//! A web seed is a plain HTTP(S) server holding the torrent's files. Pieces are
//! fetched with `Range` requests, one per file the piece touches. Everything the
//! server says is untrusted: sizes are checked against what we asked for, and
//! the engine still hash-verifies every piece.

use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use url::Url;

use crate::metainfo::{Files, Metainfo};
use crate::ratelimit::Limits;

pub const MAX_WEB_SEEDS: usize = 4;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 3;
const MAX_LINE: u64 = 8192;
const MAX_HEADERS: usize = 100;
const BACKOFF_BASE: Duration = Duration::from_secs(30);
const BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);
const READ_CHUNK: usize = 16 * 1024;

const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

#[derive(Debug, Error)]
pub enum WsError {
    #[error("file {0} is not on the web seed")]
    Gone(usize),
    #[error("{0}")]
    Other(String),
}

fn other(msg: impl Into<String>) -> WsError {
    WsError::Other(msg.into())
}

/// The slice of one file that a piece covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub file: usize,
    pub offset: u64,
    pub len: u64,
}

pub fn piece_segments(meta: &Metainfo, piece: u32) -> Vec<Segment> {
    let start = piece as u64 * meta.piece_length as u64;
    let end = start + meta.piece_size(piece as usize);
    let mut out = Vec::new();
    let mut cursor = 0u64;
    for (file, (_, len)) in meta.files.iter().enumerate() {
        let (fs, fe) = (cursor, cursor + len);
        cursor = fe;
        let (a, b) = (fs.max(start), fe.min(end));
        if a < b {
            out.push(Segment {
                file,
                offset: a - fs,
                len: b - a,
            });
        }
    }
    out
}

fn encode_segment(s: &str) -> String {
    utf8_percent_encode(s, SEGMENT).to_string()
}

pub fn file_url(base: &str, meta: &Metainfo, file: usize) -> Option<String> {
    let (path, _) = meta.files.iter().nth(file)?;
    let encoded = |p: &std::path::Path| {
        p.components()
            .map(|c| encode_segment(&c.as_os_str().to_string_lossy()))
            .collect::<Vec<_>>()
            .join("/")
    };
    Some(match &meta.files {
        Files::Single { name, .. } => {
            if base.ends_with('/') {
                format!("{base}{}", encode_segment(name))
            } else {
                base.to_owned()
            }
        }
        Files::Multi { .. } => {
            let sep = if base.ends_with('/') { "" } else { "/" };
            format!("{base}{sep}{}", encoded(path))
        }
    })
}

/// Fetch one whole piece, one range request per file it touches.
pub async fn fetch_piece(
    meta: &Metainfo,
    base: &str,
    piece: u32,
    limits: &Limits,
    allow_local: bool,
) -> Result<Vec<u8>, WsError> {
    let mut out = Vec::with_capacity(meta.piece_size(piece as usize) as usize);
    for seg in piece_segments(meta, piece) {
        let url = file_url(base, meta, seg.file).ok_or_else(|| other("no such file"))?;
        let file_len = meta.files.iter().nth(seg.file).map_or(0, |(_, l)| l);
        let data = get_range(&url, seg.offset, seg.len, file_len, limits, allow_local)
            .await
            .map_err(|e| match e {
                WsError::Gone(_) => WsError::Gone(seg.file),
                e => e,
            })?;
        out.extend_from_slice(&data);
    }
    Ok(out)
}

async fn within<T>(fut: impl Future<Output = std::io::Result<T>>) -> Result<T, WsError> {
    match tokio::time::timeout(REQUEST_TIMEOUT, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(other(format!("io: {e}"))),
        Err(_) => Err(other("timed out")),
    }
}

enum Reply {
    Body(Vec<u8>),
    Redirect(String),
}

tokio::task_local! {
    pub static ALLOW_LOCAL: bool;
}

fn local_allowed() -> bool {
    ALLOW_LOCAL.try_with(|v| *v).unwrap_or(false)
}

const NOT_ALLOWED: &str = "address not allowed";

/// True when `ip` is a public, globally routable unicast address. Everything
/// else (loopback, LAN, link-local, CGNAT, multicast, reserved, documentation,
/// and IPv4 embedded in IPv6 forms of those) is refused for remote URLs.
pub fn address_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            if let Some(v4) = v6.to_ipv4_mapped() {
                return address_allowed(IpAddr::V4(v4));
            }
            let embedded = |a: u16, b: u16| Ipv4Addr::from([(a >> 8) as u8, a as u8, (b >> 8) as u8, b as u8]);
            if seg[..6] == [0, 0, 0, 0, 0, 0] && !v6.is_loopback() && !v6.is_unspecified() {
                return address_allowed(IpAddr::V4(embedded(seg[6], seg[7])));
            }
            if seg[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                return address_allowed(IpAddr::V4(embedded(seg[6], seg[7])));
            }
            if seg[0] == 0x2002 {
                return address_allowed(IpAddr::V4(embedded(seg[1], seg[2])));
            }
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00
                || (seg[0] & 0xffc0) == 0xfe80
                || (seg[0] & 0xffc0) == 0xfec0
                || (seg[0] == 0x2001 && seg[1] == 0x0db8))
        }
    }
}

struct Hop {
    tcp: TcpStream,
    tls: bool,
    host: String,
    host_header: String,
    target: String,
}

async fn dial(current: &Url, allow_local: bool) -> Result<Hop, WsError> {
    let host = current.host_str().ok_or_else(|| other("url has no host"))?.to_owned();
    let tls = match current.scheme() {
        "http" => false,
        "https" => true,
        s => return Err(other(format!("unsupported scheme {s}"))),
    };
    let port = current.port_or_known_default().unwrap_or(if tls { 443 } else { 80 });
    let mut target = current.path().to_owned();
    if let Some(q) = current.query() {
        target.push('?');
        target.push_str(q);
    }
    let host_header = match current.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.clone(),
    };
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let resolved: Vec<SocketAddr> = match tokio::time::timeout(REQUEST_TIMEOUT, tokio::net::lookup_host((bare, port))).await {
        Ok(Ok(it)) => it.collect(),
        _ => return Err(other("cannot resolve host")),
    };
    if !allow_local && resolved.iter().any(|a| !address_allowed(a.ip())) {
        return Err(other(NOT_ALLOWED));
    }
    let addr = resolved.first().ok_or_else(|| other("cannot resolve host"))?;
    let tcp = within(TcpStream::connect(addr)).await?;
    Ok(Hop { tcp, tls, host: bare.to_owned(), host_header, target })
}

async fn get_range(
    url: &str,
    offset: u64,
    len: u64,
    file_len: u64,
    limits: &Limits,
    allow_local: bool,
) -> Result<Vec<u8>, WsError> {
    let mut current = Url::parse(url).map_err(|e| other(format!("bad url: {e}")))?;
    for _ in 0..=MAX_REDIRECTS {
        let Hop { tcp, tls, host, host_header, target } = dial(&current, allow_local).await?;
        let reply = if tls {
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|_| other("bad TLS server name"))?;
            let stream = within(crate::tracker::tls_connector().connect(name, tcp)).await?;
            exchange(stream, &host_header, &target, offset, len, file_len, limits).await?
        } else {
            exchange(tcp, &host_header, &target, offset, len, file_len, limits).await?
        };
        match reply {
            Reply::Body(b) => return Ok(b),
            Reply::Redirect(loc) => {
                current = current.join(&loc).map_err(|e| other(format!("bad redirect: {e}")))?;
            }
        }
    }
    Err(other("too many redirects"))
}

/// Plain GET following redirects, for small documents such as feeds. The body is
/// refused once it passes `max_body` bytes rather than buffered. Loopback, LAN
/// and other non-public addresses are refused on every hop unless `allow_local`.
pub(crate) async fn get_capped(url: &str, max_body: usize, allow_local: bool) -> Result<Vec<u8>, WsError> {
    let mut current = Url::parse(url).map_err(|e| other(format!("bad url: {e}")))?;
    for _ in 0..=MAX_REDIRECTS {
        let Hop { tcp, tls, host, host_header, target } = dial(&current, allow_local).await?;
        let reply = if tls {
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|_| other("bad TLS server name"))?;
            let stream = within(crate::tracker::tls_connector().connect(name, tcp)).await?;
            exchange_capped(stream, &host_header, &target, max_body).await?
        } else {
            exchange_capped(tcp, &host_header, &target, max_body).await?
        };
        match reply {
            Reply::Body(b) => return Ok(b),
            Reply::Redirect(loc) => {
                current = current.join(&loc).map_err(|e| other(format!("bad redirect: {e}")))?;
            }
        }
    }
    Err(other("too many redirects"))
}

async fn exchange_capped<S>(
    stream: S,
    host: &str,
    target: &str,
    max_body: usize,
) -> Result<Reply, WsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut r = BufReader::new(stream);
    let req = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: torrentide/0.1\r\n\
         Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    within(r.get_mut().write_all(req.as_bytes())).await?;
    within(r.get_mut().flush()).await?;

    let head = read_head(&mut r).await?;
    match head.status {
        301 | 302 | 303 | 307 | 308 => {
            let loc = head.get("location").ok_or_else(|| other("redirect without Location"))?;
            return Ok(Reply::Redirect(loc.to_owned()));
        }
        200 => {}
        s => return Err(other(format!("unexpected HTTP status {s}"))),
    }
    if head.get("content-encoding").is_some_and(|e| !e.eq_ignore_ascii_case("identity")) {
        return Err(other("content-encoded response"));
    }
    let chunked = head
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let mut body = Vec::new();
    if chunked {
        loop {
            let line = read_line(&mut r).await?;
            let size_str = line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_str, 16).map_err(|_| other("bad chunk size"))?;
            if size == 0 {
                break;
            }
            if size > max_body.saturating_sub(body.len()) {
                return Err(other("body too large"));
            }
            let start = body.len();
            body.resize(start + size, 0);
            within(r.read_exact(&mut body[start..])).await?;
            if !read_line(&mut r).await?.is_empty() {
                return Err(other("missing chunk terminator"));
            }
        }
    } else {
        let declared = head.get("content-length").and_then(|v| v.parse::<usize>().ok());
        if declared.is_some_and(|n| n > max_body) {
            return Err(other("body too large"));
        }
        let mut tmp = [0u8; READ_CHUNK];
        loop {
            let got = within(r.read(&mut tmp)).await?;
            if got == 0 {
                break;
            }
            if got > max_body - body.len() {
                return Err(other("body too large"));
            }
            body.extend_from_slice(&tmp[..got]);
        }
        if declared.is_some_and(|n| n != body.len()) {
            return Err(other("body shorter than Content-Length"));
        }
    }
    Ok(Reply::Body(body))
}

struct Head {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Head {
    fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

async fn read_line<R: AsyncBufReadExt + Unpin>(r: &mut R) -> Result<String, WsError> {
    let mut buf = Vec::new();
    let n = within((&mut *r).take(MAX_LINE).read_until(b'\n', &mut buf)).await?;
    if n == 0 || buf.last() != Some(&b'\n') {
        return Err(other("truncated or oversized header line"));
    }
    Ok(String::from_utf8_lossy(&buf).trim_end().to_owned())
}

async fn read_head<R: AsyncBufReadExt + Unpin>(r: &mut R) -> Result<Head, WsError> {
    let status_line = read_line(r).await?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or("");
    let status = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|_| version.starts_with("HTTP/1."))
        .ok_or_else(|| other(format!("bad status line: {status_line}")))?;
    let mut headers = Vec::new();
    loop {
        let line = read_line(r).await?;
        if line.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(other("too many headers"));
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_owned()));
        }
    }
    Ok(Head { status, headers })
}

/// Parse `bytes a-b/total`.
fn parse_content_range(v: &str) -> Option<(u64, u64)> {
    let rest = v.trim().strip_prefix("bytes")?.trim_start();
    let (range, _total) = rest.split_once('/')?;
    let (a, b) = range.split_once('-')?;
    Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
}

async fn exchange<S>(
    stream: S,
    host: &str,
    target: &str,
    offset: u64,
    len: u64,
    file_len: u64,
    limits: &Limits,
) -> Result<Reply, WsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if len == 0 {
        return Ok(Reply::Body(Vec::new()));
    }
    let last = offset + len - 1;
    let mut r = BufReader::new(stream);
    let req = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: torrentide/0.1\r\n\
         Range: bytes={offset}-{last}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    within(r.get_mut().write_all(req.as_bytes())).await?;
    within(r.get_mut().flush()).await?;

    let head = read_head(&mut r).await?;
    match head.status {
        301 | 302 | 303 | 307 | 308 => {
            let loc = head.get("location").ok_or_else(|| other("redirect without Location"))?;
            return Ok(Reply::Redirect(loc.to_owned()));
        }
        404 | 410 => return Err(WsError::Gone(0)),
        206 => {
            let cr = head
                .get("content-range")
                .and_then(parse_content_range)
                .ok_or_else(|| other("206 without a valid Content-Range"))?;
            if cr != (offset, last) {
                return Err(other(format!("server sent range {}-{}, wanted {offset}-{last}", cr.0, cr.1)));
            }
        }
        200 => {
            if !(offset == 0 && len == file_len) {
                return Err(other("server ignored Range and sent the whole file"));
            }
        }
        s => return Err(other(format!("unexpected HTTP status {s}"))),
    }
    if head.get("content-encoding").is_some_and(|e| !e.eq_ignore_ascii_case("identity")) {
        return Err(other("content-encoded response"));
    }

    let expected = len as usize;
    let chunked = head
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let mut body = Vec::with_capacity(expected);
    if chunked {
        loop {
            let line = read_line(&mut r).await?;
            let size_str = line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_str, 16).map_err(|_| other("bad chunk size"))?;
            if size == 0 {
                break;
            }
            if size > expected.saturating_sub(body.len()) {
                return Err(other("chunked body longer than requested"));
            }
            read_n(&mut r, &mut body, size, limits).await?;
            if !read_line(&mut r).await?.is_empty() {
                return Err(other("missing chunk terminator"));
            }
        }
    } else {
        let cl: usize = head
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| other("missing or invalid Content-Length"))?;
        if cl != expected {
            return Err(other(format!("Content-Length {cl}, wanted {expected}")));
        }
        read_n(&mut r, &mut body, cl, limits).await?;
    }
    if body.len() != expected {
        return Err(other(format!("body is {} bytes, wanted {expected}", body.len())));
    }
    Ok(Reply::Body(body))
}

async fn read_n<R: AsyncRead + Unpin>(
    r: &mut R,
    out: &mut Vec<u8>,
    mut n: usize,
    limits: &Limits,
) -> Result<(), WsError> {
    let mut tmp = [0u8; READ_CHUNK];
    while n > 0 {
        let take = n.min(READ_CHUNK);
        let got = within(r.read(&mut tmp[..take])).await?;
        if got == 0 {
            return Err(other("connection closed mid-body"));
        }
        limits.acquire_down(got).await;
        out.extend_from_slice(&tmp[..got]);
        n -= got;
    }
    Ok(())
}

/// Result of one background piece fetch, sent back to the engine loop.
pub struct Done {
    pub seed: usize,
    pub piece: u32,
    pub result: Result<Vec<u8>, WsError>,
}

pub fn spawn_fetch(
    jobs: &mut JoinSet<()>,
    meta: std::sync::Arc<Metainfo>,
    base: String,
    seed: usize,
    piece: u32,
    limits: Limits,
    tx: mpsc::UnboundedSender<Done>,
) {
    let allow_local = local_allowed();
    jobs.spawn(async move {
        let result = fetch_piece(&meta, &base, piece, &limits, allow_local).await;
        let _ = tx.send(Done { seed, piece, result });
    });
}

/// Engine-side bookkeeping for one web seed.
pub struct WebSeed {
    pub base: String,
    pub host: String,
    pub busy: bool,
    pub downloaded: u64,
    failures: u32,
    next_try: Instant,
    dead_files: HashSet<usize>,
}

impl WebSeed {
    pub fn new(base: String) -> Self {
        let host = Url::parse(&base)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_else(|| base.clone());
        WebSeed {
            base,
            host,
            busy: false,
            downloaded: 0,
            failures: 0,
            next_try: Instant::now(),
            dead_files: HashSet::new(),
        }
    }

    pub fn ready(&self) -> bool {
        !self.busy && Instant::now() >= self.next_try
    }

    pub fn backing_off(&self) -> bool {
        Instant::now() < self.next_try
    }

    pub fn can_serve(&self, meta: &Metainfo, piece: u32) -> bool {
        self.dead_files.is_empty()
            || piece_segments(meta, piece)
                .iter()
                .all(|s| !self.dead_files.contains(&s.file))
    }

    pub fn mark_file_dead(&mut self, file: usize) {
        self.dead_files.insert(file);
    }

    pub fn succeeded(&mut self, bytes: u64) {
        self.failures = 0;
        self.downloaded += bytes;
    }

    pub fn failed(&mut self) {
        self.failures = self.failures.saturating_add(1);
        self.next_try = Instant::now() + backoff(self.failures);
    }
}

fn backoff(failures: u32) -> Duration {
    BACKOFF_BASE
        .saturating_mul(1u32 << failures.saturating_sub(1).min(10))
        .min(BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metainfo::{FileEntry, InfoHash};
    use std::path::PathBuf;

    fn meta(files: Files, piece_length: u32) -> Metainfo {
        let total = files.total_length();
        Metainfo {
            infohash: InfoHash([0; 20]),
            name: "My Show".into(),
            piece_length,
            pieces: vec![[0; 20]; total.div_ceil(piece_length as u64) as usize],
            files,
            total_length: total,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
            info_bytes: vec![],
        }
    }

    fn multi() -> Metainfo {
        let f = |p: &[&str], length| FileEntry {
            path: p.iter().collect::<PathBuf>(),
            length,
        };
        meta(
            Files::Multi {
                files: vec![
                    f(&["My Show", "a b.bin"], 10),
                    f(&["My Show", "sub", "é.bin"], 20),
                    f(&["My Show", "c.bin"], 5),
                ],
            },
            16,
        )
    }

    #[test]
    fn single_file_urls() {
        let m = meta(Files::Single { name: "x y.iso".into(), length: 40 }, 16);
        assert_eq!(file_url("http://h/f.iso", &m, 0).unwrap(), "http://h/f.iso");
        assert_eq!(file_url("http://h/dir/", &m, 0).unwrap(), "http://h/dir/x%20y.iso");
    }

    #[test]
    fn multi_file_urls_are_encoded() {
        let m = multi();
        assert_eq!(file_url("http://h/pub/", &m, 0).unwrap(), "http://h/pub/My%20Show/a%20b.bin");
        assert_eq!(file_url("http://h/pub", &m, 1).unwrap(), "http://h/pub/My%20Show/sub/%C3%A9.bin");
    }

    #[test]
    fn pieces_split_across_files() {
        let m = multi();
        let seg = |file, offset, len| Segment { file, offset, len };
        assert_eq!(piece_segments(&m, 0), vec![seg(0, 0, 10), seg(1, 0, 6)]);
        assert_eq!(piece_segments(&m, 1), vec![seg(1, 6, 14), seg(2, 0, 2)]);
        assert_eq!(piece_segments(&m, 2), vec![seg(2, 2, 3)]);
    }

    async fn run(resp: &[u8], offset: u64, len: u64, file_len: u64) -> Result<Reply, WsError> {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let resp = resp.to_vec();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = server.read(&mut buf).await;
            let _ = server.write_all(&resp).await;
            let _ = server.shutdown().await;
        });
        exchange(client, "h", "/f", offset, len, file_len, &Limits::default()).await
    }

    fn body(r: Result<Reply, WsError>) -> Vec<u8> {
        match r {
            Ok(Reply::Body(b)) => b,
            Ok(Reply::Redirect(l)) => panic!("redirect {l}"),
            Err(e) => panic!("{e}"),
        }
    }

    #[tokio::test]
    async fn partial_content() {
        let r = run(b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 2-5/10\r\nContent-Length: 4\r\n\r\nabcd", 2, 4, 10).await;
        assert_eq!(body(r), b"abcd");
    }

    #[tokio::test]
    async fn full_200_only_for_whole_file() {
        let ok = run(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd", 0, 4, 4).await;
        assert_eq!(body(ok), b"abcd");
        let bad = run(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd", 0, 2, 4).await;
        assert!(bad.is_err());
    }

    #[tokio::test]
    async fn chunked_body() {
        let r = run(
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-5/9\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n4;x=y\r\ncdef\r\n0\r\n\r\n",
            0, 6, 9,
        )
        .await;
        assert_eq!(body(r), b"abcdef");
    }

    #[tokio::test]
    async fn redirect_and_errors() {
        let r = run(b"HTTP/1.1 302 Found\r\nLocation: /other\r\n\r\n", 0, 4, 4).await;
        assert!(matches!(r, Ok(Reply::Redirect(l)) if l == "/other"));
        assert!(matches!(run(b"HTTP/1.1 404 Not Found\r\n\r\n", 0, 4, 4).await, Err(WsError::Gone(_))));
        let wrong_range = b"HTTP/1.1 206 X\r\nContent-Range: bytes 0-3/10\r\nContent-Length: 4\r\n\r\nabcd";
        assert!(run(wrong_range, 1, 4, 10).await.is_err());
        let short_cl = b"HTTP/1.1 206 X\r\nContent-Range: bytes 0-3/10\r\nContent-Length: 3\r\n\r\nabc";
        assert!(run(short_cl, 0, 4, 10).await.is_err());
        let truncated = b"HTTP/1.1 206 X\r\nContent-Range: bytes 0-3/10\r\nContent-Length: 4\r\n\r\nab";
        assert!(run(truncated, 0, 4, 10).await.is_err());
        let long_chunk = b"HTTP/1.1 206 X\r\nContent-Range: bytes 0-3/10\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabcde\r\n0\r\n\r\n";
        assert!(run(long_chunk, 0, 4, 10).await.is_err());
        assert!(run(b"garbage\r\n\r\n", 0, 4, 4).await.is_err());
    }

    #[test]
    fn address_policy_blocks_local_and_reserved_ranges() {
        for bad in [
            "127.0.0.1", "127.9.9.9", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
            "169.254.169.254", "100.64.0.1", "100.127.255.255", "0.0.0.0", "0.1.2.3", "224.0.0.1",
            "255.255.255.255", "240.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.9", "198.18.0.1",
            "::", "::1", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "2001:db8::1",
            "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:192.168.0.1", "::ffff:169.254.1.1",
            "::ffff:100.64.0.1", "::127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::1", "2002:a00:1::1",
        ] {
            assert!(!address_allowed(bad.parse().unwrap()), "{bad}");
        }
        for ok in ["8.8.8.8", "1.1.1.1", "172.15.0.1", "172.32.0.1", "100.63.0.1", "100.128.0.1", "2606:4700::1", "::ffff:8.8.8.8", "2002:808:808::1"] {
            assert!(address_allowed(ok.parse().unwrap()), "{ok}");
        }
    }

    #[tokio::test]
    async fn get_capped_refuses_local_targets_with_one_message() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        for url in [
            format!("http://127.0.0.1:{port}/x"),
            format!("http://[::1]:{port}/x"),
            format!("http://localhost:{port}/x"),
            "http://10.0.0.1:1/x".to_owned(),
            "http://192.168.0.1:1/x".to_owned(),
            "http://169.254.169.254/x".to_owned(),
            "http://[::ffff:127.0.0.1]:1/x".to_owned(),
            "http://[fd00::1]:1/x".to_owned(),
        ] {
            let err = get_capped(&url, 1024, false).await.unwrap_err();
            assert_eq!(err.to_string(), NOT_ALLOWED, "{url}");
        }
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff(1), Duration::from_secs(30));
        assert_eq!(backoff(2), Duration::from_secs(60));
        assert_eq!(backoff(50), Duration::from_secs(1800));
    }

    #[tokio::test]
    async fn huge_chunk_size_is_rejected() {
        let huge = b"HTTP/1.1 206 X\r\nContent-Range: bytes 0-3/10\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\nFFFFFFFFFFFFFFFF\r\n";
        assert!(run(huge, 0, 4, 10).await.is_err());
    }
}
