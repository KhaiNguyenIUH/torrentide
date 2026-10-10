//! Browser interface: a small hand-rolled HTTP/1.1 server (one request per
//! connection) that publishes [`SessionState`] as JSON and turns POSTs into
//! [`SessionCommand`]s.
//!
//! This is a remote-control surface fed by hostile input, so every request is
//! bounded (header and body caps, per-phase timeouts, a connection cap), the
//! password is checked before any body is read, and state-changing requests
//! must prove they come from this page (Origin/Referer host == Host) to stop
//! cross-site form posts and DNS-rebinding style attacks from a visited page.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use percent_encoding::percent_decode_str;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Semaphore};

use crate::state::{Command, SessionCommand, SessionState, WebUiSettings};

const INDEX_HTML: &str = include_str!("webui/index.html");
const MAX_HEAD: usize = 8 * 1024;
const MAX_BODY: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 64;
const MAX_PER_IP: usize = 6;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const HEAD_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_AUTH_HEADER: usize = 256;
const VERIFY_SLOTS: usize = 2;
const FAILS_BEFORE_BLOCK: u32 = 5;
const FAIL_WINDOW: Duration = Duration::from_secs(60);
const BLOCK_BASE: Duration = Duration::from_secs(15);
const BLOCK_MAX: Duration = Duration::from_secs(15 * 60);
const MAX_TRACKED_IPS: usize = 1024;
const TOKEN_COOKIE: &str = "torrust_token";

/// `script-src 'unsafe-inline'` because the page is one self-contained file;
/// all dynamic content reaches the DOM through `textContent`, never HTML.
const CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
                   connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/// Where to listen: loopback unless a password protects the interface.
pub fn bind_addr(settings: &WebUiSettings) -> SocketAddr {
    let protected = settings.password.as_deref().is_some_and(|p| !p.is_empty());
    let ip = if protected {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    SocketAddr::new(ip, settings.port)
}

/// How a client proves it may use the interface: the configured password
/// (HTTP Basic), or without one an access token the session generated.
pub enum Access {
    Password(String),
    Token(String),
}

#[derive(Default)]
struct Strikes {
    count: u32,
    level: u32,
    window_start: Option<Instant>,
    blocked_until: Option<Instant>,
}

struct Guard {
    access: Access,
    verifying: Semaphore,
    last_good: Mutex<Option<[u8; 20]>>,
    strikes: Mutex<HashMap<IpAddr, Strikes>>,
    conns: Mutex<HashMap<IpAddr, usize>>,
}

struct Conn {
    guard: Arc<Guard>,
    ip: IpAddr,
}

impl Conn {
    fn enter(guard: &Arc<Guard>, ip: IpAddr) -> Option<Conn> {
        let mut conns = guard.conns.lock().unwrap();
        let n = conns.entry(ip).or_insert(0);
        if *n >= MAX_PER_IP {
            return None;
        }
        *n += 1;
        Some(Conn { guard: Arc::clone(guard), ip })
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        let mut conns = self.guard.conns.lock().unwrap();
        if let Some(n) = conns.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                conns.remove(&self.ip);
            }
        }
    }
}

impl Guard {
    fn blocked_for(&self, ip: IpAddr) -> Option<Duration> {
        let now = Instant::now();
        let strikes = self.strikes.lock().unwrap();
        let until = strikes.get(&ip)?.blocked_until?;
        until.checked_duration_since(now).filter(|d| !d.is_zero())
    }

    fn fail(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut strikes = self.strikes.lock().unwrap();
        if strikes.len() >= MAX_TRACKED_IPS {
            strikes.retain(|_, e| e.blocked_until.is_some_and(|u| now < u + BLOCK_MAX));
        }
        let e = strikes.entry(ip).or_default();
        if e.window_start.map_or(true, |w| now.duration_since(w) > FAIL_WINDOW) {
            e.count = 0;
            e.window_start = Some(now);
        }
        e.count += 1;
        if e.count >= FAILS_BEFORE_BLOCK {
            e.count = 0;
            e.level = (e.level + 1).min(10);
            let wait = BLOCK_BASE.saturating_mul(1 << (e.level - 1)).min(BLOCK_MAX);
            e.blocked_until = Some(now + wait);
        }
    }

    fn forgive(&self, ip: IpAddr) {
        self.strikes.lock().unwrap().remove(&ip);
    }

    fn cached(&self, digest: &[u8; 20]) -> bool {
        self.last_good.lock().unwrap().as_ref().is_some_and(|d| ct_eq(d, digest))
    }

    async fn check_password(&self, stored: &str, req: &Request, ip: IpAddr) -> Gate {
        let Some(value) = req.header("authorization") else {
            return Gate::Reply(unauthorized());
        };
        let digest: [u8; 20] = Sha1::digest(value.as_bytes()).into();
        if value.len() <= MAX_AUTH_HEADER && self.cached(&digest) {
            return Gate::Open;
        }
        if let Some(wait) = self.blocked_for(ip) {
            return Gate::Reply(too_many(wait));
        }
        let given = match basic_password(value).filter(|_| value.len() <= MAX_AUTH_HEADER) {
            Some(g) => g,
            None => {
                self.fail(ip);
                return Gate::Reply(unauthorized());
            }
        };
        let _permit = self.verifying.acquire().await;
        let stored = stored.to_owned();
        let ok = tokio::task::spawn_blocking(move || crate::store::verify_password(&stored, &given))
            .await
            .unwrap_or(false);
        if ok {
            *self.last_good.lock().unwrap() = Some(digest);
            self.forgive(ip);
            Gate::Open
        } else {
            self.fail(ip);
            Gate::Reply(unauthorized())
        }
    }
}

enum Gate {
    Open,
    Reply(Vec<u8>),
}

/// Serve the web UI on an already-bound listener until the task is dropped.
pub async fn serve(listener: TcpListener, state: Arc<RwLock<SessionState>>, access: Access) {
    serve_with(listener, state, access, IO_TIMEOUT).await
}

async fn serve_with(
    listener: TcpListener,
    state: Arc<RwLock<SessionState>>,
    access: Access,
    io_timeout: Duration,
) {
    let guard = Arc::new(Guard {
        access,
        verifying: Semaphore::new(VERIFY_SLOTS),
        last_good: Mutex::new(None),
        strikes: Mutex::default(),
        conns: Mutex::default(),
    });
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let Some(conn) = Conn::enter(&guard, peer.ip()) else {
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            handle(stream, peer.ip(), state, &conn.guard, io_timeout).await;
            drop(conn);
            drop(permit);
        });
    }
}

struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

async fn handle(
    mut stream: TcpStream,
    ip: IpAddr,
    state: Arc<RwLock<SessionState>>,
    guard: &Guard,
    io_timeout: Duration,
) {
    let out = respond(&mut stream, ip, &state, guard, io_timeout).await;
    if out.is_empty() {
        return;
    }
    let _ = tokio::time::timeout(io_timeout, async {
        stream.write_all(&out).await?;
        stream.shutdown().await
    })
    .await;
}

/// Returns the full response bytes, or nothing when the peer just went away.
async fn respond(
    stream: &mut TcpStream,
    ip: IpAddr,
    state: &RwLock<SessionState>,
    guard: &Guard,
    io_timeout: Duration,
) -> Vec<u8> {
    let head_timeout = io_timeout.min(HEAD_TIMEOUT);
    let (req, leftover) = match tokio::time::timeout(head_timeout, read_head(stream)).await {
        Ok(Ok(v)) => v,
        Ok(Err(resp)) => return resp,
        Err(_) => return error(408, "request timed out"),
    };
    let gate = match &guard.access {
        Access::Password(pw) => guard.check_password(pw, &req, ip).await,
        Access::Token(token) => token_gate(&req, token),
    };
    if let Gate::Reply(resp) = gate {
        return resp;
    }
    let post = match req.method.as_str() {
        "GET" => false,
        "POST" => true,
        _ => return error(405, "method not allowed"),
    };
    let mut body = Vec::new();
    if post {
        if !same_origin(&req) {
            return error(403, "cross-origin request refused");
        }
        body = match tokio::time::timeout(io_timeout, read_body(stream, &req, leftover)).await {
            Ok(Ok(b)) => b,
            Ok(Err(resp)) => return resp,
            Err(_) => return error(408, "request timed out"),
        };
    }
    route(&req, &body, state).await
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Read up to the blank line ending the headers; `Err` is a ready response
/// (empty means close silently). Returns bytes read past the headers.
async fn read_head(stream: &mut TcpStream) -> Result<(Request, Vec<u8>), Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let end = loop {
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            break p;
        }
        if buf.len() > MAX_HEAD {
            return Err(error(431, "headers too large"));
        }
        let mut chunk = [0u8; 1024];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return Err(Vec::new()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    if end + 4 > MAX_HEAD {
        return Err(error(431, "headers too large"));
    }
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| error(400, "bad request"))?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (method, target) = match (first.next(), first.next(), first.next(), first.next()) {
        (Some(m), Some(t), Some(v), None) if v.starts_with("HTTP/1.") && t.starts_with('/') => {
            (m, t)
        }
        _ => return Err(error(400, "bad request line")),
    };
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| error(400, "bad header"))?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    let req = Request {
        method: method.to_string(),
        target: target.to_string(),
        headers,
    };
    Ok((req, buf[end + 4..].to_vec()))
}

async fn read_body(
    stream: &mut TcpStream,
    req: &Request,
    mut body: Vec<u8>,
) -> Result<Vec<u8>, Vec<u8>> {
    if req.header("transfer-encoding").is_some() {
        return Err(error(400, "chunked bodies are not supported"));
    }
    let len: usize = match req.header("content-length") {
        None => 0,
        Some(v) => v.parse().map_err(|_| error(400, "bad content-length"))?,
    };
    if len > MAX_BODY {
        return Err(error(413, "body too large"));
    }
    while body.len() < len {
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return Err(Vec::new()),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(len);
    Ok(body)
}

pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= (a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0)) as usize;
    }
    diff == 0
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// HTTP Basic; any user name, the password decides.
fn basic_password(value: &str) -> Option<Vec<u8>> {
    let (scheme, cred) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = base64_decode(cred.trim())?;
    Some(match decoded.iter().position(|&b| b == b':') {
        Some(i) => decoded[i + 1..].to_vec(),
        None => decoded,
    })
}

/// Without a password the interface needs the session's access token, as a
/// cookie or a bearer header. `GET /?token=` trades it for the cookie and
/// redirects so it does not stay in the address bar. The loopback Host check
/// stays: a DNS-rebinding page must not reach it under its own name.
fn token_gate(req: &Request, token: &str) -> Gate {
    if !loopback_host(req) {
        return Gate::Reply(error(403, "use http://localhost or 127.0.0.1, or set a password"));
    }
    let (path, query) = req.target.split_once('?').unwrap_or((&req.target, ""));
    if req.method == "GET" && path == "/" {
        let given = query.split('&').find_map(|p| p.strip_prefix("token="));
        if let Some(t) = given {
            return Gate::Reply(if ct_eq(t.as_bytes(), token.as_bytes()) {
                response(
                    303,
                    "text/plain; charset=utf-8",
                    &format!(
                        "Location: /\r\nSet-Cookie: {TOKEN_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/\r\n"
                    ),
                    b"",
                )
            } else {
                token_required()
            });
        }
    }
    let bearer = req
        .header("authorization")
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, t)| t.trim());
    let cookie = req.header("cookie").and_then(|c| {
        c.split(';').find_map(|p| p.trim().strip_prefix(TOKEN_COOKIE)?.strip_prefix('='))
    });
    if [bearer, cookie].into_iter().flatten().any(|t| ct_eq(t.as_bytes(), token.as_bytes())) {
        Gate::Open
    } else {
        Gate::Reply(token_required())
    }
}

fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', '?', '#']).next().unwrap_or("")
}

/// True when the request's Host names this machine's loopback interface.
fn loopback_host(req: &Request) -> bool {
    let Some(host) = req.header("host") else {
        return false;
    };
    let name = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => host.rsplit_once(':').map_or(host, |(h, _)| h),
    };
    name.eq_ignore_ascii_case("localhost") || name == "127.0.0.1" || name == "::1"
}

/// A state-changing request must name its origin and it must be this server.
fn same_origin(req: &Request) -> bool {
    let Some(host) = req.header("host").filter(|h| !h.is_empty()) else {
        return false;
    };
    match req.header("origin").or_else(|| req.header("referer")) {
        Some(o) => host_of(o).eq_ignore_ascii_case(host),
        None => false,
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        303 => "See Other",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        _ => "Service Unavailable",
    }
}

fn response(status: u16, content_type: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n\
         Content-Security-Policy: {CSP}\r\nConnection: close\r\n{extra}\r\n",
        reason(status),
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn json_response(status: u16, body: &str) -> Vec<u8> {
    response(status, "application/json; charset=utf-8", "", body.as_bytes())
}

fn error(status: u16, msg: &str) -> Vec<u8> {
    json_response(status, &format!("{{\"error\":{}}}", json_str(msg)))
}

fn unauthorized() -> Vec<u8> {
    response(
        401,
        "application/json; charset=utf-8",
        "WWW-Authenticate: Basic realm=\"torrust\", charset=\"UTF-8\"\r\n",
        b"{\"error\":\"authentication required\"}",
    )
}

fn token_required() -> Vec<u8> {
    error(401, "access token required: open the URL the session printed at startup")
}

fn too_many(wait: Duration) -> Vec<u8> {
    response(
        429,
        "application/json; charset=utf-8",
        &format!("Retry-After: {}\r\n", wait.as_secs() + 1),
        b"{\"error\":\"too many failed attempts, try again later\"}",
    )
}

fn ok() -> Vec<u8> {
    json_response(200, "{\"ok\":true}")
}

/// A JSON string literal that is pure ASCII: quotes, backslashes, control
/// characters, `<>&` and everything non-ASCII (as UTF-16 escapes) are escaped.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' '..='~' if !matches!(c, '<' | '>' | '&') => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

fn json_num(n: f64) -> String {
    if n.is_finite() {
        format!("{n}")
    } else {
        "null".to_string()
    }
}

fn json_opt(s: Option<&str>) -> String {
    s.map_or_else(|| "null".to_string(), json_str)
}

fn json_strs(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|s| json_str(s)).collect();
    format!("[{}]", parts.join(","))
}

fn state_json(st: &SessionState) -> String {
    let torrents: Vec<String> = st
        .torrents
        .iter()
        .map(|t| {
            let sum = t.ui.torrent.as_ref();
            let name = sum.map_or(t.id.as_str(), |s| s.name.as_str());
            let name = if name.is_empty() { t.id.as_str() } else { name };
            let state = sum.map_or("connecting", |s| s.state.label());
            let queue = t.queue_position.map_or("null".to_string(), |q| q.to_string());
            format!(
                "{{\"id\":{},\"name\":{},\"state\":{},\"progress\":{},\"download_rate\":{},\
                 \"upload_rate\":{},\"eta_secs\":{},\"ratio\":{},\"size\":{},\"downloaded\":{},\
                 \"uploaded\":{},\"label\":{},\"queue_position\":{}}}",
                json_str(&t.id),
                json_str(name),
                json_str(state),
                json_num(sum.map_or(0.0, |s| s.progress)),
                json_num(sum.map_or(0.0, |s| s.download_rate)),
                json_num(sum.map_or(0.0, |s| s.upload_rate)),
                json_num(sum.and_then(|s| s.eta_secs).unwrap_or(f64::NAN)),
                json_num(t.ratio),
                sum.map_or(0, |s| s.total_length),
                sum.map_or(0, |s| s.downloaded),
                t.uploaded,
                json_opt(t.label.as_deref()),
                queue,
            )
        })
        .collect();
    let feeds: Vec<String> = st
        .feeds
        .iter()
        .map(|f| {
            format!(
                "{{\"id\":{},\"url\":{},\"title\":{},\"include\":{},\"exclude\":{},\"dir\":{},\
                 \"last_fetch\":{},\"last_error\":{},\"recent\":{}}}",
                f.id,
                json_str(&f.url),
                json_opt(f.title.as_deref()),
                json_strs(&f.include),
                json_strs(&f.exclude),
                json_opt(f.dir.as_deref().map(|d| d.to_string_lossy()).as_deref()),
                f.last_fetch.map_or("null".to_string(), |v| v.to_string()),
                json_opt(f.last_error.as_deref()),
                json_strs(&f.recent),
            )
        })
        .collect();
    format!(
        "{{\"torrents\":[{}],\"download_rate\":{},\"upload_rate\":{},\"port_status\":{},\
         \"warning\":{},\"feeds\":[{}]}}",
        torrents.join(","),
        json_num(st.download_rate),
        json_num(st.upload_rate),
        json_str(&st.port_status),
        json_opt(st.warning.as_deref()),
        feeds.join(","),
    )
}

fn form(body: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(body);
    let decode = |s: &str| {
        percent_decode_str(&s.replace('+', " "))
            .decode_utf8_lossy()
            .into_owned()
    };
    text.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(p), String::new()),
        })
        .collect()
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

fn split_terms(s: Option<&str>) -> Vec<String> {
    s.unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

fn dispatch(st: &SessionState, cmd: SessionCommand) -> Vec<u8> {
    match &st.command_tx {
        Some(tx) if tx.send(cmd).is_ok() => ok(),
        _ => error(503, "session is not accepting commands"),
    }
}

/// A magnet or http(s) link, as opposed to a path on this machine.
fn is_link(s: &str) -> bool {
    let lower = s.trim_start().to_ascii_lowercase();
    lower.starts_with("magnet:?") || lower.starts_with("http://") || lower.starts_with("https://")
}

async fn route(req: &Request, body: &[u8], state: &RwLock<SessionState>) -> Vec<u8> {
    let path = req.target.split(['?', '#']).next().unwrap_or("/");
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match (req.method.as_str(), segments.as_slice()) {
        ("GET", [""] | ["index.html"]) => {
            response(200, "text/html; charset=utf-8", "", INDEX_HTML.as_bytes())
        }
        ("GET", ["api", "state"]) => json_response(200, &state_json(&*state.read().await)),
        ("POST", ["api", "add"]) => {
            let f = form(body);
            let Some(source) = field(&f, "source") else {
                return error(400, "source is required");
            };
            // Safe first: a remote browser may not name files or folders on
            // this machine, only links. Paths and save folders stay a
            // terminal-only feature.
            if !is_link(source) {
                return error(400, "only magnet: and http(s):// links can be added here");
            }
            if field(&f, "dir").is_some() {
                return error(400, "the save folder can only be set from the terminal");
            }
            let cmd = SessionCommand::Add {
                source: source.to_string(),
                dir: None,
            };
            dispatch(&*state.read().await, cmd)
        }
        ("POST", ["api", "feeds"]) => {
            let f = form(body);
            let Some(url) = field(&f, "url") else {
                return error(400, "url is required");
            };
            if !is_link(url) || url.starts_with("magnet:") {
                return error(400, "feed url must be http(s)://");
            }
            if field(&f, "dir").is_some() {
                return error(400, "the save folder can only be set from the terminal");
            }
            let cmd = SessionCommand::AddFeed {
                url: url.to_string(),
                include: split_terms(field(&f, "include")),
                exclude: split_terms(field(&f, "exclude")),
                dir: None,
            };
            dispatch(&*state.read().await, cmd)
        }
        ("POST", ["api", "feeds", id, "remove"]) => {
            let st = state.read().await;
            match id.parse::<u64>() {
                Ok(id) if st.feeds.iter().any(|f| f.id == id) => {
                    dispatch(&st, SessionCommand::RemoveFeed(id))
                }
                _ => error(404, "unknown feed"),
            }
        }
        ("POST", ["api", "torrents", id, action]) => {
            let st = state.read().await;
            if !st.torrents.iter().any(|t| t.id == *id) {
                return error(404, "unknown torrent");
            }
            let id = id.to_string();
            let cmd = match *action {
                "start" => SessionCommand::Start(id),
                "stop" => SessionCommand::Stop(id),
                "pause" => SessionCommand::Torrent(id, Command::Pause),
                "resume" => SessionCommand::Torrent(id, Command::Resume),
                "recheck" => SessionCommand::Torrent(id, Command::Recheck),
                "remove" => SessionCommand::Remove { id, delete_data: false },
                "remove-data" => SessionCommand::Remove { id, delete_data: true },
                _ => return error(404, "unknown action"),
            };
            dispatch(&st, cmd)
        }
        _ => error(404, "not found"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{DownloadState, FeedView, TorrentSummary, TorrentView, UiState};
    use tokio::sync::mpsc;

    const ID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NASTY: &str = "q\"uote \\ back\nline\ttab \u{1} é日本 😀 <b>&";

    fn view(id: &str, name: &str, label: Option<&str>) -> TorrentView {
        TorrentView {
            id: id.to_string(),
            ui: UiState {
                torrent: Some(TorrentSummary {
                    name: name.to_string(),
                    infohash: id.to_string(),
                    total_length: 1000,
                    downloaded: 500,
                    progress: 0.5,
                    download_rate: 12.5,
                    upload_rate: 3.0,
                    eta_secs: Some(40.0),
                    state: DownloadState::Downloading,
                    ..Default::default()
                }),
                ..Default::default()
            },
            uploaded: 250,
            ratio: 0.25,
            download_limit: 0,
            upload_limit: 0,
            added_at: 0,
            queue_position: Some(0),
            label: label.map(String::from),
        }
    }

    fn fake_state(with_tx: bool) -> (Arc<RwLock<SessionState>>, mpsc::UnboundedReceiver<SessionCommand>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let st = SessionState {
            torrents: vec![view(ID_A, NASTY, Some("linux")), view(ID_B, "plain", None)],
            feeds: vec![FeedView {
                id: 7,
                url: "http://example.com/rss".into(),
                title: Some("Feed".into()),
                include: vec!["x".into()],
                exclude: vec![],
                dir: None,
                last_fetch: Some(5),
                last_error: None,
                recent: vec![],
            }],
            command_tx: with_tx.then_some(tx),
            ..Default::default()
        };
        (Arc::new(RwLock::new(st)), rx)
    }

    const COOKIE: &str = "Cookie: torrust_token=tok123\r\n";

    async fn start(
        state: Arc<RwLock<SessionState>>,
        access: Access,
        io_timeout: Duration,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_with(listener, state, access, io_timeout));
        addr
    }

    async fn start_open(state: Arc<RwLock<SessionState>>, io_timeout: Duration) -> SocketAddr {
        start(state, Access::Token("tok123".into()), io_timeout).await
    }

    async fn raw(addr: SocketAddr, request: &[u8]) -> (u16, String, String) {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let _ = s.write_all(request).await;
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        let text = String::from_utf8_lossy(&buf).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, head.to_string(), body.to_string())
    }

    fn get(addr: SocketAddr, path: &str, extra: &str) -> Vec<u8> {
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{extra}\r\n").into_bytes()
    }

    fn post(addr: SocketAddr, path: &str, body: &str, extra: &str) -> Vec<u8> {
        format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n{extra}\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn assert_valid_json(s: &str) {
        let (mut depth, mut in_str, mut esc) = (0i32, false, false);
        for c in s.chars() {
            assert!(c.is_ascii() && (c as u32 >= 0x20), "raw control/non-ascii {c:?}");
            if in_str {
                match (esc, c) {
                    (true, _) => esc = false,
                    (false, '\\') => esc = true,
                    (false, '"') => in_str = false,
                    _ => {}
                }
            } else {
                match c {
                    '"' => in_str = true,
                    '{' | '[' => depth += 1,
                    '}' | ']' => depth -= 1,
                    _ => {}
                }
                assert!(depth >= 0);
            }
        }
        assert!(!in_str && depth == 0 && !esc);
    }

    #[test]
    fn json_escaping_is_ascii_safe() {
        let j = json_str(NASTY);
        assert_valid_json(&j);
        assert_eq!(
            j,
            "\"q\\\"uote \\\\ back\\nline\\ttab \\u0001 \\u00e9\\u65e5\\u672c \\ud83d\\ude00 \\u003cb\\u003e\\u0026\""
        );
        assert_eq!(json_num(f64::NAN), "null");
        assert_eq!(base64_decode("dTpwdw==").unwrap(), b"u:pw");
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"abc", b"abcd"));
    }

    #[tokio::test]
    async fn serves_page_and_state() {
        let (state, _rx) = fake_state(true);
        let addr = start_open(state, IO_TIMEOUT).await;

        let (status, head, body) = raw(addr, &get(addr, "/", COOKIE)).await;
        assert_eq!(status, 200);
        assert!(body.contains("<title>torrust</title>"));
        let lower = head.to_ascii_lowercase();
        assert!(lower.contains("cache-control: no-store"));
        assert!(lower.contains("x-content-type-options: nosniff"));
        assert!(lower.contains("x-frame-options: deny"));
        assert!(lower.contains("content-security-policy: default-src 'none'"));

        let (status, head, body) = raw(addr, &get(addr, "/api/state", COOKIE)).await;
        assert_eq!(status, 200);
        assert!(head.contains("application/json"));
        assert_valid_json(&body);
        assert!(body.contains(&format!("\"id\":\"{ID_A}\"")));
        assert!(body.contains(&format!("\"name\":{}", json_str(NASTY))));
        assert!(body.contains("\"state\":\"downloading\""));
        assert!(body.contains("\"label\":\"linux\""));
        assert!(body.contains("\"label\":null"));
        assert!(body.contains("\"ratio\":0.25"));
        assert!(body.contains("\"queue_position\":0"));
        assert!(body.contains("\"feeds\":[{\"id\":7"));
        assert!(body.contains("\"download_rate\":0"));

        assert_eq!(raw(addr, &get(addr, "/nope", COOKIE)).await.0, 404);
        assert_eq!(raw(addr, b"DELETE / HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: torrust_token=tok123\r\n\r\n").await.0, 405);
    }

    #[tokio::test]
    async fn posts_become_commands() {
        let (state, mut rx) = fake_state(true);
        let addr = start_open(state, IO_TIMEOUT).await;
        let id = ID_A.to_string();

        let cases: Vec<(String, String, SessionCommand)> = vec![
            ("start", Some(SessionCommand::Start(id.clone()))),
            ("stop", Some(SessionCommand::Stop(id.clone()))),
            ("pause", Some(SessionCommand::Torrent(id.clone(), Command::Pause))),
            ("resume", Some(SessionCommand::Torrent(id.clone(), Command::Resume))),
            ("recheck", Some(SessionCommand::Torrent(id.clone(), Command::Recheck))),
            ("remove", Some(SessionCommand::Remove { id: id.clone(), delete_data: false })),
            ("remove-data", Some(SessionCommand::Remove { id: id.clone(), delete_data: true })),
        ]
        .into_iter()
        .map(|(a, c)| (format!("/api/torrents/{ID_A}/{a}"), String::new(), c.unwrap()))
        .chain([
            (
                "/api/add".to_string(),
                "source=magnet%3A%3Fxt%3Durn%3Abtih%3Aabc+d".to_string(),
                SessionCommand::Add {
                    source: "magnet:?xt=urn:btih:abc d".into(),
                    dir: None,
                },
            ),
            (
                "/api/feeds".to_string(),
                "url=http%3A%2F%2Fa%2Frss&include=one%2C+two%2C&exclude=bad".to_string(),
                SessionCommand::AddFeed {
                    url: "http://a/rss".into(),
                    include: vec!["one".into(), "two".into()],
                    exclude: vec!["bad".into()],
                    dir: None,
                },
            ),
            ("/api/feeds/7/remove".to_string(), String::new(), SessionCommand::RemoveFeed(7)),
        ])
        .collect();

        for (path, body, want) in cases {
            let (status, _, _) = raw(addr, &post(addr, &path, &body, COOKIE)).await;
            assert_eq!(status, 200, "{path}");
            assert_eq!(rx.try_recv().unwrap(), want, "{path}");
        }

        let (status, _, _) = raw(addr, &post(addr, "/api/torrents/deadbeef/start", "", COOKIE)).await;
        assert_eq!(status, 404);
        let (status, _, _) = raw(addr, &post(addr, "/api/feeds/99/remove", "", COOKIE)).await;
        assert_eq!(status, 404);
        let (status, _, _) = raw(addr, &post(addr, &format!("/api/torrents/{ID_A}/explode"), "", COOKIE)).await;
        assert_eq!(status, 404);
        for bad in [
            "dir=x",
            "source=%2Fetc%2Fpasswd",
            "source=file%3A%2F%2F%2Fetc%2Fpasswd",
            "source=magnet%3A%3Fxt%3Dx&dir=%2Ftmp",
        ] {
            let (status, _, _) = raw(addr, &post(addr, "/api/add", bad, COOKIE)).await;
            assert_eq!(status, 400, "{bad}");
        }
        for bad in ["url=%2Fetc%2Fpasswd", "url=http%3A%2F%2Fa&dir=%2Ftmp"] {
            let (status, _, _) = raw(addr, &post(addr, "/api/feeds", bad, COOKIE)).await;
            assert_eq!(status, 400, "{bad}");
        }
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn missing_command_channel_is_503() {
        let (state, _rx) = fake_state(false);
        let addr = start_open(state, IO_TIMEOUT).await;
        let (status, _, _) = raw(addr, &post(addr, &format!("/api/torrents/{ID_A}/stop"), "", COOKIE)).await;
        assert_eq!(status, 503);
    }

    #[tokio::test]
    async fn password_is_required_on_every_request() {
        let (state, mut rx) = fake_state(true);
        let addr = start(state, Access::Password("s3cret".into()), IO_TIMEOUT).await;
        let good = "Authorization: Basic YWRtaW46czNjcmV0\r\n";
        let bad = "Authorization: Basic YWRtaW46d3Jvbmc=\r\n";

        for path in ["/", "/api/state"] {
            let (status, head, _) = raw(addr, &get(addr, path, "")).await;
            assert_eq!(status, 401);
            assert!(head.contains("WWW-Authenticate: Basic"));
            assert_eq!(raw(addr, &get(addr, path, bad)).await.0, 401);
            assert_eq!(raw(addr, &get(addr, path, good)).await.0, 200);
        }
        let (status, _, _) = raw(addr, &post(addr, "/api/feeds/7/remove", "", "")).await;
        assert_eq!(status, 401);
        assert!(rx.try_recv().is_err());
        let (status, _, _) = raw(addr, &post(addr, "/api/feeds/7/remove", "", good)).await;
        assert_eq!(status, 200);
        assert_eq!(rx.try_recv().unwrap(), SessionCommand::RemoveFeed(7));
    }

    #[test]
    fn bind_addr_is_loopback_without_password() {
        let mut s = WebUiSettings { enabled: true, port: 9000, password: None };
        assert_eq!(bind_addr(&s), "127.0.0.1:9000".parse().unwrap());
        s.password = Some(String::new());
        assert!(bind_addr(&s).ip().is_loopback());
        s.password = Some("pw".into());
        assert_eq!(bind_addr(&s), "0.0.0.0:9000".parse().unwrap());
    }

    #[tokio::test]
    async fn cross_origin_posts_are_refused() {
        let (state, mut rx) = fake_state(true);
        let addr = start_open(state, IO_TIMEOUT).await;
        let path = "/api/feeds/7/remove";

        let evil = format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nCookie: torrust_token=tok123\r\nOrigin: http://evil.example\r\nContent-Length: 0\r\n\r\n"
        );
        assert_eq!(raw(addr, evil.as_bytes()).await.0, 403);
        let none = format!("POST {path} HTTP/1.1\r\nHost: {addr}\r\nCookie: torrust_token=tok123\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(raw(addr, none.as_bytes()).await.0, 403);
        let referer = format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nCookie: torrust_token=tok123\r\nReferer: http://{addr}/\r\nContent-Length: 0\r\n\r\n"
        );
        assert_eq!(raw(addr, referer.as_bytes()).await.0, 200);
        assert_eq!(rx.try_recv().unwrap(), SessionCommand::RemoveFeed(7));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn oversized_requests_are_rejected() {
        let (state, _rx) = fake_state(true);
        let addr = start_open(state, IO_TIMEOUT).await;

        let big = format!("X-Pad: {}\r\n", "a".repeat(MAX_HEAD + 100));
        assert_eq!(raw(addr, &get(addr, "/", &big)).await.0, 431);

        let req = format!(
            "POST /api/add HTTP/1.1\r\nHost: {addr}\r\nCookie: torrust_token=tok123\r\nOrigin: http://{addr}\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert_eq!(raw(addr, req.as_bytes()).await.0, 413);
    }

    #[tokio::test]
    async fn slow_clients_time_out() {
        let (state, _rx) = fake_state(true);
        let addr = start_open(state, Duration::from_millis(200)).await;

        let (status, _, _) = raw(addr, b"GET / HTTP/1.1\r\nHost: x\r\n").await;
        assert_eq!(status, 408);

        let req = format!(
            "POST /api/add HTTP/1.1\r\nHost: {addr}\r\nCookie: torrust_token=tok123\r\nOrigin: http://{addr}\r\nContent-Length: 50\r\n\r\nsource=x"
        );
        assert_eq!(raw(addr, req.as_bytes()).await.0, 408);
    }

    #[test]
    fn loopback_host_rejects_rebinding_names() {
        let req = |host: &str| Request {
            method: "GET".into(),
            target: "/".into(),
            headers: vec![("host".into(), host.into())],
        };
        for ok in ["localhost:8080", "127.0.0.1:8080", "[::1]:8080", "LOCALHOST", "127.0.0.1"] {
            assert!(loopback_host(&req(ok)), "{ok}");
        }
        for bad in ["evil.example:8080", "127.0.0.1.evil.example", "localhost.evil:80", ""] {
            assert!(!loopback_host(&req(bad)), "{bad}");
        }
    }

    fn auth_basic(password: &str) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let data = format!("u:{password}").into_bytes();
        let mut out = String::new();
        for c in data.chunks(3) {
            let n = c.iter().fold(0u32, |a, b| a << 8 | *b as u32) << (8 * (3 - c.len()));
            for i in 0..=c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
            out.extend(std::iter::repeat('=').take(3 - c.len()));
        }
        format!("Authorization: Basic {out}\r\n")
    }

    async fn hashed_server() -> (SocketAddr, Duration) {
        let (state, _rx) = fake_state(true);
        let stored = crate::store::hash_password("s3cret");
        let t = Instant::now();
        assert!(!crate::store::verify_password(&stored, b"wrong"));
        let hash_time = t.elapsed();
        (start(state, Access::Password(stored), IO_TIMEOUT).await, hash_time)
    }

    #[tokio::test]
    async fn long_credentials_are_rejected_without_hashing() {
        let (addr, hash_time) = hashed_server().await;
        let long = auth_basic(&"x".repeat(3000));
        let t = Instant::now();
        assert_eq!(raw(addr, &get(addr, "/api/state", &long)).await.0, 401);
        assert!(t.elapsed() < hash_time / 2, "{:?} vs {:?}", t.elapsed(), hash_time);
        assert_eq!(raw(addr, &get(addr, "/api/state", &auth_basic("s3cret"))).await.0, 200);
    }

    #[tokio::test]
    async fn password_checks_do_not_block_the_runtime() {
        let (addr, hash_time) = hashed_server().await;
        let ticker = tokio::spawn(async move {
            let mut worst = Duration::ZERO;
            let mut last = Instant::now();
            for _ in 0..(hash_time.as_millis() as u64 * 4 / 5 + 50) {
                tokio::time::sleep(Duration::from_millis(5)).await;
                worst = worst.max(last.elapsed());
                last = Instant::now();
            }
            worst
        });
        let floods: Vec<_> = (0..4)
            .map(|i| {
                let req = get(addr, "/api/state", &auth_basic(&format!("wrong{i}")));
                tokio::spawn(async move { raw(addr, &req).await.0 })
            })
            .collect();
        for f in floods {
            assert_eq!(f.await.unwrap(), 401);
        }
        let worst = ticker.await.unwrap();
        assert!(worst < hash_time / 2 + Duration::from_millis(100), "timer stalled {worst:?}, one hash {hash_time:?}");
    }

    #[tokio::test]
    async fn repeated_failures_earn_a_429_without_hashing() {
        let (addr, hash_time) = hashed_server().await;
        for i in 0..FAILS_BEFORE_BLOCK {
            assert_eq!(raw(addr, &get(addr, "/api/state", &auth_basic(&format!("no{i}")))).await.0, 401);
        }
        let t = Instant::now();
        let (status, head, _) = raw(addr, &get(addr, "/api/state", &auth_basic("s3cret"))).await;
        assert_eq!(status, 429);
        assert!(head.contains("Retry-After: "));
        assert!(t.elapsed() < hash_time / 2);
        assert_eq!(raw(addr, &get(addr, "/api/state", "")).await.0, 401);
    }

    #[test]
    fn block_windows_grow_and_are_capped() {
        let guard = Guard {
            access: Access::Token(String::new()),
            verifying: Semaphore::new(1),
            last_good: Mutex::new(None),
            strikes: Mutex::default(),
            conns: Mutex::default(),
        };
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(guard.blocked_for(ip).is_none());
        let mut last = Duration::ZERO;
        for round in 0..12 {
            for _ in 0..FAILS_BEFORE_BLOCK {
                guard.fail(ip);
            }
            let wait = guard.blocked_for(ip).expect("blocked");
            assert!(wait <= BLOCK_MAX);
            assert!(round == 0 || wait + Duration::from_secs(1) >= last.min(BLOCK_MAX) || last >= BLOCK_MAX);
            last = wait;
        }
        assert!(last > BLOCK_MAX - Duration::from_secs(5));
        assert!(guard.blocked_for(other).is_none());
        guard.forgive(ip);
        assert!(guard.blocked_for(ip).is_none());
    }

    #[tokio::test]
    async fn the_good_password_is_cached_after_one_derivation() {
        let (addr, hash_time) = hashed_server().await;
        let good = auth_basic("s3cret");
        assert_eq!(raw(addr, &get(addr, "/api/state", &good)).await.0, 200);
        let t = Instant::now();
        for _ in 0..5 {
            assert_eq!(raw(addr, &get(addr, "/api/state", &good)).await.0, 200);
        }
        assert!(t.elapsed() < hash_time * 2, "{:?} vs {:?}", t.elapsed(), hash_time);
        assert_eq!(raw(addr, &get(addr, "/api/state", &auth_basic("s3creT"))).await.0, 401);
    }

    #[tokio::test]
    async fn idle_sockets_cannot_lock_out_a_client() {
        let (state, _rx) = fake_state(true);
        let addr = start_open(state, IO_TIMEOUT).await;
        let mut idle = Vec::new();
        for _ in 0..40 {
            idle.push(TcpStream::connect(addr).await.unwrap());
        }
        let started = Instant::now();
        let status = loop {
            let status = raw(addr, &get(addr, "/api/state", COOKIE)).await.0;
            if status == 200 || started.elapsed() > Duration::from_secs(5) {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(status, 200);
        assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
        drop(idle);
    }

    #[tokio::test]
    async fn the_head_must_arrive_within_two_seconds() {
        let (state, _rx) = fake_state(true);
        let addr = start_open(state, IO_TIMEOUT).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        let t = Instant::now();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out).await;
        assert!(String::from_utf8_lossy(&out).contains("408"));
        assert!(t.elapsed() < Duration::from_millis(3500), "{:?}", t.elapsed());
    }

    #[tokio::test]
    async fn without_a_password_the_token_is_required() {
        let (state, mut rx) = fake_state(true);
        let addr = start_open(state, IO_TIMEOUT).await;

        for path in ["/", "/api/state"] {
            assert_eq!(raw(addr, &get(addr, path, "")).await.0, 401, "{path}");
            assert_eq!(raw(addr, &get(addr, path, "Cookie: torrust_token=nope\r\n")).await.0, 401);
            assert_eq!(raw(addr, &get(addr, path, "Authorization: Bearer nope\r\n")).await.0, 401);
        }
        assert_eq!(raw(addr, &get(addr, "/?token=nope", "")).await.0, 401);
        assert_eq!(raw(addr, &post(addr, "/api/feeds/7/remove", "", "")).await.0, 401);
        assert!(rx.try_recv().is_err());

        let (status, head, _) = raw(addr, &get(addr, "/?token=tok123", "")).await;
        assert_eq!(status, 303);
        assert!(head.contains("Location: /\r\n"));
        let cookie = head.lines().find(|l| l.starts_with("Set-Cookie: ")).unwrap();
        assert_eq!(cookie, "Set-Cookie: torrust_token=tok123; HttpOnly; SameSite=Strict; Path=/");

        assert_eq!(raw(addr, &get(addr, "/", COOKIE)).await.0, 200);
        assert_eq!(raw(addr, &get(addr, "/api/state", "Cookie: a=b; torrust_token=tok123\r\n")).await.0, 200);
        assert_eq!(raw(addr, &get(addr, "/api/state", "Authorization: Bearer tok123\r\n")).await.0, 200);
        assert_eq!(raw(addr, &post(addr, "/api/feeds/7/remove", "", COOKIE)).await.0, 200);
        assert_eq!(rx.try_recv().unwrap(), SessionCommand::RemoveFeed(7));

        let rebound = "GET /api/state HTTP/1.1\r\nHost: evil.example\r\nCookie: torrust_token=tok123\r\n\r\n";
        assert_eq!(raw(addr, rebound.as_bytes()).await.0, 403);
        let rebound = "GET /?token=tok123 HTTP/1.1\r\nHost: evil.example\r\n\r\n";
        assert_eq!(raw(addr, rebound.as_bytes()).await.0, 403);
    }
}
