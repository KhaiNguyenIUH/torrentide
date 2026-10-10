//! Browser interface: a small hand-rolled HTTP/1.1 server (one request per
//! connection) that publishes [`SessionState`] as JSON and turns POSTs into
//! [`SessionCommand`]s.
//!
//! This is a remote-control surface fed by hostile input, so every request is
//! bounded (header and body caps, per-phase timeouts, a connection cap), the
//! password is checked before any body is read, and state-changing requests
//! must prove they come from this page (Origin/Referer host == Host) to stop
//! cross-site form posts and DNS-rebinding style attacks from a visited page.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use percent_encoding::percent_decode_str;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Semaphore};

use crate::state::{Command, SessionCommand, SessionState, WebUiSettings};

const INDEX_HTML: &str = include_str!("webui/index.html");
const MAX_HEAD: usize = 8 * 1024;
const MAX_BODY: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Serve the web UI on an already-bound listener until the task is dropped.
pub async fn serve(
    listener: TcpListener,
    state: Arc<RwLock<SessionState>>,
    password: Option<String>,
) {
    serve_with(listener, state, password, IO_TIMEOUT).await
}

async fn serve_with(
    listener: TcpListener,
    state: Arc<RwLock<SessionState>>,
    password: Option<String>,
    io_timeout: Duration,
) {
    let password: Option<Arc<str>> = password.filter(|p| !p.is_empty()).map(Arc::from);
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let state = state.clone();
        let password = password.clone();
        tokio::spawn(async move {
            handle(stream, state, password.as_deref(), io_timeout).await;
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
    state: Arc<RwLock<SessionState>>,
    password: Option<&str>,
    io_timeout: Duration,
) {
    let out = respond(&mut stream, &state, password, io_timeout).await;
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
    state: &RwLock<SessionState>,
    password: Option<&str>,
    io_timeout: Duration,
) -> Vec<u8> {
    let (req, leftover) = match tokio::time::timeout(io_timeout, read_head(stream)).await {
        Ok(Ok(v)) => v,
        Ok(Err(resp)) => return resp,
        Err(_) => return error(408, "request timed out"),
    };
    match password {
        Some(pw) => {
            if !authorized(&req, pw) {
                return unauthorized();
            }
        }
        // Without a password the only protection is the loopback bind. A
        // DNS-rebinding page reaches 127.0.0.1 under its own host name, and
        // its Origin then matches Host, so the Host itself must be loopback.
        None => {
            if !loopback_host(&req) {
                return error(403, "use http://localhost or 127.0.0.1, or set a password");
            }
        }
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
fn authorized(req: &Request, password: &str) -> bool {
    let Some(value) = req.header("authorization") else {
        return false;
    };
    let Some((scheme, cred)) = value.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return false;
    }
    let Some(decoded) = base64_decode(cred.trim()) else {
        return false;
    };
    let given = match decoded.iter().position(|&b| b == b':') {
        Some(i) => &decoded[i + 1..],
        None => &decoded[..],
    };
    crate::store::verify_password(password, given)
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
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        _ => "Service Unavailable",
    }
}

fn response(status: u16, content_type: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n\
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

    async fn start(
        state: Arc<RwLock<SessionState>>,
        password: Option<&str>,
        io_timeout: Duration,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let password = password.map(String::from);
        tokio::spawn(serve_with(listener, state, password, io_timeout));
        addr
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
        let addr = start(state, None, IO_TIMEOUT).await;

        let (status, head, body) = raw(addr, &get(addr, "/", "")).await;
        assert_eq!(status, 200);
        assert!(body.contains("<title>torrust</title>"));
        let lower = head.to_ascii_lowercase();
        assert!(lower.contains("cache-control: no-store"));
        assert!(lower.contains("x-content-type-options: nosniff"));
        assert!(lower.contains("x-frame-options: deny"));
        assert!(lower.contains("content-security-policy: default-src 'none'"));

        let (status, head, body) = raw(addr, &get(addr, "/api/state", "")).await;
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

        assert_eq!(raw(addr, &get(addr, "/nope", "")).await.0, 404);
        assert_eq!(raw(addr, b"DELETE / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").await.0, 405);
    }

    #[tokio::test]
    async fn posts_become_commands() {
        let (state, mut rx) = fake_state(true);
        let addr = start(state, None, IO_TIMEOUT).await;
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
            let (status, _, _) = raw(addr, &post(addr, &path, &body, "")).await;
            assert_eq!(status, 200, "{path}");
            assert_eq!(rx.try_recv().unwrap(), want, "{path}");
        }

        let (status, _, _) = raw(addr, &post(addr, "/api/torrents/deadbeef/start", "", "")).await;
        assert_eq!(status, 404);
        let (status, _, _) = raw(addr, &post(addr, "/api/feeds/99/remove", "", "")).await;
        assert_eq!(status, 404);
        let (status, _, _) = raw(addr, &post(addr, &format!("/api/torrents/{ID_A}/explode"), "", "")).await;
        assert_eq!(status, 404);
        for bad in [
            "dir=x",
            "source=%2Fetc%2Fpasswd",
            "source=file%3A%2F%2F%2Fetc%2Fpasswd",
            "source=magnet%3A%3Fxt%3Dx&dir=%2Ftmp",
        ] {
            let (status, _, _) = raw(addr, &post(addr, "/api/add", bad, "")).await;
            assert_eq!(status, 400, "{bad}");
        }
        for bad in ["url=%2Fetc%2Fpasswd", "url=http%3A%2F%2Fa&dir=%2Ftmp"] {
            let (status, _, _) = raw(addr, &post(addr, "/api/feeds", bad, "")).await;
            assert_eq!(status, 400, "{bad}");
        }
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn missing_command_channel_is_503() {
        let (state, _rx) = fake_state(false);
        let addr = start(state, None, IO_TIMEOUT).await;
        let (status, _, _) = raw(addr, &post(addr, &format!("/api/torrents/{ID_A}/stop"), "", "")).await;
        assert_eq!(status, 503);
    }

    #[tokio::test]
    async fn password_is_required_on_every_request() {
        let (state, mut rx) = fake_state(true);
        let addr = start(state, Some("s3cret"), IO_TIMEOUT).await;
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
        let addr = start(state, None, IO_TIMEOUT).await;
        let path = "/api/feeds/7/remove";

        let evil = format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://evil.example\r\nContent-Length: 0\r\n\r\n"
        );
        assert_eq!(raw(addr, evil.as_bytes()).await.0, 403);
        let none = format!("POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(raw(addr, none.as_bytes()).await.0, 403);
        let referer = format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nReferer: http://{addr}/\r\nContent-Length: 0\r\n\r\n"
        );
        assert_eq!(raw(addr, referer.as_bytes()).await.0, 200);
        assert_eq!(rx.try_recv().unwrap(), SessionCommand::RemoveFeed(7));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn oversized_requests_are_rejected() {
        let (state, _rx) = fake_state(true);
        let addr = start(state, None, IO_TIMEOUT).await;

        let big = format!("X-Pad: {}\r\n", "a".repeat(MAX_HEAD + 100));
        assert_eq!(raw(addr, &get(addr, "/", &big)).await.0, 431);

        let req = format!(
            "POST /api/add HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert_eq!(raw(addr, req.as_bytes()).await.0, 413);
    }

    #[tokio::test]
    async fn slow_clients_time_out() {
        let (state, _rx) = fake_state(true);
        let addr = start(state, None, Duration::from_millis(200)).await;

        let (status, _, _) = raw(addr, b"GET / HTTP/1.1\r\nHost: x\r\n").await;
        assert_eq!(status, 408);

        let req = format!(
            "POST /api/add HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Length: 50\r\n\r\nsource=x"
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
}
