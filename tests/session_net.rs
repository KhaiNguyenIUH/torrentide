use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use torrust::bencode::{encode, Value};
use torrust::session::{Session, SessionHandle};
use torrust::state::{SessionCommand, SessionState, Settings, WebUiSettings};
use torrust::storage::sha1_bytes;
use torrust::store::Store;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tsn-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn settings(dir: &std::path::Path) -> Settings {
    Settings {
        download_dir: dir.to_path_buf(),
        listen_port: 0,
        dht: false,
        port_forwarding: false,
        lsd: false,
        notifications: false,
        ..Settings::default()
    }
}

fn torrent(name: &str) -> Vec<u8> {
    let info = Value::Dict(BTreeMap::from([
        (b"name".to_vec(), Value::Bytes(name.as_bytes().to_vec())),
        (b"length".to_vec(), Value::Int(16)),
        (b"piece length".to_vec(), Value::Int(16384)),
        (b"pieces".to_vec(), Value::Bytes(sha1_bytes(name.as_bytes()).to_vec())),
    ]));
    encode(&Value::Dict(BTreeMap::from([
        (b"announce".to_vec(), Value::Bytes(b"http://127.0.0.1:1/announce".to_vec())),
        (b"info".to_vec(), info),
    ])))
}

type Routes = Arc<Mutex<HashMap<String, Vec<u8>>>>;

async fn http_server() -> (SocketAddr, Routes) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let routes: Routes = Arc::default();
    let shared = Arc::clone(&routes);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let routes = Arc::clone(&shared);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let path = head.split_whitespace().nth(1).unwrap_or("/").split('?').next().unwrap_or("/").to_owned();
                let body = routes.lock().unwrap().get(&path).cloned();
                let out = match body {
                    Some(b) => {
                        let mut v = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len()).into_bytes();
                        v.extend(b);
                        v
                    }
                    None => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
                };
                let _ = s.write_all(&out).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (addr, routes)
}

async fn wait_for(h: &SessionHandle, what: &str, pred: impl Fn(&SessionState) -> bool) {
    let state = h.state();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        {
            let st = state.read().await;
            if pred(&st) {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                let log: Vec<_> = st.log.iter().map(|l| l.message.clone()).collect();
                panic!("timed out waiting for {what}; log={log:#?}");
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn logged(st: &SessionState, needle: &str) -> usize {
    st.log.iter().filter(|l| l.message.contains(needle)).count()
}

async fn quit(h: SessionHandle) {
    h.command().send(SessionCommand::Quit).unwrap();
    h.wait().await.unwrap();
}

#[tokio::test]
async fn add_from_http_url() {
    let (addr, routes) = http_server().await;
    routes.lock().unwrap().insert("/a.torrent".into(), torrent("alpha"));
    routes.lock().unwrap().insert("/garbage".into(), b"not a torrent at all".to_vec());
    routes.lock().unwrap().insert("/huge".into(), vec![b'x'; 10 * 1024 * 1024 + 1024]);
    let dl = temp_dir("dl");
    let h = Session::start_in(Store::at(temp_dir("home")), settings(&dl)).await.unwrap();
    let add = |p: &str| {
        h.command().send(SessionCommand::Add { source: format!("http://{addr}{p}?token=secret"), dir: None }).unwrap();
    };
    add("/garbage");
    add("/huge");
    add("/missing");
    add("/a.torrent");
    wait_for(&h, "torrent from url", |st| st.torrents.len() == 1).await;
    wait_for(&h, "three errors", |st| logged(st, "cannot add") == 3).await;
    let st = h.state();
    let st = st.read().await;
    assert!(st.log.iter().all(|l| !l.message.contains("secret")), "query leaked into the log");
    assert_eq!(st.torrents.len(), 1);
    drop(st);
    quit(h).await;
}

fn feed_xml(items: &[(&str, &str)], addr: SocketAddr) -> Vec<u8> {
    let items: String = items
        .iter()
        .map(|(title, file)| {
            format!(
                "<item><title>{title}</title><guid>{file}</guid>\
                 <enclosure url=\"http://{addr}/{file}\" type=\"application/x-bittorrent\" length=\"16\"/></item>"
            )
        })
        .collect();
    format!("<?xml version=\"1.0\"?><rss version=\"2.0\"><channel><title>Test feed</title>{items}</channel></rss>").into_bytes()
}

#[tokio::test]
async fn rss_primes_then_adds_new_matches_and_survives_restart() {
    let (addr, routes) = http_server().await;
    let put = |p: &str, b: Vec<u8>| {
        routes.lock().unwrap().insert(p.to_owned(), b);
    };
    for n in ["alpha1", "beta2", "alpha3", "beta4", "alpha5"] {
        put(&format!("/{n}.torrent"), torrent(n));
    }
    let mut items = vec![("Alpha one", "alpha1.torrent"), ("Beta two", "beta2.torrent")];
    put("/feed", feed_xml(&items, addr));

    let home = temp_dir("home");
    let dl = temp_dir("dl");
    let feed_dir = temp_dir("feeddir");
    let h = Session::start_in(Store::at(&home), settings(&dl)).await.unwrap();
    h.command()
        .send(SessionCommand::AddFeed {
            url: "ftp://nope/feed".into(),
            include: vec![],
            exclude: vec![],
            dir: None,
        })
        .unwrap();
    h.command()
        .send(SessionCommand::AddFeed {
            url: format!("http://{addr}/feed"),
            include: vec!["alpha".into()],
            exclude: vec!["skipme".into()],
            dir: Some(feed_dir.clone()),
        })
        .unwrap();
    wait_for(&h, "priming", |st| logged(st, "watching 2 existing items") == 1 && st.feeds.iter().any(|f| f.last_fetch.is_some())).await;
    {
        let st = h.state();
        let st = st.read().await;
        assert_eq!(logged(&st, "not an http(s) URL"), 1);
        assert!(st.torrents.is_empty(), "existing items must not be downloaded");
        assert_eq!(st.feeds.len(), 1);
        assert_eq!(st.feeds[0].title.as_deref(), Some("Test feed"));
        assert!(st.feeds[0].last_fetch.is_some() && st.feeds[0].last_error.is_none());
    }

    items.extend([("Alpha three", "alpha3.torrent"), ("Beta four", "beta4.torrent")]);
    put("/feed", feed_xml(&items, addr));
    h.command().send(SessionCommand::RefreshFeeds).unwrap();
    wait_for(&h, "alpha three", |st| st.torrents.len() == 1).await;
    {
        let st = h.state();
        let st = st.read().await;
        let t = st.torrents[0].ui.torrent.as_ref().unwrap();
        assert_eq!(t.name, "alpha3");
        assert_eq!(t.download_dir, feed_dir.display().to_string());
        assert_eq!(st.feeds[0].recent, vec!["Alpha three".to_owned()]);
    }
    h.command().send(SessionCommand::RefreshFeeds).unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(h.state().read().await.torrents.len(), 1, "filtered or seen items were added");
    quit(h).await;

    items.push(("Alpha five", "alpha5.torrent"));
    put("/feed", feed_xml(&items, addr));
    let h = Session::start_in(Store::at(&home), settings(&dl)).await.unwrap();
    assert_eq!(h.state().read().await.feeds.len(), 1);
    h.command().send(SessionCommand::RefreshFeeds).unwrap();
    wait_for(&h, "alpha five", |st| st.torrents.len() == 2).await;
    h.command().send(SessionCommand::RefreshFeeds).unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    {
        let st = h.state();
        let st = st.read().await;
        let mut names: Vec<_> = st.torrents.iter().map(|t| t.ui.torrent.as_ref().unwrap().name.clone()).collect();
        names.sort();
        assert_eq!(names, ["alpha3", "alpha5"], "seen list lost across restart");
    }

    let id = h.state().read().await.feeds[0].id;
    h.command().send(SessionCommand::RemoveFeed(id)).unwrap();
    wait_for(&h, "feed removed", |st| st.feeds.is_empty()).await;
    quit(h).await;
    assert!(Store::at(&home).load_feeds().1.is_empty());
}

fn basic(password: &str) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let data = format!("user:{password}").into_bytes();
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = c.iter().fold(0u32, |a, b| a << 8 | *b as u32) << (8 * (3 - c.len()));
        for i in 0..=c.len() {
            out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
        out.extend(std::iter::repeat('=').take(3 - c.len()));
    }
    out
}

async fn request(addr: SocketAddr, method: &str, path: &str, auth: Option<&str>, body: &str) -> u16 {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let auth = auth.map(|p| format!("Authorization: Basic {}\r\n", basic(p))).unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{auth}Origin: http://127.0.0.1:{}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        addr.port(),
        addr.port(),
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out).split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
}

#[tokio::test]
async fn web_ui_with_password_runs_in_a_headless_session() {
    let home = temp_dir("home");
    let mut s = settings(&temp_dir("dl"));
    s.webui = WebUiSettings { enabled: true, port: 0, password: Some("correct horse battery".into()), lan: false };
    let h = Session::start_in(Store::at(&home), s).await.unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], h.webui_addr().expect("web UI bound").port()));
    assert!(h.state().read().await.settings.webui.password.as_deref().unwrap().starts_with("torrust-sha1$"));

    assert_eq!(request(addr, "GET", "/api/state", None, "").await, 401);
    assert_eq!(request(addr, "GET", "/api/state", Some("wrong"), "").await, 401);
    assert_eq!(request(addr, "GET", "/api/state", Some("correct horse battery"), "").await, 200);
    let magnet = format!("source=magnet%3A%3Fxt%3Durn%3Abtih%3A{}", "ab".repeat(20));
    assert_eq!(request(addr, "POST", "/api/add", None, &magnet).await, 401);
    assert_eq!(request(addr, "POST", "/api/add", Some("correct horse battery"), &magnet).await, 200);
    wait_for(&h, "magnet added", |st| st.torrents.len() == 1).await;

    h.command().send(SessionCommand::SetSettings(h.state().read().await.settings.clone())).unwrap();
    quit(h).await;
    let raw = std::fs::read(home.join("settings.bencode")).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("correct horse"));
    assert!(Store::at(&home).load_settings().webui.password.unwrap().starts_with("torrust-sha1$100000$"));
}

#[tokio::test]
async fn web_ui_disabled_listens_nowhere() {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut s = settings(&temp_dir("dl"));
    s.webui = WebUiSettings { enabled: false, port, password: None, lan: false };
    let h = Session::start_in(Store::at(temp_dir("home")), s).await.unwrap();
    assert!(h.webui_addr().is_none());
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    quit(h).await;
}

#[tokio::test]
async fn web_ui_bind_failure_is_a_warning() {
    let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = taken.local_addr().unwrap().port();
    let mut s = settings(&temp_dir("dl"));
    s.webui = WebUiSettings { enabled: true, port, password: None, lan: false };
    let h = Session::start_in(Store::at(temp_dir("home")), s).await.unwrap();
    assert!(h.webui_addr().is_none());
    assert_eq!(logged(&*h.state().read().await, "web UI unavailable"), 1);
    quit(h).await;
}

async fn http_get(addr: SocketAddr, path: &str, extra: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{extra}Connection: close\r\n\r\n", addr.port());
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    let text = String::from_utf8_lossy(&out).into_owned();
    let status = text.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    (status, text)
}

#[tokio::test]
async fn web_ui_without_a_password_needs_the_logged_token() {
    let home = temp_dir("home");
    let mut s = settings(&temp_dir("dl"));
    s.webui = WebUiSettings { enabled: true, port: 0, password: None, lan: false };
    let h = Session::start_in(Store::at(&home), s.clone()).await.unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], h.webui_addr().expect("web UI bound").port()));
    let url = h.webui_url().expect("token URL").to_owned();
    let token = url.split("?token=").nth(1).unwrap().to_owned();
    assert_eq!(url, format!("http://127.0.0.1:{}/?token={token}", addr.port()));
    assert_eq!(logged(&*h.state().read().await, &url), 1);
    assert_eq!(std::fs::read_to_string(home.join("webui.token")).unwrap().trim(), token);

    assert_eq!(http_get(addr, "/api/state", "").await.0, 401);
    assert_eq!(http_get(addr, "/api/state", "Cookie: torrust_token=0000\r\n").await.0, 401);
    assert_eq!(http_get(addr, "/?token=0000", "").await.0, 401);
    let (status, head) = http_get(addr, &format!("/?token={token}"), "").await;
    assert_eq!(status, 303);
    assert!(head.contains(&format!("Set-Cookie: torrust_token={token}; HttpOnly; SameSite=Strict; Path=/")), "{head}");
    assert!(head.contains("Location: /\r\n"));
    let cookie = format!("Cookie: torrust_token={token}\r\n");
    assert_eq!(http_get(addr, "/", &cookie).await.0, 200);
    assert_eq!(http_get(addr, "/api/state", &cookie).await.0, 200);
    assert_eq!(http_get(addr, "/api/state", &format!("Authorization: Bearer {token}\r\n")).await.0, 200);
    let rebound = format!("GET /api/state HTTP/1.1\r\nHost: evil.example\r\n{cookie}Connection: close\r\n\r\n");
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(rebound.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out).await;
    assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 403"));
    quit(h).await;

    let h = Session::start_in(Store::at(&home), s).await.unwrap();
    assert_eq!(h.webui_url().unwrap().split("?token=").nth(1).unwrap(), token);
    quit(h).await;
}

#[tokio::test]
async fn pending_downloads_are_bounded_and_feeds_have_their_own_slot() {
    let hang = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hang_addr = hang.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = hang.accept().await {
            held.push(s);
        }
    });
    let (addr, routes) = http_server().await;
    routes.lock().unwrap().insert("/feed".into(), feed_xml(&[("Alpha one", "alpha1.torrent")], addr));

    let h = Session::start_in(Store::at(temp_dir("home")), settings(&temp_dir("dl"))).await.unwrap();
    for i in 0..40 {
        h.command().send(SessionCommand::Add { source: format!("http://{hang_addr}/t{i}.torrent"), dir: None }).unwrap();
    }
    h.command()
        .send(SessionCommand::AddFeed { url: format!("http://{addr}/feed"), include: vec![], exclude: vec![], dir: None })
        .unwrap();
    wait_for(&h, "feed fetched while adds hang", |st| st.feeds.iter().any(|f| f.last_fetch.is_some())).await;
    wait_for(&h, "refusals", |st| logged(st, "too many pending downloads") == 8).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(logged(&*h.state().read().await, "too many pending downloads"), 8);
    quit(h).await;
}
