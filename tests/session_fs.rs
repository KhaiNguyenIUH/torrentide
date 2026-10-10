#![allow(dead_code)]
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use torrust::bencode::{encode, Value};
use torrust::engine::build_seeder;
use torrust::session::{Session, SessionHandle};
use torrust::state::{DownloadState, SessionCommand, SessionState, Settings};
use torrust::storage::{sha1_bytes, Storage};
use torrust::store::Store;
use torrust::Metainfo;

const PIECE_LEN: usize = 16 * 1024;
const FILES: [(&str, usize); 3] = [("a.bin", 100_000), ("sub/b.bin", 40_000), ("sub/c.bin", 131_077)];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ts-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn payload(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (x >> 33) as u8
        })
        .collect()
}

fn key(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn bytes(s: &[u8]) -> Value {
    Value::Bytes(s.to_vec())
}

struct Fixture {
    name: &'static str,
    contents: Vec<Vec<u8>>,
}

impl Fixture {
    fn new(name: &'static str, seed: u64) -> Self {
        let contents = FILES
            .iter()
            .enumerate()
            .map(|(i, (_, len))| payload(seed * 10 + i as u64, *len))
            .collect();
        Fixture { name, contents }
    }

    fn torrent(&self, announce: &str) -> Vec<u8> {
        let all: Vec<u8> = self.contents.concat();
        let pieces: Vec<u8> = all.chunks(PIECE_LEN).flat_map(|c| sha1_bytes(c)).collect();
        let files = FILES
            .iter()
            .zip(&self.contents)
            .map(|((path, _), data)| {
                let segs = path.split('/').map(|s| bytes(s.as_bytes())).collect();
                Value::Dict(BTreeMap::from([
                    (key("length"), Value::Int(data.len() as i64)),
                    (key("path"), Value::List(segs)),
                ]))
            })
            .collect();
        let info = Value::Dict(BTreeMap::from([
            (key("name"), bytes(self.name.as_bytes())),
            (key("piece length"), Value::Int(PIECE_LEN as i64)),
            (key("pieces"), Value::Bytes(pieces)),
            (key("files"), Value::List(files)),
        ]));
        encode(&Value::Dict(BTreeMap::from([
            (key("announce"), bytes(announce.as_bytes())),
            (key("info"), info),
        ])))
    }

    fn write_to(&self, root: &Path) {
        for ((path, _), data) in FILES.iter().zip(&self.contents) {
            let p = root.join(self.name).join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, data).unwrap();
        }
    }

    fn assert_on_disk(&self, root: &Path) {
        for ((path, _), data) in FILES.iter().zip(&self.contents) {
            let got = std::fs::read(root.join(self.name).join(path)).unwrap();
            assert!(got == *data, "{}/{path} differs", self.name);
        }
    }
}

struct Tracker {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Tracker {
    fn saw_port(&self, port: u16) -> bool {
        let needle = format!("port={port}&");
        self.requests.lock().unwrap().iter().any(|r| r.contains(&needle))
    }
}

async fn mock_tracker(peer: Option<SocketAddr>) -> Tracker {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut peers = Vec::new();
    if let Some(p) = peer {
        peers.extend_from_slice(&[127, 0, 0, 1]);
        peers.extend_from_slice(&p.port().to_be_bytes());
    }
    let body = encode(&Value::Dict(BTreeMap::from([
        (key("interval"), Value::Int(1800)),
        (key("peers"), Value::Bytes(peers)),
    ])));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let body = body.clone();
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]);
                log.lock().unwrap().push(head.lines().next().unwrap_or("").to_owned());
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    Tracker { addr, requests }
}

async fn seeder_for(fx: &Fixture) -> SocketAddr {
    let seed_dir = temp_dir("seed");
    fx.write_to(&seed_dir);
    let meta = Metainfo::from_bytes(&fx.torrent("http://127.0.0.1:1/announce")).unwrap();
    let storage = Arc::new(Storage::prepare(&meta, &seed_dir).unwrap());
    let seeder = build_seeder(storage, &meta, &vec![true; meta.piece_count()]);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (addr, _h) = torrust::peer::pool::listen(Arc::new(meta), seeder, 0, tx).await.unwrap();
    tokio::spawn(async move {
        let mut live = vec![];
        while let Some((_, ev)) = rx.recv().await {
            if let torrust::peer::connection::FromPeer::Connected(h) = ev {
                live.push(h);
            }
        }
    });
    addr
}

fn settings(dir: &Path) -> Settings {
    Settings {
        download_dir: dir.to_path_buf(),
        listen_port: 0,
        ratio_target: 0.0,
        dht: false,
        port_forwarding: false,
        lsd: false,
        notifications: false,
        ..Settings::default()
    }
}

fn write_torrent(fx: &Fixture, tracker: &Tracker) -> (PathBuf, String) {
    let raw = fx.torrent(&format!("http://{}/announce", tracker.addr));
    let id = Metainfo::from_bytes(&raw).unwrap().infohash.to_hex();
    let path = temp_dir("tor").join(format!("{}.torrent", fx.name));
    std::fs::write(&path, raw).unwrap();
    (path, id)
}

fn add(h: &SessionHandle, path: &Path, dir: &Path) {
    h.command()
        .send(SessionCommand::Add { source: path.display().to_string(), dir: Some(dir.to_path_buf()) })
        .unwrap();
}

fn torrent_state(st: &SessionState, id: &str) -> Option<DownloadState> {
    st.torrents.iter().find(|t| t.id == id)?.ui.torrent.as_ref().map(|t| t.state)
}

async fn wait_for(h: &SessionHandle, what: &str, secs: u64, pred: impl Fn(&SessionState) -> bool) {
    let state = h.state();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        {
            let st = state.read().await;
            if pred(&st) {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                let torrents: Vec<_> = st
                    .torrents
                    .iter()
                    .map(|t| (t.id.clone(), t.ui.torrent.as_ref().map(|t| (t.state, t.progress)), t.ui.warning.clone()))
                    .collect();
                let log: Vec<_> = st.log.iter().map(|l| l.message.clone()).collect();
                panic!("timed out waiting for {what}; torrents={torrents:?}; log={log:#?}");
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn is_done(s: Option<DownloadState>) -> bool {
    matches!(s, Some(DownloadState::Seeding | DownloadState::Complete))
}

async fn quit(h: SessionHandle) {
    h.command().send(SessionCommand::Quit).unwrap();
    h.wait().await.unwrap();
}


fn view_dir(st: &SessionState, id: &str) -> Option<String> {
    st.torrents.iter().find(|t| t.id == id)?.ui.torrent.as_ref().map(|t| t.download_dir.clone())
}

fn at(st: &SessionState, id: &str, dir: &Path) -> bool {
    is_done(torrent_state(st, id)) && view_dir(st, id) == Some(dir.display().to_string())
}

async fn seeding_session(fx: &Fixture, dl: &Path) -> (SessionHandle, PathBuf, String) {
    fx.write_to(dl);
    let t = mock_tracker(None).await;
    let (p, id) = write_torrent(fx, &t);
    let home = temp_dir("home");
    let h = Session::start_in(Store::at(&home), settings(dl)).await.unwrap();
    add(&h, &p, dl);
    wait_for(&h, "seeding", 30, |st| is_done(torrent_state(st, &id))).await;
    (h, home, id)
}

fn meta_of(fx: &Fixture) -> Metainfo {
    Metainfo::from_bytes(&fx.torrent("http://127.0.0.1:1/announce")).unwrap()
}

fn swap_case(p: &Path) -> PathBuf {
    let name = p.file_name().unwrap().to_string_lossy().to_uppercase();
    p.with_file_name(name)
}

#[tokio::test]
async fn move_to_another_spelling_of_the_same_folder_keeps_the_data() {
    let fx = Fixture::new("same", 60);
    let dl = temp_dir("dl");
    let (h, _home, id) = seeding_session(&fx, &dl).await;

    let mut spellings = vec![dl.join("."), dl.join("same/..")];
    let alias = temp_dir("alias").join("lnk");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&dl, &alias).unwrap();
        spellings.push(alias);
        if let Ok(p) = dl.strip_prefix("/var") {
            spellings.push(Path::new("/private/var").join(p));
        }
    }
    let upper = swap_case(&dl);
    if upper != dl && upper.exists() {
        spellings.push(upper);
    }
    for dir in spellings {
        h.command().send(SessionCommand::MoveData { id: id.clone(), dir }).unwrap();
        tokio::time::sleep(Duration::from_millis(700)).await;
        wait_for(&h, "seeding again", 30, |st| at(st, &id, &dl)).await;
        fx.assert_on_disk(&dl);
    }
    quit(h).await;
}

#[test]
fn symlinked_directory_is_refused_when_preparing() {
    let fx = Fixture::new("sy", 61);
    let dl = temp_dir("dl");
    let outside = temp_dir("outside");
    std::fs::create_dir_all(dl.join("sy")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, dl.join("sy/sub")).unwrap();
    let err = Storage::prepare(&meta_of(&fx), &dl).err().expect("must refuse");
    assert!(format!("{err:#}").contains("symlink"), "{err:#}");
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
}

#[test]
fn symlinked_download_root_is_allowed() {
    let fx = Fixture::new("rootlink", 62);
    let real = temp_dir("real");
    let link = temp_dir("lk").join("dl");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, &link).unwrap();
    #[cfg(not(unix))]
    let link = real.clone();
    Storage::prepare(&meta_of(&fx), &link).unwrap();
    assert!(real.join("rootlink/a.bin").is_file());
}

#[test]
fn symlinked_file_is_refused_when_preparing() {
    let fx = Fixture::new("fsy", 63);
    let dl = temp_dir("dl");
    let outside = temp_dir("outside").join("victim");
    std::fs::write(&outside, b"precious").unwrap();
    std::fs::create_dir_all(dl.join("fsy")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, dl.join("fsy/a.bin")).unwrap();
    assert!(Storage::prepare(&meta_of(&fx), &dl).is_err());
    assert_eq!(std::fs::read(&outside).unwrap(), b"precious");
}

#[cfg(unix)]
#[tokio::test]
async fn remove_and_move_do_not_follow_a_symlinked_subdirectory() {
    let fx = Fixture::new("rmsy", 64);
    let dl = temp_dir("dl");
    let (h, _home, id) = seeding_session(&fx, &dl).await;
    let outside = temp_dir("outside");
    std::fs::rename(dl.join("rmsy/sub"), outside.join("sub")).unwrap();
    std::os::unix::fs::symlink(outside.join("sub"), dl.join("rmsy/sub")).unwrap();

    let dest = temp_dir("dest");
    h.command().send(SessionCommand::MoveData { id: id.clone(), dir: dest.clone() }).unwrap();
    wait_for(&h, "move refused", 15, |st| st.log.iter().any(|l| l.message.contains("cannot move"))).await;
    assert!(!dest.join("rmsy/sub").exists());
    assert!(outside.join("sub/b.bin").is_file());

    h.command().send(SessionCommand::Remove { id: id.clone(), delete_data: true }).unwrap();
    wait_for(&h, "removed", 15, |st| st.torrents.is_empty()).await;
    assert!(outside.join("sub/b.bin").is_file(), "deleted through the symlink");
    assert!(outside.join("sub/c.bin").is_file(), "deleted through the symlink");
    quit(h).await;
}

#[test]
fn a_different_file_at_a_torrent_path_is_refused_and_left_alone() {
    let fx = Fixture::new("diff", 65);
    let dl = temp_dir("dl");
    std::fs::create_dir_all(dl.join("diff/sub")).unwrap();
    let bigger = vec![9u8; FILES[1].1 + 500];
    std::fs::write(dl.join("diff/sub/b.bin"), &bigger).unwrap();
    let smaller = vec![8u8; 10];
    std::fs::write(dl.join("diff/a.bin"), &smaller).unwrap();

    let err = Storage::prepare(&meta_of(&fx), &dl).err().expect("must refuse");
    let msg = format!("{err:#}");
    assert!(msg.contains("a different file already exists at") && msg.contains("move it away"), "{msg}");
    assert_eq!(std::fs::read(dl.join("diff/sub/b.bin")).unwrap(), bigger);
    assert_eq!(std::fs::read(dl.join("diff/a.bin")).unwrap(), smaller);
}

#[test]
fn an_empty_leftover_and_a_right_sized_file_are_adopted() {
    let fx = Fixture::new("adopt", 66);
    let dl = temp_dir("dl");
    std::fs::create_dir_all(dl.join("adopt")).unwrap();
    std::fs::write(dl.join("adopt/a.bin"), b"").unwrap();
    std::fs::create_dir_all(dl.join("adopt/sub")).unwrap();
    std::fs::write(dl.join("adopt/sub/b.bin"), vec![5u8; FILES[1].1]).unwrap();
    Storage::prepare(&meta_of(&fx), &dl).unwrap();
    assert_eq!(std::fs::metadata(dl.join("adopt/a.bin")).unwrap().len(), FILES[0].1 as u64);
    assert_eq!(std::fs::read(dl.join("adopt/sub/b.bin")).unwrap(), vec![5u8; FILES[1].1]);
}

#[tokio::test]
async fn a_different_file_stops_the_torrent_with_an_error_and_is_untouched() {
    let fx = Fixture::new("dfs", 67);
    let dl = temp_dir("dl");
    std::fs::create_dir_all(dl.join("dfs")).unwrap();
    std::fs::write(dl.join("dfs/a.bin"), b"user data").unwrap();
    let t = mock_tracker(None).await;
    let (p, id) = write_torrent(&fx, &t);
    let h = Session::start_in(Store::at(temp_dir("home")), settings(&dl)).await.unwrap();
    add(&h, &p, &dl);
    wait_for(&h, "error", 15, |st| torrent_state(st, &id) == Some(DownloadState::Error)).await;
    assert_eq!(std::fs::read(dl.join("dfs/a.bin")).unwrap(), b"user data");
    quit(h).await;
}

#[tokio::test]
async fn remove_data_keeps_an_adopted_file_that_was_never_verified() {
    let fx = Fixture::new("keep", 68);
    let dl = temp_dir("dl");
    std::fs::create_dir_all(dl.join("keep/sub")).unwrap();
    let mine = vec![3u8; FILES[1].1];
    std::fs::write(dl.join("keep/sub/b.bin"), &mine).unwrap();
    let t = mock_tracker(None).await;
    let (p, id) = write_torrent(&fx, &t);
    let home = temp_dir("home");
    let h = Session::start_in(Store::at(&home), settings(&dl)).await.unwrap();
    add(&h, &p, &dl);
    wait_for(&h, "files created", 15, |st| {
        !st.torrents.is_empty() && dl.join("keep/a.bin").exists() && dl.join("keep/sub/c.bin").exists()
    })
    .await;
    h.command().send(SessionCommand::Remove { id, delete_data: true }).unwrap();
    wait_for(&h, "removed", 15, |st| st.torrents.is_empty()).await;
    assert_eq!(std::fs::read(dl.join("keep/sub/b.bin")).unwrap(), mine);
    assert!(!dl.join("keep/a.bin").exists());
    assert!(!dl.join("keep/sub/c.bin").exists());
    quit(h).await;
}

#[tokio::test]
async fn an_interrupted_move_is_finished_on_startup() {
    let fx = Fixture::new("crash", 69);
    let dl = temp_dir("dl");
    let (h, home, id) = seeding_session(&fx, &dl).await;
    quit(h).await;

    let dest = temp_dir("dest");
    std::fs::create_dir_all(dest.join("crash")).unwrap();
    std::fs::rename(dl.join("crash/a.bin"), dest.join("crash/a.bin")).unwrap();
    let intent = home.join("torrents").join(format!("{id}.move"));
    std::fs::write(&intent, encode(&Value::Bytes(dest.display().to_string().into_bytes()))).unwrap();

    let h = Session::start_in(Store::at(&home), settings(&dl)).await.unwrap();
    wait_for(&h, "seeding at the target", 30, |st| at(st, &id, &dest)).await;
    fx.assert_on_disk(&dest);
    assert!(!intent.exists());
    quit(h).await;
    assert_eq!(Store::at(&home).load_records().0[0].dir, dest);
}

#[tokio::test]
async fn an_interrupted_move_that_cannot_finish_is_rolled_back() {
    let fx = Fixture::new("undo", 70);
    let dl = temp_dir("dl");
    let (h, home, id) = seeding_session(&fx, &dl).await;
    quit(h).await;

    let dest = temp_dir("dest");
    std::fs::create_dir_all(dest.join("undo/sub")).unwrap();
    std::fs::rename(dl.join("undo/a.bin"), dest.join("undo/a.bin")).unwrap();
    std::fs::write(dest.join("undo/sub/b.bin"), b"someone else's").unwrap();
    let intent = home.join("torrents").join(format!("{id}.move"));
    std::fs::write(&intent, encode(&Value::Bytes(dest.display().to_string().into_bytes()))).unwrap();

    let h = Session::start_in(Store::at(&home), settings(&dl)).await.unwrap();
    wait_for(&h, "seeding back in place", 30, |st| at(st, &id, &dl)).await;
    fx.assert_on_disk(&dl);
    assert_eq!(std::fs::read(dest.join("undo/sub/b.bin")).unwrap(), b"someone else's");
    assert!(!intent.exists());
    quit(h).await;
}

#[cfg(unix)]
#[tokio::test]
async fn a_fifo_source_does_not_hang_the_session() {
    let dl = temp_dir("dl");
    let fifo = temp_dir("fifo").join("x.torrent");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let h = Session::start_in(Store::at(temp_dir("home")), settings(&dl)).await.unwrap();
    add(&h, &fifo, &dl);
    wait_for(&h, "refusal", 10, |st| st.log.iter().any(|l| l.message.contains("not a regular file"))).await;

    let fx = Fixture::new("after", 71);
    fx.write_to(&dl);
    let t = mock_tracker(None).await;
    let (p, id) = write_torrent(&fx, &t);
    add(&h, &p, &dl);
    wait_for(&h, "later add still works", 30, |st| is_done(torrent_state(st, &id))).await;
    quit(h).await;
}

#[cfg(unix)]
#[tokio::test]
async fn a_huge_source_is_refused_without_reading_it_all() {
    let dl = temp_dir("dl");
    let big = temp_dir("big").join("x.torrent");
    let f = std::fs::File::create(&big).unwrap();
    f.set_len(11 * 1024 * 1024).unwrap();
    let h = Session::start_in(Store::at(temp_dir("home")), settings(&dl)).await.unwrap();
    add(&h, &big, &dl);
    wait_for(&h, "refusal", 10, |st| st.log.iter().any(|l| l.message.contains("larger than"))).await;
    quit(h).await;
}

#[tokio::test]
async fn a_queued_file_is_deleted_only_after_its_torrent_is_saved() {
    let fx = Fixture::new("qf", 72);
    let dl = temp_dir("dl");
    fx.write_to(&dl);
    let t = mock_tracker(None).await;
    let (p, id) = write_torrent(&fx, &t);
    let home = temp_dir("home");
    Store::at(&home).enqueue(&p.display().to_string(), Some(&dl)).unwrap();
    let h = Session::start_in(Store::at(&home), settings(&dl)).await.unwrap();
    wait_for(&h, "added", 15, |st| st.torrents.iter().any(|t| t.id == id)).await;
    quit(h).await;
    assert_eq!(Store::at(&home).load_records().0.len(), 1);
    let left = std::fs::read_dir(home.join("queue")).map(|d| d.count()).unwrap_or(0);
    assert_eq!(left, 0);
}

#[tokio::test]
async fn a_queued_download_survives_until_it_has_been_fetched() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            held.push(s);
        }
    });
    let home = temp_dir("home");
    Store::at(&home).enqueue(&format!("http://{addr}/x.torrent"), None).unwrap();
    let h = Session::start_in(Store::at(&home), settings(&temp_dir("dl"))).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let left = std::fs::read_dir(home.join("queue")).unwrap().count();
    assert_eq!(left, 1, "queue file deleted before the torrent was saved");
    quit(h).await;
}
