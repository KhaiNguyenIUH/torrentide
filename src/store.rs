//! On-disk session state: settings, one record per torrent, and the queue of
//! torrents added while no session was running. Everything is bencode, and
//! every write goes through a temp file and a rename so a crash never leaves
//! a half-written file.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::bencode::{self, Value};
use crate::state::{FilePriority, Settings, TorrentId};

/// Where the session keeps its files. `TORRUST_HOME` overrides the platform
/// default.
pub fn data_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("TORRUST_HOME") {
        return PathBuf::from(p);
    }
    let home = || {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    if cfg!(target_os = "macos") {
        home().join("Library/Application Support/torrust")
    } else if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join("AppData/Roaming"))
            .join("torrust")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home().join(".local/share"))
            .join("torrust")
    }
}

/// Everything persisted about one torrent besides its metainfo.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub id: TorrentId,
    pub dir: PathBuf,
    pub added_at: u64,
    pub stopped: bool,
    pub uploaded: u64,
    pub download_limit: u64,
    pub upload_limit: u64,
    pub priorities: Option<Vec<FilePriority>>,
    /// Queue position; records are loaded in this order.
    pub queue: u64,
    /// Started past the queue limits; cleared when the torrent is stopped.
    pub force: bool,
    /// What the torrent last showed, so it renders real progress while not running.
    pub snapshot: Option<Snapshot>,
    /// The magnet URI, kept until the metadata has been fetched and stored.
    pub magnet: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub name: String,
    pub total_length: u64,
    pub piece_count: u32,
    pub verified_pieces: u32,
    pub downloaded: u64,
    pub progress: f64,
    pub complete: bool,
    pub files: Vec<u64>,
}

/// A `torrust add` left for the next session to pick up.
#[derive(Debug, Clone, PartialEq)]
pub struct Queued {
    pub source: String,
    pub dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn open() -> Self {
        Store { root: data_dir() }
    }

    pub fn at(root: impl Into<PathBuf>) -> Self {
        Store { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn socket_path(&self) -> PathBuf {
        self.root.join("torrust.sock")
    }

    fn torrents_dir(&self) -> PathBuf {
        self.root.join("torrents")
    }

    fn queue_dir(&self) -> PathBuf {
        self.root.join("queue")
    }

    fn torrent_path(&self, id: &str) -> PathBuf {
        self.torrents_dir().join(format!("{id}.torrent"))
    }

    fn state_path(&self, id: &str) -> PathBuf {
        self.torrents_dir().join(format!("{id}.state"))
    }

    pub fn load_settings(&self) -> Settings {
        let path = self.root.join("settings.bencode");
        let Ok(raw) = fs::read(&path) else {
            return Settings::default();
        };
        match decode_settings(&raw) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "ignoring corrupt settings");
                Settings::default()
            }
        }
    }

    pub fn save_settings(&self, s: &Settings) -> Result<()> {
        write_atomic(&self.root.join("settings.bencode"), &encode_settings(s))
    }

    pub fn save_torrent(&self, id: &str, bytes: &[u8]) -> Result<()> {
        write_atomic(&self.torrent_path(id), bytes)
    }

    pub fn load_torrent(&self, id: &str) -> Option<Vec<u8>> {
        fs::read(self.torrent_path(id)).ok()
    }

    pub fn save_record(&self, r: &Record) -> Result<()> {
        write_atomic(&self.state_path(&r.id), &encode_record(r))
    }

    /// Delete a torrent's stored files.
    pub fn remove(&self, id: &str) {
        let _ = fs::remove_file(self.torrent_path(id));
        let _ = fs::remove_file(self.state_path(id));
    }

    /// Every readable record in queue order, plus a warning per skipped file.
    pub fn load_records(&self) -> (Vec<Record>, Vec<String>) {
        let mut out = Vec::new();
        let mut warnings = Vec::new();
        let Ok(rd) = fs::read_dir(self.torrents_dir()) else {
            return (out, warnings);
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("state") {
                continue;
            }
            let id = path.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_owned();
            let rec = fs::read(&path)
                .map_err(anyhow::Error::from)
                .and_then(|raw| decode_record(&id, &raw))
                .and_then(|r| {
                    if r.magnet.is_none() && !self.torrent_path(&id).exists() {
                        anyhow::bail!("no .torrent stored");
                    }
                    Ok(r)
                });
            match rec {
                Ok(r) => out.push(r),
                Err(e) => {
                    let msg = format!("skipping stored torrent {id}: {e:#}");
                    tracing::warn!("{msg}");
                    warnings.push(msg);
                }
            }
        }
        out.sort_by(|a, b| a.queue.cmp(&b.queue).then(a.added_at.cmp(&b.added_at)).then(a.id.cmp(&b.id)));
        (out, warnings)
    }

    pub fn enqueue(&self, source: &str, dir: Option<&Path>) -> Result<()> {
        let mut d = BTreeMap::new();
        d.insert(b"source".to_vec(), Value::Bytes(source.as_bytes().to_vec()));
        if let Some(dir) = dir {
            d.insert(b"dir".to_vec(), Value::Bytes(path_bytes(dir)));
        }
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let name = format!("{nanos}-{}.add", std::process::id());
        write_atomic(&self.queue_dir().join(name), &bencode::encode(&Value::Dict(d)))
    }

    /// Read and delete every queued add, oldest first.
    pub fn take_queue(&self) -> Vec<Queued> {
        let Ok(rd) = fs::read_dir(self.queue_dir()) else {
            return Vec::new();
        };
        let mut paths: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("add"))
            .collect();
        paths.sort();
        let mut out = Vec::new();
        for p in paths {
            let parsed = fs::read(&p)
                .map_err(anyhow::Error::from)
                .and_then(|raw| decode_queued(&raw));
            match parsed {
                Ok(q) => out.push(q),
                Err(e) => tracing::warn!(path = %p.display(), error = %e, "skipping corrupt queue entry"),
            }
            let _ = fs::remove_file(&p);
        }
        out
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("")
    ));
    fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e: io::Error| {
        let _ = fs::remove_file(&tmp);
        anyhow::Error::from(e).context(format!("replacing {}", path.display()))
    })
}

fn path_bytes(p: &Path) -> Vec<u8> {
    p.to_string_lossy().into_owned().into_bytes()
}

fn bytes_path(v: &Value) -> Result<PathBuf> {
    Ok(PathBuf::from(String::from_utf8_lossy(v.as_bytes()?).into_owned()))
}

fn int(n: u64) -> Value {
    Value::Int(n.min(i64::MAX as u64) as i64)
}

fn encode_settings(s: &Settings) -> Vec<u8> {
    let mut d = BTreeMap::new();
    d.insert(b"download_dir".to_vec(), Value::Bytes(path_bytes(&s.download_dir)));
    d.insert(b"listen_port".to_vec(), int(s.listen_port as u64));
    d.insert(b"download_limit".to_vec(), int(s.download_limit));
    d.insert(b"upload_limit".to_vec(), int(s.upload_limit));
    d.insert(b"ratio_target".to_vec(), Value::Bytes(s.ratio_target.to_string().into_bytes()));
    d.insert(b"max_peers".to_vec(), int(s.max_peers as u64));
    d.insert(b"dht".to_vec(), int(s.dht as u64));
    d.insert(b"port_forwarding".to_vec(), int(s.port_forwarding as u64));
    d.insert(b"max_active_downloads".to_vec(), int(s.max_active_downloads as u64));
    d.insert(b"max_active_torrents".to_vec(), int(s.max_active_torrents as u64));
    bencode::encode(&Value::Dict(d))
}

fn decode_settings(raw: &[u8]) -> Result<Settings> {
    let v = bencode::decode(raw)?;
    let mut s = Settings::default();
    if let Some(d) = v.get_opt("download_dir") {
        s.download_dir = bytes_path(d)?;
    }
    if let Some(n) = v.get_int_opt("listen_port") {
        s.listen_port = u16::try_from(n).context("listen_port out of range")?;
    }
    if let Some(n) = v.get_int_opt("download_limit") {
        s.download_limit = n.max(0) as u64;
    }
    if let Some(n) = v.get_int_opt("upload_limit") {
        s.upload_limit = n.max(0) as u64;
    }
    if let Some(r) = v.get_str_opt("ratio_target") {
        s.ratio_target = r.parse::<f64>().ok().filter(|r| r.is_finite() && *r >= 0.0).unwrap_or(s.ratio_target);
    }
    if let Some(n) = v.get_int_opt("max_peers") {
        s.max_peers = n.max(1) as usize;
    }
    if let Some(n) = v.get_int_opt("dht") {
        s.dht = n != 0;
    }
    if let Some(n) = v.get_int_opt("port_forwarding") {
        s.port_forwarding = n != 0;
    }
    if let Some(n) = v.get_int_opt("max_active_downloads") {
        s.max_active_downloads = n.max(0) as usize;
    }
    if let Some(n) = v.get_int_opt("max_active_torrents") {
        s.max_active_torrents = n.max(0) as usize;
    }
    Ok(s)
}

fn encode_record(r: &Record) -> Vec<u8> {
    let mut d = BTreeMap::new();
    d.insert(b"dir".to_vec(), Value::Bytes(path_bytes(&r.dir)));
    d.insert(b"added_at".to_vec(), int(r.added_at));
    d.insert(b"stopped".to_vec(), int(r.stopped as u64));
    d.insert(b"uploaded".to_vec(), int(r.uploaded));
    d.insert(b"download_limit".to_vec(), int(r.download_limit));
    d.insert(b"upload_limit".to_vec(), int(r.upload_limit));
    if let Some(p) = &r.priorities {
        d.insert(b"priorities".to_vec(), Value::Bytes(p.iter().map(|p| priority_byte(*p)).collect()));
    }
    d.insert(b"queue".to_vec(), int(r.queue));
    d.insert(b"force".to_vec(), int(r.force as u64));
    if let Some(s) = &r.snapshot {
        d.insert(b"snapshot".to_vec(), encode_snapshot(s));
    }
    if let Some(m) = &r.magnet {
        d.insert(b"magnet".to_vec(), Value::Bytes(m.as_bytes().to_vec()));
    }
    bencode::encode(&Value::Dict(d))
}

fn decode_record(id: &str, raw: &[u8]) -> Result<Record> {
    let v = bencode::decode(raw)?;
    Ok(Record {
        id: id.to_owned(),
        dir: bytes_path(v.get("dir")?)?,
        added_at: v.get("added_at")?.as_int_u64()?,
        stopped: v.get_int_opt("stopped").unwrap_or(0) != 0,
        uploaded: v.get_int_opt("uploaded").unwrap_or(0).max(0) as u64,
        download_limit: v.get_int_opt("download_limit").unwrap_or(0).max(0) as u64,
        upload_limit: v.get_int_opt("upload_limit").unwrap_or(0).max(0) as u64,
        priorities: v.get_bytes_opt("priorities").map(|b| b.iter().map(|c| byte_priority(*c)).collect()).or_else(|| {
            v.get_bytes_opt("wanted")
                .map(|b| b.iter().map(|c| if *c == b'1' { FilePriority::Normal } else { FilePriority::Skip }).collect())
        }),
        queue: v.get_int_opt("queue").unwrap_or(0).max(0) as u64,
        force: v.get_int_opt("force").unwrap_or(0) != 0,
        snapshot: v.get_opt("snapshot").and_then(decode_snapshot),
        magnet: v.get_str_opt("magnet").map(str::to_owned),
    })
}

fn priority_byte(p: FilePriority) -> u8 {
    b'0' + p as u8
}

fn byte_priority(b: u8) -> FilePriority {
    match b {
        b'0' => FilePriority::Skip,
        b'1' => FilePriority::Low,
        b'3' => FilePriority::High,
        _ => FilePriority::Normal,
    }
}

fn encode_snapshot(s: &Snapshot) -> Value {
    let mut d = BTreeMap::new();
    d.insert(b"name".to_vec(), Value::Bytes(s.name.as_bytes().to_vec()));
    d.insert(b"total_length".to_vec(), int(s.total_length));
    d.insert(b"piece_count".to_vec(), int(s.piece_count as u64));
    d.insert(b"verified_pieces".to_vec(), int(s.verified_pieces as u64));
    d.insert(b"downloaded".to_vec(), int(s.downloaded));
    d.insert(b"progress".to_vec(), Value::Bytes(s.progress.to_string().into_bytes()));
    d.insert(b"complete".to_vec(), int(s.complete as u64));
    d.insert(b"files".to_vec(), Value::List(s.files.iter().map(|n| int(*n)).collect()));
    Value::Dict(d)
}

fn decode_snapshot(v: &Value) -> Option<Snapshot> {
    let n = |k: &str| v.get_int_opt(k).map(|n| n.max(0) as u64);
    Some(Snapshot {
        name: v.get_str_opt("name")?.to_owned(),
        total_length: n("total_length")?,
        piece_count: n("piece_count")? as u32,
        verified_pieces: n("verified_pieces")? as u32,
        downloaded: n("downloaded")?,
        progress: v.get_str_opt("progress")?.parse::<f64>().ok().filter(|p| p.is_finite())?.clamp(0.0, 1.0),
        complete: n("complete").unwrap_or(0) != 0,
        files: match v.get_opt("files")? {
            Value::List(l) => l.iter().map(|x| x.as_int_u64().unwrap_or(0)).collect(),
            _ => return None,
        },
    })
}

fn decode_queued(raw: &[u8]) -> Result<Queued> {
    let v = bencode::decode(raw)?;
    Ok(Queued {
        source: v.get_str_opt("source").context("missing source")?.to_owned(),
        dir: v.get_opt("dir").map(bytes_path).transpose()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "torrust-store-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn settings_round_trip() {
        let store = Store::at(tmp("settings"));
        assert_eq!(store.load_settings(), Settings::default());
        let s = Settings {
            download_dir: PathBuf::from("/x/y"),
            listen_port: 7000,
            download_limit: 5,
            upload_limit: 6,
            ratio_target: 1.5,
            max_peers: 12,
            dht: false,
            port_forwarding: false,
            max_active_downloads: 2,
            max_active_torrents: 4,
        };
        store.save_settings(&s).unwrap();
        assert_eq!(store.load_settings(), s);
    }

    #[test]
    fn records_round_trip_and_corrupt_is_skipped() {
        let store = Store::at(tmp("records"));
        let r = Record {
            id: "aa".repeat(20),
            dir: PathBuf::from("/d"),
            added_at: 9,
            stopped: true,
            uploaded: 1234,
            download_limit: 1,
            upload_limit: 2,
            priorities: Some(vec![FilePriority::High, FilePriority::Skip, FilePriority::Low]),
            queue: 2,
            force: true,
            snapshot: Some(Snapshot {
                name: "n".into(),
                total_length: 99,
                piece_count: 7,
                verified_pieces: 3,
                downloaded: 40,
                progress: 0.4242,
                complete: false,
                files: vec![10, 0, 30],
            }),
            magnet: None,
        };
        store.save_torrent(&r.id, b"d4:infode").unwrap();
        store.save_record(&r).unwrap();
        let m = Record {
            id: "bb".repeat(20),
            magnet: Some("magnet:?xt=urn:btih:x".into()),
            priorities: None,
            snapshot: None,
            ..r.clone()
        };
        store.save_record(&m).unwrap();
        fs::write(store.state_path("cc"), b"garbage").unwrap();
        let (got, warnings) = store.load_records();
        assert_eq!(got, vec![r.clone(), m]);
        assert_eq!(warnings.len(), 1);
        store.remove(&r.id);
        assert_eq!(store.load_records().0.len(), 1);
    }

    #[test]
    fn old_format_record_loads_with_defaults_and_migrated_wanted() {
        let store = Store::at(tmp("old"));
        let id = "dd".repeat(20);
        let old = bencode::encode(&Value::Dict(BTreeMap::from([
            (b"dir".to_vec(), Value::Bytes(b"/d".to_vec())),
            (b"added_at".to_vec(), Value::Int(5)),
            (b"wanted".to_vec(), Value::Bytes(b"101".to_vec())),
        ])));
        store.save_torrent(&id, b"x").unwrap();
        write_atomic(&store.state_path(&id), &old).unwrap();
        let (got, warnings) = store.load_records();
        assert!(warnings.is_empty());
        let r = &got[0];
        assert_eq!(r.priorities, Some(vec![FilePriority::Normal, FilePriority::Skip, FilePriority::Normal]));
        assert!(!r.force && r.snapshot.is_none() && r.queue == 0 && !r.stopped);
    }

    #[test]
    fn old_settings_without_queue_limits_get_defaults() {
        let store = Store::at(tmp("oldsettings"));
        let raw = bencode::encode(&Value::Dict(BTreeMap::from([(b"listen_port".to_vec(), Value::Int(7))])));
        write_atomic(&store.root.join("settings.bencode"), &raw).unwrap();
        let s = store.load_settings();
        assert_eq!(s.listen_port, 7);
        assert_eq!(s.max_active_downloads, Settings::default().max_active_downloads);
    }

    #[test]
    fn queue_is_taken_once_in_order() {
        let store = Store::at(tmp("queue"));
        store.enqueue("a.torrent", Some(Path::new("/o"))).unwrap();
        store.enqueue("magnet:?xt=urn:btih:z", None).unwrap();
        let q = store.take_queue();
        assert_eq!(q.len(), 2);
        assert_eq!(q[0], Queued { source: "a.torrent".into(), dir: Some(PathBuf::from("/o")) });
        assert_eq!(q[1].dir, None);
        assert!(store.take_queue().is_empty());
    }
}
