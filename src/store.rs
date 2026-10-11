//! On-disk session state: settings, one record per torrent, and the queue of
//! torrents added while no session was running. Everything is bencode, and
//! every write goes through a temp file and a rename so a crash never leaves
//! a half-written file.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::bencode::{self, Value};
use crate::schedule::Schedule;
use crate::state::{EncryptionMode, FilePriority, Settings, TorrentId};

/// Where the session keeps its files. `TORRENTIDE_HOME` overrides the
/// platform default; the old `TORRUST_HOME` is honoured when it is unset. A
/// data directory left by the project's former name is moved on first use.
pub fn data_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("TORRENTIDE_HOME").or_else(|| std::env::var_os("TORRUST_HOME")) {
        return PathBuf::from(p);
    }
    let home = || {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    let platform = |name: &str| {
        if cfg!(target_os = "macos") {
            home().join("Library/Application Support").join(name)
        } else if cfg!(windows) {
            std::env::var_os("APPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| home().join("AppData/Roaming"))
                .join(name)
        } else {
            std::env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home().join(".local/share"))
                .join(name)
        }
    };
    migrate_legacy_dir(&platform("torrust"), &platform("torrentide"))
}

fn migrate_legacy_dir(old: &Path, new: &Path) -> PathBuf {
    if new.symlink_metadata().is_ok() || old.symlink_metadata().is_err() {
        return new.to_path_buf();
    }
    // An old session still running owns that directory; move it next time.
    #[cfg(unix)]
    if std::os::unix::net::UnixStream::connect(old.join("torrust.sock")).is_ok() {
        return old.to_path_buf();
    }
    match fs::rename(old, new) {
        Ok(()) => {
            let _ = fs::rename(new.join("torrust.log"), new.join("torrentide.log"));
            let _ = fs::remove_file(new.join("torrust.sock"));
            tracing::info!(from = %old.display(), to = %new.display(), "moved the old data directory");
            new.to_path_buf()
        }
        Err(e) => {
            tracing::warn!(from = %old.display(), to = %new.display(), error = %e, "could not move the old data directory; using it as is");
            old.to_path_buf()
        }
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
    pub label: Option<String>,
    pub sequential: bool,
    /// Completion has been seen (and any move-on-complete done); never moved automatically again.
    pub moved: bool,
    /// Tracker list that replaces the metainfo's, once trackers were added or removed.
    pub trackers: Option<Vec<String>>,
    pub super_seed: bool,
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

/// An RSS subscription as kept on disk. `seen` is oldest first and holds the
/// items already handed out, so a restart never re-adds them.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredFeed {
    pub id: u64,
    pub url: String,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub dir: Option<PathBuf>,
    pub title: Option<String>,
    /// False until the first fetch has recorded the items already in the feed.
    pub primed: bool,
    pub seen: Vec<String>,
}

/// A `torrentide add` left for the next session to pick up.
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
        let root = data_dir();
        if let Err(e) = secure_dir(&root) {
            tracing::warn!(path = %root.display(), error = %e, "could not secure the data directory");
        }
        Store { root }
    }

    pub fn at(root: impl Into<PathBuf>) -> Self {
        Store { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Our DHT node id and the nodes we knew last time, so a restart rejoins
    /// the DHT at once instead of starting over from the public routers.
    pub fn load_dht(&self) -> (Option<[u8; 20]>, Vec<SocketAddr>) {
        let Ok(text) = fs::read_to_string(self.root.join("dht.nodes")) else {
            return (None, Vec::new());
        };
        let mut lines = text.lines();
        let id = lines.next().and_then(|l| hex::decode(l.trim()).ok()).and_then(|b| b.try_into().ok());
        (id, lines.filter_map(|l| l.trim().parse().ok()).take(MAX_DHT_NODES).collect())
    }

    pub fn save_dht(&self, id: [u8; 20], nodes: &[SocketAddr]) -> Result<()> {
        let mut text = hex::encode(id);
        for n in nodes.iter().take(MAX_DHT_NODES) {
            text.push('\n');
            text.push_str(&n.to_string());
        }
        write_atomic(&self.root.join("dht.nodes"), text.as_bytes())
    }

    /// The 128-bit access token that guards a web UI without a password. It is
    /// created on first use and kept (readable by the owner only) so that the
    /// URL stays valid across restarts.
    pub fn web_token(&self) -> Result<String> {
        let path = self.root.join("webui.token");
        if let Ok(t) = fs::read_to_string(&path) {
            let t = t.trim();
            if t.len() == 32 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Ok(t.to_owned());
            }
        }
        use rand::RngCore;
        let mut raw = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut raw);
        let token = hex::encode(raw);
        write_atomic(&path, token.as_bytes())?;
        Ok(token)
    }

    pub fn socket_path(&self) -> PathBuf {
        self.root.join("torrentide.sock")
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

    /// Stored feeds and the next free feed id. A missing or unreadable file means none.
    pub fn load_feeds(&self) -> (u64, Vec<StoredFeed>) {
        let path = self.root.join("feeds.bencode");
        let Ok(raw) = fs::read(&path) else {
            return (1, Vec::new());
        };
        match decode_feeds(&raw) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "ignoring corrupt feeds file");
                (1, Vec::new())
            }
        }
    }

    pub fn save_feeds(&self, next_id: u64, feeds: &[StoredFeed]) -> Result<()> {
        write_atomic(&self.root.join("feeds.bencode"), &encode_feeds(next_id, feeds))
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

/// DHT nodes kept across restarts.
const MAX_DHT_NODES: usize = 200;

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("path has no parent")?;
    create_private_dir(parent).with_context(|| format!("creating {}", parent.display()))?;
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("")
    ));
    write_tmp(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e: io::Error| {
        let _ = fs::remove_file(&tmp);
        anyhow::Error::from(e).context(format!("replacing {}", path.display()))
    })?;
    sync_dir(parent).with_context(|| format!("syncing {}", parent.display()))
}

fn write_tmp(tmp: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(bytes)?;
    f.sync_all()
}

/// Open (creating, appending) the log file owner-only, refusing a symlink.
pub fn open_log(path: &Path) -> io::Result<fs::File> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "log path is a symlink"));
    }
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    let mut opts = fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(f)
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

/// Create `dir` owner-only, and tighten it if an earlier version left it
/// readable by group or others.
fn secure_dir(dir: &Path) -> io::Result<()> {
    create_private_dir(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir)?.permissions().mode();
        if mode & 0o077 != 0 {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            tracing::warn!(path = %dir.display(), "data directory was accessible to others; set to owner-only");
        }
    }
    Ok(())
}

const HASH_SCHEME: &str = "torrentide-sha1";
const LEGACY_HASH_SCHEME: &str = "sha1";
const HASH_ITERATIONS: u32 = 100_000;
const MAX_HASH_ITERATIONS: u32 = 1_000_000;

/// Whether `stored` is already a salted hash from [`hash_password`].
pub fn is_password_hash(stored: &str) -> bool {
    parse_hash(stored).is_some()
}

/// `torrentide-sha1$<iterations>$<salt hex>$<hash hex>`: SHA-1 over salt and
/// password, then iterated so each guess costs 100 000 rounds. The plaintext is
/// never stored. The older `sha1$...` spelling is still read.
pub fn hash_password(password: &str) -> String {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let hash = derive(&salt, password.as_bytes(), HASH_ITERATIONS);
    format!("{HASH_SCHEME}${HASH_ITERATIONS}${}${}", hex::encode(salt), hex::encode(hash))
}

/// Keep a stored hash as is and hash anything else.
pub fn hashed(password: &str) -> String {
    if is_password_hash(password) {
        password.to_owned()
    } else {
        hash_password(password)
    }
}

/// Check a password a client sent against what the settings hold: a stored
/// hash is recomputed and compared in constant time; plaintext (only ever
/// present in memory, before the session hashes it) is compared directly.
pub fn verify_password(stored: &str, given: &[u8]) -> bool {
    match parse_hash(stored) {
        Some((iterations, salt, hash)) => {
            crate::webui::ct_eq(&derive(&salt, given, iterations), &hash)
        }
        None if has_hash_scheme(stored) => false,
        None => crate::webui::ct_eq(given, stored.as_bytes()),
    }
}

fn has_hash_scheme(stored: &str) -> bool {
    let scheme = stored.split('$').next().unwrap_or("");
    stored.contains('$') && (scheme == HASH_SCHEME || scheme == LEGACY_HASH_SCHEME)
}

fn derive(salt: &[u8], password: &[u8], iterations: u32) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h: [u8; 20] = Sha1::new().chain_update(salt).chain_update(password).finalize().into();
    for _ in 1..iterations {
        h = Sha1::new().chain_update(h).chain_update(salt).chain_update(password).finalize().into();
    }
    h
}

fn parse_hash(stored: &str) -> Option<(u32, Vec<u8>, [u8; 20])> {
    let mut parts = stored.split('$');
    if !matches!(parts.next()?, HASH_SCHEME | LEGACY_HASH_SCHEME) {
        return None;
    }
    let iterations: u32 = parts.next()?.parse().ok().filter(|n| (1..=MAX_HASH_ITERATIONS).contains(n))?;
    let salt = hex::decode(parts.next()?).ok().filter(|s| !s.is_empty())?;
    let hash: [u8; 20] = hex::decode(parts.next()?).ok()?.try_into().ok()?;
    parts.next().is_none().then_some((iterations, salt, hash))
}

fn path_bytes(p: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        p.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    p.to_string_lossy().into_owned().into_bytes()
}

fn bytes_path(v: &Value) -> Result<PathBuf> {
    let raw = v.as_bytes()?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(raw)))
    }
    #[cfg(not(unix))]
    Ok(PathBuf::from(String::from_utf8_lossy(raw).into_owned()))
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
    d.insert(b"lsd".to_vec(), int(s.lsd as u64));
    d.insert(b"max_active_downloads".to_vec(), int(s.max_active_downloads as u64));
    d.insert(b"max_active_torrents".to_vec(), int(s.max_active_torrents as u64));
    if let Some(p) = &s.move_completed_dir {
        d.insert(b"move_completed_dir".to_vec(), Value::Bytes(path_bytes(p)));
    }
    d.insert(b"encryption".to_vec(), Value::Bytes(s.encryption.label().as_bytes().to_vec()));
    d.insert(b"utp".to_vec(), int(s.utp as u64));
    d.insert(b"webui_enabled".to_vec(), int(s.webui.enabled as u64));
    d.insert(b"webui_port".to_vec(), int(s.webui.port as u64));
    if let Some(p) = s.webui.password.as_deref().filter(|p| !p.is_empty()) {
        d.insert(b"webui_password".to_vec(), Value::Bytes(hashed(p).into_bytes()));
    }
    if let Some(p) = &s.blocklist {
        d.insert(b"blocklist".to_vec(), Value::Bytes(path_bytes(p)));
    }
    d.insert(b"notifications".to_vec(), int(s.notifications as u64));
    d.insert(b"webui_lan".to_vec(), int(s.webui.lan as u64));
    if !s.webui.save_roots.is_empty() {
        let roots: Vec<Value> = s.webui.save_roots.iter().map(|p| Value::Bytes(path_bytes(p))).collect();
        d.insert(b"webui_save_roots".to_vec(), Value::List(roots));
    }
    d.insert(b"allow_local_urls".to_vec(), int(s.allow_local_urls as u64));
    let sc = &s.schedule;
    d.insert(b"schedule_enabled".to_vec(), int(sc.enabled as u64));
    d.insert(b"schedule_grid".to_vec(), Value::Bytes(sc.to_string_grid().into_bytes()));
    d.insert(b"schedule_limited_down".to_vec(), int(sc.limited_down));
    d.insert(b"schedule_limited_up".to_vec(), int(sc.limited_up));
    d.insert(b"schedule_utc_offset".to_vec(), Value::Int(sc.utc_offset_minutes as i64));
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
    if let Some(n) = v.get_int_opt("lsd") {
        s.lsd = n != 0;
    }
    if let Some(n) = v.get_int_opt("max_active_downloads") {
        s.max_active_downloads = n.max(0) as usize;
    }
    if let Some(n) = v.get_int_opt("max_active_torrents") {
        s.max_active_torrents = n.max(0) as usize;
    }
    if let Some(m) = v.get_str_opt("encryption").and_then(EncryptionMode::parse) {
        s.encryption = m;
    }
    if let Some(n) = v.get_int_opt("utp") {
        s.utp = n != 0;
    }
    if let Some(n) = v.get_int_opt("webui_enabled") {
        s.webui.enabled = n != 0;
    }
    if let Some(n) = v.get_int_opt("webui_port") {
        s.webui.port = u16::try_from(n).context("webui_port out of range")?;
    }
    s.webui.password = v.get_str_opt("webui_password").filter(|p| !p.is_empty()).map(str::to_owned);
    s.move_completed_dir = v.get_opt("move_completed_dir").map(bytes_path).transpose()?.filter(|p| !p.as_os_str().is_empty());
    s.blocklist = v.get_opt("blocklist").map(bytes_path).transpose()?.filter(|p| !p.as_os_str().is_empty());
    if let Some(n) = v.get_int_opt("webui_lan") {
        s.webui.lan = n != 0;
    }
    if let Some(Value::List(l)) = v.get_opt("webui_save_roots") {
        s.webui.save_roots =
            l.iter().filter_map(|x| bytes_path(x).ok()).filter(|p| !p.as_os_str().is_empty()).collect();
    }
    if let Some(n) = v.get_int_opt("allow_local_urls") {
        s.allow_local_urls = n != 0;
    }
    if let Some(n) = v.get_int_opt("notifications") {
        s.notifications = n != 0;
    }
    if let Some(n) = v.get_int_opt("schedule_enabled") {
        s.schedule.enabled = n != 0;
    }
    if let Some(g) = v.get_str_opt("schedule_grid") {
        match Schedule::parse_grid(g) {
            Ok(grid) => s.schedule.grid = grid,
            Err(e) => tracing::warn!(error = %e, "ignoring corrupt schedule grid"),
        }
    }
    if let Some(n) = v.get_int_opt("schedule_limited_down") {
        s.schedule.limited_down = n.max(0) as u64;
    }
    if let Some(n) = v.get_int_opt("schedule_limited_up") {
        s.schedule.limited_up = n.max(0) as u64;
    }
    if let Some(n) = v.get_int_opt("schedule_utc_offset") {
        s.schedule.utc_offset_minutes = n.clamp(-14 * 60, 14 * 60) as i32;
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
    if let Some(l) = &r.label {
        d.insert(b"label".to_vec(), Value::Bytes(l.as_bytes().to_vec()));
    }
    d.insert(b"sequential".to_vec(), int(r.sequential as u64));
    d.insert(b"moved".to_vec(), int(r.moved as u64));
    if let Some(t) = &r.trackers {
        d.insert(b"trackers".to_vec(), Value::List(t.iter().map(|x| Value::Bytes(x.as_bytes().to_vec())).collect()));
    }
    d.insert(b"super_seed".to_vec(), int(r.super_seed as u64));
    bencode::encode(&Value::Dict(d))
}

fn decode_record(id: &str, raw: &[u8]) -> Result<Record> {
    let v = bencode::decode(raw)?;
    let snapshot = v.get_opt("snapshot").and_then(decode_snapshot);
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
        magnet: v.get_str_opt("magnet").map(str::to_owned),
        label: v.get_str_opt("label").filter(|l| !l.is_empty()).map(str::to_owned),
        sequential: v.get_int_opt("sequential").unwrap_or(0) != 0,
        moved: v.get_int_opt("moved").map_or_else(|| snapshot.as_ref().is_some_and(|s| s.complete), |n| n != 0),
        trackers: match v.get_opt("trackers") {
            Some(Value::List(l)) => Some(
                l.iter()
                    .filter_map(|x| x.as_bytes().ok())
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect(),
            ),
            _ => None,
        },
        super_seed: v.get_int_opt("super_seed").unwrap_or(0) != 0,
        snapshot,
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

fn encode_feeds(next_id: u64, feeds: &[StoredFeed]) -> Vec<u8> {
    let strings = |l: &[String]| Value::List(l.iter().map(|x| Value::Bytes(x.as_bytes().to_vec())).collect());
    let list = feeds
        .iter()
        .map(|f| {
            let mut d = BTreeMap::new();
            d.insert(b"id".to_vec(), int(f.id));
            d.insert(b"url".to_vec(), Value::Bytes(f.url.as_bytes().to_vec()));
            d.insert(b"include".to_vec(), strings(&f.include));
            d.insert(b"exclude".to_vec(), strings(&f.exclude));
            if let Some(p) = &f.dir {
                d.insert(b"dir".to_vec(), Value::Bytes(path_bytes(p)));
            }
            if let Some(t) = &f.title {
                d.insert(b"title".to_vec(), Value::Bytes(t.as_bytes().to_vec()));
            }
            d.insert(b"primed".to_vec(), int(f.primed as u64));
            d.insert(b"seen".to_vec(), strings(&f.seen));
            Value::Dict(d)
        })
        .collect();
    let mut d = BTreeMap::new();
    d.insert(b"next_id".to_vec(), int(next_id));
    d.insert(b"feeds".to_vec(), Value::List(list));
    bencode::encode(&Value::Dict(d))
}

fn decode_feeds(raw: &[u8]) -> Result<(u64, Vec<StoredFeed>)> {
    let strings = |v: &Value, key: &str| -> Vec<String> {
        match v.get_opt(key) {
            Some(Value::List(l)) => l
                .iter()
                .filter_map(|x| x.as_bytes().ok())
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .collect(),
            _ => Vec::new(),
        }
    };
    let v = bencode::decode(raw)?;
    let mut feeds = Vec::new();
    if let Some(Value::List(l)) = v.get_opt("feeds") {
        for f in l {
            let (Some(id), Some(url)) = (f.get_int_opt("id").filter(|n| *n > 0), f.get_str_opt("url")) else {
                continue;
            };
            feeds.push(StoredFeed {
                id: id as u64,
                url: url.to_owned(),
                include: strings(f, "include"),
                exclude: strings(f, "exclude"),
                dir: f.get_opt("dir").map(bytes_path).transpose()?.filter(|p| !p.as_os_str().is_empty()),
                title: f.get_str_opt("title").filter(|t| !t.is_empty()).map(str::to_owned),
                primed: f.get_int_opt("primed").unwrap_or(0) != 0,
                seen: strings(f, "seen"),
            });
        }
    }
    let next = feeds.iter().map(|f| f.id + 1).max().unwrap_or(1).max(v.get_int_opt("next_id").unwrap_or(1).max(1) as u64);
    Ok((next, feeds))
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
            "torrentide-store-{tag}-{}-{}",
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
    fn dht_nodes_round_trip_and_tolerate_junk() {
        let store = Store::at(tmp("dht"));
        assert_eq!(store.load_dht(), (None, Vec::new()));
        let nodes: Vec<SocketAddr> = vec!["1.2.3.4:6881".parse().unwrap(), "[2001:db8::1]:51413".parse().unwrap()];
        store.save_dht([7; 20], &nodes).unwrap();
        assert_eq!(store.load_dht(), (Some([7; 20]), nodes.clone()));
        fs::write(store.root().join("dht.nodes"), "nothex\n1.2.3.4:6881\ngarbage\n").unwrap();
        assert_eq!(store.load_dht(), (None, nodes[..1].to_vec()));
    }

    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn legacy_dir_is_moved_only_when_new_is_missing() {
        let base = tmp("migrate");
        let old = base.join("torrust");
        let new = base.join("torrentide");

        assert_eq!(migrate_legacy_dir(&old, &new), new);
        assert!(!new.exists());

        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("settings.bencode"), b"s").unwrap();
        fs::write(old.join("torrust.log"), b"l").unwrap();
        fs::write(old.join("torrust.sock"), b"").unwrap();
        assert_eq!(migrate_legacy_dir(&old, &new), new);
        assert!(!old.exists());
        assert_eq!(fs::read(new.join("settings.bencode")).unwrap(), b"s");
        assert_eq!(fs::read(new.join("torrentide.log")).unwrap(), b"l");
        assert!(!new.join("torrust.log").exists());
        assert!(!new.join("torrust.sock").exists());

        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("keep"), b"k").unwrap();
        assert_eq!(migrate_legacy_dir(&old, &new), new);
        assert!(old.join("keep").exists());
        assert!(!new.join("keep").exists());
    }

    #[cfg(unix)]
    #[test]
    fn data_dir_is_0700_and_every_file_0600() {
        let root = tmp("perms").join("fresh");
        let store = Store::at(&root);
        store.save_settings(&Settings::default()).unwrap();
        store.save_feeds(1, &[]).unwrap();
        store.save_torrent("abc", b"x").unwrap();
        store.enqueue("magnet:?xt=urn:btih:aa", None).unwrap();
        store.web_token().unwrap();
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&root.join("torrents")), 0o700);
        assert_eq!(mode(&root.join("queue")), 0o700);
        for f in ["settings.bencode", "feeds.bencode", "torrents/abc.torrent", "webui.token"] {
            assert_eq!(mode(&root.join(f)), 0o600, "{f}");
        }
        let queued = fs::read_dir(root.join("queue")).unwrap().next().unwrap().unwrap().path();
        assert_eq!(mode(&queued), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn log_file_is_0600_and_symlinks_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("log");
        let log = d.join("torrentide.log");
        fs::write(&log, b"old\n").unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
        drop(open_log(&log).unwrap());
        assert_eq!(mode(&log), 0o600);
        assert_eq!(fs::read(&log).unwrap(), b"old\n");

        let target = d.join("victim");
        fs::write(&target, b"keep").unwrap();
        let link = d.join("linked.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_log(&link).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn secure_dir_tightens_an_existing_open_dir() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("tighten");
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        secure_dir(&d).unwrap();
        assert_eq!(mode(&d), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_round_trip() {
        use std::os::unix::ffi::OsStrExt;
        let odd = PathBuf::from(std::ffi::OsStr::from_bytes(b"/d/caf\xe9/\xff"));
        let store = Store::at(tmp("nonutf8"));
        let s = Settings { download_dir: odd.clone(), ..Settings::default() };
        store.save_settings(&s).unwrap();
        assert_eq!(store.load_settings().download_dir, odd);
        store.enqueue("x", Some(&odd)).unwrap();
        assert_eq!(store.take_queue()[0].dir.as_deref(), Some(odd.as_path()));
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
            lsd: false,
            max_active_downloads: 2,
            max_active_torrents: 4,
            move_completed_dir: Some(PathBuf::from("/done")),
            blocklist: Some(PathBuf::from("/x/bl.txt")),
            notifications: false,
            schedule: {
                let mut sc = Schedule { enabled: true, limited_down: 11, limited_up: 22, utc_offset_minutes: -330, ..Default::default() };
                sc.apply_rule("mon-fri 09-18 limited").unwrap();
                sc.apply_rule("sat 22-02 off").unwrap();
                sc
            },
            ..Settings::default()
        };
        store.save_settings(&s).unwrap();
        assert_eq!(store.load_settings(), s);
    }

    #[test]
    fn old_settings_file_loads_new_fields_as_defaults() {
        let store = Store::at(tmp("oldsettings"));
        let old = bencode::encode(&Value::Dict(BTreeMap::from([(b"listen_port".to_vec(), Value::Int(7000))])));
        write_atomic(&store.root.join("settings.bencode"), &old).unwrap();
        let s = store.load_settings();
        assert_eq!(s.listen_port, 7000);
        assert_eq!((s.blocklist, s.notifications, s.schedule), (None, true, Schedule::default()));
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
            label: Some("movies".into()),
            sequential: true,
            moved: true,
            trackers: Some(vec!["http://t/a".into(), "udp://u:1/b".into()]),
            super_seed: true,
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
        assert!(r.label.is_none() && !r.sequential && !r.moved && r.trackers.is_none() && !r.super_seed);
    }

    #[test]
    fn old_complete_record_counts_as_already_moved() {
        let store = Store::at(tmp("oldcomplete"));
        let id = "ee".repeat(20);
        let r = Record {
            id: id.clone(),
            dir: PathBuf::from("/d"),
            added_at: 1,
            stopped: false,
            uploaded: 0,
            download_limit: 0,
            upload_limit: 0,
            priorities: None,
            queue: 0,
            force: false,
            snapshot: Some(Snapshot {
                name: "n".into(),
                total_length: 1,
                piece_count: 1,
                verified_pieces: 1,
                downloaded: 1,
                progress: 1.0,
                complete: true,
                files: vec![1],
            }),
            magnet: None,
            label: None,
            sequential: false,
            moved: false,
            trackers: None,
            super_seed: false,
        };
        let mut d = match bencode::decode(&encode_record(&r)).unwrap() {
            Value::Dict(d) => d,
            _ => unreachable!(),
        };
        d.remove(b"moved".as_slice());
        store.save_torrent(&id, b"x").unwrap();
        write_atomic(&store.state_path(&id), &bencode::encode(&Value::Dict(d))).unwrap();
        assert!(store.load_records().0[0].moved);
    }

    #[test]
    fn old_settings_without_queue_limits_get_defaults() {
        let store = Store::at(tmp("oldsettings"));
        let raw = bencode::encode(&Value::Dict(BTreeMap::from([(b"listen_port".to_vec(), Value::Int(7))])));
        write_atomic(&store.root.join("settings.bencode"), &raw).unwrap();
        let s = store.load_settings();
        assert_eq!(s.listen_port, 7);
        assert_eq!(s.max_active_downloads, Settings::default().max_active_downloads);
        assert_eq!(s.move_completed_dir, None);
    }

    #[test]
    fn new_settings_round_trip() {
        let store = Store::at(tmp("newsettings"));
        let s = Settings {
            encryption: EncryptionMode::Require,
            utp: false,
            webui: crate::state::WebUiSettings { enabled: true, port: 9123, password: Some(hash_password("pw")), lan: true, save_roots: Vec::new() },
            allow_local_urls: true,
            ..Settings::default()
        };
        store.save_settings(&s).unwrap();
        assert_eq!(store.load_settings(), s);
        let d = Settings::default();
        assert!(!d.webui.lan && !d.allow_local_urls);
    }

    #[test]
    fn old_settings_get_new_defaults() {
        let store = Store::at(tmp("oldnew"));
        let raw = bencode::encode(&Value::Dict(BTreeMap::from([(b"listen_port".to_vec(), Value::Int(7))])));
        write_atomic(&store.root.join("settings.bencode"), &raw).unwrap();
        let s = store.load_settings();
        let d = Settings::default();
        assert_eq!((s.encryption, s.utp, s.webui.clone()), (d.encryption, d.utp, d.webui));
    }

    #[test]
    fn hash_grammar_is_strict_and_reads_the_old_spelling() {
        let salt = "00112233";
        let hash = hex::encode(derive(&hex::decode(salt).unwrap(), b"pw", 3));
        let legacy = format!("sha1$3${salt}${hash}");
        let current = format!("torrentide-sha1$3${salt}${hash}");
        for h in [&legacy, &current] {
            assert!(is_password_hash(h));
            assert!(verify_password(h, b"pw") && !verify_password(h, b"px"));
        }
        let too_many = format!("torrentide-sha1${}${salt}${hash}", MAX_HASH_ITERATIONS + 1);
        let legacy_too_many = format!("sha1$99999999${salt}${hash}");
        for bad in [too_many, legacy_too_many, format!("sha1$0${salt}${hash}"), format!("sha1$3$${hash}")] {
            assert!(!is_password_hash(&bad), "{bad}");
            assert!(!verify_password(&bad, bad.as_bytes()), "{bad}");
            assert!(!verify_password(&bad, b"pw"), "{bad}");
        }
        assert!(verify_password("sha1", b"sha1") && verify_password("my$pass", b"my$pass"));
    }

    #[test]
    fn web_token_is_random_stable_and_private() {
        let root = tmp("token");
        let store = Store::at(&root);
        let t = store.web_token().unwrap();
        assert_eq!(t.len(), 32);
        assert!(t.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(Store::at(&root).web_token().unwrap(), t);
        assert_ne!(Store::at(tmp("token2")).web_token().unwrap(), t);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(root.join("webui.token")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        fs::write(root.join("webui.token"), "short").unwrap();
        assert_eq!(store.web_token().unwrap().len(), 32);
    }

    #[test]
    fn password_is_never_written_in_plaintext() {
        let root = tmp("pw");
        let store = Store::at(&root);
        let mut s = Settings::default();
        s.webui.password = Some("correct horse battery".into());
        store.save_settings(&s).unwrap();
        let raw = fs::read(root.join("settings.bencode")).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("correct horse"));
        let stored = store.load_settings().webui.password.unwrap();
        assert!(is_password_hash(&stored) && stored.starts_with("torrentide-sha1$100000$"));
        assert!(verify_password(&stored, b"correct horse battery"));
        assert!(!verify_password(&stored, b"correct horse batterz"));
        assert!(!verify_password(&stored, b""));
        assert!(verify_password("plain", b"plain") && !verify_password("plain", b"other"));
        assert_ne!(hash_password("x"), hash_password("x"));
    }

    #[cfg(unix)]
    #[test]
    fn settings_and_feeds_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let root = tmp("mode");
        let store = Store::at(&root);
        fs::write(root.join("settings.bencode.tmp"), b"x").unwrap();
        fs::set_permissions(root.join("settings.bencode.tmp"), fs::Permissions::from_mode(0o644)).unwrap();
        store.save_settings(&Settings::default()).unwrap();
        store.save_feeds(1, &[]).unwrap();
        for f in ["settings.bencode", "feeds.bencode"] {
            let mode = fs::metadata(root.join(f)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{f}");
        }
    }

    #[test]
    fn feeds_round_trip_and_missing_or_corrupt_means_none() {
        let root = tmp("feeds");
        let store = Store::at(&root);
        assert_eq!(store.load_feeds(), (1, vec![]));
        let f = StoredFeed {
            id: 4,
            url: "http://h/feed".into(),
            include: vec!["a".into()],
            exclude: vec![],
            dir: Some(PathBuf::from("/d")),
            title: Some("T".into()),
            primed: true,
            seen: vec!["g1".into(), "g2".into()],
        };
        store.save_feeds(9, std::slice::from_ref(&f)).unwrap();
        assert_eq!(store.load_feeds(), (9, vec![f]));
        fs::write(root.join("feeds.bencode"), b"garbage").unwrap();
        assert_eq!(store.load_feeds(), (1, vec![]));
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
