//! Shared state types published to the TUI.
//!
//! The engine owns the authoritative download state and exposes it as a single
//! `UiState` snapshot. The TUI only ever reads a snapshot, so it can never
//! observe a half-updated download.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DownloadState {
    Connecting,
    FetchingMetadata,
    Announcing,
    Downloading,
    Paused,
    Complete,
    /// Finished and still uploading until the ratio target is reached.
    Seeding,
    /// Waiting for a free slot under the session's active-torrent limits.
    Queued,
    /// Re-hashing the data on disk (startup or a forced recheck).
    Checking,
    Error,
    Stopped,
}

impl DownloadState {
    pub fn label(&self) -> &'static str {
        match self {
            DownloadState::Connecting => "connecting",
            DownloadState::FetchingMetadata => "fetching metadata",
            DownloadState::Announcing => "announcing",
            DownloadState::Downloading => "downloading",
            DownloadState::Paused => "paused",
            DownloadState::Complete => "complete",
            DownloadState::Seeding => "seeding",
            DownloadState::Queued => "queued",
            DownloadState::Checking => "checking",
            DownloadState::Error => "error",
            DownloadState::Stopped => "stopped",
        }
    }

    /// Whether the engine is actively requesting blocks in this state.
    pub fn is_active(&self) -> bool {
        matches!(self, DownloadState::Downloading)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorrentSummary {
    pub name: String,
    pub infohash: String,
    pub total_length: u64,
    pub downloaded: u64,
    pub piece_length: u32,
    pub piece_count: u32,
    pub verified_pieces: u32,
    pub progress: f64,
    pub download_rate: f64,
    pub upload_rate: f64,
    pub eta_secs: Option<f64>,
    pub state: DownloadState,
    pub download_dir: String,
    pub trackers: Vec<String>,
    /// Peers with at least one piece of the torrent.
    pub seeders_known: u32,
    /// Pieces are fetched in order (for watching while downloading).
    pub sequential: bool,
    /// Super-seeding (BEP 16) is on.
    pub super_seeding: bool,
    pub leecher_known: u32,
    /// Cumulative bytes uploaded for this torrent, including earlier runs.
    pub uploaded: u64,
    /// Per-file progress, in torrent file order. Empty for magnet links until
    /// metadata arrives.
    pub files: Vec<FileSummary>,
}

impl Default for TorrentSummary {
    fn default() -> Self {
        TorrentSummary {
            name: String::new(),
            infohash: String::new(),
            total_length: 0,
            downloaded: 0,
            piece_length: 0,
            piece_count: 0,
            verified_pieces: 0,
            progress: 0.0,
            download_rate: 0.0,
            upload_rate: 0.0,
            eta_secs: None,
            state: DownloadState::Connecting,
            download_dir: String::new(),
            trackers: vec![],
            seeders_known: 0,
            sequential: false,
            super_seeding: false,
            leecher_known: 0,
            uploaded: 0,
            files: vec![],
        }
    }
}

impl TorrentSummary {
    /// Human-readable byte count, e.g. `1.4 GB`.
    pub fn human_size(&self) -> String {
        human_bytes(self.total_length)
    }

    pub fn human_downloaded(&self) -> String {
        human_bytes(self.downloaded)
    }

    pub fn human_rate(&self) -> String {
        format!("{}/s", human_bytes(self.download_rate as u64))
    }

    /// Estimated time remaining, formatted as `1h 04m 09s` or `--:--` when
    /// there is no meaningful estimate.
    pub fn human_eta(&self) -> String {
        match self.eta_secs {
            Some(s) if s.is_finite() && s > 0.0 => human_duration(s),
            _ => "--:--".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSummary {
    pub addr: String,
    pub downloaded: u64,
    pub uploaded: u64,
    /// Fraction of the torrent this peer reports having.
    pub progress: f64,
    pub choked_by_us: bool,
    pub choking_us: bool,
    /// Outstanding blocks requested from this peer.
    pub outstanding: usize,
    /// uTorrent-style connection flags, e.g. "EPu": E encrypted, P uTP,
    /// I incoming, X found via PEX, L local discovery, H DHT, F fast extension.
    pub flags: String,
}

/// One file of a (usually multi-file) torrent, with its download progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSummary {
    /// Position in the torrent's file list; stable across snapshots.
    pub index: usize,
    /// Path relative to the torrent root, with `/` separators.
    pub path: String,
    pub length: u64,
    /// Verified bytes held so far.
    pub downloaded: u64,
    /// False when the user skipped this file. Its bytes are never requested,
    /// though pieces shared with wanted files still arrive.
    /// Always equal to `priority != FilePriority::Skip`.
    pub wanted: bool,
    pub priority: FilePriority,
}

/// Download priority of one file. Pieces of higher-priority files are
/// requested first; `Skip` files are not downloaded at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FilePriority {
    Skip,
    Low,
    #[default]
    Normal,
    High,
}

impl FilePriority {
    pub fn label(self) -> &'static str {
        match self {
            FilePriority::Skip => "skip",
            FilePriority::Low => "low",
            FilePriority::Normal => "normal",
            FilePriority::High => "high",
        }
    }
}

impl FileSummary {
    pub fn progress(&self) -> f64 {
        if self.length == 0 {
            return 1.0;
        }
        (self.downloaded as f64 / self.length as f64).clamp(0.0, 1.0)
    }

    pub fn human_size(&self) -> String {
        human_bytes(self.length)
    }
}

/// Commands the TUI sends to the engine.
///
/// The sender lives in [`UiState::command_tx`] so the UI thread can clone it
/// out of any snapshot; the engine drains it once per tick. Sending is
/// synchronous and never blocks, so it is safe to call from key handling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    /// Stop requesting new blocks. In-flight responses are still processed.
    Pause,
    /// Resume requesting after a pause.
    Resume,
    /// Flip whether the file at this file-list index is downloaded.
    ToggleFile(usize),
    /// Shut the engine down gracefully; `Engine::run` returns `Ok` with the
    /// torrent marked [`DownloadState::Stopped`].
    Stop,
    /// Re-hash every piece on disk and continue from what verifies.
    Recheck,
    /// Set one file's priority by file-list index.
    SetFilePriority(usize, FilePriority),
    /// Download pieces in order instead of rarest-first.
    SetSequential(bool),
    /// Initial-seeder mode: reveal pieces one peer at a time.
    SetSuperSeed(bool),
    /// Add a tracker URL to this torrent (http, https or udp).
    AddTracker(String),
    /// Remove a tracker URL from this torrent.
    RemoveTracker(String),
    /// Change the connection cap while running.
    SetMaxPeers(usize),
}

/// Stable identifier of a torrent within a session: its infohash in hex.
pub type TorrentId = String;

/// Session-wide preferences, edited from the settings screen and persisted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// Where new torrents are saved unless `add` names a directory.
    pub download_dir: PathBuf,
    /// TCP port for incoming peers. If it is taken the session falls back to
    /// an ephemeral port and says so.
    pub listen_port: u16,
    /// Global caps in bytes per second; 0 means unlimited.
    pub download_limit: u64,
    pub upload_limit: u64,
    /// Stop seeding once uploaded / size reaches this; 0 means seed forever.
    pub ratio_target: f64,
    /// Connection cap per torrent.
    pub max_peers: usize,
    pub dht: bool,
    /// Ask the router (NAT-PMP, then UPnP) to forward `listen_port`.
    pub port_forwarding: bool,
    /// Announce and listen for peers on the local network (BEP 14).
    pub lsd: bool,
    /// Move finished downloads here; `None` leaves them where they are.
    pub move_completed_dir: Option<PathBuf>,
    /// Queue limits: at most this many torrents downloading, and this many
    /// running in total (downloading + seeding). 0 means no limit.
    pub max_active_downloads: usize,
    pub max_active_torrents: usize,
    /// Peer connection encryption (BEP 8 / MSE).
    pub encryption: EncryptionMode,
    /// Try uTP (BEP 29) before TCP and accept uTP connections.
    pub utp: bool,
    pub webui: WebUiSettings,
    /// IP block list file (ipfilter.dat, PeerGuardian or CIDR lines).
    pub blocklist: Option<PathBuf>,
    /// Bandwidth schedule by hour of the week.
    pub schedule: crate::schedule::Schedule,
    /// Desktop notification when a download finishes.
    pub notifications: bool,
    /// Let torrent links, feeds and web seeds reach loopback and private
    /// (LAN) addresses. Off by default so a remote link can't probe the
    /// local network.
    pub allow_local_urls: bool,
}

/// Whether peer connections are obfuscated with Message Stream Encryption.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionMode {
    /// Plaintext only; encrypted inbound connections are refused.
    Disabled,
    /// Encrypt when the peer supports it, fall back to plaintext.
    #[default]
    Prefer,
    /// Encrypted connections only.
    Require,
}

impl EncryptionMode {
    pub fn label(self) -> &'static str {
        match self {
            EncryptionMode::Disabled => "disabled",
            EncryptionMode::Prefer => "prefer",
            EncryptionMode::Require => "require",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "disabled" | "off" => Some(EncryptionMode::Disabled),
            "prefer" | "enabled" | "on" => Some(EncryptionMode::Prefer),
            "require" | "required" | "forced" => Some(EncryptionMode::Require),
            _ => None,
        }
    }
}

/// The optional browser interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebUiSettings {
    /// Off by default: it is a remote-control surface.
    pub enabled: bool,
    pub port: u16,
    /// Without a password the web UI only listens on 127.0.0.1.
    pub password: Option<String>,
    /// Listen on every interface instead of loopback. Only honoured with a
    /// password; the connection is plain HTTP, so prefer an SSH tunnel.
    pub lan: bool,
    /// Extra folders the browser may save into, e.g. another drive. Empty
    /// keeps it to subfolders of the session's download folder, so a request
    /// can never steer writes off that tree.
    pub save_roots: Vec<PathBuf>,
}

impl Default for WebUiSettings {
    fn default() -> Self {
        WebUiSettings {
            enabled: false,
            port: 8080,
            password: None,
            lan: false,
            save_roots: Vec::new(),
        }
    }
}

/// Stable identifier of an RSS feed within a session.
pub type FeedId = u64;

/// One RSS/Atom subscription as the UI sees it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedView {
    pub id: FeedId,
    pub url: String,
    /// Feed title once fetched.
    pub title: Option<String>,
    /// Case-insensitive substrings: an item is added when its title contains
    /// any `include` term (or `include` is empty) and no `exclude` term.
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    /// Save folder for matched items; `None` uses the default.
    pub dir: Option<PathBuf>,
    /// Unix seconds of the last successful fetch.
    pub last_fetch: Option<u64>,
    pub last_error: Option<String>,
    /// Titles of the most recently added items, newest first.
    pub recent: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        Settings {
            download_dir: home.join("Downloads"),
            listen_port: 6881,
            download_limit: 0,
            upload_limit: 0,
            ratio_target: 2.0,
            max_peers: 50,
            max_active_downloads: 3,
            max_active_torrents: 8,
            dht: true,
            port_forwarding: true,
            lsd: true,
            move_completed_dir: None,
            encryption: EncryptionMode::default(),
            utp: true,
            webui: WebUiSettings::default(),
            blocklist: None,
            schedule: crate::schedule::Schedule::default(),
            notifications: true,
            allow_local_urls: false,
        }
    }
}

/// One torrent as the session TUI sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorrentView {
    pub id: TorrentId,
    /// The engine's own snapshot (summary, peers, log). Its `command_tx` is
    /// `None`; commands go through [`SessionState::command_tx`].
    pub ui: UiState,
    /// Cumulative bytes uploaded, across restarts.
    pub uploaded: u64,
    /// `uploaded / total_length`; 0 before metadata is known.
    pub ratio: f64,
    /// Per-torrent caps in bytes per second; 0 means unlimited.
    pub download_limit: u64,
    pub upload_limit: u64,
    /// Unix seconds when the torrent was added.
    pub added_at: u64,
    /// Position in the queue (0 = first), or `None` for a stopped torrent.
    pub queue_position: Option<usize>,
    /// User label (category), e.g. "linux" or "movies".
    pub label: Option<String>,
}

/// Everything the session TUI renders. Published by the session every
/// 250 ms; the TUI only ever reads a cloned snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionState {
    /// In the order they were added.
    pub torrents: Vec<TorrentView>,
    pub settings: Settings,
    /// Session-level events (adds, removals, port mapping, errors).
    pub log: Vec<LogEntry>,
    /// Totals across all torrents, bytes per second.
    pub download_rate: f64,
    pub upload_rate: f64,
    /// Human-readable listen/port-forwarding status, e.g.
    /// `"port 6881 · forwarded via NAT-PMP"`.
    pub port_status: String,
    pub warning: Option<String>,
    /// Set when the session is shutting down; the TUI exits its loop.
    pub shutdown: bool,
    #[serde(skip)]
    pub command_tx: Option<tokio::sync::mpsc::UnboundedSender<SessionCommand>>,
    pub feeds: Vec<FeedView>,
    /// Total download/upload rates, one sample per second, oldest first,
    /// at most 300 entries (five minutes) for the speed graph.
    pub rate_history: Vec<(f64, f64)>,
    /// Ranges loaded from the IP block list, or 0.
    pub blocklist_ranges: usize,
    /// Log lines ever appended, so a viewer can tell which entries are new
    /// after the oldest ones roll off.
    pub log_total: u64,
}

impl SessionState {
    pub fn log(&mut self, level: Level, message: impl Into<String>) {
        const MAX: usize = 500;
        self.log_total += 1;
        if self.log.len() >= MAX {
            self.log.remove(0);
        }
        self.log.push(LogEntry {
            level,
            message: message.into(),
        });
    }
}

/// Commands the session TUI (and `torrust add` over IPC) send to the session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SessionCommand {
    /// A `.torrent` path or a `magnet:` URI; `dir` defaults to
    /// [`Settings::download_dir`].
    Add { source: String, dir: Option<PathBuf> },
    /// The bytes of a `.torrent` file, saved to `dir` or, when it is `None`,
    /// to [`Settings::download_dir`]. The web UI resolves a caller-supplied
    /// subfolder against the download root before building this, so `dir` is
    /// always an absolute path inside that root.
    AddTorrent { bytes: Vec<u8>, dir: Option<PathBuf> },
    /// Stop the torrent and forget it; with `delete_data` also remove its
    /// downloaded files once the engine has shut down.
    Remove { id: TorrentId, delete_data: bool },
    Start(TorrentId),
    Stop(TorrentId),
    /// Forward a per-torrent command (pause, resume, file toggle).
    Torrent(TorrentId, Command),
    SetTorrentLimits { id: TorrentId, download: u64, upload: u64 },
    /// Move a torrent one place up (`true`) or down in the queue.
    MoveQueue { id: TorrentId, up: bool },
    /// Set or clear a torrent's label.
    SetLabel { id: TorrentId, label: Option<String> },
    /// Move a torrent's data to another folder and keep seeding from there.
    MoveData { id: TorrentId, dir: PathBuf },
    /// Subscribe to an RSS/Atom feed.
    AddFeed { url: String, include: Vec<String>, exclude: Vec<String>, dir: Option<PathBuf> },
    RemoveFeed(FeedId),
    /// Fetch every feed now instead of waiting for its interval.
    RefreshFeeds,
    SetSettings(Settings),
    /// Persist everything and shut down.
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn label(&self) -> &'static str {
        match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub level: Level,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UiState {
    pub torrent: Option<TorrentSummary>,
    pub peers: Vec<PeerSummary>,
    pub log: Vec<LogEntry>,
    /// Non-fatal problem worth surfacing prominently (e.g. tracker failures).
    pub warning: Option<String>,
    /// Ask the TUI to quit gracefully, restoring the terminal. Set when the
    /// engine is done and the CLI was asked to exit, so shutdown goes through
    /// the normal loop instead of killing the UI thread mid-frame (which
    /// would leave a frozen stale frame painted on the terminal).
    pub shutdown: bool,
    /// When the engine last published stats; a stale stamp means it is stuck.
    #[serde(skip)]
    pub stats_at: Option<std::time::Instant>,
    /// Channel into the engine for [`Command`]. `None` in tests and before the
    /// engine starts; the TUI disables its control keys while it is absent.
    #[serde(skip)]
    pub command_tx: Option<tokio::sync::mpsc::UnboundedSender<Command>>,
}

impl UiState {
    /// Append a log line, keeping the buffer bounded so a long-running session
    /// cannot grow without limit.
    pub fn log(&mut self, level: Level, message: impl Into<String>) {
        const MAX: usize = 500;
        if self.log.len() >= MAX {
            self.log.remove(0);
        }
        self.log.push(LogEntry {
            level,
            message: message.into(),
        });
    }
}

/// Format a byte count with binary units.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.2} {}", UNITS[i])
}

/// Format a duration in seconds as `1h 04m 09s`, `4m 09s`, or `09s`.
pub fn human_duration(secs: f64) -> String {
    let total = secs.max(0.0).round() as u64;
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    if h > 0 {
        format!("{h}h {m:02}m {s:02}s")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}

/// Current wall-clock time as `HH:MM:SS`.
pub fn now_hms() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let secs = d % 86400;
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_byte_counts() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.00 KiB");
        assert_eq!(human_bytes(1536), "1.50 KiB");
        assert_eq!(human_bytes(1024 * 1024 * 3), "3.00 MiB");
        assert_eq!(human_bytes(1024u64.pow(4) * 2), "2.00 TiB");
    }

    #[test]
    fn formats_durations() {
        assert_eq!(human_duration(5.0), "5s");
        assert_eq!(human_duration(65.0), "1m 05s");
        assert_eq!(human_duration(3705.0), "1h 01m 45s");
        assert_eq!(human_duration(0.0), "0s");
    }

    #[test]
    fn eta_falls_back_when_unknown() {
        let t = TorrentSummary {
            eta_secs: None,
            ..Default::default()
        };
        assert_eq!(t.human_eta(), "--:--");

        let t = TorrentSummary {
            eta_secs: Some(f64::INFINITY),
            ..Default::default()
        };
        assert_eq!(t.human_eta(), "--:--");
    }

    #[test]
    fn eta_formats_when_known() {
        let t = TorrentSummary {
            eta_secs: Some(125.0),
            ..Default::default()
        };
        assert_eq!(t.human_eta(), "2m 05s");
    }

    #[test]
    fn log_buffer_is_bounded() {
        let mut s = UiState::default();
        for i in 0..600 {
            s.log(Level::Info, format!("line {i}"));
        }
        assert_eq!(s.log.len(), 500);
        assert_eq!(s.log[0].message, "line 100");
    }

    #[test]
    fn state_labels() {
        assert_eq!(DownloadState::Downloading.label(), "downloading");
        assert_eq!(DownloadState::Complete.label(), "complete");
    }
}