//! Shared state types published to the TUI.
//!
//! The engine owns the authoritative download state and exposes it as a single
//! `UiState` snapshot. The TUI only ever reads a snapshot, so it can never
//! observe a half-updated download.

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadState {
    Connecting,
    FetchingMetadata,
    Announcing,
    Downloading,
    Paused,
    Complete,
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
            DownloadState::Error => "error",
            DownloadState::Stopped => "stopped",
        }
    }

    /// Whether the engine is actively requesting blocks in this state.
    pub fn is_active(&self) -> bool {
        matches!(self, DownloadState::Downloading)
    }
}

#[derive(Debug, Clone)]
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
    pub leecher_known: u32,
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
            leecher_known: 0,
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

#[derive(Debug, Clone)]
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
}

/// One file of a (usually multi-file) torrent, with its download progress.
#[derive(Debug, Clone)]
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
    pub wanted: bool,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Stop requesting new blocks. In-flight responses are still processed.
    Pause,
    /// Resume requesting after a pause.
    Resume,
    /// Flip whether the file at this file-list index is downloaded.
    ToggleFile(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: Level,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
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
    /// Channel into the engine for [`Command`]. `None` in tests and before the
    /// engine starts; the TUI disables its control keys while it is absent.
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