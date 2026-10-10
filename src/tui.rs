//! Terminal user interface.
//!
//! [`run_tui`] owns the terminal for the duration of the call: it switches to
//! the alternate screen, enables raw mode, and runs a blocking render/input
//! loop on a dedicated OS thread so the engine's async runtime is never blocked
//! by terminal I/O. Nothing in here drives the terminal with tokio; the shared
//! [`UiState`] is only ever read as an immutable snapshot.

use std::io::{self, Stdout, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::cursor::{Hide, Show};
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Gauge, Paragraph, Row, Table, TableState, Wrap,
};
use ratatui::{Frame, Terminal};
use tokio::sync::RwLock;

use crate::state::{
    human_bytes, now_hms, Command, DownloadState, FilePriority, FileSummary, Level, LogEntry, PeerSummary,
    SessionCommand, SessionState, Settings, TorrentId, TorrentSummary, TorrentView, UiState,
};

/// Narrowest terminal the full layout is attempted in.
const MIN_WIDTH: u16 = 40;
/// Shortest terminal the full layout is attempted in.
const MIN_HEIGHT: u16 = 12;

/// Rows taken by the header block.
const HEADER_ROWS: u16 = 3;

/// Redraw cadence. Input is polled with this as the timeout, so the screen keeps
/// refreshing (progress, rates, clock, log tail) even while the user is idle.
const TICK: Duration = Duration::from_millis(100);

/// Hex characters kept from the infohash in the header.
const HASH_ABBREV: usize = 12;

/// Key bindings advertised in the footer and in the help overlay.
const KEYS: [(&str, &str); 8] = [
    ("q", "quit"),
    ("tab", "panel"),
    ("j/k", "move"),
    ("space", "skip file"),
    ("p", "pause"),
    ("PgUp/PgDn", "log"),
    ("?", "keys"),
    ("r", "redraw"),
];

// ---------------------------------------------------------------------------
// Palette
// ---------------------------------------------------------------------------

fn base_style() -> Style {
    Style::default().bg(Color::Black)
}

fn border_style() -> Style {
    Style::default().fg(Color::DarkGray)
}

/// Headings, labels and key hints.
fn heading_style() -> Style {
    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
}

fn value_style() -> Style {
    Style::default().fg(Color::White)
}

fn good_style() -> Style {
    Style::default().fg(Color::Green)
}

fn warn_style() -> Style {
    Style::default().fg(Color::Yellow)
}

fn error_style() -> Style {
    Style::default().fg(Color::Red)
}

fn muted_style() -> Style {
    Style::default().fg(Color::DarkGray)
}

fn selection_style() -> Style {
    Style::default()
        .bg(Color::DarkGray)
        .fg(Color::White)
        .add_modifier(Modifier::BOLD)
}

/// Colour for a log level: errors red, warnings yellow, info green, and the
/// chatty levels dimmed out so real problems stand out.
fn level_style(level: Level) -> Style {
    match level {
        Level::Error => error_style(),
        Level::Warn => warn_style(),
        Level::Info => good_style(),
        Level::Debug => muted_style(),
        Level::Trace => muted_style().add_modifier(Modifier::DIM),
    }
}

/// Colour for the torrent state shown in the header.
fn state_style(state: DownloadState) -> Style {
    match state {
        DownloadState::Complete | DownloadState::Seeding => good_style(),
        DownloadState::Error => error_style(),
        DownloadState::Paused => warn_style(),
        DownloadState::Stopped => muted_style(),
        DownloadState::Queued => Style::default().fg(Color::LightBlue),
        DownloadState::Checking => warn_style(),
        _ => heading_style(),
    }
}

// ---------------------------------------------------------------------------
// Pure formatting helpers (unit-tested below)
// ---------------------------------------------------------------------------

/// Clamp an arbitrary `f64` into the `0.0..=1.0` range a progress widget can
/// display. `NaN` collapses to zero rather than poisoning a layout.
fn clamp_ratio(ratio: f64) -> f64 {
    if ratio.is_nan() {
        0.0
    } else {
        ratio.clamp(0.0, 1.0)
    }
}

/// Render a ratio as a one-decimal percentage.
fn percent(ratio: f64) -> String {
    format!("{:.1}%", clamp_ratio(ratio) * 100.0)
}

/// First [`HASH_ABBREV`] characters of an infohash, ellipsised if longer.
///
/// An infohash is always a run of hex digits, so anything else is reported as
/// unknown rather than partially rendered. This also keeps the slice on a
/// character boundary for malformed input.
fn abbrev_hash(hash: &str) -> String {
    let trimmed = hash.trim();
    let is_hex = |c: char| c.is_ascii_hexdigit();
    if trimmed.is_empty() || !trimmed.chars().all(is_hex) {
        return "(unknown)".to_string();
    }
    let hex: String = trimmed.chars().take(HASH_ABBREV).collect();
    if hex.chars().count() < HASH_ABBREV {
        hex
    } else {
        format!("{hex}\u{2026}")
    }
}

/// Fit `text` into `width` cells, replacing control characters with spaces and
/// marking truncation with a single-cell ellipsis.
fn truncate_line(text: &str, width: usize) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if width == 0 {
        return String::new();
    }
    if cleaned.chars().count() <= width {
        return cleaned;
    }
    let mut out: String = cleaned.chars().take(width - 1).collect();
    out.push('\u{2026}');
    out
}

/// Compact flag letters for a peer.
///
/// First slot is *our* choke state (`\u{2191}` when we are choking them), second
/// is *their* choke state (`\u{2191}` when they are choking us), and `*` marks
/// blocks we still have outstanding with that peer.
fn peer_flags(peer: &PeerSummary) -> String {
    let mut flags = String::with_capacity(3);
    flags.push(if peer.choked_by_us { '\u{2191}' } else { '\u{2193}' });
    flags.push(if peer.choking_us { '\u{2191}' } else { '\u{2193}' });
    if peer.outstanding > 0 {
        flags.push('*');
    }
    flags
}

/// The five cells of a peer table row, in column order.
fn peer_cells(peer: &PeerSummary) -> [String; 5] {
    [
        peer.addr.clone(),
        human_bytes(peer.downloaded),
        human_bytes(peer.uploaded),
        percent(peer.progress),
        peer_flags(peer),
    ]
}

/// The four cells of a file table row, in column order: path, size, progress
/// bar, and priority.
fn file_cells(file: &FileSummary, bar_width: usize) -> [String; 4] {
    [
        file.path.clone(),
        file.human_size(),
        file_bar(file.progress(), bar_width),
        file.priority.label().to_string(),
    ]
}

/// A fixed-width text progress bar, e.g. `[####------] 42%`.
fn file_bar(ratio: f64, width: usize) -> String {
    let width = width.max(8);
    // Reserve room for the brackets, a space, and "100%".
    let bar = width.saturating_sub(8).max(1);
    let filled = (clamp_ratio(ratio) * bar as f64).round() as usize;
    format!(
        "[{}{}] {}",
        "#".repeat(filled),
        "-".repeat(bar - filled),
        percent(ratio)
    )
}

/// Peers ordered by bytes received, most productive first. Ties fall back to
/// address so the table does not shuffle between frames.
fn sort_peers(peers: &[PeerSummary]) -> Vec<PeerSummary> {
    let mut sorted = peers.to_vec();
    sorted.sort_by(|a, b| {
        b.downloaded
            .cmp(&a.downloaded)
            .then_with(|| a.addr.cmp(&b.addr))
    });
    sorted
}

/// Rows the log panel gets on a terminal `total` rows tall: about 30% of the
/// screen, clamped to a range that is still worth drawing.
fn log_height(total: u16) -> u16 {
    let share = (u32::from(total) * 30) / 100;
    share.clamp(3, 8) as u16
}

/// Height at which the full progress section still leaves room for the peers
/// table and the log.
const ROOMY_HEIGHT: u16 = 18;

/// Rows the progress section takes with every stat row shown: a gauge plus a
/// bordered block holding six stats.
const PROGRESS_ROWS_FULL: u16 = 9;

/// Rows the progress section takes: a gauge plus a bordered stats block. On a
/// short terminal [`stat_lines`] drops to its compact form and saves two rows.
fn progress_rows(height: u16) -> u16 {
    if height >= ROOMY_HEIGHT {
        PROGRESS_ROWS_FULL
    } else {
        PROGRESS_ROWS_FULL - 2
    }
}

/// The slice of `log` visible in a `height`-row window that has been scrolled
/// `scroll` rows up from the bottom. `scroll == 0` pins to the newest entry.
fn log_window(log: &[LogEntry], height: usize, scroll: usize) -> &[LogEntry] {
    if log.is_empty() || height == 0 {
        return &[];
    }
    let height = height.min(log.len());
    let max_scroll = log.len() - height;
    let end = log.len() - scroll.min(max_scroll);
    &log[end - height..end]
}

/// Newest-first-of-nothing clamp: keep the selection inside the row count.
fn clamp_selection(selected: Option<usize>, len: usize) -> Option<usize> {
    if len == 0 {
        None
    } else {
        Some(selected.unwrap_or(0).min(len - 1))
    }
}

/// Move the selection by `delta` rows, sticking at either end.
///
/// With nothing selected a downward move lands on the first row rather than
/// skipping past it.
fn move_selection(selected: Option<usize>, len: usize, delta: isize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let current = match selected {
        Some(index) => index as isize,
        None => -1,
    };
    let next = (current + delta).clamp(0, len as isize - 1);
    Some(next as usize)
}

/// Clamp a log scroll offset to the available history. A positive `delta`
/// scrolls towards older entries, a negative one back towards the newest.
///
/// The result is always in `0..=total - height`, so it is always a valid
/// window into the buffer regardless of how the user got there.
fn scroll_log(current: usize, total: usize, height: usize, delta: isize) -> usize {
    let max_scroll = total.saturating_sub(height);
    if max_scroll == 0 {
        return 0;
    }
    let moved = if delta >= 0 {
        current.saturating_add(delta as usize)
    } else {
        current.saturating_sub(delta.unsigned_abs())
    };
    moved.min(max_scroll)
}

/// Adjust a table scroll offset so the selected row stays on screen.
fn ensure_visible(offset: usize, selected: Option<usize>, visible: usize, total: usize) -> usize {
    if visible == 0 {
        return 0;
    }
    let max_offset = total.saturating_sub(visible);
    let mut off = offset.min(max_offset);
    if let Some(sel) = selected {
        if sel < off {
            off = sel;
        } else if sel >= off + visible {
            off = sel + 1 - visible;
        }
    }
    off.min(max_offset)
}

/// A `label`/`value` row with the label padded into a fixed gutter.
fn kv(label: &str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<12}"), heading_style()),
        Span::styled(value, value_style()),
    ])
}

/// The progress-section rows, given the peers we are currently connected to.
///
/// `compact` drops the two secondary rows so the block still fits on a short
/// terminal; the numbers that matter while downloading are kept.
fn stat_lines(torrent: &TorrentSummary, connected: usize, compact: bool) -> Vec<Line<'static>> {
    let ratio = if torrent.total_length > 0 {
        torrent.downloaded as f64 / torrent.total_length as f64
    } else {
        0.0
    };
    let upload = format!("{}/s", human_bytes(torrent.upload_rate as u64));
    let mut lines = vec![
        kv(
            "Downloaded",
            format!(
                "{} / {} ({})",
                torrent.human_downloaded(),
                torrent.human_size(),
                percent(ratio)
            ),
        ),
        kv(
            "Speed",
            format!("\u{2193} {}   \u{2191} {}", torrent.human_rate(), upload),
        ),
        kv("ETA", torrent.human_eta()),
        kv(
            "Pieces",
            format!(
                "{} / {}   (piece {})",
                torrent.verified_pieces,
                torrent.piece_count,
                human_bytes(u64::from(torrent.piece_length))
            ),
        ),
    ];
    if !compact {
        lines.push(kv(
            "Peers",
            format!(
                "{connected} connected   ({} seeders, {} leechers)",
                torrent.seeders_known, torrent.leecher_known
            ),
        ));
        lines.push(kv("Save to", torrent.download_dir.clone()));
    }
    lines
}

/// A stand-in used before metadata arrives, which is the normal state for a
/// magnet link at startup.
fn placeholder_torrent() -> TorrentSummary {
    TorrentSummary {
        name: "(fetching metadata...)".to_string(),
        ..TorrentSummary::default()
    }
}

/// The torrent to render, or a placeholder when `None`.
fn torrent_or_placeholder(torrent: Option<&TorrentSummary>) -> TorrentSummary {
    match torrent {
        Some(t) => t.clone(),
        None => placeholder_torrent(),
    }
}

/// Footer key hints, with the clock right-aligned when there is room for it.
fn bindings_line(width: u16) -> Line<'static> {
    keys_line(&KEYS, width)
}

/// Footer hints for an arbitrary key list; shared by both screens.
fn keys_line(keys: &[(&'static str, &'static str)], width: u16) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut used = 0usize;
    for (i, (key, desc)) in keys.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
            used += 2;
        }
        spans.push(Span::styled(*key, heading_style()));
        spans.push(Span::raw(format!(" {desc}")));
        used += key.chars().count() + 1 + desc.chars().count();
    }
    let clock = now_hms();
    let clock_len = clock.chars().count();
    let total = usize::from(width);
    if total > used + clock_len + 2 {
        spans.push(Span::raw(" ".repeat(total - used - clock_len)));
        spans.push(Span::styled(clock, muted_style()));
    }
    Line::from(spans)
}

/// A rectangle `px`% wide and `py`% tall, centred inside `area`.
///
/// The result is always contained by `area`, even for percentages above 100, so
/// a caller can never render outside the frame it was handed.
fn centered_rect(px: u16, py: u16, area: Rect) -> Rect {
    let width = (area.width.saturating_mul(px) / 100).min(area.width);
    let height = (area.height.saturating_mul(py) / 100).min(area.height);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

/// Placeholder shown when the terminal cannot fit the layout at all.
fn too_small_message() -> String {
    format!("terminal too small \u{2014} need at least {MIN_WIDTH}x{MIN_HEIGHT}")
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Everything the render loop carries between frames. Purely view state; the
/// download itself lives behind the shared [`UiState`].
/// Which table the movement keys currently drive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Focus {
    #[default]
    Peers,
    Files,
}

impl Focus {
    fn next(self) -> Focus {
        match self {
            Focus::Peers => Focus::Files,
            Focus::Files => Focus::Peers,
        }
    }
}

#[derive(Default)]
struct App {
    peers: Vec<PeerSummary>,
    selected: Option<usize>,
    offset: usize,
    files: Vec<FileSummary>,
    file_selected: Option<usize>,
    file_offset: usize,
    focus: Focus,
    /// Mirrors `torrent.state == Paused` so `p` knows which command to send.
    paused: bool,
    /// Channel into the engine. Absent before the engine starts (and in
    /// tests); control keys are inert while it is.
    cmd: Option<tokio::sync::mpsc::UnboundedSender<Command>>,
    log_scroll: usize,
    /// Size of the log buffer and of the visible window, as of the last frame.
    /// Key handling needs them to keep the scroll offset valid.
    log_total: usize,
    log_visible: usize,
    show_help: bool,
    quit: bool,
    redraw: bool,
}

impl App {
    /// Apply a key press. `key` is expected to already be filtered to Press or
    /// Repeat events.
    fn on_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => self.quit = true,
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::Char('p') => self.send(if self.paused {
                Command::Resume
            } else {
                Command::Pause
            }),
            // Space skips (or re-wants) the highlighted file. The stable file
            // *index* goes over the wire, not the row number, so a resort can
            // never retarget the command.
            KeyCode::Char(' ') if self.focus == Focus::Files => {
                if let Some(f) = self.file_selected.and_then(|s| self.files.get(s)) {
                    self.send(Command::ToggleFile(f.index));
                }
            }
            KeyCode::Char('j') | KeyCode::Down => match self.focus {
                Focus::Peers => {
                    self.selected = move_selection(self.selected, self.peers.len(), 1);
                }
                Focus::Files => {
                    self.file_selected =
                        move_selection(self.file_selected, self.files.len(), 1);
                }
            },
            KeyCode::Char('k') | KeyCode::Up => match self.focus {
                Focus::Peers => {
                    self.selected = move_selection(self.selected, self.peers.len(), -1);
                }
                Focus::Files => {
                    self.file_selected =
                        move_selection(self.file_selected, self.files.len(), -1);
                }
            },
            KeyCode::PageDown => self.page_log(5),
            KeyCode::PageUp => self.page_log(-5),
            KeyCode::Home => self.log_scroll = 0,
            KeyCode::End => self.page_log(isize::MAX),
            KeyCode::Char('?') => self.show_help = !self.show_help,
            KeyCode::Char('r') => self.redraw = true,
            _ => {}
        }
    }

    /// Send a command to the engine, if the channel exists. Never blocks and
    /// never panics: without a channel (tests, pre-engine frames) the key is
    /// simply inert.
    fn send(&self, cmd: Command) {
        if let Some(tx) = &self.cmd {
            let _ = tx.send(cmd);
        }
    }

    /// Scroll the log window by `delta` rows (positive means towards older
    /// entries), clamped to the history that actually exists.
    fn page_log(&mut self, delta: isize) {
        self.log_scroll = scroll_log(self.log_scroll, self.log_total, self.log_visible, delta);
    }

    /// Re-clamp the log scroll: the buffer is trimmed at 500 entries and a
    /// resize can shrink the window, either of which can invalidate the offset.
    fn clamp_log(&mut self, total: usize, height: usize) {
        self.log_total = total;
        self.log_visible = height;
        self.log_scroll = scroll_log(self.log_scroll, total, height, 0);
    }
}

/// A view of the shared state, or the reason we could not obtain one.
enum Snapshot {
    State(UiState),
    Error(String),
}

// ---------------------------------------------------------------------------
// Terminal setup / teardown
// ---------------------------------------------------------------------------

/// Restores the terminal on drop, so a panic or an early `?` can never leave
/// the user staring at a raw-mode alternate screen.
struct TerminalGuard;

impl TerminalGuard {
    fn restore() {
        let mut out = io::stdout();
        let _ = execute!(out, DisableBracketedPaste, LeaveAlternateScreen, Show);
        let _ = disable_raw_mode();
        let _ = out.flush();
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        Self::restore();
    }
}

/// Switch to the alternate screen and raw mode.
///
/// The guard is constructed *first* so that any failure below still puts the
/// terminal back the way we found it; it is returned to the caller, which keeps
/// it alive for as long as the terminal is in use.
fn setup_terminal() -> Result<(Terminal<CrosstermBackend<Stdout>>, TerminalGuard)> {
    let guard = TerminalGuard;
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen, Hide).context("failed to enter the alternate screen")?;
    let terminal = Terminal::new(CrosstermBackend::new(out)).context("failed to create terminal")?;
    Ok((terminal, guard))
}

/// Clone the shared state for rendering.
///
/// The read is deliberately non-blocking: the engine only holds the write lock
/// while it clones a snapshot, so a `try_read` succeeds on essentially every
/// frame and keeps the render loop on a steady budget. If it ever fails we
/// report the reason on screen rather than unwinding out of the UI thread.
fn read_state(state: &Arc<RwLock<UiState>>) -> Snapshot {
    match state.try_read() {
        Ok(guard) => Snapshot::State(guard.clone()),
        Err(err) => Snapshot::Error(format!("session state unavailable: {err}")),
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Paint one frame.
fn render(frame: &mut Frame, snapshot: &Snapshot, app: &mut App) {
    let area = frame.area();
    // A zero-sized terminal (detached pty, mid-resize) has nothing to paint.
    if area.width == 0 || area.height == 0 {
        return;
    }
    // Base fill: covers every cell so nothing stale can survive a redraw.
    frame.render_widget(Block::default().style(base_style()), area);

    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(frame, area);
        return;
    }

    let state = match snapshot {
        Snapshot::State(state) => state,
        Snapshot::Error(message) => {
            render_error(frame, area, message);
            return;
        }
    };

    let torrent = torrent_or_placeholder(state.torrent.as_ref());

    let footer_rows = if state.warning.is_some() { 2 } else { 1 };
    let log_rows = log_height(area.height);
    let progress_rows = progress_rows(area.height);
    // The files panel is collapsible: absent for single-file torrents and
    // before metadata arrives, capped so a torrent with hundreds of files
    // cannot squeeze the peers table out.
    let file_rows: u16 = if torrent.files.is_empty() {
        0
    } else {
        (torrent.files.len().min(8) as u16 + 2).min(10)
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(HEADER_ROWS),
            Constraint::Length(progress_rows),
            Constraint::Min(0),
            Constraint::Length(file_rows),
            Constraint::Length(log_rows),
            Constraint::Length(footer_rows),
        ])
        .split(area);

    render_header(frame, chunks[0], &torrent);
    render_progress(
        frame,
        chunks[1],
        &torrent,
        state.peers.len(),
        progress_rows < PROGRESS_ROWS_FULL,
    );

    // Refresh the view-model peers, then render the table against them.
    app.peers = sort_peers(&state.peers);
    app.selected = clamp_selection(app.selected, app.peers.len());
    // Files stay in torrent order: the stable index each row carries is what
    // toggle commands refer to, so a resort must never reorder them.
    app.files = torrent.files.clone();
    app.file_selected = clamp_selection(app.file_selected, app.files.len());
    app.paused = matches!(torrent.state, DownloadState::Paused);
    if app.cmd.is_none() {
        app.cmd = state.command_tx.clone();
    }
    render_peers(frame, chunks[2], app, app.focus == Focus::Peers);
    render_files(frame, chunks[3], app, app.focus == Focus::Files);

    render_log(frame, chunks[4], &state.log, "log", app);
    render_footer(frame, chunks[5], state.warning.as_deref(), &KEYS);

    if app.show_help {
        render_help(frame, area, &KEYS, (50, 60));
    }
}

fn render_header(frame: &mut Frame, area: Rect, torrent: &TorrentSummary) {
    let inner_width = usize::from(area.width.saturating_sub(2));
    let title = truncate_line(&torrent.name, inner_width.saturating_sub(4).max(1));
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style())
        .style(base_style())
        .title(Span::styled(
            format!(" {title} "),
            heading_style(),
        ));

    let hash = abbrev_hash(&torrent.infohash);
    let label = torrent.state.label();
    let gap = inner_width
        .saturating_sub(hash.chars().count() + label.chars().count())
        .max(1);

    let line = Line::from(vec![
        Span::styled(hash, muted_style()),
        Span::raw(" ".repeat(gap)),
        Span::styled(label, state_style(torrent.state)),
    ]);
    frame.render_widget(Paragraph::new(Text::from(line)).block(block), area);
}

fn render_progress(
    frame: &mut Frame,
    area: Rect,
    torrent: &TorrentSummary,
    connected: usize,
    compact: bool,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    let ratio = clamp_ratio(torrent.progress);
    let gauge_label = format!(
        " {:.1}%   {}/{} ",
        ratio * 100.0,
        torrent.human_downloaded(),
        torrent.human_size()
    );
    frame.render_widget(
        Gauge::default()
            .ratio(ratio)
            .gauge_style(
                Style::default()
                    .fg(Color::Green)
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .label(Span::styled(gauge_label, Style::default().fg(Color::White))),
        rows[0],
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style())
        .style(base_style())
        .title(Span::styled(" transfer ", heading_style()));
    frame.render_widget(
        Paragraph::new(Text::from(stat_lines(torrent, connected, compact)))
            .block(block)
            .wrap(Wrap { trim: false }),
        rows[1],
    );
}

fn render_peers(frame: &mut Frame, area: Rect, app: &mut App, focused: bool) {
    let inner_width = area.width.saturating_sub(2);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style())
        .style(base_style())
        .title(Span::styled(
            if focused { " peers ● " } else { " peers " },
            heading_style(),
        ));
    let inner_height = area.height.saturating_sub(3); // borders + header row

    let header = Row::new(vec![
        Cell::from("Address"),
        Cell::from("DL"),
        Cell::from("UP"),
        Cell::from("Progress"),
        Cell::from("Flags"),
    ])
    .style(heading_style());

    let rows: Vec<Row> = if app.peers.is_empty() {
        vec![Row::new(vec![
            Cell::from("no peers connected"),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
        ])
        .style(muted_style())]
    } else {
        app.peers
            .iter()
            .map(|peer| {
                // Destructured so each owned cell can be moved into its own
                // `Cell` without cloning.
                let [addr, down, up, progress, flags] = peer_cells(peer);
                Row::new(vec![
                    Cell::from(truncate_line(&addr, usize::from(inner_width))),
                    Cell::from(down),
                    Cell::from(up),
                    Cell::from(progress),
                    Cell::from(flags),
                ])
            })
            .collect()
    };

    let widths = [
        Constraint::Min(18),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(9),
        Constraint::Length(6),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .column_spacing(1)
        .row_highlight_style(selection_style())
        .highlight_symbol("> ");

    app.offset = ensure_visible(
        app.offset,
        app.selected,
        usize::from(inner_height),
        app.peers.len(),
    );

    let mut table_state = TableState::new()
        .with_selected(app.selected.filter(|_| focused))
        .with_offset(app.offset);
    frame.render_stateful_widget(table, area, &mut table_state);
}

/// Per-file progress table. Skipped files render dimmed; the focused panel
/// gets the selection highlight. The row order is always torrent order so the
/// stable file index behind each row is what toggle commands refer to.
fn render_files(frame: &mut Frame, area: Rect, app: &mut App, focused: bool) {
    if area.height == 0 {
        return;
    }
    let inner_width = usize::from(area.width.saturating_sub(2));
    // Path | size | bar | priority columns; the bar takes what is left.
    let bar_width = inner_width.saturating_sub(55).max(10);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style())
        .style(base_style())
        .title(Span::styled(
            if focused { " files ● " } else { " files " },
            heading_style(),
        ));
    let inner_height = area.height.saturating_sub(3);

    let header = Row::new(vec![
        Cell::from("File"),
        Cell::from("Size"),
        Cell::from("Progress"),
        Cell::from("Priority"),
    ])
    .style(heading_style());

    let rows: Vec<Row> = app
        .files
        .iter()
        .map(|file| {
            let [path, size, progress, priority] = file_cells(file, bar_width);
            let row = Row::new(vec![
                Cell::from(truncate_line(&path, inner_width)),
                Cell::from(size),
                Cell::from(progress),
                Cell::from(priority),
            ]);
            if file.wanted {
                row
            } else {
                row.style(muted_style())
            }
        })
        .collect();

    let widths = [
        Constraint::Min(16),
        Constraint::Length(10),
        Constraint::Length(bar_width.min(40) as u16),
        Constraint::Length(8),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .column_spacing(1)
        .row_highlight_style(selection_style())
        .highlight_symbol("> ");

    app.file_offset = ensure_visible(
        app.file_offset,
        app.file_selected,
        usize::from(inner_height),
        app.files.len(),
    );

    let mut table_state = TableState::new()
        .with_selected(app.file_selected.filter(|_| focused))
        .with_offset(app.file_offset);
    frame.render_stateful_widget(table, area, &mut table_state);
}

/// Render the tail of the log, scrolling back through history when the user has
/// paged up. The scroll offset is clamped here because this is the first place
/// both the buffer size and the visible height are known.
fn render_log(frame: &mut Frame, area: Rect, log: &[LogEntry], label: &str, app: &mut App) {
    let inner_width = usize::from(area.width.saturating_sub(2));
    let inner_height = usize::from(area.height.saturating_sub(2));

    // The buffer only ever shrinks when it is trimmed at 500 entries, but a
    // resize can also shrink the window under us.
    app.clamp_log(log.len(), inner_height);
    let visible = log_window(log, inner_height, app.log_scroll);
    let end = log.len() - app.log_scroll.min(log.len());
    let start = end.saturating_sub(visible.len());

    let lines: Vec<Line> = visible
        .iter()
        .map(|entry: &LogEntry| {
            Line::from(vec![
                Span::styled(
                    format!("{:>5} ", entry.level.label()),
                    level_style(entry.level),
                ),
                Span::styled(
                    truncate_line(&entry.message, inner_width.saturating_sub(6)),
                    value_style(),
                ),
            ])
        })
        .collect();

    let title = if log.is_empty() {
        format!(" {label} ")
    } else {
        format!(" {label} {}-{}/{} ", start + 1, end, log.len())
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style())
        .style(base_style())
        .title(Span::styled(title, heading_style()));
    frame.render_widget(Paragraph::new(Text::from(lines)).block(block), area);
}

fn render_footer(frame: &mut Frame, area: Rect, warning: Option<&str>, keys: &[(&'static str, &'static str)]) {
    let mut lines: Vec<Line> = Vec::new();
    if let Some(message) = warning {
        let text = truncate_line(message, usize::from(area.width).saturating_sub(2));
        lines.push(Line::from(vec![
            Span::styled(" ! ", warn_style().add_modifier(Modifier::BOLD)),
            Span::styled(text, warn_style()),
        ]));
    }
    lines.push(keys_line(keys, area.width));
    frame.render_widget(Paragraph::new(Text::from(lines)), area);
}

fn render_help(frame: &mut Frame, area: Rect, keys: &[(&str, &str)], size: (u16, u16)) {
    let mut lines: Vec<Line> = vec![Line::from(Span::styled("Keys", heading_style()))];
    for (key, desc) in keys.iter() {
        lines.push(Line::from(vec![
            Span::styled(format!("  {key:<12}"), heading_style()),
            Span::raw(*desc),
        ]));
    }
    lines.push(Line::from(Span::raw("")));
    lines.push(Line::from(Span::styled(
        "q, Esc or Ctrl-C to quit",
        muted_style(),
    )));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(heading_style())
        .style(base_style())
        .title(Span::styled(" help ", heading_style()));

    let popup = centered_rect(size.0, size.1, area);
    frame.render_widget(Clear, popup);
    frame.render_widget(Paragraph::new(Text::from(lines)).block(block), popup);
}

fn render_too_small(frame: &mut Frame, area: Rect) {
    let message = too_small_message();
    let row = Rect {
        x: area.x,
        y: area.y + area.height.saturating_sub(1) / 2,
        width: area.width,
        height: 1,
    };
    frame.render_widget(
        Paragraph::new(Span::styled(message, warn_style())).alignment(Alignment::Center),
        row,
    );
}

fn render_error(frame: &mut Frame, area: Rect, message: &str) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(error_style())
        .style(base_style())
        .title(Span::styled(" session error ", error_style()));
    let inner_width = usize::from(area.width.saturating_sub(2));
    frame.render_widget(
        Paragraph::new(Text::from(vec![
            Line::from(Span::styled(
                truncate_line(message, inner_width),
                error_style(),
            )),
            Line::from(Span::raw("")),
            bindings_line(area.width),
        ]))
        .block(block),
        area,
    );
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

/// Drive the UI until the user quits.
fn run_loop(state: Arc<RwLock<UiState>>) -> Result<()> {
    let (mut terminal, _guard) = setup_terminal()?;
    terminal.clear().context("failed to clear the terminal")?;

    let mut app = App::default();
    'frames: loop {
        let snapshot = read_state(&state);
        terminal
            .draw(|frame| render(frame, &snapshot, &mut app))
            .context("failed to draw a frame")?;

        // Quit on user request, or when the engine signals shutdown. The
        // shutdown path must go through here (not process exit) so the
        // terminal guard below restores the console instead of leaving the
        // last frame frozen on screen.
        let shutdown = matches!(&snapshot, Snapshot::State(s) if s.shutdown);
        if app.quit || shutdown {
            break;
        }
        if app.redraw {
            // 'r' skips the poll so the repaint happens immediately.
            app.redraw = false;
            continue 'frames;
        }

        let polled = event::poll(TICK).context("failed to poll terminal events")?;
        if !polled {
            continue 'frames;
        }
        match event::read().context("failed to read a terminal event")? {
            Event::Key(key) if key.kind != KeyEventKind::Release => app.on_key(key),
            // Resizes need no special handling: every frame recomputes its
            // layout from the live terminal area, so nothing is cached.
            _ => {}
        }
    }

    Ok(())
}

/// Run the terminal UI until the user quits.
///
/// Blocks the calling thread. The terminal is restored before returning, on
/// both the normal path and on error.
pub fn run_tui(state: Arc<RwLock<UiState>>) -> Result<()> {
    std::thread::Builder::new()
        .name("torrust-tui".to_string())
        .spawn(move || run_loop(state))
        .context("failed to spawn the TUI thread")?
        .join()
        .map_err(|_| anyhow::anyhow!("the TUI thread panicked"))?
}

// ---------------------------------------------------------------------------
// Session screen (many torrents)
// ---------------------------------------------------------------------------

/// Key bindings advertised in the session footer and help overlay. The most
/// used keys come first because the footer is clipped on narrow terminals.
const SESSION_KEYS: [(&str, &str); 17] = [
    ("a", "add"),
    ("s", "start/stop"),
    ("p", "pause"),
    ("d", "remove"),
    ("l", "limits"),
    ("o", "settings"),
    ("R", "force recheck"),
    ("[ / ]", "queue up/down"),
    ("tab/1-6", "panel"),
    ("j/k", "torrents"),
    ("J/K", "files"),
    ("space", "skip file"),
    ("+ / -", "file priority"),
    ("PgUp/PgDn", "log"),
    ("?", "keys"),
    ("q", "quit"),
    ("Enter/Esc", "confirm/cancel"),
];

/// Footer hints: the global keys only; the modal keys live in the help overlay.
const SESSION_FOOTER_KEYS: [(&str, &str); 11] = [
    ("a", "add"),
    ("s", "start/stop"),
    ("p", "pause"),
    ("d", "remove"),
    ("?", "keys"),
    ("q", "quit"),
    ("R", "recheck"),
    ("[/]", "queue"),
    ("l", "limits"),
    ("o", "settings"),
    ("tab", "panel"),
];

/// Text shown in the torrent table while the session holds nothing.
const EMPTY_MESSAGE: &str = "No torrents \u{2014} press a to add one";

/// Name shown before a magnet link has produced metadata.
const PENDING_NAME: &str = "(fetching metadata...)";

/// Compact byte count for table cells, e.g. `1.4G`, `523K`, `12B`.
fn compact_bytes(n: u64) -> String {
    const UNITS: [char; 5] = ['K', 'M', 'G', 'T', 'P'];
    if n < 1024 {
        return format!("{n}B");
    }
    let mut v = n as f64 / 1024.0;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v < 10.0 {
        format!("{v:.1}{}", UNITS[i])
    } else {
        format!("{v:.0}{}", UNITS[i])
    }
}

/// A rate for a table cell; idle is a dash so busy rows stand out.
fn compact_rate(rate: f64) -> String {
    if !rate.is_finite() || rate < 1.0 {
        "-".to_string()
    } else {
        format!("{}/s", compact_bytes(rate as u64))
    }
}

/// ETA for a table cell: `1h04m`, `4m09s`, `09s`, or `--` without an estimate.
fn compact_eta(eta: Option<f64>) -> String {
    let secs = match eta {
        Some(s) if s.is_finite() && s > 0.0 => s.round() as u64,
        _ => return "--".to_string(),
    };
    if secs >= 86_400 {
        format!("{}d{:02}h", secs / 86_400, (secs % 86_400) / 3600)
    } else if secs >= 3600 {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

/// A byte-per-second cap as shown to the user; 0 is unlimited.
fn limit_label(bytes: u64) -> String {
    if bytes == 0 {
        "unlimited".to_string()
    } else {
        format!("{}/s", human_bytes(bytes))
    }
}

fn view_state(view: &TorrentView) -> DownloadState {
    view.ui
        .torrent
        .as_ref()
        .map(|t| t.state)
        .unwrap_or(DownloadState::Connecting)
}

fn view_name(view: &TorrentView) -> String {
    match view.ui.torrent.as_ref() {
        Some(t) if !t.name.is_empty() => t.name.clone(),
        _ => PENDING_NAME.to_string(),
    }
}

const TABLE_HEADERS: [&str; 10] = [
    "#", "Name", "Size", "Done", "Status", "\u{2193}", "\u{2191}", "ETA", "Peers", "Ratio",
];

/// Queue number for the `#` column: 1-based, blank for a stopped torrent.
fn queue_cell(view: &TorrentView) -> String {
    view.queue_position.map(|p| (p + 1).to_string()).unwrap_or_default()
}

/// Peers cell: connected peers, then the tracker-reported swarm as
/// `(seeders/leechers)`, e.g. `3 (41/12)`.
fn swarm_cell(view: &TorrentView) -> String {
    let connected = view.ui.peers.len();
    match view.ui.torrent.as_ref() {
        Some(t) => format!("{connected} ({}/{})", t.seeders_known, t.leecher_known),
        None => connected.to_string(),
    }
}

/// The ten cells of a torrent table row, in [`TABLE_HEADERS`] order.
fn torrent_cells(view: &TorrentView) -> [String; 10] {
    let summary = view.ui.torrent.as_ref();
    let size = match summary {
        Some(t) if t.total_length > 0 => compact_bytes(t.total_length),
        _ => "?".to_string(),
    };
    [
        queue_cell(view),
        view_name(view),
        size,
        percent(summary.map(|t| t.progress).unwrap_or(0.0)),
        view_state(view).label().to_string(),
        compact_rate(summary.map(|t| t.download_rate).unwrap_or(0.0)),
        compact_rate(summary.map(|t| t.upload_rate).unwrap_or(0.0)),
        compact_eta(summary.and_then(|t| t.eta_secs)),
        swarm_cell(view),
        format!("{:.2}", view.ratio),
    ]
}

/// Which table columns fit in `width` cells. Narrow terminals drop the
/// secondary columns (size, ETA, peers, ratio) rather than crushing the name.
fn visible_columns(width: u16) -> &'static [usize] {
    if width >= 80 {
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    } else if width >= 56 {
        &[0, 1, 3, 4, 5, 6]
    } else {
        &[0, 1, 3, 5]
    }
}

fn column_width(column: usize) -> Constraint {
    match column {
        0 => Constraint::Length(3),
        1 => Constraint::Min(8),
        2 => Constraint::Length(5),
        3 => Constraint::Length(6),
        4 => Constraint::Length(11),
        5 | 6 => Constraint::Length(7),
        7 => Constraint::Length(6),
        8 => Constraint::Length(9),
        _ => Constraint::Length(5),
    }
}

/// Rows the torrent table takes out of `body` rows: enough for every torrent
/// plus borders and header, but never more than ~45% so the detail panel
/// keeps room, and never so few that a row cannot be seen.
fn table_rows(torrents: usize, body: u16) -> u16 {
    let wanted = u16::try_from(torrents).unwrap_or(u16::MAX).saturating_add(3);
    wanted.min(body * 45 / 100).max(4).min(body)
}

/// One-line session summary for the header.
fn header_summary(state: &SessionState) -> String {
    let mut text = format!(
        "{} torrent{}  \u{2193} {}/s  \u{2191} {}/s",
        state.torrents.len(),
        if state.torrents.len() == 1 { "" } else { "s" },
        human_bytes(state.download_rate.max(0.0) as u64),
        human_bytes(state.upload_rate.max(0.0) as u64),
    );
    if !state.port_status.is_empty() {
        text.push_str("  ");
        text.push_str(&state.port_status);
    }
    text
}

/// Keep the selection on the same torrent across refreshes.
///
/// The list can grow or shrink under the user, so the row number alone would
/// silently retarget `d` or `s` onto a different torrent. If the selected id is
/// gone the old row position is kept (clamped), which lands on the torrent that
/// slid into its place.
fn reselect(prev_id: Option<&str>, prev_index: Option<usize>, ids: &[&str]) -> Option<usize> {
    if let Some(id) = prev_id {
        if let Some(pos) = ids.iter().position(|candidate| *candidate == id) {
            return Some(pos);
        }
    }
    clamp_selection(prev_index, ids.len())
}

/// Show the end of `text` within `width` cells, so the cursor end of a long
/// path stays visible while typing.
fn tail_fit(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let tail: String = text.chars().skip(count - (width - 1)).collect();
    format!("\u{2026}{tail}")
}

/// Strip whitespace and the quotes a terminal adds when a file is dragged in.
fn clean_input(text: &str) -> String {
    text.trim().trim_matches(['"', '\'']).trim().to_string()
}

/// A single-line text buffer. The cursor is always at the end; that covers
/// typing, paste and backspace, which is all the prompts need.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TextInput {
    text: String,
}

impl TextInput {
    fn new(text: impl Into<String>) -> Self {
        TextInput { text: text.into() }
    }

    /// Apply an editing key; returns whether the buffer changed.
    fn handle(&mut self, key: &KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        match key.code {
            KeyCode::Char('u') if ctrl => {
                self.text.clear();
                true
            }
            KeyCode::Char(c) if !ctrl && !alt && !c.is_control() => {
                self.text.push(c);
                true
            }
            KeyCode::Backspace => self.text.pop().is_some(),
            _ => false,
        }
    }

    /// Insert pasted text. Only the first line is kept: a trailing newline
    /// from the clipboard must not submit the prompt.
    fn paste(&mut self, pasted: &str) {
        let line = pasted.lines().next().unwrap_or("");
        self.text.extend(line.chars().filter(|c| !c.is_control()));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldKind {
    Text,
    Number,
    Toggle,
}

#[derive(Debug, Clone)]
struct Field {
    label: &'static str,
    kind: FieldKind,
    input: TextInput,
    on: bool,
}

impl Field {
    fn text(label: &'static str, value: impl Into<String>) -> Self {
        Field { label, kind: FieldKind::Text, input: TextInput::new(value), on: false }
    }

    fn number(label: &'static str, value: impl Into<String>) -> Self {
        Field { label, kind: FieldKind::Number, input: TextInput::new(value), on: false }
    }

    fn toggle(label: &'static str, on: bool) -> Self {
        Field { label, kind: FieldKind::Toggle, input: TextInput::default(), on }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormAction {
    None,
    Submit,
    Cancel,
}

/// A small modal form: a focused field list plus an inline error line.
#[derive(Debug, Clone)]
struct Form {
    title: &'static str,
    fields: Vec<Field>,
    focus: usize,
    error: Option<String>,
}

impl Form {
    fn new(title: &'static str, fields: Vec<Field>) -> Self {
        Form { title, fields, focus: 0, error: None }
    }

    fn on_key(&mut self, key: &KeyEvent) -> FormAction {
        let last = self.fields.len().saturating_sub(1);
        match key.code {
            KeyCode::Esc => return FormAction::Cancel,
            KeyCode::Enter => return FormAction::Submit,
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1).min(last),
            KeyCode::BackTab | KeyCode::Up => self.focus = self.focus.saturating_sub(1),
            _ => {
                let Some(field) = self.fields.get_mut(self.focus) else {
                    return FormAction::None;
                };
                let changed = match field.kind {
                    FieldKind::Toggle => match key.code {
                        KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right => {
                            field.on = !field.on;
                            true
                        }
                        _ => false,
                    },
                    _ => field.input.handle(key),
                };
                if changed {
                    self.error = None;
                }
            }
        }
        FormAction::None
    }

    fn paste(&mut self, pasted: &str) {
        if let Some(field) = self.fields.get_mut(self.focus) {
            if field.kind != FieldKind::Toggle {
                field.input.paste(pasted);
                self.error = None;
            }
        }
    }
}

/// Parse a KiB/s field into bytes per second; 0 means unlimited.
/// Next priority up or down the Skip < Low < Normal < High ladder, clamped.
fn step_priority(current: FilePriority, up: bool) -> FilePriority {
    const LADDER: [FilePriority; 4] =
        [FilePriority::Skip, FilePriority::Low, FilePriority::Normal, FilePriority::High];
    let at = LADDER.iter().position(|p| *p == current).unwrap_or(2);
    LADDER[if up { (at + 1).min(3) } else { at.saturating_sub(1) }]
}

fn parse_kib(label: &str, text: &str) -> Result<u64, String> {
    let kib: u64 = text
        .trim()
        .parse()
        .map_err(|_| format!("{label}: enter a whole number of KiB/s"))?;
    kib.checked_mul(1024)
        .ok_or_else(|| format!("{label}: value is too large"))
}

fn kib_text(bytes: u64) -> String {
    bytes.div_ceil(1024).to_string()
}

fn limits_form(down: u64, up: u64) -> Form {
    Form::new(
        "torrent limits",
        vec![
            Field::number("Download (KiB/s, 0 = off)", kib_text(down)),
            Field::number("Upload (KiB/s, 0 = off)", kib_text(up)),
        ],
    )
}

fn parse_limits(form: &Form) -> Result<(u64, u64), String> {
    Ok((
        parse_kib("Download", &form.fields[0].input.text)?,
        parse_kib("Upload", &form.fields[1].input.text)?,
    ))
}

fn settings_form(settings: &Settings) -> Form {
    Form::new(
        "settings",
        vec![
            Field::text("Download folder", settings.download_dir.display().to_string()),
            Field::number("Listen port", settings.listen_port.to_string()),
            Field::number("Download (KiB/s, 0 = off)", kib_text(settings.download_limit)),
            Field::number("Upload (KiB/s, 0 = off)", kib_text(settings.upload_limit)),
            Field::number("Seed ratio (0 = forever)", settings.ratio_target.to_string()),
            Field::number("Max peers per torrent", settings.max_peers.to_string()),
            Field::toggle("DHT", settings.dht),
            Field::toggle("Port forwarding", settings.port_forwarding),
            Field::number("Max active downloads (0 = any)", settings.max_active_downloads.to_string()),
            Field::number("Max active torrents (0 = any)", settings.max_active_torrents.to_string()),
            Field::toggle("Local peer discovery", settings.lsd),
        ],
    )
}

/// Validate the settings form. Nothing is sent to the session unless every
/// field parses, so a typo can never reach the engine as a bad value. Values
/// the form does not edit are carried over from `base`.
fn parse_settings(form: &Form, base: &Settings) -> Result<Settings, String> {
    let f = &form.fields;
    let dir = clean_input(&f[0].input.text);
    if dir.is_empty() {
        return Err("Download folder: enter a path".to_string());
    }
    let listen_port = match f[1].input.text.trim().parse::<u16>() {
        Ok(p) if p > 0 => p,
        _ => return Err("Listen port: enter a number from 1 to 65535".to_string()),
    };
    let ratio_target = match f[4].input.text.trim().parse::<f64>() {
        Ok(r) if r.is_finite() && r >= 0.0 => r,
        _ => return Err("Seed ratio: enter a number, 0 or more".to_string()),
    };
    let max_peers = match f[5].input.text.trim().parse::<usize>() {
        Ok(n) if n > 0 => n,
        _ => return Err("Max peers: enter a whole number, 1 or more".to_string()),
    };
    let max_active_downloads = f[8]
        .input
        .text
        .trim()
        .parse::<usize>()
        .map_err(|_| "Max active downloads: enter a whole number, 0 or more".to_string())?;
    let max_active_torrents = f[9]
        .input
        .text
        .trim()
        .parse::<usize>()
        .map_err(|_| "Max active torrents: enter a whole number, 0 or more".to_string())?;
    Ok(Settings {
        download_dir: PathBuf::from(dir),
        listen_port,
        download_limit: parse_kib("Download", &f[2].input.text)?,
        upload_limit: parse_kib("Upload", &f[3].input.text)?,
        ratio_target,
        max_peers,
        dht: f[6].on,
        port_forwarding: f[7].on,
        max_active_downloads,
        max_active_torrents,
        lsd: f[10].on,
        ..base.clone()
    })
}

/// The add-torrent prompt: first the source, then the optional save folder.
#[derive(Debug, Clone)]
struct AddPrompt {
    source: Option<String>,
    input: TextInput,
    default_dir: String,
    error: Option<String>,
}

impl AddPrompt {
    fn new(default_dir: String) -> Self {
        AddPrompt { source: None, input: TextInput::default(), default_dir, error: None }
    }

    /// Advance on Enter; yields the command once both answers are in.
    fn submit(&mut self) -> Option<SessionCommand> {
        let text = clean_input(&self.input.text);
        match self.source.clone() {
            None => {
                if text.is_empty() {
                    self.error = Some("enter a .torrent path or a magnet link".to_string());
                } else {
                    self.source = Some(text);
                    self.input.text.clear();
                    self.error = None;
                }
                None
            }
            Some(source) => Some(SessionCommand::Add {
                source,
                dir: if text.is_empty() { None } else { Some(PathBuf::from(text)) },
            }),
        }
    }
}

#[derive(Debug, Clone, Default)]
enum Modal {
    #[default]
    None,
    Help,
    Add(AddPrompt),
    Remove { id: TorrentId, name: String },
    Limits { id: TorrentId, form: Form },
    Settings(Form),
}

/// The panels under the torrent table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Tab {
    #[default]
    General,
    Peers,
    Files,
    Trackers,
    Log,
    Session,
}

impl Tab {
    const ALL: [Tab; 6] =
        [Tab::General, Tab::Peers, Tab::Files, Tab::Trackers, Tab::Log, Tab::Session];

    fn label(self) -> &'static str {
        match self {
            Tab::General => "General",
            Tab::Peers => "Peers",
            Tab::Files => "Files",
            Tab::Trackers => "Trackers",
            Tab::Log => "Log",
            Tab::Session => "Session",
        }
    }

    fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    fn step(self, delta: isize) -> Tab {
        let n = Tab::ALL.len() as isize;
        Tab::ALL[(self.index() as isize + delta).rem_euclid(n) as usize]
    }
}

/// The tab strip. Inactive tabs shrink to their number when the full labels
/// would not fit.
fn tab_line(active: Tab, width: u16) -> Line<'static> {
    let full: usize = Tab::ALL.iter().map(|t| t.label().len() + 4).sum();
    let compact = usize::from(width) < full;
    let mut spans = Vec::new();
    for (i, tab) in Tab::ALL.iter().enumerate() {
        let text = if compact && *tab != active {
            format!(" {} ", i + 1)
        } else {
            format!(" {} {} ", i + 1, tab.label())
        };
        let style = if *tab == active { selection_style() } else { muted_style() };
        spans.push(Span::styled(text, style));
    }
    Line::from(spans)
}

/// What key handling needs to know about one torrent between frames.
#[derive(Debug, Clone)]
struct RowInfo {
    id: TorrentId,
    name: String,
    state: DownloadState,
    download_limit: u64,
    upload_limit: u64,
}

struct SessionApp {
    rows: Vec<RowInfo>,
    selected: Option<usize>,
    selected_id: Option<TorrentId>,
    table_offset: usize,
    tab: Tab,
    /// Peers/files/log view state, shared with the single-torrent renderers.
    view: App,
    settings: Settings,
    modal: Modal,
    cmd: Option<tokio::sync::mpsc::UnboundedSender<SessionCommand>>,
    quit: bool,
}

impl SessionApp {
    fn new() -> Self {
        SessionApp {
            rows: Vec::new(),
            selected: None,
            selected_id: None,
            table_offset: 0,
            tab: Tab::default(),
            view: App::default(),
            settings: Settings::default(),
            modal: Modal::None,
            cmd: None,
            quit: false,
        }
    }

    /// Absorb a fresh snapshot: refresh the rows, keep the selection on the
    /// same torrent, and rebuild the per-torrent peer and file views.
    fn sync(&mut self, state: &SessionState) {
        self.rows = state
            .torrents
            .iter()
            .map(|t| RowInfo {
                id: t.id.clone(),
                name: view_name(t),
                state: view_state(t),
                download_limit: t.download_limit,
                upload_limit: t.upload_limit,
            })
            .collect();
        self.settings = state.settings.clone();
        if self.cmd.is_none() {
            self.cmd = state.command_tx.clone();
        }

        let ids: Vec<&str> = self.rows.iter().map(|r| r.id.as_str()).collect();
        self.selected = reselect(self.selected_id.as_deref(), self.selected, &ids);
        let new_id = self.selected.map(|i| self.rows[i].id.clone());
        if new_id != self.selected_id {
            self.view.selected = None;
            self.view.file_selected = None;
            self.view.log_scroll = 0;
            self.selected_id = new_id;
        }

        let current = self.selected.and_then(|i| state.torrents.get(i));
        self.view.peers = current.map(|t| sort_peers(&t.ui.peers)).unwrap_or_default();
        self.view.files = current
            .and_then(|t| t.ui.torrent.as_ref())
            .map(|s| s.files.clone())
            .unwrap_or_default();
        self.view.selected = clamp_selection(self.view.selected, self.view.peers.len());
        self.view.file_selected = clamp_selection(self.view.file_selected, self.view.files.len());
    }

    fn current(&self) -> Option<&RowInfo> {
        self.selected.and_then(|i| self.rows.get(i))
    }

    /// Send a command to the session. Never blocks; inert without a channel.
    fn send(&self, cmd: SessionCommand) {
        if let Some(tx) = &self.cmd {
            let _ = tx.send(cmd);
        }
    }

    fn move_torrent(&mut self, delta: isize) {
        self.selected = move_selection(self.selected, self.rows.len(), delta);
        let new_id = self.selected.map(|i| self.rows[i].id.clone());
        if new_id != self.selected_id {
            self.view.selected = None;
            self.view.file_selected = None;
            self.view.log_scroll = 0;
            self.selected_id = new_id;
        }
    }

    fn step_file_priority(&mut self, up: bool) {
        let Some(id) = self.current().map(|row| row.id.clone()) else { return };
        let Some(file) = self.view.file_selected.and_then(|i| self.view.files.get_mut(i)) else {
            return;
        };
        let priority = step_priority(file.priority, up);
        file.priority = priority;
        file.wanted = priority != FilePriority::Skip;
        let index = file.index;
        self.send(SessionCommand::Torrent(id, Command::SetFilePriority(index, priority)));
    }

    fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.view.log_scroll = 0;
    }

    fn quit_session(&mut self) {
        self.send(SessionCommand::Quit);
        self.quit = true;
    }

    /// Apply a key press. `key` is expected to already be filtered to Press
    /// or Repeat events.
    fn on_key(&mut self, key: KeyEvent) {
        if !matches!(self.modal, Modal::None) {
            self.on_modal_key(key);
            return;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c') if ctrl => self.quit_session(),
            KeyCode::Char('q') => self.quit_session(),
            KeyCode::Char('j') | KeyCode::Down => self.move_torrent(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_torrent(-1),
            KeyCode::Char('J') => {
                self.view.file_selected =
                    move_selection(self.view.file_selected, self.view.files.len(), 1);
            }
            KeyCode::Char('K') => {
                self.view.file_selected =
                    move_selection(self.view.file_selected, self.view.files.len(), -1);
            }
            KeyCode::Tab => self.set_tab(self.tab.step(1)),
            KeyCode::BackTab => self.set_tab(self.tab.step(-1)),
            KeyCode::Char(c @ '1'..='6') => self.set_tab(Tab::ALL[usize::from(c as u8 - b'1')]),
            KeyCode::Char(' ') if self.tab == Tab::Files => {
                let file = self
                    .view
                    .file_selected
                    .and_then(|i| self.view.files.get(i))
                    .map(|f| f.index);
                if let (Some(row), Some(index)) = (self.current(), file) {
                    self.send(SessionCommand::Torrent(row.id.clone(), Command::ToggleFile(index)));
                }
            }
            KeyCode::Char(c @ ('+' | '=' | '-')) if self.tab == Tab::Files => {
                self.step_file_priority(c != '-');
            }
            KeyCode::Char('R') => {
                if let Some(row) = self.current() {
                    self.send(SessionCommand::Torrent(row.id.clone(), Command::Recheck));
                }
            }
            KeyCode::Char(c @ ('[' | ']')) => {
                if let Some(row) = self.current() {
                    self.send(SessionCommand::MoveQueue { id: row.id.clone(), up: c == '[' });
                }
            }
            KeyCode::Char('a') => {
                let dir = self.settings.download_dir.display().to_string();
                self.modal = Modal::Add(AddPrompt::new(dir));
            }
            KeyCode::Char('s') => {
                if let Some(row) = self.current() {
                    let id = row.id.clone();
                    self.send(if row.state == DownloadState::Stopped {
                        SessionCommand::Start(id)
                    } else {
                        SessionCommand::Stop(id)
                    });
                }
            }
            KeyCode::Char('p') => {
                if let Some(row) = self.current() {
                    let id = row.id.clone();
                    match row.state {
                        DownloadState::Stopped => {}
                        DownloadState::Paused => {
                            self.send(SessionCommand::Torrent(id, Command::Resume))
                        }
                        _ => self.send(SessionCommand::Torrent(id, Command::Pause)),
                    }
                }
            }
            KeyCode::Char('d') => {
                if let Some(row) = self.current() {
                    self.modal = Modal::Remove { id: row.id.clone(), name: row.name.clone() };
                }
            }
            KeyCode::Char('l') => {
                if let Some(row) = self.current() {
                    self.modal = Modal::Limits {
                        id: row.id.clone(),
                        form: limits_form(row.download_limit, row.upload_limit),
                    };
                }
            }
            KeyCode::Char('o') => self.modal = Modal::Settings(settings_form(&self.settings)),
            KeyCode::Char('?') => self.modal = Modal::Help,
            KeyCode::PageDown => self.view.page_log(-5),
            KeyCode::PageUp => self.view.page_log(5),
            KeyCode::Home => self.view.page_log(isize::MAX),
            KeyCode::End => self.view.log_scroll = 0,
            _ => {}
        }
    }

    fn on_modal_key(&mut self, key: KeyEvent) {
        let modal = std::mem::take(&mut self.modal);
        self.modal = match modal {
            Modal::None => Modal::None,
            Modal::Help => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?') | KeyCode::Char('q') => {
                    Modal::None
                }
                _ => Modal::Help,
            },
            Modal::Add(mut prompt) => match key.code {
                KeyCode::Esc => Modal::None,
                KeyCode::Enter => match prompt.submit() {
                    Some(cmd) => {
                        self.send(cmd);
                        Modal::None
                    }
                    None => Modal::Add(prompt),
                },
                _ => {
                    if prompt.input.handle(&key) {
                        prompt.error = None;
                    }
                    Modal::Add(prompt)
                }
            },
            Modal::Remove { id, name } => match key.code {
                KeyCode::Char('k') => {
                    self.send(SessionCommand::Remove { id, delete_data: false });
                    Modal::None
                }
                KeyCode::Char('D') => {
                    self.send(SessionCommand::Remove { id, delete_data: true });
                    Modal::None
                }
                KeyCode::Esc => Modal::None,
                _ => Modal::Remove { id, name },
            },
            Modal::Limits { id, mut form } => match form.on_key(&key) {
                FormAction::Cancel => Modal::None,
                FormAction::Submit => match parse_limits(&form) {
                    Ok((download, upload)) => {
                        self.send(SessionCommand::SetTorrentLimits { id, download, upload });
                        Modal::None
                    }
                    Err(message) => {
                        form.error = Some(message);
                        Modal::Limits { id, form }
                    }
                },
                FormAction::None => Modal::Limits { id, form },
            },
            Modal::Settings(mut form) => match form.on_key(&key) {
                FormAction::Cancel => Modal::None,
                FormAction::Submit => match parse_settings(&form, &self.settings) {
                    Ok(settings) => {
                        self.send(SessionCommand::SetSettings(settings));
                        Modal::None
                    }
                    Err(message) => {
                        form.error = Some(message);
                        Modal::Settings(form)
                    }
                },
                FormAction::None => Modal::Settings(form),
            },
        };
    }

    /// Bracketed paste: goes into the open prompt, ignored otherwise.
    fn on_paste(&mut self, pasted: &str) {
        match &mut self.modal {
            Modal::Add(prompt) => {
                prompt.input.paste(pasted);
                prompt.error = None;
            }
            Modal::Limits { form, .. } | Modal::Settings(form) => form.paste(pasted),
            _ => {}
        }
    }
}

fn read_session(state: &Arc<RwLock<SessionState>>) -> Result<SessionState, String> {
    state
        .try_read()
        .map(|guard| guard.clone())
        .map_err(|err| format!("session state unavailable: {err}"))
}

/// Paint one session frame.
fn render_session(frame: &mut Frame, snapshot: &Result<SessionState, String>, app: &mut SessionApp) {
    let area = frame.area();
    if area.width == 0 || area.height == 0 {
        return;
    }
    frame.render_widget(Block::default().style(base_style()), area);

    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(frame, area);
        return;
    }
    let state = match snapshot {
        Ok(state) => state,
        Err(message) => {
            render_error(frame, area, message);
            return;
        }
    };
    app.sync(state);

    let footer_rows = if state.warning.is_some() { 2 } else { 1 };
    let body_rows = area.height.saturating_sub(HEADER_ROWS + footer_rows);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(HEADER_ROWS),
            Constraint::Length(table_rows(state.torrents.len(), body_rows)),
            Constraint::Min(0),
            Constraint::Length(footer_rows),
        ])
        .split(area);

    render_session_header(frame, chunks[0], state);
    render_torrent_table(frame, chunks[1], state, app);
    render_detail(frame, chunks[2], state, app);
    render_footer(frame, chunks[3], state.warning.as_deref(), &SESSION_FOOTER_KEYS);
    render_modal(frame, area, app);
}

fn render_session_header(frame: &mut Frame, area: Rect, state: &SessionState) {
    let inner_width = usize::from(area.width.saturating_sub(2));
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style())
        .style(base_style())
        .title(Span::styled(" torrust ", heading_style()));
    let text = truncate_line(&header_summary(state), inner_width);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(text, value_style()))).block(block),
        area,
    );
}

fn render_torrent_table(frame: &mut Frame, area: Rect, state: &SessionState, app: &mut SessionApp) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style())
        .style(base_style())
        .title(Span::styled(" torrents ", heading_style()));

    if state.torrents.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(EMPTY_MESSAGE, muted_style()))
                .alignment(Alignment::Center)
                .block(block),
            area,
        );
        return;
    }

    let columns = visible_columns(area.width);
    let header = Row::new(columns.iter().map(|&c| Cell::from(TABLE_HEADERS[c]))).style(heading_style());
    let rows: Vec<Row> = state
        .torrents
        .iter()
        .map(|view| {
            let cells = torrent_cells(view);
            let status_style = state_style(view_state(view));
            Row::new(columns.iter().map(|&c| {
                let cell = Cell::from(cells[c].clone());
                if c == 4 { cell.style(status_style) } else { cell }
            }))
        })
        .collect();
    let widths: Vec<Constraint> = columns.iter().map(|&c| column_width(c)).collect();
    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .column_spacing(1)
        .row_highlight_style(selection_style())
        .highlight_symbol("> ");

    app.table_offset = ensure_visible(
        app.table_offset,
        app.selected,
        usize::from(area.height.saturating_sub(3)),
        state.torrents.len(),
    );
    let mut table_state = TableState::new()
        .with_selected(app.selected)
        .with_offset(app.table_offset);
    frame.render_stateful_widget(table, area, &mut table_state);
}

fn render_detail(frame: &mut Frame, area: Rect, state: &SessionState, app: &mut SessionApp) {
    if area.height == 0 {
        return;
    }
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);
    frame.render_widget(Paragraph::new(tab_line(app.tab, area.width)), parts[0]);
    let body = parts[1];

    let current = app.selected.and_then(|i| state.torrents.get(i));
    let Some(view) = current else {
        render_log(frame, body, &state.log, "session log", &mut app.view);
        return;
    };
    match app.tab {
        Tab::General => render_general(frame, body, view),
        Tab::Peers => render_peers(frame, body, &mut app.view, false),
        Tab::Files => render_files(frame, body, &mut app.view, true),
        Tab::Trackers => render_trackers(frame, body, view),
        Tab::Log => render_log(frame, body, &view.ui.log, "log", &mut app.view),
        Tab::Session => render_log(frame, body, &state.log, "session log", &mut app.view),
    }
}

fn general_lines(view: &TorrentView) -> Vec<Line<'static>> {
    let Some(t) = view.ui.torrent.as_ref() else {
        return vec![kv("Status", "waiting for metadata".to_string())];
    };
    vec![
        kv("Name", view_name(view)),
        kv(
            "Queue",
            view.queue_position.map(|p| format!("#{}", p + 1)).unwrap_or_else(|| "-".to_string()),
        ),
        kv(
            "Seeds/Peers",
            format!(
                "{} connected   (tracker: {} seeds, {} peers)",
                view.ui.peers.len(),
                t.seeders_known,
                t.leecher_known
            ),
        ),
        kv("Size", t.human_size()),
        kv("Saved to", t.download_dir.clone()),
        kv("Infohash", t.infohash.clone()),
        kv(
            "Pieces",
            format!(
                "{} / {}   (piece {})",
                t.verified_pieces,
                t.piece_count,
                human_bytes(u64::from(t.piece_length))
            ),
        ),
        kv(
            "Downloaded",
            format!("{} ({})", t.human_downloaded(), percent(t.progress)),
        ),
        kv("Uploaded", human_bytes(view.uploaded)),
        kv("Ratio", format!("{:.2}", view.ratio)),
        kv(
            "Limits",
            format!(
                "\u{2193} {}   \u{2191} {}",
                limit_label(view.download_limit),
                limit_label(view.upload_limit)
            ),
        ),
        kv("Trackers", t.trackers.len().to_string()),
    ]
}

fn render_general(frame: &mut Frame, area: Rect, view: &TorrentView) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style())
        .style(base_style())
        .title(Span::styled(" general ", heading_style()));
    frame.render_widget(Paragraph::new(Text::from(general_lines(view))).block(block), area);
}

fn render_trackers(frame: &mut Frame, area: Rect, view: &TorrentView) {
    let width = usize::from(area.width.saturating_sub(2));
    let trackers = view.ui.torrent.as_ref().map(|t| t.trackers.as_slice()).unwrap_or(&[]);
    let lines: Vec<Line> = if trackers.is_empty() {
        vec![Line::from(Span::styled("no trackers", muted_style()))]
    } else {
        trackers
            .iter()
            .map(|url| Line::from(Span::styled(truncate_line(url, width), value_style())))
            .collect()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style())
        .style(base_style())
        .title(Span::styled(format!(" trackers ({}) ", trackers.len()), heading_style()));
    frame.render_widget(Paragraph::new(Text::from(lines)).block(block), area);
}

/// A rectangle at most `w` x `h`, centred in `area` and never outside it.
fn popup_rect(w: u16, h: u16, area: Rect) -> Rect {
    let width = w.min(area.width);
    let height = h.min(area.height);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

fn modal_block(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(heading_style())
        .style(base_style())
        .title(Span::styled(format!(" {title} "), heading_style()))
}

fn render_modal(frame: &mut Frame, area: Rect, app: &SessionApp) {
    match &app.modal {
        Modal::None => {}
        Modal::Help => render_help(frame, area, &SESSION_KEYS, (70, 95)),
        Modal::Add(prompt) => render_add(frame, area, prompt),
        Modal::Remove { name, .. } => render_remove(frame, area, name),
        Modal::Limits { form, .. } | Modal::Settings(form) => render_form(frame, area, form),
    }
}

fn render_add(frame: &mut Frame, area: Rect, prompt: &AddPrompt) {
    let popup = popup_rect(70, 6, area);
    let width = usize::from(popup.width.saturating_sub(4));
    let label = if prompt.source.is_none() {
        "Torrent file path or magnet link:".to_string()
    } else {
        format!("Save to (empty = {}):", prompt.default_dir)
    };
    let hint = match &prompt.error {
        Some(message) => Span::styled(message.clone(), error_style()),
        None => Span::styled("Enter next/confirm  Esc cancel", muted_style()),
    };
    let lines = vec![
        Line::from(Span::styled(truncate_line(&label, width), heading_style())),
        Line::from(Span::styled(
            format!("{}_", tail_fit(&prompt.input.text, width.saturating_sub(1))),
            value_style(),
        )),
        Line::from(hint),
    ];
    frame.render_widget(Clear, popup);
    frame.render_widget(Paragraph::new(Text::from(lines)).block(modal_block("add torrent")), popup);
}

fn render_remove(frame: &mut Frame, area: Rect, name: &str) {
    let popup = popup_rect(70, 6, area);
    let width = usize::from(popup.width.saturating_sub(4));
    let lines = vec![
        Line::from(Span::styled(truncate_line(name, width), value_style())),
        Line::from(vec![
            Span::styled("k", heading_style()),
            Span::raw(" keep data   "),
            Span::styled("D", error_style().add_modifier(Modifier::BOLD)),
            Span::raw(" delete data   "),
            Span::styled("Esc", heading_style()),
            Span::raw(" cancel"),
        ]),
    ];
    frame.render_widget(Clear, popup);
    frame.render_widget(Paragraph::new(Text::from(lines)).block(modal_block("remove torrent")), popup);
}

fn render_form(frame: &mut Frame, area: Rect, form: &Form) {
    const LABEL: usize = 26;
    let popup = popup_rect(72, form.fields.len() as u16 + 3, area);
    let inner_width = usize::from(popup.width.saturating_sub(2));
    let value_width = inner_width.saturating_sub(2 + LABEL + 1);
    let visible = usize::from(popup.height.saturating_sub(3)).max(1);
    let offset = ensure_visible(0, Some(form.focus), visible, form.fields.len());

    let mut lines: Vec<Line> = form
        .fields
        .iter()
        .enumerate()
        .skip(offset)
        .take(visible)
        .map(|(i, field)| {
            let focused = i == form.focus;
            let value = match field.kind {
                FieldKind::Toggle => {
                    if field.on { "[x] on".to_string() } else { "[ ] off".to_string() }
                }
                _ => {
                    let cursor = if focused { "_" } else { "" };
                    format!("{}{cursor}", tail_fit(&field.input.text, value_width.saturating_sub(1)))
                }
            };
            Line::from(vec![
                Span::styled(if focused { "> " } else { "  " }, heading_style()),
                Span::styled(format!("{:<LABEL$} ", field.label), heading_style()),
                Span::styled(value, if focused { selection_style() } else { value_style() }),
            ])
        })
        .collect();
    lines.push(Line::from(match &form.error {
        Some(message) => Span::styled(truncate_line(message, inner_width), error_style()),
        None => Span::styled("Enter save  Esc cancel  Tab/Up/Down field", muted_style()),
    }));
    frame.render_widget(Clear, popup);
    frame.render_widget(Paragraph::new(Text::from(lines)).block(modal_block(form.title)), popup);
}

/// Drive the session UI until the user quits or the session shuts down.
fn run_session_loop(state: Arc<RwLock<SessionState>>) -> Result<()> {
    let (mut terminal, _guard) = setup_terminal()?;
    let _ = execute!(io::stdout(), EnableBracketedPaste);
    terminal.clear().context("failed to clear the terminal")?;

    let mut app = SessionApp::new();
    loop {
        let snapshot = read_session(&state);
        terminal
            .draw(|frame| render_session(frame, &snapshot, &mut app))
            .context("failed to draw a frame")?;

        let shutdown = matches!(&snapshot, Ok(s) if s.shutdown);
        if app.quit || shutdown {
            break;
        }
        if !event::poll(TICK).context("failed to poll terminal events")? {
            continue;
        }
        match event::read().context("failed to read a terminal event")? {
            Event::Key(key) if key.kind != KeyEventKind::Release => app.on_key(key),
            Event::Paste(text) => app.on_paste(&text),
            _ => {}
        }
    }
    Ok(())
}

/// Run the multi-torrent session UI until the user quits.
///
/// Blocks the calling thread; the terminal is restored before returning.
/// Quitting sends [`SessionCommand::Quit`] so the session persists and exits.
pub fn run_session_tui(state: Arc<RwLock<SessionState>>) -> Result<()> {
    std::thread::Builder::new()
        .name("torrust-session-tui".to_string())
        .spawn(move || run_session_loop(state))
        .context("failed to spawn the TUI thread")?
        .join()
        .map_err(|_| anyhow::anyhow!("the TUI thread panicked"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::DownloadState;

    fn peer(addr: &str, downloaded: u64, uploaded: u64, progress: f64) -> PeerSummary {
        PeerSummary {
            addr: addr.to_string(),
            downloaded,
            uploaded,
            progress,
            choked_by_us: false,
            choking_us: false,
            outstanding: 0,
        }
    }

    fn entry(level: Level, message: &str) -> LogEntry {
        LogEntry {
            level,
            message: message.to_string(),
        }
    }

    #[test]
    fn clamp_ratio_bounds_the_widget_range() {
        assert_eq!(clamp_ratio(0.0), 0.0);
        assert_eq!(clamp_ratio(0.5), 0.5);
        assert_eq!(clamp_ratio(1.0), 1.0);
        assert_eq!(clamp_ratio(-0.5), 0.0);
        assert_eq!(clamp_ratio(42.0), 1.0);
    }

    #[test]
    fn clamp_ratio_neutralises_nan() {
        assert_eq!(clamp_ratio(f64::NAN), 0.0);
        assert_eq!(clamp_ratio(f64::NEG_INFINITY), 0.0);
        assert_eq!(clamp_ratio(f64::INFINITY), 1.0);
    }

    #[test]
    fn percent_formats_and_clamps() {
        assert_eq!(percent(0.0), "0.0%");
        assert_eq!(percent(0.12345), "12.3%");
        assert_eq!(percent(1.0), "100.0%");
        assert_eq!(percent(3.0), "100.0%");
        assert_eq!(percent(-1.0), "0.0%");
        assert_eq!(percent(f64::NAN), "0.0%");
    }

    #[test]
    fn abbrev_hash_truncates_long_hashes() {
        let hash = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(abbrev_hash(hash), "0123456789ab\u{2026}");
    }

    #[test]
    fn abbrev_hash_leaves_short_and_empty_values_alone() {
        assert_eq!(abbrev_hash("abc"), "abc");
        assert_eq!(abbrev_hash("ABCDEF"), "ABCDEF");
        assert_eq!(abbrev_hash(""), "(unknown)");
        assert_eq!(abbrev_hash("   "), "(unknown)");
    }

    #[test]
    fn abbrev_hash_rejects_anything_that_is_not_hex() {
        // Partially-hex input must not render as a plausible-looking prefix.
        assert_eq!(abbrev_hash("not-a-hash"), "(unknown)");
        assert_eq!(abbrev_hash("magnet:?xt=urn:btih:abc"), "(unknown)");
        assert_eq!(abbrev_hash("zzzzzzzzzzzzzzzz"), "(unknown)");
        // Surrounding whitespace is tolerated.
        assert_eq!(
            abbrev_hash("  0123456789abcdef0123456789abcdef01234567  "),
            "0123456789ab\u{2026}"
        );
    }

    #[test]
    fn truncate_line_fits_and_marks_truncation() {
        assert_eq!(truncate_line("hello", 10), "hello");
        assert_eq!(truncate_line("hello", 5), "hello");
        assert_eq!(truncate_line("hello", 0), "");
        assert_eq!(truncate_line("hello", 3), "he\u{2026}");
    }

    #[test]
    fn truncate_line_flattens_control_characters() {
        assert_eq!(truncate_line("a\nb\tc", 10), "a b c");
    }

    #[test]
    fn peer_flags_encode_choke_and_outstanding_blocks() {
        let mut p = peer("1.2.3.4:1", 0, 0, 0.0);
        assert_eq!(peer_flags(&p), "\u{2193}\u{2193}");

        p.choking_us = true;
        assert_eq!(peer_flags(&p), "\u{2193}\u{2191}");

        p.choked_by_us = true;
        assert_eq!(peer_flags(&p), "\u{2191}\u{2191}");

        p.outstanding = 3;
        assert_eq!(peer_flags(&p), "\u{2191}\u{2191}*");
    }

    #[test]
    fn peer_row_cells_are_in_column_order() {
        let p = peer("10.0.0.1:6881", 2048, 512, 0.5);
        let cells = peer_cells(&p);
        assert_eq!(cells[0], "10.0.0.1:6881");
        assert_eq!(cells[1], "2.00 KiB");
        assert_eq!(cells[2], "512 B");
        assert_eq!(cells[3], "50.0%");
        assert_eq!(cells[4], "\u{2193}\u{2193}");
    }

    #[test]
    fn sort_peers_orders_by_downloaded_descending() {
        let peers = vec![
            peer("a", 10, 0, 0.0),
            peer("b", 300, 0, 0.0),
            peer("c", 100, 0, 0.0),
        ];
        let sorted = sort_peers(&peers);
        let addrs: Vec<&str> = sorted.iter().map(|p| p.addr.as_str()).collect();
        assert_eq!(addrs, vec!["b", "c", "a"]);
    }

    #[test]
    fn sort_peers_breaks_ties_on_address() {
        let peers = vec![peer("z", 5, 0, 0.0), peer("a", 5, 0, 0.0)];
        let sorted = sort_peers(&peers);
        assert_eq!(sorted[0].addr, "a");
        assert_eq!(sorted[1].addr, "z");
    }

    #[test]
    fn sort_peers_does_not_mutate_its_input() {
        let peers = vec![peer("a", 1, 0, 0.0), peer("b", 2, 0, 0.0)];
        let _ = sort_peers(&peers);
        assert_eq!(peers[0].addr, "a");
    }

    #[test]
    fn log_height_is_bounded_throughout() {
        assert_eq!(log_height(0), 3);
        assert_eq!(log_height(12), 3);
        assert_eq!(log_height(40), 8);
        assert_eq!(log_height(200), 8);
        assert_eq!(log_height(u16::MAX), 8);
    }

    #[test]
    fn log_window_pins_to_the_newest_entries() {
        let log: Vec<LogEntry> = (0..10).map(|i| entry(Level::Info, &format!("{i}"))).collect();
        let window = log_window(&log, 3, 0);
        assert_eq!(window.len(), 3);
        assert_eq!(window[0].message, "7");
        assert_eq!(window[2].message, "9");
    }

    #[test]
    fn log_window_scrolls_back_and_clamps() {
        let log: Vec<LogEntry> = (0..10).map(|i| entry(Level::Info, &format!("{i}"))).collect();

        let scrolled = log_window(&log, 3, 4);
        assert_eq!(scrolled[0].message, "3");
        assert_eq!(scrolled[2].message, "5");

        // Scrolling past the top of the buffer is not allowed.
        let clamped = log_window(&log, 3, 99);
        assert_eq!(clamped[0].message, "0");
        assert_eq!(clamped[2].message, "2");

        // A window taller than the buffer shows everything.
        assert_eq!(log_window(&log, 50, 0).len(), 10);
        assert!(log_window(&[], 5, 0).is_empty());
        assert!(log_window(&log, 0, 0).is_empty());
    }

    #[test]
    fn selection_movement_stops_at_the_ends() {
        assert_eq!(move_selection(None, 3, 1), Some(0), "first press selects row 0");
        assert_eq!(move_selection(None, 3, -1), Some(0));
        assert_eq!(move_selection(Some(0), 3, -1), Some(0));
        assert_eq!(move_selection(Some(2), 3, 1), Some(2));
        assert_eq!(move_selection(Some(1), 3, 1), Some(2));
        assert_eq!(move_selection(Some(1), 0, 1), None);
    }

    #[test]
    fn selection_is_clamped_to_the_row_count() {
        assert_eq!(clamp_selection(Some(9), 3), Some(2));
        assert_eq!(clamp_selection(None, 3), Some(0));
        assert_eq!(clamp_selection(Some(0), 0), None);
    }

    #[test]
    fn log_scroll_is_clamped_to_available_history() {
        assert_eq!(scroll_log(0, 10, 3, 5), 5);
        assert_eq!(scroll_log(0, 10, 3, -1), 0);
        assert_eq!(scroll_log(3, 10, 3, 99), 7);
        assert_eq!(scroll_log(3, 2, 3, 1), 0);
        // Extreme deltas must saturate rather than wrap around.
        assert_eq!(scroll_log(0, 10, 3, isize::MAX), 7);
        assert_eq!(scroll_log(5, 10, 3, isize::MIN), 0);
        assert_eq!(scroll_log(usize::MAX, 10, 3, 0), 7);
    }

    #[test]
    fn log_paging_uses_the_window_measured_by_the_last_frame() {
        let mut app = App::default();
        app.clamp_log(50, 10); // 50 entries, 10 visible -> 40 rows of history
        assert_eq!(app.log_scroll, 0);

        app.on_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(app.log_scroll, 5);
        app.on_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(app.log_scroll, 10);

        app.on_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert_eq!(app.log_scroll, 5);
        app.on_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert_eq!(app.log_scroll, 0, "cannot scroll past the newest entry");

        app.on_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        assert_eq!(app.log_scroll, 40, "End jumps to the oldest entry");
        app.on_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
        assert_eq!(app.log_scroll, 0);
    }

    #[test]
    fn a_shrinking_log_buffer_reclamps_the_scroll() {
        let mut app = App::default();
        app.clamp_log(500, 10);
        app.on_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        assert_eq!(app.log_scroll, 490);

        // The buffer is trimmed and the window grows: the offset must follow.
        app.clamp_log(20, 18);
        assert_eq!(app.log_scroll, 2);
    }

    #[test]
    fn ensure_visible_scrolls_the_offset_to_the_selection() {
        assert_eq!(ensure_visible(0, Some(5), 3, 10), 3);
        assert_eq!(ensure_visible(8, Some(1), 3, 10), 1);
        assert_eq!(ensure_visible(4, Some(5), 3, 10), 4);
        assert_eq!(ensure_visible(0, None, 3, 10), 0);
        assert_eq!(ensure_visible(0, Some(0), 0, 10), 0);
        assert_eq!(ensure_visible(0, Some(0), 50, 10), 0);
    }

    #[test]
    fn tab_cycles_focus_between_peers_and_files() {
        let mut app = App::default();
        assert_eq!(app.focus, Focus::Peers);
        let tab = KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE);
        app.on_key(tab);
        assert_eq!(app.focus, Focus::Files);
        app.on_key(tab);
        assert_eq!(app.focus, Focus::Peers);
    }

    #[test]
    fn movement_keys_drive_the_focused_list_only() {
        let mut app = App::default();
        app.peers = vec![peer("a", 1, 0, 0.0), peer("b", 2, 0, 0.0)];
        app.files = vec![file(0, "a", 10), file(1, "b", 10)];
        app.selected = Some(0);
        app.file_selected = Some(0);

        // Focus starts on peers: j moves the peer cursor, files stay put.
        app.on_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.selected, Some(1));
        assert_eq!(app.file_selected, Some(0));

        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.selected, Some(1), "peer cursor must not move");
        assert_eq!(app.file_selected, Some(1));
    }

    #[test]
    fn space_sends_the_stable_file_index_not_the_row() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::default();
        // Rows sorted differently from torrent order would retarget a
        // row-based command; the index must survive that.
        app.files = vec![file(7, "g", 10), file(3, "c", 10)];
        app.file_selected = Some(1);
        app.focus = Focus::Files;
        app.cmd = Some(tx);

        app.on_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        assert_eq!(
            rx.try_recv().unwrap(),
            Command::ToggleFile(3),
            "must send the file's stable index"
        );
    }

    #[test]
    fn space_outside_the_files_panel_sends_nothing() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::default();
        app.files = vec![file(0, "a", 10)];
        app.file_selected = Some(0);
        app.focus = Focus::Peers;
        app.cmd = Some(tx);

        app.on_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn p_sends_pause_or_resume_from_the_mirrored_flag() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::default();
        app.cmd = Some(tx);

        app.paused = false;
        app.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        assert_eq!(rx.try_recv().unwrap(), Command::Pause);

        app.paused = true;
        app.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        assert_eq!(rx.try_recv().unwrap(), Command::Resume);
    }

    #[test]
    fn control_keys_are_inert_without_a_channel() {
        // Pre-engine frames have no channel; keys must not panic.
        let mut app = App::default();
        app.files = vec![file(0, "a", 10)];
        app.file_selected = Some(0);
        app.focus = Focus::Files;
        app.on_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
    }

    #[test]
    fn file_bar_is_fixed_width_and_clamped() {
        // The bar itself is fixed width; only the percent label varies.
        let bar_of = |s: &str| s.split(']').next().unwrap().len();
        let full = file_bar(1.0, 20);
        let empty = file_bar(0.0, 20);
        assert_eq!(bar_of(&full), bar_of(&empty));
        assert!(full.contains("100.0%"));
        assert!(empty.contains("0.0%"));
        // Out-of-range ratios cannot break the width.
        assert_eq!(bar_of(&file_bar(2.0, 20)), bar_of(&full));
        assert_eq!(bar_of(&file_bar(-1.0, 20)), bar_of(&full));
        assert!(file_bar(2.0, 20).contains("100.0%"), "clamped display");
    }

    #[test]
    fn file_cells_mark_unwanted_files() {
        let wanted = file(0, "a.bin", 100);
        let [_, _, _, w] = file_cells(&wanted, 20);
        assert_eq!(w, "normal");
        let mut skipped = file(1, "b.bin", 100);
        skipped.priority = FilePriority::Skip;
        let [_, _, _, s] = file_cells(&skipped, 20);
        assert_eq!(s, "skip");
    }

    #[test]
    fn paused_state_renders_yellow() {
        assert_eq!(state_style(DownloadState::Paused).fg, Some(Color::Yellow));
    }

    fn file(index: usize, path: &str, length: u64) -> FileSummary {
        FileSummary {
            index,
            path: path.to_string(),
            length,
            downloaded: 0,
            wanted: true,
            priority: FilePriority::Normal,
        }
    }

    #[test]
    fn key_presses_drive_quit_selection_and_overlays() {
        let mut app = App::default();
        app.peers = vec![peer("a", 1, 0, 0.0), peer("b", 2, 0, 0.0)];
        app.selected = Some(0);

        app.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.selected, Some(1));
        app.on_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.selected, Some(1), "must not run past the last peer");
        app.on_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.selected, Some(0));
        app.on_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        assert_eq!(app.selected, Some(0));

        app.on_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert!(app.show_help);
        app.on_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert!(!app.show_help);

        app.on_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
        assert!(app.redraw);

        assert!(!app.quit);
        app.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(app.quit);
    }

    #[test]
    fn every_quit_key_sets_the_quit_flag() {
        for code in [
            KeyCode::Char('q'),
            KeyCode::Esc,
            KeyCode::Char('c'),
        ] {
            let mut app = App::default();
            let modifiers = if code == KeyCode::Char('c') {
                KeyModifiers::CONTROL
            } else {
                KeyModifiers::NONE
            };
            app.on_key(KeyEvent::new(code, modifiers));
            assert!(app.quit, "{code:?} should quit");
        }
    }

    #[test]
    fn a_bare_c_does_not_quit() {
        let mut app = App::default();
        app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE));
        assert!(!app.quit);
    }

    #[test]
    fn progress_section_shrinks_on_a_short_terminal() {
        assert_eq!(progress_rows(40), PROGRESS_ROWS_FULL);
        assert_eq!(progress_rows(ROOMY_HEIGHT), PROGRESS_ROWS_FULL);
        assert_eq!(progress_rows(ROOMY_HEIGHT - 1), PROGRESS_ROWS_FULL - 2);
        assert_eq!(progress_rows(MIN_HEIGHT), PROGRESS_ROWS_FULL - 2);
        assert_eq!(progress_rows(u16::MAX), PROGRESS_ROWS_FULL);
    }

#[test]
    fn stat_lines_cover_every_required_row() {
        let torrent = TorrentSummary {
            name: "test".into(),
            infohash: "abc".into(),
            total_length: 2048,
            downloaded: 512,
            piece_length: 256,
            piece_count: 8,
            verified_pieces: 2,
            progress: 0.25,
            download_rate: 1024.0,
            upload_rate: 512.0,
            ..Default::default()
        };
        let lines = stat_lines(&torrent, 3, false);
        assert_eq!(lines.len(), 6);
        let rendered: Vec<String> = lines
            .iter()
            .map(|line| line.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        assert!(rendered[0].contains("Downloaded") && rendered[0].contains("25.0%"));
        assert!(rendered[1].contains("1.00 KiB/s") && rendered[1].contains("512 B/s"));
        assert!(rendered[2].contains("--:--"));
        assert!(rendered[3].contains("2 / 8") && rendered[3].contains("256 B"));
        assert!(rendered[4].contains("3 connected"));
        assert!(rendered[5].contains("Save to"));
    }

    #[test]
    fn compact_stat_lines_drop_the_secondary_rows() {
        let torrent = TorrentSummary {
            total_length: 2048,
            downloaded: 512,
            ..Default::default()
        };
        let full = stat_lines(&torrent, 3, false);
        let compact = stat_lines(&torrent, 3, true);
        assert_eq!(full.len(), 6);
        assert_eq!(compact.len(), 4);

        // The rows that survive are a prefix of the full set, so the layout
        // keeps the numbers that matter while downloading.
        for (short, tall) in compact.iter().zip(full.iter()) {
            assert_eq!(short.spans[0].content, tall.spans[0].content);
        }
        let kept: String = compact
            .iter()
            .map(|line| line.spans[0].content.as_ref())
            .collect();
        assert!(kept.contains("Downloaded") && kept.contains("Pieces"));
    }

    #[test]
    fn stat_lines_survive_a_zero_length_torrent() {
        let lines = stat_lines(&TorrentSummary::default(), 0, false);
        assert_eq!(lines.len(), 6);
        assert!(lines[0].spans.iter().any(|s| s.content.contains("0.0%")));
    }

    #[test]
    fn a_missing_torrent_renders_as_a_placeholder() {
        let placeholder = torrent_or_placeholder(None);
        assert!(placeholder.name.contains("metadata"));
        assert_eq!(placeholder.state, DownloadState::Connecting);

        let real = TorrentSummary {
            name: "ubuntu.iso".into(),
            ..Default::default()
        };
        assert_eq!(torrent_or_placeholder(Some(&real)).name, "ubuntu.iso");
    }

    #[test]
    fn state_colour_follows_the_download_state() {
        // Assert on the actual `fg` field rather than the `Debug` rendering:
        // ratatui does not promise a particular Debug format for `Style`, so a
        // string match on it is a test of the formatting library, not of us.
        assert_eq!(state_style(DownloadState::Error).fg, Some(Color::Red));
        assert_eq!(state_style(DownloadState::Complete).fg, Some(Color::Green));
        assert_eq!(state_style(DownloadState::Stopped).fg, Some(Color::DarkGray));
        assert_eq!(
            state_style(DownloadState::Downloading).fg,
            Some(Color::Cyan)
        );

        assert_eq!(level_style(Level::Error).fg, Some(Color::Red));
        assert_eq!(level_style(Level::Warn).fg, Some(Color::Yellow));
        assert_eq!(level_style(Level::Info).fg, Some(Color::Green));
        assert_eq!(level_style(Level::Debug).fg, Some(Color::DarkGray));
        assert_eq!(level_style(Level::Trace).fg, Some(Color::DarkGray));
        assert!(
            level_style(Level::Trace)
                .add_modifier
                .contains(Modifier::DIM),
            "trace should be dimmed"
        );
    }

    #[test]
    fn bindings_line_fits_narrow_terminals_without_the_clock() {
        let narrow: String = bindings_line(10)
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(!narrow.is_empty());
        // No room for right-alignment, so the clock is dropped rather than
        // pushing the line past the edge.
        assert!(!narrow.contains(':') || narrow.contains("quit"));

        let wide: String = bindings_line(120)
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(wide.contains("quit"));
        assert!(wide.contains("PgUp/PgDn"));
    }

    #[test]
    fn centered_rect_stays_inside_the_screen() {
        let area = Rect {
            x: 0,
            y: 0,
            width: 100,
            height: 40,
        };
        let popup = centered_rect(50, 50, area);
        assert_eq!(popup.width, 50);
        assert_eq!(popup.height, 20);
        assert_eq!(popup.x, 25);
        assert_eq!(popup.y, 10);

        // Absurd percentages must never grow a rect past its parent, or the
        // widget would render outside the frame buffer.
        for percent in [0u16, 1, 50, 99, 100, 150, 200, u16::MAX] {
            let clamped = centered_rect(percent, percent, area);
            assert!(
                clamped.x >= area.x && clamped.x + clamped.width <= area.x + area.width,
                "percent {percent} overflowed horizontally: {clamped:?}"
            );
            assert!(
                clamped.y >= area.y && clamped.y + clamped.height <= area.y + area.height,
                "percent {percent} overflowed vertically: {clamped:?}"
            );
        }

        // Offset parents are honoured.
        let offset = Rect { x: 10, y: 5, width: 100, height: 40 };
        let popup = centered_rect(50, 50, offset);
        assert_eq!(popup.x, 35);
        assert_eq!(popup.y, 15);

        // A zero-sized parent must not underflow.
        let empty = centered_rect(50, 50, Rect::new(0, 0, 0, 0));
        assert_eq!(empty.width, 0);
        assert_eq!(empty.height, 0);
    }

    #[test]
    fn too_small_message_names_the_required_size() {
        let message = too_small_message();
        assert!(message.contains(&MIN_WIDTH.to_string()));
        assert!(message.contains(&MIN_HEIGHT.to_string()));
        assert!(message.contains("too small"));
    }
}
#[cfg(test)]
mod session_tests {
    use super::*;
    use crate::state::{Level, UiState};
    use ratatui::backend::TestBackend;
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ch(c: char) -> KeyEvent {
        key(KeyCode::Char(c))
    }

    fn view(id: &str, state: DownloadState) -> TorrentView {
        TorrentView {
            id: id.to_string(),
            ui: UiState {
                torrent: Some(TorrentSummary {
                    name: format!("name-{id}"),
                    infohash: "0123456789abcdef0123456789abcdef01234567".to_string(),
                    total_length: 3 * 1024 * 1024 * 1024,
                    progress: 0.5,
                    download_rate: 1536.0 * 1024.0,
                    upload_rate: 0.0,
                    eta_secs: Some(3725.0),
                    state,
                    trackers: vec!["http://tracker.example/announce".to_string()],
                    files: vec![
                        FileSummary { index: 0, path: "a.bin".into(), length: 10, downloaded: 5, wanted: true, priority: FilePriority::Normal },
                        FileSummary { index: 1, path: "b.bin".into(), length: 10, downloaded: 0, wanted: true, priority: FilePriority::Normal },
                    ],
                    ..TorrentSummary::default()
                }),
                peers: vec![PeerSummary {
                    addr: "1.2.3.4:6881".into(),
                    downloaded: 1,
                    uploaded: 2,
                    progress: 0.5,
                    choked_by_us: false,
                    choking_us: false,
                    outstanding: 0,
                }],
                log: vec![LogEntry { level: Level::Info, message: format!("log-{id}") }],
                ..UiState::default()
            },
            ratio: 1.25,
            uploaded: 4096,
            download_limit: 100 * 1024,
            upload_limit: 0,
            added_at: 0,
            queue_position: None,
        }
    }

    fn session(ids: &[&str]) -> SessionState {
        SessionState {
            torrents: ids.iter().map(|id| view(id, DownloadState::Downloading)).collect(),
            ..SessionState::default()
        }
    }

    fn app_with(state: &SessionState) -> (SessionApp, UnboundedReceiver<SessionCommand>) {
        let (tx, rx) = unbounded_channel();
        let mut app = SessionApp::new();
        app.cmd = Some(tx);
        app.sync(state);
        (app, rx)
    }

    fn type_text(app: &mut SessionApp, text: &str) {
        for c in text.chars() {
            app.on_key(ch(c));
        }
    }

    #[test]
    fn compact_formats() {
        assert_eq!(compact_bytes(12), "12B");
        assert_eq!(compact_bytes(1536), "1.5K");
        assert_eq!(compact_bytes(523 * 1024), "523K");
        assert_eq!(compact_bytes(3 * 1024 * 1024 * 1024), "3.0G");
        assert_eq!(compact_rate(0.0), "-");
        assert_eq!(compact_rate(f64::NAN), "-");
        assert_eq!(compact_rate(2048.0), "2.0K/s");
        assert_eq!(compact_eta(None), "--");
        assert_eq!(compact_eta(Some(f64::INFINITY)), "--");
        assert_eq!(compact_eta(Some(45.0)), "45s");
        assert_eq!(compact_eta(Some(249.0)), "4m09s");
        assert_eq!(compact_eta(Some(3725.0)), "1h02m");
        assert_eq!(compact_eta(Some(90_000.0)), "1d01h");
        assert_eq!(limit_label(0), "unlimited");
        assert_eq!(limit_label(2048), "2.00 KiB/s");
    }

    #[test]
    fn row_cells_describe_a_torrent() {
        let mut v = view("x", DownloadState::Seeding);
        v.queue_position = Some(2);
        v.ui.torrent.as_mut().unwrap().seeders_known = 41;
        v.ui.torrent.as_mut().unwrap().leecher_known = 12;
        let cells = torrent_cells(&v);
        assert_eq!(cells[0], "3");
        assert_eq!(cells[1], "name-x");
        assert_eq!(cells[2], "3.0G");
        assert_eq!(cells[3], "50.0%");
        assert_eq!(cells[4], "seeding");
        assert_eq!(cells[5], "1.5M/s");
        assert_eq!(cells[6], "-");
        assert_eq!(cells[7], "1h02m");
        assert_eq!(cells[8], "1 (41/12)");
        assert_eq!(cells[9], "1.25");
    }

    #[test]
    fn row_cells_survive_missing_metadata() {
        let bare = TorrentView { ui: UiState::default(), ..view("x", DownloadState::Connecting) };
        let cells = torrent_cells(&bare);
        assert_eq!(cells[0], "");
        assert_eq!(cells[8], "0");
        assert_eq!(cells[1], PENDING_NAME);
        assert_eq!(cells[2], "?");
        assert_eq!(cells[4], "connecting");
    }

    #[test]
    fn table_rows_leave_room_for_details() {
        assert_eq!(table_rows(0, 20), 4);
        assert_eq!(table_rows(2, 20), 5);
        assert_eq!(table_rows(50, 20), 9);
        assert_eq!(table_rows(1, 8), 4);
        assert_eq!(table_rows(1, 3), 3);
    }

    #[test]
    fn narrow_widths_drop_columns() {
        assert_eq!(visible_columns(120).len(), 10);
        assert_eq!(visible_columns(60), &[0, 1, 3, 4, 5, 6]);
        assert_eq!(visible_columns(40), &[0, 1, 3, 5]);
    }

    #[test]
    fn header_summarises_the_session() {
        let mut s = session(&["a"]);
        s.download_rate = 2048.0;
        s.port_status = "port 6881".to_string();
        assert_eq!(header_summary(&s), "1 torrent  \u{2193} 2.00 KiB/s  \u{2191} 0 B/s  port 6881");
        assert!(header_summary(&session(&[])).starts_with("0 torrents"));
    }

    #[test]
    fn reselect_follows_the_id() {
        assert_eq!(reselect(Some("b"), Some(0), &["x", "a", "b"]), Some(2));
        assert_eq!(reselect(None, None, &["a", "b"]), Some(0));
        assert_eq!(reselect(Some("gone"), Some(1), &["a", "b", "c"]), Some(1));
        assert_eq!(reselect(Some("gone"), Some(2), &["a", "b"]), Some(1));
        assert_eq!(reselect(Some("a"), Some(0), &[]), None);
    }

    #[test]
    fn selection_is_stable_when_the_list_changes() {
        let (mut app, _rx) = app_with(&session(&["a", "b", "c"]));
        app.on_key(ch('j'));
        app.on_key(ch('j'));
        assert_eq!(app.selected_id.as_deref(), Some("c"));

        app.sync(&session(&["x", "a", "c"]));
        assert_eq!(app.selected, Some(2));
        assert_eq!(app.selected_id.as_deref(), Some("c"));

        app.sync(&session(&["x", "a"]));
        assert_eq!(app.selected, Some(1));
        assert_eq!(app.selected_id.as_deref(), Some("a"));

        app.sync(&session(&[]));
        assert_eq!(app.selected, None);
        assert_eq!(app.selected_id, None);
        app.on_key(ch('d'));
        assert!(matches!(app.modal, Modal::None));
    }

    #[test]
    fn movement_sticks_at_the_ends() {
        let (mut app, _rx) = app_with(&session(&["a", "b"]));
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.selected, Some(0));
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.selected, Some(1));
    }

    #[test]
    fn tabs_switch_by_key() {
        let (mut app, _rx) = app_with(&session(&["a"]));
        app.on_key(key(KeyCode::Tab));
        assert_eq!(app.tab, Tab::Peers);
        app.on_key(ch('6'));
        assert_eq!(app.tab, Tab::Session);
        app.on_key(key(KeyCode::Tab));
        assert_eq!(app.tab, Tab::General);
        app.on_key(key(KeyCode::BackTab));
        assert_eq!(app.tab, Tab::Session);
        app.on_key(ch('3'));
        assert_eq!(app.tab, Tab::Files);
    }

    #[test]
    fn start_stop_depends_on_state() {
        let mut state = session(&["a"]);
        let (mut app, mut rx) = app_with(&state);
        app.on_key(ch('s'));
        assert_eq!(rx.try_recv().unwrap(), SessionCommand::Stop("a".into()));

        state.torrents[0] = view("a", DownloadState::Stopped);
        app.sync(&state);
        app.on_key(ch('s'));
        assert_eq!(rx.try_recv().unwrap(), SessionCommand::Start("a".into()));
        app.on_key(ch('p'));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn pause_and_resume() {
        let mut state = session(&["a"]);
        let (mut app, mut rx) = app_with(&state);
        app.on_key(ch('p'));
        assert_eq!(rx.try_recv().unwrap(), SessionCommand::Torrent("a".into(), Command::Pause));

        state.torrents[0] = view("a", DownloadState::Paused);
        app.sync(&state);
        app.on_key(ch('p'));
        assert_eq!(rx.try_recv().unwrap(), SessionCommand::Torrent("a".into(), Command::Resume));
    }

    #[test]
    fn remove_asks_keep_or_delete() {
        let (mut app, mut rx) = app_with(&session(&["a", "b"]));
        app.on_key(ch('j'));
        app.on_key(ch('d'));
        assert!(matches!(app.modal, Modal::Remove { .. }));
        app.on_key(ch('x'));
        assert!(matches!(app.modal, Modal::Remove { .. }));
        app.on_key(key(KeyCode::Esc));
        assert!(matches!(app.modal, Modal::None));
        assert!(rx.try_recv().is_err());

        app.on_key(ch('d'));
        app.on_key(ch('k'));
        assert_eq!(
            rx.try_recv().unwrap(),
            SessionCommand::Remove { id: "b".into(), delete_data: false }
        );
        assert!(matches!(app.modal, Modal::None));

        app.on_key(ch('d'));
        app.on_key(ch('D'));
        assert_eq!(
            rx.try_recv().unwrap(),
            SessionCommand::Remove { id: "b".into(), delete_data: true }
        );
    }

    #[test]
    fn add_flow_with_default_and_explicit_dir() {
        let (mut app, mut rx) = app_with(&session(&[]));
        app.on_key(ch('a'));
        app.on_key(key(KeyCode::Enter));
        assert!(matches!(&app.modal, Modal::Add(p) if p.error.is_some() && p.source.is_none()));

        type_text(&mut app, "magnet:?xt=urn:btih:abc");
        app.on_key(key(KeyCode::Enter));
        assert!(matches!(&app.modal, Modal::Add(p) if p.source.is_some()));
        app.on_key(key(KeyCode::Enter));
        assert_eq!(
            rx.try_recv().unwrap(),
            SessionCommand::Add { source: "magnet:?xt=urn:btih:abc".into(), dir: None }
        );
        assert!(matches!(app.modal, Modal::None));

        app.on_key(ch('a'));
        app.on_paste("'/tmp/x.torrent'\n");
        app.on_key(key(KeyCode::Enter));
        type_text(&mut app, "/data");
        app.on_key(key(KeyCode::Enter));
        assert_eq!(
            rx.try_recv().unwrap(),
            SessionCommand::Add { source: "/tmp/x.torrent".into(), dir: Some(PathBuf::from("/data")) }
        );

        app.on_key(ch('a'));
        app.on_key(key(KeyCode::Esc));
        assert!(matches!(app.modal, Modal::None));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn modal_swallows_global_keys() {
        let (mut app, mut rx) = app_with(&session(&["a"]));
        app.on_key(ch('a'));
        type_text(&mut app, "qsdp");
        assert!(!app.quit);
        assert!(rx.try_recv().is_err());
        assert!(matches!(&app.modal, Modal::Add(p) if p.input.text == "qsdp"));
    }

    #[test]
    fn limits_flow_converts_kib_to_bytes() {
        let (mut app, mut rx) = app_with(&session(&["a"]));
        app.on_key(ch('l'));
        match &app.modal {
            Modal::Limits { form, .. } => {
                assert_eq!(form.fields[0].input.text, "100");
                assert_eq!(form.fields[1].input.text, "0");
            }
            _ => panic!("limits modal expected"),
        }
        app.on_key(key(KeyCode::Backspace));
        app.on_key(key(KeyCode::Backspace));
        app.on_key(key(KeyCode::Backspace));
        type_text(&mut app, "250");
        app.on_key(key(KeyCode::Tab));
        app.on_key(key(KeyCode::Backspace));
        type_text(&mut app, "8");
        app.on_key(key(KeyCode::Enter));
        assert_eq!(
            rx.try_recv().unwrap(),
            SessionCommand::SetTorrentLimits { id: "a".into(), download: 250 * 1024, upload: 8 * 1024 }
        );
    }

    #[test]
    fn limits_reject_non_numbers_inline() {
        let (mut app, mut rx) = app_with(&session(&["a"]));
        app.on_key(ch('l'));
        type_text(&mut app, "x");
        app.on_key(key(KeyCode::Enter));
        assert!(rx.try_recv().is_err());
        match &app.modal {
            Modal::Limits { form, .. } => assert!(form.error.is_some()),
            _ => panic!("modal should stay open"),
        }
        app.on_key(key(KeyCode::Backspace));
        match &app.modal {
            Modal::Limits { form, .. } => assert!(form.error.is_none()),
            _ => panic!(),
        }
    }

    #[test]
    fn parse_kib_validates() {
        assert_eq!(parse_kib("D", " 4 "), Ok(4096));
        assert_eq!(parse_kib("D", "0"), Ok(0));
        assert!(parse_kib("D", "").is_err());
        assert!(parse_kib("D", "-1").is_err());
        assert!(parse_kib("D", "1.5").is_err());
        assert!(parse_kib("D", &u64::MAX.to_string()).is_err());
    }

    #[test]
    fn settings_round_trip_and_edit() {
        let mut state = session(&["a"]);
        state.settings = Settings {
            download_dir: PathBuf::from("/dl"),
            listen_port: 7000,
            download_limit: 2048,
            upload_limit: 0,
            ratio_target: 1.5,
            max_peers: 30,
            dht: true,
            port_forwarding: false,
            ..Settings::default()
        };
        let (mut app, mut rx) = app_with(&state);
        app.on_key(ch('o'));
        app.on_key(key(KeyCode::Enter));
        assert_eq!(rx.try_recv().unwrap(), SessionCommand::SetSettings(state.settings.clone()));

        app.on_key(ch('o'));
        for _ in 0..6 {
            app.on_key(key(KeyCode::Tab));
        }
        app.on_key(ch(' '));
        app.on_key(key(KeyCode::Tab));
        app.on_key(ch(' '));
        app.on_key(key(KeyCode::Enter));
        match rx.try_recv().unwrap() {
            SessionCommand::SetSettings(s) => {
                assert!(!s.dht);
                assert!(s.port_forwarding);
                assert_eq!(s.listen_port, 7000);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn settings_validation_blocks_bad_values() {
        let base = settings_form(&Settings::default());
        let set = |idx: usize, text: &str| {
            let mut form = base.clone();
            form.fields[idx].input = TextInput::new(text);
            parse_settings(&form, &Settings::default())
        };
        assert!(set(0, "  ").is_err());
        assert!(set(1, "0").is_err());
        assert!(set(1, "70000").is_err());
        assert!(set(1, "abc").is_err());
        assert!(set(2, "fast").is_err());
        assert!(set(3, "-5").is_err());
        assert!(set(4, "NaN").is_err());
        assert!(set(4, "-1").is_err());
        assert!(set(5, "0").is_err());
        assert_eq!(set(4, "0").unwrap().ratio_target, 0.0);
        assert_eq!(set(1, "6881").unwrap().listen_port, 6881);
        assert!(parse_settings(&base, &Settings::default()).is_ok());
        assert!(set(8, "-1").is_err());
        assert!(set(8, "x").is_err());
        assert!(set(9, "1.5").is_err());
        assert!(set(9, "").is_err());
        assert_eq!(set(8, "0").unwrap().max_active_downloads, 0);
        assert_eq!(set(9, "12").unwrap().max_active_torrents, 12);
    }

    #[test]
    fn settings_form_carries_unedited_values() {
        let base = Settings { max_active_downloads: 5, max_active_torrents: 0, ..Settings::default() };
        let form = settings_form(&base);
        assert_eq!(parse_settings(&form, &base).unwrap(), base);
        let mut edited = form.clone();
        edited.fields[8].input = TextInput::new("2");
        edited.fields[9].input = TextInput::new("4");
        let parsed = parse_settings(&edited, &base).unwrap();
        assert_eq!((parsed.max_active_downloads, parsed.max_active_torrents), (2, 4));
        assert_eq!(parsed.ratio_target, base.ratio_target);
    }

    #[test]
    fn state_styles_and_labels_for_queue_and_check() {
        assert_ne!(state_style(DownloadState::Queued), state_style(DownloadState::Downloading));
        assert_eq!(state_style(DownloadState::Checking).fg, Some(Color::Yellow));
        let cells = torrent_cells(&view("x", DownloadState::Queued));
        assert_eq!(cells[4], "queued");
        let cells = torrent_cells(&view("x", DownloadState::Checking));
        assert_eq!(cells[4], "checking");
    }

    #[test]
    fn priority_steps_clamp() {
        use FilePriority::*;
        assert_eq!(step_priority(Normal, true), High);
        assert_eq!(step_priority(High, true), High);
        assert_eq!(step_priority(Normal, false), Low);
        assert_eq!(step_priority(Low, false), Skip);
        assert_eq!(step_priority(Skip, false), Skip);
        assert_eq!(step_priority(Skip, true), Low);
    }

    #[test]
    fn r_sends_recheck() {
        let (mut app, mut rx) = app_with(&session(&["a", "b"]));
        app.on_key(ch('j'));
        app.on_key(ch('R'));
        assert_eq!(rx.try_recv().unwrap(), SessionCommand::Torrent("b".into(), Command::Recheck));
    }

    #[test]
    fn plus_and_minus_set_file_priority() {
        let (mut app, mut rx) = app_with(&session(&["a"]));
        app.on_key(ch('+'));
        assert!(rx.try_recv().is_err());
        app.on_key(ch('3'));
        app.on_key(ch('J'));
        let sent = |rx: &mut UnboundedReceiver<SessionCommand>| rx.try_recv().unwrap();
        let cmd = |p| SessionCommand::Torrent("a".into(), Command::SetFilePriority(1, p));
        app.on_key(ch('+'));
        assert_eq!(sent(&mut rx), cmd(FilePriority::High));
        app.on_key(ch('='));
        assert_eq!(sent(&mut rx), cmd(FilePriority::High));
        app.on_key(ch('-'));
        app.on_key(ch('-'));
        app.on_key(ch('-'));
        assert_eq!(sent(&mut rx), cmd(FilePriority::Normal));
        assert_eq!(sent(&mut rx), cmd(FilePriority::Low));
        assert_eq!(sent(&mut rx), cmd(FilePriority::Skip));
        app.on_key(ch('-'));
        assert_eq!(sent(&mut rx), cmd(FilePriority::Skip));
        app.on_key(ch(' '));
        assert_eq!(rx.try_recv().unwrap(), SessionCommand::Torrent("a".into(), Command::ToggleFile(1)));
    }

    #[test]
    fn brackets_move_the_queue() {
        let (mut app, mut rx) = app_with(&session(&["a", "b"]));
        app.on_key(ch('['));
        assert_eq!(rx.try_recv().unwrap(), SessionCommand::MoveQueue { id: "a".into(), up: true });
        app.on_key(ch(']'));
        assert_eq!(rx.try_recv().unwrap(), SessionCommand::MoveQueue { id: "a".into(), up: false });
    }

    #[test]
    fn settings_form_edits_queue_limits() {
        let (mut app, mut rx) = app_with(&session(&["a"]));
        app.on_key(ch('o'));
        for _ in 0..9 {
            app.on_key(key(KeyCode::Tab));
        }
        app.on_key(key(KeyCode::Backspace));
        app.on_key(ch('0'));
        app.on_key(key(KeyCode::Enter));
        match rx.try_recv().unwrap() {
            SessionCommand::SetSettings(s) => {
                assert_eq!(s.max_active_torrents, 0);
                assert_eq!(s.max_active_downloads, Settings::default().max_active_downloads);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn queued_and_checking_render_at_small_sizes() {
        let mut state = session(&["a", "b", "c"]);
        for (v, st, pos) in [
            (0, DownloadState::Queued, Some(0)),
            (1, DownloadState::Checking, Some(1)),
            (2, DownloadState::Stopped, None),
        ] {
            state.torrents[v].ui.torrent.as_mut().unwrap().state = st;
            state.torrents[v].queue_position = pos;
        }
        for (w, h) in [(80, 24), (40, 12)] {
            let mut app = SessionApp::new();
            for tab in Tab::ALL {
                app.set_tab(tab);
                draw(w, h, &state, &mut app);
            }
        }
        let mut app = SessionApp::new();
        let screen = draw(80, 24, &state, &mut app);
        assert!(screen.contains("queued") && screen.contains("checking"), "{screen}");
        assert!(screen.contains("Queue"), "{screen}");
        app.set_tab(Tab::Files);
        assert!(draw(80, 24, &state, &mut app).contains("Priority"));
    }

    #[test]
    fn files_tab_toggles_the_stable_file_index() {
        let (mut app, mut rx) = app_with(&session(&["a"]));
        app.on_key(ch(' '));
        assert!(rx.try_recv().is_err());
        app.on_key(ch('3'));
        app.on_key(ch('J'));
        app.on_key(ch(' '));
        assert_eq!(rx.try_recv().unwrap(), SessionCommand::Torrent("a".into(), Command::ToggleFile(1)));
    }

    #[test]
    fn quit_sends_quit_command() {
        let (mut app, mut rx) = app_with(&session(&["a"]));
        app.on_key(ch('q'));
        assert!(app.quit);
        assert_eq!(rx.try_recv().unwrap(), SessionCommand::Quit);
    }

    #[test]
    fn keys_are_inert_without_a_channel_or_selection() {
        let mut app = SessionApp::new();
        app.sync(&session(&["a"]));
        app.on_key(ch('s'));
        app.on_key(ch('p'));
        let mut empty = SessionApp::new();
        empty.on_key(ch('l'));
        empty.on_key(ch('s'));
        assert!(matches!(empty.modal, Modal::None));
    }

    #[test]
    fn text_input_edits() {
        let mut input = TextInput::default();
        for c in "abc".chars() {
            assert!(input.handle(&ch(c)));
        }
        assert!(input.handle(&key(KeyCode::Backspace)));
        assert_eq!(input.text, "ab");
        input.paste("cd\nignored");
        assert_eq!(input.text, "abcd");
        assert!(!input.handle(&KeyEvent::new(KeyCode::Char('x'), KeyModifiers::CONTROL)));
        assert!(input.handle(&KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)));
        assert_eq!(input.text, "");
        assert!(!input.handle(&key(KeyCode::Backspace)));
        assert!(!input.handle(&key(KeyCode::Left)));
    }

    #[test]
    fn tail_fit_keeps_the_cursor_end() {
        assert_eq!(tail_fit("abc", 5), "abc");
        assert_eq!(tail_fit("abcdef", 4), "\u{2026}def");
        assert_eq!(tail_fit("abc", 0), "");
        assert_eq!(clean_input("  \"/a b/c.torrent\" "), "/a b/c.torrent");
    }

    fn draw(width: u16, height: u16, state: &SessionState, app: &mut SessionApp) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let snapshot = Ok(state.clone());
        terminal.draw(|f| render_session(f, &snapshot, app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn renders_at_small_sizes_without_panicking() {
        for (w, h) in [(80, 24), (40, 12)] {
            for ids in [&[][..], &["a"][..], &["a", "b", "c", "d", "e", "f", "g"][..]] {
                let state = session(ids);
                let mut app = SessionApp::new();
                for tab in Tab::ALL {
                    app.set_tab(tab);
                    let screen = draw(w, h, &state, &mut app);
                    assert!(screen.contains("add"), "{w}x{h} {tab:?}:\n{screen}");
                    assert!(screen.contains("quit") || w < 80, "{w}x{h}:\n{screen}");
                    if ids.is_empty() {
                        assert!(screen.contains("No torrents"), "{screen}");
                    }
                }
            }
        }
    }

    #[test]
    fn wide_render_shows_table_and_details() {
        let mut state = session(&["a", "b"]);
        state.port_status = "port 6881 forwarded".to_string();
        let mut app = SessionApp::new();
        let screen = draw(80, 24, &state, &mut app);
        for needle in ["2 torrents", "port 6881", "name-a", "name-b", "Status", "Ratio", "1.25", "downloading", "General", "Infohash", "quit"] {
            assert!(screen.contains(needle), "missing {needle}:\n{screen}");
        }
        app.set_tab(Tab::Trackers);
        assert!(draw(80, 24, &state, &mut app).contains("tracker.example"));
        app.set_tab(Tab::Log);
        assert!(draw(80, 24, &state, &mut app).contains("log-a"));
        app.set_tab(Tab::Peers);
        assert!(draw(80, 24, &state, &mut app).contains("1.2.3.4"));
        app.set_tab(Tab::Files);
        assert!(draw(80, 24, &state, &mut app).contains("a.bin"));
    }

    #[test]
    fn modals_render_at_both_sizes() {
        let state = session(&["a"]);
        for (w, h) in [(80, 24), (40, 12)] {
            for key_char in ['a', 'd', 'l', 'o', '?'] {
                let mut app = SessionApp::new();
                draw(w, h, &state, &mut app);
                app.on_key(ch(key_char));
                let screen = draw(w, h, &state, &mut app);
                assert!(!screen.trim().is_empty());
            }
        }
        let mut app = SessionApp::new();
        draw(80, 24, &state, &mut app);
        app.on_key(ch('d'));
        assert!(draw(80, 24, &state, &mut app).contains("delete data"));
        app.on_key(key(KeyCode::Esc));
        app.on_key(ch('o'));
        assert!(draw(80, 24, &state, &mut app).contains("Listen port"));
    }

    #[test]
    fn too_small_and_warning() {
        let mut state = session(&["a"]);
        let mut app = SessionApp::new();
        assert!(draw(20, 5, &state, &mut app).contains("too small"));
        state.warning = Some("tracker down".to_string());
        assert!(draw(80, 24, &state, &mut app).contains("tracker down"));
    }
}
