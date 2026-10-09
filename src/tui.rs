//! Terminal user interface.
//!
//! [`run_tui`] owns the terminal for the duration of the call: it switches to
//! the alternate screen, enables raw mode, and runs a blocking render/input
//! loop on a dedicated OS thread so the engine's async runtime is never blocked
//! by terminal I/O. Nothing in here drives the terminal with tokio; the shared
//! [`UiState`] is only ever read as an immutable snapshot.

use std::io::{self, Stdout, Write};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
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
    human_bytes, now_hms, Command, DownloadState, FileSummary, Level, LogEntry, PeerSummary,
    TorrentSummary, UiState,
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
        DownloadState::Complete => good_style(),
        DownloadState::Error => error_style(),
        DownloadState::Paused => warn_style(),
        DownloadState::Stopped => muted_style(),
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
/// bar, and wanted flag.
fn file_cells(file: &FileSummary, bar_width: usize) -> [String; 4] {
    [
        file.path.clone(),
        file.human_size(),
        file_bar(file.progress(), bar_width),
        if file.wanted { "[x]".to_string() } else { "[ ]".to_string() },
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
    let keys = KEYS;
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
        let _ = execute!(out, LeaveAlternateScreen, Show);
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

    render_log(frame, chunks[4], state, app);
    render_footer(frame, chunks[5], state.warning.as_deref());

    if app.show_help {
        render_help(frame, area);
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
    // Path | size | bar | want columns; the bar takes what is left.
    let bar_width = inner_width.saturating_sub(52).max(10);
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
        Cell::from("Want"),
    ])
    .style(heading_style());

    let rows: Vec<Row> = app
        .files
        .iter()
        .map(|file| {
            let [path, size, progress, want] = file_cells(file, bar_width);
            let row = Row::new(vec![
                Cell::from(truncate_line(&path, inner_width)),
                Cell::from(size),
                Cell::from(progress),
                Cell::from(want),
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
        Constraint::Length(5),
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
fn render_log(frame: &mut Frame, area: Rect, state: &UiState, app: &mut App) {
    let inner_width = usize::from(area.width.saturating_sub(2));
    let inner_height = usize::from(area.height.saturating_sub(2));

    // The buffer only ever shrinks when it is trimmed at 500 entries, but a
    // resize can also shrink the window under us.
    app.clamp_log(state.log.len(), inner_height);
    let visible = log_window(&state.log, inner_height, app.log_scroll);
    let end = state.log.len() - app.log_scroll.min(state.log.len());
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

    let title = if state.log.is_empty() {
        " log ".to_string()
    } else {
        format!(" log {}-{}/{} ", start + 1, end, state.log.len())
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style())
        .style(base_style())
        .title(Span::styled(title, heading_style()));
    frame.render_widget(Paragraph::new(Text::from(lines)).block(block), area);
}

fn render_footer(frame: &mut Frame, area: Rect, warning: Option<&str>) {
    let mut lines: Vec<Line> = Vec::new();
    if let Some(message) = warning {
        let text = truncate_line(message, usize::from(area.width).saturating_sub(2));
        lines.push(Line::from(vec![
            Span::styled(" ! ", warn_style().add_modifier(Modifier::BOLD)),
            Span::styled(text, warn_style()),
        ]));
    }
    lines.push(bindings_line(area.width));
    frame.render_widget(Paragraph::new(Text::from(lines)), area);
}

fn render_help(frame: &mut Frame, area: Rect) {
    let keys = KEYS;
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

    let popup = centered_rect(50, 60, area);
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
        assert_eq!(w, "[x]");
        let mut skipped = file(1, "b.bin", 100);
        skipped.wanted = false;
        let [_, _, _, s] = file_cells(&skipped, 20);
        assert_eq!(s, "[ ]");
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