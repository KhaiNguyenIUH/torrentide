//! Command-line entry point.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use tokio::sync::RwLock;

use torrentide::engine::{self, Engine};
use torrentide::metainfo::{Magnet, Metainfo};
use torrentide::state::{Level, UiState};

#[derive(Parser)]
#[command(
    name = "torrentide",
    version,
    about = "A BitTorrent client with a TUI",
    long_about = "Download torrents over the BitTorrent protocol.\n\n\
                  Accepts a local .torrent file or a magnet: URI."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the multi-torrent session (the default when no subcommand is given)
    Session {
        /// Print a summary line every few seconds instead of starting the TUI
        #[arg(long)]
        no_tui: bool,

        /// Run as the background service the TUI attaches to
        #[arg(long, hide = true)]
        background: bool,
    },

    /// Stop the background torrentide session
    Stop,

    /// Set the web UI password (read from stdin) and enable the web UI
    ///
    /// The password is stored only as a salted hash, and reading it from stdin
    /// keeps it out of shell history. Restart the session afterwards.
    WebuiPassword,

    /// Hand a .torrent or magnet link to the running session, or queue it
    Add {
        /// Path to a .torrent file, or a magnet: URI
        source: String,

        /// Directory to save into (default: the session's download directory)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Download a torrent to a directory
    Download {
        /// Path to a .torrent file, or a magnet: URI
        source: String,

        /// Directory to save the downloaded files into
        #[arg(short, long, default_value = ".")]
        output: PathBuf,

        /// Exit when the download finishes instead of waiting
        #[arg(long)]
        exit_when_done: bool,

        /// Print progress to stdout instead of starting the TUI
        #[arg(long)]
        no_tui: bool,
    },

    /// Create a .torrent file from a file or directory
    Create {
        /// File or directory to share
        path: PathBuf,

        /// Output file (default: <name>.torrent in the current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Tracker announce URL (repeatable; each gets its own tier)
        #[arg(short, long = "tracker")]
        tracker: Vec<String>,

        /// HTTP(S) web seed URL (repeatable)
        #[arg(long)]
        web_seed: Vec<String>,

        /// Mark the torrent private (no DHT, PEX or local discovery)
        #[arg(long)]
        private: bool,

        /// Piece size in KiB (power of two, 16 to 16384; default: automatic)
        #[arg(long)]
        piece_size: Option<u32>,

        /// Free-form comment
        #[arg(long)]
        comment: Option<String>,

        /// Source tag (changes the infohash)
        #[arg(long)]
        source: Option<String>,

        /// Leave out the creation date
        #[arg(long)]
        no_date: bool,

        /// Overwrite an existing output file
        #[arg(long)]
        force: bool,

        /// Hand the new torrent to the session and seed it from <path>'s parent
        #[arg(long)]
        seed: bool,
    },

    /// Parse a .torrent file and print its contents without downloading
    Inspect {
        /// Path to a .torrent file
        path: PathBuf,
    },

    /// Parse a magnet URI and print what it contains
    #[command(alias = "m")]
    Magnet {
        /// The magnet: URI
        uri: String,
    },

    /// Adopt a half-downloaded torrent from another client
    ///
    /// Matches the other app's files against the torrent (tolerating its
    /// `.!qB` incomplete-file suffix and no-subfolder layouts), transfers
    /// them into the download directory, and verifies what will resume.
    /// Stop the other client first.
    Import {
        /// Path to the .torrent file (must be the same torrent)
        torrent: PathBuf,

        /// Directory holding the other app's files
        #[arg(short, long)]
        from: PathBuf,

        /// Directory to place the adopted files into (our download dir)
        #[arg(short, long, default_value = ".")]
        output: PathBuf,

        /// How to bring the bytes over: copy, move, or link (hard-link)
        #[arg(long, default_value = "copy")]
        mode: String,

        /// Skip the post-transfer hash check (trust name+size matching;
        /// startup will still verify before downloading)
        #[arg(long)]
        no_verify: bool,

        /// Start downloading immediately after importing
        #[arg(long)]
        start: bool,

        /// Exit when the download finishes instead of waiting (with --start)
        #[arg(long)]
        exit_when_done: bool,

        /// Print progress to stdout instead of starting the TUI (with --start)
        #[arg(long)]
        no_tui: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    #[cfg(windows)]
    if cli.command.is_none() {
        if let Err(e) = run(cli).await {
            eprintln!("error: {e:#}\npress Enter to exit");
            let _ = std::io::stdin().read_line(&mut String::new());
            std::process::exit(1);
        }
        return Ok(());
    }
    run(cli).await
}

async fn run(cli: Cli) -> Result<()> {
    let command = cli.command.unwrap_or(Command::Session { no_tui: false, background: false });
    let uses_tui = matches!(
        command,
        Command::Session { no_tui: false, .. }
            | Command::Download { no_tui: false, .. }
            | Command::Import { no_tui: false, start: true, .. }
    );
    init_tracing(uses_tui);

    match command {
        Command::Session { no_tui, background } => {
            let store = torrentide::store::Store::open();
            if background {
                return torrentide::session::Session::run_background(store.load_settings()).await;
            }
            #[cfg(unix)]
            if !no_tui {
                return attach_tui(&store).await;
            }
            torrentide::session::Session::run(store.load_settings(), !no_tui).await
        }
        #[cfg(windows)]
        Command::Stop => {
            println!(
                "torrentide stop is not available on Windows: the session runs in the window that started it (torrentide or torrentide session); close it there with Q or Ctrl-C"
            );
            Ok(())
        }
        #[cfg(not(windows))]
        Command::Stop => {
            if torrentide::ipc::stop(&torrentide::store::Store::open()).await {
                println!("stopping torrentide");
            } else {
                println!("no torrentide session is running");
            }
            Ok(())
        }
        Command::WebuiPassword => set_webui_password().await,
        Command::Add { source, output } => {
            use torrentide::ipc::Delivery;
            #[cfg(unix)]
            let watch = {
                let store = torrentide::store::Store::open();
                if !torrentide::ipc::session_running(&store) {
                    start_service(&store).await?;
                }
                torrentide::ipc::attach(&store).await.ok().map(|(state, _)| state)
            };
            #[cfg(not(unix))]
            let watch: Option<Arc<RwLock<torrentide::state::SessionState>>> = None;
            let before = match &watch {
                Some(state) => state.read().await.log_total,
                None => 0,
            };
            match torrentide::ipc::send_add(&source, output.as_deref()).await? {
                Delivery::Delivered => match watch {
                    Some(state) => println!("{}", add_outcome(&state, before).await?),
                    None => println!("sent to the running session"),
                },
                Delivery::Queued => println!("queued; it will start next time torrentide runs"),
            }
            Ok(())
        }
        Command::Download {
            source,
            output,
            exit_when_done,
            no_tui,
        } => run_download(&source, output, exit_when_done, no_tui).await,
        Command::Create {
            path,
            output,
            tracker,
            web_seed,
            private,
            piece_size,
            comment,
            source,
            no_date,
            force,
            seed,
        } => {
            let opts = torrentide::create::CreateOptions {
                path,
                trackers: tracker,
                web_seeds: web_seed,
                private,
                piece_len: piece_size
                    .map(|k| k.checked_mul(1024).context("--piece-size is too large"))
                    .transpose()?,
                comment,
                source,
                no_date,
                progress: std::io::IsTerminal::is_terminal(&std::io::stdout()),
            };
            run_create(opts, output, force, seed).await
        }
        Command::Inspect { path } => inspect(&path),
        Command::Magnet { uri } => inspect_magnet(&uri),
        Command::Import {
            torrent,
            from,
            output,
            mode,
            no_verify,
            start,
            exit_when_done,
            no_tui,
        } => {
            run_import(
                &torrent,
                &from,
                output,
                &mode,
                !no_verify,
                start,
                exit_when_done,
                no_tui,
            )
            .await
        }
    }
}

struct EchoOff(String);

impl EchoOff {
    #[cfg(unix)]
    fn new() -> Option<EchoOff> {
        use std::io::IsTerminal;
        use std::process::{Command, Stdio};
        if !std::io::stdin().is_terminal() {
            return None;
        }
        let saved = Command::new("stty").arg("-g").stdin(Stdio::inherit()).output().ok()?;
        let saved = String::from_utf8(saved.stdout).ok()?.trim().to_owned();
        let off = Command::new("stty").arg("-echo").status().ok()?;
        (off.success() && !saved.is_empty()).then_some(EchoOff(saved))
    }

    #[cfg(not(unix))]
    fn new() -> Option<EchoOff> {
        None
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = std::process::Command::new("stty").arg(&self.0).status();
    }
}

#[cfg(unix)]
async fn attach_tui(store: &torrentide::store::Store) -> Result<()> {
    if !torrentide::ipc::session_running(store) {
        start_service(store).await?;
    }
    let (state, sender) = torrentide::ipc::attach(store).await?;
    let ui = Arc::clone(&state);
    let result = tokio::task::spawn_blocking(move || torrentide::tui::run_session_tui(ui))
        .await
        .context("the TUI task panicked")?;
    // Let a final command (`Q` sends Quit) reach the session before exiting.
    state.write().await.command_tx = None;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), sender).await;
    result
}

/// Start `torrentide session --background`, detached from this terminal, and
/// wait for it to answer on the socket.
#[cfg(unix)]
async fn start_service(store: &torrentide::store::Store) -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    let mut child = std::process::Command::new(std::env::current_exe().context("locating the torrentide binary")?)
        .args(["session", "--background"])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("starting the background session")?;
    for _ in 0..100 {
        if torrentide::ipc::session_running(store) {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            bail!("the background session exited ({status}); see {}", log_path().display());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    bail!("the background session did not start within 10 s; see {}", log_path().display())
}

/// Wait briefly for the session to log the result of an add sent after
/// `before` log lines, so the caller sees "added X" or why it was refused.
async fn add_outcome(state: &RwLock<torrentide::state::SessionState>, before: u64) -> Result<String> {
    for _ in 0..50 {
        {
            let st = state.read().await;
            let fresh = (st.log_total.saturating_sub(before) as usize).min(st.log.len());
            for l in &st.log[st.log.len() - fresh..] {
                if l.message.starts_with("cannot add ") {
                    bail!("{}", l.message);
                }
                if l.message.starts_with("added ") {
                    return Ok(l.message.clone());
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Ok("sent to the running session; still working on it (see the TUI or web UI)".to_string())
}

async fn set_webui_password() -> Result<()> {
    let store = torrentide::store::Store::open();
    if torrentide::ipc::session_running(&store) {
        bail!("a torrentide session is running and would overwrite these settings when it quits; stop it, then run this command again");
    }
    eprintln!("New web UI password (one line):");
    let echo = EchoOff::new();
    let read = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).map(|_| line)
    });
    let line = tokio::select! {
        r = read => r.context("reading the password")?.context("reading the password")?,
        _ = tokio::signal::ctrl_c() => {
            drop(echo);
            eprintln!();
            std::process::exit(130);
        }
    };
    if echo.is_some() {
        drop(echo);
        eprintln!();
    }
    let password = line.trim_end_matches(['\r', '\n']);
    if password.is_empty() {
        bail!("the password cannot be empty");
    }
    let mut settings = store.load_settings();
    settings.webui.enabled = true;
    settings.webui.password = Some(torrentide::store::hash_password(password));
    store.save_settings(&settings)?;
    println!("web UI enabled with the new password (stored as a salted hash)");
    println!("open http://localhost:{}/ (any user name) after the session restarts", settings.webui.port);
    Ok(())
}

async fn run_download(
    source: &str,
    output: PathBuf,
    exit_when_done: bool,
    no_tui: bool,
) -> Result<()> {
    validate_source(source)?;

    let state = Arc::new(RwLock::new(UiState::default()));

    // Commands flow TUI -> engine. The sender is published in the shared state
    // so the UI thread can clone it out of any snapshot; the receiver is owned
    // by whichever engine starts below.
    let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel();
    state.write().await.command_tx = Some(command_tx);

    if source.starts_with("magnet:") {
        let magnet = Magnet::parse(source)?;
        log_to(
            &state,
            Level::Info,
            format!("parsed magnet {}", magnet.infohash),
        )
        .await;

        if !no_tui {
            log_to(&state, Level::Info, format!("logs: {}", log_path().display())).await;
        }

        // Without a TUI and with --exit-when-done we still need a driver, so
        // always run the engine in a task.
        let ui = spawn_ui_if_needed(&state, no_tui);

        let handle = tokio::spawn(engine::run_magnet(
            magnet,
            output.clone(),
            Arc::clone(&state),
            command_rx,
        ));
        return finish(handle, &state, ui, exit_when_done, exit_when_done || no_tui).await;
    }

    let raw = std::fs::read(source).map_err(|e| anyhow::anyhow!("reading {source}: {e}"))?;
    let meta = Arc::new(Metainfo::from_bytes(&raw).context("parsing .torrent file")?);

    start_download(meta, output, &state, command_rx, exit_when_done, no_tui).await
}

/// Adopt a half-finished download from another client: match its files,
/// transfer them into our layout, verify what will resume, and optionally
/// start downloading immediately.
#[allow(clippy::too_many_arguments)]
async fn run_import(
    torrent: &Path,
    from: &Path,
    output: PathBuf,
    mode: &str,
    verify: bool,
    start: bool,
    exit_when_done: bool,
    no_tui: bool,
) -> Result<()> {
    use torrentide::import;
    use torrentide::state::human_bytes;

    if !from.is_dir() {
        bail!("--from {} is not a directory", from.display());
    }
    let mode: import::Mode = mode.parse()?;

    let raw = std::fs::read(torrent).map_err(|e| anyhow::anyhow!("reading {}: {e}", torrent.display()))?;
    let meta = Metainfo::from_bytes(&raw).context("parsing .torrent file")?;

    let file_count = meta.files.iter().count();
    println!("importing {}", meta.name);
    println!("  torrent:  {} ({} files, {})", torrent.display(), file_count, human_bytes(meta.total_length));
    println!("  from:     {}", from.display());
    println!("  into:     {}", output.display());
    println!("  mode:     {mode:?}");
    println!();

    let plan = import::plan(&meta, from);
    for f in &plan.found {
        let note = if f.source_len == f.length {
            String::new()
        } else if f.source_len < f.length {
            format!("  (partial: {} of {} on disk)", human_bytes(f.source_len), human_bytes(f.length))
        } else {
            "  (larger than expected — will be truncated)".to_string()
        };
        let renamed = if f.renamed { "  [stripped .!qB]" } else { "" };
        println!(
            "  FOUND   {:>10}  {}{}{}",
            human_bytes(f.source_len.min(f.length)),
            f.rel.display(),
            renamed,
            note,
        );
    }
    for m in &plan.missing {
        println!(
            "  MISSING {:>10}  {}  (will download)",
            human_bytes(m.length),
            m.rel.display(),
        );
    }
    println!();
    println!(
        "  {} of {} on disk{}",
        human_bytes(plan.found_bytes()),
        human_bytes(plan.total_bytes()),
        if plan.missing.is_empty() {
            String::new()
        } else {
            format!(" — {} will be fetched", human_bytes(plan.missing_bytes()))
        }
    );

    let rep = import::execute(&plan, &output, mode)?;
    println!(
        "  transferred {} (copy:{}, move:{}, link:{}, in place:{}, renamed:{})",
        human_bytes(rep.bytes),
        rep.copied,
        rep.moved,
        rep.linked,
        rep.in_place,
        rep.renamed,
    );

    if verify {
        println!("  verifying...");
        let v = import::verify(&meta, &output)?;
        println!(
            "  verified {}/{} pieces — {} will resume",
            v.pieces_verified,
            v.pieces_total,
            human_bytes(v.bytes_verified),
        );
    } else {
        println!("  (skipped verification; startup will verify before downloading)");
    }

    if start {
        println!();
        let state = Arc::new(RwLock::new(UiState::default()));
        let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel();
        state.write().await.command_tx = Some(command_tx);
        start_download(Arc::new(meta), output, &state, command_rx, exit_when_done, no_tui).await
    } else {
        println!();
        println!(
            "  now run: torrentide download {} --output {}",
            torrent.display(),
            output.display()
        );
        Ok(())
    }
}
/// Publish the torrent summary, start the TUI, run the engine, and shut down
/// gracefully.
async fn start_download(
    meta: Arc<Metainfo>,
    output: PathBuf,
    state: &Arc<RwLock<UiState>>,
    command_rx: tokio::sync::mpsc::UnboundedReceiver<torrentide::state::Command>,
    exit_when_done: bool,
    no_tui: bool,
) -> Result<()> {
    {
        let mut st = state.write().await;
        st.torrent = Some(torrentide::state::TorrentSummary {
            name: meta.name.clone(),
            infohash: meta.infohash.to_hex(),
            total_length: meta.total_length,
            piece_length: meta.piece_length,
            piece_count: meta.piece_count() as u32,
            download_dir: output.display().to_string(),
            trackers: meta.announce_list.clone(),
            ..Default::default()
        });
        st.log(Level::Info, format!("loaded {}", meta.name));
        if !no_tui {
            st.log(Level::Info, format!("logs: {}", log_path().display()));
        }
        if meta.announce_list.is_empty() {
            if meta.private {
                st.log(
                    Level::Warn,
                    "private torrent with no trackers: DHT is disabled for private torrents, so no peers can be found",
                );
            } else {
                st.log(
                    Level::Warn,
                    "torrent has no trackers; peers will come from the DHT only",
                );
            }
        }
    }

    let ui = spawn_ui_if_needed(state, no_tui);

    let engine = Engine::new(meta, Arc::clone(state), command_rx);
    let handle = tokio::spawn(engine.run(output));
    finish(handle, state, ui, exit_when_done, exit_when_done || no_tui).await
}

/// Run the TUI on a dedicated thread unless the caller opted out.
///
/// Returns the thread handle so the caller can wait for a graceful shutdown
/// (terminal restored) instead of letting process exit kill the UI mid-frame.
fn spawn_ui_if_needed(state: &Arc<RwLock<UiState>>, skip: bool) -> Option<std::thread::JoinHandle<()>> {
    if skip {
        return None;
    }
    let ui_state = Arc::clone(state);
    Some(std::thread::spawn(move || {
        if let Err(e) = torrentide::tui::run_tui(ui_state) {
            tracing::error!("TUI exited with an error: {e}");
        }
    }))
}

/// Await the engine, shut the UI down gracefully, then print a final summary.
///
/// When the TUI is active the process must not return while it is mid-frame:
/// that would leave a frozen stale frame painted on the terminal. So with
/// `--exit-when-done` we signal shutdown and join the UI thread (which
/// restores the console) before printing; otherwise we wait for the user to
/// quit with `q`, leaving the finished state on screen for inspection.
async fn finish(
    handle: tokio::task::JoinHandle<Result<()>>,
    state: &Arc<RwLock<UiState>>,
    ui: Option<std::thread::JoinHandle<()>>,
    exit_when_done: bool,
    print_summary: bool,
) -> Result<()> {
    let result = handle.await.context("download task panicked")?;

    if let Err(e) = &result {
        let mut st = state.write().await;
        st.log(Level::Error, format!("{e}"));
        if let Some(t) = &mut st.torrent {
            t.state = torrentide::state::DownloadState::Error;
        }
    }

    if exit_when_done {
        state.write().await.shutdown = true;
    }
    if let Some(h) = ui {
        // `JoinHandle::join` blocks; run it off the async runtime.
        let _ = tokio::task::spawn_blocking(|| h.join()).await;
    }

    if print_summary {
        let st = state.read().await;
        if let Some(t) = &st.torrent {
            println!();
            println!("  {}", t.name);
            println!("  infohash    {}", t.infohash);
            println!("  size        {}", t.human_size());
            println!(
                "  progress    {:.1}% ({}/{} pieces)",
                t.progress * 100.0,
                t.verified_pieces,
                t.piece_count
            );
            println!("  downloaded  {}", t.human_downloaded());
            println!("  saved to    {}", t.download_dir);
        }
        for line in st.log.iter() {
            println!("  [{}] {}", line.level.label(), line.message);
        }
        println!();
    }

    result
}

async fn log_to(state: &Arc<RwLock<UiState>>, level: Level, msg: String) {
    state.write().await.log(level, msg);
}

async fn run_create(
    opts: torrentide::create::CreateOptions,
    output: Option<PathBuf>,
    force: bool,
    seed: bool,
) -> Result<()> {
    use std::io::Write;

    let output = match output {
        Some(o) => o,
        None => PathBuf::from(format!("{}.torrent", torrentide::create::torrent_name(&opts.path)?)),
    };
    if !force && output.exists() {
        bail!("{} already exists (use --force to overwrite)", output.display());
    }
    let created = torrentide::create::build(&opts)?;
    let mut file = std::fs::OpenOptions::new();
    file.write(true);
    if force {
        file.create(true).truncate(true);
    } else {
        file.create_new(true);
    }
    file.open(&output)
        .and_then(|mut f| f.write_all(&created.bytes))
        .with_context(|| format!("writing {}", output.display()))?;

    println!("name        {}", created.name);
    println!("size        {}", torrentide::state::human_bytes(created.total));
    println!("pieces      {} x {} KiB", created.pieces, created.piece_len / 1024);
    println!("infohash    {}", created.infohash);
    println!("magnet      {}", created.magnet);
    println!("saved to    {}", output.display());

    if seed {
        use torrentide::ipc::Delivery;
        let parent = std::fs::canonicalize(&opts.path)?
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/"));
        match torrentide::ipc::send_add(&output.to_string_lossy(), Some(&parent)).await? {
            Delivery::Delivered => println!("seeding: added to running session"),
            Delivery::Queued => println!("seeding: queued; it will start next time torrentide runs"),
        }
    }
    Ok(())
}

fn inspect(path: &std::path::Path) -> Result<()> {
    let raw =
        std::fs::read(path).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    let m = Metainfo::from_bytes(&raw)?;

    println!("name        {}", m.name);
    println!("infohash    {}", m.infohash);
    println!("private     {}", m.private);
    println!(
        "total size  {} ({} bytes)",
        torrentide::state::human_bytes(m.total_length),
        m.total_length
    );
    println!("pieces      {} x {}", m.piece_count(), m.piece_length);
    match &m.announce {
        Some(a) => println!("announce    {a}"),
        None => println!("announce    (none)"),
    }
    if m.announce_list.len() > 1 {
        println!("trackers    ({} total)", m.announce_list.len());
        for t in &m.announce_list {
            println!("              {t}");
        }
    }

    println!("\nfiles");
    for (p, len) in m.files.iter() {
        println!(
            "  {:>12}  {}",
            torrentide::state::human_bytes(len),
            p.display()
        );
    }
    Ok(())
}

fn inspect_magnet(uri: &str) -> Result<()> {
    let m = Magnet::parse(uri)?;
    println!("infohash    {}", m.infohash);
    if let Some(dn) = &m.display_name {
        println!("name        {dn}");
    }
    if m.trackers.is_empty() {
        println!("trackers    (none — DHT only)");
    } else {
        println!("trackers    ({} total)", m.trackers.len());
        for t in &m.trackers {
            println!("              {t}");
        }
    }
    if m.trackers.is_empty() && m.display_name.is_none() {
        println!("\nnote: without trackers or a display name, metadata must come from the DHT");
    }
    Ok(())
}

fn log_path() -> PathBuf {
    torrentide::store::data_dir().join("torrentide.log")
}

/// With the TUI running, logs go to a file so they cannot corrupt the screen
/// (if the file cannot be opened they are dropped, never sent to the
/// terminal). Otherwise they go to stderr.
fn init_tracing(to_file: bool) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("torrentide=info,warn"));
    let file_layer = to_file.then(|| {
        let file = torrentide::store::open_log(&log_path()).ok();
        fmt::layer()
            .with_writer(file.map(std::sync::Mutex::new).map_or_else(
                || tracing_subscriber::fmt::writer::BoxMakeWriter::new(std::io::sink),
                tracing_subscriber::fmt::writer::BoxMakeWriter::new,
            ))
            .with_ansi(false)
    });
    let stderr_layer = (!to_file)
        .then(|| fmt::layer().with_writer(std::io::stderr).with_ansi(false));
    let _ = tracing_subscriber::registry()
        .with(file_layer)
        .with(stderr_layer)
        .with(filter)
        .try_init();
}

/// Guard against a source that is neither a readable file nor a magnet URI.
fn validate_source(source: &str) -> Result<()> {
    if source.starts_with("magnet:") {
        return Ok(());
    }
    let p = std::path::Path::new(source);
    if !p.exists() {
        bail!(
            "{source} is neither a magnet: URI nor an existing file.\n\
             Usage: torrentide download <file.torrent|magnet:?xt=...>"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_nonexistent_source() {
        assert!(
            validate_source("magnet:?xt=urn:btih:0000000000000000000000000000000000000000").is_ok()
        );
        assert!(validate_source(r"C:\definitely\not\here.torrent").is_err());
    }
}
