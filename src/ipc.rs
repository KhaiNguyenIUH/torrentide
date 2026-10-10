//! Hand-off of `torrust add` to a running session over a Unix socket in the
//! data directory. One request per connection: `ADD\t<source>\t<dir>\n`
//! answered by `OK\n` or `ERR <message>\n`, or `STOP\n` answered by `OK\n`.
//! Where there is no session, or on platforms without Unix sockets, the add is
//! queued in the store instead.
//!
//! `ATTACH\n` turns the connection into a stream of frames (a big-endian u32
//! length, then a postcard payload): the session sends a `SessionState`
//! snapshot every 250 ms and the client sends `SessionCommand`s.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::store::Store;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Delivered,
    Queued,
}

/// A magnet or http(s) link rather than a path.
fn is_link(source: &str) -> bool {
    let lower = source.to_ascii_lowercase();
    lower.starts_with("magnet:") || lower.starts_with("http://") || lower.starts_with("https://")
}

/// Make a source usable from a session with a different working directory.
fn absolutize(source: &str) -> String {
    if is_link(source) {
        return source.to_owned();
    }
    std::path::absolute(source)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| source.to_owned())
}

pub async fn send_add(source: &str, dir: Option<&Path>) -> Result<Delivery> {
    send_add_to(&Store::open(), source, dir).await
}

pub async fn send_add_to(store: &Store, source: &str, dir: Option<&Path>) -> Result<Delivery> {
    let source = absolutize(source);
    let dir: Option<PathBuf> = dir.map(|d| std::path::absolute(d).unwrap_or_else(|_| d.to_path_buf()));
    #[cfg(unix)]
    if let Some(reply) = unix::request(store, &source, dir.as_deref()).await {
        return match reply.strip_prefix("ERR ") {
            Some(msg) => Err(anyhow::anyhow!("{msg}")),
            None => Ok(Delivery::Delivered),
        };
    }
    store.enqueue(&source, dir.as_deref())?;
    Ok(Delivery::Queued)
}

/// Whether a session is answering on the data directory's socket.
pub fn session_running(store: &Store) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(store.socket_path()).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = store;
        false
    }
}

/// Ask a running session to shut down; `false` when none is running.
pub async fn stop(store: &Store) -> bool {
    #[cfg(unix)]
    {
        unix::exchange(store, "STOP\n").await.is_some()
    }
    #[cfg(not(unix))]
    {
        let _ = store;
        false
    }
}

#[cfg(unix)]
pub use unix::{attach, listen};

#[cfg(not(unix))]
pub fn listen(
    _store: &Store,
    _tx: tokio::sync::mpsc::UnboundedSender<crate::state::SessionCommand>,
    _state: std::sync::Arc<tokio::sync::RwLock<crate::state::SessionState>>,
) -> Result<Option<tokio::task::JoinHandle<()>>> {
    Ok(None)
}

#[cfg(unix)]
mod unix {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{bail, Context, Result};
    use tokio::io::{
        AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf, WriteHalf,
    };
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
    use tokio::sync::RwLock;

    use crate::state::{SessionCommand, SessionState};
    use crate::store::Store;

    const IO_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_LINE: u64 = 64 * 1024;
    const SNAPSHOT_EVERY: Duration = Duration::from_millis(250);
    const MAX_COMMAND_FRAME: usize = 1024 * 1024;
    const MAX_STATE_FRAME: usize = 64 * 1024 * 1024;

    /// `None` when no session is listening.
    pub async fn request(store: &Store, source: &str, dir: Option<&Path>) -> Option<String> {
        let line = format!(
            "ADD\t{}\t{}\n",
            source.replace(['\t', '\n'], " "),
            dir.map(|d| d.to_string_lossy().replace(['\t', '\n'], " ")).unwrap_or_default()
        );
        exchange(store, &line).await
    }

    /// Send one request line and read the one-line reply; `None` when no
    /// session is listening.
    pub async fn exchange(store: &Store, line: &str) -> Option<String> {
        let path = store.socket_path();
        let attempt = async {
            let mut s = UnixStream::connect(&path).await.ok()?;
            s.write_all(line.as_bytes()).await.ok()?;
            let mut reply = String::new();
            BufReader::new(s.take(MAX_LINE)).read_line(&mut reply).await.ok()?;
            Some(reply.trim().to_owned())
        };
        tokio::time::timeout(IO_TIMEOUT, attempt).await.ok().flatten()
    }

    async fn write_frame(w: &mut (impl AsyncWrite + Unpin), payload: &[u8]) -> std::io::Result<()> {
        let len = u32::try_from(payload.len())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large"))?;
        w.write_all(&len.to_be_bytes()).await?;
        w.write_all(payload).await?;
        w.flush().await
    }

    async fn read_frame(r: &mut (impl AsyncRead + Unpin), max: usize) -> std::io::Result<Vec<u8>> {
        let mut len = [0u8; 4];
        r.read_exact(&mut len).await?;
        let len = u32::from_be_bytes(len) as usize;
        if len > max {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
        }
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf).await?;
        Ok(buf)
    }

    /// Connect to a running session and mirror its state. The mirror's
    /// `command_tx` feeds the session; when the connection ends the mirror's
    /// `shutdown` is set. The returned task ends once every `command_tx` is
    /// dropped and the commands queued before that have been sent.
    pub async fn attach(store: &Store) -> Result<(Arc<RwLock<SessionState>>, tokio::task::JoinHandle<()>)> {
        let path = store.socket_path();
        let mut stream = UnixStream::connect(&path)
            .await
            .with_context(|| format!("connecting to the torrust session at {}", path.display()))?;
        stream.write_all(b"ATTACH\n").await?;
        let (mut reader, mut writer) = tokio::io::split(stream);
        let first = tokio::time::timeout(IO_TIMEOUT, read_frame(&mut reader, MAX_STATE_FRAME))
            .await
            .context("the torrust session did not answer")??;
        let (tx, mut rx) = unbounded_channel::<SessionCommand>();
        let mut snapshot: SessionState = postcard::from_bytes(&first).context("decoding the session state")?;
        snapshot.command_tx = Some(tx);
        let mirror = Arc::new(RwLock::new(snapshot));

        let state = Arc::clone(&mirror);
        tokio::spawn(async move {
            while let Ok(frame) = read_frame(&mut reader, MAX_STATE_FRAME).await {
                let Ok(mut next) = postcard::from_bytes::<SessionState>(&frame) else {
                    break;
                };
                let mut guard = state.write().await;
                next.command_tx = guard.command_tx.take();
                *guard = next;
            }
            state.write().await.shutdown = true;
        });
        let sender = tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                let Ok(payload) = postcard::to_stdvec(&cmd) else {
                    continue;
                };
                if write_frame(&mut writer, &payload).await.is_err() {
                    break;
                }
            }
        });
        Ok((mirror, sender))
    }

    /// Start serving requests, replacing a stale socket file but refusing to
    /// start if another session answers on it.
    pub fn listen(
        store: &Store,
        tx: UnboundedSender<SessionCommand>,
        state: Arc<RwLock<SessionState>>,
    ) -> Result<Option<tokio::task::JoinHandle<()>>> {
        let path = store.socket_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bound = match UnixListener::bind(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                    bail!("another torrust session is already running ({})", path.display());
                }
                let _ = std::fs::remove_file(&path);
                UnixListener::bind(&path)
            }
            other => other,
        };
        // Without the socket `torrust add` still works by queueing, so a bind
        // failure (e.g. a data dir path longer than SUN_LEN) must not stop the
        // session.
        let listener = match bound {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "cannot open the add socket; `torrust add` will queue instead");
                return Ok(None);
            }
        };
        if let Err(e) = std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)) {
            tracing::warn!(path = %path.display(), error = %e, "cannot restrict the add socket");
        }
        Ok(Some(tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                };
                let tx = tx.clone();
                let state = Arc::clone(&state);
                tokio::spawn(serve(stream, tx, state));
            }
        })))
    }

    async fn serve(stream: UnixStream, tx: UnboundedSender<SessionCommand>, state: Arc<RwLock<SessionState>>) {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        let read = tokio::time::timeout(IO_TIMEOUT, (&mut reader).take(MAX_LINE).read_line(&mut line)).await;
        let line = line.trim_end_matches(['\r', '\n']);
        if matches!(read, Ok(Ok(n)) if n > 0) && line == "ATTACH" {
            attached(reader, tx, state).await;
            return;
        }
        let reply = match read {
            Ok(Ok(n)) if n > 0 => match parse(line) {
                Ok(cmd) => {
                    let _ = tx.send(cmd);
                    "OK\n".to_owned()
                }
                Err(msg) => format!("ERR {msg}\n"),
            },
            _ => "ERR empty request\n".to_owned(),
        };
        let _ = tokio::time::timeout(IO_TIMEOUT, reader.into_inner().write_all(reply.as_bytes())).await;
    }

    async fn attached(stream: BufReader<UnixStream>, tx: UnboundedSender<SessionCommand>, state: Arc<RwLock<SessionState>>) {
        let (reader, writer) = tokio::io::split(stream);
        tokio::select! {
            _ = push_snapshots(writer, state) => {}
            _ = forward_commands(reader, tx) => {}
        }
    }

    async fn push_snapshots(mut writer: WriteHalf<BufReader<UnixStream>>, state: Arc<RwLock<SessionState>>) {
        let mut every = tokio::time::interval(SNAPSHOT_EVERY);
        loop {
            every.tick().await;
            let (payload, shutdown) = {
                let snapshot = state.read().await;
                (postcard::to_stdvec(&*snapshot), snapshot.shutdown)
            };
            let sent = match payload {
                Ok(p) => write_frame(&mut writer, &p).await,
                Err(e) => {
                    tracing::warn!(error = %e, "cannot encode the session state; dropping the attached client");
                    return;
                }
            };
            if sent.is_err() || shutdown {
                let _ = writer.shutdown().await;
                return;
            }
        }
    }

    async fn forward_commands(mut reader: ReadHalf<BufReader<UnixStream>>, tx: UnboundedSender<SessionCommand>) {
        while let Ok(frame) = read_frame(&mut reader, MAX_COMMAND_FRAME).await {
            let Ok(cmd) = postcard::from_bytes::<SessionCommand>(&frame) else {
                return;
            };
            let _ = tx.send(cmd);
        }
    }

    fn parse(line: &str) -> std::result::Result<SessionCommand, String> {
        let mut parts = line.split('\t');
        match parts.next() {
            Some("ADD") => {}
            Some("STOP") => return Ok(SessionCommand::Quit),
            _ => return Err("unknown command".into()),
        }
        let source = parts.next().unwrap_or("").to_owned();
        if source.is_empty() {
            return Err("missing source".into());
        }
        if !super::is_link(&source) && !Path::new(&source).is_file() {
            return Err(format!("{source} is not a magnet: URI, an http(s) URL or a file"));
        }
        let dir = parts.next().filter(|d| !d.is_empty()).map(PathBuf::from);
        Ok(SessionCommand::Add { source, dir })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn tmp(tag: &str) -> PathBuf {
            let d = std::env::temp_dir().join(format!("ts-ipc-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            d
        }

        #[tokio::test]
        async fn socket_is_0600_stale_is_replaced_and_live_is_refused() {
            use std::os::unix::fs::PermissionsExt;
            let store = Store::at(tmp("sock"));
            std::fs::create_dir_all(store.root()).unwrap();
            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
            let state = Arc::default();

            drop(std::os::unix::net::UnixListener::bind(store.socket_path()).unwrap());
            assert!(!crate::ipc::session_running(&store));
            let h = listen(&store, tx.clone(), Arc::clone(&state)).unwrap().unwrap();
            let mode = std::fs::metadata(store.socket_path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            assert!(crate::ipc::session_running(&store));

            let err = listen(&store, tx, state).unwrap_err().to_string();
            assert!(err.contains("another torrust session is already running"), "{err}");
            h.abort();
        }

        async fn served(tag: &str) -> (Store, Arc<RwLock<SessionState>>, tokio::sync::mpsc::UnboundedReceiver<SessionCommand>, tokio::task::JoinHandle<()>) {
            let store = Store::at(tmp(tag));
            std::fs::create_dir_all(store.root()).unwrap();
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let state = Arc::new(RwLock::new(SessionState::default()));
            state.write().await.log(crate::state::Level::Info, "hello");
            let h = listen(&store, tx, Arc::clone(&state)).unwrap().unwrap();
            (store, state, rx, h)
        }

        #[tokio::test]
        async fn attach_mirrors_state_forwards_commands_and_closes_on_shutdown() {
            let (store, state, mut rx, h) = served("attach").await;
            let (mirror, _sender) = attach(&store).await.unwrap();
            assert_eq!(mirror.read().await.log[0].message, "hello");

            state.write().await.download_rate = f64::NAN;
            let cmd = SessionCommand::Remove { id: "ab".into(), delete_data: true };
            mirror.read().await.command_tx.as_ref().unwrap().send(cmd.clone()).unwrap();
            assert_eq!(tokio::time::timeout(IO_TIMEOUT, rx.recv()).await.unwrap(), Some(cmd));
            tokio::time::timeout(IO_TIMEOUT, async {
                while !mirror.read().await.download_rate.is_nan() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            assert!(mirror.read().await.command_tx.is_some());

            state.write().await.shutdown = true;
            tokio::time::timeout(IO_TIMEOUT, async {
                while !mirror.read().await.shutdown {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            h.abort();
        }

        #[tokio::test]
        async fn stop_sends_quit() {
            let (store, _state, mut rx, h) = served("stop").await;
            assert!(crate::ipc::stop(&store).await);
            assert_eq!(rx.recv().await, Some(SessionCommand::Quit));
            h.abort();
            assert!(!crate::ipc::stop(&Store::at(tmp("stop-none"))).await);
        }

        #[tokio::test]
        async fn oversized_and_garbage_frames_drop_the_client() {
            let (store, _state, mut rx, h) = served("garbage").await;
            for payload in [
                (u32::MAX).to_be_bytes().to_vec(),
                [&3u32.to_be_bytes()[..], &[0xff, 0xff, 0xff]].concat(),
            ] {
                let mut s = UnixStream::connect(store.socket_path()).await.unwrap();
                s.write_all(b"ATTACH\n").await.unwrap();
                s.write_all(&payload).await.unwrap();
                let mut sink = Vec::new();
                tokio::time::timeout(IO_TIMEOUT, s.read_to_end(&mut sink)).await.unwrap().unwrap();
                assert!(rx.try_recv().is_err());
            }
            assert!(crate::ipc::session_running(&store));
            assert!(attach(&store).await.is_ok());
            h.abort();
        }

        #[test]
        fn parses_add_lines() {
            assert_eq!(
                parse("ADD\tmagnet:?xt=urn:btih:ab\t/d"),
                Ok(SessionCommand::Add { source: "magnet:?xt=urn:btih:ab".into(), dir: Some("/d".into()) })
            );
            assert!(matches!(parse("ADD\tmagnet:?x\t"), Ok(SessionCommand::Add { dir: None, .. })));
            assert!(matches!(parse("ADD\thttps://example.com/a.torrent\t"), Ok(SessionCommand::Add { .. })));
            assert_eq!(crate::ipc::absolutize("https://example.com/a.torrent"), "https://example.com/a.torrent");
            assert!(parse("ADD\t\t").is_err());
            assert!(parse("NOPE").is_err());
            assert_eq!(parse("STOP"), Ok(SessionCommand::Quit));
            assert!(parse("ADD\t/definitely/not/here.torrent\t").is_err());
        }
    }
}
