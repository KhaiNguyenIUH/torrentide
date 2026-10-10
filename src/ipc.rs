//! Hand-off of `torrust add` to a running session over a Unix socket in the
//! data directory. One request per connection: `ADD\t<source>\t<dir>\n`
//! answered by `OK\n` or `ERR <message>\n`. Where there is no session, or on
//! platforms without Unix sockets, the add is queued in the store instead.

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

#[cfg(unix)]
pub use unix::listen;

#[cfg(not(unix))]
pub fn listen(
    _store: &Store,
    _tx: tokio::sync::mpsc::UnboundedSender<crate::state::SessionCommand>,
) -> Result<Option<tokio::task::JoinHandle<()>>> {
    Ok(None)
}

#[cfg(unix)]
mod unix {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use anyhow::{bail, Result};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::mpsc::UnboundedSender;

    use crate::state::SessionCommand;
    use crate::store::Store;

    const IO_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_LINE: u64 = 64 * 1024;

    /// `None` when no session is listening.
    pub async fn request(store: &Store, source: &str, dir: Option<&Path>) -> Option<String> {
        let path = store.socket_path();
        let attempt = async {
            let mut s = UnixStream::connect(&path).await.ok()?;
            let line = format!(
                "ADD\t{}\t{}\n",
                source.replace(['\t', '\n'], " "),
                dir.map(|d| d.to_string_lossy().replace(['\t', '\n'], " ")).unwrap_or_default()
            );
            s.write_all(line.as_bytes()).await.ok()?;
            let mut reply = String::new();
            BufReader::new(s.take(MAX_LINE)).read_line(&mut reply).await.ok()?;
            Some(reply.trim().to_owned())
        };
        tokio::time::timeout(IO_TIMEOUT, attempt).await.ok().flatten()
    }

    /// Start serving `ADD` requests, replacing a stale socket file but
    /// refusing to start if another session answers on it.
    pub fn listen(
        store: &Store,
        tx: UnboundedSender<SessionCommand>,
    ) -> Result<Option<tokio::task::JoinHandle<()>>> {
        let path = store.socket_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if path.exists() {
            if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                bail!("another torrust session is already running ({})", path.display());
            }
            let _ = std::fs::remove_file(&path);
        }
        // Without the socket `torrust add` still works by queueing, so a bind
        // failure (e.g. a data dir path longer than SUN_LEN) must not stop the
        // session.
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "cannot open the add socket; `torrust add` will queue instead");
                return Ok(None);
            }
        };
        Ok(Some(tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(IO_TIMEOUT, serve(stream, tx)).await;
                });
            }
        })))
    }

    async fn serve(stream: UnixStream, tx: UnboundedSender<SessionCommand>) {
        let mut line = String::new();
        let mut reader = BufReader::new(stream.take(MAX_LINE));
        let reply = match reader.read_line(&mut line).await {
            Ok(n) if n > 0 => match parse(line.trim_end_matches(['\r', '\n'])) {
                Ok(cmd) => {
                    let _ = tx.send(cmd);
                    "OK\n".to_owned()
                }
                Err(msg) => format!("ERR {msg}\n"),
            },
            _ => "ERR empty request\n".to_owned(),
        };
        let _ = reader.into_inner().into_inner().write_all(reply.as_bytes()).await;
    }

    fn parse(line: &str) -> std::result::Result<SessionCommand, String> {
        let mut parts = line.split('\t');
        if parts.next() != Some("ADD") {
            return Err("unknown command".into());
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
            assert!(parse("ADD\t/definitely/not/here.torrent\t").is_err());
        }
    }
}
