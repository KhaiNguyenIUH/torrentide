//! Building v1 `.torrent` files from a file or directory.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use sha1::{Digest, Sha1};

use crate::bencode::{encode, Value};
use crate::metainfo::InfoHash;

pub const MIN_PIECE_LEN: u32 = 16 * 1024;
pub const MAX_PIECE_LEN: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    pub path: PathBuf,
    pub trackers: Vec<String>,
    pub web_seeds: Vec<String>,
    pub private: bool,
    pub piece_len: Option<u32>,
    pub comment: Option<String>,
    pub source: Option<String>,
    pub no_date: bool,
    pub progress: bool,
}

#[derive(Debug, Clone)]
pub struct CreatedTorrent {
    pub bytes: Vec<u8>,
    pub infohash: InfoHash,
    pub name: String,
    pub total: u64,
    pub piece_len: u32,
    pub pieces: usize,
    pub magnet: String,
}

struct Entry {
    abs: PathBuf,
    rel: Vec<String>,
    len: u64,
    start: u64,
}

pub fn torrent_name(path: &Path) -> Result<String> {
    let abs = std::fs::canonicalize(path).with_context(|| format!("reading {}", path.display()))?;
    match abs.file_name() {
        Some(n) => Ok(n.to_string_lossy().into_owned()),
        None => bail!("cannot derive a torrent name from {}", path.display()),
    }
}

pub fn auto_piece_len(total: u64) -> u32 {
    let wanted = total.div_ceil(2000).clamp(MIN_PIECE_LEN as u64, MAX_PIECE_LEN as u64);
    wanted.next_power_of_two() as u32
}

fn collect(dir: &Path, rel: &mut Vec<String>, out: &mut Vec<Entry>) -> Result<()> {
    for item in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let item = item?;
        let name = item.file_name().to_string_lossy().into_owned();
        let kind = item.file_type()?;
        rel.push(name);
        if kind.is_symlink() {
            eprintln!("warning: skipping symlink {}", item.path().display());
        } else if kind.is_dir() {
            collect(&item.path(), rel, out)?;
        } else if kind.is_file() {
            out.push(Entry { abs: item.path(), rel: rel.clone(), len: item.metadata()?.len(), start: 0 });
        }
        rel.pop();
    }
    Ok(())
}

fn hash_pieces(entries: &[Entry], total: u64, piece_len: u32, progress: bool) -> Result<Vec<u8>> {
    let piece_len = piece_len as u64;
    let count = total.div_ceil(piece_len) as usize;
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get()).min(count).max(1);
    let per = count.div_ceil(workers);
    let done = AtomicU64::new(0);

    let hash_range = |first: usize, last: usize| -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity((last - first) * 20);
        let mut buf = vec![0u8; piece_len as usize];
        for piece in first..last {
            let offset = piece as u64 * piece_len;
            let want = piece_len.min(total - offset) as usize;
            let mut filled = 0usize;
            let mut idx = entries.partition_point(|e| e.start + e.len <= offset);
            while filled < want {
                let e = &entries[idx];
                let pos = offset + filled as u64 - e.start;
                let n = ((e.len - pos) as usize).min(want - filled);
                if n > 0 {
                    let mut f = File::open(&e.abs).with_context(|| format!("opening {}", e.abs.display()))?;
                    f.seek(SeekFrom::Start(pos))?;
                    f.read_exact(&mut buf[filled..filled + n])
                        .with_context(|| format!("reading {} (did it change while hashing?)", e.abs.display()))?;
                    filled += n;
                }
                idx += 1;
            }
            out.extend_from_slice(&Sha1::digest(&buf[..want]));
            done.fetch_add(want as u64, Ordering::Relaxed);
        }
        Ok(out)
    };

    std::thread::scope(|s| {
        let handles: Vec<_> = (0..workers)
            .map(|w| {
                let (first, last) = ((w * per).min(count), ((w + 1) * per).min(count));
                let hash_range = &hash_range;
                s.spawn(move || hash_range(first, last))
            })
            .collect();
        while progress && !handles.iter().all(|h| h.is_finished()) {
            eprint!("\rhashing {:3}%", done.load(Ordering::Relaxed) * 100 / total);
            std::thread::sleep(Duration::from_millis(100));
        }
        if progress {
            eprintln!("\rhashing 100%");
        }
        let mut pieces = Vec::with_capacity(count * 20);
        for h in handles {
            pieces.extend(h.join().map_err(|_| anyhow::anyhow!("hash worker panicked"))??);
        }
        Ok(pieces)
    })
}

fn key(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn text(s: &str) -> Value {
    Value::Bytes(key(s))
}

pub fn build(opts: &CreateOptions) -> Result<CreatedTorrent> {
    if let Some(p) = opts.piece_len {
        if !p.is_power_of_two() || !(MIN_PIECE_LEN..=MAX_PIECE_LEN).contains(&p) {
            bail!("piece size must be a power of two between 16 KiB and 16 MiB");
        }
    }
    let name = torrent_name(&opts.path)?;
    let meta = std::fs::symlink_metadata(&opts.path)?;
    if meta.file_type().is_symlink() {
        bail!("{} is a symlink; pass the path it points to instead", opts.path.display());
    }
    let single = !meta.is_dir();
    let mut entries = Vec::new();
    if single {
        entries.push(Entry { abs: opts.path.clone(), rel: vec![name.clone()], len: meta.len(), start: 0 });
    } else {
        collect(&opts.path, &mut Vec::new(), &mut entries)?;
        entries.sort_by(|a, b| a.rel.iter().map(|c| c.as_bytes()).cmp(b.rel.iter().map(|c| c.as_bytes())));
    }
    let mut total = 0u64;
    for e in &mut entries {
        e.start = total;
        total += e.len;
    }
    if total == 0 {
        bail!("{} has no data to hash (empty input)", opts.path.display());
    }

    let piece_len = opts.piece_len.unwrap_or_else(|| auto_piece_len(total));
    let pieces = hash_pieces(&entries, total, piece_len, opts.progress)?;
    let count = pieces.len() / 20;

    let mut info = BTreeMap::from([
        (key("name"), text(&name)),
        (key("piece length"), Value::Int(piece_len as i64)),
        (key("pieces"), Value::Bytes(pieces)),
    ]);
    if single {
        info.insert(key("length"), Value::Int(total as i64));
    } else {
        let files = entries
            .iter()
            .map(|e| {
                Value::Dict(BTreeMap::from([
                    (key("length"), Value::Int(e.len as i64)),
                    (key("path"), Value::List(e.rel.iter().map(|c| text(c)).collect())),
                ]))
            })
            .collect();
        info.insert(key("files"), Value::List(files));
    }
    if opts.private {
        info.insert(key("private"), Value::Int(1));
    }
    if let Some(s) = &opts.source {
        info.insert(key("source"), text(s));
    }
    let info = Value::Dict(info);
    let infohash = InfoHash(Sha1::digest(encode(&info)).into());

    let mut root = BTreeMap::from([(key("info"), info), (key("created by"), text(concat!("torrust ", env!("CARGO_PKG_VERSION"))))]);
    if let Some(first) = opts.trackers.first() {
        root.insert(key("announce"), text(first));
        let tiers = opts.trackers.iter().map(|t| Value::List(vec![text(t)])).collect();
        root.insert(key("announce-list"), Value::List(tiers));
    }
    if !opts.web_seeds.is_empty() {
        root.insert(key("url-list"), Value::List(opts.web_seeds.iter().map(|u| text(u)).collect()));
    }
    if let Some(c) = &opts.comment {
        root.insert(key("comment"), text(c));
    }
    if !opts.no_date {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        root.insert(key("creation date"), Value::Int(now as i64));
    }

    let enc = |s: &str| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
    let mut magnet = format!("magnet:?xt=urn:btih:{}&dn={}", infohash.to_hex(), enc(&name));
    for t in &opts.trackers {
        magnet.push_str(&format!("&tr={}", enc(t)));
    }
    for w in &opts.web_seeds {
        magnet.push_str(&format!("&ws={}", enc(w)));
    }

    Ok(CreatedTorrent {
        bytes: encode(&Value::Dict(root)),
        infohash,
        name,
        total,
        piece_len,
        pieces: count,
        magnet,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn symlink_input_is_refused() {
        let dir = std::env::temp_dir().join(format!("torrust-create-link-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.bin");
        std::fs::write(&target, vec![7u8; 40_000]).unwrap();
        let link = dir.join("link.bin");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let opts = |path| CreateOptions {
            path,
            trackers: vec![],
            web_seeds: vec![],
            private: false,
            piece_len: None,
            comment: None,
            source: None,
            no_date: true,
            progress: false,
        };
        let err = build(&opts(link)).unwrap_err().to_string();
        assert!(err.contains("is a symlink"), "{err}");
        assert!(build(&opts(target)).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
