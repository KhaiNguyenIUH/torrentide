//! Adopting an in-progress download from another BitTorrent client.
//!
//! The scenario: a torrent is half-downloaded in qBittorrent/Transmission/etc.
//! and the user wants to finish it here instead of starting over. This module
//! figures out which of the torrent's files already exist in the other app's
//! directory (tolerating that app's naming quirks), transfers them into our
//! download layout, and verifies what will resume.
//!
//! What transfers and what does not:
//! - file bytes transfer; piece completion does not. Our startup recheck
//!   re-hashes everything, so only whole verified pieces resume. Partial
//!   pieces at the boundaries re-download.
//! - file *selection* does not transfer; re-skip files with `space` in the TUI.
//! - the other client must be stopped first. Two writers on the same files
//!   corrupt both downloads.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::metainfo::Metainfo;
use crate::storage::Storage;

/// qBittorrent's (default-on) suffix for incomplete files. Our parser looks
/// for exact torrent names, so these must be recognised and stripped.
pub const PARTIAL_SUFFIX: &str = ".!qB";

/// How to bring the other app's bytes into our download directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Duplicate the bytes. Slowest, safest; the source is untouched.
    #[default]
    Copy,
    /// Relocate the bytes. Fast; the source directory loses them.
    Move,
    /// Hard-link the bytes (same volume only). Instant and shares no writes
    /// as long as the other client stays stopped — either side writing
    /// copy-on-writes? No: hard links share the same inode, so a write from
    /// the other app *would* corrupt our view. Only use this with the other
    /// client stopped or removed.
    Link,
}

impl std::str::FromStr for Mode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "copy" => Ok(Mode::Copy),
            "move" => Ok(Mode::Move),
            "link" | "hardlink" => Ok(Mode::Link),
            _ => anyhow::bail!("unknown mode {s:?}: expected copy, move, or link"),
        }
    }
}

/// One torrent file located in the source directory.
#[derive(Debug, Clone)]
pub struct FoundFile {
    /// Position in the torrent's file list.
    pub index: usize,
    /// Torrent-relative path (what it will be called under our output dir).
    pub rel: PathBuf,
    /// Where it was found under `--from`.
    pub source: PathBuf,
    /// True when the source carries a partial-download suffix that is stripped
    /// on transfer.
    pub renamed: bool,
    /// Declared length from the torrent.
    pub length: u64,
    /// Bytes actually present in the source file.
    pub source_len: u64,
}

/// One torrent file with no match in the source directory.
#[derive(Debug, Clone)]
pub struct MissingFile {
    pub index: usize,
    pub rel: PathBuf,
    pub length: u64,
}

/// The result of scanning `--from` against the torrent: what was found, what
/// was not, and how each found file was recognised.
#[derive(Debug)]
pub struct Plan {
    pub found: Vec<FoundFile>,
    pub missing: Vec<MissingFile>,
}

impl Plan {
    pub fn found_bytes(&self) -> u64 {
        self.found.iter().map(|f| f.source_len.min(f.length)).sum()
    }

    pub fn missing_bytes(&self) -> u64 {
        self.missing.iter().map(|f| f.length).sum()
    }

    pub fn total_bytes(&self) -> u64 {
        self.found_bytes() + self.missing_bytes()
    }
}

/// Match the torrent's file list against a directory.
///
/// For each expected relative path `R`, in order:
/// 1. `from/R` — the file is already in our layout (or the app used it).
/// 2. `from/R.!qB` — qBittorrent-style incomplete file; stripped on transfer.
/// 3. `from/R` with the first component removed — the app saved with "no
///    subfolder" layout, plus its `.!qB` variant.
///
/// Anything else is reported missing with its size, so the user sees exactly
/// what will be fetched.
pub fn plan(meta: &Metainfo, from: &Path) -> Plan {
    let mut found = Vec::new();
    let mut missing = Vec::new();

    for (index, (rel, length)) in meta.files.iter().enumerate() {
        let rel = rel.to_path_buf();
        let mut hit: Option<(PathBuf, bool)> = None;

        // Zero-length files need no bytes; they always "match".
        if length == 0 {
            hit = Some((from.join(&rel), false));
        }
        if hit.is_none() {
            hit = straight_match(from, &rel);
        }
        if hit.is_none() {
            hit = no_subfolder_match(from, &rel);
        }

        match hit {
            Some((source, renamed)) => {
                let source_len = fs::metadata(&source).map(|m| m.len()).unwrap_or(0);
                // A zero-length declaration with no file on disk still counts:
                // there is nothing to transfer and nothing to verify.
                found.push(FoundFile {
                    index,
                    rel,
                    source,
                    renamed,
                    length,
                    source_len,
                });
            }
            None => missing.push(MissingFile {
                index,
                rel,
                length,
            }),
        }
    }

    Plan { found, missing }
}

/// `from/R` and `from/R.!qB`.
fn straight_match(from: &Path, rel: &Path) -> Option<(PathBuf, bool)> {
    let direct = from.join(rel);
    if is_file(&direct) {
        return Some((direct, false));
    }
    let suffixed = from.join(with_suffix(rel));
    if is_file(&suffixed) {
        return Some((suffixed, true));
    }
    None
}

/// `from/<R without first component>`, and its `.!qB` variant.
///
/// Some clients save multi-file torrents without the top-level folder, so
/// `bundle/a.bin` may live at `from/a.bin`.
fn no_subfolder_match(from: &Path, rel: &Path) -> Option<(PathBuf, bool)> {
    let mut parts = rel.components();
    parts.next(); // drop the torrent root folder
    let rest: PathBuf = parts.as_path().to_path_buf();
    if rest.as_os_str().is_empty() {
        return None;
    }
    let direct = from.join(&rest);
    if is_file(&direct) {
        return Some((direct, false));
    }
    let suffixed = from.join(with_suffix(&rest));
    if is_file(&suffixed) {
        return Some((suffixed, true));
    }
    None
}

fn with_suffix(rel: &Path) -> PathBuf {
    let mut s = rel.as_os_str().to_owned();
    s.push(PARTIAL_SUFFIX);
    PathBuf::from(s)
}

fn is_file(p: &Path) -> bool {
    fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

/// What a transfer did, for the final report.
#[derive(Debug, Default)]
pub struct TransferReport {
    pub copied: usize,
    pub moved: usize,
    pub linked: usize,
    pub renamed: usize,
    /// Files already where they belong; touched only to strip a suffix.
    pub in_place: usize,
    pub bytes: u64,
}

/// Bring every found file into `<output>/<torrent-relative-path>`.
///
/// A file already at its destination is left alone (except a pending suffix
/// strip). `Move` falls back to copy+remove across volumes, where a rename
/// cannot work.
pub fn execute(plan: &Plan, output: &Path, mode: Mode) -> Result<TransferReport> {
    let mut report = TransferReport::default();

    for f in &plan.found {
        let dest = output.join(&f.rel);
        // Zero-length files carry no bytes: just ensure the path exists.
        // (The source may not exist at all, and there is nothing to copy.)
        if f.length == 0 {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            if !dest.exists() {
                fs::write(&dest, &[])
                    .with_context(|| format!("creating {}", dest.display()))?;
            }
            report.in_place += 1;
            continue;
        }
        if same_file(&without_suffix(&f.source), &dest) {
            // Already home, possibly under the other client's partial suffix,
            // which a rename strips.
            if f.renamed {
                fs::rename(&f.source, &dest).with_context(|| {
                    format!("stripping suffix on {}", f.source.display())
                })?;
                report.renamed += 1;
            } else {
                report.in_place += 1;
            }
            report.bytes += f.source_len.min(f.length);
            continue;
        }

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        // A stale destination (e.g. from an aborted earlier import) must not
        // be appended to or merged; remove it first.
        if dest.exists() {
            fs::remove_file(&dest)
                .with_context(|| format!("removing stale {}", dest.display()))?;
        }

        match mode {
            Mode::Copy => {
                fs::copy(&f.source, &dest).with_context(|| {
                    format!("copying {} to {}", f.source.display(), dest.display())
                })?;
                report.copied += 1;
            }
            Mode::Move => {
                if fs::rename(&f.source, &dest).is_err() {
                    // Cross-volume: rename cannot work, so copy and remove.
                    fs::copy(&f.source, &dest).with_context(|| {
                        format!("copying {} to {}", f.source.display(), dest.display())
                    })?;
                    fs::remove_file(&f.source).with_context(|| {
                        format!("removing {}", f.source.display())
                    })?;
                }
                report.moved += 1;
            }
            Mode::Link => {
                fs::hard_link(&f.source, &dest).with_context(|| {
                    format!(
                        "linking {} to {} (same volume only)",
                        f.source.display(),
                        dest.display()
                    )
                })?;
                report.linked += 1;
            }
        }
        if f.renamed {
            report.renamed += 1;
        }
        report.bytes += f.source_len.min(f.length);
    }

    Ok(report)
}

/// `path` with a trailing [`PARTIAL_SUFFIX`] removed from its file name.
fn without_suffix(path: &Path) -> PathBuf {
    match path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(PARTIAL_SUFFIX))
    {
        Some(stem) => path.with_file_name(stem),
        None => path.to_path_buf(),
    }
}

/// Are these two paths the same file? Compares canonicalised absolute paths;
/// a path that does not exist yet resolves through its parent. Anything
/// unresolvable counts as different (safer direction).
fn same_file(a: &Path, b: &Path) -> bool {
    fn resolve(p: &Path) -> Option<PathBuf> {
        fs::canonicalize(p)
            .ok()
            .or_else(|| Some(fs::canonicalize(p.parent()?).ok()?.join(p.file_name()?)))
    }
    matches!((resolve(a), resolve(b)), (Some(x), Some(y)) if x == y)
}

/// What the post-transfer verification found.
#[derive(Debug)]
pub struct VerifyReport {
    pub pieces_verified: usize,
    pub pieces_total: usize,
    /// Verified bytes. This is the honest "will resume" number: only whole
    /// pieces whose SHA-1 matches count.
    pub bytes_verified: u64,
}

/// Prepare the output dir and hash every piece, reusing the engine's own
/// verification so the number means the same thing it will mean at startup.
///
/// This also repairs sizes: short files are extended with zeros (their bytes
/// fail verification and re-download) and over-long files are truncated.
pub fn verify(meta: &Metainfo, output: &Path) -> Result<VerifyReport> {
    let store = Storage::prepare(meta, output).context("preparing output directory")?;

    let mut pieces_verified = 0usize;
    let mut bytes_verified = 0u64;
    for i in 0..meta.piece_count() {
        if store
            .verify_piece(meta, i as u32)
            .with_context(|| format!("verifying piece {i}"))?
        {
            pieces_verified += 1;
            bytes_verified += meta.piece_size(i);
        }
    }

    Ok(VerifyReport {
        pieces_verified,
        pieces_total: meta.piece_count(),
        bytes_verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metainfo::{FileEntry, Files, InfoHash};
    use crate::storage::sha1_bytes;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "torrust-import-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Two-file torrent over real bytes, with genuine piece hashes.
    fn meta_two_files(piece_len: u32, a: &[u8], b: &[u8]) -> (Metainfo, Vec<u8>) {
        let mut flat = Vec::new();
        flat.extend_from_slice(a);
        flat.extend_from_slice(b);
        let piece_count = flat.len().div_ceil(piece_len as usize);
        let mut pieces = Vec::new();
        for i in 0..piece_count {
            let s = i * piece_len as usize;
            let e = (s + piece_len as usize).min(flat.len());
            pieces.push(sha1_bytes(&flat[s..e]));
        }
        let total = flat.len() as u64;
        let meta = Metainfo {
            infohash: InfoHash([1u8; 20]),
            name: "bundle".into(),
            piece_length: piece_len,
            pieces,
            files: Files::Multi {
                files: vec![
                    FileEntry {
                        path: PathBuf::from("bundle").join("a.bin"),
                        length: a.len() as u64,
                    },
                    FileEntry {
                        path: PathBuf::from("bundle").join("b.bin"),
                        length: b.len() as u64,
                    },
                ],
            },
            total_length: total,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
            info_bytes: vec![],
        };
        (meta, flat)
    }

    fn payload(n: usize, seed: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut x = seed;
        for _ in 0..n {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.push((x >> 24) as u8);
        }
        out
    }

    #[test]
    fn plan_finds_exact_layout() {
        let dir = TempDir::new("exact");
        let a = payload(100, 1);
        let b = payload(100, 2);
        let (meta, _) = meta_two_files(64, &a, &b);

        fs::create_dir_all(dir.path().join("bundle")).unwrap();
        fs::write(dir.path().join("bundle").join("a.bin"), &a).unwrap();
        fs::write(dir.path().join("bundle").join("b.bin"), &b).unwrap();

        let plan = plan(&meta, dir.path());
        assert!(plan.missing.is_empty());
        assert_eq!(plan.found.len(), 2);
        assert!(plan.found.iter().all(|f| !f.renamed));
        assert_eq!(plan.found_bytes(), 200);
    }

    #[test]
    fn plan_strips_partial_suffix() {
        let dir = TempDir::new("suffix");
        let a = payload(100, 1);
        let b = payload(100, 2);
        let (meta, _) = meta_two_files(64, &a, &b);

        fs::create_dir_all(dir.path().join("bundle")).unwrap();
        fs::write(dir.path().join("bundle").join("a.bin"), &a).unwrap();
        fs::write(
            dir.path().join("bundle").join("b.bin.!qB"),
            &b[..50],
        )
        .unwrap();

        let plan = plan(&meta, dir.path());
        assert!(plan.missing.is_empty());
        let b_found = plan.found.iter().find(|f| f.index == 1).unwrap();
        assert!(b_found.renamed);
        assert_eq!(b_found.source_len, 50);
        // Only present bytes count toward the total.
        assert_eq!(plan.found_bytes(), 150);
    }

    #[test]
    fn plan_matches_no_subfolder_layout() {
        let dir = TempDir::new("nosub");
        let a = payload(100, 1);
        let b = payload(100, 2);
        let (meta, _) = meta_two_files(64, &a, &b);

        // Files directly under `from/`, without the `bundle/` folder.
        fs::write(dir.path().join("a.bin"), &a).unwrap();
        fs::write(dir.path().join("b.bin.!qB"), &b).unwrap();

        let plan = plan(&meta, dir.path());
        assert!(plan.missing.is_empty(), "both files should match");
        assert!(plan.found.iter().any(|f| f.renamed));
    }

    #[test]
    fn plan_reports_missing_files_with_sizes() {
        let dir = TempDir::new("missing");
        let a = payload(100, 1);
        let b = payload(100, 2);
        let (meta, _) = meta_two_files(64, &a, &b);

        fs::create_dir_all(dir.path().join("bundle")).unwrap();
        fs::write(dir.path().join("bundle").join("a.bin"), &a).unwrap();

        let plan = plan(&meta, dir.path());
        assert_eq!(plan.missing.len(), 1);
        assert_eq!(plan.missing[0].length, 100);
        assert_eq!(plan.missing_bytes(), 100);
    }

    #[test]
    fn execute_copies_and_strips_suffix() {
        let from = TempDir::new("exec-from");
        let out = TempDir::new("exec-out");
        let a = payload(100, 1);
        let b = payload(100, 2);
        let (meta, _) = meta_two_files(64, &a, &b);

        fs::create_dir_all(from.path().join("bundle")).unwrap();
        fs::write(from.path().join("bundle").join("a.bin"), &a).unwrap();
        fs::write(from.path().join("bundle").join("b.bin.!qB"), &b).unwrap();

        let plan = plan(&meta, from.path());
        let rep = execute(&plan, out.path(), Mode::Copy).unwrap();
        assert_eq!(rep.copied, 2);
        assert_eq!(rep.renamed, 1);

        // Destination has clean names with identical bytes...
        assert_eq!(fs::read(out.path().join("bundle").join("b.bin")).unwrap(), b);
        // ...and the source is untouched in copy mode.
        assert!(from.path().join("bundle").join("b.bin.!qB").exists());
    }

    #[test]
    fn execute_moves_and_links() {
        let from = TempDir::new("mode-from");
        let out = TempDir::new("mode-out");
        let a = payload(100, 1);
        let b = payload(100, 2);
        let (meta, _) = meta_two_files(64, &a, &b);

        fs::create_dir_all(from.path().join("bundle")).unwrap();
        fs::write(from.path().join("bundle").join("a.bin"), &a).unwrap();
        fs::write(from.path().join("bundle").join("b.bin"), &b).unwrap();

        let plan = plan(&meta, from.path());
        let rep = execute(&plan, out.path(), Mode::Move).unwrap();
        assert_eq!(rep.moved, 2);
        assert!(!from.path().join("bundle").join("a.bin").exists());
        assert_eq!(fs::read(out.path().join("bundle").join("a.bin")).unwrap(), a);

        let from2 = TempDir::new("mode-from2");
        let out2 = TempDir::new("mode-out2");
        fs::create_dir_all(from2.path().join("bundle")).unwrap();
        fs::write(from2.path().join("bundle").join("a.bin"), &a).unwrap();
        fs::write(from2.path().join("bundle").join("b.bin"), &b).unwrap();
        let plan2 = super::plan(&meta, from2.path());
        let rep2 = execute(&plan2, out2.path(), Mode::Link).unwrap();
        assert_eq!(rep2.linked, 2);
        assert_eq!(fs::read(out2.path().join("bundle").join("b.bin")).unwrap(), b);
    }

    #[test]
    fn execute_skips_files_already_home() {
        let dir = TempDir::new("inplace");
        let a = payload(100, 1);
        let b = payload(100, 2);
        let (meta, _) = meta_two_files(64, &a, &b);

        fs::create_dir_all(dir.path().join("bundle")).unwrap();
        fs::write(dir.path().join("bundle").join("a.bin"), &a).unwrap();
        fs::write(dir.path().join("bundle").join("b.bin"), &b).unwrap();

        // from == output: everything is already home.
        let plan = plan(&meta, dir.path());
        let rep = execute(&plan, dir.path(), Mode::Copy).unwrap();
        assert_eq!(rep.in_place, 2);
        assert_eq!(rep.copied, 0);
    }

    #[test]
    fn execute_strips_suffix_in_place() {
        let dir = TempDir::new("inplace-strip");
        let a = payload(100, 1);
        let (meta, _) = meta_two_files(64, &a, &[]);
        let _ = &a;

        fs::create_dir_all(dir.path().join("bundle")).unwrap();
        fs::write(dir.path().join("bundle").join("a.bin.!qB"), &a).unwrap();

        let plan = plan(&meta, dir.path());
        let rep = execute(&plan, dir.path(), Mode::Copy).unwrap();
        assert_eq!(rep.renamed, 1);
        assert!(dir.path().join("bundle").join("a.bin").exists());
        assert!(!dir.path().join("bundle").join("a.bin.!qB").exists());
    }

    #[test]
    fn verify_counts_only_intact_pieces() {
        let out = TempDir::new("verify");
        let a = payload(128, 1);
        let b = payload(128, 2);
        let (meta, _) = meta_two_files(64, &a, &b); // 4 pieces

        // Seed only the first file intact; corrupt one byte of the second.
        let from = TempDir::new("verify-from");
        fs::create_dir_all(from.path().join("bundle")).unwrap();
        fs::write(from.path().join("bundle").join("a.bin"), &a).unwrap();
        let mut bad = b.clone();
        bad[10] ^= 0xff;
        fs::write(from.path().join("bundle").join("b.bin"), &bad).unwrap();

        let plan = plan(&meta, from.path());
        execute(&plan, out.path(), Mode::Copy).unwrap();
        let rep = verify(&meta, out.path()).unwrap();
        assert_eq!(rep.pieces_total, 4);
        // Pieces 0-1 are file a; piece 2 holds the corrupt byte; piece 3 is intact.
        assert_eq!(rep.pieces_verified, 3, "only the corrupt piece fails");
        assert_eq!(rep.bytes_verified, 192);
    }

    #[test]
    fn mode_rejects_unknown_words() {
        use std::str::FromStr;
        assert_eq!(Mode::from_str("copy").unwrap(), Mode::Copy);
        assert_eq!(Mode::from_str("MOVE").unwrap(), Mode::Move);
        assert_eq!(Mode::from_str("hardlink").unwrap(), Mode::Link);
        assert!(Mode::from_str("symlink").is_err());
    }
}