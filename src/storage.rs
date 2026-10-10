//! Track file layout and piece hashing.
//!
//! A torrent's payload is a flat byte stream. Files are carved out of that
//! stream in order, so piece `i` may span several files, or part of one file.
//! This module owns the mapping between (piece index, offset) and file
//! positions, plus verification of downloaded data against the piece hashes.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha1::{Digest, Sha1};

use crate::metainfo::{is_safe_relative, Metainfo};

/// A half-open byte range `[start, end)` in the torrent's flat payload stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRange {
    pub start: u64,
    pub end: u64,
}

impl BlockRange {
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Maps flat torrent offsets onto concrete files on disk.
pub struct Storage {
    files: Vec<StoredFile>,
    total_length: u64,
    root: PathBuf,
}

struct StoredFile {
    path: PathBuf,
    /// Offset of this file's first byte within the flat stream.
    start: u64,
    length: u64,
}

impl Storage {
    /// Prepare the download directory, creating any missing files at full size.
    ///
    /// Files are allocated sparse where the platform allows it, so a fresh
    /// torrent does not immediately consume its full size on disk. A file that
    /// already exists at a torrent path is only adopted when it has exactly the
    /// torrent's length (the recheck then decides what is valid); any other
    /// non-empty file is somebody else's data and is never resized.
    pub fn prepare(meta: &Metainfo, root: &Path) -> Result<Self> {
        Self::prepare_with(meta, root, false)
    }

    /// Like [`Storage::prepare`], but resizes wrong-sized existing files: for
    /// imported data the user pointed us at, where short files are padded and
    /// over-long ones truncated.
    pub fn prepare_repairing(meta: &Metainfo, root: &Path) -> Result<Self> {
        Self::prepare_with(meta, root, true)
    }

    fn prepare_with(meta: &Metainfo, root: &Path, repair: bool) -> Result<Self> {
        for (path, _) in meta.files.iter() {
            if !is_safe_relative(path) || !root.join(path).starts_with(root) {
                bail!("torrent path escapes the download directory: {}", path.display());
            }
            check_no_symlinks(root, path)?;
        }

        fs::create_dir_all(root)
            .with_context(|| format!("creating download directory {}", root.display()))?;

        let mut files = Vec::new();
        let mut offset = 0u64;
        for (path, length) in meta.files.iter() {
            let disk_path = root.join(path);
            if let Some(parent) = disk_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating directory {}", parent.display()))?;
            }

            match fs::symlink_metadata(&disk_path) {
                Ok(md) if md.is_file() && md.len() == length => {}
                Ok(md) if md.is_file() && (repair || md.len() == 0) => {
                    let f = OpenOptions::new()
                        .write(true)
                        .open(&disk_path)
                        .with_context(|| format!("resizing {}", disk_path.display()))?;
                    f.set_len(length)
                        .with_context(|| format!("setting length on {}", disk_path.display()))?;
                }
                Ok(md) if md.is_file() => bail!(
                    "a different file already exists at {}; move it away or choose another folder",
                    disk_path.display()
                ),
                Ok(_) => bail!("{} exists and is not a regular file", disk_path.display()),
                Err(_) => {
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&disk_path)
                        .with_context(|| format!("creating {}", disk_path.display()))?
                        .set_len(length)
                        .with_context(|| format!("setting length on {}", disk_path.display()))?;
                }
            }

            files.push(StoredFile {
                path: disk_path,
                start: offset,
                length,
            });
            offset = offset.checked_add(length).context("torrent length overflows")?;
        }

        Ok(Storage {
            files,
            total_length: offset,
            root: root.to_path_buf(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn total_length(&self) -> u64 {
        self.total_length
    }

    /// Which file contains the given absolute stream offset.
    fn file_at(&self, offset: u64) -> Option<&StoredFile> {
        self.files
            .iter()
            .find(|f| offset >= f.start && offset < f.start + f.length)
            .or_else(|| {
                // A zero-length final file is a legal edge case; fall back to the
                // last file that starts at or before `offset`.
                self.files.iter().rev().find(|f| f.start <= offset)
            })
    }

    /// Read `len` bytes starting at absolute stream `offset`.
    pub fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>> {
        if offset + len > self.total_length {
            bail!("read past end of torrent data ({offset}+{len} > {})", self.total_length);
        }
        let mut out = Vec::with_capacity(len as usize);
        let mut remaining = len;
        let mut cursor = offset;

        while remaining > 0 {
            let file = self
                .file_at(cursor)
                .context("no file covers the requested offset")?;
            let within = cursor - file.start;
            let chunk = remaining.min(file.length - within);
            if chunk == 0 {
                break;
            }

            let mut f = File::open(&file.path)
                .with_context(|| format!("opening {}", file.path.display()))?;
            f.seek(SeekFrom::Start(within))?;
            let start = out.len();
            out.resize(start + chunk as usize, 0);
            f.read_exact(&mut out[start..])
                .with_context(|| format!("reading {}", file.path.display()))?;

            cursor += chunk;
            remaining -= chunk;
        }
        Ok(out)
    }

    /// Write `data` at absolute stream `offset`, spanning files as needed.
    ///
    /// Takes `&self` rather than `&mut self`: files are opened per call and no
    /// cached state changes. That lets the same `Storage` be shared with the
    /// seeding path through an `Arc` while the engine is still writing to it.
    pub fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        if offset + data.len() as u64 > self.total_length {
            bail!("write past end of torrent data");
        }
        let mut written = 0usize;
        let mut cursor = offset;

        while written < data.len() {
            let idx = self
                .files
                .iter()
                .position(|f| cursor >= f.start && cursor < f.start + f.length)
                .with_context(|| format!("no file covers write offset {cursor}"))?;
            let file = &self.files[idx];
            let within = cursor - file.start;
            let chunk = ((file.length - within) as usize).min(data.len() - written);

            let mut f = OpenOptions::new()
                .write(true)
                .open(&file.path)
                .with_context(|| format!("opening {} for write", file.path.display()))?;
            f.seek(SeekFrom::Start(within))?;
            f.write_all(&data[written..written + chunk])?;
            f.flush()?;

            written += chunk;
            cursor += chunk as u64;
        }
        Ok(())
    }

    /// Read a whole piece.
    pub fn read_piece(&self, meta: &Metainfo, index: u32) -> Result<Vec<u8>> {
        let offset = index as u64 * meta.piece_length as u64;
        self.read_at(offset, meta.piece_size(index as usize))
    }

    /// Hash a piece's bytes and compare against the torrent's expected hash.
    pub fn verify_piece(&self, meta: &Metainfo, index: u32) -> Result<bool> {
        let data = self.read_piece(meta, index)?;
        let digest = sha1_bytes(&data);
        let i = index as usize;
        match meta.pieces.get(i) {
            Some(expected) => Ok(digest == *expected),
            None => bail!("piece {index} is out of range for this torrent"),
        }
    }
}

/// Fail if any component of `rel` that already exists under `root` is a
/// symlink. `root` itself may be one.
pub fn check_no_symlinks(root: &Path, rel: &Path) -> Result<()> {
    let mut cur = root.to_path_buf();
    for c in rel.components() {
        cur.push(c);
        match fs::symlink_metadata(&cur) {
            Ok(md) if md.file_type().is_symlink() => {
                bail!("{} is a symlink; refusing to follow it", cur.display())
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("checking {}", cur.display())),
        }
    }
    Ok(())
}

/// SHA-1 of a byte slice, the hash function BitTorrent is built on.
pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metainfo::{Files, InfoHash};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "torrust-test-{tag}-{}",
                std::process::id()
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

    fn meta_multifile(piece_len: u32, files: Vec<(&str, u64)>) -> Metainfo {
        let total: u64 = files.iter().map(|f| f.1).sum();
        let piece_count = total.div_ceil(piece_len as u64) as usize;
        let mut pieces = Vec::new();
        for _ in 0..piece_count {
            pieces.push([0u8; 20]);
        }
        Metainfo {
            infohash: InfoHash([0u8; 20]),
            name: "root".into(),
            piece_length: piece_len,
            pieces,
            files: Files::Multi {
                files: files
                    .iter()
                    .map(|(n, l)| crate::metainfo::FileEntry {
                        path: PathBuf::from("root").join(n),
                        length: *l,
                    })
                    .collect(),
            },
            total_length: total,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
            info_bytes: vec![],
        }
    }

    /// Write a known payload across two files so piece boundaries land
    /// mid-file, which is the case most likely to be implemented wrong.
    fn seed(meta: &Metainfo, store: &mut Storage, payload: &[u8]) {
        let mut consumed = 0u64;
        for (path, len) in meta.files.iter() {
            let len = len as usize;
            let chunk = &payload[consumed as usize..consumed as usize + len];
            let mut f = File::create(store.root().join(path)).unwrap();
            f.write_all(chunk).unwrap();
            consumed += len as u64;
        }
    }

    #[test]
    fn read_at_spans_file_boundaries() {
        let dir = TempDir::new("span");
        let meta = meta_multifile(16, vec![("a.bin", 10), ("b.bin", 20)]);
        let mut store = Storage::prepare(&meta, dir.path()).unwrap();
        let payload: Vec<u8> = (0..30u8).collect();
        seed(&meta, &mut store, &payload);

        // A read straddling the 10-byte boundary.
        let got = store.read_at(8, 5).unwrap();
        assert_eq!(got, vec![8, 9, 10, 11, 12]);
    }

    #[test]
    fn write_at_spans_file_boundaries() {
        let dir = TempDir::new("wspan");
        let meta = meta_multifile(16, vec![("a.bin", 10), ("b.bin", 20)]);
        let mut store = Storage::prepare(&meta, dir.path()).unwrap();

        let payload: Vec<u8> = (0..30u8).collect();
        seed(&meta, &mut store, &payload);

        // Overwrite bytes 8..13, which crosses into the second file.
        store.write_at(8, &[100, 101, 102, 103, 104]).unwrap();

        let got = store.read_at(0, 30).unwrap();
        let mut expect = payload.clone();
        expect[8..13].copy_from_slice(&[100, 101, 102, 103, 104]);
        assert_eq!(got, expect);
    }

    #[test]
    fn piece_verification_detects_corruption() {
        let dir = TempDir::new("verify");
        let meta = meta_multifile(16, vec![("a.bin", 10), ("b.bin", 20)]);
        let mut store = Storage::prepare(&meta, dir.path()).unwrap();
        let payload: Vec<u8> = (0..30u8).collect();
        seed(&meta, &mut store, &payload);

        // Record the true hash for piece 0, which spans both files.
        let piece0 = store.read_piece(&meta, 0).unwrap();
        let mut m2 = meta_multifile(16, vec![("a.bin", 10), ("b.bin", 20)]);
        m2.pieces[0] = sha1_bytes(&piece0);
        assert!(store.verify_piece(&m2, 0).unwrap());

        // Flip a byte in the second file, inside piece 0's range.
        store.write_at(11, &[0xff]).unwrap();
        assert!(!store.verify_piece(&m2, 0).unwrap());
    }

    #[test]
    fn last_piece_is_short() {
        let dir = TempDir::new("short");
        let meta = meta_multifile(16, vec![("a.bin", 20)]);
        let store = Storage::prepare(&meta, dir.path()).unwrap();
        assert_eq!(meta.piece_count(), 2);
        assert_eq!(meta.piece_size(0), 16);
        assert_eq!(meta.piece_size(1), 4);
        assert_eq!(meta.last_piece_length(), 4);
        assert_eq!(store.total_length(), 20);
    }

    #[test]
    fn prepare_preserves_existing_correct_size_file() {
        let dir = TempDir::new("preserve");
        let meta = meta_multifile(16, vec![("a.bin", 10)]);
        let target = dir.path().join("root").join("a.bin");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        {
            let mut f = File::create(&target).unwrap();
            f.write_all(b"keepme").unwrap();
            f.set_len(10).unwrap();
        }

        Storage::prepare(&meta, dir.path()).unwrap();
        // prepare must not have truncated or rewritten the existing bytes.
        let after = fs::read(&target).unwrap();
        assert_eq!(after.len(), 10, "size should be untouched");
        assert!(
            after.starts_with(b"keepme"),
            "content must be preserved, got {after:?}"
        );
    }

    #[test]
    fn rejects_read_past_end() {
        let dir = TempDir::new("past");
        let meta = meta_multifile(16, vec![("a.bin", 10)]);
        let store = Storage::prepare(&meta, dir.path()).unwrap();
        assert!(store.read_at(8, 5).is_err());
    }

    #[test]
    fn prepare_refuses_paths_outside_root() {
        let dir = TempDir::new("escape");
        let root = dir.path().join("dl");
        let mut meta = meta_multifile(16, vec![("a.bin", 10)]);
        meta.files = Files::Single { name: "../evil.bin".into(), length: 10 };
        assert!(Storage::prepare(&meta, &root).is_err());
        assert!(!dir.path().join("evil.bin").exists());
        meta.files = Files::Single { name: "/tmp/torrust-abs-evil".into(), length: 10 };
        assert!(Storage::prepare(&meta, &root).is_err());
        assert!(!Path::new("/tmp/torrust-abs-evil").exists());
    }
}