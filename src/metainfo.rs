//! Parsing of `.torrent` metainfo files and `magnet:` URIs into a common
//! [`Metainfo`] type.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha1::{Digest, Sha1};

use crate::bencode::{self, Value};

/// An infohash is always SHA-1 over the bencoded `info` dictionary.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InfoHash(pub [u8; 20]);

impl InfoHash {
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Decode a 40-character hex infohash.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).context("infohash is not valid hex")?;
        let arr: [u8; 20] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("infohash must be 20 bytes (40 hex chars)"))?;
        Ok(InfoHash(arr))
    }
}

impl std::fmt::Display for InfoHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl std::fmt::Debug for InfoHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InfoHash({})", self.to_hex())
    }
}

/// One entry in a multi-file torrent's file list.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: PathBuf,
    pub length: u64,
}

#[derive(Debug, Clone)]
pub enum Files {
    /// BEP 3 single-file torrent: one logical file, name from `info.name`.
    Single { name: String, length: u64 },
    /// BEP 3 multi-file torrent. Paths are relative to the torrent root.
    Multi { files: Vec<FileEntry> },
}

impl Files {
    pub fn total_length(&self) -> u64 {
        match self {
            Files::Single { length, .. } => *length,
            Files::Multi { files } => files.iter().map(|f| f.length).sum(),
        }
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = (&Path, u64)> + '_> {
        match self {
            Files::Single { name, length } => {
                Box::new(std::iter::once((Path::new(name.as_str()), *length)))
            }
            Files::Multi { files } => Box::new(
                files
                    .iter()
                    .map(|f| (f.path.as_path(), f.length)),
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Metainfo {
    pub infohash: InfoHash,
    pub name: String,
    pub piece_length: u32,
    /// SHA-1 of each piece, concatenated.
    pub pieces: Vec<[u8; 20]>,
    pub files: Files,
    /// Total torrent length in bytes.
    pub total_length: u64,
    pub private: bool,
    pub announce: Option<String>,
    pub announce_list: Vec<String>,
    /// BEP 19 `url-list` web seeds, http(s) only.
    pub web_seeds: Vec<String>,
    /// The original bencoded `info` dictionary, served to peers over BEP 9.
    pub info_bytes: Vec<u8>,
}

impl Metainfo {
    pub fn piece_count(&self) -> usize {
        self.pieces.len()
    }

    /// Length of the final piece, which is usually short.
    pub fn last_piece_length(&self) -> u64 {
        let pl = self.piece_length as u64;
        let rem = self.total_length % pl;
        if rem == 0 {
            pl
        } else {
            rem
        }
    }

    pub fn piece_size(&self, index: usize) -> u64 {
        let pl = self.piece_length as u64;
        if index + 1 == self.pieces.len() {
            self.last_piece_length()
        } else {
            pl
        }
    }

    /// Parse a `.torrent` file's raw bytes.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        let root = bencode::decode(raw)
            .map_err(|e| anyhow::anyhow!("torrent file is not valid bencode: {e}"))?;

        // The infohash is the SHA-1 of the *original* bencoded bytes of the info
        // dict, not of our re-encoded copy. Re-encoding is byte-identical for
        // valid input, but for torrents with unsorted or non-canonical keys we
        // need the exact original slice, so locate it in the raw buffer.
        let info_start = find_dict_value_slice(raw, b"info")
            .context("torrent file has no 'info' dictionary")?;
        let info_bytes = info_start.to_vec();
        let mut hasher = Sha1::new();
        hasher.update(info_start);
        let digest = hasher.finalize();
        let infohash = InfoHash(digest.into());

        let info = root.get("info").context("missing info dict")?;

        let name = info
            .get("name")
            .and_then(|v| v.as_str().map(|s| s.to_owned()))
            .context("info dict has no valid name")?;

        let piece_length = info
            .get("piece length")
            .context("info dict has no 'piece length'")?
            .as_int_u64()
            .context("'piece length' must be a positive integer")?;
        if piece_length == 0 || piece_length > 16 * 1024 * 1024 {
            bail!("implausible piece length: {piece_length}");
        }

        let pieces_raw = info
            .get("pieces")
            .context("info dict has no 'pieces'")?
            .as_bytes()?;
        if pieces_raw.len() % 20 != 0 {
            bail!(
                "pieces length {} is not a multiple of 20",
                pieces_raw.len()
            );
        }
        let pieces: Vec<[u8; 20]> = pieces_raw
            .chunks_exact(20)
            .map(|c| {
                let mut a = [0u8; 20];
                a.copy_from_slice(c);
                a
            })
            .collect();

        let private = info
            .get_int_opt("private")
            .map(|n| n == 1)
            .unwrap_or(false);

        let files = parse_files(info, &name)?;

        let mut announce = None;
        let mut announce_list = Vec::new();
        if let Ok(v) = root.get("announce").and_then(|v| v.as_str()) {
            announce = Some(v.to_owned());
            announce_list.push(v.to_owned());
        }
        // BEP 12 extended announce-list, stored as a list of lists.
        if let Some(v) = root.get_opt("announce-list") {
            if let Ok(tiers) = v.as_list() {
                for tier in tiers {
                    if let Ok(entries) = tier.as_list() {
                        for e in entries {
                            if let Ok(url) = e.as_str() {
                                announce_list.push(url.to_owned());
                            }
                        }
                    }
                }
            }
        }
        announce_list.sort();
        announce_list.dedup();

        let mut web_seeds = Vec::new();
        if let Some(v) = root.get_opt("url-list") {
            if let Ok(list) = v.as_list() {
                web_seeds.extend(list.iter().filter_map(|e| e.as_str().ok().map(str::to_owned)));
            } else if let Ok(s) = v.as_str() {
                web_seeds.push(s.to_owned());
            }
        }
        web_seeds.retain(|u| is_http_url(u));
        web_seeds.dedup();

        let total_length = files.total_length();

        // Sanity check: the piece count implied by the file sizes must match the
        // number of hashes present, otherwise the torrent is corrupt.
        let expected = ((total_length + piece_length - 1) / piece_length) as usize;
        if expected != pieces.len() {
            bail!(
                "piece count mismatch: {} hashes but {} pieces implied by total length {}",
                pieces.len(),
                expected,
                total_length
            );
        }

        Ok(Metainfo {
            infohash,
            name,
            piece_length: piece_length as u32,
            pieces,
            files,
            total_length,
            private,
            announce,
            announce_list,
            web_seeds,
            info_bytes,
        })
    }
}

pub fn is_http_url(u: &str) -> bool {
    let l = u.to_ascii_lowercase();
    l.starts_with("http://") || l.starts_with("https://")
}

fn parse_files(info: &Value, root_name: &str) -> Result<Files> {
    if let Some(v) = info.get_opt("length") {
        let len = v.as_int_u64().context("'length' must be an integer")?;
        return Ok(Files::Single {
            name: root_name.to_owned(),
            length: len,
        });
    }

    let list = info
        .get("files")
        .context("info dict has neither 'length' nor 'files'")?
        .as_list()?;

    let mut files = Vec::with_capacity(list.len());
    for entry in list {
        let length = entry
            .get("length")
            .context("file entry has no 'length'")?
            .as_int_u64()
            .context("file 'length' must be an integer")?;
        let path_parts = entry
            .get("path")
            .context("file entry has no 'path'")?
            .as_list()?;

        let mut path = PathBuf::from(root_name);
        for (i, part) in path_parts.iter().enumerate() {
            let seg = part
                .as_str()
                .with_context(|| format!("path component {i} is not valid UTF-8"))?;
            // Reject traversal and separators inside path components; a malicious
            // torrent must not be able to write outside the download directory.
            if seg.is_empty()
                || seg == "."
                || seg == ".."
                || seg.contains('/')
                || seg.contains('\\')
                || seg.contains('\0')
                || (i == 0 && (seg.contains(':') || seg.starts_with('/')))
            {
                bail!("unsafe path component in torrent: {seg:?}");
            }
            path.push(seg);
        }
        files.push(FileEntry { path, length });
    }

    Ok(Files::Multi { files })
}

/// Find the raw bencoded bytes of the value for `key` at the top level of `raw`.
///
/// The infohash must be computed over the exact original bytes of the `info`
/// dictionary, so we cannot rely on re-encoding a parsed value: a torrent with
/// non-canonical (but still widely accepted) key ordering would hash differently.
/// This walks the top-level dictionary, tracking byte offsets, and returns the
/// original slice.
///
/// Reuses the tested decoder to find each value's end rather than reimplementing
/// bencode parsing, so the two can never disagree about where a value ends.
fn find_dict_value_slice<'a>(raw: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    use crate::bencode::{decode_partial, Value};

    if raw.first() != Some(&b'd') {
        return None;
    }

    let mut offset = 1usize; // past the leading 'd'
    let mut prev_key: Option<Vec<u8>> = None;

    loop {
        // End of the dictionary without finding the key.
        match raw.get(offset) {
            None | Some(b'e') => return None,
            Some(_) => {}
        }

        // `decode_partial` returns the unconsumed tail, so the number of bytes a
        // value consumed is `input.len() - tail.len()`. For a key that is the
        // *encoded* length, e.g. `8:announce` is 10 bytes, which is what we
        // need in order to advance. The key's actual content is the decoded
        // byte string, which is what we compare against.
        let (key_value, after_key) = decode_partial(raw.get(offset..)?).ok()?;
        let key_encoded_len = raw.len() - after_key.len() - offset;

        let key_bytes: Vec<u8> = match key_value {
            Value::Bytes(b) => b,
            _ => return None,
        };

        // Bencode requires dictionary keys to be sorted. A torrent that breaks
        // that is malformed and its infohash would be ambiguous.
        if let Some(p) = &prev_key {
            if p.as_slice() > key_bytes.as_slice() {
                return None;
            }
        }
        prev_key = Some(key_bytes.clone());

        let value_start = offset + key_encoded_len;
        let (_, after_value) = decode_partial(raw.get(value_start..)?).ok()?;
        let value_end = raw.len() - after_value.len();

        if key_bytes.as_slice() == key {
            return raw.get(value_start..value_end);
        }

        offset = value_end;
    }
}

/// A `magnet:` URI. Metadata is usually not included, so we normally need to
/// contact peers directly to fetch it (see the `dht` module).
#[derive(Debug, Clone)]
pub struct Magnet {
    pub infohash: InfoHash,
    pub display_name: Option<String>,
    pub trackers: Vec<String>,
    pub peers: Vec<SocketAddrLite>,
    /// `x.pe` peer list from the `ws=` parameter (WebSeed-compatible peers).
    pub webseeds: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketAddrLite {
    pub ip: IpAddr,
    pub port: u16,
}

impl std::fmt::Display for SocketAddrLite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ip {
            IpAddr::V4(v4) => write!(f, "{v4}:{}", self.port),
            IpAddr::V6(v6) => write!(f, "[{v6}]:{}", self.port),
        }
    }
}

impl Magnet {
    pub fn parse(uri: &str) -> Result<Self> {
        let body = uri
            .strip_prefix("magnet:")
            .or_else(|| uri.strip_prefix("MAGNET:"))
            .context("not a magnet URI")?;

        // `magnet:?xt=...` leaves the leading '?' on the first parameter, so it
        // must come off before splitting on '&' or the first key reads "?xt".
        let rest = body.strip_prefix('?').unwrap_or(body);

        let mut infohash = None;
        let mut display_name = None;
        let mut trackers = Vec::new();
        let peers: Vec<SocketAddrLite> = Vec::new();
        let mut webseeds = Vec::new();

        for pair in rest.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, raw) = match pair.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            // Magnet URIs use query syntax, where `+` is a space in addition to %20.
            // Both appear in the wild, so normalise before percent-decoding.
            let decoded = percent_encoding::percent_decode_str(&raw.replace('+', " "))
                .decode_utf8_lossy()
                .into_owned();

            match key {
                "xt" => {
                    // xt=urn:btih:<40 hex> or <32 base32>
                    if let Some(hash) = decoded
                        .strip_prefix("urn:btih:")
                        .or_else(|| decoded.strip_prefix("urn:btmh:"))
                    {
                        if hash.len() == 40 {
                            infohash = Some(InfoHash::from_hex(hash)?);
                        } else if hash.len() == 32 {
                            infohash = Some(InfoHash(base32_decode_20(hash)?));
                        }
                    }
                }
                "dn" => display_name = Some(decoded),
                "tr" => trackers.push(decoded),
                // `xs` is an exact-topic search we cannot serve; `as` is a
                // deprecated alias that some trackers still emit.
                "ws" => webseeds.push(decoded),
                _ => {}
            }
        }

        let infohash = infohash.context("magnet URI has no usable 'xt' infohash (need urn:btih)")?;

        Ok(Magnet {
            infohash,
            display_name,
            trackers,
            peers,
            webseeds,
        })
    }
}

/// Decode RFC 4648 base32 (case-insensitive, no padding required) into 20 bytes,
/// which is the binary form of an infohash.
fn base32_decode_20(s: &str) -> Result<[u8; 20]> {
    let mut bits = 0u32;
    let mut acc: u64 = 0;
    let mut out = Vec::with_capacity(20);
    for ch in s.chars() {
        if ch == '=' {
            continue;
        }
        let v = match ch.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => bail!("invalid base32 character in infohash: {ch:?}"),
        };
        // We retain at most 7 bits between characters and consume 5 new ones, so a
        // 12-bit window is sufficient. Masking keeps `acc` from overflowing on
        // long (or maliciously over-long) input.
        acc = ((acc << 5) | v as u64) & 0x0fff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
        if out.len() == 20 {
            break;
        }
    }
    if out.len() != 20 {
        bail!("base32 infohash decoded to {} bytes, expected 20", out.len());
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&out);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Build a valid single-file torrent by encoding a dict, rather than
    /// concatenating bencode by hand. Hand-written byte strings are easy to get
    /// subtly wrong (a miscounted string length silently shifts every following
    /// offset), which tests the fixture instead of the parser.
    fn single_file_torrent(piece_len: u32, total: u64, name: &str) -> Vec<u8> {
        use crate::bencode::Value;
        let piece_count = total.div_ceil(piece_len as u64) as usize;
        let mut pieces = Vec::new();
        for i in 0..piece_count {
            let mut h = Sha1::new();
            h.update((i as u64).to_be_bytes());
            pieces.extend_from_slice(&h.finalize());
        }

        let info = Value::Dict(std::collections::BTreeMap::from([
            (b"length".to_vec(), Value::Int(total as i64)),
            (b"name".to_vec(), Value::Bytes(name.as_bytes().to_vec())),
            (b"piece length".to_vec(), Value::Int(piece_len as i64)),
            (b"pieces".to_vec(), Value::Bytes(pieces)),
        ]));

        crate::bencode::encode(&Value::Dict(std::collections::BTreeMap::from([
            (b"announce".to_vec(), Value::Bytes(b"http://tracker/ann".to_vec())),
            (b"info".to_vec(), info),
        ])))
    }

    fn with_url_list(url_list: crate::bencode::Value) -> Metainfo {
        use crate::bencode::Value;
        let raw = single_file_torrent(16384, 40_000, "hello.bin");
        let Value::Dict(mut d) = crate::bencode::decode(&raw).unwrap() else { panic!() };
        d.insert(b"url-list".to_vec(), url_list);
        Metainfo::from_bytes(&crate::bencode::encode(&Value::Dict(d))).unwrap()
    }

    #[test]
    fn url_list_string_list_and_non_http() {
        use crate::bencode::Value;
        let b = |s: &str| Value::Bytes(s.as_bytes().to_vec());
        assert_eq!(with_url_list(b("http://a/f")).web_seeds, vec!["http://a/f"]);
        let m = with_url_list(Value::List(vec![b("https://b/"), b("ftp://c/x"), b("http://d/y")]));
        assert_eq!(m.web_seeds, vec!["https://b/", "http://d/y"]);
        assert!(with_url_list(b("")).web_seeds.is_empty());
        assert!(Metainfo::from_bytes(&single_file_torrent(16384, 40_000, "x")).unwrap().web_seeds.is_empty());
    }

    #[test]
    fn parses_single_file_torrent() {
        let raw = single_file_torrent(16384, 40_000, "hello.bin");
        let mi = Metainfo::from_bytes(&raw).unwrap();
        assert_eq!(mi.name, "hello.bin");
        assert_eq!(mi.total_length, 40_000);
        assert_eq!(mi.piece_length, 16384);
        assert_eq!(mi.piece_count(), 3); // ceil(40000/16384) = 3
        assert_eq!(mi.last_piece_length(), 40_000 - 2 * 16_384);
        assert_eq!(mi.announce.as_deref(), Some("http://tracker/ann"));
    }

    #[test]
    fn infohash_is_sha1_of_info_dict() {
        let raw = single_file_torrent(16384, 40_000, "hello.bin");
        let mi = Metainfo::from_bytes(&raw).unwrap();
        let info_slice = find_dict_value_slice(&raw, b"info").unwrap();
        let mut h = Sha1::new();
        h.update(info_slice);
        let expect: [u8; 20] = h.finalize().into();
        assert_eq!(mi.infohash.0, expect);
    }

    #[test]
    fn rejects_piece_count_mismatch() {
        use crate::bencode::Value;
        // 70000 bytes at 16384/piece implies 5 pieces, but only 3 hashes are
        // supplied. The torrent is corrupt and must be refused rather than
        // silently downloading a truncated payload.
        let info = Value::Dict(std::collections::BTreeMap::from([
            (b"length".to_vec(), Value::Int(70_000)),
            (b"name".to_vec(), Value::Bytes(b"mismatch.bin".to_vec())),
            (b"piece length".to_vec(), Value::Int(16384)),
            (b"pieces".to_vec(), Value::Bytes(vec![0u8; 3 * 20])),
        ]));
        let err = Metainfo::from_bytes(&wrap(info)).unwrap_err();
        assert!(
            format!("{err:#}").contains("piece count mismatch"),
            "expected a piece count mismatch, got: {err:#}"
        );
    }

    #[test]
    fn rejects_pieces_length_not_multiple_of_twenty() {
        use crate::bencode::Value;
        let info = Value::Dict(std::collections::BTreeMap::from([
            (b"length".to_vec(), Value::Int(10)),
            (b"name".to_vec(), Value::Bytes(b"odd.bin".to_vec())),
            (b"piece length".to_vec(), Value::Int(10)),
            (b"pieces".to_vec(), Value::Bytes(vec![0u8; 25])), // not a multiple of 20
        ]));
        assert!(Metainfo::from_bytes(&wrap(info)).is_err());
    }

    /// Assemble a torrent file from an info dict.
    fn wrap(info: crate::bencode::Value) -> Vec<u8> {
        use crate::bencode::Value;
        crate::bencode::encode(&Value::Dict(std::collections::BTreeMap::from([
            (b"announce".to_vec(), Value::Bytes(b"http://tracker/ann".to_vec())),
            (b"info".to_vec(), info),
        ])))
    }

    /// A multi-file info dict with the given (name, length) entries.
    fn multi_file_info(name: &str, entries: &[(&str, u64)], piece_len: u32, pieces: usize) -> crate::bencode::Value {
        use crate::bencode::Value;
        let files: Vec<Value> = entries
            .iter()
            .map(|(n, len)| {
                Value::Dict(std::collections::BTreeMap::from([
                    (b"length".to_vec(), Value::Int(*len as i64)),
                    (
                        b"path".to_vec(),
                        Value::List(vec![Value::Bytes(n.as_bytes().to_vec())]),
                    ),
                ]))
            })
            .collect();
        Value::Dict(std::collections::BTreeMap::from([
            (b"files".to_vec(), Value::List(files)),
            (b"name".to_vec(), Value::Bytes(name.as_bytes().to_vec())),
            (b"piece length".to_vec(), Value::Int(piece_len as i64)),
            (b"pieces".to_vec(), Value::Bytes(vec![0u8; pieces * 20])),
        ]))
    }

    #[test]
    fn parses_multi_file_torrent() {
        // 10 + 30 = 40 bytes at 20 bytes/piece = 2 pieces.
        let raw = wrap(multi_file_info("root", &[("a.txt", 10), ("b.txt", 30)], 20, 2));

        let mi = Metainfo::from_bytes(&raw).unwrap();
        assert_eq!(mi.total_length, 40);
        assert_eq!(mi.piece_count(), 2);
        match &mi.files {
            Files::Multi { files } => {
                assert_eq!(files.len(), 2);
                assert_eq!(files[0].path, PathBuf::from("root").join("a.txt"));
                assert_eq!(files[1].path, PathBuf::from("root").join("b.txt"));
            }
            _ => panic!("expected multi-file"),
        }
    }

    #[test]
    fn rejects_path_traversal() {
        use crate::bencode::Value;
        // A path component of ".." must never be accepted, however it is
        // encoded, or a malicious torrent could write outside the download dir.
        for evil in ["..", ".", "", "a/b", "a\\b", "/abs", "C:/abs"] {
            let files = Value::List(vec![Value::Dict(std::collections::BTreeMap::from([
                (b"length".to_vec(), Value::Int(10)),
                (
                    b"path".to_vec(),
                    Value::List(vec![Value::Bytes(evil.as_bytes().to_vec())]),
                ),
            ]))]);
            let info = Value::Dict(std::collections::BTreeMap::from([
                (b"files".to_vec(), files),
                (b"name".to_vec(), Value::Bytes(b"root".to_vec())),
                (b"piece length".to_vec(), Value::Int(10)),
                (b"pieces".to_vec(), Value::Bytes(vec![0u8; 20])),
            ]));
            assert!(
                Metainfo::from_bytes(&wrap(info)).is_err(),
                "path component {evil:?} should be rejected"
            );
        }
    }

    #[test]
    fn accepts_ordinary_path_components() {
        let mi = Metainfo::from_bytes(&wrap(multi_file_info(
            "root",
            &[("a.txt", 10)],
            10,
            1,
        )))
        .unwrap();
        assert_eq!(mi.files.iter().count(), 1);
    }

    #[test]
    fn parses_magnet_uri() {
        let m = Magnet::parse("magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=Some+Name&tr=http://a/ann&tr=udp://b:1337/ann").unwrap();
        assert_eq!(
            m.infohash.to_hex(),
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(m.display_name.as_deref(), Some("Some Name"));
        assert_eq!(m.trackers.len(), 2);
    }

    #[test]
    fn parses_base32_magnet() {
        // "0123456789abcdef0123456789abcdef01234567" in RFC 4648 base32
        let b32 = "AERUKZ4JVPG66AJDIVTYTK6N54ASGRLH";
        let m = Magnet::parse(&format!("magnet:?xt=urn:btih:{b32}")).unwrap();
        assert_eq!(m.infohash.to_hex(), "0123456789abcdef0123456789abcdef01234567");
    }

    #[test]
    fn rejects_magnet_without_infohash() {
        assert!(Magnet::parse("magnet:?dn=nothing").is_err());
    }

    #[test]
    fn infohash_hex_roundtrip() {
        let h = InfoHash([7u8; 20]);
        assert_eq!(InfoHash::from_hex(&h.to_hex()).unwrap(), h);
    }

    #[test]
    fn helper_ip_formatting() {
        let v4 = SocketAddrLite {
            ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            port: 6881,
        };
        assert_eq!(v4.to_string(), "1.2.3.4:6881");
        let v6 = SocketAddrLite {
            ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 6881,
        };
        assert_eq!(v6.to_string(), "[::1]:6881");
    }
}