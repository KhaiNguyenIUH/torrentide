//! Piece selection.
//!
//! Deciding which blocks to ask for is the core quality decision in a
//! BitTorrent client. A naive first-come-first-served scheduler thrashes:
//! it downloads random fragments, produces lots of unverified data, and wastes
//! bandwidth on pieces it already partly has. This uses rarest-first with an
//! endgame phase, the standard approach.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::metainfo::Metainfo;
use crate::state::FilePriority;
use crate::peer::connection::BLOCK_SIZE;

/// How long a requested block may stay unanswered before it is requested
/// again. Peers that choke us, disconnect, or just stall drop our requests
/// without telling us; without this those blocks would stay "in flight"
/// forever and the download would hang just short of 100%.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// In endgame the last few blocks are re-requested this quickly, so the
/// fastest peer that has them wins instead of the slowest one we asked first.
pub const ENDGAME_RETRY: Duration = Duration::from_secs(5);

/// Tracks which blocks of which pieces we hold.
pub struct BlockMap {
    /// Per piece, a bitmask over the blocks of that piece.
    pieces: Vec<Option<Vec<bool>>>,
    piece_len: u32,
    /// Length of the final piece, which is usually shorter than `piece_len`.
    last_piece_len: u32,
    piece_count: usize,
    /// Pieces already verified against their hash.
    verified: Vec<bool>,
}

impl BlockMap {
    pub fn new(meta: &Metainfo) -> Self {
        let piece_len = meta.piece_length;
        let piece_count = meta.piece_count();
        BlockMap {
            pieces: vec![None; piece_count],
            verified: vec![false; piece_count],
            piece_len,
            last_piece_len: if piece_count == 0 {
                piece_len
            } else {
                meta.last_piece_length() as u32
            },
            piece_count,
        }
    }

    /// Length of a given piece. The final piece is short whenever the torrent's
    /// total size is not an exact multiple of the piece length.
    fn length_of(&self, index: usize) -> u32 {
        if index + 1 == self.piece_count {
            self.last_piece_len
        } else {
            self.piece_len
        }
    }

    pub fn blocks_in_piece(&self, index: usize) -> usize {
        self.length_of(index).div_ceil(BLOCK_SIZE) as usize
    }

    pub fn have_block(&self, piece: u32, block: usize) -> bool {
        self.pieces
            .get(piece as usize)
            .and_then(|p| p.as_ref())
            .and_then(|v| v.get(block))
            .copied()
            .unwrap_or(false)
    }

    /// Record a received block.
    pub fn add_block(&mut self, piece: u32, block: usize) {
        let idx = piece as usize;
        let n = self.blocks_in_piece(idx);
        if idx >= self.pieces.len() {
            return;
        }
        let entry = self.pieces[idx].get_or_insert_with(|| vec![false; n]);
        if let Some(slot) = entry.get_mut(block) {
            *slot = true;
        }
    }

    pub fn is_piece_complete(&self, piece: u32) -> bool {
        let idx = piece as usize;
        match &self.pieces[idx] {
            None => false,
            Some(bits) => bits.iter().all(|b| *b),
        }
    }

    pub fn mark_verified(&mut self, piece: u32) {
        let idx = piece as usize;
        if idx < self.verified.len() {
            self.verified[idx] = true;
        }
    }

    pub fn is_verified(&self, piece: u32) -> bool {
        self.verified.get(piece as usize).copied().unwrap_or(false)
    }

    /// Bytes held so far, counting only verified pieces plus in-flight partial
    /// pieces. Used for progress display.
    pub fn bytes_downloaded(&self, meta: &Metainfo) -> u64 {
        let mut total = 0u64;
        for i in 0..meta.piece_count() {
            if self.is_verified(i as u32) {
                total += meta.piece_size(i);
                continue;
            }
            match &self.pieces[i] {
                None => {}
                Some(bits) => {
                    for (b, have) in bits.iter().enumerate() {
                        if *have {
                            let begin = (b as u32) * BLOCK_SIZE;
                            total += block_len(self.length_of(i), begin) as u64;
                        }
                    }
                }
            }
        }
        total
    }

    /// Mark every block of a piece as present but not verified. Used when
    /// rechecking existing data on disk at startup.
    pub fn mark_piece_present(&mut self, piece: u32) {
        let idx = piece as usize;
        if idx >= self.pieces.len() {
            return;
        }
        let n = self.blocks_in_piece(idx);
        self.pieces[idx] = Some(vec![true; n]);
    }

    /// Drop all unverified data for a piece after a hash mismatch.
    pub fn invalidate_piece(&mut self, piece: u32) {
        let idx = piece as usize;
        self.verified[idx] = false;
        self.pieces[idx] = None;
    }

    pub fn verified_count(&self) -> u32 {
        self.verified.iter().filter(|v| **v).count() as u32
    }

    /// Per-piece verified flags, used to build the set we advertise as a seeder.
    pub fn verified_pieces(&self) -> Vec<bool> {
        self.verified.clone()
    }

    pub fn total_pieces(&self) -> usize {
        self.pieces.len()
    }
}

/// One unit of work handed to the peer pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRequest {
    pub piece: u32,
    pub block: usize,
    pub begin: u32,
    pub length: u32,
}

impl BlockRequest {
    pub fn key(&self) -> (u32, usize) {
        (self.piece, self.block)
    }
}

/// Chooses which blocks to request next.
pub struct Scheduler {
    block_map: BlockMap,
    piece_len: u32,
    piece_count: usize,
    /// Length of the final piece. It is usually shorter than `piece_len` because
    /// a torrent's total size is rarely an exact multiple of the piece length,
    /// and a request that overshoots it would run past the end of the payload.
    last_piece_len: u32,
    /// Blocks requested but not yet received, with when they were last asked
    /// for, so we do not ask twice until the request goes stale.
    in_flight: HashMap<(u32, usize), Instant>,
    request_timeout: Duration,
    endgame_retry: Duration,
    /// Pieces the user skipped via per-file selection. They are never
    /// requested and do not count toward completion. A piece is excludable
    /// only when none of its bytes belong to a wanted file; pieces straddling
    /// the boundary still download.
    excluded: HashSet<u32>,
    /// Per-piece priority band, empty meaning every piece is Normal.
    priority: Vec<FilePriority>,
    /// Below this many pieces remaining we switch to endgame, asking every peer
    /// that claims a piece so a single slow peer cannot stall the download.
    endgame_threshold: usize,
}

impl Scheduler {
    pub fn new(meta: &Metainfo) -> Self {
        let piece_count = meta.piece_count();
        let pl = meta.piece_length;
        let last_piece_len = if piece_count == 0 {
            pl
        } else {
            meta.last_piece_length() as u32
        };
        Self {
            block_map: BlockMap::new(meta),
            piece_len: pl,
            piece_count,
            last_piece_len,
            in_flight: HashMap::new(),
            request_timeout: REQUEST_TIMEOUT,
            endgame_retry: ENDGAME_RETRY,
            excluded: HashSet::new(),
            priority: Vec::new(),
            endgame_threshold: 4,
        }
    }

    /// Replace the set of skipped pieces, e.g. after the user toggles a file.
    /// In-flight blocks of newly excluded pieces are dropped so they are never
    /// re-requested; blocks that already arrived stay on disk, harmlessly.
    pub fn set_excluded(&mut self, pieces: &HashSet<u32>) {
        self.excluded = pieces.clone();
        self.in_flight.retain(|(p, _), _| !self.excluded.contains(p));
    }

    /// Install per-piece priorities (see [`piece_priorities`]). Pieces whose
    /// every file is `Skip` become the excluded set, so this subsumes
    /// [`Scheduler::set_excluded`] for callers that track priorities.
    pub fn set_piece_priorities(&mut self, priorities: Vec<FilePriority>) {
        let skipped = priorities
            .iter()
            .enumerate()
            .filter(|(_, p)| **p == FilePriority::Skip)
            .map(|(i, _)| i as u32)
            .collect();
        self.priority = priorities;
        self.set_excluded(&skipped);
    }

    fn priority_of(&self, piece: u32) -> FilePriority {
        self.priority.get(piece as usize).copied().unwrap_or_default()
    }

    pub fn excluded(&self) -> &HashSet<u32> {
        &self.excluded
    }

    /// Length of a given piece, accounting for a short final piece.
    fn length_of_piece(&self, piece: u32) -> u32 {
        if piece + 1 == self.piece_count as u32 {
            self.last_piece_len
        } else {
            self.piece_len
        }
    }

    pub fn block_map(&self) -> &BlockMap {
        &self.block_map
    }

    /// Mutable access, used by the engine when marking pieces verified or
    /// discarding a piece that failed its hash check.
    pub fn block_map_mut(&mut self) -> &mut BlockMap {
        &mut self.block_map
    }

    pub fn remaining_bytes(&self, meta: &Metainfo) -> u64 {
        meta.total_length.saturating_sub(self.block_map.bytes_downloaded(meta))
    }

    pub fn is_complete(&self) -> bool {
        (0..self.piece_count as u32)
            .filter(|i| !self.excluded.contains(i))
            .all(|i| self.block_map.is_verified(i))
    }

    pub fn progress(&self) -> f64 {
        let wanted: Vec<u32> = (0..self.piece_count as u32)
            .filter(|i| !self.excluded.contains(i))
            .collect();
        if wanted.is_empty() {
            return 1.0;
        }
        let done = wanted
            .iter()
            .filter(|i| self.block_map.is_verified(**i))
            .count();
        done as f64 / wanted.len() as f64
    }

    /// Mark a block as received.
    pub fn on_block(&mut self, req: BlockRequest) {
        self.in_flight.remove(&req.key());
        self.block_map.add_block(req.piece, req.block);
    }

    /// Drop blocks that never arrived, so they can be retried.
    pub fn on_timeout(&mut self, key: (u32, usize)) {
        self.in_flight.remove(&key);
    }

    pub fn release_piece(&mut self, piece: u32) {
        self.in_flight.retain(|(p, _), _| *p != piece);
    }

    /// A piece is ready to hash when all of its blocks have arrived.
    pub fn ready_pieces(&self) -> Vec<u32> {
        (0..self.piece_count as u32)
            .filter(|i| {
                !self.block_map.is_verified(*i)
                    && !self.excluded.contains(i)
                    && self.block_map.is_piece_complete(*i)
            })
            .collect()
    }

    /// Pick the next block to request, preferring rare pieces.
    ///
    /// `rarity` maps a piece index to how many connected peers hold it. Passing
    /// `None` means rarity is unknown and every piece is treated as equally
    /// rare.
    ///
    /// A block whose request has gone stale is handed out again: after
    /// [`REQUEST_TIMEOUT`] normally, or [`ENDGAME_RETRY`] in endgame.
    pub fn next_block(&mut self, rarity: &HashMap<u32, u32>) -> Option<BlockRequest> {
        let candidates = self.candidate_pieces(rarity);
        let retry_after = if self.in_endgame() {
            self.endgame_retry
        } else {
            self.request_timeout
        };

        for piece in candidates {
            let n = self.block_map.blocks_in_piece(piece as usize);
            for block in 0..n {
                let key = (piece, block);
                let pending = self
                    .in_flight
                    .get(&key)
                    .is_some_and(|asked| asked.elapsed() < retry_after);
                if self.block_map.have_block(piece, block) || pending {
                    continue;
                }
                let begin = (block as u32) * BLOCK_SIZE;
                let length = block_len(self.length_of_piece(piece), begin);
                self.in_flight.insert(key, Instant::now());
                return Some(BlockRequest {
                    piece,
                    block,
                    begin,
                    length,
                });
            }
        }
        None
    }

    /// Claim a whole piece for an HTTP web seed. Only pieces with no fresh
    /// in-flight block qualify, so the web seed never duplicates a peer's
    /// work. Returns the piece's missing blocks, now marked in flight.
    pub fn claim_piece_for_webseed(
        &mut self,
        rarity: &HashMap<u32, u32>,
        usable: impl Fn(u32) -> bool,
    ) -> Option<(u32, Vec<BlockRequest>)> {
        let retry_after = if self.in_endgame() {
            self.endgame_retry
        } else {
            self.request_timeout
        };
        for piece in self.candidate_pieces(rarity) {
            if !usable(piece) {
                continue;
            }
            let piece_len = self.length_of_piece(piece);
            let missing: Vec<usize> = (0..self.block_map.blocks_in_piece(piece as usize))
                .filter(|b| !self.block_map.have_block(piece, *b))
                .collect();
            let pending = missing.iter().any(|b| {
                self.in_flight
                    .get(&(piece, *b))
                    .is_some_and(|asked| asked.elapsed() < retry_after)
            });
            if missing.is_empty() || pending {
                continue;
            }
            let now = Instant::now();
            let reqs = missing
                .into_iter()
                .map(|block| {
                    let begin = block as u32 * BLOCK_SIZE;
                    self.in_flight.insert((piece, block), now);
                    BlockRequest {
                        piece,
                        block,
                        begin,
                        length: block_len(piece_len, begin),
                    }
                })
                .collect();
            return Some((piece, reqs));
        }
        None
    }

    /// Fill a batch of requests, using rarest-first ordering.
    pub fn fill_batch(&mut self, rarity: &HashMap<u32, u32>, n: usize) -> Vec<BlockRequest> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            match self.next_block(rarity) {
                Some(r) => out.push(r),
                None => break,
            }
        }
        out
    }

    /// Endgame means re-asking for the last blocks so one slow peer cannot
    /// stall us. It is only worth the duplicate traffic near the end; on a
    /// torrent whose entire size is below the threshold we would be in endgame
    /// from the first block, which is pure waste.
    fn in_endgame(&self) -> bool {
        let remaining = self.remaining_pieces();
        remaining <= self.endgame_threshold && remaining < self.piece_count
    }

    fn candidate_pieces(&self, rarity: &HashMap<u32, u32>) -> Vec<u32> {
        let endgame = self.in_endgame();

        let mut pieces: Vec<u32> = (0..self.piece_count as u32)
            .filter(|i| !self.block_map.is_verified(*i) && !self.excluded.contains(i))
            .collect();

        if !endgame {
            // Priority band first (High > Normal > Low), so a file the user
            // wants sooner is never starved by a rarer piece of a lesser one.
            // Within a band: rarest-first, because the pieces held by the
            // fewest peers are the ones most likely to become unavailable.
            //
            // Both criteria must live in a SINGLE sort key. Sorting by rarity
            // and then re-sorting by how much of the piece we already hold
            // would discard the rarity ordering entirely, since the second sort
            // becomes the primary ordering.
            pieces.sort_by_key(|p| {
                let holders = rarity.get(p).copied().unwrap_or(u32::MAX / 2);
                // Prefer rare pieces; among equally-rare ones, prefer the piece
                // we have most of, so pieces complete (and become seedable)
                // sooner; then fall back to ascending index for determinism.
                (
                    std::cmp::Reverse(self.priority_of(*p)),
                    holders,
                    std::cmp::Reverse(self.piece_block_count(*p)),
                    *p,
                )
            });
        }

        pieces
    }

    fn remaining_pieces(&self) -> usize {
        (0..self.piece_count as u32)
            .filter(|i| !self.block_map.is_verified(*i) && !self.excluded.contains(i))
            .count()
    }

    fn piece_block_count(&self, piece: u32) -> usize {
        (0..self.block_map.blocks_in_piece(piece as usize))
            .filter(|b| self.block_map.have_block(piece, *b))
            .count()
    }

    /// Requests still awaiting an answer. Stale ones do not count, so they
    /// never eat the engine's request budget.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight
            .values()
            .filter(|asked| asked.elapsed() < self.request_timeout)
            .count()
    }
}

pub fn block_len(piece_len: u32, begin: u32) -> u32 {
    std::cmp::min(BLOCK_SIZE, piece_len.saturating_sub(begin))
}

/// Pieces that may be skipped given per-file wanted flags.
///
/// A piece is excludable only when its whole byte range lies inside unwanted
/// files. Pieces straddling a wanted/unwanted boundary still download, because
/// they carry wanted bytes.
pub fn excluded_pieces(meta: &Metainfo, wanted: &[bool]) -> HashSet<u32> {
    let mut ranges: Vec<(u64, u64, bool)> = Vec::new();
    let mut cursor = 0u64;
    for (i, (_, len)) in meta.files.iter().enumerate() {
        ranges.push((cursor, cursor + len, wanted.get(i).copied().unwrap_or(true)));
        cursor += len;
    }

    let piece_len = meta.piece_length as u64;
    (0..meta.piece_count() as u32)
        .filter(|p| {
            let ps = *p as u64 * piece_len;
            let pe = ps + meta.piece_size(*p as usize);
            // Excluded when no wanted file overlaps the piece at all.
            !ranges.iter().any(|(fs, fe, w)| {
                *w && *fs < pe && ps < *fe
            })
        })
        .collect()
}

/// Priority of every piece: the highest priority among the files overlapping
/// it. A piece is `Skip` only when all of its files are, so a piece shared by
/// a skipped file and a wanted one is still fetched at the wanted file's
/// priority.
pub fn piece_priorities(meta: &Metainfo, files: &[FilePriority]) -> Vec<FilePriority> {
    let mut out = vec![FilePriority::Skip; meta.piece_count()];
    let piece_len = meta.piece_length as u64;
    if piece_len == 0 {
        return out;
    }
    let mut cursor = 0u64;
    for (i, (_, len)) in meta.files.iter().enumerate() {
        let (fs, fe) = (cursor, cursor + len);
        cursor = fe;
        if fs >= fe {
            continue;
        }
        let prio = files.get(i).copied().unwrap_or_default();
        let first = (fs / piece_len) as usize;
        let last = (((fe - 1) / piece_len) as usize).min(out.len().saturating_sub(1));
        for slot in out.iter_mut().take(last + 1).skip(first) {
            *slot = (*slot).max(prio);
        }
    }
    out
}

/// Downloaded bytes per file, in torrent file order.
///
/// A file's count is the verified bytes within its range: the full overlap for
/// verified pieces, plus individual blocks that already arrived in pieces that
/// are still partial. Used for the per-file progress display.
pub fn file_downloaded(meta: &Metainfo, map: &BlockMap) -> Vec<u64> {
    // File byte ranges in the flat stream, in torrent order.
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut cursor = 0u64;
    for (_, len) in meta.files.iter() {
        ranges.push((cursor, cursor + len));
        cursor += len;
    }

    let mut out = vec![0u64; ranges.len()];
    let piece_len = meta.piece_length as u64;

    for (fi, (fs, fe)) in ranges.iter().enumerate() {
        if fs >= fe {
            continue; // zero-length file: nothing to download
        }
        // Every piece overlapping [fs, fe).
        let first = (fs / piece_len) as u32;
        let last = ((fe - 1) / piece_len) as u32;
        for piece in first..=last {
            let ps = piece as u64 * piece_len;
            let pe = ps + meta.piece_size(piece as usize);
            let overlap = (*fs).max(ps)..(*fe).min(pe);
            if overlap.is_empty() {
                continue;
            }
            if map.is_verified(piece) {
                out[fi] += overlap.end - overlap.start;
                continue;
            }
            // Partial piece: count individual blocks within the file range.
            let n = map.blocks_in_piece(piece as usize);
            for b in 0..n {
                if !map.have_block(piece, b) {
                    continue;
                }
                let begin = (b as u32) * BLOCK_SIZE;
                let len = block_len(map.length_of(piece as usize), begin) as u64;
                let bs = ps + begin as u64;
                let be = bs + len;
                let inter = (*fs).max(bs)..(*fe).min(be);
                if !inter.is_empty() {
                    out[fi] += inter.end - inter.start;
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metainfo::{Files, InfoHash};

    fn meta(piece_len: u32, pieces: usize) -> Metainfo {
        Metainfo {
            infohash: InfoHash([0; 20]),
            name: "t".into(),
            piece_length: piece_len,
            pieces: vec![[0u8; 20]; pieces],
            files: Files::Single {
                name: "t".into(),
                length: piece_len as u64 * pieces as u64,
            },
            total_length: piece_len as u64 * pieces as u64,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
        }
    }

    #[test]
    fn webseed_claims_only_pieces_without_inflight_blocks() {
        let m = meta(BLOCK_SIZE * 2, 3);
        let mut s = Scheduler::new(&m);
        let rarity = HashMap::new();
        let first = s.next_block(&rarity).unwrap();
        let (p, reqs) = s.claim_piece_for_webseed(&rarity, |_| true).unwrap();
        assert_ne!(p, first.piece);
        assert_eq!(reqs.len(), 2);
        let (p2, _) = s.claim_piece_for_webseed(&rarity, |x| x != first.piece && x != p).unwrap();
        assert!(p2 != p && p2 != first.piece);
        assert!(s.claim_piece_for_webseed(&rarity, |_| true).is_none());
        s.release_piece(p);
        assert_eq!(s.claim_piece_for_webseed(&rarity, |_| true).unwrap().0, p);
    }

    #[test]
    fn block_map_tracks_completion() {
        let m = meta(BLOCK_SIZE * 2, 1); // 2 blocks per piece
        let mut bm = BlockMap::new(&m);
        assert_eq!(bm.blocks_in_piece(0), 2);
        assert!(!bm.is_piece_complete(0));

        bm.add_block(0, 0);
        assert!(!bm.is_piece_complete(0));
        bm.add_block(0, 1);
        assert!(bm.is_piece_complete(0));

        bm.mark_verified(0);
        assert!(bm.is_verified(0));
    }

    #[test]
    fn last_piece_block_count_accounts_for_short_piece() {
        // Piece length 20 KiB => 2 blocks (16 KiB + 4 KiB).
        let m = meta(20480, 1);
        let bm = BlockMap::new(&m);
        assert_eq!(bm.blocks_in_piece(0), 2);
    }

    #[test]
    fn scheduler_prefers_rarest_piece() {
        let m = meta(BLOCK_SIZE, 4);
        let mut s = Scheduler::new(&m);
        // Piece 2 is held by one peer, piece 0 by many.
        let rarity = HashMap::from([(0u32, 50u32), (1, 20), (2, 1), (3, 30)]);

        let first = s.next_block(&rarity).unwrap();
        assert_eq!(first.piece, 2, "rarest piece should be requested first");
    }

    #[test]
    fn scheduler_marks_in_flight_to_avoid_duplicates() {
        // 3 pieces of one block each: three distinct requests must be possible
        // before the scheduler runs dry.
        let m = meta(BLOCK_SIZE, 3);
        let mut s = Scheduler::new(&m);
        let r1 = s.next_block(&HashMap::new()).unwrap();
        let r2 = s.next_block(&HashMap::new()).unwrap();
        assert_ne!(r1.key(), r2.key());
        assert_eq!(s.in_flight_count(), 2);

        // A third request must not reuse an in-flight block.
        let r3 = s.next_block(&HashMap::new()).unwrap();
        assert_ne!(r3.key(), r1.key());
        assert_ne!(r3.key(), r2.key());
    }

    #[test]
    fn on_timeout_allows_retry() {
        let m = meta(BLOCK_SIZE, 1);
        let mut s = Scheduler::new(&m);
        let r = s.next_block(&HashMap::new()).unwrap();
        assert!(s.next_block(&HashMap::new()).is_none());

        s.on_timeout(r.key());
        let again = s.next_block(&HashMap::new()).unwrap();
        assert_eq!(again.key(), r.key());
    }

    #[test]
    fn stale_requests_are_retried() {
        let m = meta(BLOCK_SIZE, 1);
        let mut s = Scheduler::new(&m);
        let r = s.next_block(&HashMap::new()).unwrap();
        assert!(s.next_block(&HashMap::new()).is_none());

        // The peer never answered: once the request is stale the block is
        // handed out again and stops counting against the request budget.
        s.request_timeout = Duration::ZERO;
        assert_eq!(s.in_flight_count(), 0);
        let again = s.next_block(&HashMap::new()).unwrap();
        assert_eq!(again.key(), r.key());
    }

    #[test]
    fn endgame_retries_sooner_than_normal() {
        let m = meta(BLOCK_SIZE, 8);
        let mut s = Scheduler::new(&m);
        s.endgame_retry = Duration::ZERO;

        // Far from the end: an unanswered block is not re-requested.
        let r = s.next_block(&HashMap::new()).unwrap();
        let next = s.next_block(&HashMap::new()).unwrap();
        assert_ne!(next.key(), r.key());

        // One piece left: its pending block is handed out again at once.
        for i in 0..7u32 {
            s.block_map.mark_verified(i);
        }
        let first = s.next_block(&HashMap::new()).unwrap();
        let dup = s.next_block(&HashMap::new()).unwrap();
        assert_eq!((first.key(), dup.key()), ((7, 0), (7, 0)));
    }

    #[test]
    fn ready_pieces_only_when_fully_downloaded() {
        // Two blocks per piece, so one block is genuinely not enough.
        let m = meta(BLOCK_SIZE * 2, 3);
        let mut s = Scheduler::new(&m);
        s.on_block(BlockRequest {
            piece: 1,
            block: 0,
            begin: 0,
            length: BLOCK_SIZE,
        });
        assert!(
            s.ready_pieces().is_empty(),
            "a half-downloaded piece must not be ready"
        );

        let r = s.next_block(&HashMap::new()).unwrap();
        s.on_block(r);
        let ready = s.ready_pieces();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], 1);
    }

    #[test]
    fn verified_pieces_are_never_rescheduled() {
        let m = meta(BLOCK_SIZE, 3);
        let mut s = Scheduler::new(&m);
        for i in 0..3u32 {
            s.on_block(BlockRequest {
                piece: i,
                block: 0,
                begin: 0,
                length: BLOCK_SIZE,
            });
            s.block_map.mark_verified(i);
        }
        assert!(s.is_complete());
        assert!(s.next_block(&HashMap::new()).is_none());
        assert_eq!(s.progress(), 1.0);
    }

    #[test]
    fn invalidating_a_bad_piece_makes_it_available_again() {
        let m = meta(BLOCK_SIZE * 2, 1);
        let mut s = Scheduler::new(&m);
        for b in 0..2 {
            s.on_block(BlockRequest {
                piece: 0,
                block: b,
                begin: (b as u32) * BLOCK_SIZE,
                length: BLOCK_SIZE,
            });
        }
        s.block_map.mark_verified(0);
        assert!(s.is_complete());

        s.block_map.invalidate_piece(0);
        assert!(!s.is_complete());
        assert!(s.next_block(&HashMap::new()).is_some(), "must re-download");
    }

    #[test]
    fn endgame_ignores_rarity() {
        let m = meta(BLOCK_SIZE, 4);
        let mut s = Scheduler::new(&m);
        for i in 0..3u32 {
            s.block_map.mark_verified(i);
        }
        // One piece left, which is at or below the endgame threshold.
        let rarity = HashMap::from([(3u32, 1u32)]);
        let r = s.next_block(&rarity).unwrap();
        assert_eq!(r.piece, 3);
    }

    #[test]
    fn fill_batch_respects_limit() {
        let m = meta(BLOCK_SIZE, 10);
        let mut s = Scheduler::new(&m);
        let batch = s.fill_batch(&HashMap::new(), 4);
        assert_eq!(batch.len(), 4);
        let unique: HashSet<_> = batch.iter().map(|b| b.key()).collect();
        assert_eq!(unique.len(), 4, "batch must not repeat blocks");
    }

    #[test]
    fn progress_tracks_verified_pieces() {
        let m = meta(BLOCK_SIZE, 4);
        let mut s = Scheduler::new(&m);
        assert_eq!(s.progress(), 0.0);
        s.block_map.mark_verified(0);
        s.block_map.mark_verified(1);
        assert!((s.progress() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_ignores_excluded_pieces() {
        let m = meta(BLOCK_SIZE, 4);
        let mut s = Scheduler::new(&m);
        s.set_excluded(&HashSet::from([2, 3]));
        assert_eq!(s.progress(), 0.0);
        s.block_map.mark_verified(0);
        assert!((s.progress() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn excluded_pieces_are_never_scheduled() {
        let m = meta(BLOCK_SIZE, 4);
        let mut s = Scheduler::new(&m);
        s.set_excluded(&HashSet::from([1, 3]));

        let mut seen = HashSet::new();
        let rarity = HashMap::from([(0u32, 1u32), (1, 1), (2, 1), (3, 1)]);
        while let Some(r) = s.next_block(&rarity) {
            seen.insert(r.piece);
            s.on_block(r);
        }
        assert_eq!(seen, HashSet::from([0u32, 2u32]));
        assert!(s.ready_pieces().iter().all(|p| *p == 0 || *p == 2));
    }

    #[test]
    fn completion_ignores_excluded_pieces() {
        let m = meta(BLOCK_SIZE, 3);
        let mut s = Scheduler::new(&m);
        s.set_excluded(&HashSet::from([2]));
        assert!(!s.is_complete());

        for i in [0u32, 1] {
            s.on_block(BlockRequest {
                piece: i,
                block: 0,
                begin: 0,
                length: BLOCK_SIZE,
            });
            s.block_map.mark_verified(i);
        }
        assert!(s.is_complete(), "excluded piece 2 must not block completion");
        assert!((s.progress() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn excluding_a_piece_drops_its_in_flight_blocks() {
        let m = meta(BLOCK_SIZE * 2, 2);
        let mut s = Scheduler::new(&m);
        let r = s.next_block(&HashMap::new()).unwrap();
        assert_eq!(s.in_flight_count(), 1);

        s.set_excluded(&HashSet::from([r.piece]));
        assert_eq!(s.in_flight_count(), 0);
        // ...and the piece is never handed out again.
        let again = s.next_block(&HashMap::new()).unwrap();
        assert_ne!(again.piece, r.piece);
    }

    #[test]
    fn file_downloaded_counts_verified_and_partial_bytes() {
        // 2 pieces of 2 blocks: piece 0 verified, piece 1 half-held.
        let m = meta(BLOCK_SIZE * 2, 2);
        let mut s = Scheduler::new(&m);
        for b in 0..2 {
            s.on_block(BlockRequest {
                piece: 0,
                block: b,
                begin: (b as u32) * BLOCK_SIZE,
                length: BLOCK_SIZE,
            });
        }
        s.block_map.mark_verified(0);
        s.on_block(BlockRequest {
            piece: 1,
            block: 0,
            begin: 0,
            length: BLOCK_SIZE,
        });

        let got = file_downloaded(&m, s.block_map());
        assert_eq!(got.len(), 1, "single-file torrent has one entry");
        assert_eq!(got[0], (BLOCK_SIZE * 3) as u64);
    }

    #[test]
    fn excluded_pieces_respects_straddling_pieces() {
        use crate::metainfo::{Files, InfoHash};
        use std::path::PathBuf;
        // Two 10-byte files, 16-byte pieces: piece 0 spans both files.
        let meta = Metainfo {
            infohash: InfoHash([0; 20]),
            name: "root".into(),
            piece_length: 16,
            pieces: vec![[0u8; 20]; 2],
            files: Files::Multi {
                files: vec![
                    crate::metainfo::FileEntry {
                        path: PathBuf::from("root").join("a"),
                        length: 10,
                    },
                    crate::metainfo::FileEntry {
                        path: PathBuf::from("root").join("b"),
                        length: 10,
                    },
                ],
            },
            total_length: 20,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
        };
        // Skip file 1 (bytes 10..20): piece 1 (bytes 16..20) lies entirely
        // inside it and is excludable; piece 0 (bytes 0..16) straddles the
        // boundary and must stay, because it carries file 0's bytes.
        let excl = excluded_pieces(&meta, &[true, false]);
        assert_eq!(excl, HashSet::from([1u32]));
    }

    #[test]
    fn remaining_bytes_accounts_for_partial_pieces() {
        let m = meta(BLOCK_SIZE * 2, 2); // 2 pieces x 32 KiB = 64 KiB
        let mut s = Scheduler::new(&m);
        assert_eq!(s.remaining_bytes(&m), 4 * BLOCK_SIZE as u64);
        s.on_block(BlockRequest {
            piece: 0,
            block: 0,
            begin: 0,
            length: BLOCK_SIZE,
        });
        assert_eq!(s.remaining_bytes(&m), 3 * BLOCK_SIZE as u64);
    }

    fn multi(piece_len: u32, lengths: &[u64]) -> Metainfo {
        use crate::metainfo::{FileEntry, Files, InfoHash};
        use std::path::PathBuf;
        let total: u64 = lengths.iter().sum();
        Metainfo {
            infohash: InfoHash([0; 20]),
            name: "root".into(),
            piece_length: piece_len,
            pieces: vec![[0u8; 20]; total.div_ceil(piece_len as u64) as usize],
            files: Files::Multi {
                files: lengths
                    .iter()
                    .enumerate()
                    .map(|(i, length)| FileEntry {
                        path: PathBuf::from("root").join(format!("f{i}")),
                        length: *length,
                    })
                    .collect(),
            },
            total_length: total,
            private: false,
            announce: None,
            announce_list: vec![],
            web_seeds: vec![],
        }
    }

    #[test]
    fn priority_band_beats_rarity() {
        let m = multi(BLOCK_SIZE, &[BLOCK_SIZE as u64; 3]);
        let mut s = Scheduler::new(&m);
        s.set_piece_priorities(piece_priorities(
            &m,
            &[FilePriority::Low, FilePriority::Normal, FilePriority::High],
        ));
        let rarity = HashMap::from([(0u32, 1u32), (1, 10), (2, 50)]);
        let order: Vec<u32> = s.fill_batch(&rarity, 3).iter().map(|r| r.piece).collect();
        assert_eq!(order, [2, 1, 0]);
    }

    #[test]
    fn rarest_first_within_a_priority_band() {
        let m = multi(BLOCK_SIZE, &[BLOCK_SIZE as u64; 4]);
        let mut s = Scheduler::new(&m);
        s.set_piece_priorities(piece_priorities(&m, &[FilePriority::High; 4]));
        let rarity = HashMap::from([(0u32, 9u32), (1, 1), (2, 5), (3, 3)]);
        let order: Vec<u32> = s.fill_batch(&rarity, 4).iter().map(|r| r.piece).collect();
        assert_eq!(order, [1, 3, 2, 0]);
    }

    #[test]
    fn skipped_files_are_never_scheduled() {
        let m = multi(BLOCK_SIZE, &[BLOCK_SIZE as u64; 3]);
        let mut s = Scheduler::new(&m);
        s.set_piece_priorities(piece_priorities(
            &m,
            &[FilePriority::Skip, FilePriority::Normal, FilePriority::Skip],
        ));
        let got: Vec<u32> = s.fill_batch(&HashMap::new(), 10).iter().map(|r| r.piece).collect();
        assert_eq!(got, [1]);
        assert_eq!(s.excluded(), &HashSet::from([0u32, 2]));
    }

    #[test]
    fn straddling_piece_takes_the_highest_priority() {
        let m = multi(16, &[10, 10]);
        assert_eq!(
            piece_priorities(&m, &[FilePriority::Skip, FilePriority::Low]),
            [FilePriority::Low, FilePriority::Low]
        );
        assert_eq!(
            piece_priorities(&m, &[FilePriority::Skip, FilePriority::Skip]),
            [FilePriority::Skip, FilePriority::Skip]
        );
        assert_eq!(
            piece_priorities(&m, &[FilePriority::High, FilePriority::Skip]),
            [FilePriority::High, FilePriority::Skip]
        );
    }
}
