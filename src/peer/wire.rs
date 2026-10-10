//! The BitTorrent peer wire protocol (BEP 3).
//!
//! Wire format is length-prefixed: `<4-byte big-endian length><1-byte id><body>`.
//! A length of zero means keep-alive. The handshake (BEP 3) is a special
//! 68-byte fixed message that is not length-prefixed.

use std::io;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Protocol identifier for the original BitTorrent, used in the handshake
/// reserved bytes. Peers that want DHT, extended messages, or the v2 protocol
/// negotiate via the reserved field instead of changing this.
pub const PROTOCOL: [u8; 19] = *b"BitTorrent protocol";
/// A reserved-field flag as `(byte index, bit mask)` within the 8 reserved
/// bytes. Each capability lives in a different byte, so a single integer mask
/// cannot represent them without byte-order mistakes.
pub type ReservedFlag = (usize, u8);

/// BEP 5: the peer runs a DHT node.
pub const RESERVED_DHT: ReservedFlag = (7, 0x01);
/// BEP 10: the peer speaks the extension protocol (needed for `ut_metadata`).
pub const RESERVED_EXTENDED: ReservedFlag = (5, 0x10);
/// BEP 6: the peer supports the Fast extension.
pub const RESERVED_FAST: ReservedFlag = (7, 0x04);

#[derive(Debug, Error)]
pub enum WireError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    #[error("handshake reserved bits do not match: expected {expected:#x}, got {got:#x}")]
    ReservedMismatch { expected: u32, got: u32 },
    #[error("unexpected handshake protocol string")]
    BadProtocolString,
    #[error("message id {0} is not implemented")]
    UnknownMessage(u8),
}

/// One decoded peer wire message. `Extended` covers BEP 10, which is a local
/// sub-protocol multiplexed over the single id byte 20.
#[derive(Debug, Clone)]
pub enum Message {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have { index: u32 },
    Bitfield { bits: Vec<u8> },
    Request { index: u32, begin: u32, length: u32 },
    Cancel { index: u32, begin: u32, length: u32 },
    Port { port: u16 },
    Piece { index: u32, begin: u32, block: Vec<u8> },
    Extended { ext_id: u8, payload: Vec<u8> },
    SuggestPiece { index: u32 },
    HaveAll,
    HaveNone,
    RejectRequest { index: u32, begin: u32, length: u32 },
    AllowedFast { index: u32 },
}

impl Message {
    pub fn is_fast(&self) -> bool {
        matches!(
            self,
            Message::SuggestPiece { .. }
                | Message::HaveAll
                | Message::HaveNone
                | Message::RejectRequest { .. }
                | Message::AllowedFast { .. }
        )
    }
}

/// Azureus-style client prefix: torrust 0.1.0.
const PEER_ID_PREFIX: &[u8; 8] = b"-TU0100-";

/// The one peer id this process uses in every handshake and tracker announce.
pub fn local_peer_id() -> &'static [u8; 20] {
    static ID: std::sync::OnceLock<[u8; 20]> = std::sync::OnceLock::new();
    ID.get_or_init(|| {
        use rand::RngCore;
        let mut id = [0u8; 20];
        id[..8].copy_from_slice(PEER_ID_PREFIX);
        rand::thread_rng().fill_bytes(&mut id[8..]);
        id
    })
}

/// Perform the BEP 3 handshake as the initiating side.
///
/// `infohash` is the 20-byte torrent hash. `dht`, `fast` and `extended` set the
/// reserved bits that advertise our own capabilities.
pub async fn handshake_outgoing<S>(
    stream: &mut S,
    infohash: &[u8; 20],
    dht: bool,
    fast: bool,
    extended: bool,
) -> Result<(), WireError>
where
    S: AsyncWrite + Unpin,
{
    let mut reserved = [0u8; 8];
    for (on, (idx, mask)) in [
        (dht, RESERVED_DHT),
        (fast, RESERVED_FAST),
        (extended, RESERVED_EXTENDED),
    ] {
        if on {
            reserved[idx] |= mask;
        }
    }

    let mut buf = [0u8; 68];
    buf[0] = 19;
    buf[1..20].copy_from_slice(&PROTOCOL);
    buf[20..28].copy_from_slice(&reserved);
    buf[28..48].copy_from_slice(infohash);

    buf[48..68].copy_from_slice(local_peer_id());

    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

/// What a peer's handshake tells us.
#[derive(Debug, Clone, Copy)]
pub struct Handshake {
    pub infohash: [u8; 20],
    /// The peer's 20-byte id, which occupies the last 20 bytes of the
    /// handshake itself.
    pub peer_id: [u8; 20],
    /// The peer's 8 reserved bytes, which advertise optional protocol features.
    pub reserved: [u8; 8],
    /// The connection arrived over uTP. Set by whoever accepted the socket;
    /// the handshake bytes cannot tell.
    pub utp: bool,
    /// The connection is wrapped in MSE. Set like `utp`.
    pub encrypted: bool,
}

impl Handshake {
    pub fn supports_dht(&self) -> bool {
        self.reserved[RESERVED_DHT.0] & RESERVED_DHT.1 != 0
    }

    pub fn supports_extended(&self) -> bool {
        self.reserved[RESERVED_EXTENDED.0] & RESERVED_EXTENDED.1 != 0
    }

    pub fn supports_fast(&self) -> bool {
        self.reserved[RESERVED_FAST.0] & RESERVED_FAST.1 != 0
    }
}

/// Read and validate the peer's handshake.
///
/// The whole exchange is one fixed 68-byte message:
/// `<pstrlen:1><pstr:19><reserved:8><infohash:20><peerid:20>`. The peer id is
/// therefore *part of* the handshake. Reading it as a separate 20-byte message
/// after this would consume the first bytes of the peer's actual message
/// stream (their Bitfield) and desynchronise the connection permanently.
pub async fn handshake_incoming<S>(stream: &mut S) -> Result<Handshake, WireError>
where
    S: AsyncRead + Unpin,
{
    let mut buf = [0u8; 68];
    stream.read_exact(&mut buf).await?;

    if buf[0] != 19 {
        return Err(WireError::BadProtocolString);
    }
    if buf[1..20] != PROTOCOL {
        return Err(WireError::BadProtocolString);
    }

    let mut reserved = [0u8; 8];
    reserved.copy_from_slice(&buf[20..28]);

    let mut infohash = [0u8; 20];
    infohash.copy_from_slice(&buf[28..48]);
    let mut peer_id = [0u8; 20];
    peer_id.copy_from_slice(&buf[48..68]);
    let hs = Handshake {
        infohash,
        peer_id,
        reserved,
        utp: false,
        encrypted: false,
    };
    if !hs.supports_dht() {
        tracing::debug!("peer did not advertise DHT support");
    }
    Ok(hs)
}

/// Read one length-prefixed message from the wire.
pub async fn read_message<S>(stream: &mut S) -> Result<Message, WireError>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    // A clean EOF here means the peer closed the connection, which is normal
    // and not an error worth propagating as a protocol failure.
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(WireError::Protocol("peer closed connection"))
        }
        Err(e) => return Err(e.into()),
    }

    let len = u32::from_be_bytes(len_buf);
    if len == 0 {
        return Ok(Message::KeepAlive);
    }
    if len > 1 << 20 {
        return Err(WireError::Protocol("message length exceeds 1 MiB"));
    }

    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await?;

    let id = body[0];
    let payload = &body[1..];

    let msg = match id {
        0 => Message::Choke,
        1 => Message::Unchoke,
        2 => Message::Interested,
        3 => Message::NotInterested,
        4 => Message::Have {
            index: be32(payload, 0)?,
        },
        5 => Message::Bitfield { bits: payload.to_vec() },
        6 => Message::Request {
            index: be32(payload, 0)?,
            begin: be32(payload, 4)?,
            length: be32(payload, 8)?,
        },
        7 => Message::Piece {
            index: be32(payload, 0)?,
            begin: be32(payload, 4)?,
            block: payload[8..].to_vec(),
        },
        8 => Message::Cancel {
            index: be32(payload, 0)?,
            begin: be32(payload, 4)?,
            length: be32(payload, 8)?,
        },
        9 => {
            let p = payload
                .get(..2)
                .ok_or(WireError::Protocol("short port message"))?;
            Message::Port {
                port: u16::from_be_bytes([p[0], p[1]]),
            }
        }
        0x0D => Message::SuggestPiece {
            index: be32(payload, 0)?,
        },
        0x0E => Message::HaveAll,
        0x0F => Message::HaveNone,
        0x10 => Message::RejectRequest {
            index: be32(payload, 0)?,
            begin: be32(payload, 4)?,
            length: be32(payload, 8)?,
        },
        0x11 => Message::AllowedFast {
            index: be32(payload, 0)?,
        },
        20 => Message::Extended {
            ext_id: *payload.first().ok_or(WireError::Protocol("empty extended message"))?,
            payload: payload.get(1..).unwrap_or(&[]).to_vec(),
        },
        other => return Err(WireError::UnknownMessage(other)),
    };
    Ok(msg)
}

fn be32(b: &[u8], off: usize) -> Result<u32, WireError> {
    let s = b
        .get(off..off + 4)
        .ok_or(WireError::Protocol("message payload too short"))?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Serialize a message to its wire representation (excluding the length prefix).
pub fn encode(msg: &Message) -> Vec<u8> {
    match msg {
        Message::KeepAlive => Vec::new(),
        Message::Choke => vec![0],
        Message::Unchoke => vec![1],
        Message::Interested => vec![2],
        Message::NotInterested => vec![3],
        Message::Have { index } => {
            let mut v = vec![4];
            v.extend_from_slice(&index.to_be_bytes());
            v
        }
        Message::Bitfield { bits } => {
            let mut v = vec![5];
            v.extend_from_slice(bits);
            v
        }
        Message::Request {
            index,
            begin,
            length,
        } => {
            let mut v = vec![6];
            v.extend_from_slice(&index.to_be_bytes());
            v.extend_from_slice(&begin.to_be_bytes());
            v.extend_from_slice(&length.to_be_bytes());
            v
        }
        Message::Cancel {
            index,
            begin,
            length,
        } => {
            let mut v = vec![8];
            v.extend_from_slice(&index.to_be_bytes());
            v.extend_from_slice(&begin.to_be_bytes());
            v.extend_from_slice(&length.to_be_bytes());
            v
        }
        Message::Port { port } => {
            let mut v = vec![9];
            v.extend_from_slice(&port.to_be_bytes());
            v
        }
        Message::Piece {
            index,
            begin,
            block,
        } => {
            let mut v = vec![7];
            v.extend_from_slice(&index.to_be_bytes());
            v.extend_from_slice(&begin.to_be_bytes());
            v.extend_from_slice(block);
            v
        }
        Message::Extended { ext_id, payload } => {
            let mut v = vec![20];
            v.push(*ext_id);
            v.extend_from_slice(payload);
            v
        }
        Message::SuggestPiece { index } => {
            let mut v = vec![0x0D];
            v.extend_from_slice(&index.to_be_bytes());
            v
        }
        Message::HaveAll => vec![0x0E],
        Message::HaveNone => vec![0x0F],
        Message::RejectRequest {
            index,
            begin,
            length,
        } => {
            let mut v = vec![0x10];
            v.extend_from_slice(&index.to_be_bytes());
            v.extend_from_slice(&begin.to_be_bytes());
            v.extend_from_slice(&length.to_be_bytes());
            v
        }
        Message::AllowedFast { index } => {
            let mut v = vec![0x11];
            v.extend_from_slice(&index.to_be_bytes());
            v
        }
    }
}

/// Wrap an encoded message with its 4-byte big-endian length prefix.
pub fn encode_framed(msg: &Message) -> Vec<u8> {
    let body = encode(msg);
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// A peer's advertised piece availability.
#[derive(Debug, Clone, Default)]
pub struct Bitfield {
    bits: Vec<u8>,
}

impl Bitfield {
    /// Build from a wire bitfield payload. Bits beyond `piece_count` are dropped,
    /// since a malicious peer may claim more pieces than the torrent has.
    pub fn from_wire(bytes: &[u8], piece_count: usize) -> Self {
        let mut bits = bytes.to_vec();
        let needed = piece_count.div_ceil(8);
        bits.resize(needed.max(1), 0);
        let mut bf = Bitfield { bits };
        bf.clear_bits_from(piece_count);
        bf
    }

    pub fn with_pieces(piece_count: usize) -> Self {
        let mut bf = Bitfield {
            bits: vec![0u8; piece_count.div_ceil(8).max(1)],
        };
        bf.clear_bits_from(piece_count);
        bf
    }

    pub fn all(piece_count: usize) -> Self {
        let mut bf = Self::with_pieces(piece_count);
        for i in 0..piece_count as u32 {
            bf.set(i);
        }
        bf
    }

    pub fn set(&mut self, index: u32) {
        let i = index as usize;
        if i / 8 < self.bits.len() {
            self.bits[i / 8] |= 1 << (7 - (i % 8));
        }
    }

    pub fn clear(&mut self, index: u32) {
        let i = index as usize;
        if i / 8 < self.bits.len() {
            self.bits[i / 8] &= !(1 << (7 - (i % 8)));
        }
    }

    fn clear_bits_from(&mut self, piece_count: usize) {
        for i in piece_count..self.bits.len() * 8 {
            self.clear(i as u32);
        }
    }

    pub fn has(&self, index: u32) -> bool {
        let i = index as usize;
        if i / 8 >= self.bits.len() {
            return false;
        }
        self.bits[i / 8] & (1 << (7 - (i % 8))) != 0
    }

    pub fn len(&self) -> usize {
        self.bits.len() * 8
    }

    pub fn count(&self) -> u32 {
        self.bits
            .iter()
            .map(|b| b.count_ones())
            .sum::<u32>()
    }

    pub fn full(&self, piece_count: usize) -> bool {
        (0..piece_count as u32).all(|i| self.has(i))
    }

    /// Bitwise OR, used to merge a peer's bitfield into our own view when we
    /// decide what to seed.
    pub fn union(&mut self, other: &Bitfield) {
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a |= *b;
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip_all_types() {
        let cases = vec![
            Message::KeepAlive,
            Message::Choke,
            Message::Unchoke,
            Message::Interested,
            Message::NotInterested,
            Message::Have { index: 7 },
            Message::Bitfield {
                bits: vec![0b1010_0000],
            },
            Message::Request {
                index: 3,
                begin: 16384,
                length: 16384,
            },
            Message::Cancel {
                index: 1,
                begin: 0,
                length: 512,
            },
            Message::Port { port: 6881 },
            Message::Piece {
                index: 2,
                begin: 128,
                block: vec![9, 8, 7],
            },
            Message::Extended {
                ext_id: 0,
                payload: vec![1, 2],
            },
        ];
        for c in cases {
            let framed = encode_framed(&c);
            let len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
            assert_eq!(len + 4, framed.len(), "length prefix must match body");
            assert_eq!(encode(&c), &framed[4..]);
        }
    }

    #[tokio::test]
    async fn fast_messages_round_trip_through_the_decoder() {
        let cases = vec![
            Message::SuggestPiece { index: 4 },
            Message::HaveAll,
            Message::HaveNone,
            Message::RejectRequest { index: 1, begin: 16384, length: 16384 },
            Message::AllowedFast { index: 9 },
        ];
        for c in cases {
            assert!(c.is_fast());
            let framed = encode_framed(&c);
            let got = read_message(&mut framed.as_slice()).await.unwrap();
            assert_eq!(encode(&got), encode(&c));
        }
        assert!(!Message::Have { index: 1 }.is_fast());
        assert!(read_message(&mut [0u8, 0, 0, 1, 0x10].as_slice()).await.is_err());
    }

    #[test]
    fn keepalive_is_zero_length() {
        assert_eq!(encode_framed(&Message::KeepAlive), vec![0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn bitfield_message_round_trips_through_the_decoder() {
        // 3 pieces set in a single byte; the remaining 5 bits are padding.
        let framed = encode_framed(&Message::Bitfield {
            bits: vec![0b1110_0000],
        });
        let mut input = framed.as_slice();
        match read_message(&mut input).await.unwrap() {
            Message::Bitfield { bits } => {
                assert_eq!(bits, vec![0b1110_0000], "payload must be delivered as sent, unpadded");
            }
            other => panic!("expected Bitfield, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn truncated_message_is_an_error_not_a_panic() {
        // A peer that sends a length prefix and then disconnects must produce
        // an error, never a panic.
        let mut input: &[u8] = &[0, 0, 0, 16, 4, 0, 0]; // claims 16 bytes, sends 3
        assert!(read_message(&mut input).await.is_err());
    }

    #[tokio::test]
    async fn oversized_message_length_is_rejected() {
        // Claim more than the 1 MiB cap so we never try to allocate it.
        let mut input: &[u8] = &[0xff, 0xff, 0xff, 0xff];
        match read_message(&mut input).await {
            Err(WireError::Protocol(msg)) => assert!(msg.contains("1 MiB")),
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_message_id_is_reported() {
        let framed = encode_framed(&Message::Have { index: 1 });
        let mut bad = framed.clone();
        bad[4] = 200; // no such message id
        let mut input = bad.as_slice();
        match read_message(&mut input).await {
            Err(WireError::UnknownMessage(id)) => assert_eq!(id, 200),
            other => panic!("expected UnknownMessage, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn short_port_message_is_rejected() {
        let mut framed = encode_framed(&Message::Port { port: 1 });
        framed.truncate(5); // length says 2-byte body, but id only
        let mut input = framed.as_slice();
        assert!(read_message(&mut input).await.is_err());
    }

    #[test]
    fn bitfield_set_get() {
        let mut bf = Bitfield::with_pieces(20);
        assert!(!bf.has(0));
        bf.set(0);
        bf.set(7);
        bf.set(8);
        bf.set(19);
        assert!(bf.has(0) && bf.has(7) && bf.has(8) && bf.has(19));
        assert!(!bf.has(1));
        assert_eq!(bf.count(), 4);
    }

    #[test]
    fn bitfield_ignores_out_of_range_set() {
        let mut bf = Bitfield::with_pieces(8);
        bf.set(9999);
        assert_eq!(bf.count(), 0);
    }

    #[test]
    fn bitfield_from_wire_drops_extra_bits() {
        // A peer claiming all 64 bits of a 20-piece torrent must not register
        // pieces we don't have.
        let bf = Bitfield::from_wire(&[0xff; 8], 20);
        assert_eq!(bf.count(), 20);
        assert!(!bf.has(20));
        assert!(!bf.has(63));
    }

    #[test]
    fn bitfield_full_detection() {
        let mut bf = Bitfield::with_pieces(10);
        for i in 0..9 {
            bf.set(i);
        }
        assert!(!bf.full(10));
        bf.set(9);
        assert!(bf.full(10));
    }

    #[test]
    fn bitfield_union() {
        let mut a = Bitfield::with_pieces(16);
        a.set(1);
        let mut b = Bitfield::with_pieces(16);
        b.set(2);
        a.union(&b);
        assert!(a.has(1) && a.has(2));
    }

    #[test]
    fn reserved_bits_have_dht_bit() {
        assert_eq!(RESERVED_DHT, (7, 0x01));
        assert_eq!(RESERVED_EXTENDED, (5, 0x10));
        assert_eq!(RESERVED_FAST, (7, 0x04));
    }

    #[tokio::test]
    async fn handshake_reserved_bytes_round_trip() {
        let ih = [9u8; 20];
        let mut buf = Vec::new();
        handshake_outgoing(&mut buf, &ih, true, false, true)
            .await
            .unwrap();
        assert_eq!(buf.len(), 68);
        assert_eq!(buf[20..28], [0, 0, 0, 0, 0, 0x10, 0, 0x01]);
        let hs = handshake_incoming(&mut buf.as_slice()).await.unwrap();
        assert!(hs.supports_dht() && hs.supports_extended());
        assert_eq!(hs.infohash, ih);

        let mut plain = Vec::new();
        handshake_outgoing(&mut plain, &ih, false, true, false)
            .await
            .unwrap();
        assert_eq!(plain[20..28], [0, 0, 0, 0, 0, 0, 0, 0x04]);
        let hs = handshake_incoming(&mut plain.as_slice()).await.unwrap();
        assert!(!hs.supports_dht() && !hs.supports_extended());
    }

    #[tokio::test]
    async fn every_handshake_carries_the_same_prefixed_peer_id() {
        let mut ids = Vec::new();
        for _ in 0..3 {
            let mut buf = Vec::new();
            handshake_outgoing(&mut buf, &[1; 20], true, true, true).await.unwrap();
            ids.push(handshake_incoming(&mut buf.as_slice()).await.unwrap().peer_id);
        }
        assert!(ids.iter().all(|i| *i == ids[0]));
        assert_eq!(ids[0], *local_peer_id());
        assert_eq!(&ids[0][..8], b"-TU0100-");
    }

    #[test]
    fn handshake_bytes_are_correct_length() {
        assert_eq!(PROTOCOL.len(), 19);
        assert_eq!(1 + 19 + 4 + 8 + 20, 52);
        // Full handshake is 19 + 49 = 68 bytes.
        assert_eq!(19 + 49, 68);
    }
}