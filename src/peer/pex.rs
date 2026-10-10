//! Peer exchange (BEP 11) over the BEP 10 extension protocol.
//!
//! Everything here is parsed from untrusted peers: lists are bounded, wrong
//! types read as absent, and nothing panics.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::bencode::{self, Value};

/// The extended-message id we ask peers to use for `ut_pex` messages to us.
pub const OUR_PEX_ID: u8 = 1;

/// The extended-message id we ask peers to use for `ut_metadata` requests to
/// us (BEP 9). Distinct from [`OUR_PEX_ID`].
pub const OUR_METADATA_ID: u8 = 2;

/// BEP 9 metadata piece size.
pub const METADATA_PIECE: usize = 16 * 1024;

/// Metadata requests answered per peer per minute; more get a reject.
pub const METADATA_MAX_PER_MINUTE: u32 = 64;

/// Most addresses we will take from one incoming message, per list. Real
/// clients send at most 50 per direction; this leaves slack without letting a
/// peer make us dial thousands of addresses.
pub const MAX_RECEIVED: usize = 200;

/// Most addresses we put in one outgoing list, so a message stays small.
pub const MAX_SENT: usize = 50;

/// Messages arriving faster than this are dropped. The spec allows one per
/// minute; the margin absorbs timer jitter on the sender.
pub const MIN_RECEIVE_GAP: std::time::Duration = std::time::Duration::from_secs(45);

/// How often the pool sends PEX messages to each peer.
pub const SEND_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// What a peer's BEP 10 handshake tells us that we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExtHandshake {
    /// The id the peer wants `ut_pex` messages sent under; `None` when it does
    /// not support PEX or disabled it (id 0).
    pub pex_id: Option<u8>,
    /// The peer's listen port, which is the only way to learn it for an
    /// inbound connection (its source port is ephemeral).
    pub port: Option<u16>,
    /// The id the peer wants `ut_metadata` replies sent under.
    pub metadata_id: Option<u8>,
}

/// Our extended handshake. `port` is our listen port; 0 omits it. A
/// `metadata_size` advertises that we serve `ut_metadata` (BEP 9).
pub fn encode_handshake(port: u16, metadata_size: Option<usize>) -> Vec<u8> {
    let mut m = BTreeMap::new();
    m.insert(b"ut_pex".to_vec(), Value::Int(OUR_PEX_ID as i64));
    let mut d = BTreeMap::new();
    if let Some(size) = metadata_size {
        m.insert(b"ut_metadata".to_vec(), Value::Int(OUR_METADATA_ID as i64));
        d.insert(b"metadata_size".to_vec(), Value::Int(size as i64));
    }
    d.insert(b"m".to_vec(), Value::Dict(m));
    if port != 0 {
        d.insert(b"p".to_vec(), Value::Int(port as i64));
    }
    d.insert(b"reqq".to_vec(), Value::Int(250));
    d.insert(b"v".to_vec(), Value::Bytes(b"torrust".to_vec()));
    bencode::encode(&Value::Dict(d))
}

pub fn decode_handshake(payload: &[u8]) -> Option<ExtHandshake> {
    let v = bencode::decode(payload).ok()?;
    let pex_id = v
        .get_opt("m")
        .and_then(|m| m.get_int_opt("ut_pex"))
        .and_then(|i| u8::try_from(i).ok())
        .filter(|&i| i != 0);
    let port = v
        .get_int_opt("p")
        .and_then(|p| u16::try_from(p).ok())
        .filter(|&p| p != 0);
    let metadata_id = v
        .get_opt("m")
        .and_then(|m| m.get_int_opt("ut_metadata"))
        .and_then(|i| u8::try_from(i).ok())
        .filter(|&i| i != 0);
    Some(ExtHandshake {
        pex_id,
        port,
        metadata_id,
    })
}

/// The piece a `ut_metadata` request asks for, or `None` for any other
/// message type or malformed input.
pub fn metadata_request(payload: &[u8]) -> Option<u32> {
    let (v, _) = bencode::decode_partial(payload).ok()?;
    if v.get_int_opt("msg_type")? != 0 {
        return None;
    }
    u32::try_from(v.get_int_opt("piece")?).ok()
}

/// Answer a request for `piece` of the raw `info` dict: a data message for a
/// piece in range, a reject otherwise.
pub fn metadata_reply(info: &[u8], piece: u32) -> Vec<u8> {
    let start = piece as usize * METADATA_PIECE;
    let mut d = BTreeMap::new();
    d.insert(b"piece".to_vec(), Value::Int(piece as i64));
    if start >= info.len() {
        d.insert(b"msg_type".to_vec(), Value::Int(2));
        return bencode::encode(&Value::Dict(d));
    }
    d.insert(b"msg_type".to_vec(), Value::Int(1));
    d.insert(b"total_size".to_vec(), Value::Int(info.len() as i64));
    let mut out = bencode::encode(&Value::Dict(d));
    out.extend_from_slice(&info[start..(start + METADATA_PIECE).min(info.len())]);
    out
}

/// A decoded `ut_pex` message, already filtered to dialable addresses.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pex {
    pub added: Vec<SocketAddr>,
    pub dropped: Vec<SocketAddr>,
}

/// Port 0, unspecified and multicast addresses are never worth dialing.
fn dialable(a: &SocketAddr) -> bool {
    a.port() != 0 && !a.ip().is_unspecified() && !a.ip().is_multicast()
}

fn compact_v4(buf: &[u8], out: &mut Vec<SocketAddr>) {
    for c in buf.chunks_exact(6) {
        if out.len() >= MAX_RECEIVED {
            return;
        }
        let ip = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
        let a = SocketAddr::new(IpAddr::V4(ip), u16::from_be_bytes([c[4], c[5]]));
        if dialable(&a) {
            out.push(a);
        }
    }
}

fn compact_v6(buf: &[u8], out: &mut Vec<SocketAddr>) {
    for c in buf.chunks_exact(18) {
        if out.len() >= MAX_RECEIVED {
            return;
        }
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&c[..16]);
        let a = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(ip)),
            u16::from_be_bytes([c[16], c[17]]),
        );
        if dialable(&a) {
            out.push(a);
        }
    }
}

fn list(v: &Value, key4: &str, key6: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    if let Some(b) = v.get_bytes_opt(key4) {
        compact_v4(b, &mut out);
    }
    if let Some(b) = v.get_bytes_opt(key6) {
        compact_v6(b, &mut out);
    }
    out
}

/// Decode a `ut_pex` payload. Malformed input yields an empty message; a
/// trailing partial compact entry is ignored.
pub fn decode(payload: &[u8]) -> Pex {
    let Ok(v) = bencode::decode(payload) else {
        return Pex::default();
    };
    Pex {
        added: list(&v, "added", "added6"),
        dropped: list(&v, "dropped", "dropped6"),
    }
}

fn compact(addrs: &[SocketAddr]) -> (Vec<u8>, Vec<u8>) {
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for a in addrs.iter().take(MAX_SENT) {
        match a.ip() {
            IpAddr::V4(ip) => {
                v4.extend_from_slice(&ip.octets());
                v4.extend_from_slice(&a.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                v6.extend_from_slice(&ip.octets());
                v6.extend_from_slice(&a.port().to_be_bytes());
            }
        }
    }
    (v4, v6)
}

/// Encode a `ut_pex` payload, splitting IPv4 and IPv6 into their own keys.
pub fn encode(added: &[SocketAddr], dropped: &[SocketAddr]) -> Vec<u8> {
    let mut d = BTreeMap::new();
    for (list, k4, k6) in [(added, "added", "added6"), (dropped, "dropped", "dropped6")] {
        let (v4, v6) = compact(list);
        if !v4.is_empty() {
            d.insert(k4.as_bytes().to_vec(), Value::Bytes(v4));
        }
        if !v6.is_empty() {
            d.insert(k6.as_bytes().to_vec(), Value::Bytes(v6));
        }
    }
    bencode::encode(&Value::Dict(d))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn pex_round_trips_v4_v6_and_dropped() {
        let added = [sa("1.2.3.4:6881"), sa("[2001:db8::1]:51413"), sa("5.6.7.8:80")];
        let dropped = [sa("9.9.9.9:1"), sa("[2001:db8::2]:2")];
        let p = decode(&encode(&added, &dropped));
        assert_eq!(p.added, vec![added[0], added[2], added[1]]);
        assert_eq!(p.dropped, vec![dropped[0], dropped[1]]);
    }

    #[test]
    fn decode_filters_undialable_addresses() {
        let mut v4 = Vec::new();
        for (ip, port) in [([0, 0, 0, 0], 80u16), ([1, 1, 1, 1], 0), ([224, 0, 0, 1], 80), ([8, 8, 8, 8], 53)] {
            v4.extend_from_slice(&ip);
            v4.extend_from_slice(&port.to_be_bytes());
        }
        let mut d = BTreeMap::new();
        d.insert(b"added".to_vec(), Value::Bytes(v4));
        let p = decode(&bencode::encode(&Value::Dict(d)));
        assert_eq!(p.added, vec![sa("8.8.8.8:53")]);
    }

    #[test]
    fn decode_survives_hostile_input() {
        assert_eq!(decode(b""), Pex::default());
        assert_eq!(decode(b"garbage"), Pex::default());
        assert_eq!(decode(b"i5e"), Pex::default());
        assert_eq!(decode(b"d5:addedi3ee"), Pex::default());
        assert_eq!(decode(b"d5:addedl1:aee"), Pex::default());

        let mut d = BTreeMap::new();
        d.insert(b"added".to_vec(), Value::Bytes(vec![1, 2, 3, 4, 0x1a, 0xe1, 9, 9, 9]));
        d.insert(b"added6".to_vec(), Value::Bytes(vec![1; 17]));
        let p = decode(&bencode::encode(&Value::Dict(d)));
        assert_eq!(p.added, vec![sa("1.2.3.4:6881")]);

        let mut big = Vec::new();
        for i in 0..5000u32 {
            big.extend_from_slice(&[10, 0, (i >> 8) as u8, i as u8, 0x1a, 0xe1]);
        }
        let mut d = BTreeMap::new();
        d.insert(b"added".to_vec(), Value::Bytes(big.clone()));
        d.insert(b"dropped".to_vec(), Value::Bytes(big));
        let p = decode(&bencode::encode(&Value::Dict(d)));
        assert_eq!(p.added.len(), MAX_RECEIVED);
        assert_eq!(p.dropped.len(), MAX_RECEIVED);
    }

    #[test]
    fn encode_caps_outgoing_lists() {
        let many: Vec<SocketAddr> = (0..200u16).map(|i| sa(&format!("10.0.0.{}:{}", i % 250, 1000 + i))).collect();
        assert_eq!(decode(&encode(&many, &many)).added.len(), MAX_SENT);
    }

    #[test]
    fn handshake_round_trips_with_pex_and_port() {
        let hs = decode_handshake(&encode_handshake(51413, None)).unwrap();
        assert_eq!(
            hs,
            ExtHandshake { pex_id: Some(OUR_PEX_ID), port: Some(51413), metadata_id: None }
        );
        let hs = decode_handshake(&encode_handshake(0, Some(40_000))).unwrap();
        assert_eq!(hs.port, None);
        assert_eq!(hs.metadata_id, Some(OUR_METADATA_ID));
    }

    #[test]
    fn metadata_replies_cover_data_and_out_of_range() {
        let info: Vec<u8> = (0..METADATA_PIECE + 100).map(|i| i as u8).collect();
        let req = |p: i64| {
            let mut d = BTreeMap::new();
            d.insert(b"msg_type".to_vec(), Value::Int(0));
            d.insert(b"piece".to_vec(), Value::Int(p));
            bencode::encode(&Value::Dict(d))
        };
        assert_eq!(metadata_request(&req(1)), Some(1));
        assert_eq!(metadata_request(&req(-1)), None);
        assert_eq!(metadata_request(b"junk"), None);
        let data = metadata_reply(&info, 1);
        let (v, rest) = bencode::decode_partial(&data).unwrap();
        assert_eq!(v.get_int_opt("msg_type"), Some(1));
        assert_eq!(v.get_int_opt("total_size"), Some(info.len() as i64));
        assert_eq!(rest, &info[METADATA_PIECE..]);
        let reject = metadata_reply(&info, 2);
        let (v, rest) = bencode::decode_partial(&reject).unwrap();
        assert_eq!(v.get_int_opt("msg_type"), Some(2));
        assert!(rest.is_empty());
    }

    #[test]
    fn handshake_decode_is_defensive() {
        assert!(decode_handshake(b"nope").is_none());
        assert_eq!(decode_handshake(b"d1:pi0ee").unwrap(), ExtHandshake::default());
        assert_eq!(decode_handshake(b"d1:pi70000ee").unwrap().port, None);
        assert_eq!(decode_handshake(b"d1:md6:ut_pexi0eee").unwrap().pex_id, None);
        assert_eq!(decode_handshake(b"d1:md6:ut_pexi300eee").unwrap().pex_id, None);
        assert_eq!(decode_handshake(b"d1:m3:abce").unwrap().pex_id, None);
        assert_eq!(decode_handshake(b"d1:md6:ut_pexi9eee").unwrap().pex_id, Some(9));
    }
}
