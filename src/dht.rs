//! Kademlia DHT node (BEP 5) plus BEP 9 `ut_metadata` exchange (BEP 10 handshake).
//!
//! Two things live here:
//!
//! 1. A minimal but real Kademlia node: an ephemeral UDP socket, a read loop, an
//!    XOR-bucketed routing table and a pending-transaction table keyed by the
//!    2-byte KRPC transaction id. It answers `ping`, `find_node`, `get_peers`
//!    and `announce_peer`, which is enough to bootstrap and to look up peers for
//!    a torrent we have no trackers for.
//! 2. `ut_metadata` (BEP 9) over the BitTorrent extended protocol (BEP 10),
//!    which is how the raw bencoded `info` dict of a magnet link is fetched and
//!    then checked against the infohash we were given.
//!
//! Everything that arrives from the network is treated as hostile: malformed
//! KRPC produces `Err(DhtError::Protocol(..))` rather than a panic. All slice
//! indexing, conversions and length arithmetic on peer-supplied data is
//! checked.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use futures::future::join_all;
use futures::stream::{FuturesUnordered, StreamExt};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::oneshot;

use crate::bencode::{self, Value};
use crate::metainfo::InfoHash;
use crate::state::EncryptionMode;
use crate::peer::wire::{self, Message, WireError};
use crate::storage::sha1_bytes;

// ---------------------------------------------------------------- constants

/// The extended-protocol extension name for BEP 9 metadata exchange.
pub const UT_METADATA: &str = "ut_metadata";

/// `ut_metadata` splits the metadata into pieces of this size.
pub const UT_METADATA_PIECE_SIZE: usize = 16 * 1024;

/// Prefix byte of a BEP 9 request message (`{msg_type: 0, piece: N}`).
pub const UT_MSG_REQUEST: u8 = 0;
/// Prefix byte of a BEP 9 data message (`{msg_type: 1, piece, total_size, data}`).
pub const UT_MSG_DATA: u8 = 1;
/// Prefix byte of a BEP 9 reject message (`{msg_type: 2, piece}`).
pub const UT_MSG_REJECT: u8 = 2;

/// Receive buffer size for a UDP datagram.
pub const MAX_UDP_PAYLOAD: usize = 4096;
/// Largest KRPC message we are willing to put on the wire (BEP 5 says 2048).
pub const MAX_MESSAGE_LEN: usize = 2048;
/// Kademlia `k`: bucket size and the number of closest nodes to ask.
pub const K: usize = 8;
/// Longest announce token we will store or echo.
const MAX_TOKEN_LEN: usize = 64;
/// A contact heard from within this window is "good" (BEP 5).
const FRESH_FOR: Duration = Duration::from_secs(15 * 60);
/// Unanswered queries after which a contact is "bad" and may be replaced.
const BAD_FAILURES: u32 = 2;
/// How often the token secret rotates; the previous one is still accepted.
const SECRET_ROTATION: Duration = Duration::from_secs(5 * 60);

/// How long a single query waits for its matching response.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Ceiling on the total metadata size we will accept from a peer.
pub const MAX_METADATA_SIZE: usize = 4 * 1024 * 1024;
/// Largest bencoded message accepted from a peer during metadata exchange.
const MAX_EXT_MESSAGE_LEN: usize = 2 * 1024 * 1024;

/// Upper bound on the rounds of one iterative lookup; it usually stops
/// earlier, once no unasked node is left.
const LOOKUP_ROUNDS: usize = 8;

/// Public DHT routers, used when the caller has none configured.
pub const DEFAULT_ROUTERS: &[&str] = &[
    "router.bittorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "router.utorrent.com:6881",
    "dht.libtorrent.org:25401",
    "dht.aelitis.com:6881",
];

// ------------------------------------------------------------------- errors

#[derive(Debug, Error)]
pub enum DhtError {
    #[error("bencode error: {0}")]
    Bencode(#[from] bencode::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("dht node timed out")]
    Timeout,

    #[error("dht node is shut down")]
    Shutdown,

    #[error("malformed dht message: {0}")]
    Protocol(String),

    #[error("remote node {peer} replied with error {code}: {message}")]
    Remote {
        peer: String,
        code: i64,
        message: String,
    },

    #[error("invalid node address: {0}")]
    InvalidAddress(String),

    #[error("peer wire error: {0}")]
    Wire(#[from] WireError),

    #[error("peer does not support ut_metadata")]
    Unsupported,

    #[error("metadata exchange failed: {0}")]
    Metadata(String),

    #[error("infohash mismatch: wanted {expected}, peer sent {actual}")]
    InfoHashMismatch {
        expected: InfoHash,
        actual: InfoHash,
    },
}

pub type Result<T> = std::result::Result<T, DhtError>;

// ---------------------------------------------------------------- node info

/// A Kademlia node identifier: 20 opaque random bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub [u8; 20]);

impl NodeId {
    /// A fresh random id.
    pub fn random() -> Self {
        let mut id = [0u8; 20];
        rand::Rng::fill(&mut rand::thread_rng(), &mut id);
        // An all-zero id is the "unknown node" placeholder; never hand it out.
        if id.iter().all(|b| *b == 0) {
            id[19] = 1;
        }
        NodeId(id)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let arr: [u8; 20] = b.try_into().map_err(|_| {
            DhtError::Protocol(format!("node id must be 20 bytes, got {}", b.len()))
        })?;
        Ok(NodeId(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// XOR distance to another id. Symmetric, and zero only for identical ids.
    pub fn distance(&self, other: &NodeId) -> [u8; 20] {
        distance(&self.0, &other.0)
    }
}

/// XOR distance between two ids, interpreted big-endian.
pub fn distance(a: &[u8; 20], b: &[u8; 20]) -> [u8; 20] {
    let mut out = [0u8; 20];
    for (o, (x, y)) in out.iter_mut().zip(a.iter().zip(b.iter())) {
        *o = *x ^ *y;
    }
    out
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// The many shapes a Kademlia node reference takes on the wire and on command
/// lines: a hex node id, a compact IPv4 address, or a compact IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Info {
    /// A 20-byte node id (40 hex chars).
    Id20([u8; 20]),
    /// 4-byte IPv4 address + 2-byte port (12 hex chars).
    Compact([u8; 6]),
    /// 16-byte IPv6 address + 2-byte port (36 hex chars).
    Compact6([u8; 18]),
}

impl Info {
    /// The socket address this reference points at, when it carries one.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Info::Id20(_) => None,
            Info::Compact(b) => socket_from_compact(b).ok(),
            Info::Compact6(b) => socket_from_compact6(b).ok(),
        }
    }

    pub fn to_hex(&self) -> String {
        match self {
            Info::Id20(b) => hex::encode(b),
            Info::Compact(b) => hex::encode(b),
            Info::Compact6(b) => hex::encode(b),
        }
    }
}

impl FromStr for Info {
    type Err = DhtError;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(DhtError::InvalidAddress("empty node reference".into()));
        }
        // Tolerate a "0x" prefix on hex node ids.
        let hexpart = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);

        match hexpart.len() {
            40 => {
                let bytes =
                    hex::decode(hexpart).map_err(|_| DhtError::InvalidAddress(s.to_owned()))?;
                let arr: [u8; 20] = bytes
                    .try_into()
                    .map_err(|_| DhtError::InvalidAddress("node id must be 20 bytes".into()))?;
                Ok(Info::Id20(arr))
            }
            12 => {
                let bytes =
                    hex::decode(hexpart).map_err(|_| DhtError::InvalidAddress(s.to_owned()))?;
                let arr: [u8; 6] = bytes
                    .try_into()
                    .map_err(|_| DhtError::InvalidAddress("compact addr must be 6 bytes".into()))?;
                let port = u16::from_be_bytes([arr[4], arr[5]]);
                if port == 0 {
                    return Err(DhtError::InvalidAddress(format!(
                        "compact address {hexpart} has port 0"
                    )));
                }
                Ok(Info::Compact(arr))
            }
            36 => {
                let bytes =
                    hex::decode(hexpart).map_err(|_| DhtError::InvalidAddress(s.to_owned()))?;
                let arr: [u8; 18] = bytes.try_into().map_err(|_| {
                    DhtError::InvalidAddress("compact IPv6 addr must be 18 bytes".into())
                })?;
                let port = u16::from_be_bytes([arr[16], arr[17]]);
                if port == 0 {
                    return Err(DhtError::InvalidAddress(format!(
                        "compact address {hexpart} has port 0"
                    )));
                }
                Ok(Info::Compact6(arr))
            }
            n => Err(DhtError::InvalidAddress(format!(
                "node reference has {n} hex chars; expected 12, 36 or 40"
            ))),
        }
    }
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Compact (6-byte) form of an IPv4 socket address.
pub fn socket_to_compact(addr: SocketAddr) -> Option<[u8; 6]> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut out = [0u8; 6];
            out[..4].copy_from_slice(&v4.ip().octets());
            out[4..].copy_from_slice(&v4.port().to_be_bytes());
            Some(out)
        }
        SocketAddr::V6(_) => None,
    }
}

/// Compact (18-byte) form of an IPv6 socket address.
pub fn socket_to_compact6(addr: SocketAddr) -> Option<[u8; 18]> {
    match addr {
        SocketAddr::V6(v6) => {
            let mut out = [0u8; 18];
            out[..16].copy_from_slice(&v6.ip().octets());
            out[16..].copy_from_slice(&v6.port().to_be_bytes());
            Some(out)
        }
        SocketAddr::V4(_) => None,
    }
}

fn socket_from_compact(b: &[u8]) -> Result<SocketAddr> {
    let s: [u8; 6] = b
        .try_into()
        .map_err(|_| DhtError::InvalidAddress("compact IPv4 address must be 6 bytes".into()))?;
    let ip = [s[0], s[1], s[2], s[3]];
    let port = u16::from_be_bytes([s[4], s[5]]);
    if port == 0 {
        return Err(DhtError::InvalidAddress(
            "compact address has port 0".into(),
        ));
    }
    Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
}

fn socket_from_compact6(b: &[u8]) -> Result<SocketAddr> {
    let s: [u8; 18] = b
        .try_into()
        .map_err(|_| DhtError::InvalidAddress("compact IPv6 address must be 18 bytes".into()))?;
    let ip: [u8; 16] = s[..16]
        .try_into()
        .map_err(|_| DhtError::InvalidAddress("bad IPv6 address".into()))?;
    let port = u16::from_be_bytes([s[16], s[17]]);
    if port == 0 {
        return Err(DhtError::InvalidAddress(
            "compact address has port 0".into(),
        ));
    }
    Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
}

/// One node in a `find_node` / `get_peers` response: 20-byte id plus a compact
/// address, i.e. BEP 5's 26-byte compact node info.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BencodedNode {
    pub id: NodeId,
    pub addr: SocketAddr,
}

impl BencodedNode {
    /// The 26-byte wire form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(26);
        out.extend_from_slice(id20_as_compact(&self.id).as_slice());
        if let Some(c) = socket_to_compact(self.addr) {
            out.extend_from_slice(&c);
        } else if let Some(c6) = socket_to_compact6(self.addr) {
            // IPv6 is not expressible in 26 bytes; keep the IPv6 address out and
            // leave the trailing bytes zeroed so we never emit a bogus node.
            out.truncate(20);
            let _ = c6;
        } else {
            out.extend_from_slice(&[0u8; 6]);
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let s: [u8; 26] = b.try_into().map_err(|_| {
            DhtError::Protocol(format!("compact node must be 26 bytes, got {}", b.len()))
        })?;
        let id = NodeId([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13],
            s[14], s[15], s[16], s[17], s[18], s[19],
        ]);
        let addr = socket_from_compact(&s[20..26])?;
        Ok(BencodedNode { id, addr })
    }
}

/// A node id on the wire is 20 bytes: a compact address followed by padding.
fn id20_as_compact(id: &NodeId) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&id.0);
    out
}

// ------------------------------------------------------------- KRPC messages

/// A 2-byte transaction id. BEP 5 says it is opaque; we use two random bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransactionId(pub [u8; 2]);

impl TransactionId {
    pub fn random() -> Self {
        let mut b = [0u8; 2];
        rand::Rng::fill(&mut rand::thread_rng(), &mut b);
        TransactionId(b)
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.0[0] as char, self.0[1] as char)
    }
}

/// The four queries BEP 5 defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    Ping,
    FindNode {
        target: NodeId,
    },
    GetPeers {
        infohash: InfoHash,
        want: Option<NodeId>,
    },
    AnnouncePeer {
        infohash: InfoHash,
        port: u16,
        token: Vec<u8>,
        implied_port: bool,
    },
}

impl Query {
    pub fn name(&self) -> &'static str {
        match self {
            Query::Ping => "ping",
            Query::FindNode { .. } => "find_node",
            Query::GetPeers { .. } => "get_peers",
            Query::AnnouncePeer { .. } => "announce_peer",
        }
    }
}

/// A decoded inbound query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryMsg {
    pub tid: TransactionId,
    pub id: NodeId,
    pub query: Query,
}

/// The payload of a `y=r` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponsePayload {
    /// `ping` and `announce_peer` return just the id.
    Empty,
    Nodes(Vec<BencodedNode>),
    GetPeers {
        token: Vec<u8>,
        nodes: Vec<BencodedNode>,
        values: Vec<SocketAddr>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub tid: TransactionId,
    pub id: NodeId,
    pub payload: ResponsePayload,
}

/// A `y=e` message. Aliased as `Error` to match the BEP 5 vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrpcError {
    pub tid: TransactionId,
    pub code: i64,
    pub message: String,
}

pub type Error = KrpcError;

/// Any decoded KRPC message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    Query(QueryMsg),
    Response(Response),
    Error(KrpcError),
}

// ---- encoding helpers

fn bencoded_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len() + 12);
    out.extend_from_slice(b.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(b);
    out
}

fn put_bytes(out: &mut Vec<u8>, key: &str, val: &[u8]) {
    out.extend_from_slice(&bencoded_bytes(key.as_bytes()));
    out.extend_from_slice(&bencoded_bytes(val));
}

fn put_int(out: &mut Vec<u8>, key: &str, val: i64) {
    out.extend_from_slice(&bencoded_bytes(key.as_bytes()));
    out.push(b'i');
    out.extend_from_slice(val.to_string().as_bytes());
    out.push(b'e');
}

/// Write `key` as a bencoded list of byte strings.
///
/// BEP 5 is picky here: `nodes` is a *single* byte string holding every 26-byte
/// record back to back, while `values` is a genuine list whose elements are
/// individually length-prefixed.
fn put_node_blob(out: &mut Vec<u8>, key: &str, nodes: &[BencodedNode]) {
    let mut blob = Vec::with_capacity(nodes.len() * 26);
    for n in nodes {
        blob.extend_from_slice(&n.to_bytes());
    }
    put_bytes(out, key, &blob);
}

fn put_peer_list(out: &mut Vec<u8>, key: &str, addrs: &[SocketAddr]) {
    out.extend_from_slice(&bencoded_bytes(key.as_bytes()));
    out.push(b'l');
    for a in addrs {
        if let Some(c) = socket_to_compact(*a) {
            out.extend_from_slice(&bencoded_bytes(&c));
        } else if let Some(c6) = socket_to_compact6(*a) {
            out.extend_from_slice(&bencoded_bytes(&c6));
        }
    }
    out.push(b'e');
}

fn encode_args(out: &mut Vec<u8>, id: NodeId, q: &Query) {
    out.push(b'd');
    match q {
        Query::Ping => {
            put_bytes(out, "id", &id.0);
        }
        Query::FindNode { target } => {
            put_bytes(out, "id", &id.0);
            put_bytes(out, "target", &target.0);
        }
        Query::GetPeers { infohash, want } => {
            put_bytes(out, "id", &id.0);
            put_bytes(out, "info_hash", &infohash.0);
            if let Some(w) = want {
                put_bytes(out, "want", &w.0);
            }
        }
        Query::AnnouncePeer {
            infohash,
            port,
            token,
            implied_port,
        } => {
            put_bytes(out, "id", &id.0);
            put_int(out, "implied_port", i64::from(*implied_port));
            put_bytes(out, "info_hash", &infohash.0);
            put_int(out, "port", i64::from(*port));
            put_bytes(out, "token", token);
        }
    }
    out.push(b'e');
}

/// Encode an outbound query.
pub fn encode_query(tid: TransactionId, id: NodeId, q: &Query) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.push(b'd');
    out.extend_from_slice(&bencoded_bytes(b"a"));
    encode_args(&mut out, id, q);
    out.extend_from_slice(&bencoded_bytes(b"q"));
    out.extend_from_slice(&bencoded_bytes(q.name().as_bytes()));
    out.extend_from_slice(&bencoded_bytes(b"t"));
    out.extend_from_slice(&bencoded_bytes(&tid.0));
    out.extend_from_slice(&bencoded_bytes(b"y"));
    out.extend_from_slice(&bencoded_bytes(b"q"));
    out.push(b'e');
    out
}

/// Encode an outbound response.
pub fn encode_response(tid: TransactionId, id: NodeId, payload: &ResponsePayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.push(b'd');
    out.extend_from_slice(&bencoded_bytes(b"r"));
    out.push(b'd');
    put_bytes(&mut out, "id", &id.0);
    match payload {
        ResponsePayload::Empty => {}
        ResponsePayload::Nodes(nodes) => {
            put_node_blob(&mut out, "nodes", nodes);
        }
        ResponsePayload::GetPeers {
            token,
            nodes,
            values,
        } => {
            if !nodes.is_empty() {
                put_node_blob(&mut out, "nodes", nodes);
            }
            put_bytes(&mut out, "token", token);
            if !values.is_empty() {
                put_peer_list(&mut out, "values", values);
            }
        }
    }
    out.push(b'e'); // r
    out.extend_from_slice(&bencoded_bytes(b"t"));
    out.extend_from_slice(&bencoded_bytes(&tid.0));
    out.extend_from_slice(&bencoded_bytes(b"y"));
    out.extend_from_slice(&bencoded_bytes(b"r"));
    out.push(b'e');
    out
}

/// Encode an outbound error.
pub fn encode_error(tid: TransactionId, code: i64, message: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(b'd');
    out.extend_from_slice(&bencoded_bytes(b"e"));
    out.push(b'l');
    out.push(b'i');
    out.extend_from_slice(code.to_string().as_bytes());
    out.push(b'e');
    out.extend_from_slice(&bencoded_bytes(message.as_bytes()));
    out.push(b'e');
    out.extend_from_slice(&bencoded_bytes(b"t"));
    out.extend_from_slice(&bencoded_bytes(&tid.0));
    out.extend_from_slice(&bencoded_bytes(b"y"));
    out.extend_from_slice(&bencoded_bytes(b"e"));
    out.push(b'e');
    out
}

// ---- decoding

fn dict_bytes<'a>(v: &'a Value, key: &str) -> Result<Option<&'a [u8]>> {
    match v.get_opt(key) {
        None => Ok(None),
        Some(val) => Ok(Some(val.as_bytes()?)),
    }
}

fn decode_tid(v: &Value) -> Result<TransactionId> {
    let t = v.get("t")?.as_bytes()?;
    let arr: [u8; 2] = t.try_into().map_err(|_| {
        DhtError::Protocol(format!("transaction id must be 2 bytes, got {}", t.len()))
    })?;
    Ok(TransactionId(arr))
}

fn decode_node_id(bytes: &[u8]) -> Result<NodeId> {
    NodeId::from_bytes(bytes)
}

/// Decode any KRPC message from a UDP payload. Never panics on bad input.
pub fn decode_message(bytes: &[u8]) -> Result<Inbound> {
    if bytes.is_empty() {
        return Err(DhtError::Protocol("empty packet".into()));
    }
    // Other implementations do not always sort their keys.
    let v = bencode::decode_unordered(bytes)?;
    if !matches!(v, Value::Dict(_)) {
        return Err(DhtError::Protocol(
            "krpc message is not a dictionary".into(),
        ));
    }
    let tid = decode_tid(&v)?;
    let y = v
        .get("y")?
        .as_bytes()?
        .iter()
        .map(|b| *b as char)
        .collect::<String>();
    if y.len() != 1 {
        return Err(DhtError::Protocol(format!("bad message type {y:?}")));
    }

    match y.as_str() {
        "q" => {
            let qname = v.get("q")?.as_str()?.to_owned();
            let args = v.get("a")?;
            let id_bytes = args
                .get("id")?
                .as_bytes()
                .map_err(|e| DhtError::Protocol(e.to_string()))?;
            let id = decode_node_id(id_bytes)?;
            let query = match qname.as_str() {
                "ping" => Query::Ping,
                "find_node" => {
                    let t = args.get("target")?.as_bytes()?;
                    Query::FindNode {
                        target: decode_node_id(t)?,
                    }
                }
                "get_peers" => {
                    let ih = args.get("info_hash")?.as_bytes()?;
                    let ih: [u8; 20] = ih
                        .try_into()
                        .map_err(|_| DhtError::Protocol("info_hash must be 20 bytes".into()))?;
                    let want = match dict_bytes(args, "want")? {
                        Some(w) => Some(decode_node_id(w)?),
                        None => None,
                    };
                    Query::GetPeers {
                        infohash: InfoHash(ih),
                        want,
                    }
                }
                "announce_peer" | "announce" => {
                    let ih = args.get("info_hash")?.as_bytes()?;
                    let ih: [u8; 20] = ih
                        .try_into()
                        .map_err(|_| DhtError::Protocol("info_hash must be 20 bytes".into()))?;
                    // A missing `port` defaults to 0, but a present-but-malformed
                    // one is a protocol error.
                    let port = match args.get("port") {
                        Ok(p) => p.as_int().map_err(|e| DhtError::Protocol(e.to_string()))?,
                        Err(_) => 0,
                    };
                    if !(0..=65535).contains(&port) {
                        return Err(DhtError::Protocol(format!("bad announce port {port}")));
                    }
                    let token = dict_bytes(args, "token")?.unwrap_or(&[]).to_vec();
                    let implied = args
                        .get_opt("implied_port")
                        .and_then(|v| v.as_int().ok())
                        .unwrap_or(0)
                        != 0
                        || args.get_opt("implied").is_some();
                    Query::AnnouncePeer {
                        infohash: InfoHash(ih),
                        port: port as u16,
                        token,
                        implied_port: implied,
                    }
                }
                other => {
                    return Err(DhtError::Protocol(format!("unknown query {other:?}")));
                }
            };
            Ok(Inbound::Query(QueryMsg { tid, id, query }))
        }
        "r" => {
            let r = v.get("r")?;
            let id = decode_node_id(r.get("id")?.as_bytes()?)?;
            let token = dict_bytes(r, "token")?;
            let payload = match (token, r.get_opt("values")) {
                (None, None) => match r.get_opt("nodes") {
                    Some(nodes) => ResponsePayload::Nodes(parse_nodes(nodes)?),
                    None => ResponsePayload::Empty,
                },
                (token, values) => ResponsePayload::GetPeers {
                    token: token
                        .filter(|t| t.len() <= MAX_TOKEN_LEN)
                        .unwrap_or(&[])
                        .to_vec(),
                    nodes: r
                        .get_opt("nodes")
                        .and_then(|n| parse_nodes(n).ok())
                        .unwrap_or_default(),
                    values: match values {
                        Some(v) => parse_peer_values(v)?,
                        None => Vec::new(),
                    },
                },
            };
            Ok(Inbound::Response(Response { tid, id, payload }))
        }
        "e" => {
            let list = v.get("e")?.as_list()?;
            let first = list
                .first()
                .ok_or_else(|| DhtError::Protocol("error list is empty".into()))?;
            let code = first
                .as_int()
                .map_err(|e| DhtError::Protocol(e.to_string()))?;
            let message = list
                .get(1)
                .and_then(|m| m.as_str().ok())
                .unwrap_or("")
                .to_owned();
            Ok(Inbound::Error(KrpcError { tid, code, message }))
        }
        other => Err(DhtError::Protocol(format!("bad y field {other:?}"))),
    }
}

/// Parse a `nodes` value: one long byte string of 26-byte node records.
pub fn parse_nodes(v: &Value) -> Result<Vec<BencodedNode>> {
    let raw = v.as_bytes()?;
    if raw.len() % 26 != 0 {
        return Err(DhtError::Protocol(format!(
            "nodes blob of {} bytes is not a multiple of 26",
            raw.len()
        )));
    }
    let mut out = Vec::with_capacity(raw.len() / 26);
    for chunk in raw.chunks_exact(26) {
        // A single bad record must not lose the whole response.
        match BencodedNode::from_bytes(chunk) {
            Ok(n) => out.push(n),
            Err(e) => tracing::trace!(error = %e, "skipping malformed node record"),
        }
    }
    Ok(out)
}

/// Parse a `values` list: 6-byte and 18-byte compact peer addresses only.
/// Anything else (notably 26-byte node records) is not a peer and is dropped.
fn parse_peer_values(v: &Value) -> Result<Vec<SocketAddr>> {
    let list = v.as_list()?;
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        let raw = match item.as_bytes() {
            Ok(b) => b,
            Err(e) => {
                tracing::trace!(error = %e, "skipping non-bytes peer value");
                continue;
            }
        };
        match raw.len() {
            6 => match socket_from_compact(raw) {
                Ok(a) => out.push(a),
                Err(e) => tracing::trace!(error = %e, "skipping bad compact peer"),
            },
            18 => match socket_from_compact6(raw) {
                Ok(a) => out.push(a),
                Err(e) => tracing::trace!(error = %e, "skipping bad compact IPv6 peer"),
            },
            n => tracing::trace!(len = n, "skipping peer value of unexpected length"),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------- routing table

/// A node we know about.
#[derive(Debug, Clone)]
pub struct Contact {
    pub id: NodeId,
    pub addr: SocketAddr,
    pub last_seen: Instant,
    /// Consecutive queries that went unanswered; high values get evicted first.
    pub failures: u32,
    probing: bool,
}

impl Contact {
    fn is_bad(&self) -> bool {
        self.failures >= BAD_FAILURES
    }

    fn is_questionable(&self) -> bool {
        self.last_seen.elapsed() > FRESH_FOR
    }
}

/// One XOR bucket. Kademlia's tree is flattened to `BUCKET_COUNT` levels, which
/// is plenty for a client that only ever walks the handful of closest nodes.
#[derive(Debug, Clone)]
pub struct Bucket {
    contacts: Vec<Contact>,
}

impl Bucket {
    fn new() -> Self {
        Bucket {
            contacts: Vec::with_capacity(BUCKET_CAP),
        }
    }

    fn len(&self) -> usize {
        self.contacts.len()
    }

    /// Add or refresh a node. A known id is never rebound to another address.
    /// A full bucket only gives way to a bad node; otherwise the stalest
    /// questionable node is returned so the caller can ping it.
    fn touch(&mut self, id: NodeId, addr: SocketAddr) -> Option<SocketAddr> {
        if let Some(c) = self.contacts.iter_mut().find(|c| c.id == id) {
            if c.addr == addr {
                c.last_seen = Instant::now();
                c.failures = 0;
                c.probing = false;
            }
            return None;
        }
        if self.contacts.len() >= BUCKET_CAP {
            if let Some(i) = self.contacts.iter().position(Contact::is_bad) {
                self.contacts.remove(i);
            } else {
                return self
                    .contacts
                    .iter_mut()
                    .filter(|c| c.is_questionable() && !c.probing)
                    .min_by_key(|c| c.last_seen)
                    .map(|c| {
                        c.probing = true;
                        c.addr
                    });
            }
        }
        self.contacts.push(Contact {
            id,
            addr,
            last_seen: Instant::now(),
            failures: 0,
            probing: false,
        });
        None
    }

    fn collect(&self, out: &mut Vec<Contact>) {
        out.extend(self.contacts.iter().cloned());
    }
}

pub const BUCKET_COUNT: usize = 160;
const BUCKET_CAP: usize = 8;

/// The Kademlia routing table for one node id.
#[derive(Debug, Clone)]
pub struct RoutingTable {
    id: NodeId,
    buckets: Vec<Bucket>,
}

impl RoutingTable {
    pub fn new(id: NodeId) -> Self {
        let mut buckets = Vec::with_capacity(BUCKET_COUNT);
        for _ in 0..BUCKET_COUNT {
            buckets.push(Bucket::new());
        }
        RoutingTable { id, buckets }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(Bucket::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bucket index for `id`: the position of the first bit where it differs
    /// from our own id. Returns `None` for ourselves.
    fn bucket_index(&self, id: &NodeId) -> Option<usize> {
        if *id == self.id {
            return None;
        }
        for (i, byte) in id.0.iter().enumerate() {
            let mine = self.id.0[i];
            if byte != &mine {
                let diff = (byte ^ mine).leading_zeros() as usize;
                let bit = i * 8 + diff;
                return Some(bit.min(BUCKET_COUNT - 1));
            }
        }
        None
    }

    /// Add or refresh a node. Unknown ids (from a compact address alone) are
    /// stored under the all-zero placeholder and upgraded once we learn the id.
    /// Returns an address worth pinging when the bucket is full of old nodes.
    pub fn insert(&mut self, id: NodeId, addr: SocketAddr) -> Option<SocketAddr> {
        if id == self.id {
            return None;
        }
        let known = self.get_by_addr(&addr).map(|c| c.id);
        match known {
            Some(old) if old == id => {}
            Some(old) if old.0 == [0u8; 20] => {
                for bucket in &mut self.buckets {
                    bucket.contacts.retain(|c| c.addr != addr);
                }
            }
            Some(_) => return None,
            None => {}
        }
        let i = self.bucket_index(&id)?;
        self.buckets[i].touch(id, addr)
    }

    /// Count an unanswered query against `addr`.
    pub fn fail(&mut self, addr: &SocketAddr) {
        for c in self.buckets.iter_mut().flat_map(|b| b.contacts.iter_mut()) {
            if c.addr == *addr {
                c.failures = c.failures.saturating_add(1);
            }
        }
    }

    fn mark_dead(&mut self, addr: &SocketAddr) {
        for c in self.buckets.iter_mut().flat_map(|b| b.contacts.iter_mut()) {
            if c.addr == *addr {
                c.failures = BAD_FAILURES;
                c.probing = false;
            }
        }
    }

    /// The `k` nodes closest to `target` in XOR distance, nearest first.
    pub fn find_closest(&self, target: &NodeId, k: usize) -> Vec<Contact> {
        let mut all = Vec::with_capacity(self.len());
        for bucket in &self.buckets {
            bucket.collect(&mut all);
        }
        // Ties (equal distance) are broken by address so ordering is total and
        // deterministic rather than dependent on bucket layout.
        all.sort_by(|a, b| {
            let da = distance(&a.id.0, &target.0);
            let db = distance(&b.id.0, &target.0);
            da.cmp(&db).then_with(|| a.addr.cmp(&b.addr))
        });
        all.truncate(k);
        all
    }

    /// Nodes sorted by how recently they were heard from.
    pub fn good_nodes(&self) -> Vec<Contact> {
        let mut all = Vec::with_capacity(self.len());
        for bucket in &self.buckets {
            bucket.collect(&mut all);
        }
        all.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        all
    }

    /// Look up a node by exact id.
    pub fn get(&self, id: &NodeId) -> Option<&Contact> {
        let i = self.bucket_index(id)?;
        self.buckets[i]
            .contacts
            .iter()
            .find(|c| c.id == *id || c.id.0 == id.0)
    }

    /// Look up a node by address.
    pub fn get_by_addr(&self, addr: &SocketAddr) -> Option<&Contact> {
        self.buckets
            .iter()
            .flat_map(|b| b.contacts.iter())
            .find(|c| c.addr == *addr)
    }
}

// ---------------------------------------------------------------- DhtNode

type PendingMap = HashMap<[u8; 2], (SocketAddr, oneshot::Sender<Inbound>)>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding the lock must not take the whole node down.
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// State shared between the socket, the read loop and query callers.
#[derive(Clone)]
struct Shared {
    id: NodeId,
    socket: Arc<UdpSocket>,
    table: Arc<Mutex<RoutingTable>>,
    pending: Arc<Mutex<PendingMap>>,
    secrets: Arc<Mutex<Secrets>>,
    stopped: Arc<AtomicBool>,
}

struct Secrets {
    current: [u8; 20],
    previous: [u8; 20],
    rotated: Instant,
}

impl Secrets {
    fn new() -> Self {
        Secrets {
            current: rand::random(),
            previous: rand::random(),
            rotated: Instant::now(),
        }
    }

    fn rotate_if_due(&mut self) {
        if self.rotated.elapsed() >= SECRET_ROTATION {
            self.previous = self.current;
            self.current = rand::random();
            self.rotated = Instant::now();
        }
    }
}

fn make_token(secret: &[u8; 20], ip: IpAddr, infohash: InfoHash) -> Vec<u8> {
    let mut buf = Vec::with_capacity(56);
    buf.extend_from_slice(secret);
    match ip {
        IpAddr::V4(a) => buf.extend_from_slice(&a.octets()),
        IpAddr::V6(a) => buf.extend_from_slice(&a.octets()),
    }
    buf.extend_from_slice(&infohash.0);
    sha1_bytes(&buf).to_vec()
}

impl Shared {
    fn begin(&self, addr: SocketAddr) -> Option<(TransactionId, oneshot::Receiver<Inbound>)> {
        let (tx, rx) = oneshot::channel();
        let mut pending = lock(&self.pending);
        for _ in 0..32 {
            let tid = TransactionId::random();
            if let std::collections::hash_map::Entry::Vacant(e) = pending.entry(tid.0) {
                e.insert((addr, tx));
                return Some((tid, rx));
            }
        }
        None
    }

    fn finish(&self, tid: TransactionId) {
        lock(&self.pending).remove(&tid.0);
    }

    /// Hand a reply to the query waiting on `tid`, but only if it came from the
    /// address that query was sent to.
    fn deliver(&self, from: SocketAddr, tid: TransactionId, inbound: Inbound) -> bool {
        let mut pending = lock(&self.pending);
        if pending.get(&tid.0).map(|(a, _)| *a) != Some(from) {
            tracing::trace!(%from, tid = %tid, "dropping reply that matches no pending query");
            return false;
        }
        match pending.remove(&tid.0) {
            Some((_, s)) => s.send(inbound).is_ok(),
            None => false,
        }
    }

    fn add_contact(&self, id: NodeId, addr: SocketAddr) {
        if id == self.id {
            return;
        }
        let stale = lock(&self.table).insert(id, addr);
        if let Some(stale) = stale {
            tokio::spawn(self.clone().probe(stale));
        }
    }

    async fn probe(self, addr: SocketAddr) {
        let alive = match self.begin(addr) {
            Some((tid, rx)) => {
                let msg = encode_query(tid, self.id, &Query::Ping);
                let sent = self.socket.send_to(&msg, addr).await.is_ok();
                let got =
                    sent && matches!(tokio::time::timeout(QUERY_TIMEOUT, rx).await, Ok(Ok(_)));
                self.finish(tid);
                got
            }
            None => true,
        };
        if !alive {
            lock(&self.table).mark_dead(&addr);
        }
    }

    /// Token for `ip` and `infohash`: SHA-1(secret || ip || infohash).
    fn token_for(&self, ip: IpAddr, infohash: InfoHash) -> Vec<u8> {
        let mut s = lock(&self.secrets);
        s.rotate_if_due();
        make_token(&s.current, ip, infohash)
    }

    fn token_valid(&self, ip: IpAddr, infohash: InfoHash, token: &[u8]) -> bool {
        let mut s = lock(&self.secrets);
        s.rotate_if_due();
        make_token(&s.current, ip, infohash) == token
            || make_token(&s.previous, ip, infohash) == token
    }
}

/// A running DHT node: one UDP socket, a routing table and a pending map.
pub struct DhtNode {
    shared: Shared,
}

impl DhtNode {
    /// Bind an ephemeral UDP port and start the read loop. `id` defaults to a
    /// fresh random node id.
    pub async fn new(id: Option<[u8; 20]>) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let node_id = match id {
            Some(bytes) => NodeId(bytes),
            None => NodeId::random(),
        };
        let socket = Arc::new(socket);
        let shared = Shared {
            id: node_id,
            socket: socket.clone(),
            table: Arc::new(Mutex::new(RoutingTable::new(node_id))),
            pending: Arc::new(Mutex::new(HashMap::new())),
            secrets: Arc::new(Mutex::new(Secrets::new())),
            stopped: Arc::new(AtomicBool::new(false)),
        };
        tracing::debug!(id = %node_id, addr = %socket.local_addr()?, "dht node started");
        tokio::spawn(read_loop(shared.clone()));
        Ok(DhtNode { shared })
    }

    /// The address the node's socket is bound to (an ephemeral port).
    pub fn local_addr(&self) -> SocketAddr {
        self.shared.socket.local_addr().unwrap_or_else(|e| {
            tracing::debug!(error = %e, "dht socket has no local address");
            SocketAddr::from(([0, 0, 0, 0], 0))
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.shared.id
    }

    /// How many nodes we know about.
    pub fn node_count(&self) -> usize {
        lock(&self.shared.table).len()
    }

    /// Snapshot of the routing table, freshest node first.
    pub fn good_nodes(&self) -> Vec<Contact> {
        lock(&self.shared.table).good_nodes()
    }

    /// Stop answering queries and fail anything still in flight.
    pub fn shutdown(&self) {
        self.shared.stopped.store(true, Ordering::Relaxed);
        lock(&self.shared.pending).clear();
    }

    /// Insert a node we learned about out of band (a bootstrap router, say).
    pub async fn add_node(&self, info: Info) {
        match info {
            Info::Id20(id) => {
                // We have an id but no address; pair it with a known address.
                let table = lock(&self.shared.table);
                if let Some(c) = table.get_by_addr(&self.local_addr()) {
                    let addr = c.addr;
                    drop(table);
                    self.shared.add_contact(NodeId(id), addr);
                } else if let Some(c) = table.find_closest(&NodeId(id), 1).into_iter().next() {
                    self.shared.add_contact(NodeId(id), c.addr);
                }
            }
            Info::Compact(b) => {
                if let Ok(addr) = socket_from_compact(&b) {
                    self.shared.add_contact(NodeId([0u8; 20]), addr);
                }
            }
            Info::Compact6(b) => {
                if let Ok(addr) = socket_from_compact6(&b) {
                    self.shared.add_contact(NodeId([0u8; 20]), addr);
                }
            }
        }
    }

    /// Resolve a node reference to an address, consulting the routing table when
    /// we were given a bare id.
    fn resolve(&self, target: &Info) -> Option<SocketAddr> {
        match target {
            Info::Compact(_) | Info::Compact6(_) => target.socket_addr(),
            Info::Id20(id) => {
                let wanted = NodeId(*id);
                let table = lock(&self.shared.table);
                table.get(&wanted).map(|c| c.addr).or_else(|| {
                    table
                        .find_closest(&wanted, 1)
                        .into_iter()
                        .next()
                        .map(|c| c.addr)
                })
            }
        }
    }

    /// Send one query and wait for the matching response.
    async fn query(&self, addr: SocketAddr, q: Query) -> Result<Inbound> {
        let (tid, rx) = self
            .shared
            .begin(addr)
            .ok_or_else(|| DhtError::Protocol("too many queries in flight".into()))?;
        let msg = encode_query(tid, self.shared.id, &q);
        if msg.len() > MAX_MESSAGE_LEN {
            self.shared.finish(tid);
            return Err(DhtError::Protocol(format!(
                "outgoing {} query is {} bytes, over the {MAX_MESSAGE_LEN} byte limit",
                q.name(),
                msg.len()
            )));
        }
        if let Err(e) = self.shared.socket.send_to(&msg, addr).await {
            self.shared.finish(tid);
            return Err(DhtError::Io(e));
        }
        tracing::trace!(%addr, query = q.name(), tid = %tid, "sent dht query");
        let result = tokio::time::timeout(QUERY_TIMEOUT, rx).await;
        // Belt and braces: the read loop removes the entry too.
        self.shared.finish(tid);
        match result {
            Ok(Ok(inbound)) => Ok(inbound),
            Ok(Err(_)) => Err(DhtError::Shutdown),
            Err(_) => {
                tracing::trace!(%addr, query = q.name(), "dht query timed out");
                lock(&self.shared.table).fail(&addr);
                Err(DhtError::Timeout)
            }
        }
    }

    /// Measure the round-trip time to a node. Errors if it does not answer.
    pub async fn ping(&self, target: Info) -> Result<Duration> {
        let addr = self.resolve(&target).ok_or_else(|| {
            DhtError::InvalidAddress(format!("cannot resolve {target} to an address"))
        })?;
        let start = Instant::now();
        match self.query(addr, Query::Ping).await? {
            Inbound::Response(r) => {
                let rtt = start.elapsed();
                self.shared.add_contact(r.id, addr);
                tracing::debug!(%addr, rtt_ms = rtt.as_millis(), "dht ping ok");
                Ok(rtt)
            }
            Inbound::Error(e) => Err(DhtError::Remote {
                peer: addr.to_string(),
                code: e.code,
                message: e.message,
            }),
            Inbound::Query(_) => Err(DhtError::Protocol("unexpected query reply".into())),
        }
    }

    /// The next `K` nodes to ask: the closest to `target` among those just
    /// learned and those in the table, skipping any already asked. Picking by
    /// distance, not arrival order, is what makes a lookup converge.
    fn next_hops(&self, target: &NodeId, mut learned: Vec<(NodeId, SocketAddr)>, seen: &mut HashSet<SocketAddr>) -> Vec<SocketAddr> {
        learned.extend(lock(&self.shared.table).find_closest(target, K * 2).into_iter().map(|c| (c.id, c.addr)));
        learned.sort_by(|a, b| a.0.distance(target).cmp(&b.0.distance(target)));
        learned.into_iter().filter(|(_, addr)| seen.insert(*addr)).take(K).map(|(_, addr)| addr).collect()
    }

    /// Ask the closest known nodes for nodes closer to `target`.
    ///
    /// Returns everything learned, nearest first. Nodes that do not answer are
    /// simply skipped: the result is partial rather than an error.
    pub async fn find_node(&self, target: [u8; 20]) -> Result<Vec<BencodedNode>> {
        let target_id = NodeId(target);
        let mut seen: HashSet<SocketAddr> = HashSet::new();
        let mut found: BTreeMap<NodeId, BencodedNode> = BTreeMap::new();
        let mut frontier = self.candidates(&target_id, &mut seen, K);

        for round in 0..LOOKUP_ROUNDS {
            if frontier.is_empty() {
                break;
            }
            let this = self;
            let futures = frontier.iter().map(move |&addr| {
                let q = Query::FindNode { target: target_id };
                async move { (addr, this.query(addr, q).await) }
            });
            let results = join_all(futures).await;
            let mut learned: Vec<(NodeId, SocketAddr)> = Vec::new();

            for (addr, result) in results {
                match result {
                    Ok(Inbound::Response(r)) => {
                        // Some nodes add a token to find_node replies too.
                        if let ResponsePayload::Nodes(nodes) | ResponsePayload::GetPeers { nodes, .. } = &r.payload {
                            for n in nodes {
                                // Never route to ourselves.
                                if n.id == this.shared.id {
                                    continue;
                                }
                                this.shared.add_contact(n.id, n.addr);
                                found.insert(n.id, *n);
                                learned.push((n.id, n.addr));
                            }
                        }
                    }
                    Ok(Inbound::Error(e)) => {
                        tracing::debug!(%addr, code = e.code, "find_node rejected by remote");
                    }
                    Ok(_) => {}
                    Err(e) => tracing::trace!(%addr, round, error = %e, "find_node query failed"),
                }
            }

            frontier = this.next_hops(&target_id, learned, &mut seen);
        }

        let mut out: Vec<BencodedNode> = found.into_values().collect();
        out.sort_by(|a, b| a.id.distance(&target_id).cmp(&b.id.distance(&target_id)));
        tracing::debug!(target = %target_id, nodes = out.len(), "find_node finished");
        Ok(out)
    }

    /// Look up peers seeding `infohash`.
    ///
    /// Returns whatever we found, which may be empty: an empty routing table or
    /// unresponsive nodes is a normal outcome, not an error.
    pub async fn get_peers(&self, infohash: InfoHash) -> Result<Vec<SocketAddr>> {
        Ok(self.get_peers_rounds(infohash, LOOKUP_ROUNDS).await?.0)
    }

    /// Peers found, plus every node that answered with a token (id, address, token).
    async fn get_peers_rounds(
        &self,
        infohash: InfoHash,
        max_rounds: usize,
    ) -> Result<(Vec<SocketAddr>, Vec<(NodeId, SocketAddr, Vec<u8>)>)> {
        let target_id = NodeId(infohash.0);
        let mut seen_nodes: HashSet<SocketAddr> = HashSet::new();
        let mut peers: Vec<SocketAddr> = Vec::new();
        let mut peer_set: HashSet<SocketAddr> = HashSet::new();
        let mut tokens: Vec<(NodeId, SocketAddr, Vec<u8>)> = Vec::new();
        let mut frontier = self.candidates(&target_id, &mut seen_nodes, K);

        for round in 0..max_rounds.max(1) {
            if frontier.is_empty() {
                break;
            }
            let this = self;
            let futures = frontier.iter().map(move |&addr| {
                let q = Query::GetPeers {
                    infohash,
                    want: None,
                };
                async move { (addr, this.query(addr, q).await) }
            });
            let results = join_all(futures).await;
            let mut learned: Vec<(NodeId, SocketAddr)> = Vec::new();

            for (addr, result) in results {
                match result {
                    Ok(Inbound::Response(r)) => {
                        if let ResponsePayload::GetPeers {
                            token,
                            nodes,
                            values,
                        } = r.payload
                        {
                            if !token.is_empty() {
                                tokens.push((r.id, addr, token));
                            }
                            for p in values {
                                if peer_set.insert(p) {
                                    peers.push(p);
                                }
                            }
                            for n in nodes {
                                if n.id == this.shared.id {
                                    continue;
                                }
                                this.shared.add_contact(n.id, n.addr);
                                learned.push((n.id, n.addr));
                            }
                        }
                    }
                    Ok(Inbound::Error(e)) => {
                        tracing::debug!(%addr, code = e.code, "get_peers rejected by remote");
                    }
                    Ok(_) => {}
                    Err(e) => tracing::trace!(%addr, round, error = %e, "get_peers query failed"),
                }
            }

            frontier = this.next_hops(&target_id, learned, &mut seen_nodes);
        }

        tracing::debug!(infohash = %infohash, peers = peers.len(), "get_peers finished");
        Ok((peers, tokens))
    }

    /// Tell the closest nodes that gave us a token we are serving `infohash`
    /// on `port`, echoing the token each one returned from `get_peers`.
    ///
    /// Announcing is best-effort; failures are logged, not returned.
    pub async fn announce(&self, infohash: InfoHash, port: u16) -> Result<()> {
        let target_id = NodeId(infohash.0);
        let (_, mut tokens) = self.get_peers_rounds(infohash, LOOKUP_ROUNDS).await?;
        if tokens.is_empty() {
            tracing::debug!(infohash = %infohash, "announce_peer skipped: no node gave a token");
            return Ok(());
        }
        tokens.sort_by_key(|(id, _, _)| id.distance(&target_id));
        tokens.truncate(K);
        let this = self;
        let futures = tokens.into_iter().map(move |(_, addr, token)| {
            let q = Query::AnnouncePeer {
                infohash,
                port,
                token,
                implied_port: false,
            };
            async move { (addr, this.query(addr, q).await) }
        });
        let results = join_all(futures).await;
        let mut ok = 0usize;
        for (addr, result) in results {
            match result {
                Ok(Inbound::Response(_)) => ok += 1,
                Ok(Inbound::Error(e)) => {
                    tracing::debug!(%addr, code = e.code, "announce_peer rejected by remote");
                }
                Ok(_) => {}
                Err(e) => tracing::trace!(%addr, error = %e, "announce_peer failed"),
            }
        }
        tracing::debug!(infohash = %infohash, port, acked = ok, "announce_peer finished");
        Ok(())
    }

    /// Up to `k` addresses to try next, skipping any already visited.
    fn candidates(
        &self,
        target: &NodeId,
        seen: &mut HashSet<SocketAddr>,
        k: usize,
    ) -> Vec<SocketAddr> {
        let mut out = Vec::with_capacity(k);
        for c in lock(&self.shared.table).find_closest(target, k * 2) {
            if c.id == self.shared.id {
                continue;
            }
            if out.len() >= k {
                break;
            }
            if seen.insert(c.addr) {
                out.push(c.addr);
            }
        }
        out
    }

    /// Ping a list of `host:port` bootstrap routers. Returns how many answered.
    pub async fn bootstrap(&self, routers: &[String]) -> usize {
        let mut targets: Vec<SocketAddr> = Vec::with_capacity(routers.len());
        for r in routers {
            match resolve_router(r).await {
                Ok(addr) => targets.push(addr),
                Err(e) => {
                    tracing::warn!(router = %r, error = %e, "cannot resolve bootstrap router")
                }
            }
        }
        if targets.is_empty() {
            tracing::warn!("no usable bootstrap routers");
            return 0;
        }

        let this = self;
        let futures = targets
            .iter()
            .map(move |&addr| async move { (addr, this.query(addr, Query::Ping).await) });
        let results = join_all(futures).await;
        let mut reachable = 0usize;
        for (addr, result) in results {
            match result {
                Ok(Inbound::Response(r)) => {
                    this.shared.add_contact(r.id, addr);
                    reachable += 1;
                }
                Ok(Inbound::Error(e)) => {
                    tracing::debug!(%addr, code = e.code, "bootstrap router errored")
                }
                Ok(_) => {}
                Err(e) => tracing::debug!(%addr, error = %e, "bootstrap router unreachable"),
            }
        }
        if reachable > 0 {
            // Pinging only puts the routers in the table; a lookup of our own
            // id is what fills it with real nodes near us.
            let _ = this.find_node(this.shared.id.0).await;
        }
        tracing::info!(routers = routers.len(), reachable, nodes = this.node_count(), "dht bootstrap finished");
        reachable
    }
}

impl Drop for DhtNode {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Resolve a `host:port` bootstrap router, accepting bare IPv4 addresses too.
pub async fn resolve_router(spec: &str) -> Result<SocketAddr> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(DhtError::InvalidAddress("empty router".into()));
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(spec)
        .await
        .map_err(|e| DhtError::InvalidAddress(format!("{spec}: {e}")))?
        .collect();
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| DhtError::InvalidAddress(format!("{spec} resolved to no addresses")))
}

// ------------------------------------------------------------- read loop

async fn read_loop(shared: Shared) {
    let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
    loop {
        if shared.stopped.load(Ordering::Relaxed) {
            break;
        }
        match tokio::time::timeout(
            Duration::from_millis(250),
            shared.socket.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((n, from))) => {
                let datagram = buf.get(..n).unwrap_or(&[]);
                handle_datagram(&shared, from, datagram).await;
            }
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "dht recv failed");
                // Transient errors (e.g. ICMP port unreachable) must not end the loop.
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(_) => { /* idle tick, loop back to check the stop flag */ }
        }
    }
    tracing::debug!(id = %shared.id, "dht read loop stopped");
}

async fn handle_datagram(shared: &Shared, from: SocketAddr, data: &[u8]) {
    match decode_message(data) {
        Ok(Inbound::Query(q)) => respond_query(shared, from, q).await,
        Ok(Inbound::Response(r)) => {
            tracing::trace!(%from, id = %r.id, "dht response received");
            let (id, tid) = (r.id, r.tid);
            if shared.deliver(from, tid, Inbound::Response(r)) {
                shared.add_contact(id, from);
            }
        }
        Ok(Inbound::Error(e)) => {
            tracing::trace!(%from, code = e.code, "dht error received");
            shared.deliver(
                from,
                e.tid,
                Inbound::Error(KrpcError {
                    tid: e.tid,
                    code: e.code,
                    message: e.message,
                }),
            );
        }
        Err(e) => {
            // Garbage on a random port must be ignored, not fatal.
            tracing::trace!(%from, len = data.len(), error = %e, "discarding bad dht packet");
        }
    }
}

fn closest_nodes(shared: &Shared, target: &NodeId) -> Vec<BencodedNode> {
    lock(&shared.table)
        .find_closest(target, K)
        .into_iter()
        .map(|c| BencodedNode {
            id: c.id,
            addr: c.addr,
        })
        .collect()
}

async fn respond_query(shared: &Shared, to: SocketAddr, msg: QueryMsg) {
    // Anyone who asks us anything is, by definition, reachable.
    if msg.id != shared.id {
        shared.add_contact(msg.id, to);
    }
    let tid = msg.tid;

    let reply: Vec<u8> = match msg.query {
        Query::Ping => encode_response(tid, shared.id, &ResponsePayload::Empty),
        Query::FindNode { target } => {
            let nodes = closest_nodes(shared, &target);
            encode_response(tid, shared.id, &ResponsePayload::Nodes(nodes))
        }
        Query::GetPeers { infohash, .. } => {
            let nodes = closest_nodes(shared, &NodeId(infohash.0));
            let token = shared.token_for(to.ip(), infohash);
            encode_response(
                tid,
                shared.id,
                &ResponsePayload::GetPeers {
                    token,
                    nodes,
                    values: Vec::new(),
                },
            )
        }
        Query::AnnouncePeer {
            infohash, token, ..
        } => {
            if shared.token_valid(to.ip(), infohash, &token) {
                encode_response(tid, shared.id, &ResponsePayload::Empty)
            } else {
                encode_error(tid, 203, "Bad token")
            }
        }
    };

    if let Err(e) = shared.socket.send_to(&reply, to).await {
        tracing::debug!(%to, error = %e, "failed to answer dht query");
    }
}

/// How we advertise our own address in a KRPC query's `id` field: a compact
/// IPv4 address followed by zero padding to fill 20 bytes.
pub fn compact_id_of(addr: SocketAddr) -> Option<[u8; 20]> {
    let compact = socket_to_compact(addr)?;
    let mut out = [0u8; 20];
    out[..6].copy_from_slice(&compact);
    Some(out)
}

// -------------------------------------------------------- extended protocol

/// The BitTorrent message id that carries every BEP 10 extended message.
const MSG_EXTENDED: u8 = 20;
/// Extended message id reserved for the BEP 10 handshake itself.
const EXT_HANDSHAKE_ID: u8 = 0;
/// The id we ask peers to use when sending us `ut_metadata` messages. Requests
/// we send go to the peer's own id, which comes from their handshake.
const LOCAL_UT_METADATA_ID: u8 = 1;
/// Ordinary peer-wire messages (bitfield, have, ...) tolerated while waiting
/// for the extended exchange, so a chatty peer cannot stall us indefinitely.
const MAX_SKIPPED_MESSAGES: usize = 512;
/// How long a single peer gets during [`fetch_metadata`].
const PER_PEER_TIMEOUT: Duration = Duration::from_secs(10);
/// Peers asked at the same time during [`fetch_metadata`].
const METADATA_CONCURRENCY: usize = 32;
/// Peers tried at most during [`fetch_metadata`].
const METADATA_MAX_PEERS: usize = 200;

/// The BEP 10 handshake, restricted to the fields BEP 9 needs.
///
/// `m` is a dictionary mapping extension names to the message id the sender
/// wants to *receive* that extension under, so the two directions of a
/// connection use different ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedHandshake {
    /// The id the sender expects `ut_metadata` messages under, if supported.
    pub ut_metadata: Option<u8>,
    /// Client identification, conventionally `"<version><name>"`.
    pub v: String,
    /// Request queue length; informational only.
    pub reqq: i64,
    /// Size of our local metadata, absent when we have none (a leecher).
    pub metadata_size: Option<usize>,
}

impl ExtendedHandshake {
    pub fn new(
        ut_metadata: Option<u8>,
        v: impl Into<String>,
        reqq: i64,
        metadata_size: Option<usize>,
    ) -> Self {
        ExtendedHandshake {
            ut_metadata,
            v: v.into(),
            reqq,
            metadata_size,
        }
    }

    pub fn supports_ut_metadata(&self) -> bool {
        self.ut_metadata.is_some()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut m = BTreeMap::new();
        if let Some(id) = self.ut_metadata {
            m.insert(UT_METADATA.as_bytes().to_vec(), Value::Int(i64::from(id)));
        }
        let mut d = BTreeMap::new();
        d.insert(b"m".to_vec(), Value::Dict(m));
        if let Some(size) = self.metadata_size {
            d.insert(b"metadata_size".to_vec(), Value::Int(size as i64));
        }
        d.insert(b"reqq".to_vec(), Value::Int(self.reqq));
        d.insert(b"v".to_vec(), Value::Bytes(self.v.as_bytes().to_vec()));
        bencode::encode(&Value::Dict(d))
    }

    /// Decode a handshake payload. Rejects anything that is not a dictionary,
    /// ignores fields it does not understand, and refuses a `metadata_size`
    /// above [`MAX_METADATA_SIZE`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (v, _) = bencode::decode_partial(bytes)?;
        if v.as_dict().is_err() {
            return Err(DhtError::Protocol(
                "extended handshake is not a dictionary".into(),
            ));
        }
        // Id 0 means "extension disabled" and anything above 255 cannot be a
        // message id; both are treated as unsupported.
        let ut_metadata = v
            .get_opt("m")
            .and_then(|m| m.get_int_opt(UT_METADATA))
            .and_then(|id| u8::try_from(id).ok())
            .filter(|id| *id != EXT_HANDSHAKE_ID);
        let metadata_size = match v.get_int_opt("metadata_size") {
            None => None,
            Some(n) => {
                let n = usize::try_from(n)
                    .map_err(|_| DhtError::Protocol("negative metadata_size".into()))?;
                if n > MAX_METADATA_SIZE {
                    return Err(DhtError::Protocol(format!(
                        "metadata_size {n} exceeds the {MAX_METADATA_SIZE} byte limit"
                    )));
                }
                Some(n)
            }
        };
        Ok(ExtendedHandshake {
            ut_metadata,
            v: v.get_bytes_opt("v")
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default(),
            reqq: v.get_int_opt("reqq").unwrap_or(0),
            metadata_size,
        })
    }
}

/// Encode a BEP 10 message body: `<20><ext_id><bencoded dict>`. The caller
/// adds the 4-byte length prefix via [`write_framed`].
fn encode_ut_message(ext_id: u8, dict: BTreeMap<Vec<u8>, Value>) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(MSG_EXTENDED);
    out.push(ext_id);
    out.extend_from_slice(&bencode::encode(&Value::Dict(dict)));
    out
}

/// A request for one metadata piece, addressed to the peer's `ut_metadata` id.
fn ut_request(peer_ext_id: u8, piece: u32) -> Vec<u8> {
    let mut d = BTreeMap::new();
    d.insert(b"msg_type".to_vec(), Value::Int(i64::from(UT_MSG_REQUEST)));
    d.insert(b"piece".to_vec(), Value::Int(i64::from(piece)));
    encode_ut_message(peer_ext_id, d)
}

/// A decoded `ut_metadata` message. For data messages `data` is the raw piece
/// that follows the bencoded dictionary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtMessage {
    pub msg_type: u8,
    pub piece: u32,
    pub total_size: Option<usize>,
    pub data: Vec<u8>,
}

/// Decode a `ut_metadata` payload (the bytes after `<20><ext_id>`).
///
/// BEP 9 data messages are a bencoded dictionary immediately followed by the
/// raw piece bytes, so the dictionary must be parsed without demanding that
/// the input ends after it.
fn decode_ut_message(payload: &[u8]) -> Result<UtMessage> {
    let (v, rest) = bencode::decode_partial(payload)?;
    let msg_type = v
        .get_int_opt("msg_type")
        .and_then(|n| u8::try_from(n).ok())
        .ok_or_else(|| DhtError::Metadata("ut_metadata message without msg_type".into()))?;
    let piece = v
        .get_int_opt("piece")
        .ok_or_else(|| DhtError::Metadata("ut_metadata message without piece".into()))?;
    let piece =
        u32::try_from(piece).map_err(|_| DhtError::Metadata("negative piece number".into()))?;
    let total_size = v
        .get_int_opt("total_size")
        .and_then(|n| usize::try_from(n).ok());
    Ok(UtMessage {
        msg_type,
        piece,
        total_size,
        data: rest.to_vec(),
    })
}

/// Reads a peer's metadata (its bencoded `info` dict) over `ut_metadata`.
///
/// The sha1 of the assembled dict is checked against the infohash we wanted
/// before anything is handed back.
#[derive(Debug, Clone, Copy)]
pub struct MetadataClient {
    /// Our own BEP 10 client identifier.
    pub client: &'static str,
    /// Advertised request queue length.
    pub reqq: i64,
}

impl Default for MetadataClient {
    fn default() -> Self {
        MetadataClient {
            client: "torrust",
            reqq: 250,
        }
    }
}

impl MetadataClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_client(client: &'static str) -> Self {
        MetadataClient { client, reqq: 250 }
    }

    fn our_handshake(&self) -> ExtendedHandshake {
        ExtendedHandshake::new(Some(LOCAL_UT_METADATA_ID), self.client, self.reqq, None)
    }

    /// Run the whole exchange on an already-connected stream: the BitTorrent
    /// handshake, the BEP 10 handshake, then piece requests.
    pub async fn fetch<S>(
        &self,
        stream: &mut S,
        infohash: InfoHash,
        timeout: Duration,
    ) -> Result<Vec<u8>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let future = self.fetch_inner(stream, infohash);
        match tokio::time::timeout(timeout, future).await {
            Ok(r) => r,
            Err(_) => Err(DhtError::Timeout),
        }
    }

    async fn fetch_inner<S>(&self, stream: &mut S, infohash: InfoHash) -> Result<Vec<u8>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        wire::handshake_outgoing(stream, &infohash.0, true, false, true).await?;
        let bt = wire::handshake_incoming(stream).await?;
        if bt.infohash != infohash.0 {
            return Err(DhtError::Metadata(
                "peer answered for a different infohash".into(),
            ));
        }
        if !bt.supports_extended() {
            return Err(DhtError::Unsupported);
        }
        self.exchange(stream, infohash).await
    }

    /// The BEP 10 handshake and `ut_metadata` exchange, run once both
    /// BitTorrent handshakes are done.
    async fn exchange<S>(&self, stream: &mut S, infohash: InfoHash) -> Result<Vec<u8>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        write_framed(
            stream,
            &[
                &[MSG_EXTENDED, EXT_HANDSHAKE_ID][..],
                &self.our_handshake().encode(),
            ]
            .concat(),
        )
        .await?;

        let mut skipped = 0usize;
        let hs = loop {
            let (ext_id, payload) = read_extended(stream, &mut skipped).await?;
            if ext_id == EXT_HANDSHAKE_ID {
                break ExtendedHandshake::decode(&payload)?;
            }
        };
        let peer_ext_id = hs.ut_metadata.ok_or(DhtError::Unsupported)?;
        let total = hs
            .metadata_size
            .ok_or_else(|| DhtError::Metadata("peer did not advertise a metadata_size".into()))?;
        if total == 0 {
            return Err(DhtError::Metadata("peer advertised empty metadata".into()));
        }
        if total > MAX_METADATA_SIZE {
            return Err(DhtError::Metadata(format!(
                "peer metadata_size {total} exceeds our limit"
            )));
        }
        tracing::debug!(
            infohash = %infohash,
            total,
            client = %if hs.v.is_empty() { "?" } else { hs.v.as_str() },
            "peer handshake ok"
        );

        let piece_count = total.div_ceil(UT_METADATA_PIECE_SIZE);
        let mut info_dict = Vec::with_capacity(total);

        for piece in 0..piece_count {
            let piece_id = u32::try_from(piece).map_err(|_| {
                DhtError::Metadata(format!("piece index {piece} does not fit in a request"))
            })?;
            write_framed(stream, &ut_request(peer_ext_id, piece_id)).await?;
            let expected = (total - piece * UT_METADATA_PIECE_SIZE).min(UT_METADATA_PIECE_SIZE);
            loop {
                let (ext_id, payload) = read_extended(stream, &mut skipped).await?;
                if ext_id != LOCAL_UT_METADATA_ID {
                    continue;
                }
                let msg = decode_ut_message(&payload)?;
                tracing::trace!(
                    piece = msg.piece,
                    msg_type = msg.msg_type,
                    "ut_metadata message"
                );
                match msg.msg_type {
                    UT_MSG_DATA if msg.piece == piece_id => {
                        if msg.data.len() != expected {
                            return Err(DhtError::Metadata(format!(
                                "piece {piece} is {} bytes, expected {expected}",
                                msg.data.len()
                            )));
                        }
                        info_dict.extend_from_slice(&msg.data);
                        break;
                    }
                    UT_MSG_REJECT if msg.piece == piece_id => {
                        return Err(DhtError::Metadata(format!("peer rejected piece {piece}")));
                    }
                    _ => { /* a request from the peer or a stray piece: ignore */ }
                }
            }
        }

        let actual = InfoHash(sha1_bytes(&info_dict));
        if actual != infohash {
            return Err(DhtError::InfoHashMismatch {
                expected: infohash,
                actual,
            });
        }
        tracing::info!(infohash = %infohash, bytes = info_dict.len(), "fetched metadata");
        Ok(info_dict)
    }
}

async fn write_framed<S>(stream: &mut S, payload: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    if payload.len() > MAX_EXT_MESSAGE_LEN {
        return Err(DhtError::Protocol("outgoing message too large".into()));
    }
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

/// Read peer-wire messages until an extended one arrives and return its
/// `(ext_id, payload)`. Everything else is skipped, up to
/// [`MAX_SKIPPED_MESSAGES`] across the whole exchange via `skipped`; message ids
/// we do not implement are skipped too, since `read_message` has already
/// consumed their bytes and the stream stays in sync.
async fn read_extended<S>(stream: &mut S, skipped: &mut usize) -> Result<(u8, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    loop {
        match wire::read_message(stream).await {
            Ok(Message::Extended { ext_id, payload }) => return Ok((ext_id, payload)),
            Ok(_) | Err(WireError::UnknownMessage(_)) => {
                *skipped += 1;
                if *skipped > MAX_SKIPPED_MESSAGES {
                    return Err(DhtError::Metadata(
                        "peer sent too many unrelated messages".into(),
                    ));
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Connect to a peer, do the whole `ut_metadata` exchange and verify the hash.
///
/// `mode` is the encryption policy: `Prefer` tries MSE first and falls back
/// to plaintext, as peer dials do, so peers that only accept encrypted
/// connections can supply metadata too. With `utp` set, a uTP attempt races
/// the TCP one and the first success wins.
pub async fn fetch_metadata_from_peer(
    addr: SocketAddr,
    infohash: InfoHash,
    timeout: Duration,
    mode: EncryptionMode,
    utp: Option<Arc<crate::utp::UtpSocket>>,
) -> Result<Vec<u8>> {
    let tcp = fetch_with_policy(addr, infohash, timeout, mode, || async {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true).ok();
        Ok(stream)
    });
    let whole = async {
        let Some(utp) = utp else { return tcp.await };
        let utp = fetch_with_policy(addr, infohash, timeout, mode, || async {
            Ok(utp.connect(addr).await?)
        });
        futures::future::select_ok([
            Box::pin(tcp) as std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + '_>>,
            Box::pin(utp),
        ])
            .await
            .map(|(meta, _)| meta)
    };
    match tokio::time::timeout(timeout, whole).await {
        Ok(r) => r,
        Err(_) => Err(DhtError::Timeout),
    }
}

/// The MSE-then-plaintext policy over one transport, dialled by `connect`.
async fn fetch_with_policy<S, F, Fut>(
    addr: SocketAddr,
    infohash: InfoHash,
    timeout: Duration,
    mode: EncryptionMode,
    connect: F,
) -> Result<Vec<u8>>
where
    S: crate::peer::AsyncStream,
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<S>>,
{
    if mode != EncryptionMode::Disabled {
        // Leave a plaintext retry some of the budget under `Prefer`.
        let budget = if mode == EncryptionMode::Prefer { timeout / 2 } else { timeout };
        match tokio::time::timeout(budget, fetch_over(connect(), infohash, budget, Some(mode))).await {
            Ok(Ok(meta)) => return Ok(meta),
            Ok(Err(e)) if mode == EncryptionMode::Require => return Err(e),
            Err(_) if mode == EncryptionMode::Require => return Err(DhtError::Timeout),
            Ok(Err(e)) => tracing::trace!(peer = %addr, error = %e, "encrypted metadata fetch failed, retrying plaintext"),
            Err(_) => tracing::trace!(peer = %addr, "encrypted metadata fetch timed out, retrying plaintext"),
        }
    }
    fetch_over(connect(), infohash, timeout, None).await
}

/// One connection's metadata exchange, wrapped in MSE when `mse` is set.
async fn fetch_over<S>(
    connecting: impl std::future::Future<Output = Result<S>>,
    infohash: InfoHash,
    timeout: Duration,
    mse: Option<EncryptionMode>,
) -> Result<Vec<u8>>
where
    S: crate::peer::AsyncStream,
{
    let stream = connecting.await?;
    match mse {
        Some(mode) => {
            let mut stream = crate::peer::mse::connect(stream, infohash, mode)
                .await
                .map_err(|e| DhtError::Metadata(format!("encryption handshake: {e:#}")))?;
            MetadataClient::new().fetch(&mut stream, infohash, timeout).await
        }
        None => {
            let mut stream = stream;
            MetadataClient::new().fetch(&mut stream, infohash, timeout).await
        }
    }
}

/// Fetch the metadata over a connection the listener accepted: `hs` is the
/// peer's BitTorrent handshake, which the listener has already read (after
/// MSE, if any). Replies with our own handshake and runs the exchange.
pub async fn fetch_metadata_inbound(
    stream: &mut crate::peer::PeerStream,
    hs: &wire::Handshake,
    infohash: InfoHash,
    timeout: Duration,
) -> Result<Vec<u8>> {
    if hs.infohash != infohash.0 {
        return Err(DhtError::Metadata("peer asked for a different infohash".into()));
    }
    if !hs.supports_extended() {
        return Err(DhtError::Unsupported);
    }
    let run = async {
        wire::handshake_outgoing(stream, &infohash.0, true, false, true).await?;
        MetadataClient::new().exchange(stream, infohash).await
    };
    match tokio::time::timeout(timeout, run).await {
        Ok(r) => r,
        Err(_) => Err(DhtError::Timeout),
    }
}

/// Spin up a DHT node, bootstrap, find peers for `infohash` and ask them for
/// the metadata until one supplies a dict with the right hash.
///
/// Peers are queried [`METADATA_CONCURRENCY`] at a time with a short
/// per-peer timeout, because most peers handed out by the DHT are dead or
/// unresponsive and trying them one by one would take minutes. `timeout` bounds
/// the whole peer phase.
pub async fn fetch_metadata(
    infohash: InfoHash,
    routers: &[String],
    timeout: Duration,
    mode: EncryptionMode,
) -> Result<Vec<u8>> {
    let node = DhtNode::new(None).await?;
    node.bootstrap(routers).await;
    fetch_metadata_with_node(&node, infohash, timeout, mode, None).await
}

/// Like [`fetch_metadata`] on an already running, bootstrapped node.
pub async fn fetch_metadata_with_node(
    node: &DhtNode,
    infohash: InfoHash,
    timeout: Duration,
    mode: EncryptionMode,
    utp: Option<Arc<crate::utp::UtpSocket>>,
) -> Result<Vec<u8>> {
    let mut peers = node.get_peers(infohash).await?;
    peers.sort_unstable();
    peers.dedup();
    if peers.is_empty() {
        tracing::warn!(infohash = %infohash, "dht returned no peers for metadata");
        return Err(DhtError::Metadata("no peers found for infohash".into()));
    }
    fetch_metadata_from_peers(peers, infohash, timeout, mode, utp).await
}

/// Ask `peers` for the metadata of `infohash`, [`METADATA_CONCURRENCY`] at a
/// time with a short per-peer timeout, returning the first dict whose hash
/// verifies. `timeout` bounds the whole call.
pub async fn fetch_metadata_from_peers(
    peers: Vec<SocketAddr>,
    infohash: InfoHash,
    timeout: Duration,
    mode: EncryptionMode,
    utp: Option<Arc<crate::utp::UtpSocket>>,
) -> Result<Vec<u8>> {
    tracing::info!(infohash = %infohash, peers = peers.len(), "asking peers for metadata");

    let deadline = tokio::time::Instant::now() + timeout;
    let per_peer = timeout.min(PER_PEER_TIMEOUT);
    let mut queue = peers.into_iter().take(METADATA_MAX_PEERS);
    let mut inflight = FuturesUnordered::new();
    let mut last_error: Option<DhtError> = None;

    loop {
        while inflight.len() < METADATA_CONCURRENCY {
            let Some(peer) = queue.next() else { break };
            let utp = utp.clone();
            inflight.push(async move {
                (
                    peer,
                    fetch_metadata_from_peer(peer, infohash, per_peer, mode, utp).await,
                )
            });
        }
        match tokio::time::timeout_at(deadline, inflight.next()).await {
            Err(_) => return Err(DhtError::Timeout),
            Ok(None) => break,
            Ok(Some((_, Ok(meta)))) => return Ok(meta),
            Ok(Some((peer, Err(e)))) => {
                tracing::debug!(peer = %peer, error = %e, "peer did not supply metadata");
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| DhtError::Metadata("no peers answered".into())))
}

/// Same as [`fetch_metadata`] but using [`DEFAULT_ROUTERS`].
pub async fn fetch_metadata_default(infohash: InfoHash, timeout: Duration) -> Result<Vec<u8>> {
    let routers: Vec<String> = DEFAULT_ROUTERS.iter().map(|s| (*s).to_owned()).collect();
    fetch_metadata(infohash, &routers, timeout, EncryptionMode::Prefer).await
}

/// Bootstrap using [`DEFAULT_ROUTERS`] and return the resulting node.
pub async fn new_bootstrapped_node() -> Result<(DhtNode, usize)> {
    let node = DhtNode::new(None).await?;
    let routers: Vec<String> = DEFAULT_ROUTERS.iter().map(|s| (*s).to_owned()).collect();
    let reachable = node.bootstrap(&routers).await;
    Ok((node, reachable))
}

// ------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn node_id(byte: u8) -> NodeId {
        NodeId([byte; 20])
    }

    fn compact6(port: u16) -> Info {
        let mut b = [0u8; 18];
        b[15] = 1; // ::1
        b[16..].copy_from_slice(&port.to_be_bytes());
        Info::Compact6(b)
    }

    // ---- Info

    #[test]
    fn info_id20_round_trips() {
        let hex = "0123456789abcdef0123456789abcdef01234567";
        let info: Info = hex.parse().unwrap();
        assert_eq!(
            info,
            Info::Id20([
                1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef, 0x01, 0x23, 0x45, 0x67
            ])
        );
        assert_eq!(info.to_string(), hex);
        assert_eq!(hex.parse::<Info>().unwrap().to_string(), hex);
    }

    #[test]
    fn info_accepts_0x_prefix() {
        let hex = "0123456789abcdef0123456789abcdef01234567";
        let with = format!("0x{hex}");
        assert_eq!(with.parse::<Info>().unwrap(), hex.parse::<Info>().unwrap());
    }

    #[test]
    fn info_compact_round_trips() {
        let info = Info::Compact([192, 168, 1, 5, 0x1a, 0xe1]); // 6881
        let text = info.to_string();
        assert_eq!(text, "c0a801051ae1");
        assert_eq!(text.parse::<Info>().unwrap(), info);
        let addr = info.socket_addr().unwrap();
        assert_eq!(addr.to_string(), "192.168.1.5:6881");
    }

    #[test]
    fn info_compact6_round_trips() {
        let info = compact6(6881);
        let text = info.to_string();
        assert_eq!(text.len(), 36);
        assert_eq!(text.parse::<Info>().unwrap(), info);
        assert_eq!(info.socket_addr().unwrap().to_string(), "[::1]:6881");
    }

    #[test]
    fn info_rejects_zero_port() {
        assert!("c0a801050000".parse::<Info>().is_err());
        let mut v6 = [0u8; 18];
        v6[15] = 1;
        assert!(Info::Compact6(v6).to_string().parse::<Info>().is_err());
    }

    #[test]
    fn info_rejects_bad_lengths() {
        assert!("".parse::<Info>().is_err());
        assert!("abcd".parse::<Info>().is_err());
        assert!("zz".repeat(20).parse::<Info>().is_err());
        // Right length, not hex.
        assert!("zz0123456789abcdef0123456789abcdef012345"
            .parse::<Info>()
            .is_err());
    }

    // ---- NodeId and distance

    #[test]
    fn distance_is_symmetric_and_bounded() {
        let a = node_id(0);
        let b = node_id(255);
        assert_eq!(distance(&a.0, &b.0), distance(&b.0, &a.0));
        assert_eq!(distance(&a.0, &a.0), [0u8; 20]);
        assert_eq!(a.distance(&b), b.distance(&a));
        let c = NodeId([0xff; 20]);
        assert_eq!(distance(&b.0, &c.0), [0u8; 20]);
    }

    #[test]
    fn distance_orders_by_first_differing_bit() {
        let target = [0u8; 20];
        let mut near = target;
        near[19] = 1; // distance 1
        let mut far = target;
        far[0] = 1; // distance 2^152
        assert!(distance(&near, &target) < distance(&far, &target));
    }

    #[test]
    fn random_node_ids_differ() {
        assert_ne!(NodeId::random(), NodeId::random());
        assert_eq!(NodeId::random().0.len(), 20);
    }

    // ---- routing table

    #[test]
    fn find_closest_orders_by_xor_distance() {
        let target = node_id(0);
        let mut table = RoutingTable::new(target);
        let mut ids = Vec::new();
        for i in 1..=40u8 {
            let mut id = [0u8; 20];
            id[0] = i;
            ids.push(NodeId(id));
        }
        for id in &ids {
            table.insert(
                *id,
                SocketAddr::from(([127, 0, 0, 1], 1000 + u16::from(id.0[0]))),
            );
        }
        let got = table.find_closest(&target, 5);
        assert_eq!(got.len(), 5);
        // The five closest are the ids with the smallest first byte.
        for w in got.windows(2) {
            assert!(w[0].id.distance(&target) <= w[1].id.distance(&target));
        }
        assert_eq!(
            got[0].id,
            NodeId([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );
        // Buckets are capped, so a large insert round is lossy by design.
        assert!(table.len() <= 40);
    }

    #[test]
    fn find_closest_excludes_self_and_respects_k() {
        let target = node_id(7);
        let mut table = RoutingTable::new(target);
        for i in 1..=20u8 {
            let mut id = target.0;
            id[0] = id[0].wrapping_add(i);
            table.insert(
                NodeId(id),
                SocketAddr::from(([10, 0, 0, 1], 7000 + u16::from(i))),
            );
        }
        let got = table.find_closest(&target, 3);
        assert_eq!(got.len(), 3);
        assert!(got.iter().all(|c| c.id != target));
    }

    #[test]
    fn buckets_are_capped_by_lru() {
        let me = node_id(0);
        let mut table = RoutingTable::new(me);
        // All these ids fall in the same bucket (first byte differs, bit 0).
        for i in 1..=(BUCKET_CAP as u8 + 6) {
            let mut id = [0u8; 20];
            id[0] = i.wrapping_mul(2).max(1);
            id[0] |= 1; // keep them all in the same half of the tree
            id[19] = i;
            table.insert(
                NodeId(id),
                SocketAddr::from(([10, 0, 0, 1], u16::from(i) + 5000)),
            );
        }
        assert!(table.len() <= BUCKET_CAP * BUCKET_COUNT);
        // Good nodes are ordered freshest first.
        let good = table.good_nodes();
        for w in good.windows(2) {
            assert!(w[0].last_seen >= w[1].last_seen);
        }
    }

    #[test]
    fn insert_refreshes_existing_contact() {
        let me = node_id(0);
        let mut table = RoutingTable::new(me);
        let mut id = [0u8; 20];
        id[0] = 2;
        let addr = SocketAddr::from(([1, 2, 3, 4], 6881));
        table.insert(NodeId(id), addr);
        assert_eq!(table.len(), 1);
        table.insert(NodeId(id), addr);
        assert_eq!(table.len(), 1);
        assert!(table.get(&NodeId(id)).is_some());
        assert!(table.get_by_addr(&addr).is_some());
    }

    // ---- BencodedNode

    #[test]
    fn bencoded_node_round_trips() {
        let mut id = [0u8; 20];
        for (i, b) in id.iter_mut().enumerate() {
            *b = i as u8 * 7;
        }
        let node = BencodedNode {
            id: NodeId(id),
            addr: SocketAddr::from(([192, 168, 0, 9], 51413)),
        };
        let bytes = node.to_bytes();
        assert_eq!(bytes.len(), 26);
        assert_eq!(BencodedNode::from_bytes(&bytes).unwrap(), node);
    }

    #[test]
    fn bencoded_node_rejects_wrong_length() {
        assert!(BencodedNode::from_bytes(&[0u8; 25]).is_err());
        assert!(BencodedNode::from_bytes(&[0u8; 27]).is_err());
        assert!(BencodedNode::from_bytes(&[]).is_err());
        // Right length, zero port: still rejected.
        let mut b = [0u8; 26];
        b[0] = 1;
        assert!(BencodedNode::from_bytes(&b).is_err());
    }

    #[test]
    fn nodes_blob_parses_and_tolerates_garbage() {
        let a = BencodedNode {
            id: node_id(1),
            addr: SocketAddr::from(([10, 0, 0, 1], 1000)),
        };
        let mut blob = a.to_bytes();
        blob.extend_from_slice(&[0u8; 26]); // second node with a zero port
        let parsed = parse_nodes(&Value::Bytes(blob)).unwrap();
        assert_eq!(parsed, vec![a]);
        // A blob that is not a multiple of 26 is an error, not a panic.
        assert!(parse_nodes(&Value::Bytes(vec![0u8; 13])).is_err());
    }

    // ---- KRPC

    #[test]
    fn krpc_query_round_trips() {
        let tid = TransactionId(*b"ab");
        let queries = vec![
            Query::Ping,
            Query::FindNode { target: node_id(3) },
            Query::GetPeers {
                infohash: InfoHash([9; 20]),
                want: Some(node_id(4)),
            },
            Query::AnnouncePeer {
                infohash: InfoHash([8; 20]),
                port: 51413,
                token: vec![1, 2, 3, 4, 5, 6, 7, 8],
                implied_port: false,
            },
        ];
        for q in queries {
            let bytes = encode_query(tid, node_id(2), &q);
            match decode_message(&bytes).unwrap() {
                Inbound::Query(msg) => {
                    assert_eq!(msg.tid, tid);
                    assert_eq!(msg.id, node_id(2));
                    assert_eq!(msg.query, q);
                }
                other => panic!("expected a query, got {other:?}"),
            }
        }
    }

    #[test]
    fn krpc_get_peers_query_omits_want_when_absent() {
        let bytes = encode_query(
            TransactionId(*b"qq"),
            node_id(2),
            &Query::GetPeers {
                infohash: InfoHash([1; 20]),
                want: None,
            },
        );
        assert!(!bytes.windows(4).any(|w| w == b"want"));
        match decode_message(&bytes).unwrap() {
            Inbound::Query(m) => assert_eq!(
                m.query,
                Query::GetPeers {
                    infohash: InfoHash([1; 20]),
                    want: None
                }
            ),
            other => panic!("expected a query, got {other:?}"),
        }
    }

    #[test]
    fn krpc_nodes_response_round_trips() {
        let nodes = vec![
            BencodedNode {
                id: node_id(1),
                addr: SocketAddr::from(([1, 2, 3, 4], 1001)),
            },
            BencodedNode {
                id: node_id(2),
                addr: SocketAddr::from(([1, 2, 3, 5], 1002)),
            },
        ];
        let bytes = encode_response(
            TransactionId(*b"nn"),
            node_id(5),
            &ResponsePayload::Nodes(nodes.clone()),
        );
        match decode_message(&bytes).unwrap() {
            Inbound::Response(r) => {
                assert_eq!(r.id, node_id(5));
                assert_eq!(r.payload, ResponsePayload::Nodes(nodes));
            }
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[test]
    fn krpc_get_peers_response_round_trips() {
        let payload = ResponsePayload::GetPeers {
            token: b"tok".to_vec(),
            nodes: vec![BencodedNode {
                id: node_id(6),
                addr: SocketAddr::from(([9, 9, 9, 9], 6882)),
            }],
            values: vec![SocketAddr::from(([8, 8, 8, 8], 6881))],
        };
        let bytes = encode_response(TransactionId(*b"pp"), node_id(5), &payload);
        match decode_message(&bytes).unwrap() {
            Inbound::Response(r) => assert_eq!(r.payload, payload),
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[test]
    fn krpc_ping_response_is_empty_payload() {
        let bytes = encode_response(TransactionId(*b"rr"), node_id(5), &ResponsePayload::Empty);
        match decode_message(&bytes).unwrap() {
            Inbound::Response(r) => assert_eq!(r.payload, ResponsePayload::Empty),
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[test]
    fn krpc_error_round_trips() {
        let bytes = encode_error(TransactionId(*b"ee"), 201, "generic error");
        match decode_message(&bytes).unwrap() {
            Inbound::Error(e) => {
                assert_eq!(e.tid, TransactionId(*b"ee"));
                assert_eq!(e.code, 201);
                assert_eq!(e.message, "generic error");
            }
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn krpc_decodes_a_hand_written_query() {
        let raw = b"d1:ad2:id20:012345678901234567896:target20:01234567890123456789e\
1:q9:find_node1:t2:aa1:y1:qe";
        match decode_message(raw).unwrap() {
            Inbound::Query(m) => {
                assert_eq!(m.id, NodeId(*b"01234567890123456789"));
                assert_eq!(
                    m.query,
                    Query::FindNode {
                        target: NodeId(*b"01234567890123456789")
                    }
                );
            }
            other => panic!("expected a query, got {other:?}"),
        }
    }

    #[test]
    fn garbage_packets_error_instead_of_panicking() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            b"garbage".to_vec(),
            b"d".to_vec(),
            b"de".to_vec(),
            b"d1:t".to_vec(),
            b"d1:t2:aae".to_vec(),
            b"d1:t3:aaae".to_vec(),      // transaction id must be 2 bytes
            b"d1:t2:aa1:y1:qe".to_vec(), // no `q`
            b"d1:t2:aa1:y1:qe1:q4:ping".to_vec(), // no `a`
            b"d1:t2:aa1:y1:qe1:q4:ping1:ad1:id5:shorte".to_vec(), // short id
            b"d1:t2:aa1:y1:xe".to_vec(), // bad `y`
            b"d1:t2:aa1:y1:re".to_vec(), // empty `r`
            b"d1:t2:aa1:y1:re1:rd1:id5:shortee".to_vec(),
            b"d1:t2:aa1:y1:re1:rd1:id20:012345678901234567891:peersli1ee1:peers".to_vec(),
            b"d1:t2:aa1:y1:ee".to_vec(),   // error with no list
            b"d1:t2:aa1:y1:elee".to_vec(), // error list with no code
            b"i1e".to_vec(),
            b"l".to_vec(),
            b"9999999999:short".to_vec(),
            b"d1:t2:aa1:y1:re1:rd6:valuesli3:abc1:xi2eee".to_vec(),
        ];
        for payload in cases {
            let res = decode_message(&payload);
            assert!(
                res.is_err(),
                "expected an error for {:?}",
                String::from_utf8_lossy(&payload)
            );
        }
    }
    // ---- extended handshake

    #[test]
    fn extended_handshake_round_trips() {
        let hs = ExtendedHandshake::new(Some(1), "torrust", 250, Some(1234));
        let bytes = hs.encode();
        assert_eq!(ExtendedHandshake::decode(&bytes).unwrap(), hs);
    }

    #[test]
    fn extended_handshake_encodes_m_as_a_dictionary() {
        let hs = ExtendedHandshake::new(Some(1), "torrust", 100, Some(42));
        assert_eq!(
            hs.encode(),
            b"d1:md11:ut_metadatai1ee13:metadata_sizei42e4:reqqi100e1:v7:torruste".to_vec()
        );
    }

    #[test]
    fn handshake_without_metadata_size_omits_the_key() {
        let hs = ExtendedHandshake::new(Some(1), "torrust", 250, None);
        let bytes = hs.encode();
        assert_eq!(
            bytes,
            b"d1:md11:ut_metadatai1ee4:reqqi250e1:v7:torruste".to_vec()
        );
        let back = ExtendedHandshake::decode(&bytes).unwrap();
        assert_eq!(back.metadata_size, None);
        assert!(back.supports_ut_metadata());
    }

    #[test]
    fn handshake_decodes_a_real_client_message() {
        let raw = b"d1:md11:ut_metadatai3e6:ut_pexi2ee13:metadata_sizei42e4:porti6881e4:reqqi100e1:v7:torrust6:yourip4:\x7f\x00\x00\x01e";
        let hs = ExtendedHandshake::decode(raw).unwrap();
        assert_eq!(hs.ut_metadata, Some(3));
        assert_eq!(hs.metadata_size, Some(42));
        assert_eq!(hs.reqq, 100);
        assert_eq!(hs.v, "torrust");
    }

    #[test]
    fn handshake_without_ut_metadata_is_unsupported() {
        let hs = ExtendedHandshake::decode(b"d1:md6:ut_pexi2eee").unwrap();
        assert!(!hs.supports_ut_metadata());
        let zero = ExtendedHandshake::decode(b"d1:md11:ut_metadatai0eee").unwrap();
        assert!(!zero.supports_ut_metadata());
        let wide = ExtendedHandshake::decode(b"d1:md11:ut_metadatai300eee").unwrap();
        assert!(!wide.supports_ut_metadata());
    }

    #[test]
    fn handshake_rejects_bad_input() {
        assert!(ExtendedHandshake::decode(b"").is_err());
        assert!(ExtendedHandshake::decode(b"x").is_err());
        assert!(ExtendedHandshake::decode(b"d").is_err());
        assert!(ExtendedHandshake::decode(b"i5e").is_err());
        assert!(ExtendedHandshake::decode(b"d1:md11:ut_metadat").is_err());
        assert!(ExtendedHandshake::decode(b"d13:metadata_sizei-1e1:v2:txe").is_err());
        let big = "d13:metadata_sizei9999999999e1:v2:txe";
        assert!(ExtendedHandshake::decode(big.as_bytes()).is_err());
    }

    // ---- ut_metadata messages

    #[test]
    fn ut_request_has_bep10_framing() {
        let msg = ut_request(3, 5);
        assert_eq!(msg[0], MSG_EXTENDED);
        assert_eq!(msg[1], 3);
        let body = bencode::decode(&msg[2..]).unwrap();
        assert_eq!(body.get("msg_type").unwrap().as_int().unwrap(), 0);
        assert_eq!(body.get("piece").unwrap().as_int().unwrap(), 5);
    }

    #[test]
    fn ut_data_message_splits_dict_from_raw_bytes() {
        let mut d = BTreeMap::new();
        d.insert(b"msg_type".to_vec(), Value::Int(1));
        d.insert(b"piece".to_vec(), Value::Int(2));
        d.insert(b"total_size".to_vec(), Value::Int(4));
        let mut encoded = encode_ut_message(1, d);
        encoded.extend_from_slice(&[1, 2, 3, 4]);
        let msg = decode_ut_message(&encoded[2..]).unwrap();
        assert_eq!(msg.msg_type, UT_MSG_DATA);
        assert_eq!(msg.piece, 2);
        assert_eq!(msg.data, vec![1, 2, 3, 4]);
        assert_eq!(msg.total_size, Some(4));
        assert!(decode_ut_message(b"not bencode").is_err());
        assert!(decode_ut_message(b"").is_err());
        assert!(decode_ut_message(b"di5ei1ee").is_err());
        assert!(decode_ut_message(b"d5:piecei0ee").is_err());
    }

    // ---- live node behaviour

    // ---- hardening

    fn contact_addr(n: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, n], 6881))
    }

    fn same_bucket_id(n: u8) -> NodeId {
        let mut id = [0u8; 20];
        id[0] = 0x80;
        id[19] = n;
        NodeId(id)
    }

    fn full_table() -> RoutingTable {
        let mut table = RoutingTable::new(node_id(0));
        for n in 1..=BUCKET_CAP as u8 {
            table.insert(same_bucket_id(n), contact_addr(n));
        }
        assert_eq!(table.len(), BUCKET_CAP);
        table
    }

    fn age_all(table: &mut RoutingTable) {
        for c in table.buckets.iter_mut().flat_map(|b| b.contacts.iter_mut()) {
            c.last_seen = Instant::now() - FRESH_FOR - Duration::from_secs(1);
        }
    }

    #[test]
    fn known_id_is_not_rebound_to_a_new_address() {
        let mut table = RoutingTable::new(node_id(0));
        let id = same_bucket_id(1);
        table.insert(id, contact_addr(1));
        table.insert(id, contact_addr(99));
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(&id).unwrap().addr, contact_addr(1));
        assert!(table.get_by_addr(&contact_addr(99)).is_none());
    }

    #[test]
    fn known_address_is_not_taken_over_by_another_id() {
        let mut table = RoutingTable::new(node_id(0));
        table.insert(same_bucket_id(1), contact_addr(1));
        table.insert(same_bucket_id(2), contact_addr(1));
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.get_by_addr(&contact_addr(1)).unwrap().id,
            same_bucket_id(1)
        );
    }

    #[test]
    fn full_bucket_keeps_good_nodes() {
        let mut table = full_table();
        assert!(table
            .insert(same_bucket_id(100), contact_addr(100))
            .is_none());
        assert_eq!(table.len(), BUCKET_CAP);
        assert!(table.get(&same_bucket_id(100)).is_none());
        for n in 1..=BUCKET_CAP as u8 {
            assert!(table.get(&same_bucket_id(n)).is_some());
        }
    }

    #[test]
    fn full_bucket_pings_the_stalest_node_instead_of_evicting_it() {
        let mut table = full_table();
        age_all(&mut table);
        let target = table.insert(same_bucket_id(100), contact_addr(100));
        assert!(target.is_some());
        assert_eq!(table.len(), BUCKET_CAP);
        assert!(table.get(&same_bucket_id(100)).is_none());
        let again = table.insert(same_bucket_id(101), contact_addr(101));
        assert_ne!(
            again, target,
            "a node already being probed is not probed twice"
        );
        let probed = table.get_by_addr(&target.unwrap()).unwrap().id;
        table.insert(probed, target.unwrap());
        assert!(table.get(&probed).is_some());
        assert_eq!(table.get(&probed).unwrap().failures, 0);
    }

    #[test]
    fn full_bucket_replaces_a_bad_node() {
        let mut table = full_table();
        table.fail(&contact_addr(3));
        table.fail(&contact_addr(3));
        table.insert(same_bucket_id(100), contact_addr(100));
        assert_eq!(table.len(), BUCKET_CAP);
        assert!(table.get(&same_bucket_id(3)).is_none());
        assert!(table.get(&same_bucket_id(100)).is_some());
    }

    #[test]
    fn tokens_are_bound_to_ip_and_infohash_and_rotate() {
        let ip = IpAddr::from([1, 2, 3, 4]);
        let ih = InfoHash([7; 20]);
        let a = make_token(&[1; 20], ip, ih);
        assert_eq!(a.len(), 20);
        assert_ne!(a, make_token(&[1; 20], IpAddr::from([1, 2, 3, 5]), ih));
        assert_ne!(a, make_token(&[1; 20], ip, InfoHash([8; 20])));
        assert_ne!(a, make_token(&[2; 20], ip, ih));
    }

    async fn raw_socket() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    async fn recv_msg(sock: &UdpSocket) -> (Inbound, SocketAddr) {
        let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
        let (n, from) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .expect("no datagram arrived")
            .unwrap();
        (decode_message(&buf[..n]).unwrap(), from)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn spoofed_response_from_another_address_is_ignored() {
        let node = DhtNode::new(None).await.unwrap();
        let real = raw_socket().await;
        let spoofer = raw_socket().await;
        let real_addr = real.local_addr().unwrap();
        let spoofer_addr = spoofer.local_addr().unwrap();

        let pinger = async { node.ping(compact_127(real_addr.port())).await };
        let responder = async {
            let (msg, from) = recv_msg(&real).await;
            let Inbound::Query(q) = msg else {
                panic!("expected a query")
            };
            let node_addr = SocketAddr::from(([127, 0, 0, 1], node.local_addr().port()));
            spoofer
                .send_to(
                    &encode_response(q.tid, node_id(0xEE), &ResponsePayload::Empty),
                    node_addr,
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(node.shared.pending.lock().unwrap().contains_key(&q.tid.0));
            real.send_to(
                &encode_response(q.tid, node_id(0x11), &ResponsePayload::Empty),
                from,
            )
            .await
            .unwrap();
        };
        let (res, ()) = tokio::join!(pinger, responder);
        res.unwrap();
        let contacts = node.good_nodes();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].id, node_id(0x11));
        assert_eq!(contacts[0].addr, real_addr);
        assert!(contacts.iter().all(|c| c.addr != spoofer_addr));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unsolicited_response_adds_no_contact() {
        let node = DhtNode::new(None).await.unwrap();
        let sock = raw_socket().await;
        let node_addr = SocketAddr::from(([127, 0, 0, 1], node.local_addr().port()));
        sock.send_to(
            &encode_response(
                TransactionId(*b"zz"),
                node_id(0x42),
                &ResponsePayload::Empty,
            ),
            node_addr,
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(node.node_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn transaction_ids_are_not_sequential() {
        let node = DhtNode::new(None).await.unwrap();
        let addr = contact_addr(1);
        let tids: Vec<[u8; 2]> = (0..16)
            .map(|_| node.shared.begin(addr).unwrap().0 .0)
            .collect();
        let sequential = tids
            .windows(2)
            .all(|w| u16::from_be_bytes(w[1]) == u16::from_be_bytes(w[0]).wrapping_add(1));
        assert!(!sequential);
        assert_eq!(node.shared.pending.lock().unwrap().len(), 16);
    }

    async fn fake_remote(
        reply: impl Fn(&QueryMsg) -> ResponsePayload + Send + 'static,
    ) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<Query>) {
        let sock = raw_socket().await;
        let addr = sock.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                if let Ok(Inbound::Query(q)) = decode_message(&buf[..n]) {
                    let _ = tx.send(q.query.clone());
                    let out = encode_response(q.tid, node_id(0x33), &reply(&q));
                    let _ = sock.send_to(&out, from).await;
                }
            }
        });
        (addr, rx)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn announce_echoes_the_token_from_get_peers() {
        let (remote, mut seen) = fake_remote(|q| match q.query {
            Query::GetPeers { .. } => ResponsePayload::GetPeers {
                token: b"remote-token".to_vec(),
                nodes: Vec::new(),
                values: Vec::new(),
            },
            _ => ResponsePayload::Empty,
        })
        .await;
        let node = DhtNode::new(None).await.unwrap();
        node.add_node(compact_127(remote.port())).await;
        node.announce(InfoHash([5; 20]), 51413).await.unwrap();
        let mut announced = None;
        while let Ok(q) = seen.try_recv() {
            if let Query::AnnouncePeer { token, port, .. } = q {
                announced = Some((token, port));
            }
        }
        assert_eq!(announced, Some((b"remote-token".to_vec(), 51413)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn announce_without_a_token_sends_nothing() {
        let (remote, mut seen) = fake_remote(|_| ResponsePayload::Empty).await;
        let node = DhtNode::new(None).await.unwrap();
        node.add_node(compact_127(remote.port())).await;
        node.announce(InfoHash([5; 20]), 51413).await.unwrap();
        while let Ok(q) = seen.try_recv() {
            assert!(!matches!(q, Query::AnnouncePeer { .. }));
        }
    }

    async fn ask(sock: &UdpSocket, node: SocketAddr, tid: &[u8; 2], q: &Query) -> Inbound {
        let msg = encode_query(TransactionId(*tid), node_id(0x77), q);
        sock.send_to(&msg, node).await.unwrap();
        recv_msg(sock).await.0
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn inbound_announce_checks_the_token() {
        let node = DhtNode::new(None).await.unwrap();
        let node_addr = SocketAddr::from(([127, 0, 0, 1], node.local_addr().port()));
        let sock = raw_socket().await;
        let infohash = InfoHash([9; 20]);

        let Inbound::Response(r) = ask(
            &sock,
            node_addr,
            b"g1",
            &Query::GetPeers {
                infohash,
                want: None,
            },
        )
        .await
        else {
            panic!("expected a get_peers response")
        };
        let ResponsePayload::GetPeers { token, .. } = r.payload else {
            panic!("expected a token")
        };

        let announce = |token: Vec<u8>, infohash: InfoHash| Query::AnnouncePeer {
            infohash,
            port: 6881,
            token,
            implied_port: false,
        };
        match ask(
            &sock,
            node_addr,
            b"a1",
            &announce(b"bogus".to_vec(), infohash),
        )
        .await
        {
            Inbound::Error(e) => assert_eq!(e.code, 203),
            other => panic!("expected error 203, got {other:?}"),
        }
        match ask(
            &sock,
            node_addr,
            b"a2",
            &announce(token.clone(), InfoHash([10; 20])),
        )
        .await
        {
            Inbound::Error(e) => assert_eq!(e.code, 203),
            other => panic!("expected error 203, got {other:?}"),
        }
        match ask(&sock, node_addr, b"a3", &announce(token, infohash)).await {
            Inbound::Response(r) => assert_eq!(r.payload, ResponsePayload::Empty),
            other => panic!("expected an ack, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_previous_token_secret_is_still_accepted() {
        let node = DhtNode::new(None).await.unwrap();
        let ip = IpAddr::from([127, 0, 0, 1]);
        let ih = InfoHash([4; 20]);
        let old = node.shared.token_for(ip, ih);
        {
            let mut s = node.shared.secrets.lock().unwrap();
            s.rotated = Instant::now() - SECRET_ROTATION;
        }
        assert!(node.shared.token_valid(ip, ih, &old));
        assert_ne!(node.shared.token_for(ip, ih), old);
        {
            let mut s = node.shared.secrets.lock().unwrap();
            s.rotated = Instant::now() - SECRET_ROTATION;
        }
        assert!(!node.shared.token_valid(ip, ih, &old));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn nodes_are_never_returned_as_peers() {
        let decoy = SocketAddr::from(([203, 0, 113, 9], 4444));
        let peer = SocketAddr::from(([198, 51, 100, 7], 5555));
        let (remote, _seen) = fake_remote(move |_| ResponsePayload::GetPeers {
            token: b"t".to_vec(),
            nodes: vec![BencodedNode {
                id: node_id(0x55),
                addr: decoy,
            }],
            values: vec![peer],
        })
        .await;
        let node = DhtNode::new(None).await.unwrap();
        node.add_node(compact_127(remote.port())).await;
        let peers = node.get_peers(InfoHash([6; 20])).await.unwrap();
        assert_eq!(peers, vec![peer]);

        let (nodes_only, _seen2) = fake_remote(move |_| ResponsePayload::GetPeers {
            token: b"t".to_vec(),
            nodes: vec![BencodedNode {
                id: node_id(0x56),
                addr: decoy,
            }],
            values: Vec::new(),
        })
        .await;
        let node2 = DhtNode::new(None).await.unwrap();
        node2.add_node(compact_127(nodes_only.port())).await;
        assert!(node2.get_peers(InfoHash([6; 20])).await.unwrap().is_empty());
    }

    #[test]
    fn values_that_look_like_nodes_are_not_peers() {
        let node = BencodedNode {
            id: node_id(1),
            addr: SocketAddr::from(([1, 2, 3, 4], 5)),
        };
        let mut body = b"d1:rd2:id20:".to_vec();
        body.extend_from_slice(&[5u8; 20]);
        body.extend_from_slice(b"5:token1:t6:valuesl26:");
        body.extend_from_slice(&node.to_bytes());
        body.extend_from_slice(b"6:");
        body.extend_from_slice(&[8, 8, 8, 8, 0x1a, 0xe1]);
        body.extend_from_slice(b"ee1:t2:aa1:y1:re");
        match decode_message(&body).unwrap() {
            Inbound::Response(r) => match r.payload {
                ResponsePayload::GetPeers { values, .. } => {
                    assert_eq!(values, vec![SocketAddr::from(([8, 8, 8, 8], 6881))]);
                }
                other => panic!("unexpected payload {other:?}"),
            },
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn our_get_peers_reply_has_nodes_and_a_token() {
        let node = DhtNode::new(None).await.unwrap();
        let node_addr = SocketAddr::from(([127, 0, 0, 1], node.local_addr().port()));
        let helper = DhtNode::new(None).await.unwrap();
        helper.ping(compact_127(node_addr.port())).await.unwrap();
        let known = helper.node_id();
        assert!(node.good_nodes().iter().any(|c| c.id == known));

        let sock = raw_socket().await;
        let Inbound::Response(r) = ask(
            &sock,
            node_addr,
            b"g2",
            &Query::GetPeers {
                infohash: InfoHash([2; 20]),
                want: None,
            },
        )
        .await
        else {
            panic!("expected a response")
        };
        match r.payload {
            ResponsePayload::GetPeers {
                token,
                nodes,
                values,
            } => {
                assert_eq!(token.len(), 20);
                assert!(nodes.iter().any(|n| n.id == known));
                assert!(values.is_empty());
            }
            other => panic!("unexpected payload {other:?}"),
        }
    }

    fn compact_127(port: u16) -> Info {
        Info::Compact([127, 0, 0, 1, (port >> 8) as u8, port as u8])
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn node_ignores_garbage_and_still_answers_ping() {
        let a = DhtNode::new(None).await.unwrap();
        let a_addr = a.local_addr();
        assert_ne!(a_addr.port(), 0, "node must bind an ephemeral port");

        let junk = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payloads: Vec<Vec<u8>> = vec![
            vec![],
            b"garbage".to_vec(),
            b"d".to_vec(),
            b"d1:t2:aa1:y1:qe".to_vec(),
            b"d1:t3:aaae1:y1:qe".to_vec(),
            vec![0xffu8; 512],
        ];
        for p in &payloads {
            let _ = junk.send_to(p, a_addr).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            a.node_count() <= 1,
            "garbage must not fill the routing table"
        );

        let b = DhtNode::new(None).await.unwrap();
        let rtt = b.ping(compact_127(a_addr.port())).await.unwrap();
        assert!(rtt < QUERY_TIMEOUT);
        assert!(
            a.node_count() >= 1,
            "the answering node should be remembered"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn queries_return_empty_partial_results() {
        let node = DhtNode::new(None).await.unwrap();
        assert!(node.get_peers(InfoHash([1; 20])).await.unwrap().is_empty());
        assert!(node.find_node([2; 20]).await.unwrap().is_empty());
        // announce with an empty table is a no-op, not an error.
        node.announce(InfoHash([3; 20]), 51413).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ping_times_out_on_a_dead_address() {
        let node = DhtNode::new(None).await.unwrap();
        // Bound then dropped: almost certainly nothing is listening.
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let res = node.ping(compact_127(port)).await;
        assert!(matches!(res, Err(DhtError::Timeout) | Err(DhtError::Io(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn find_node_sees_a_third_party_node() {
        // b talks to both a and c, so when a asks b for nodes near c's id, b
        // can actually answer with c.
        let a = DhtNode::new(None).await.unwrap();
        let b = DhtNode::new(None).await.unwrap();
        let c = DhtNode::new(None).await.unwrap();
        b.ping(compact_127(a.local_addr().port())).await.unwrap();
        b.ping(compact_127(c.local_addr().port())).await.unwrap();

        let found = a.find_node(c.node_id().0).await.unwrap();
        assert!(
            found.iter().any(|n| n.id == c.node_id()),
            "expected to learn about c, got {found:?}"
        );
        // Having learned it, a can now reach c directly.
        a.ping(compact_127(c.local_addr().port())).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bootstrap_rejects_a_rubbish_router_list() {
        let node = DhtNode::new(None).await.unwrap();
        let routers = vec!["not a router".to_owned(), String::new()];
        assert_eq!(node.bootstrap(&routers).await, 0);
    }

    async fn write_ext(sock: &mut (impl AsyncWrite + Unpin), ext_id: u8, body: &[u8]) {
        use tokio::io::AsyncWriteExt;
        let mut payload = vec![MSG_EXTENDED, ext_id];
        payload.extend_from_slice(body);
        sock.write_all(&frame(&payload)).await.unwrap();
    }

    fn test_info_dict() -> Vec<u8> {
        let mut v = b"d4:name4:test6:pieces".to_vec();
        v.extend_from_slice(b"20000:");
        v.extend((0..20000u32).map(|i| (i % 251) as u8));
        v.push(b'e');
        v
    }

    /// A fake peer speaking the real wire format: BT handshake with the
    /// extension bit, noise before its extended handshake, ut_metadata id 3.
    async fn spawn_fake_peer(info_dict: Vec<u8>, handshake_hash: [u8; 20]) -> SocketAddr {
        spawn_fake_peer_with(info_dict, handshake_hash, None).await
    }

    /// The fake peer, answering MSE with `mse` as its policy first when set.
    async fn spawn_fake_peer_with(info_dict: Vec<u8>, handshake_hash: [u8; 20], mse: Option<EncryptionMode>) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Every connection is served on its own task, so a client that
        // retries (MSE, then plaintext) gets a fresh peer each time.
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let info_dict = info_dict.clone();
                tokio::spawn(async move {
                    match mse {
                        Some(mode) => {
                            let skeys = [InfoHash(handshake_hash)];
                            let (s, _) = crate::peer::mse::accept(sock, Vec::new(), &skeys, mode).await.unwrap();
                            serve_fake_peer(s, info_dict, handshake_hash).await;
                        }
                        None => serve_fake_peer(sock, info_dict, handshake_hash).await,
                    }
                });
            }
        });
        addr
    }

    async fn serve_fake_peer(mut sock: impl AsyncRead + AsyncWrite + Unpin, info_dict: Vec<u8>, handshake_hash: [u8; 20]) {
        use tokio::io::AsyncReadExt;
        {
            let mut theirs = [0u8; 68];
            sock.read_exact(&mut theirs).await.unwrap();
            assert_eq!(&theirs[1..20], b"BitTorrent protocol");
            assert_eq!(theirs[25] & 0x10, 0x10, "client must set the extension bit");
            let mut ours = [0u8; 68];
            ours[0] = 19;
            ours[1..20].copy_from_slice(b"BitTorrent protocol");
            ours[25] = 0x10;
            ours[28..48].copy_from_slice(&handshake_hash);
            sock.write_all(&ours).await.unwrap();

            sock.write_all(&frame(&[5, 0xff, 0xff])).await.unwrap();
            sock.write_all(&0u32.to_be_bytes()).await.unwrap();
            sock.write_all(&frame(&[1])).await.unwrap();
            let hs = ExtendedHandshake::new(Some(3), "fake", 100, Some(info_dict.len()));
            write_ext(&mut sock, EXT_HANDSHAKE_ID, &hs.encode()).await;

            let client_hs = read_frame(&mut sock).await.unwrap();
            assert_eq!(client_hs[..2], [MSG_EXTENDED, EXT_HANDSHAKE_ID]);
            let parsed = ExtendedHandshake::decode(&client_hs[2..]).unwrap();
            assert_eq!(parsed.ut_metadata, Some(LOCAL_UT_METADATA_ID));

            while let Ok(req) = read_frame(&mut sock).await {
                assert_eq!(req[..2], [MSG_EXTENDED, 3], "requests use the peer's id");
                let body = bencode::decode(&req[2..]).unwrap();
                assert_eq!(body.get_int_opt("msg_type"), Some(0));
                let piece = body.get_int_opt("piece").unwrap() as usize;
                let start = piece * UT_METADATA_PIECE_SIZE;
                let end = (start + UT_METADATA_PIECE_SIZE).min(info_dict.len());
                let mut d = BTreeMap::new();
                d.insert(b"msg_type".to_vec(), Value::Int(1));
                d.insert(b"piece".to_vec(), Value::Int(piece as i64));
                d.insert(b"total_size".to_vec(), Value::Int(info_dict.len() as i64));
                let mut out = bencode::encode(&Value::Dict(d));
                out.extend_from_slice(&info_dict[start..end]);
                write_ext(&mut sock, LOCAL_UT_METADATA_ID, &out).await;
            }
        }
    }

    #[tokio::test]
    async fn metadata_is_fetched_over_an_inbound_connection() {
        let info_dict = test_info_dict();
        let infohash = InfoHash(sha1_bytes(&info_dict));
        let (ours, mut theirs) = tokio::io::duplex(64 * 1024);
        let served = info_dict.clone();
        let hash = infohash.0;
        let peer = tokio::spawn(async move {
            let mut reserved = [0u8; 8];
            reserved[5] = 0x10;
            let mut hs = vec![19u8];
            hs.extend_from_slice(b"BitTorrent protocol");
            hs.extend_from_slice(&reserved);
            hs.extend_from_slice(&hash);
            hs.extend_from_slice(&[7u8; 20]);
            theirs.write_all(&hs).await.unwrap();
            let incoming = wire::handshake_incoming(&mut theirs).await.unwrap();
            assert_eq!(incoming.infohash, hash);
            let ext = ExtendedHandshake::new(Some(3), "fake", 100, Some(served.len()));
            write_ext(&mut theirs, EXT_HANDSHAKE_ID, &ext.encode()).await;
            let client_hs = read_frame(&mut theirs).await.unwrap();
            assert_eq!(client_hs[..2], [MSG_EXTENDED, EXT_HANDSHAKE_ID]);
            while let Ok(req) = read_frame(&mut theirs).await {
                let body = bencode::decode(&req[2..]).unwrap();
                let piece = body.get_int_opt("piece").unwrap() as usize;
                let start = piece * UT_METADATA_PIECE_SIZE;
                let end = (start + UT_METADATA_PIECE_SIZE).min(served.len());
                let mut d = BTreeMap::new();
                d.insert(b"msg_type".to_vec(), Value::Int(1));
                d.insert(b"piece".to_vec(), Value::Int(piece as i64));
                d.insert(b"total_size".to_vec(), Value::Int(served.len() as i64));
                let mut out = bencode::encode(&Value::Dict(d));
                out.extend_from_slice(&served[start..end]);
                write_ext(&mut theirs, LOCAL_UT_METADATA_ID, &out).await;
            }
        });
        let mut stream: crate::peer::PeerStream = Box::new(ours);
        let theirs_hs = wire::handshake_incoming(&mut stream).await.unwrap();
        let got = fetch_metadata_inbound(&mut stream, &theirs_hs, infohash, Duration::from_secs(5)).await.unwrap();
        assert_eq!(got, info_dict);
        let mut wrong = theirs_hs.clone();
        wrong.infohash = [9; 20];
        assert!(fetch_metadata_inbound(&mut stream, &wrong, infohash, Duration::from_secs(1)).await.is_err());
        drop(stream);
        peer.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn metadata_is_fetched_from_a_peer_that_requires_encryption() {
        let info_dict = test_info_dict();
        let infohash = InfoHash(sha1_bytes(&info_dict));
        let addr = spawn_fake_peer_with(info_dict.clone(), infohash.0, Some(EncryptionMode::Require)).await;
        let got = fetch_metadata_from_peer(addr, infohash, Duration::from_secs(5), EncryptionMode::Prefer, None).await.unwrap();
        assert_eq!(got, info_dict);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prefer_falls_back_to_plaintext_and_require_does_not() {
        let info_dict = test_info_dict();
        let infohash = InfoHash(sha1_bytes(&info_dict));
        let addr = spawn_fake_peer(info_dict.clone(), infohash.0).await;
        let got = fetch_metadata_from_peer(addr, infohash, Duration::from_secs(5), EncryptionMode::Prefer, None).await.unwrap();
        assert_eq!(got, info_dict);
        let addr = spawn_fake_peer(info_dict, infohash.0).await;
        assert!(fetch_metadata_from_peer(addr, infohash, Duration::from_secs(5), EncryptionMode::Require, None).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn metadata_exchange_uses_the_real_wire_format() {
        let info_dict = test_info_dict();
        assert!(info_dict.len() > UT_METADATA_PIECE_SIZE);
        let infohash = InfoHash(sha1_bytes(&info_dict));
        let addr = spawn_fake_peer(info_dict.clone(), infohash.0).await;
        let got = fetch_metadata_from_peer(addr, infohash, Duration::from_secs(5), EncryptionMode::Disabled, None)
            .await
            .unwrap();
        assert_eq!(got, info_dict);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn metadata_exchange_rejects_a_wrong_hash_dict() {
        let info_dict = test_info_dict();
        let wanted = InfoHash([7u8; 20]);
        let addr = spawn_fake_peer(info_dict, wanted.0).await;
        let err = fetch_metadata_from_peer(addr, wanted, Duration::from_secs(5), EncryptionMode::Disabled, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DhtError::InfoHashMismatch { .. }),
            "expected an infohash mismatch, got {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn metadata_exchange_times_out_on_a_silent_peer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let err = fetch_metadata_from_peer(addr, InfoHash([1; 20]), Duration::from_millis(300), EncryptionMode::Disabled, None)
            .await
            .unwrap_err();
        assert!(matches!(err, DhtError::Timeout), "got {err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn metadata_exchange_rejects_a_peer_without_the_extension_bit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut theirs = [0u8; 68];
            sock.read_exact(&mut theirs).await.unwrap();
            let mut ours = [0u8; 68];
            ours[0] = 19;
            ours[1..20].copy_from_slice(b"BitTorrent protocol");
            ours[28..48].copy_from_slice(&[1; 20]);
            sock.write_all(&ours).await.unwrap();
            let _ = read_frame(&mut sock).await;
        });
        let err = fetch_metadata_from_peer(addr, InfoHash([1; 20]), Duration::from_secs(5), EncryptionMode::Disabled, None)
            .await
            .unwrap_err();
        assert!(matches!(err, DhtError::Unsupported), "got {err:?}");
    }

    // Frame helpers for the little peer simulators above.
    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    async fn read_frame(sock: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let len = sock.read_u32().await? as usize;
        let mut buf = vec![0u8; len];
        sock.read_exact(&mut buf).await?;
        Ok(buf)
    }
}
