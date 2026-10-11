//! Hole punching (BEP 55, `ut_holepunch`) over the BEP 10 extension protocol.
//!
//! A peer that cannot reach a target asks a relay both are connected to; the
//! relay tells both to open a uTP connection to each other at once. Every
//! field is parsed from untrusted peers and checked.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// The extended-message id we ask peers to use for `ut_holepunch` messages
/// to us. Distinct from the other `OUR_*` ids in [`super::pex`].
pub const OUR_HOLEPUNCH_ID: u8 = 3;

/// Holepunch messages accepted per peer per minute; more are dropped. This
/// bounds how often a peer can use us as a relay or make us send a SYN.
pub const MAX_PER_MINUTE: u32 = 4;

/// How long we wait before asking for the same target again.
pub const RENDEZVOUS_COOLDOWN: Duration = Duration::from_secs(600);

pub const ERR_NO_SUCH_PEER: u32 = 1;
pub const ERR_NOT_CONNECTED: u32 = 2;
pub const ERR_NO_SUPPORT: u32 = 3;
pub const ERR_NO_SELF: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Rendezvous,
    Connect,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Msg {
    pub kind: Kind,
    pub addr: SocketAddr,
    pub err: u32,
}

impl Msg {
    pub fn new(kind: Kind, addr: SocketAddr) -> Self {
        Msg { kind, addr, err: 0 }
    }

    pub fn error(addr: SocketAddr, err: u32) -> Self {
        Msg { kind: Kind::Error, addr, err }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![
            match self.kind {
                Kind::Rendezvous => 0,
                Kind::Connect => 1,
                Kind::Error => 2,
            },
            u8::from(self.addr.is_ipv6()),
        ];
        match self.addr.ip() {
            IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
            IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
        }
        out.extend_from_slice(&self.addr.port().to_be_bytes());
        out.extend_from_slice(&self.err.to_be_bytes());
        out
    }

    /// Strict: wrong length, unknown type or address family, and port 0 all
    /// read as `None`.
    pub fn decode(payload: &[u8]) -> Option<Msg> {
        let kind = match *payload.first()? {
            0 => Kind::Rendezvous,
            1 => Kind::Connect,
            2 => Kind::Error,
            _ => return None,
        };
        let (ip, rest): (IpAddr, &[u8]) = match *payload.get(1)? {
            0 => {
                let b: [u8; 4] = payload.get(2..6)?.try_into().ok()?;
                (Ipv4Addr::from(b).into(), &payload[6..])
            }
            1 => {
                let b: [u8; 16] = payload.get(2..18)?.try_into().ok()?;
                (Ipv6Addr::from(b).into(), &payload[18..])
            }
            _ => return None,
        };
        if rest.len() != 6 {
            return None;
        }
        let port = u16::from_be_bytes([rest[0], rest[1]]);
        if port == 0 {
            return None;
        }
        let err = u32::from_be_bytes([rest[2], rest[3], rest[4], rest[5]]);
        Some(Msg { kind, addr: SocketAddr::new(ip, port), err })
    }
}

/// What a relay does with a rendezvous from `from` naming `target`.
/// `target_supports` is `None` when we have no such connection, else whether
/// that peer advertised `ut_holepunch`. `Err` carries the error code to send.
pub fn relay_check(from: SocketAddr, target: SocketAddr, target_supports: Option<bool>) -> Result<(), u32> {
    match target_supports {
        _ if from == target => Err(ERR_NO_SELF),
        None => Err(ERR_NOT_CONNECTED),
        Some(false) => Err(ERR_NO_SUPPORT),
        Some(true) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn messages_round_trip_v4_and_v6() {
        for addr in [sa("8.8.8.8:6881"), sa("[2001:db8::1]:51413")] {
            for kind in [Kind::Rendezvous, Kind::Connect, Kind::Error] {
                let m = Msg { kind, addr, err: 3 };
                assert_eq!(Msg::decode(&m.encode()), Some(m));
            }
        }
        assert_eq!(Msg::new(Kind::Connect, sa("1.2.3.4:5")).encode(), [1, 0, 1, 2, 3, 4, 0, 5, 0, 0, 0, 0]);
        assert_eq!(Msg::error(sa("1.2.3.4:5"), ERR_NO_SELF).encode()[8..], [0, 0, 0, 4]);
    }

    #[test]
    fn malformed_messages_are_rejected() {
        let good = Msg::new(Kind::Rendezvous, sa("1.2.3.4:5")).encode();
        let good6 = Msg::new(Kind::Rendezvous, sa("[2001:db8::1]:5")).encode();
        assert!(Msg::decode(&good).is_some());
        assert!(Msg::decode(&[]).is_none());
        for n in 0..good.len() {
            assert!(Msg::decode(&good[..n]).is_none(), "truncated to {n}");
        }
        for n in 0..good6.len() {
            assert!(Msg::decode(&good6[..n]).is_none(), "v6 truncated to {n}");
        }
        let mut long = good.clone();
        long.push(0);
        assert!(Msg::decode(&long).is_none());
        let mut bad_kind = good.clone();
        bad_kind[0] = 3;
        assert!(Msg::decode(&bad_kind).is_none());
        let mut bad_family = good.clone();
        bad_family[1] = 2;
        assert!(Msg::decode(&bad_family).is_none());
        let mut v6_with_v4_len = good.clone();
        v6_with_v4_len[1] = 1;
        assert!(Msg::decode(&v6_with_v4_len).is_none());
        let mut zero_port = good.clone();
        zero_port[6] = 0;
        zero_port[7] = 0;
        assert!(Msg::decode(&zero_port).is_none());
    }

    #[test]
    fn relay_decisions() {
        let (a, b) = (sa("1.1.1.1:1"), sa("2.2.2.2:2"));
        assert_eq!(relay_check(a, a, Some(true)), Err(ERR_NO_SELF));
        assert_eq!(relay_check(a, a, None), Err(ERR_NO_SELF));
        assert_eq!(relay_check(a, b, None), Err(ERR_NOT_CONNECTED));
        assert_eq!(relay_check(a, b, Some(false)), Err(ERR_NO_SUPPORT));
        assert_eq!(relay_check(a, b, Some(true)), Ok(()));
    }
}
