//! BEP 29 wire format: a 20-byte header, a chain of extensions, then payload.

pub const HEADER_LEN: usize = 20;
const VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Data = 0,
    Fin = 1,
    State = 2,
    Reset = 3,
    Syn = 4,
}

impl Kind {
    fn from_u8(v: u8) -> Option<Kind> {
        Some(match v {
            0 => Kind::Data,
            1 => Kind::Fin,
            2 => Kind::State,
            3 => Kind::Reset,
            4 => Kind::Syn,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub conn_id: u16,
    pub timestamp: u32,
    pub timestamp_diff: u32,
    pub wnd_size: u32,
    pub seq_nr: u16,
    pub ack_nr: u16,
}

impl Header {
    pub fn encode(&self, payload: &[u8]) -> Vec<u8> {
        self.encode_sack(&[], payload)
    }

    /// `sack` is the selective-ACK bitmask (extension 1); empty means none.
    pub fn encode_sack(&self, sack: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 2 + sack.len() + payload.len());
        out.push((self.kind as u8) << 4 | VERSION);
        out.push(!sack.is_empty() as u8);
        out.extend_from_slice(&self.conn_id.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.timestamp_diff.to_be_bytes());
        out.extend_from_slice(&self.wnd_size.to_be_bytes());
        out.extend_from_slice(&self.seq_nr.to_be_bytes());
        out.extend_from_slice(&self.ack_nr.to_be_bytes());
        if !sack.is_empty() {
            out.extend_from_slice(&[0, sack.len() as u8]);
            out.extend_from_slice(sack);
        }
        out.extend_from_slice(payload);
        out
    }
}

/// Parses a datagram into header, payload and the selective-ACK bitmask
/// (empty if absent); other extensions are skipped. `None` means "not uTP".
pub fn decode_sack(buf: &[u8]) -> Option<(Header, &[u8], &[u8])> {
    if buf.len() < HEADER_LEN || buf[0] & 0x0f != VERSION {
        return None;
    }
    let kind = Kind::from_u8(buf[0] >> 4)?;
    let mut ext = buf[1];
    let mut at = HEADER_LEN;
    let mut sack: &[u8] = &[];
    while ext != 0 {
        let next = *buf.get(at)?;
        let len = *buf.get(at + 1)? as usize;
        let end = at + 2 + len;
        if end > buf.len() {
            return None;
        }
        if ext == 1 {
            sack = &buf[at + 2..end];
        }
        at = end;
        ext = next;
    }
    let u16_at = |i: usize| u16::from_be_bytes([buf[i], buf[i + 1]]);
    let u32_at = |i: usize| u32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
    let header = Header {
        kind,
        conn_id: u16_at(2),
        timestamp: u32_at(4),
        timestamp_diff: u32_at(8),
        wnd_size: u32_at(12),
        seq_nr: u16_at(16),
        ack_nr: u16_at(18),
    };
    Some((header, &buf[at..], sack))
}

#[cfg(test)]
pub fn decode(buf: &[u8]) -> Option<(Header, &[u8])> {
    decode_sack(buf).map(|(h, payload, _)| (h, payload))
}

/// Signed distance `a - b` on the wrapping 16-bit sequence space.
pub fn seq_diff(a: u16, b: u16) -> i16 {
    a.wrapping_sub(b) as i16
}
