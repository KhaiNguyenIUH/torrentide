//! Bencode encoding and decoding.
//!
//! BEncode has four types: byte strings, integers, lists, and dictionaries.
//! Byte strings are length-prefixed: `<len>:<bytes>`. Dictionaries are required
//! to have keys sorted as raw byte strings, which matters when we later re-encode
//! an info dictionary to build an infohash.

use std::collections::BTreeMap;
use std::fmt;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Dict(BTreeMap<Vec<u8>, Value>),
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("unexpected byte {0:?} at offset {1}")]
    UnexpectedByte(u8, usize),
    #[error("invalid integer {0:?}")]
    InvalidInt(String),
    #[error("dictionary keys are not sorted or repeat (at offset {0})")]
    UnsortedDict(usize),
    #[error("nesting deeper than {MAX_DEPTH} levels (at offset {0})")]
    TooDeep(usize),
    #[error("trailing bytes after value at offset {0}")]
    TrailingData(usize),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Value {
    pub fn as_int(&self) -> Result<i64> {
        match self {
            Value::Int(i) => Ok(*i),
            _ => Err(Error::InvalidInt("expected integer".into())),
        }
    }

    pub fn as_int_u64(&self) -> Result<u64> {
        let v = self.as_int()?;
        u64::try_from(v).map_err(|_| Error::InvalidInt(format!("negative: {v}")))
    }

    pub fn as_bytes(&self) -> Result<&[u8]> {
        match self {
            Value::Bytes(b) => Ok(b),
            _ => Err(Error::InvalidInt("expected byte string".into())),
        }
    }

    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(self.as_bytes()?).map_err(|e| Error::InvalidInt(e.to_string()))
    }

    pub fn as_list(&self) -> Result<&[Value]> {
        match self {
            Value::List(l) => Ok(l),
            _ => Err(Error::InvalidInt("expected list".into())),
        }
    }

    pub fn as_dict(&self) -> Result<&BTreeMap<Vec<u8>, Value>> {
        match self {
            Value::Dict(d) => Ok(d),
            _ => Err(Error::InvalidInt("expected dictionary".into())),
        }
    }

    /// Look up a required key, erroring if it is absent.
    pub fn get(&self, key: &str) -> Result<&Value> {
        self.as_dict()?
            .get(key.as_bytes())
            .ok_or_else(|| Error::InvalidInt(format!("missing key: {key}")))
    }

    /// Look up an optional key.
    ///
    /// This is infallible: it returns `None` when the key is absent, and also
    /// when `self` is not a dictionary. Callers that treat a wrong-typed value
    /// as absent are almost always doing the right thing with a network-supplied
    /// dictionary, where every field is untrusted.
    pub fn get_opt(&self, key: &str) -> Option<&Value> {
        self.as_dict().ok()?.get(key.as_bytes())
    }

    /// Look up a key that must hold an integer.
    pub fn get_int(&self, key: &str) -> Result<i64> {
        self.get(key)?.as_int()
    }

    /// Look up a key that must hold an integer, treating absence as `None`.
    pub fn get_int_opt(&self, key: &str) -> Option<i64> {
        self.get_opt(key)?.as_int().ok()
    }

    /// Look up a key that must hold a byte string, treating absence as `None`.
    pub fn get_bytes_opt(&self, key: &str) -> Option<&[u8]> {
        self.get_opt(key)?.as_bytes().ok()
    }

    /// Look up a key that must hold a UTF-8 string, treating absence as `None`.
    pub fn get_str_opt(&self, key: &str) -> Option<&str> {
        self.get_opt(key)?.as_str().ok()
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Int(i) => write!(f, "i{i}e"),
            Value::Bytes(b) => write!(f, "{}:{:?}", b.len(), String::from_utf8_lossy(b)),
            Value::List(l) => {
                write!(f, "l")?;
                for v in l {
                    write!(f, "{v}")?;
                }
                write!(f, "e")
            }
            Value::Dict(d) => {
                write!(f, "d")?;
                for (k, v) in d {
                    write!(f, "{}:{}={}", k.len(), String::from_utf8_lossy(k), v)?;
                }
                write!(f, "e")
            }
        }
    }
}

/// Decode exactly one value, rejecting any trailing bytes.
pub fn decode(input: &[u8]) -> Result<Value> {
    let (v, rest) = decode_partial(input)?;
    if !rest.is_empty() {
        return Err(Error::TrailingData(input.len() - rest.len()));
    }
    Ok(v)
}

/// Decode one value, returning it plus whatever unconsumed input remains.
pub fn decode_partial(input: &[u8]) -> Result<(Value, &[u8])> {
    let mut p = Parser { buf: input, pos: 0, depth: 0 };
    let v = p.value()?;
    Ok((v, &input[p.pos..]))
}

const MAX_DEPTH: usize = 64;

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Result<u8> {
        self.buf.get(self.pos).copied().ok_or(Error::UnexpectedEof)
    }

    fn value(&mut self) -> Result<Value> {
        match self.peek()? {
            b'i' => self.integer(),
            b'l' => self.nested(Self::list),
            b'd' => self.nested(Self::dict),
            b'0'..=b'9' => self.bytes(),
            other => Err(Error::UnexpectedByte(other, self.pos)),
        }
    }

    fn nested(&mut self, parse: fn(&mut Self) -> Result<Value>) -> Result<Value> {
        if self.depth >= MAX_DEPTH {
            return Err(Error::TooDeep(self.pos));
        }
        self.depth += 1;
        let v = parse(self);
        self.depth -= 1;
        v
    }

    fn integer(&mut self) -> Result<Value> {
        self.pos += 1; // 'i'
        let start = self.pos;
        while self.pos < self.buf.len() && self.buf[self.pos] != b'e' {
            self.pos += 1;
        }
        if self.pos >= self.buf.len() {
            return Err(Error::UnexpectedEof);
        }
        let raw = &self.buf[start..self.pos];
        self.pos += 1; // 'e'
        if raw.is_empty() {
            return Err(Error::InvalidInt("empty".into()));
        }
        // Reject anything that is not a plain base-10 integer with an optional
        // leading '-'. Bencode forbids leading zeros and '+'.
        let body = raw.strip_prefix(b"-").unwrap_or(raw);
        if body.is_empty() || !body.iter().all(|b| b.is_ascii_digit()) {
            return Err(Error::InvalidInt(String::from_utf8_lossy(raw).into()));
        }
        if body.len() > 1 && body[0] == b'0' {
            return Err(Error::InvalidInt("leading zero".into()));
        }
        // `-0` is not a canonical integer.
        if raw.first() == Some(&b'-') && body == b"0" {
            return Err(Error::InvalidInt("negative zero".into()));
        }
        let s = std::str::from_utf8(raw).map_err(|e| Error::InvalidInt(e.to_string()))?;
        let n = s.parse::<i64>().map_err(|e| Error::InvalidInt(e.to_string()))?;
        Ok(Value::Int(n))
    }

    fn bytes(&mut self) -> Result<Value> {
        let start = self.pos;
        while self.pos < self.buf.len() && self.buf[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        if self.pos >= self.buf.len() {
            return Err(Error::UnexpectedEof);
        }
        let len_raw = std::str::from_utf8(&self.buf[start..self.pos])
            .map_err(|e| Error::InvalidInt(e.to_string()))?;
        let len: usize = len_raw.parse().map_err(|_| Error::InvalidInt(len_raw.into()))?;
        if len_raw.len() > 1 && len_raw.starts_with('0') {
            return Err(Error::InvalidInt("leading zero in length".into()));
        }
        if self.buf.get(self.pos) != Some(&b':') {
            return Err(Error::UnexpectedByte(self.peek()?, self.pos));
        }
        self.pos += 1;
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| Error::InvalidInt("length overflow".into()))?;
        if end > self.buf.len() {
            return Err(Error::UnexpectedEof);
        }
        let out = self.buf[self.pos..end].to_vec();
        self.pos = end;
        Ok(Value::Bytes(out))
    }

    fn list(&mut self) -> Result<Value> {
        self.pos += 1; // 'l'
        let mut items = Vec::new();
        loop {
            match self.peek()? {
                b'e' => {
                    self.pos += 1;
                    return Ok(Value::List(items));
                }
                _ => items.push(self.value()?),
            }
        }
    }

    fn dict(&mut self) -> Result<Value> {
        self.pos += 1; // 'd'
        let mut map: BTreeMap<Vec<u8>, Value> = BTreeMap::new();
        let mut prev_key: Option<Vec<u8>> = None;
        loop {
            match self.peek()? {
                b'e' => {
                    self.pos += 1;
                    return Ok(Value::Dict(map));
                }
                b'0'..=b'9' => {
                    let key = match self.value()? {
                        Value::Bytes(b) => b,
                        _ => {
                            return Err(Error::InvalidInt(
                                "dictionary key must be a byte string".into(),
                            ))
                        }
                    };
                    if let Some(p) = &prev_key {
                        if *p >= key {
                            return Err(Error::UnsortedDict(self.pos));
                        }
                    }
                    prev_key = Some(key.clone());
                    let v = self.value()?;
                    map.insert(key, v);
                }
                other => return Err(Error::UnexpectedByte(other, self.pos)),
            }
        }
    }
}

/// Encode a value back to bencode. Dictionary keys are ordered by `BTreeMap`,
/// which yields the byte-string ordering the spec requires.
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Int(i) => {
            out.push(b'i');
            out.extend_from_slice(i.to_string().as_bytes());
            out.push(b'e');
        }
        Value::Bytes(b) => {
            out.extend_from_slice(b.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(b);
        }
        Value::List(l) => {
            out.push(b'l');
            for item in l {
                encode_into(item, out);
            }
            out.push(b'e');
        }
        Value::Dict(d) => {
            out.push(b'd');
            for (k, val) in d {
                out.extend_from_slice(k.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(k);
                encode_into(val, out);
            }
            out.push(b'e');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_scalars() {
        assert_eq!(decode(b"i42e").unwrap(), Value::Int(42));
        assert_eq!(decode(b"i-7e").unwrap(), Value::Int(-7));
        assert_eq!(decode(b"i0e").unwrap(), Value::Int(0));
        assert_eq!(decode(b"4:spam").unwrap(), Value::Bytes(b"spam".to_vec()));
        assert_eq!(decode(b"0:").unwrap(), Value::Bytes(vec![]));
    }

    #[test]
    fn decodes_containers() {
        assert_eq!(
            decode(b"l4:spami3ee").unwrap(),
            Value::List(vec![Value::Bytes(b"spam".to_vec()), Value::Int(3)])
        );
        let d = decode(b"d3:cow3:moo4:spam4:eggse").unwrap();
        let m = d.as_dict().unwrap();
        assert_eq!(m[&b"cow".to_vec()], Value::Bytes(b"moo".to_vec()));
        assert_eq!(m[&b"spam".to_vec()], Value::Bytes(b"eggs".to_vec()));
    }

    #[test]
    fn rejects_malformed_integers() {
        assert!(decode(b"ie").is_err());
        assert!(decode(b"i-0e").is_err());
        assert!(decode(b"i01e").is_err());
        assert!(decode(b"i1.5e").is_err());
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(decode(b"5:spam").is_err(), "length exceeds input");
        assert!(decode(b"01:a").is_err(), "leading zero length");
    }

    #[test]
    fn rejects_trailing_data() {
        assert!(decode(b"i1ei2e").is_err());
        let (v, rest) = decode_partial(b"i1ei2e").unwrap();
        assert_eq!(v, Value::Int(1));
        assert_eq!(rest, b"i2e");
    }

    #[test]
    fn rejects_unsorted_dict_keys() {
        // 'z' > 'a', so this dict is out of order.
        assert!(decode(b"d1:z1:ai1:a1:be").is_err());
    }

    #[test]
    fn round_trips() {
        let v = Value::Dict(BTreeMap::from([
            (b"announce".to_vec(), Value::Bytes(b"http://t/announce".to_vec())),
            (b"info".to_vec(), Value::Dict(BTreeMap::from([
                (b"length".to_vec(), Value::Int(1234)),
                (b"name".to_vec(), Value::Bytes(b"file.bin".to_vec())),
            ]))),
            (b"piece length".to_vec(), Value::Int(262144)),
        ]));
        let bytes = encode(&v);
        assert_eq!(decode(&bytes).unwrap(), v);
    }

    #[test]
    fn encodes_keys_in_sorted_order() {
        let v = Value::Dict(BTreeMap::from([
            (b"z".to_vec(), Value::Int(1)),
            (b"a".to_vec(), Value::Int(2)),
        ]));
        assert_eq!(encode(&v), b"d1:ai2e1:zi1ee");
    }

    #[test]
    fn rejects_deep_nesting() {
        let mut deep = vec![b'l'; 100_000];
        deep.extend(std::iter::repeat(b'e').take(100_000));
        assert!(decode(&deep).is_err());
        let mut ok = vec![b'l'; MAX_DEPTH];
        ok.extend(std::iter::repeat(b'e').take(MAX_DEPTH));
        assert!(decode(&ok).is_ok());
    }

    #[test]
    fn rejects_duplicate_dict_keys() {
        assert!(decode(b"d1:ai1e1:ai2ee").is_err());
        assert!(decode(b"d1:ai1e1:bi2ee").is_ok());
    }
}