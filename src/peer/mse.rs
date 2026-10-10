//! Message Stream Encryption (the "MSE/PE" obfuscation used by uTorrent,
//! libtorrent and Vuze). A 768-bit Diffie-Hellman exchange yields a shared
//! secret; RC4 keyed from it (and the infohash) hides the BitTorrent handshake
//! from passive traffic shaping. It is obfuscation, not authentication.
//!
//! The bignum arithmetic is written out here instead of pulling in a crate:
//! the group is fixed and tiny, so shift-and-add multiplication is plenty.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use rand::Rng;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::AsyncStream;
use crate::metainfo::InfoHash;
use crate::state::EncryptionMode;

const CRYPTO_PLAIN: u32 = 0x01;
const CRYPTO_RC4: u32 = 0x02;

const KEY_LEN: usize = 96;
const MAX_PAD: usize = 512;
const RC4_DISCARD: usize = 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_CHUNK: usize = 16 * 1024;

type U768 = [u64; 12];

/// The 768-bit prime from the MSE specification, little-endian limbs. It is
/// close to, but NOT the same as, the RFC 2409 Oakley group 1 prime: its low
/// end is `...A63A3621 00000000 00090563`. Using the Oakley prime passes every
/// loopback test and fails against every real client.
const P: U768 = [
    0x0000_0000_0009_0563,
    0xF44C_42E9_A63A_3621,
    0xE485_B576_625E_7EC6,
    0x4FE1_356D_6D51_C245,
    0x302B_0A6D_F25F_1437,
    0xEF95_19B3_CD3A_431B,
    0x514A_0879_8E34_04DD,
    0x020B_BEA6_3B13_9B22,
    0x2902_4E08_8A67_CC74,
    0xC4C6_628B_80DC_1CD1,
    0xC90F_DAA2_2168_C234,
    0xFFFF_FFFF_FFFF_FFFF,
];

const TWO: U768 = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

fn from_be_bytes(bytes: &[u8]) -> U768 {
    let mut out = [0u64; 12];
    for (i, chunk) in bytes.rchunks(8).enumerate() {
        out[i] = chunk.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
    }
    out
}

fn to_be_bytes(n: &U768) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    for (i, limb) in n.iter().rev().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

fn ge(a: &U768, b: &U768) -> bool {
    for i in (0..12).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn sub_p(a: &mut U768) {
    let mut borrow = false;
    for i in 0..12 {
        let (d, b1) = a[i].overflowing_sub(P[i]);
        let (d, b2) = d.overflowing_sub(borrow as u64);
        a[i] = d;
        borrow = b1 || b2;
    }
}

fn add_mod(a: &mut U768, b: &U768) {
    let mut carry = false;
    for i in 0..12 {
        let (s, c1) = a[i].overflowing_add(b[i]);
        let (s, c2) = s.overflowing_add(carry as u64);
        a[i] = s;
        carry = c1 || c2;
    }
    if carry || ge(a, &P) {
        sub_p(a);
    }
}

fn mulmod(a: &U768, b: &U768) -> U768 {
    let mut acc = [0u64; 12];
    for limb in b.iter().rev() {
        for bit in (0..64).rev() {
            let doubled = acc;
            add_mod(&mut acc, &doubled);
            if (limb >> bit) & 1 == 1 {
                add_mod(&mut acc, a);
            }
        }
    }
    acc
}

fn powmod(base: &U768, exp: &U768) -> U768 {
    let mut acc: U768 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for limb in exp.iter().rev() {
        for bit in (0..64).rev() {
            acc = mulmod(&acc, &acc);
            if (limb >> bit) & 1 == 1 {
                acc = mulmod(&acc, base);
            }
        }
    }
    acc
}

/// 160-bit private exponent, which is what deployed clients use.
fn random_exponent() -> U768 {
    let mut bytes = [0u8; 20];
    rand::thread_rng().fill(&mut bytes[..]);
    from_be_bytes(&bytes)
}

/// Rejects the degenerate public values 0, 1, P-1 and anything >= P, which
/// would force the shared secret to a value the attacker knows.
fn valid_public(y: &U768) -> bool {
    let mut p_minus_1 = P;
    p_minus_1[0] -= 1;
    let small = y[1..].iter().all(|l| *l == 0) && y[0] <= 1;
    !small && !ge(y, &P) && *y != p_minus_1
}

struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Rc4 { s, i: 0, j: 0 }
    }

    /// MSE throws away the first 1024 keystream bytes, which are biased.
    fn mse(key: &[u8]) -> Self {
        let mut rc4 = Rc4::new(key);
        rc4.apply(&mut [0u8; RC4_DISCARD]);
        rc4
    }

    fn apply(&mut self, data: &mut [u8]) {
        for b in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *b ^= k;
        }
    }
}

fn hash(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn random_pad() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut pad = vec![0u8; rng.gen_range(0..=MAX_PAD)];
    rng.fill(&mut pad[..]);
    pad
}

async fn fill<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>, n: usize) -> Result<()> {
    while buf.len() < n {
        let mut chunk = [0u8; 1024];
        let read = s.read(&mut chunk).await?;
        if read == 0 {
            bail!("peer closed during encryption handshake");
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    Ok(())
}

/// Scans for `pattern` starting within `max_offset` bytes, consuming through
/// it. The offset bound is what keeps hostile input from growing `buf`.
async fn sync<S: AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
    pattern: &[u8],
    max_offset: usize,
) -> Result<()> {
    loop {
        if let Some(pos) = buf.windows(pattern.len()).position(|w| w == pattern) {
            if pos > max_offset {
                bail!("encryption sync marker too far into the stream");
            }
            buf.drain(..pos + pattern.len());
            return Ok(());
        }
        if buf.len() >= max_offset + pattern.len() {
            bail!("encryption sync marker not found");
        }
        let mut chunk = [0u8; 1024];
        let read = s.read(&mut chunk).await?;
        if read == 0 {
            bail!("peer closed during encryption handshake");
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

async fn take_decrypted<S: AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
    n: usize,
    dec: &mut Rc4,
) -> Result<Vec<u8>> {
    fill(s, buf, n).await?;
    let mut out: Vec<u8> = buf.drain(..n).collect();
    dec.apply(&mut out);
    Ok(out)
}

/// A peer stream after the MSE handshake. `enc`/`dec` are `None` when
/// plaintext was negotiated. `rbuf` holds payload bytes that arrived during
/// the handshake (IA and anything read past it) and is served before the
/// socket.
pub struct MseStream<S> {
    inner: S,
    enc: Option<Rc4>,
    dec: Option<Rc4>,
    rbuf: Vec<u8>,
    rpos: usize,
    wbuf: Vec<u8>,
    wpos: usize,
}

impl<S: AsyncWrite + Unpin> MseStream<S> {
    fn new(inner: S, ciphers: Option<(Rc4, Rc4)>, rbuf: Vec<u8>) -> Self {
        let (enc, dec) = match ciphers {
            Some((e, d)) => (Some(e), Some(d)),
            None => (None, None),
        };
        MseStream {
            inner,
            enc,
            dec,
            rbuf,
            rpos: 0,
            wbuf: Vec::new(),
            wpos: 0,
        }
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.wpos += n;
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for MseStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.rpos < this.rbuf.len() {
            let n = buf.remaining().min(this.rbuf.len() - this.rpos);
            buf.put_slice(&this.rbuf[this.rpos..this.rpos + n]);
            this.rpos += n;
            if this.rpos == this.rbuf.len() {
                this.rbuf = Vec::new();
                this.rpos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        let start = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        if let Some(dec) = &mut this.dec {
            dec.apply(&mut buf.filled_mut()[start..]);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MseStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.enc.is_none() {
            return Pin::new(&mut this.inner).poll_write(cx, data);
        }
        ready!(this.drain(cx))?;
        let n = data.len().min(WRITE_CHUNK);
        this.wbuf.extend_from_slice(&data[..n]);
        if let Some(enc) = &mut this.enc {
            enc.apply(&mut this.wbuf);
        }
        if let Poll::Ready(Err(e)) = this.drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn choose(provide: u32, allowed: u32) -> Option<u32> {
    let common = provide & allowed;
    if common & CRYPTO_RC4 != 0 {
        Some(CRYPTO_RC4)
    } else if common & CRYPTO_PLAIN != 0 {
        Some(CRYPTO_PLAIN)
    } else {
        None
    }
}

fn mode_mask(mode: EncryptionMode) -> Result<u32> {
    match mode {
        EncryptionMode::Disabled => bail!("encryption is disabled"),
        EncryptionMode::Prefer => Ok(CRYPTO_RC4 | CRYPTO_PLAIN),
        EncryptionMode::Require => Ok(CRYPTO_RC4),
    }
}

/// Starts MSE as the connecting side. `Prefer` offers RC4 and plaintext,
/// `Require` offers RC4 only. The caller sends its BitTorrent handshake
/// through the returned stream.
pub async fn connect<S: AsyncStream>(
    stream: S,
    infohash: InfoHash,
    mode: EncryptionMode,
) -> Result<impl AsyncStream> {
    let provide = mode_mask(mode)?;
    connect_inner(stream, infohash, provide, &[]).await
}

/// Answers MSE as the listening side. `prefix` is what the caller already
/// read from the socket; `skeys` are the infohashes we serve, and the one the
/// peer asked for is returned.
pub async fn accept<S: AsyncStream>(
    stream: S,
    prefix: Vec<u8>,
    skeys: &[InfoHash],
    mode: EncryptionMode,
) -> Result<(impl AsyncStream, InfoHash)> {
    let allowed = mode_mask(mode)?;
    accept_inner(stream, prefix, skeys, |provide| choose(provide, allowed)).await
}

async fn connect_inner<S: AsyncStream>(
    stream: S,
    infohash: InfoHash,
    provide: u32,
    ia: &[u8],
) -> Result<MseStream<S>> {
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connect_handshake(stream, infohash, provide, ia),
    )
    .await
    .context("encryption handshake timed out")?
}

async fn connect_handshake<S: AsyncStream>(
    mut s: S,
    infohash: InfoHash,
    provide: u32,
    ia: &[u8],
) -> Result<MseStream<S>> {
    let Ok(ia_len) = u16::try_from(ia.len()) else {
        bail!("initial payload too large");
    };
    let x = random_exponent();
    let mut out = to_be_bytes(&powmod(&TWO, &x)).to_vec();
    out.extend(random_pad());
    s.write_all(&out).await?;

    let mut buf = Vec::new();
    fill(&mut s, &mut buf, KEY_LEN).await?;
    let yb = from_be_bytes(&buf[..KEY_LEN]);
    if !valid_public(&yb) {
        bail!("invalid DH public value");
    }
    buf.drain(..KEY_LEN);
    let secret = to_be_bytes(&powmod(&yb, &x));

    let skey = infohash.0;
    let mut enc = Rc4::mse(&hash(&[b"keyA", &secret, &skey]));
    let mut dec = Rc4::mse(&hash(&[b"keyB", &secret, &skey]));

    let mut msg = hash(&[b"req1", &secret]).to_vec();
    let req2 = hash(&[b"req2", &skey]);
    let req3 = hash(&[b"req3", &secret]);
    msg.extend(req2.iter().zip(req3).map(|(a, b)| a ^ b));
    let pad = random_pad();
    let mut crypt = vec![0u8; 8];
    crypt.extend(provide.to_be_bytes());
    crypt.extend((pad.len() as u16).to_be_bytes());
    crypt.extend(pad);
    crypt.extend(ia_len.to_be_bytes());
    crypt.extend(ia);
    enc.apply(&mut crypt);
    msg.extend(crypt);
    s.write_all(&msg).await?;

    let mut vc = [0u8; 8];
    dec.apply(&mut vc);
    sync(&mut s, &mut buf, &vc, MAX_PAD).await?;
    let head = take_decrypted(&mut s, &mut buf, 6, &mut dec).await?;
    let select = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let pad_len = u16::from_be_bytes([head[4], head[5]]) as usize;
    if pad_len > MAX_PAD {
        bail!("oversized padding");
    }
    take_decrypted(&mut s, &mut buf, pad_len, &mut dec).await?;

    match select {
        CRYPTO_RC4 | CRYPTO_PLAIN if select & provide != 0 => {}
        _ => bail!("peer selected a crypto method we did not offer"),
    }
    if select == CRYPTO_RC4 {
        dec.apply(&mut buf);
        Ok(MseStream::new(s, Some((enc, dec)), buf))
    } else {
        Ok(MseStream::new(s, None, buf))
    }
}

async fn accept_inner<S: AsyncStream>(
    stream: S,
    prefix: Vec<u8>,
    skeys: &[InfoHash],
    select: impl Fn(u32) -> Option<u32>,
) -> Result<(MseStream<S>, InfoHash)> {
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        accept_handshake(stream, prefix, skeys, select),
    )
    .await
    .context("encryption handshake timed out")?
}

async fn accept_handshake<S: AsyncStream>(
    mut s: S,
    prefix: Vec<u8>,
    skeys: &[InfoHash],
    select: impl Fn(u32) -> Option<u32>,
) -> Result<(MseStream<S>, InfoHash)> {
    let mut buf = prefix;
    fill(&mut s, &mut buf, KEY_LEN).await?;
    let ya = from_be_bytes(&buf[..KEY_LEN]);
    if !valid_public(&ya) {
        bail!("invalid DH public value");
    }
    buf.drain(..KEY_LEN);

    let y = random_exponent();
    let mut out = to_be_bytes(&powmod(&TWO, &y)).to_vec();
    out.extend(random_pad());
    s.write_all(&out).await?;
    let secret = to_be_bytes(&powmod(&ya, &y));

    sync(&mut s, &mut buf, &hash(&[b"req1", &secret]), MAX_PAD).await?;
    fill(&mut s, &mut buf, 20).await?;
    let req3 = hash(&[b"req3", &secret]);
    let wanted: Vec<u8> = buf.drain(..20).collect();
    let Some(skey) = skeys.iter().copied().find(|k| {
        let req2 = hash(&[b"req2", &k.0]);
        req2.iter()
            .zip(req3)
            .map(|(a, b)| a ^ b)
            .eq(wanted.iter().copied())
    }) else {
        bail!("peer asked for an unknown torrent");
    };

    let mut dec = Rc4::mse(&hash(&[b"keyA", &secret, &skey.0]));
    let mut enc = Rc4::mse(&hash(&[b"keyB", &secret, &skey.0]));

    let head = take_decrypted(&mut s, &mut buf, 14, &mut dec).await?;
    if head[..8] != [0u8; 8] {
        bail!("bad verification constant");
    }
    let provide = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
    let pad_len = u16::from_be_bytes([head[12], head[13]]) as usize;
    if pad_len > MAX_PAD {
        bail!("oversized padding");
    }
    let tail = take_decrypted(&mut s, &mut buf, pad_len + 2, &mut dec).await?;
    let ia_len = u16::from_be_bytes([tail[pad_len], tail[pad_len + 1]]) as usize;
    let mut payload = take_decrypted(&mut s, &mut buf, ia_len, &mut dec).await?;

    let Some(chosen) = select(provide) else {
        bail!("no acceptable crypto method offered");
    };

    let pad = random_pad();
    let mut reply = vec![0u8; 8];
    reply.extend(chosen.to_be_bytes());
    reply.extend((pad.len() as u16).to_be_bytes());
    reply.extend(pad);
    enc.apply(&mut reply);
    s.write_all(&reply).await?;

    if chosen == CRYPTO_RC4 {
        dec.apply(&mut buf);
        payload.extend(buf);
        Ok((MseStream::new(s, Some((enc, dec)), payload), skey))
    } else {
        payload.extend(buf);
        Ok((MseStream::new(s, None, payload), skey))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn ih(b: u8) -> InfoHash {
        InfoHash([b; 20])
    }

    fn hex_u768(s: &str) -> U768 {
        let padded = format!("{s:0>192}");
        from_be_bytes(&hex::decode(padded).unwrap())
    }

    const P_HEX: &str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a36210000000000090563";

    #[test]
    fn prime_matches_mse_spec() {
        assert_eq!(P, hex_u768(P_HEX));
        assert_eq!(hex::encode(to_be_bytes(&P)), P_HEX);
    }

    #[test]
    fn powmod_matches_python() {
        let cases = [
            ("3", "8"),
            (
                "123456789abcdef0123456789abcdef012345678",
                "9d2559a62e1bf5834b6fdbefe51896aa07ab1f71f9f6d9ed16c17dcfde4c82cc1caed6afc7757e58a4d0234cd95c630582da5ddb11b03646a3a60308236808cb5f2b1fcf041a63b1c1d70ea117f265a930d862be96d23bef41638912e7923ba7",
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffff",
                "fe9aac142f64ad4d5bca7e30bea17d62c709de9e4c5694e2b27e8c6ed82510bb57952fcce38f6a5084b9699ec34b033ed1a0dbd51d70274bff40ae493f0ce2cdbd3cbd6055c9677a7eb70d29f4d8ecfbc2625316a7ae1a0d3d6605f0406bad79",
            ),
        ];
        for (x, want) in cases {
            assert_eq!(powmod(&TWO, &hex_u768(x)), hex_u768(want), "x = {x}");
        }
    }

    #[test]
    fn dh_agrees() {
        let (x, y) = (random_exponent(), random_exponent());
        let (a, b) = (powmod(&TWO, &x), powmod(&TWO, &y));
        assert_eq!(powmod(&b, &x), powmod(&a, &y));
    }

    #[test]
    fn rc4_known_vector() {
        let mut data = *b"Plaintext";
        Rc4::new(b"Key").apply(&mut data);
        assert_eq!(hex::encode_upper(data), "BBF316E8D940AF0AD3");
    }

    #[test]
    fn rc4_discard() {
        let mut raw = Rc4::new(b"Key");
        let mut skipped = vec![0u8; RC4_DISCARD + 16];
        raw.apply(&mut skipped);
        let mut mse = [0u8; 16];
        Rc4::mse(b"Key").apply(&mut mse);
        assert_eq!(&skipped[RC4_DISCARD..], &mse);
    }

    fn plain_only(provide: u32) -> Option<u32> {
        choose(provide, CRYPTO_PLAIN)
    }

    async fn pair(
        provide: u32,
        ia: &[u8],
        select: impl Fn(u32) -> Option<u32>,
    ) -> (
        Result<MseStream<tokio::io::DuplexStream>>,
        Result<(MseStream<tokio::io::DuplexStream>, InfoHash)>,
    ) {
        let (a, b) = duplex(1 << 16);
        let keys = [ih(1), ih(2), ih(3)];
        tokio::join!(
            connect_inner(a, ih(2), provide, ia),
            accept_inner(b, Vec::new(), &keys, select)
        )
    }

    async fn exchange<S: AsyncStream>(a: &mut S, b: &mut S) {
        let up: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let down: Vec<u8> = (0..7000u32).map(|i| (i % 241) as u8).collect();
        let (mut got_up, mut got_down) = (vec![0u8; up.len()], vec![0u8; down.len()]);
        let (ra, rb) = tokio::join!(
            async {
                a.write_all(&up).await?;
                a.read_exact(&mut got_down).await
            },
            async {
                b.write_all(&down).await?;
                b.read_exact(&mut got_up).await
            }
        );
        ra.unwrap();
        rb.unwrap();
        assert_eq!(got_up, up);
        assert_eq!(got_down, down);
    }

    #[tokio::test]
    async fn rc4_loopback_picks_infohash() {
        let (c, a) = pair(CRYPTO_RC4 | CRYPTO_PLAIN, &[], |p| {
            choose(p, CRYPTO_RC4 | CRYPTO_PLAIN)
        })
        .await;
        let mut c = c.unwrap();
        let (mut a, found) = a.unwrap();
        assert_eq!(found, ih(2));
        assert!(c.enc.is_some() && a.enc.is_some());
        let hs = [0x13u8; 68];
        c.write_all(&hs).await.unwrap();
        let mut got = [0u8; 68];
        a.read_exact(&mut got).await.unwrap();
        assert_eq!(got, hs);
        exchange(&mut c, &mut a).await;
    }

    #[tokio::test]
    async fn ia_is_delivered_first() {
        let ia: Vec<u8> = (0..68).collect();
        for select in [CRYPTO_RC4, CRYPTO_PLAIN] {
            let (c, a) = pair(CRYPTO_RC4 | CRYPTO_PLAIN, &ia, move |_| Some(select)).await;
            let mut c = c.unwrap();
            let (mut a, _) = a.unwrap();
            c.write_all(b"after").await.unwrap();
            let mut got = vec![0u8; 68 + 5];
            a.read_exact(&mut got).await.unwrap();
            assert_eq!(&got[..68], &ia[..]);
            assert_eq!(&got[68..], b"after");
        }
    }

    #[tokio::test]
    async fn plaintext_passes_through() {
        let (c, a) = pair(CRYPTO_RC4 | CRYPTO_PLAIN, &[], plain_only).await;
        let mut c = c.unwrap();
        let (mut a, _) = a.unwrap();
        assert!(c.enc.is_none() && a.enc.is_none());
        exchange(&mut c, &mut a).await;
    }

    #[tokio::test]
    async fn public_api_prefer_and_prefix() {
        let (a, mut b) = duplex(1 << 16);
        let init = tokio::spawn(async move {
            let mut s = connect(a, ih(3), EncryptionMode::Prefer).await.unwrap();
            s.write_all(b"hello mse").await.unwrap();
            let mut got = [0u8; 5];
            s.read_exact(&mut got).await.unwrap();
            got
        });
        let mut prefix = vec![0u8; 20];
        b.read_exact(&mut prefix).await.unwrap();
        let (mut s, found) = accept(b, prefix, &[ih(1), ih(3)], EncryptionMode::Prefer)
            .await
            .unwrap();
        assert_eq!(found, ih(3));
        let mut got = [0u8; 9];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello mse");
        s.write_all(b"reply").await.unwrap();
        assert_eq!(&init.await.unwrap(), b"reply");
    }

    #[tokio::test]
    async fn require_refuses_plaintext_selection() {
        let (a, b) = duplex(1 << 16);
        let keys = [ih(2)];
        let (c, _) = tokio::join!(
            connect(a, ih(2), EncryptionMode::Require),
            accept_inner(b, Vec::new(), &keys, |_| Some(CRYPTO_PLAIN))
        );
        assert!(c.is_err());
    }

    #[tokio::test]
    async fn require_acceptor_refuses_plaintext_only_peer() {
        let (a, b) = duplex(1 << 16);
        let keys = [ih(2)];
        let (c, s) = tokio::join!(
            connect_inner(a, ih(2), CRYPTO_PLAIN, &[]),
            accept(b, Vec::new(), &keys, EncryptionMode::Require)
        );
        assert!(s.is_err());
        assert!(c.is_err());
    }

    #[tokio::test]
    async fn disabled_mode_refuses() {
        let (a, _b) = duplex(1024);
        assert!(connect(a, ih(1), EncryptionMode::Disabled).await.is_err());
    }

    #[tokio::test]
    async fn unknown_infohash_errors() {
        let (a, b) = duplex(1 << 16);
        let keys = [ih(1), ih(2)];
        let (c, s) = tokio::join!(
            connect(a, ih(9), EncryptionMode::Prefer),
            accept(b, Vec::new(), &keys, EncryptionMode::Prefer)
        );
        assert!(c.is_err());
        assert!(s.is_err());
    }

    #[tokio::test]
    async fn garbage_and_short_input_error() {
        for len in [0usize, 10, 96, 700, 4096] {
            let (mut a, b) = duplex(1 << 16);
            let junk: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8 | 1).collect();
            tokio::spawn(async move {
                let _ = a.write_all(&junk).await;
                let _ = a.shutdown().await;
            });
            let res = accept(b, Vec::new(), &[ih(1)], EncryptionMode::Prefer).await;
            assert!(res.is_err(), "len {len}");
        }
        let (mut a, b) = duplex(1 << 16);
        let junk = vec![0xAAu8; 4096];
        tokio::spawn(async move {
            let _ = a.write_all(&junk).await;
            std::future::pending::<()>().await;
        });
        assert!(connect(b, ih(1), EncryptionMode::Prefer).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_peer_times_out() {
        let (a, _b) = duplex(1 << 16);
        let err = accept(a, vec![1u8; 20], &[ih(1)], EncryptionMode::Prefer).await;
        assert!(err.is_err());
    }
}
