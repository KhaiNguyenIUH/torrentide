use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    time::Instant,
};

use super::packet::{decode, seq_diff, Header, Kind, HEADER_LEN};
use super::*;

fn header(kind: Kind) -> Header {
    Header { kind, conn_id: 0xabcd, timestamp: 7, timestamp_diff: 9, wnd_size: 1234, seq_nr: 65535, ack_nr: 3 }
}

fn plain() -> Config {
    Config { idle: IDLE_TIMEOUT, first_seq: None }
}

async fn udp() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

fn pattern(len: usize, seed: u32) -> Vec<u8> {
    (0..len as u32).map(|i| (i.wrapping_add(seed).wrapping_mul(2654435761) >> 24) as u8).collect()
}

#[test]
fn header_round_trip() {
    for kind in [Kind::Data, Kind::Fin, Kind::State, Kind::Reset, Kind::Syn] {
        let h = header(kind);
        let bytes = h.encode(b"abc");
        assert_eq!(bytes.len(), HEADER_LEN + 3);
        assert_eq!(decode(&bytes), Some((h, &b"abc"[..])));
    }
}

#[test]
fn decode_rejects_garbage_and_skips_extensions() {
    let good = header(Kind::Data).encode(b"xy");
    assert!(decode(&good[..HEADER_LEN - 1]).is_none());
    assert!(decode(&[]).is_none());
    let mut bad_version = good.clone();
    bad_version[0] = (bad_version[0] & 0xf0) | 2;
    assert!(decode(&bad_version).is_none());
    let mut bad_type = good.clone();
    bad_type[0] = 0x51;
    assert!(decode(&bad_type).is_none());

    let mut chained = good[..HEADER_LEN].to_vec();
    chained[1] = 1;
    chained.extend_from_slice(&[9, 4, 1, 2, 3, 4]);
    chained.extend_from_slice(&[0, 2, 7, 7]);
    chained.extend_from_slice(b"xy");
    let (h, payload) = decode(&chained).unwrap();
    assert_eq!(h.seq_nr, 65535);
    assert_eq!(payload, b"xy");

    let mut truncated = good[..HEADER_LEN].to_vec();
    truncated[1] = 1;
    truncated.extend_from_slice(&[0, 200, 1]);
    assert!(decode(&truncated).is_none());
    let mut dangling = good[..HEADER_LEN].to_vec();
    dangling[1] = 1;
    assert!(decode(&dangling).is_none());
}

#[test]
fn seq_arithmetic_wraps() {
    assert_eq!(seq_diff(2, 65534), 4);
    assert_eq!(seq_diff(65534, 2), -4);
    assert_eq!(seq_diff(5, 5), 0);
    assert_eq!(65535u16.wrapping_add(1), 0);
}

async fn forward(from: Arc<UdpSocket>, to: Arc<UdpSocket>, dest: SocketAddr) {
    let mut buf = vec![0u8; 2048];
    loop {
        let Ok((n, _)) = from.recv_from(&mut buf).await else { continue };
        let roll = rand::random::<f64>();
        if roll < 0.05 {
            continue;
        }
        let pkt = buf[..n].to_vec();
        if roll < 0.15 {
            let to = to.clone();
            let ms = 1 + rand::random::<u64>() % 10;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(ms)).await;
                let _ = to.send_to(&pkt, dest).await;
            });
        } else {
            let _ = to.send_to(&pkt, dest).await;
        }
    }
}

async fn lossy_relay(a: SocketAddr, b: SocketAddr) -> SocketAddr {
    let ra = Arc::new(udp().await);
    let rb = Arc::new(udp().await);
    let facing_a = ra.local_addr().unwrap();
    tokio::spawn(forward(ra.clone(), rb.clone(), b));
    tokio::spawn(forward(rb, ra, a));
    facing_a
}

async fn pair() -> (UtpSocket, UtpSocket) {
    (UtpSocket::bind(udp().await), UtpSocket::bind(udp().await))
}

async fn connected(a: &UtpSocket, b: &UtpSocket, to: SocketAddr) -> (UtpStream, UtpStream) {
    let (c, s) = tokio::join!(a.connect(to), b.accept());
    (c.unwrap(), s.unwrap().0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ten_mib_both_ways_over_lossy_link() {
    const N: usize = 10 * 1024 * 1024;
    let a = UtpSocket::bind_with(udp().await, plain());
    let b = UtpSocket::bind_with(udp().await, Config { idle: IDLE_TIMEOUT, first_seq: Some(65000) });
    let via = lossy_relay(a.local_addr().unwrap(), b.local_addr().unwrap()).await;
    let started = Instant::now();
    let (client, server) = connected(&a, &b, via).await;

    async fn exchange(stream: UtpStream, send_seed: u32, recv_seed: u32) {
        let (mut r, mut w) = tokio::io::split(stream);
        let writer = tokio::spawn(async move {
            w.write_all(&pattern(N, send_seed)).await.unwrap();
            w.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert!(got == pattern(N, recv_seed), "payload mismatch");
    }

    tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(exchange(client, 1, 2), exchange(server, 2, 1));
    })
    .await
    .expect("transfer stalled");
    let took = started.elapsed();
    eprintln!("20 MiB total over lossy link in {took:?}");
    assert!(took < Duration::from_secs(30));
}

#[tokio::test]
async fn shutdown_gives_peer_eof_both_ways() {
    let (a, b) = pair().await;
    let (mut c, mut s) = connected(&a, &b, b.local_addr().unwrap()).await;
    c.write_all(b"hello").await.unwrap();
    c.shutdown().await.unwrap();
    assert!(c.write_all(b"x").await.is_err());
    let mut got = Vec::new();
    s.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"hello");
    s.write_all(b"world").await.unwrap();
    s.shutdown().await.unwrap();
    let mut back = Vec::new();
    c.read_to_end(&mut back).await.unwrap();
    assert_eq!(back, b"world");
}

#[tokio::test]
async fn drop_flushes_then_peer_sees_eof() {
    let (a, b) = pair().await;
    let (mut c, mut s) = connected(&a, &b, b.local_addr().unwrap()).await;
    c.write_all(&pattern(100_000, 5)).await.unwrap();
    drop(c);
    let mut got = Vec::new();
    s.read_to_end(&mut got).await.unwrap();
    assert!(got == pattern(100_000, 5));
}

#[tokio::test]
async fn connect_without_listener_times_out() {
    let silent = udp().await;
    let a = UtpSocket::bind(udp().await);
    let started = Instant::now();
    let err = a.connect(silent.local_addr().unwrap()).await.err().unwrap();
    let took = started.elapsed();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(took >= Duration::from_millis(3900) && took < Duration::from_secs(6), "{took:?}");
    assert!(a.inner.registry.lock().unwrap().is_empty());
}

#[tokio::test]
async fn silent_peer_hits_idle_timeout() {
    let a = UtpSocket::bind_with(udp().await, Config { idle: Duration::from_millis(1500), first_seq: None });
    let b = UtpSocket::bind(udp().await);
    let (mut c, _s) = connected(&a, &b, b.local_addr().unwrap()).await;
    drop(b);
    let started = Instant::now();
    let err = c.read(&mut [0u8; 8]).await.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn reset_surfaces_as_error() {
    let raw = udp().await;
    let a = UtpSocket::bind(udp().await);
    let raw_addr = raw.local_addr().unwrap();
    let connecting = tokio::spawn(async move {
        let stream = a.connect(raw_addr).await.unwrap();
        (a, stream)
    });
    let mut buf = [0u8; 64];
    let (n, from) = raw.recv_from(&mut buf).await.unwrap();
    let (syn, _) = decode(&buf[..n]).unwrap();
    assert_eq!(syn.kind, Kind::Syn);
    let state = Header { kind: Kind::State, conn_id: syn.conn_id, timestamp: 0, timestamp_diff: 0, wnd_size: 65536, seq_nr: 100, ack_nr: syn.seq_nr };
    raw.send_to(&state.encode(&[]), from).await.unwrap();
    let (_a, mut stream) = connecting.await.unwrap();
    let reset = Header { kind: Kind::Reset, seq_nr: 100, ..state };
    raw.send_to(&reset.encode(&[]), from).await.unwrap();
    let err = stream.read(&mut [0u8; 8]).await.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(stream.write_all(b"x").await.err().unwrap().kind(), io::ErrorKind::ConnectionReset);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn twenty_streams_demux_and_junk_is_ignored() {
    const STREAMS: u32 = 20;
    let a = Arc::new(UtpSocket::bind(udp().await));
    let b = Arc::new(UtpSocket::bind(udp().await));
    let target = b.local_addr().unwrap();

    let junk = udp().await;
    for junk_packet in [vec![], vec![0u8; 3], vec![0xffu8; 40], vec![0x41; 19], vec![0x41; 20], vec![0x21; 25]] {
        junk.send_to(&junk_packet, target).await.unwrap();
    }
    let hostile = header(Kind::Data).encode(b"data for nobody");
    junk.send_to(&hostile, target).await.unwrap();

    let server = {
        let b = b.clone();
        tokio::spawn(async move {
            let mut readers = Vec::new();
            for _ in 0..STREAMS {
                let (mut s, _) = b.accept().await.unwrap();
                readers.push(tokio::spawn(async move {
                    let mut got = Vec::new();
                    s.read_to_end(&mut got).await.unwrap();
                    let id = u32::from_be_bytes(got[..4].try_into().unwrap());
                    assert!(got[4..] == pattern(60_000, id), "stream {id} corrupted");
                    id
                }));
            }
            let mut ids = Vec::new();
            for r in readers {
                ids.push(r.await.unwrap());
            }
            ids.sort();
            ids
        })
    };

    let mut writers = Vec::new();
    for id in 0..STREAMS {
        let a = a.clone();
        writers.push(tokio::spawn(async move {
            let mut s = a.connect(target).await.unwrap();
            let mut data = id.to_be_bytes().to_vec();
            data.extend(pattern(60_000, id));
            s.write_all(&data).await.unwrap();
            s.shutdown().await.unwrap();
            s
        }));
    }
    let mut kept = Vec::new();
    for w in writers {
        kept.push(w.await.unwrap());
    }
    let ids = tokio::time::timeout(Duration::from_secs(30), server).await.unwrap().unwrap();
    assert_eq!(ids, (0..STREAMS).collect::<Vec<_>>());
}
