//! Interop check of the MSE initiator against an independent responder.
//! Run `python3 -I scripts/dev/mse_responder.py <port> <infohash-hex>` first, then
//! `MSE_PEER=127.0.0.1:<port> cargo test --test mse_interop -- --ignored`.

use torrentide::metainfo::InfoHash;
use torrentide::peer::{mse, wire};
use torrentide::state::EncryptionMode;

#[tokio::test]
#[ignore]
async fn initiator_talks_to_reference_responder() {
    let addr = std::env::var("MSE_PEER").expect("set MSE_PEER");
    let infohash = match std::env::var("MSE_INFOHASH") {
        Ok(h) => InfoHash::from_hex(&h).unwrap(),
        Err(_) => InfoHash([0x5a; 20]),
    };
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut s = mse::connect(tcp, infohash, EncryptionMode::Prefer).await.unwrap();
    wire::handshake_outgoing(&mut s, &infohash.0, true, false, false).await.unwrap();
    let hs = wire::handshake_incoming(&mut s).await.unwrap();
    assert_eq!(hs.infohash, infohash.0);
}
