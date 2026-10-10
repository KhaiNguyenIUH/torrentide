//! Peer wire protocol and peer connection management.

pub mod connection;
pub mod mse;
pub mod pex;
pub mod pool;
pub mod wire;

pub use connection::{FromPeer, PeerHandle, PeerState, ToPeer, BLOCK_SIZE};
pub use pool::{PeerPool, MAX_PEERS, MIN_PEERS};
pub use wire::{Bitfield, Message, WireError};
/// A byte stream to a peer: plain TCP, uTP, or either wrapped in Message
/// Stream Encryption. Connections are generic over it so every transport
/// shares one wire-protocol implementation.
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> AsyncStream for T {}

/// A boxed peer stream, for code that picks the transport at runtime.
pub type PeerStream = Box<dyn AsyncStream>;
