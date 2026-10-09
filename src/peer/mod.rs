//! Peer wire protocol and peer connection management.

pub mod connection;
pub mod pool;
pub mod wire;

pub use connection::{FromPeer, PeerHandle, PeerState, ToPeer, BLOCK_SIZE};
pub use pool::{PeerPool, MAX_PEERS, MIN_PEERS};
pub use wire::{Bitfield, Message, WireError};