//! torrust — a BitTorrent client written from scratch in Rust.
//!
//! Module layout:
//! - [`bencode`] — the BEncode serialisation format
//! - [`metainfo`] — `.torrent` parsing and magnet URIs
//! - [`storage`] — mapping the flat payload stream onto files, and SHA-1 checks
//! - [`peer`] — the peer wire protocol (BEP 3) and the peer pool
//! - [`tracker`] — HTTP and UDP tracker announces
//! - [`dht`] — Kademlia DHT and metadata exchange
//! - [`scheduler`] — piece selection, rarest-first with endgame
//! - [`engine`] — orchestration
//! - [`state`] — snapshots published to the UI
//! - [`tui`] — the terminal interface

pub mod bencode;
pub mod dht;
pub mod engine;
pub mod import;
pub mod metainfo;
pub mod peer;
pub mod portmap;
pub mod ratelimit;
pub mod scheduler;
pub mod state;
pub mod storage;
pub mod tracker;
pub mod tui;

pub use metainfo::{InfoHash, Magnet, Metainfo};