//! torrentide — a BitTorrent client written from scratch in Rust.
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
//! - [`session`] — multi-torrent session, with [`store`] persistence and [`ipc`] hand-off
//! - [`webseed`] — HTTP web seeds (BEP 19)
//! - [`tui`] — the terminal interface

pub mod bencode;
pub mod blocklist;
pub mod create;
pub mod dht;
pub mod engine;
pub mod import;
pub mod ipc;
pub mod lsd;
pub mod metainfo;
pub mod peer;
pub mod portmap;
pub mod ratelimit;
pub mod redact;
pub mod rss;
pub mod schedule;
pub mod scheduler;
pub mod session;
pub mod state;
pub mod storage;
pub mod store;
pub mod tracker;
pub mod tui;
pub mod utp;
pub mod webseed;
pub mod webui;

pub use metainfo::{InfoHash, Magnet, Metainfo};