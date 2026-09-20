//! Parse network packets transmitted between the game and the server
//!
//! Packets are built up in following layers depending on the purpose of the packet:
//!
//! - Packets for connection management ([`GamePacket::Connection`])
//!     - **Ethernet/IP/UDP**, handled using [`etherparse`]
//!     - **[`ConnectionPacket`]**, containing events for connection establishment/disconnection
//! - Packets for game commands ([`GamePacket::Commands`])
//!     - **Ethernet/IP/UDP**, handled using [`etherparse`]
//!     - **KCP**, handled using [`kcp`]
//!         - The KCP header contains an extra field that needs to be removed
//!           to be compatible with the regular KCP protocol
//!     - **[`GameCommand`]**, encrypted using XOR
//!     - **Protobuf**, payload, needs to be parsed into using the types generated in [`gen::proto`]
//!
//! [`GameCommand`]s are encrypted using an XOR-key.
//! One of the first packets sent is a request for a new key from a seed.
//! That key is used for the rest of the packets.
//! This means the recording for packets needs to start before the game starts (train hyperdrive).
//!
//! ## Example
//! ```
//! use auto_artifactarium::{GamePacket, GameSniffer, ConnectionPacket};
//!
//! let packets: Vec<Vec<u8>> = vec![/**/];
//!
//! let mut sniffer = GameSniffer::new();
//! for packet in packets {
//!     match sniffer.receive_packet(packet) {
//!         Some(GamePacket::Connection(ConnectionPacket::Disconnected)) => {
//!             println!("Disconnected!");
//!             break;
//!         }
//!         Some(GamePacket::Commands(commands)) => {
//!             for command in commands {
//!                 println!("{:?}", command);
//!             }
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey};
use tracing::{error, info, info_span, instrument, trace, warn};

use crate::connection::parse_connection_packet;
use crate::crypto::{
    KEY_LEN, bruteforce, decrypt_command, key_from_known_body, lookup_initial_key,
};
// use crate::gen::protos::GetPlayerTokenRsp;
use crate::Key::Dispatch;
use crate::r#gen::protos::PacketHead;
use crate::kcp::KcpSniffer;
pub use crate::unk_util::Achievement;
pub use crate::unk_util::{
    matches_achievement_all_data_notify, matches_avatars_all_data_notify,
    matches_get_player_token_rsp, matches_items_all_data_notify,
};

fn bytes_as_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02x}");
        output
    })
}

/// Whether `data` is a plaintext game command frame: magic `45 67` and `89 AB`.
fn looks_like_command(data: &[u8]) -> bool {
    data.len() >= 4
        && data[0] == 0x45
        && data[1] == 0x67
        && data[data.len() - 2] == 0x89
        && data[data.len() - 1] == 0xAB
}

/// Whether `key` is the key that opens `data`.
fn opens_command(key: &[u8], data: &[u8]) -> bool {
    let mut test = data.to_vec();
    decrypt_command(key, &mut test);
    looks_like_command(&test)
}

// pub mod command_id;
pub mod r#gen;

mod connection;
mod crypto;
mod cs_rand;
mod kcp;
mod proto_json;
mod unk_util;

const PORTS: [u16; 2] = [22101, 22102];

/// Top-level packet sent by the game
pub enum GamePacket {
    Connection(ConnectionPacket),
    Commands(Vec<GameCommand>),
}

/// Packet for connection management
pub enum ConnectionPacket {
    HandshakeRequested,
    Disconnected,
    HandshakeEstablished,
    SegmentData(PacketDirection, Vec<u8>),
}

#[repr(u16)]
enum CommandId {
    AvatarDataNotify = 6586,
    PlayerStoreNotify = 8132,
}

/// Game command header.
///
/// Contains the type of the command in `command_id`
/// and the data encoded in protobuf in `proto_data`
///
/// ## Bit Layout
/// | Bit indices     |  Type |  Name |
/// | - | - | - |
/// |   0..2      |  `u16`  |  Header (magic constant) |
/// |   2..4      |  `u16`  |  command_id |
/// |   4..6      |  `u16`  |  header_len — length of the extended header |
/// |   6..10     |  `u32`  |  data_len — length of `proto_data` |
/// | 10..10+header_len |  variable  |  extended header (protobuf-encoded; carries a `unix_time` field) |
/// | 10+header_len..10+header_len+data_len |  variable  |  proto_data |
/// |  len-2..len  |  `u16`  |  Tail (magic constant) |
///
/// `header_len` is zero for most commands, in which case the extended header is
/// absent and `proto_data` starts directly at byte 10.
#[derive(Clone)]
pub struct GameCommand {
    pub command_id: u16,
    #[allow(unused)]
    pub header_len: u16,
    #[allow(unused)]
    pub data_len: u32,
    /// Serialized `PacketHead` carried before the body when `header_len` > 0.
    pub ext_header: Vec<u8>,
    pub proto_data: Vec<u8>,
    /// Whether this command was sent by the client or received from the server.
    pub direction: PacketDirection,
}

impl GameCommand {
    const HEADER_LEN: usize = 10;
    const TAIL_LEN: usize = 2;

    #[instrument(skip(bytes), fields(len = bytes.len()))]
    pub fn try_new(bytes: Vec<u8>, direction: PacketDirection) -> Option<Self> {
        let header_overhead = Self::HEADER_LEN + Self::TAIL_LEN;
        if bytes.len() < header_overhead {
            warn!(len = bytes.len(), "game command header incomplete");
            return None;
        }

        if bytes[0] != 0x45
            || bytes[1] != 0x67
            || bytes[bytes.len() - 2] != 0x89
            || bytes[bytes.len() - 1] != 0xAB
        {
            error!("Didn't get magic in try_new!");
            return None;
        }

        // skip header magic const
        let command_id = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        let header_len = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        let data_len = u32::from_be_bytes(bytes[6..10].try_into().unwrap());

        // The extended header (a serialized `PacketHead`) sits between the
        // fixed header and the protobuf body.
        let body_start = Self::HEADER_LEN + header_len as usize;
        let body_end = body_start + data_len as usize;
        let (Some(ext), Some(body)) = (
            bytes.get(Self::HEADER_LEN..body_start),
            bytes.get(body_start..body_end),
        ) else {
            warn!(
                len = bytes.len(),
                header_len, data_len, "game command body exceeds buffer"
            );
            return None;
        };

        Some(GameCommand {
            command_id,
            header_len,
            data_len,
            ext_header: ext.to_vec(),
            proto_data: body.to_vec(),
            direction,
        })
    }

    /// Human-readable packet direction for JSON output: `"sent"` or `"received"`.
    pub fn direction_str(&self) -> &'static str {
        match self.direction {
            PacketDirection::Sent => "sent",
            PacketDirection::Received => "received",
        }
    }

    pub fn parse_proto<T: protobuf::Message>(&self) -> protobuf::Result<T> {
        T::parse_from_bytes(&self.proto_data)
    }

    /// Parse the extended header as `PacketHead`. Falls back to the body for
    /// commands that carry no extended header.
    pub fn parse_head(&self) -> protobuf::Result<PacketHead> {
        let bytes = if self.ext_header.is_empty() {
            &self.proto_data
        } else {
            &self.ext_header
        };
        protobuf::Message::parse_from_bytes(bytes)
    }

    pub fn is_avatar_data_notify(&self) -> bool {
        self.command_id == CommandId::AvatarDataNotify as u16
    }

    pub fn is_player_store_notify(&self) -> bool {
        self.command_id == CommandId::PlayerStoreNotify as u16
    }

    /// Serialize this command to a JSON object for UI display:
    /// `{cmd_id, name, direction, header_len, size, data}` where `data` is the
    /// proto body parsed via reflection. Returns `None` for command ids whose
    /// body message type is unknown.
    pub fn to_json(&self) -> Option<serde_json::Value> {
        proto_json::command_to_json(self)
    }

    /// Serialize a lightweight summary (no body values) for list display.
    pub fn summary_json(&self) -> serde_json::Value {
        proto_json::command_summary_json(self)
    }
}

impl fmt::Debug for GameCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GameCommand")
            .field("command_id", &self.command_id)
            .field("header_len", &self.header_len)
            .field("data_len", &self.data_len)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum PacketDirection {
    Sent,
    Received,
}

pub enum Key {
    Dispatch(Vec<u8>),
    Session(Vec<u8>),
}

#[derive(Default)]
pub struct GameSniffer {
    sent_kcp: Option<KcpSniffer>,
    recv_kcp: Option<KcpSniffer>,
    client_seed: Option<u64>,
    key: Option<Key>,
    initial_keys: HashMap<u16, Vec<u8>>,
    rsa_keys: Vec<RsaPrivateKey>,
    sent_time: Option<u64>,
    possible_seeds: Vec<u64>,
    /// Command bodies recovered from earlier sessions, used for a
    /// known-plaintext recovery of a session key we cannot derive from a seed.
    known_bodies: Vec<Vec<u8>>,
}

impl GameSniffer {
    pub fn new() -> Self {
        let pem_data_4 = include_str!("../keys/private_key_4.pem");
        let pem_data_5 = include_str!("../keys/private_key_5.pem");

        let rsa_4 = RsaPrivateKey::from_pkcs1_pem(pem_data_4);
        let rsa_5 = RsaPrivateKey::from_pkcs1_pem(pem_data_5);

        GameSniffer {
            rsa_keys: vec![rsa_4, rsa_5]
                .iter()
                .filter_map(|rsa_key| rsa_key.clone().ok())
                .collect(),
            ..Default::default()
        }
    }

    pub fn set_initial_keys(mut self, initial_keys: HashMap<u16, Vec<u8>>) -> Self {
        self.initial_keys = initial_keys;
        self
    }

    /// Teach the sniffer the body of a command that repeats verbatim across
    /// client processes, so its key can be recovered from ciphertext alone. In
    /// practice this is the anti-cheat Lua shell body: 167875 bytes, carrying the
    /// 4096-byte session key 41 times over.
    pub fn add_known_body(mut self, body: Vec<u8>) -> Self {
        self.known_bodies.push(body);
        self
    }

    /// The command bodies this sniffer can open a future session with: the ones
    /// injected through [`add_known_body`](Self::add_known_body) plus the ones it
    /// noted while decrypting. Persist these to carry them into the next process.
    pub fn known_bodies(&self) -> &[Vec<u8>] {
        &self.known_bodies
    }

    /// Keep a copy of a command body long enough to carry the whole session key,
    /// so a later session we cannot seed can still be opened. See
    /// `crypto::key_from_known_body`.
    fn note_known_body(&mut self, body: &[u8]) {
        const MIN_BODY_LEN: usize = 2 * KEY_LEN;
        const MAX_SAMPLES: usize = 4;

        if body.len() < MIN_BODY_LEN
            || self.known_bodies.iter().any(|kept| kept.len() == body.len())
        {
            return;
        }
        // Prefer the longest bodies: each 4096 bytes is another copy of the key,
        // so a region that does vary between sessions still leaves every byte a
        // clear majority.
        let shortest = self.known_bodies.iter().map(Vec::len).min().unwrap_or(0);
        if self.known_bodies.len() == MAX_SAMPLES {
            if body.len() <= shortest {
                return;
            }
            let worst = self
                .known_bodies
                .iter()
                .position(|kept| kept.len() == shortest)
                .unwrap();
            self.known_bodies.remove(worst);
        }
        info!(len = body.len(), "noting known command body");
        self.known_bodies.push(body.to_vec());
    }

    #[instrument(skip_all, fields(len = bytes.len()))]
    pub fn receive_packet(&mut self, bytes: Vec<u8>) -> Option<GamePacket> {
        let packet = parse_connection_packet(&PORTS, bytes)?;
        match packet {
            ConnectionPacket::HandshakeRequested => {
                info!("handshake requested, resetting state");
                self.recv_kcp = None;
                self.sent_kcp = None;
                self.key = None;
                Some(GamePacket::Connection(packet))
            }
            ConnectionPacket::HandshakeEstablished | ConnectionPacket::Disconnected => {
                Some(GamePacket::Connection(packet))
            }

            ConnectionPacket::SegmentData(direction, kcp_seg) => {
                let commands = self.receive_kcp_segment(direction, &kcp_seg);
                match commands {
                    Some(commands) => Some(GamePacket::Commands(commands)),
                    None => Some(GamePacket::Connection(ConnectionPacket::SegmentData(
                        direction, kcp_seg,
                    ))),
                }
            }
        }
    }

    fn receive_kcp_segment(
        &mut self,
        direction: PacketDirection,
        kcp_seg: &[u8],
    ) -> Option<Vec<GameCommand>> {
        let kcp = match direction {
            PacketDirection::Sent => &mut self.sent_kcp,
            PacketDirection::Received => &mut self.recv_kcp,
        };

        if kcp.is_none() {
            let new_kcp = KcpSniffer::try_new(kcp_seg)?;
            *kcp = Some(new_kcp);
        }

        if let Some(kcp) = kcp {
            let commands = kcp
                .receive_segments(kcp_seg)
                .into_iter()
                .filter_map(|data| self.receive_command(direction, data))
                .collect();

            return Some(commands);
        }

        None
    }

    #[instrument(skip_all, fields(len = data.len()))]
    fn receive_command(&mut self, direction: PacketDirection, mut data: Vec<u8>) -> Option<GameCommand> {
        let key_r = match &self.key {
            None => {
                let key = lookup_initial_key(&self.initial_keys, &data);
                match key {
                    Some(key) => {
                        self.key = Some(Dispatch(key));
                        self.key.as_ref().unwrap()
                    }
                    None => {
                        error!("No dispatch key found");
                        return None;
                    }
                }
            }
            Some(Dispatch(k)) => {
                let mut test = data.clone();
                decrypt_command(k, &mut test);

                if looks_like_command(&test) {
                    self.key.as_ref().unwrap()
                } else {
                    match self.deduce_key(&data) {
                        Some(key) => {
                            self.key = Some(Key::Session(key));
                            self.key.as_ref().unwrap()
                        }
                        None => {
                            error!("Couldn't deduce the session key");
                            return None;
                        }
                    }
                }
            }
            Some(Key::Session(k)) => {
                let mut test = data.clone();
                decrypt_command(k, &mut test);

                if looks_like_command(&test) {
                    self.key.as_ref().unwrap()
                } else {
                    // The session key either stopped working because the client
                    // re-authenticated, or was never right — the time search can
                    // hit four magic bytes by chance. Try to deduce a key that
                    // opens *this* packet before giving up on it.
                    warn!("Invalidated session key");
                    self.key = None;
                    match self.deduce_key(&data) {
                        Some(key) => {
                            self.key = Some(Key::Session(key));
                            self.key.as_ref().unwrap()
                        }
                        None => {
                            error!("Session key dead, relaunch game");
                            return None;
                        }
                    }
                }
            }
        };

        let key = match key_r {
            Dispatch(k) | Key::Session(k) => k,
        };

        decrypt_command(key, &mut data);

        let command = GameCommand::try_new(data, direction)?;

        let span = info_span!("command", ?command);
        let _enter = span.enter();

        info!("received");
        trace!(data = BASE64_STANDARD.encode(&command.proto_data), "data");

        // if !matches!(
        //     command.command_id,
        //     command_id::GET_PLAYER_TOKEN_RSP | command_id::ACHIEVEMENT_ALL_DATA_NOTIFY
        // ) {
        //     return None;
        // }

        if matches!(self.key, Some(Key::Session(_))) {
            self.note_known_body(&command.proto_data);
        }

        if let Some(Dispatch(_)) = self.key {
            if let Some(possible_seeds) =
                matches_get_player_token_rsp(command.proto_data.clone(), self.rsa_keys.clone())
            {
                self.possible_seeds = possible_seeds;
                info!(?self.possible_seeds, "setting new possible session seeds");
                let header_command = command.parse_head().unwrap();
                self.sent_time = Some(header_command.sent_ms);
                info!(?self.sent_time, "setting new send time");
            }
        }

        Some(command)
    }

    /// Recover the session key that opens `data`.
    ///
    /// The time-anchored bruteforce only works for a client process's *first*
    /// login. Measured across a day of captures: a re-auth inside a long-running
    /// client keeps the rand key it chose when the process started, and no
    /// wall-clock time in the 26 hours before its handshake yielded the key. For
    /// those sessions a known plaintext is the only way in, so try it first — it
    /// is also orders of magnitude cheaper than searching.
    #[instrument(skip_all, fields(len = data.len()))]
    fn deduce_key(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        for body in &self.known_bodies {
            if let Some(key) = key_from_known_body(body, data)
                && opens_command(&key, data)
            {
                info!("recovered session key from a known command body");
                return Some(key);
            }
        }

        let seeds = self.possible_seeds.clone();
        let anchors: Vec<u64> = self.client_seed.into_iter().chain(self.sent_time).collect();
        let bruteforced = seeds.iter().find_map(|&server| {
            anchors
                .iter()
                .find_map(|&anchor| bruteforce(anchor, server, data.to_vec()))
        });

        if let Some((time, key)) = bruteforced {
            self.client_seed = Some(time);
            return Some(key);
        }
        None
    }
}

pub fn matches_achievement_packet(game_command: &GameCommand) -> Option<Vec<Achievement>> {
    return matches_achievement_all_data_notify(game_command.proto_data.clone());
}

/// Heuristic item packet matching — does not depend on command_id.
pub fn matches_item_packet(game_command: &GameCommand) -> Option<Vec<r#gen::protos::Item>> {
    return matches_items_all_data_notify(&game_command.proto_data);
}

/// Heuristic avatar packet matching — does not depend on command_id.
pub fn matches_avatar_packet(game_command: &GameCommand) -> Option<Vec<r#gen::protos::AvatarInfo>> {
    return matches_avatars_all_data_notify(&game_command.proto_data);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(header_len: u16, ext: &[u8], body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x45, 0x67, 0x19, 0x81];
        out.extend_from_slice(&header_len.to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(ext);
        out.extend_from_slice(body);
        out.extend_from_slice(&[0x89, 0xAB]);
        out
    }

    #[test]
    fn proto_data_skips_extended_header() {
        let ext = [0x18, 0x57, 0x30, 0xd0, 0xc5, 0x9d, 0x97, 0x8b, 0x34];
        let body = [0x12, 0x02, 0x01, 0x02, 0x60, 0x03];
        let cmd = GameCommand::try_new(frame(9, &ext, &body), PacketDirection::Received).unwrap();
        assert_eq!(cmd.command_id, 6529);
        assert_eq!(cmd.ext_header, ext);
        assert_eq!(cmd.proto_data, body);
    }

    #[test]
    fn proto_data_starts_at_10_without_extended_header() {
        let body = [0x08, 0x01, 0x12, 0x00];
        let cmd = GameCommand::try_new(frame(0, &[], &body), PacketDirection::Sent).unwrap();
        assert_eq!(cmd.proto_data, body);
    }

    #[test]
    fn rejects_frame_whose_body_exceeds_buffer() {
        let mut buf = frame(0, &[], &[0x08, 0x01]);
        buf[6..10].copy_from_slice(&9999u32.to_be_bytes());
        assert!(GameCommand::try_new(buf, PacketDirection::Sent).is_none());
    }
}
