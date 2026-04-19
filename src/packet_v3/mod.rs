//! OSPFv3 packet parsing and serialization (RFC 5340).
//!
//! OSPFv3 is OSPF for IPv6. It shares the state machines, SPF, and
//! flooding semantics with OSPFv2 but has completely different wire
//! formats:
//!
//! - **Packet header**: 16 bytes instead of 24. No embedded authentication
//!   field — IPv6 OSPF relies on IPsec (AH or ESP). A new 1-byte Instance
//!   ID field allows multiple OSPFv3 instances per link.
//! - **LSA header**: 20 bytes. The Options field has moved out of the
//!   LSA header into the Router-LSA body.
//! - **Router-LSA**: no longer carries prefixes — link-local connectivity
//!   only. Prefixes are advertised via Intra-Area-Prefix-LSA (Type 9).
//! - **New LSA types**: Link-LSA (Type 8), Intra-Area-Prefix-LSA (Type 9).
//! - **No Network Mask**: addresses are carried as (prefix_length, prefix)
//!   tuples with variable encoding.
//!
//! This module provides the wire format; the daemon's state machines
//! and SPF are shared with the v2 implementation via trait abstractions.

pub mod dd;
pub mod header;
pub mod hello;
pub mod lsa;
pub mod lsack;
pub mod lsr;
pub mod lsu;
pub mod prefix;

pub use header::{Ospfv3Header, Ospfv3PacketType, OSPFV3_HEADER_LEN, OSPFV3_VERSION};

use std::net::Ipv6Addr;

/// IPv6 All SPF Routers multicast address (ff02::5).
pub const ALL_SPF_ROUTERS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 5);

/// IPv6 All DR Routers multicast address (ff02::6).
pub const ALL_DR_ROUTERS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 6);

/// IP protocol number for OSPFv3 (same as OSPFv2).
pub const OSPFV3_IP_PROTO: u8 = 89;

/// Packet parsing errors.
#[derive(Debug, thiserror::Error)]
pub enum PacketV3Error {
    #[error("packet too short: expected {expected}, got {got}")]
    TooShort { expected: usize, got: usize },
    #[error("bad OSPFv3 version: {0}")]
    BadVersion(u8),
    #[error("bad packet type: {0}")]
    BadPacketType(u8),
    #[error("bad LSA type: 0x{0:04x}")]
    BadLsaType(u16),
    #[error("bad checksum")]
    BadChecksum,
}
