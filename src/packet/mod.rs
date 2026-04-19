//! OSPF packet parsing and serialization.
//!
//! All OSPF packets share a common 24-byte header (RFC 2328 Appendix A.3.1),
//! followed by type-specific data.

pub mod auth;
pub mod checksum;
pub mod hello;
pub mod dd;
pub mod lsr;
pub mod lsu;
pub mod lsa;

use std::net::Ipv4Addr;

use checksum::ip_checksum;

/// OSPF packet types (RFC 2328 Section A.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OspfPacketType {
    Hello = 1,
    DatabaseDescription = 2,
    LinkStateRequest = 3,
    LinkStateUpdate = 4,
    LinkStateAck = 5,
}

impl OspfPacketType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Hello),
            2 => Some(Self::DatabaseDescription),
            3 => Some(Self::LinkStateRequest),
            4 => Some(Self::LinkStateUpdate),
            5 => Some(Self::LinkStateAck),
            _ => None,
        }
    }
}

/// OSPF packet header (24 bytes).
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Version #   |     Type      |         Packet length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Router ID                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Area ID                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Checksum            |             AuType            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Authentication                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Authentication                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub const OSPF_HEADER_LEN: usize = 24;
pub const OSPF_VERSION: u8 = 2;

/// All OSPF routers multicast address.
pub const ALL_SPF_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 5);
/// All DR routers multicast address.
pub const ALL_DR_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 6);

/// IP protocol number for OSPF.
pub const OSPF_IP_PROTO: u8 = 89;

#[derive(Debug, Clone)]
pub struct OspfHeader {
    pub version: u8,
    pub packet_type: OspfPacketType,
    pub packet_length: u16,
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub checksum: u16,
    pub au_type: u16,
    pub authentication: [u8; 8],
}

impl OspfHeader {
    /// Parse an OSPF header from a byte slice (must be >= 24 bytes).
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < OSPF_HEADER_LEN {
            return Err(PacketError::TooShort {
                expected: OSPF_HEADER_LEN,
                got: data.len(),
            });
        }

        let version = data[0];
        if version != OSPF_VERSION {
            return Err(PacketError::BadVersion(version));
        }

        let ptype = OspfPacketType::from_u8(data[1])
            .ok_or(PacketError::BadPacketType(data[1]))?;

        let packet_length = u16::from_be_bytes([data[2], data[3]]);
        let router_id = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
        let area_id = Ipv4Addr::new(data[8], data[9], data[10], data[11]);
        let checksum = u16::from_be_bytes([data[12], data[13]]);
        let au_type = u16::from_be_bytes([data[14], data[15]]);
        let mut authentication = [0u8; 8];
        authentication.copy_from_slice(&data[16..24]);

        Ok(OspfHeader {
            version,
            packet_type: ptype,
            packet_length,
            router_id,
            area_id,
            checksum,
            au_type,
            authentication,
        })
    }

    /// Serialize the header into a 24-byte buffer.
    /// Checksum field is set to 0 — call `set_checksum` after building the full packet.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.version);
        buf.push(self.packet_type as u8);
        buf.extend_from_slice(&self.packet_length.to_be_bytes());
        buf.extend_from_slice(&self.router_id.octets());
        buf.extend_from_slice(&self.area_id.octets());
        buf.extend_from_slice(&self.checksum.to_be_bytes());
        buf.extend_from_slice(&self.au_type.to_be_bytes());
        buf.extend_from_slice(&self.authentication);
    }

    /// Create a new header with common fields set.
    pub fn new(
        packet_type: OspfPacketType,
        router_id: Ipv4Addr,
        area_id: Ipv4Addr,
    ) -> Self {
        OspfHeader {
            version: OSPF_VERSION,
            packet_type,
            packet_length: 0, // Set after building full packet
            router_id,
            area_id,
            checksum: 0,
            au_type: 0, // No authentication
            authentication: [0; 8],
        }
    }
}

/// Compute and insert the OSPF checksum into a fully-built packet.
///
/// The checksum covers the entire OSPF packet except the 8-byte
/// authentication field (bytes 16-23). Per RFC 2328 Section D.4.1,
/// the authentication field is excluded by zeroing it during checksum
/// computation.
pub fn set_ospf_checksum(packet: &mut [u8]) {
    if packet.len() < OSPF_HEADER_LEN {
        return;
    }
    // Zero the checksum field before computing
    packet[12] = 0;
    packet[13] = 0;
    // Save and zero the auth field
    let mut auth_save = [0u8; 8];
    auth_save.copy_from_slice(&packet[16..24]);
    packet[16..24].fill(0);

    let cksum = ip_checksum(packet);

    // Write checksum
    packet[12] = (cksum >> 8) as u8;
    packet[13] = (cksum & 0xFF) as u8;
    // Restore auth field
    packet[16..24].copy_from_slice(&auth_save);
}

/// Verify the OSPF checksum on a received packet.
pub fn verify_ospf_checksum(packet: &[u8]) -> bool {
    if packet.len() < OSPF_HEADER_LEN {
        return false;
    }
    // Build a copy with auth field zeroed (auth is excluded from checksum)
    let mut copy = packet.to_vec();
    copy[16..24].fill(0);
    ip_checksum(&copy) == 0
}

/// Parsed OSPF packet — header + type-specific body.
#[derive(Debug, Clone)]
pub enum OspfPacket {
    Hello(OspfHeader, hello::HelloPacket),
    DatabaseDescription(OspfHeader, dd::DbDescPacket),
    LinkStateRequest(OspfHeader, lsr::LsRequestPacket),
    LinkStateUpdate(OspfHeader, lsu::LsUpdatePacket),
    LinkStateAck(OspfHeader, lsa::LsAckPacket),
}

impl OspfPacket {
    /// Parse a complete OSPF packet from raw bytes (after the IP header).
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        let header = OspfHeader::parse(data)?;

        let body = &data[OSPF_HEADER_LEN..];

        match header.packet_type {
            OspfPacketType::Hello => {
                let hello = hello::HelloPacket::parse(body)?;
                Ok(OspfPacket::Hello(header, hello))
            }
            OspfPacketType::DatabaseDescription => {
                let dd = dd::DbDescPacket::parse(body)?;
                Ok(OspfPacket::DatabaseDescription(header, dd))
            }
            OspfPacketType::LinkStateRequest => {
                let lsr = lsr::LsRequestPacket::parse(body)?;
                Ok(OspfPacket::LinkStateRequest(header, lsr))
            }
            OspfPacketType::LinkStateUpdate => {
                let lsu = lsu::LsUpdatePacket::parse(body)?;
                Ok(OspfPacket::LinkStateUpdate(header, lsu))
            }
            OspfPacketType::LinkStateAck => {
                let ack = lsa::LsAckPacket::parse(body)?;
                Ok(OspfPacket::LinkStateAck(header, ack))
            }
        }
    }

    /// Serialize a complete OSPF packet (header + body) with correct
    /// length and checksum.
    pub fn encode(&self) -> Vec<u8> {
        let (header, body_fn): (&OspfHeader, Box<dyn Fn(&mut Vec<u8>)>) = match self {
            OspfPacket::Hello(h, hello) => (h, Box::new(|buf: &mut Vec<u8>| hello.encode(buf))),
            OspfPacket::DatabaseDescription(h, dd) => {
                (h, Box::new(|buf: &mut Vec<u8>| dd.encode(buf)))
            }
            OspfPacket::LinkStateRequest(h, lsr) => {
                (h, Box::new(|buf: &mut Vec<u8>| lsr.encode(buf)))
            }
            OspfPacket::LinkStateUpdate(h, lsu) => {
                (h, Box::new(|buf: &mut Vec<u8>| lsu.encode(buf)))
            }
            OspfPacket::LinkStateAck(h, ack) => {
                (h, Box::new(|buf: &mut Vec<u8>| ack.encode(buf)))
            }
        };

        let mut buf = Vec::with_capacity(256);

        // Write header (checksum and length will be fixed up)
        let mut hdr = header.clone();
        hdr.checksum = 0;
        hdr.encode(&mut buf);

        // Write body
        body_fn(&mut buf);

        // Fix up packet length
        let pkt_len = buf.len() as u16;
        buf[2] = (pkt_len >> 8) as u8;
        buf[3] = (pkt_len & 0xFF) as u8;

        // Compute and set checksum
        set_ospf_checksum(&mut buf);

        buf
    }

    pub fn header(&self) -> &OspfHeader {
        match self {
            OspfPacket::Hello(h, _) => h,
            OspfPacket::DatabaseDescription(h, _) => h,
            OspfPacket::LinkStateRequest(h, _) => h,
            OspfPacket::LinkStateUpdate(h, _) => h,
            OspfPacket::LinkStateAck(h, _) => h,
        }
    }
}

/// Packet parsing errors.
#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("packet too short: expected {expected}, got {got}")]
    TooShort { expected: usize, got: usize },
    #[error("bad OSPF version: {0}")]
    BadVersion(u8),
    #[error("bad packet type: {0}")]
    BadPacketType(u8),
    #[error("bad LSA type: {0}")]
    BadLsaType(u8),
    #[error("bad checksum")]
    BadChecksum,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_packet_full_roundtrip() {
        let header = OspfHeader::new(
            OspfPacketType::Hello,
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(0, 0, 0, 0),
        );
        let hello = hello::HelloPacket {
            network_mask: Ipv4Addr::new(255, 255, 255, 0),
            hello_interval: 10,
            options: hello::OspfOptions::standard(),
            router_priority: 1,
            router_dead_interval: 40,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: vec![Ipv4Addr::new(2, 2, 2, 2)],
        };

        let pkt = OspfPacket::Hello(header, hello);
        let encoded = pkt.encode();

        // Verify length field
        assert_eq!(encoded.len(), OSPF_HEADER_LEN + 20 + 4); // header + hello_min + 1 neighbor
        let pkt_len = u16::from_be_bytes([encoded[2], encoded[3]]) as usize;
        assert_eq!(pkt_len, encoded.len());

        // Verify checksum
        assert!(verify_ospf_checksum(&encoded));

        // Parse back
        let parsed = OspfPacket::parse(&encoded).unwrap();
        match parsed {
            OspfPacket::Hello(h, hello) => {
                assert_eq!(h.router_id, Ipv4Addr::new(1, 1, 1, 1));
                assert_eq!(h.area_id, Ipv4Addr::UNSPECIFIED);
                assert_eq!(hello.hello_interval, 10);
                assert_eq!(hello.router_dead_interval, 40);
                assert_eq!(hello.neighbors.len(), 1);
                assert_eq!(hello.neighbors[0], Ipv4Addr::new(2, 2, 2, 2));
            }
            _ => panic!("expected Hello packet"),
        }
    }

    #[test]
    fn test_bad_version_rejected() {
        let mut data = vec![0u8; 24];
        data[0] = 3; // Bad version
        data[1] = 1; // Hello type
        assert!(OspfHeader::parse(&data).is_err());
    }

    #[test]
    fn test_too_short_rejected() {
        let data = vec![0u8; 10];
        assert!(OspfHeader::parse(&data).is_err());
    }
}
