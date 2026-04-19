//! OSPFv3 packet header (RFC 5340 Appendix A.3.1).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |   Version #   |     Type      |         Packet length         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Router ID                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Area ID                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Checksum             |  Instance ID  |      0        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Differences from v2:
//! - 16 bytes total (was 24)
//! - No AuType / Authentication fields (IPsec is used instead)
//! - New Instance ID byte allows multiple OSPFv3 instances per link
//! - Router ID and Area ID are still 32-bit (not IPv6 addresses)
//!
//! Router ID and Area ID are identifiers, not addresses — they keep the
//! 32-bit "IPv4-like" format even in OSPFv3. This is why the crate uses
//! Ipv4Addr to represent them.

use std::net::Ipv4Addr;

use super::PacketV3Error;

pub const OSPFV3_HEADER_LEN: usize = 16;
pub const OSPFV3_VERSION: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ospfv3PacketType {
    Hello = 1,
    DatabaseDescription = 2,
    LinkStateRequest = 3,
    LinkStateUpdate = 4,
    LinkStateAck = 5,
}

impl Ospfv3PacketType {
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

#[derive(Debug, Clone)]
pub struct Ospfv3Header {
    pub version: u8,
    pub packet_type: Ospfv3PacketType,
    pub packet_length: u16,
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub checksum: u16,
    pub instance_id: u8,
}

impl Ospfv3Header {
    pub fn parse(data: &[u8]) -> Result<Self, PacketV3Error> {
        if data.len() < OSPFV3_HEADER_LEN {
            return Err(PacketV3Error::TooShort {
                expected: OSPFV3_HEADER_LEN,
                got: data.len(),
            });
        }
        if data[0] != OSPFV3_VERSION {
            return Err(PacketV3Error::BadVersion(data[0]));
        }
        let packet_type = Ospfv3PacketType::from_u8(data[1])
            .ok_or(PacketV3Error::BadPacketType(data[1]))?;
        let packet_length = u16::from_be_bytes([data[2], data[3]]);
        let router_id = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
        let area_id = Ipv4Addr::new(data[8], data[9], data[10], data[11]);
        let checksum = u16::from_be_bytes([data[12], data[13]]);
        let instance_id = data[14];
        // data[15] is reserved, must be zero

        Ok(Ospfv3Header {
            version: OSPFV3_VERSION,
            packet_type,
            packet_length,
            router_id,
            area_id,
            checksum,
            instance_id,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.version);
        buf.push(self.packet_type as u8);
        buf.extend_from_slice(&self.packet_length.to_be_bytes());
        buf.extend_from_slice(&self.router_id.octets());
        buf.extend_from_slice(&self.area_id.octets());
        buf.extend_from_slice(&self.checksum.to_be_bytes());
        buf.push(self.instance_id);
        buf.push(0); // reserved
    }

    pub fn new(
        packet_type: Ospfv3PacketType,
        router_id: Ipv4Addr,
        area_id: Ipv4Addr,
    ) -> Self {
        Ospfv3Header {
            version: OSPFV3_VERSION,
            packet_type,
            packet_length: 0,
            router_id,
            area_id,
            checksum: 0,
            instance_id: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let h = Ospfv3Header::new(
            Ospfv3PacketType::Hello,
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::UNSPECIFIED,
        );
        let mut buf = Vec::new();
        h.encode(&mut buf);
        assert_eq!(buf.len(), OSPFV3_HEADER_LEN);
        assert_eq!(buf[0], 3); // version
        assert_eq!(buf[1], 1); // Hello
        assert_eq!(buf[14], 0); // instance_id

        let parsed = Ospfv3Header::parse(&buf).unwrap();
        assert_eq!(parsed.version, 3);
        assert_eq!(parsed.packet_type, Ospfv3PacketType::Hello);
        assert_eq!(parsed.router_id, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(parsed.instance_id, 0);
    }

    #[test]
    fn test_bad_version_rejected() {
        let mut buf = vec![0u8; 16];
        buf[0] = 2; // v2 not v3
        buf[1] = 1;
        assert!(Ospfv3Header::parse(&buf).is_err());
    }

    #[test]
    fn test_too_short_rejected() {
        assert!(Ospfv3Header::parse(&[0u8; 8]).is_err());
    }
}
