//! OSPFv3 Hello packet (RFC 5340 Appendix A.3.2).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Interface ID                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Rtr Priority  |             Options                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |        HelloInterval          |       RouterDeadInterval      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   Designated Router ID                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |               Backup Designated Router ID                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Neighbor                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                              ...                              |
//! ```
//!
//! Differences from v2 Hello:
//! - No Network Mask — OSPFv3 runs per-link, not per-subnet
//! - New Interface ID field (u32) — identifies the interface within the
//!   advertising router's link-state database
//! - Options field is now 24 bits (vs 8 in v2)
//! - DR and BDR are identified by their Router ID, not interface address

use std::net::Ipv4Addr;

use super::PacketV3Error;

pub const HELLO_V3_MIN_LEN: usize = 20;

/// OSPFv3 Options (RFC 5340 Appendix A.2). 24-bit field.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options(pub u32);

impl Options {
    pub const V6: u32 = 0x01; // V6-bit (this router operates on IPv6)
    pub const E: u32 = 0x02; // External routing capability
    pub const MC: u32 = 0x04; // Multicast-capable (deprecated)
    pub const N: u32 = 0x08; // NSSA
    pub const R: u32 = 0x10; // Router is active (forwarding traffic)
    pub const DC: u32 = 0x20; // Demand circuits

    /// Standard options: V6 + E + R
    pub fn standard() -> Self {
        Self(Self::V6 | Self::E | Self::R)
    }
}

#[derive(Debug, Clone)]
pub struct HelloV3Packet {
    pub interface_id: u32,
    pub router_priority: u8,
    pub options: Options,
    pub hello_interval: u16,
    pub router_dead_interval: u16,
    pub designated_router_id: Ipv4Addr,
    pub backup_designated_router_id: Ipv4Addr,
    pub neighbors: Vec<Ipv4Addr>,
}

impl HelloV3Packet {
    pub fn parse(data: &[u8]) -> Result<Self, PacketV3Error> {
        if data.len() < HELLO_V3_MIN_LEN {
            return Err(PacketV3Error::TooShort {
                expected: HELLO_V3_MIN_LEN,
                got: data.len(),
            });
        }

        let interface_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let router_priority = data[4];
        let options = Options(u32::from_be_bytes([0, data[5], data[6], data[7]]));
        let hello_interval = u16::from_be_bytes([data[8], data[9]]);
        let router_dead_interval = u16::from_be_bytes([data[10], data[11]]);
        let designated_router_id = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let backup_designated_router_id =
            Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        let mut neighbors = Vec::new();
        let mut off = HELLO_V3_MIN_LEN;
        while off + 4 <= data.len() {
            neighbors.push(Ipv4Addr::new(
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
            ));
            off += 4;
        }

        Ok(HelloV3Packet {
            interface_id,
            router_priority,
            options,
            hello_interval,
            router_dead_interval,
            designated_router_id,
            backup_designated_router_id,
            neighbors,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.interface_id.to_be_bytes());
        buf.push(self.router_priority);
        // 24-bit options (big-endian, high byte first after priority)
        let opts = self.options.0.to_be_bytes();
        buf.push(opts[1]);
        buf.push(opts[2]);
        buf.push(opts[3]);
        buf.extend_from_slice(&self.hello_interval.to_be_bytes());
        buf.extend_from_slice(&self.router_dead_interval.to_be_bytes());
        buf.extend_from_slice(&self.designated_router_id.octets());
        buf.extend_from_slice(&self.backup_designated_router_id.octets());
        for n in &self.neighbors {
            buf.extend_from_slice(&n.octets());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_v3_roundtrip() {
        let hello = HelloV3Packet {
            interface_id: 42,
            router_priority: 1,
            options: Options::standard(),
            hello_interval: 10,
            router_dead_interval: 40,
            designated_router_id: Ipv4Addr::new(1, 1, 1, 1),
            backup_designated_router_id: Ipv4Addr::new(2, 2, 2, 2),
            neighbors: vec![Ipv4Addr::new(3, 3, 3, 3)],
        };

        let mut buf = Vec::new();
        hello.encode(&mut buf);
        assert_eq!(buf.len(), HELLO_V3_MIN_LEN + 4);

        let parsed = HelloV3Packet::parse(&buf).unwrap();
        assert_eq!(parsed.interface_id, 42);
        assert_eq!(parsed.router_priority, 1);
        assert_eq!(parsed.options.0, Options::V6 | Options::E | Options::R);
        assert_eq!(parsed.hello_interval, 10);
        assert_eq!(parsed.router_dead_interval, 40);
        assert_eq!(parsed.designated_router_id, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(parsed.neighbors.len(), 1);
        assert_eq!(parsed.neighbors[0], Ipv4Addr::new(3, 3, 3, 3));
    }

    #[test]
    fn test_hello_v3_too_short() {
        assert!(HelloV3Packet::parse(&[0u8; 10]).is_err());
    }
}
