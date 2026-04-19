//! OSPF Hello packet (RFC 2328 Section A.3.2).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Network Mask                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         HelloInterval         |    Options    |    Rtr Pri    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     RouterDeadInterval                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Designated Router                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   Backup Designated Router                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Neighbor                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                              ...                              |
//! ```

use std::net::Ipv4Addr;

use super::PacketError;

/// OSPF Options field bits (RFC 2328 Section A.2).
#[derive(Debug, Clone, Copy, Default)]
pub struct OspfOptions(pub u8);

impl OspfOptions {
    pub const E_BIT: u8 = 0x02; // External routing capability
    pub const MC_BIT: u8 = 0x04; // Multicast capability
    pub const NP_BIT: u8 = 0x08; // NSSA capability
    pub const EA_BIT: u8 = 0x10; // External attributes (deprecated)
    pub const DC_BIT: u8 = 0x20; // Demand circuits
    pub const O_BIT: u8 = 0x40; // Opaque LSA capability

    /// Standard options for a non-stub router: E-bit set.
    pub fn standard() -> Self {
        Self(Self::E_BIT)
    }

    pub fn has_e_bit(self) -> bool {
        self.0 & Self::E_BIT != 0
    }
}

pub const HELLO_MIN_LEN: usize = 20;

#[derive(Debug, Clone)]
pub struct HelloPacket {
    pub network_mask: Ipv4Addr,
    pub hello_interval: u16,
    pub options: OspfOptions,
    pub router_priority: u8,
    pub router_dead_interval: u32,
    pub designated_router: Ipv4Addr,
    pub backup_designated_router: Ipv4Addr,
    /// List of router IDs from which valid Hello packets have been seen
    /// on this network in the past RouterDeadInterval.
    pub neighbors: Vec<Ipv4Addr>,
}

impl HelloPacket {
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < HELLO_MIN_LEN {
            return Err(PacketError::TooShort {
                expected: HELLO_MIN_LEN,
                got: data.len(),
            });
        }

        let network_mask = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
        let hello_interval = u16::from_be_bytes([data[4], data[5]]);
        let options = OspfOptions(data[6]);
        let router_priority = data[7];
        let router_dead_interval = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let designated_router = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let backup_designated_router = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        // Remaining bytes are neighbor router IDs (4 bytes each)
        let neighbor_data = &data[HELLO_MIN_LEN..];
        let mut neighbors = Vec::with_capacity(neighbor_data.len() / 4);
        let mut off = 0;
        while off + 4 <= neighbor_data.len() {
            neighbors.push(Ipv4Addr::new(
                neighbor_data[off],
                neighbor_data[off + 1],
                neighbor_data[off + 2],
                neighbor_data[off + 3],
            ));
            off += 4;
        }

        Ok(HelloPacket {
            network_mask,
            hello_interval,
            options,
            router_priority,
            router_dead_interval,
            designated_router,
            backup_designated_router,
            neighbors,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.network_mask.octets());
        buf.extend_from_slice(&self.hello_interval.to_be_bytes());
        buf.push(self.options.0);
        buf.push(self.router_priority);
        buf.extend_from_slice(&self.router_dead_interval.to_be_bytes());
        buf.extend_from_slice(&self.designated_router.octets());
        buf.extend_from_slice(&self.backup_designated_router.octets());
        for neighbor in &self.neighbors {
            buf.extend_from_slice(&neighbor.octets());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_roundtrip() {
        let hello = HelloPacket {
            network_mask: Ipv4Addr::new(255, 255, 255, 0),
            hello_interval: 10,
            options: OspfOptions::standard(),
            router_priority: 1,
            router_dead_interval: 40,
            designated_router: Ipv4Addr::new(10, 0, 0, 1),
            backup_designated_router: Ipv4Addr::new(10, 0, 0, 2),
            neighbors: vec![
                Ipv4Addr::new(1, 1, 1, 1),
                Ipv4Addr::new(2, 2, 2, 2),
            ],
        };

        let mut buf = Vec::new();
        hello.encode(&mut buf);

        let parsed = HelloPacket::parse(&buf).unwrap();
        assert_eq!(parsed.network_mask, hello.network_mask);
        assert_eq!(parsed.hello_interval, 10);
        assert_eq!(parsed.options.0, OspfOptions::E_BIT);
        assert_eq!(parsed.router_priority, 1);
        assert_eq!(parsed.router_dead_interval, 40);
        assert_eq!(parsed.designated_router, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(parsed.backup_designated_router, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(parsed.neighbors.len(), 2);
        assert_eq!(parsed.neighbors[0], Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(parsed.neighbors[1], Ipv4Addr::new(2, 2, 2, 2));
    }
}
