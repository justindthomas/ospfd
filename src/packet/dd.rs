//! OSPF Database Description packet (RFC 2328 Section A.3.3).
//!
//! Used during adjacency formation to exchange LSDB summaries.

use super::PacketError;
use super::hello::OspfOptions;
use super::lsa::{LsaHeader, LSA_HEADER_LEN};

/// DD packet flags.
pub const DD_FLAG_MS: u8 = 0x01; // Master/Slave bit
pub const DD_FLAG_M: u8 = 0x02; // More bit
pub const DD_FLAG_I: u8 = 0x04; // Init bit

pub const DD_MIN_LEN: usize = 8;

/// Database Description packet body.
#[derive(Debug, Clone)]
pub struct DbDescPacket {
    pub interface_mtu: u16,
    pub options: OspfOptions,
    pub flags: u8,
    pub dd_sequence_number: u32,
    /// LSA headers describing the sender's LSDB.
    pub lsa_headers: Vec<LsaHeader>,
}

impl DbDescPacket {
    pub fn is_master(&self) -> bool {
        self.flags & DD_FLAG_MS != 0
    }

    pub fn has_more(&self) -> bool {
        self.flags & DD_FLAG_M != 0
    }

    pub fn is_init(&self) -> bool {
        self.flags & DD_FLAG_I != 0
    }

    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < DD_MIN_LEN {
            return Err(PacketError::TooShort {
                expected: DD_MIN_LEN,
                got: data.len(),
            });
        }

        let interface_mtu = u16::from_be_bytes([data[0], data[1]]);
        let options = OspfOptions(data[2]);
        let flags = data[3];
        let dd_sequence_number = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        let mut lsa_headers = Vec::new();
        let mut off = DD_MIN_LEN;
        while off + LSA_HEADER_LEN <= data.len() {
            lsa_headers.push(LsaHeader::parse(&data[off..])?);
            off += LSA_HEADER_LEN;
        }

        Ok(DbDescPacket {
            interface_mtu,
            options,
            flags,
            dd_sequence_number,
            lsa_headers,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.interface_mtu.to_be_bytes());
        buf.push(self.options.0);
        buf.push(self.flags);
        buf.extend_from_slice(&self.dd_sequence_number.to_be_bytes());
        for header in &self.lsa_headers {
            header.encode(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::lsa::LsaType;
    use std::net::Ipv4Addr;

    #[test]
    fn test_dd_roundtrip() {
        let dd = DbDescPacket {
            interface_mtu: 1500,
            options: OspfOptions::standard(),
            flags: DD_FLAG_I | DD_FLAG_M | DD_FLAG_MS,
            dd_sequence_number: 12345,
            lsa_headers: vec![LsaHeader {
                ls_age: 10,
                options: 0x02,
                ls_type: LsaType::Router,
                link_state_id: Ipv4Addr::new(1, 1, 1, 1),
                advertising_router: Ipv4Addr::new(1, 1, 1, 1),
                ls_sequence_number: 100,
                ls_checksum: 0xABCD,
                length: 36,
            }],
        };

        let mut buf = Vec::new();
        dd.encode(&mut buf);

        let parsed = DbDescPacket::parse(&buf).unwrap();
        assert_eq!(parsed.interface_mtu, 1500);
        assert!(parsed.is_init());
        assert!(parsed.has_more());
        assert!(parsed.is_master());
        assert_eq!(parsed.dd_sequence_number, 12345);
        assert_eq!(parsed.lsa_headers.len(), 1);
        assert_eq!(parsed.lsa_headers[0].ls_type, LsaType::Router);
    }
}
