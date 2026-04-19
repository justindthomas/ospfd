//! OSPFv3 Database Description packet (RFC 5340 Appendix A.3.3).
//!
//! Format differences from v2:
//! - Interface MTU field is still 16 bits
//! - Options field is now 24 bits (expanded from 8 in v2) and appears
//!   AFTER the reserved/MTU bytes
//! - Flags are still 8 bits (I, M, MS only)
//! - DD sequence number is still 32 bits
//! - Body contains a list of 20-byte LSA headers
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |       0       |               Options                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |        Interface MTU          |      0        |0|0|0|0|0|I|M|MS
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     DD Sequence Number                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                                                               +
//! |                       An LSA header                           |
//! +                                                               +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use super::lsa::{LsaV3Header, LSA_V3_HEADER_LEN};
use super::PacketV3Error;

pub const DD_V3_MIN_LEN: usize = 12;
pub const DD_V3_FLAG_MS: u8 = 0x01;
pub const DD_V3_FLAG_M: u8 = 0x02;
pub const DD_V3_FLAG_I: u8 = 0x04;

#[derive(Debug, Clone)]
pub struct DbDescV3Packet {
    pub options: u32, // 24-bit
    pub interface_mtu: u16,
    pub flags: u8,
    pub dd_sequence_number: u32,
    pub lsa_headers: Vec<LsaV3Header>,
}

impl DbDescV3Packet {
    pub fn is_master(&self) -> bool {
        self.flags & DD_V3_FLAG_MS != 0
    }
    pub fn has_more(&self) -> bool {
        self.flags & DD_V3_FLAG_M != 0
    }
    pub fn is_init(&self) -> bool {
        self.flags & DD_V3_FLAG_I != 0
    }

    pub fn parse(data: &[u8]) -> Result<Self, PacketV3Error> {
        if data.len() < DD_V3_MIN_LEN {
            return Err(PacketV3Error::TooShort {
                expected: DD_V3_MIN_LEN,
                got: data.len(),
            });
        }
        // data[0] reserved
        let options = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        let interface_mtu = u16::from_be_bytes([data[4], data[5]]);
        // data[6] reserved
        let flags = data[7];
        let dd_sequence_number = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let mut lsa_headers = Vec::new();
        let mut off = DD_V3_MIN_LEN;
        while off + LSA_V3_HEADER_LEN <= data.len() {
            lsa_headers.push(LsaV3Header::parse(&data[off..])?);
            off += LSA_V3_HEADER_LEN;
        }

        Ok(DbDescV3Packet {
            options,
            interface_mtu,
            flags,
            dd_sequence_number,
            lsa_headers,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(0); // reserved
        let opts = self.options.to_be_bytes();
        buf.push(opts[1]);
        buf.push(opts[2]);
        buf.push(opts[3]);
        buf.extend_from_slice(&self.interface_mtu.to_be_bytes());
        buf.push(0); // reserved
        buf.push(self.flags);
        buf.extend_from_slice(&self.dd_sequence_number.to_be_bytes());
        for hdr in &self.lsa_headers {
            hdr.encode(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::lsa::LsaV3Type;
    use std::net::Ipv4Addr;

    #[test]
    fn test_dd_v3_roundtrip() {
        let dd = DbDescV3Packet {
            options: 0x000013,
            interface_mtu: 1500,
            flags: DD_V3_FLAG_I | DD_V3_FLAG_M | DD_V3_FLAG_MS,
            dd_sequence_number: 0xDEADBEEF,
            lsa_headers: vec![LsaV3Header {
                ls_age: 100,
                ls_type: LsaV3Type::Router,
                link_state_id: Ipv4Addr::new(1, 1, 1, 1),
                advertising_router: Ipv4Addr::new(1, 1, 1, 1),
                ls_sequence_number: 0x80000001u32 as i32,
                ls_checksum: 0xABCD,
                length: 40,
            }],
        };

        let mut buf = Vec::new();
        dd.encode(&mut buf);
        assert_eq!(buf.len(), DD_V3_MIN_LEN + LSA_V3_HEADER_LEN);

        let parsed = DbDescV3Packet::parse(&buf).unwrap();
        assert_eq!(parsed.options, 0x000013);
        assert_eq!(parsed.interface_mtu, 1500);
        assert!(parsed.is_init());
        assert!(parsed.has_more());
        assert!(parsed.is_master());
        assert_eq!(parsed.dd_sequence_number, 0xDEADBEEF);
        assert_eq!(parsed.lsa_headers.len(), 1);
    }
}
