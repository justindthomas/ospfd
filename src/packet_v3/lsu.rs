//! OSPFv3 Link State Update packet (RFC 5340 Appendix A.3.5).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            # LSAs                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +-                                                            +-+
//! |                             LSAs                              |
//! +-                                                            +-+
//! ```
//!
//! Each LSA in the body is a full 20-byte header followed by its
//! type-specific body. The LS Length in the header gives the total
//! LSA size including the header.

use super::lsa::{LsaV3Header, LSA_V3_HEADER_LEN};
use super::PacketV3Error;

pub const LSU_V3_MIN_LEN: usize = 4;

#[derive(Debug, Clone)]
pub struct LsaV3Raw {
    pub header: LsaV3Header,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct LsUpdateV3Packet {
    pub lsas: Vec<LsaV3Raw>,
}

impl LsUpdateV3Packet {
    pub fn parse(data: &[u8]) -> Result<Self, PacketV3Error> {
        if data.len() < LSU_V3_MIN_LEN {
            return Err(PacketV3Error::TooShort {
                expected: LSU_V3_MIN_LEN,
                got: data.len(),
            });
        }
        let count = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let mut lsas = Vec::with_capacity(count);
        let mut off = LSU_V3_MIN_LEN;
        for _ in 0..count {
            if off + LSA_V3_HEADER_LEN > data.len() {
                return Err(PacketV3Error::TooShort {
                    expected: off + LSA_V3_HEADER_LEN,
                    got: data.len(),
                });
            }
            let header = LsaV3Header::parse(&data[off..])?;
            let len = header.length as usize;
            if off + len > data.len() || len < LSA_V3_HEADER_LEN {
                return Err(PacketV3Error::TooShort {
                    expected: off + len,
                    got: data.len(),
                });
            }
            lsas.push(LsaV3Raw {
                header,
                raw: data[off..off + len].to_vec(),
            });
            off += len;
        }
        Ok(LsUpdateV3Packet { lsas })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.lsas.len() as u32).to_be_bytes());
        for lsa in &self.lsas {
            buf.extend_from_slice(&lsa.raw);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_v3::lsa::LsaV3Type;
    use std::net::Ipv4Addr;

    #[test]
    fn test_lsu_v3_roundtrip_empty() {
        let pkt = LsUpdateV3Packet { lsas: vec![] };
        let mut buf = Vec::new();
        pkt.encode(&mut buf);
        assert_eq!(buf.len(), 4);
        let parsed = LsUpdateV3Packet::parse(&buf).unwrap();
        assert_eq!(parsed.lsas.len(), 0);
    }

    #[test]
    fn test_lsu_v3_roundtrip_one_lsa() {
        let header = LsaV3Header {
            ls_age: 100,
            ls_type: LsaV3Type::Router,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: Ipv4Addr::new(1, 1, 1, 1),
            ls_sequence_number: 0x80000001u32 as i32,
            ls_checksum: 0xABCD,
            length: LSA_V3_HEADER_LEN as u16 + 4,
        };
        let mut raw = Vec::new();
        header.encode(&mut raw);
        raw.extend_from_slice(&[0, 0, 0, 0]); // empty Router-LSA body

        let pkt = LsUpdateV3Packet {
            lsas: vec![LsaV3Raw {
                header: header.clone(),
                raw: raw.clone(),
            }],
        };
        let mut buf = Vec::new();
        pkt.encode(&mut buf);
        assert_eq!(buf.len(), 4 + raw.len());

        let parsed = LsUpdateV3Packet::parse(&buf).unwrap();
        assert_eq!(parsed.lsas.len(), 1);
        assert_eq!(parsed.lsas[0].header.ls_type, LsaV3Type::Router);
        assert_eq!(parsed.lsas[0].raw, raw);
    }
}
