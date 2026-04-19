//! OSPFv3 Link State Acknowledgment packet (RFC 5340 Appendix A.3.6).
//!
//! Body is just a list of LSA headers (20 bytes each) — same encoding
//! as in DD packets.

use super::lsa::{LsaV3Header, LSA_V3_HEADER_LEN};
use super::PacketV3Error;

#[derive(Debug, Clone)]
pub struct LsAckV3Packet {
    pub headers: Vec<LsaV3Header>,
}

impl LsAckV3Packet {
    pub fn parse(data: &[u8]) -> Result<Self, PacketV3Error> {
        let mut headers = Vec::new();
        let mut off = 0;
        while off + LSA_V3_HEADER_LEN <= data.len() {
            headers.push(LsaV3Header::parse(&data[off..])?);
            off += LSA_V3_HEADER_LEN;
        }
        Ok(LsAckV3Packet { headers })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        for h in &self.headers {
            h.encode(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_v3::lsa::LsaV3Type;
    use std::net::Ipv4Addr;

    #[test]
    fn test_lsack_v3_roundtrip() {
        let pkt = LsAckV3Packet {
            headers: vec![LsaV3Header {
                ls_age: 5,
                ls_type: LsaV3Type::Network,
                link_state_id: Ipv4Addr::new(0, 0, 0, 1),
                advertising_router: Ipv4Addr::new(2, 2, 2, 2),
                ls_sequence_number: 0x80000003u32 as i32,
                ls_checksum: 0x1234,
                length: 28,
            }],
        };
        let mut buf = Vec::new();
        pkt.encode(&mut buf);
        assert_eq!(buf.len(), LSA_V3_HEADER_LEN);
        let parsed = LsAckV3Packet::parse(&buf).unwrap();
        assert_eq!(parsed.headers.len(), 1);
        assert_eq!(parsed.headers[0].ls_type, LsaV3Type::Network);
    }
}
