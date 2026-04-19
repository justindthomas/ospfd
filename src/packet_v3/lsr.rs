//! OSPFv3 Link State Request packet (RFC 5340 Appendix A.3.4).
//!
//! Each request entry is 12 bytes:
//!   - 4 bytes of padding/reserved (upper 16 bits were LSA type prefix in
//!     v2; in v3 the LSA type is a full 16 bits preceded by a 16-bit pad)
//!   - 2 bytes reserved
//!   - 2 bytes LS type
//!   - 4 bytes link state ID
//!   - 4 bytes advertising router
//!
//! This gives 12 bytes total just like v2, but the type encoding differs.

use std::net::Ipv4Addr;

use super::lsa::LsaV3Type;
use super::PacketV3Error;

pub const LS_REQUEST_V3_ENTRY_LEN: usize = 12;

#[derive(Debug, Clone)]
pub struct LsRequestV3 {
    pub ls_type: LsaV3Type,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
}

impl LsRequestV3 {
    pub fn parse(data: &[u8]) -> Result<Self, PacketV3Error> {
        if data.len() < LS_REQUEST_V3_ENTRY_LEN {
            return Err(PacketV3Error::TooShort {
                expected: LS_REQUEST_V3_ENTRY_LEN,
                got: data.len(),
            });
        }
        // bytes 0-1 reserved
        let ls_type_val = u16::from_be_bytes([data[2], data[3]]);
        let ls_type = LsaV3Type::from_u16(ls_type_val)
            .ok_or(PacketV3Error::BadLsaType(ls_type_val))?;
        let link_state_id = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
        let advertising_router = Ipv4Addr::new(data[8], data[9], data[10], data[11]);
        Ok(LsRequestV3 {
            ls_type,
            link_state_id,
            advertising_router,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&(self.ls_type as u16).to_be_bytes());
        buf.extend_from_slice(&self.link_state_id.octets());
        buf.extend_from_slice(&self.advertising_router.octets());
    }
}

#[derive(Debug, Clone)]
pub struct LsRequestV3Packet {
    pub requests: Vec<LsRequestV3>,
}

impl LsRequestV3Packet {
    pub fn parse(data: &[u8]) -> Result<Self, PacketV3Error> {
        let mut requests = Vec::new();
        let mut off = 0;
        while off + LS_REQUEST_V3_ENTRY_LEN <= data.len() {
            requests.push(LsRequestV3::parse(&data[off..])?);
            off += LS_REQUEST_V3_ENTRY_LEN;
        }
        Ok(LsRequestV3Packet { requests })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        for r in &self.requests {
            r.encode(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsr_v3_roundtrip() {
        let pkt = LsRequestV3Packet {
            requests: vec![
                LsRequestV3 {
                    ls_type: LsaV3Type::Router,
                    link_state_id: Ipv4Addr::new(1, 1, 1, 1),
                    advertising_router: Ipv4Addr::new(1, 1, 1, 1),
                },
                LsRequestV3 {
                    ls_type: LsaV3Type::IntraAreaPrefix,
                    link_state_id: Ipv4Addr::new(0, 0, 0, 5),
                    advertising_router: Ipv4Addr::new(2, 2, 2, 2),
                },
            ],
        };
        let mut buf = Vec::new();
        pkt.encode(&mut buf);
        assert_eq!(buf.len(), 2 * LS_REQUEST_V3_ENTRY_LEN);

        let parsed = LsRequestV3Packet::parse(&buf).unwrap();
        assert_eq!(parsed.requests.len(), 2);
        assert_eq!(parsed.requests[0].ls_type, LsaV3Type::Router);
        assert_eq!(parsed.requests[1].ls_type, LsaV3Type::IntraAreaPrefix);
    }
}
