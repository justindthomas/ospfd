//! OSPF Link State Request packet (RFC 2328 Section A.3.4).
//!
//! Sent during adjacency formation to request specific LSAs from a neighbor.

use std::net::Ipv4Addr;

use super::PacketError;
use super::lsa::LsaType;

/// A single LSA request entry (12 bytes).
#[derive(Debug, Clone)]
pub struct LsRequest {
    /// LS type (as u32 in the wire format, though only low byte is used).
    pub ls_type: LsaType,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
}

pub const LS_REQUEST_ENTRY_LEN: usize = 12;

impl LsRequest {
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < LS_REQUEST_ENTRY_LEN {
            return Err(PacketError::TooShort {
                expected: LS_REQUEST_ENTRY_LEN,
                got: data.len(),
            });
        }
        // LS type is encoded as u32 on the wire
        let ls_type_val = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let ls_type = LsaType::from_u8(ls_type_val as u8)
            .ok_or(PacketError::BadLsaType(ls_type_val as u8))?;
        let link_state_id = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
        let advertising_router = Ipv4Addr::new(data[8], data[9], data[10], data[11]);

        Ok(LsRequest {
            ls_type,
            link_state_id,
            advertising_router,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.ls_type as u32).to_be_bytes());
        buf.extend_from_slice(&self.link_state_id.octets());
        buf.extend_from_slice(&self.advertising_router.octets());
    }
}

/// Link State Request packet body.
#[derive(Debug, Clone)]
pub struct LsRequestPacket {
    pub requests: Vec<LsRequest>,
}

impl LsRequestPacket {
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        let mut requests = Vec::new();
        let mut off = 0;
        while off + LS_REQUEST_ENTRY_LEN <= data.len() {
            requests.push(LsRequest::parse(&data[off..])?);
            off += LS_REQUEST_ENTRY_LEN;
        }
        Ok(LsRequestPacket { requests })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        for req in &self.requests {
            req.encode(buf);
        }
    }
}
