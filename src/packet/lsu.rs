//! OSPF Link State Update packet (RFC 2328 Section A.3.5).
//!
//! Contains a list of complete LSAs (header + body) for flooding.

use super::PacketError;
use super::lsa::Lsa;

/// Link State Update packet body.
#[derive(Debug, Clone)]
pub struct LsUpdatePacket {
    pub lsas: Vec<Lsa>,
}

impl LsUpdatePacket {
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < 4 {
            return Err(PacketError::TooShort {
                expected: 4,
                got: data.len(),
            });
        }

        let num_lsas = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let mut lsas = Vec::with_capacity(num_lsas);
        let mut off = 4;

        for _ in 0..num_lsas {
            if off >= data.len() {
                break;
            }
            let lsa = Lsa::parse(&data[off..])?;
            off += lsa.wire_size();
            lsas.push(lsa);
        }

        Ok(LsUpdatePacket { lsas })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.lsas.len() as u32).to_be_bytes());
        for lsa in &self.lsas {
            buf.extend_from_slice(&lsa.encode());
        }
    }
}
