//! OSPF Link State Update packet (RFC 2328 Section A.3.5).
//!
//! Contains a list of complete LSAs (header + body) for flooding.

use super::PacketError;
use super::lsa::{Lsa, LSA_HEADER_LEN};

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
        // Bound by what the buffer can hold — `num_lsas` is attacker-
        // controlled and would otherwise pre-allocate up to ~96 GB.
        let bounded = num_lsas.min(data.len().saturating_sub(4) / LSA_HEADER_LEN);
        let mut lsas = Vec::with_capacity(bounded);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for the F5 fuzz finding: a 4-byte LSU body declaring
    /// ~170M LSAs must not cause a multi-GB pre-allocation.
    #[test]
    fn parse_huge_num_lsas_does_not_oom() {
        let trigger = [0x0a, 0x30, 0x21, 0x0a];
        let pkt = LsUpdatePacket::parse(&trigger).expect("parse should succeed");
        assert!(pkt.lsas.is_empty());
    }

    #[test]
    fn parse_u32_max_num_lsas_does_not_oom() {
        let trigger = [0xff, 0xff, 0xff, 0xff];
        let pkt = LsUpdatePacket::parse(&trigger).expect("parse should succeed");
        assert!(pkt.lsas.is_empty());
    }
}
