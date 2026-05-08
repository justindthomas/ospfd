//! OSPFv3 LSA definitions (RFC 5340 Section 4.4).
//!
//! LSA types in OSPFv3 use a 16-bit encoding with a flooding-scope field
//! plus a U bit (unknown LSA handling) and a type value:
//!
//! ```text
//! 16 bits of LS Type:
//!  +---+---+---------+------------------------+
//!  | U | S2 S1       | LSA Function Code      |
//!  +---+---+---------+------------------------+
//! ```
//!
//! S1 and S2 define flooding scope:
//!   00 = link-local
//!   01 = area
//!   10 = AS (OSPF routing domain)
//!
//! U = 0: unknown LSA types are discarded
//! U = 1: unknown LSAs are treated as having link-local scope
//!
//! Function codes in use (all with U=0):
//!   1  = Router-LSA           (area scope)
//!   2  = Network-LSA          (area scope)
//!   3  = Inter-Area-Prefix-LSA (area scope)
//!   4  = Inter-Area-Router-LSA (area scope)
//!   5  = AS-External-LSA      (AS scope)
//!   6  = (deprecated: Group-Membership)
//!   7  = NSSA-LSA             (area scope)
//!   8  = Link-LSA             (link-local scope)
//!   9  = Intra-Area-Prefix-LSA (area scope)

use std::net::{Ipv4Addr, Ipv6Addr};

use super::prefix::Ospfv3Prefix;
use super::PacketV3Error;

pub const LSA_V3_HEADER_LEN: usize = 20;
pub const MAX_AGE: u16 = 3600;
pub const INITIAL_SEQUENCE_NUMBER: i32 = -0x7FFF_FFFF; // 0x80000001

/// Compute an OSPFv3 LSA's total wire length (header + body) as a u16.
///
/// Panics if the total exceeds `u16::MAX` — by spec LSA bodies are well
/// under 64 KB, so a panic here is a bug.
#[inline]
pub fn lsa_v3_total_length(body_len: usize) -> u16 {
    u16::try_from(LSA_V3_HEADER_LEN + body_len)
        .expect("OSPFv3 LSA length exceeds u16::MAX — body too large for wire format")
}

/// OSPFv3 LSA function codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum LsaV3Type {
    /// U=0 S=01 Function=1
    Router = 0x2001,
    /// U=0 S=01 Function=2
    Network = 0x2002,
    /// U=0 S=01 Function=3
    InterAreaPrefix = 0x2003,
    /// U=0 S=01 Function=4
    InterAreaRouter = 0x2004,
    /// U=0 S=10 Function=5
    AsExternal = 0x4005,
    /// U=0 S=01 Function=7
    Nssa = 0x2007,
    /// U=0 S=00 Function=8
    Link = 0x0008,
    /// U=0 S=01 Function=9
    IntraAreaPrefix = 0x2009,
}

impl LsaV3Type {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x2001 => Some(Self::Router),
            0x2002 => Some(Self::Network),
            0x2003 => Some(Self::InterAreaPrefix),
            0x2004 => Some(Self::InterAreaRouter),
            0x4005 => Some(Self::AsExternal),
            0x2007 => Some(Self::Nssa),
            0x0008 => Some(Self::Link),
            0x2009 => Some(Self::IntraAreaPrefix),
            _ => None,
        }
    }
}

/// OSPFv3 LSA header (20 bytes, RFC 5340 Section 4.4.1).
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            LS age             |           LS type             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Link State ID                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Advertising Router                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     LS Sequence Number                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Checksum           |             Length            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Key difference from v2: Options moved out (now in Router-LSA body).
/// LS type is 16 bits (was 8) with scope encoding.
#[derive(Debug, Clone)]
pub struct LsaV3Header {
    pub ls_age: u16,
    pub ls_type: LsaV3Type,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
    pub ls_sequence_number: i32,
    pub ls_checksum: u16,
    pub length: u16,
}

impl LsaV3Header {
    pub fn parse(data: &[u8]) -> Result<Self, PacketV3Error> {
        if data.len() < LSA_V3_HEADER_LEN {
            return Err(PacketV3Error::TooShort {
                expected: LSA_V3_HEADER_LEN,
                got: data.len(),
            });
        }
        let ls_age = u16::from_be_bytes([data[0], data[1]]);
        let ls_type_raw = u16::from_be_bytes([data[2], data[3]]);
        let ls_type = LsaV3Type::from_u16(ls_type_raw)
            .ok_or(PacketV3Error::BadLsaType(ls_type_raw))?;
        let link_state_id = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
        let advertising_router = Ipv4Addr::new(data[8], data[9], data[10], data[11]);
        let ls_sequence_number = i32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let ls_checksum = u16::from_be_bytes([data[16], data[17]]);
        let length = u16::from_be_bytes([data[18], data[19]]);

        Ok(LsaV3Header {
            ls_age,
            ls_type,
            link_state_id,
            advertising_router,
            ls_sequence_number,
            ls_checksum,
            length,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.ls_age.to_be_bytes());
        buf.extend_from_slice(&(self.ls_type as u16).to_be_bytes());
        buf.extend_from_slice(&self.link_state_id.octets());
        buf.extend_from_slice(&self.advertising_router.octets());
        buf.extend_from_slice(&self.ls_sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.ls_checksum.to_be_bytes());
        buf.extend_from_slice(&self.length.to_be_bytes());
    }
}

/// Router-LSA body (RFC 5340 Section 4.4.3.1).
///
/// OSPFv3 Router-LSAs no longer carry prefixes — they only describe
/// link-local connectivity. Prefixes are advertised separately in
/// Intra-Area-Prefix-LSAs.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |0|0|0|0|0|Nt|x|V|E|B|           Options                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |       0       |             Metric            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Interface ID                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Neighbor Interface ID                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Neighbor Router ID                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             ...                               |
/// ```

/// A single link in an OSPFv3 Router-LSA (16 bytes).
#[derive(Debug, Clone)]
pub struct RouterLinkV3 {
    pub link_type: u8,
    pub metric: u16,
    pub interface_id: u32,
    pub neighbor_interface_id: u32,
    pub neighbor_router_id: Ipv4Addr,
}

impl RouterLinkV3 {
    pub const TYPE_POINT_TO_POINT: u8 = 1;
    pub const TYPE_TRANSIT_NETWORK: u8 = 2;
    pub const TYPE_VIRTUAL_LINK: u8 = 4;

    pub fn parse(data: &[u8]) -> Result<Self, PacketV3Error> {
        if data.len() < 16 {
            return Err(PacketV3Error::TooShort {
                expected: 16,
                got: data.len(),
            });
        }
        let link_type = data[0];
        // data[1] reserved
        let metric = u16::from_be_bytes([data[2], data[3]]);
        let interface_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let neighbor_interface_id =
            u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let neighbor_router_id = Ipv4Addr::new(data[12], data[13], data[14], data[15]);

        Ok(RouterLinkV3 {
            link_type,
            metric,
            interface_id,
            neighbor_interface_id,
            neighbor_router_id,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.link_type);
        buf.push(0); // reserved
        buf.extend_from_slice(&self.metric.to_be_bytes());
        buf.extend_from_slice(&self.interface_id.to_be_bytes());
        buf.extend_from_slice(&self.neighbor_interface_id.to_be_bytes());
        buf.extend_from_slice(&self.neighbor_router_id.octets());
    }
}

/// OSPFv3 Router-LSA body.
#[derive(Debug, Clone)]
pub struct RouterLsaV3 {
    pub flags: u8, // V, E, B bits in the low byte of the first 4 bytes
    pub options: u32, // 24-bit options
    pub links: Vec<RouterLinkV3>,
}

impl RouterLsaV3 {
    pub const FLAG_V: u8 = 0x04;
    pub const FLAG_E: u8 = 0x02;
    pub const FLAG_B: u8 = 0x01;

    pub fn parse(data: &[u8]) -> Result<Self, PacketV3Error> {
        if data.len() < 4 {
            return Err(PacketV3Error::TooShort {
                expected: 4,
                got: data.len(),
            });
        }
        let flags = data[0];
        let options = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        let mut links = Vec::new();
        let mut off = 4;
        while off + 16 <= data.len() {
            links.push(RouterLinkV3::parse(&data[off..])?);
            off += 16;
        }
        Ok(RouterLsaV3 {
            flags,
            options,
            links,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.flags);
        let opts = self.options.to_be_bytes();
        buf.push(opts[1]);
        buf.push(opts[2]);
        buf.push(opts[3]);
        for link in &self.links {
            link.encode(buf);
        }
    }
}

/// OSPFv3 Network-LSA body (RFC 5340 Section 4.4.3.2).
///
/// Originated by the DR on broadcast/NBMA networks. Describes the
/// network by listing all attached routers. Unlike v2, the network
/// mask is NOT in the Network-LSA — subnet info is in
/// Intra-Area-Prefix-LSAs referencing the Network-LSA.
#[derive(Debug, Clone)]
pub struct NetworkLsaV3 {
    pub options: u32, // 24-bit
    pub attached_routers: Vec<Ipv4Addr>,
}

impl NetworkLsaV3 {
    pub fn parse(data: &[u8]) -> Result<Self, PacketV3Error> {
        if data.len() < 4 {
            return Err(PacketV3Error::TooShort {
                expected: 4,
                got: data.len(),
            });
        }
        let options = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        let mut attached = Vec::new();
        let mut off = 4;
        while off + 4 <= data.len() {
            attached.push(Ipv4Addr::new(
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
            ));
            off += 4;
        }
        Ok(NetworkLsaV3 {
            options,
            attached_routers: attached,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(0); // reserved
        let opts = self.options.to_be_bytes();
        buf.push(opts[1]);
        buf.push(opts[2]);
        buf.push(opts[3]);
        for r in &self.attached_routers {
            buf.extend_from_slice(&r.octets());
        }
    }
}

/// OSPFv3 Link-LSA body (RFC 5340 Section 4.4.3.8).
///
/// Flooded with link-local scope. Advertises the router's link-local
/// address on the link plus the IPv6 prefixes to be associated with
/// the link. Used by the DR when building Intra-Area-Prefix-LSAs for
/// the transit network.
#[derive(Debug, Clone)]
pub struct LinkLsaV3 {
    pub router_priority: u8,
    pub options: u32, // 24-bit
    pub link_local_address: Ipv6Addr,
    pub prefixes: Vec<Ospfv3Prefix>,
}

impl LinkLsaV3 {
    pub fn parse(data: &[u8]) -> Result<Self, PacketV3Error> {
        if data.len() < 24 {
            return Err(PacketV3Error::TooShort {
                expected: 24,
                got: data.len(),
            });
        }
        let router_priority = data[0];
        let options = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        let mut lla_bytes = [0u8; 16];
        lla_bytes.copy_from_slice(&data[4..20]);
        let link_local_address = Ipv6Addr::from(lla_bytes);
        let num_prefixes = u32::from_be_bytes([data[20], data[21], data[22], data[23]]) as usize;

        let mut prefixes = Vec::with_capacity(num_prefixes);
        let mut off = 24;
        for _ in 0..num_prefixes {
            if off >= data.len() {
                break;
            }
            let (prefix, consumed) = Ospfv3Prefix::parse(&data[off..])?;
            prefixes.push(prefix);
            off += consumed;
        }

        Ok(LinkLsaV3 {
            router_priority,
            options,
            link_local_address,
            prefixes,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.router_priority);
        let opts = self.options.to_be_bytes();
        buf.push(opts[1]);
        buf.push(opts[2]);
        buf.push(opts[3]);
        buf.extend_from_slice(&self.link_local_address.octets());
        buf.extend_from_slice(&(self.prefixes.len() as u32).to_be_bytes());
        for p in &self.prefixes {
            p.encode(buf);
        }
    }
}

/// OSPFv3 Intra-Area-Prefix-LSA body (RFC 5340 Section 4.4.3.9).
///
/// Advertises IPv6 prefixes associated with a router or a transit network.
/// Every Router-LSA / Network-LSA gets a matching Intra-Area-Prefix-LSA
/// (may be multiple if there are lots of prefixes).
#[derive(Debug, Clone)]
pub struct IntraAreaPrefixLsaV3 {
    /// Referenced LS type (0x2001 Router, 0x2002 Network)
    pub referenced_ls_type: u16,
    /// Referenced Link State ID
    pub referenced_link_state_id: Ipv4Addr,
    /// Referenced advertising router
    pub referenced_advertising_router: Ipv4Addr,
    pub prefixes: Vec<Ospfv3Prefix>,
}

impl IntraAreaPrefixLsaV3 {
    pub fn parse(data: &[u8]) -> Result<Self, PacketV3Error> {
        if data.len() < 12 {
            return Err(PacketV3Error::TooShort {
                expected: 12,
                got: data.len(),
            });
        }
        let num_prefixes = u16::from_be_bytes([data[0], data[1]]) as usize;
        let referenced_ls_type = u16::from_be_bytes([data[2], data[3]]);
        let referenced_link_state_id =
            Ipv4Addr::new(data[4], data[5], data[6], data[7]);
        let referenced_advertising_router =
            Ipv4Addr::new(data[8], data[9], data[10], data[11]);

        let mut prefixes = Vec::with_capacity(num_prefixes);
        let mut off = 12;
        for _ in 0..num_prefixes {
            if off >= data.len() {
                break;
            }
            let (prefix, consumed) = Ospfv3Prefix::parse(&data[off..])?;
            prefixes.push(prefix);
            off += consumed;
        }

        Ok(IntraAreaPrefixLsaV3 {
            referenced_ls_type,
            referenced_link_state_id,
            referenced_advertising_router,
            prefixes,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.prefixes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.referenced_ls_type.to_be_bytes());
        buf.extend_from_slice(&self.referenced_link_state_id.octets());
        buf.extend_from_slice(&self.referenced_advertising_router.octets());
        for p in &self.prefixes {
            p.encode(buf);
        }
    }
}

/// OSPFv3 Inter-Area-Prefix-LSA body (Type 3 equivalent, RFC 5340 4.4.3.3).
#[derive(Debug, Clone)]
pub struct InterAreaPrefixLsaV3 {
    /// 24-bit metric
    pub metric: u32,
    pub prefix: Ospfv3Prefix,
}

impl InterAreaPrefixLsaV3 {
    pub fn parse(data: &[u8]) -> Result<Self, PacketV3Error> {
        if data.len() < 4 {
            return Err(PacketV3Error::TooShort {
                expected: 4,
                got: data.len(),
            });
        }
        let metric = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        let (prefix, _) = Ospfv3Prefix::parse(&data[4..])?;
        Ok(InterAreaPrefixLsaV3 { metric, prefix })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(0); // reserved
        let m = self.metric.to_be_bytes();
        buf.push(m[1]);
        buf.push(m[2]);
        buf.push(m[3]);
        self.prefix.encode(buf);
    }
}

/// OSPFv3 AS-External-LSA body (Type 5, RFC 5340 §4.4.3.5).
///
/// Flooded with AS-scope. Advertises a route learned from outside
/// OSPF (redistributed from BGP/static/connected, or the default).
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |0|0|E|F|T|                Metric                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | PrefixLength  | PrefixOptions |     Referenced LS Type        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Address Prefix                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                Forwarding Address (optional, 16 bytes)        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                External Route Tag (optional, 4 bytes)         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Referenced Link State ID (optional, 4 bytes)       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone)]
pub struct AsExternalLsaV3 {
    /// E-bit: true = Type 2 (external-only metric),
    /// false = Type 1 (internal + external).
    pub metric_type_2: bool,
    /// F-bit: true if a forwarding address is present.
    pub forwarding_present: bool,
    /// T-bit: true if an external route tag is present.
    pub tag_present: bool,
    /// 24-bit metric.
    pub metric: u32,
    /// Prefix being advertised.
    pub prefix: Ospfv3Prefix,
    /// Referenced LS type (only meaningful with a referenced LS ID).
    pub referenced_ls_type: u16,
    /// Optional forwarding address (16 bytes, present iff F-bit).
    pub forwarding_address: Option<Ipv6Addr>,
    /// Optional external route tag (present iff T-bit).
    pub external_route_tag: Option<u32>,
    /// Optional referenced LS ID (present iff referenced_ls_type != 0).
    pub referenced_link_state_id: Option<Ipv4Addr>,
}

impl AsExternalLsaV3 {
    pub const FLAG_E: u8 = 0x04;
    pub const FLAG_F: u8 = 0x02;
    pub const FLAG_T: u8 = 0x01;

    pub fn parse(data: &[u8]) -> Result<Self, PacketV3Error> {
        if data.len() < 4 {
            return Err(PacketV3Error::TooShort {
                expected: 4,
                got: data.len(),
            });
        }
        let flags = data[0];
        let metric_type_2 = flags & Self::FLAG_E != 0;
        let forwarding_present = flags & Self::FLAG_F != 0;
        let tag_present = flags & Self::FLAG_T != 0;
        let metric = u32::from_be_bytes([0, data[1], data[2], data[3]]);

        let (prefix, consumed) = Ospfv3Prefix::parse(&data[4..])?;
        // The variable PrefixOrMetric field in the encoded prefix carries
        // the 2-byte "Referenced LS type" for external LSAs.
        let referenced_ls_type = prefix.prefix_or_metric;

        let mut off = 4 + consumed;
        let forwarding_address = if forwarding_present {
            if data.len() < off + 16 {
                return Err(PacketV3Error::TooShort {
                    expected: off + 16,
                    got: data.len(),
                });
            }
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&data[off..off + 16]);
            off += 16;
            Some(Ipv6Addr::from(buf))
        } else {
            None
        };
        let external_route_tag = if tag_present {
            if data.len() < off + 4 {
                return Err(PacketV3Error::TooShort {
                    expected: off + 4,
                    got: data.len(),
                });
            }
            let tag = u32::from_be_bytes([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
            ]);
            off += 4;
            Some(tag)
        } else {
            None
        };
        let referenced_link_state_id = if referenced_ls_type != 0 {
            if data.len() < off + 4 {
                return Err(PacketV3Error::TooShort {
                    expected: off + 4,
                    got: data.len(),
                });
            }
            Some(Ipv4Addr::new(
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
            ))
        } else {
            None
        };

        Ok(AsExternalLsaV3 {
            metric_type_2,
            forwarding_present,
            tag_present,
            metric,
            prefix,
            referenced_ls_type,
            forwarding_address,
            external_route_tag,
            referenced_link_state_id,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        let mut flags = 0u8;
        if self.metric_type_2 {
            flags |= Self::FLAG_E;
        }
        if self.forwarding_present {
            flags |= Self::FLAG_F;
        }
        if self.tag_present {
            flags |= Self::FLAG_T;
        }
        buf.push(flags);
        let m = self.metric.to_be_bytes();
        buf.push(m[1]);
        buf.push(m[2]);
        buf.push(m[3]);
        // The prefix's prefix_or_metric field carries the referenced LS type
        // for external LSAs. Build a local copy with that field set.
        let mut p = self.prefix.clone();
        p.prefix_or_metric = self.referenced_ls_type;
        p.encode(buf);
        if let Some(fa) = &self.forwarding_address {
            buf.extend_from_slice(&fa.octets());
        }
        if let Some(tag) = self.external_route_tag {
            buf.extend_from_slice(&tag.to_be_bytes());
        }
        if let Some(rls) = &self.referenced_link_state_id {
            buf.extend_from_slice(&rls.octets());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v3_header_roundtrip() {
        let h = LsaV3Header {
            ls_age: 100,
            ls_type: LsaV3Type::Router,
            link_state_id: Ipv4Addr::new(1, 1, 1, 1),
            advertising_router: Ipv4Addr::new(1, 1, 1, 1),
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: 40,
        };
        let mut buf = Vec::new();
        h.encode(&mut buf);
        assert_eq!(buf.len(), LSA_V3_HEADER_LEN);

        let parsed = LsaV3Header::parse(&buf).unwrap();
        assert_eq!(parsed.ls_age, 100);
        assert_eq!(parsed.ls_type, LsaV3Type::Router);
        assert_eq!(parsed.link_state_id, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(parsed.length, 40);
    }

    #[test]
    fn test_router_lsa_v3_roundtrip() {
        let lsa = RouterLsaV3 {
            flags: RouterLsaV3::FLAG_B,
            options: 0x000013, // V6 + E + R
            links: vec![
                RouterLinkV3 {
                    link_type: RouterLinkV3::TYPE_POINT_TO_POINT,
                    metric: 10,
                    interface_id: 5,
                    neighbor_interface_id: 7,
                    neighbor_router_id: Ipv4Addr::new(2, 2, 2, 2),
                },
                RouterLinkV3 {
                    link_type: RouterLinkV3::TYPE_TRANSIT_NETWORK,
                    metric: 20,
                    interface_id: 6,
                    neighbor_interface_id: 8,
                    neighbor_router_id: Ipv4Addr::new(3, 3, 3, 3),
                },
            ],
        };
        let mut buf = Vec::new();
        lsa.encode(&mut buf);
        // 4 header bytes + 2 links * 16 bytes = 36
        assert_eq!(buf.len(), 36);

        let parsed = RouterLsaV3::parse(&buf).unwrap();
        assert_eq!(parsed.flags, RouterLsaV3::FLAG_B);
        assert_eq!(parsed.options, 0x000013);
        assert_eq!(parsed.links.len(), 2);
        assert_eq!(parsed.links[0].link_type, RouterLinkV3::TYPE_POINT_TO_POINT);
        assert_eq!(parsed.links[0].metric, 10);
        assert_eq!(parsed.links[1].neighbor_router_id, Ipv4Addr::new(3, 3, 3, 3));
    }

    #[test]
    fn test_network_lsa_v3_roundtrip() {
        let lsa = NetworkLsaV3 {
            options: 0x000013,
            attached_routers: vec![
                Ipv4Addr::new(1, 1, 1, 1),
                Ipv4Addr::new(2, 2, 2, 2),
                Ipv4Addr::new(3, 3, 3, 3),
            ],
        };
        let mut buf = Vec::new();
        lsa.encode(&mut buf);
        // 4 header + 3*4 attached = 16
        assert_eq!(buf.len(), 16);

        let parsed = NetworkLsaV3::parse(&buf).unwrap();
        assert_eq!(parsed.options, 0x000013);
        assert_eq!(parsed.attached_routers.len(), 3);
        assert_eq!(parsed.attached_routers[1], Ipv4Addr::new(2, 2, 2, 2));
    }

    #[test]
    fn test_link_lsa_v3_roundtrip() {
        use super::super::prefix::{Ospfv3Prefix, PREFIX_OPT_LA};
        let lsa = LinkLsaV3 {
            router_priority: 1,
            options: 0x000013,
            link_local_address: "fe80::1".parse().unwrap(),
            prefixes: vec![Ospfv3Prefix {
                prefix_length: 64,
                prefix_options: PREFIX_OPT_LA,
                prefix_or_metric: 0,
                address: "2001:db8::".parse().unwrap(),
            }],
        };
        let mut buf = Vec::new();
        lsa.encode(&mut buf);

        let parsed = LinkLsaV3::parse(&buf).unwrap();
        assert_eq!(parsed.router_priority, 1);
        assert_eq!(parsed.options, 0x000013);
        assert_eq!(
            parsed.link_local_address,
            "fe80::1".parse::<std::net::Ipv6Addr>().unwrap()
        );
        assert_eq!(parsed.prefixes.len(), 1);
        assert_eq!(parsed.prefixes[0].prefix_length, 64);
    }

    #[test]
    fn test_intra_area_prefix_lsa_v3_roundtrip() {
        let lsa = IntraAreaPrefixLsaV3 {
            referenced_ls_type: LsaV3Type::Router as u16,
            referenced_link_state_id: Ipv4Addr::UNSPECIFIED,
            referenced_advertising_router: Ipv4Addr::new(1, 1, 1, 1),
            prefixes: vec![
                super::super::prefix::Ospfv3Prefix {
                    prefix_length: 64,
                    prefix_options: 0,
                    prefix_or_metric: 10,
                    address: "2001:db8:1::".parse().unwrap(),
                },
                super::super::prefix::Ospfv3Prefix {
                    prefix_length: 128,
                    prefix_options: super::super::prefix::PREFIX_OPT_LA,
                    prefix_or_metric: 0,
                    address: "2001:db8:1::1".parse().unwrap(),
                },
            ],
        };
        let mut buf = Vec::new();
        lsa.encode(&mut buf);

        let parsed = IntraAreaPrefixLsaV3::parse(&buf).unwrap();
        assert_eq!(parsed.referenced_ls_type, LsaV3Type::Router as u16);
        assert_eq!(parsed.prefixes.len(), 2);
        assert_eq!(parsed.prefixes[0].prefix_or_metric, 10);
        assert_eq!(parsed.prefixes[1].prefix_length, 128);
    }

    #[test]
    fn test_inter_area_prefix_lsa_v3_roundtrip() {
        let lsa = InterAreaPrefixLsaV3 {
            metric: 42,
            prefix: super::super::prefix::Ospfv3Prefix {
                prefix_length: 48,
                prefix_options: 0,
                prefix_or_metric: 0,
                address: "2001:db8:5::".parse().unwrap(),
            },
        };
        let mut buf = Vec::new();
        lsa.encode(&mut buf);

        let parsed = InterAreaPrefixLsaV3::parse(&buf).unwrap();
        assert_eq!(parsed.metric, 42);
        assert_eq!(parsed.prefix.prefix_length, 48);
    }

    #[test]
    fn test_as_external_lsa_v3_roundtrip_minimal() {
        // E1 metric, no forwarding address, no tag, no referenced LS id
        let lsa = AsExternalLsaV3 {
            metric_type_2: false,
            forwarding_present: false,
            tag_present: false,
            metric: 20,
            prefix: Ospfv3Prefix {
                prefix_length: 64,
                prefix_options: 0,
                prefix_or_metric: 0,
                address: "2001:db8:ffff::".parse().unwrap(),
            },
            referenced_ls_type: 0,
            forwarding_address: None,
            external_route_tag: None,
            referenced_link_state_id: None,
        };
        let mut buf = Vec::new();
        lsa.encode(&mut buf);
        let parsed = AsExternalLsaV3::parse(&buf).unwrap();
        assert_eq!(parsed.metric_type_2, false);
        assert_eq!(parsed.metric, 20);
        assert_eq!(parsed.prefix.prefix_length, 64);
        assert_eq!(parsed.forwarding_address, None);
    }

    #[test]
    fn test_as_external_lsa_v3_roundtrip_with_forwarding() {
        let lsa = AsExternalLsaV3 {
            metric_type_2: true,
            forwarding_present: true,
            tag_present: true,
            metric: 100,
            prefix: Ospfv3Prefix {
                prefix_length: 0,
                prefix_options: 0,
                prefix_or_metric: 0,
                address: Ipv6Addr::UNSPECIFIED,
            },
            referenced_ls_type: 0,
            forwarding_address: Some("2001:db8::1".parse().unwrap()),
            external_route_tag: Some(0xDEADBEEF),
            referenced_link_state_id: None,
        };
        let mut buf = Vec::new();
        lsa.encode(&mut buf);
        let parsed = AsExternalLsaV3::parse(&buf).unwrap();
        assert_eq!(parsed.metric_type_2, true);
        assert_eq!(parsed.metric, 100);
        assert_eq!(parsed.forwarding_address, Some("2001:db8::1".parse().unwrap()));
        assert_eq!(parsed.external_route_tag, Some(0xDEADBEEF));
    }

    #[test]
    fn test_v3_types() {
        assert_eq!(LsaV3Type::from_u16(0x2001), Some(LsaV3Type::Router));
        assert_eq!(LsaV3Type::from_u16(0x2002), Some(LsaV3Type::Network));
        assert_eq!(LsaV3Type::from_u16(0x2009), Some(LsaV3Type::IntraAreaPrefix));
        assert_eq!(LsaV3Type::from_u16(0x4005), Some(LsaV3Type::AsExternal));
        assert_eq!(LsaV3Type::from_u16(0x0008), Some(LsaV3Type::Link));
        assert_eq!(LsaV3Type::from_u16(0xFFFF), None);
    }
}
