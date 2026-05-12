//! OSPF LSA (Link State Advertisement) definitions.
//!
//! RFC 2328 Section A.4.

use std::net::Ipv4Addr;

use super::PacketError;
use super::checksum;

/// LSA types (RFC 2328 Section A.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LsaType {
    Router = 1,
    Network = 2,
    SummaryNetwork = 3,
    SummaryAsbr = 4,
    AsExternal = 5,
}

impl LsaType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Router),
            2 => Some(Self::Network),
            3 => Some(Self::SummaryNetwork),
            4 => Some(Self::SummaryAsbr),
            5 => Some(Self::AsExternal),
            _ => None,
        }
    }
}

/// LSA header (20 bytes, RFC 2328 Section A.4.1).
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            LS age             |    Options    |    LS type    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Link State ID                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Advertising Router                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     LS sequence number                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         LS checksum           |             length            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub const LSA_HEADER_LEN: usize = 20;

/// Compute an LSA's total wire length (header + body) as a u16.
///
/// The wire-format `length` field is 16-bit, so a body that pushes the
/// total over `u16::MAX` cannot be represented and would silently
/// truncate under `as u16`. This helper panics on overflow — by spec
/// LSA bodies are well under 64 KB, so hitting this is a bug.
#[inline]
pub fn lsa_total_length(body_len: usize) -> u16 {
    u16::try_from(LSA_HEADER_LEN + body_len)
        .expect("LSA length exceeds u16::MAX — body too large for OSPF wire format")
}

/// Maximum age of an LSA in seconds.
pub const MAX_AGE: u16 = 3600;

/// Maximum sequence number.
pub const MAX_SEQUENCE_NUMBER: i32 = 0x7FFF_FFFF;

/// Initial sequence number.
pub const INITIAL_SEQUENCE_NUMBER: i32 = -0x7FFF_FFFF; // 0x80000001

/// Unique key identifying an LSA in the LSDB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LsaKey {
    pub ls_type: LsaType,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
}

#[derive(Debug, Clone)]
pub struct LsaHeader {
    pub ls_age: u16,
    pub options: u8,
    pub ls_type: LsaType,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
    pub ls_sequence_number: i32,
    pub ls_checksum: u16,
    pub length: u16,
}

impl LsaHeader {
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < LSA_HEADER_LEN {
            return Err(PacketError::TooShort {
                expected: LSA_HEADER_LEN,
                got: data.len(),
            });
        }

        let ls_age = u16::from_be_bytes([data[0], data[1]]);
        let options = data[2];
        let ls_type =
            LsaType::from_u8(data[3]).ok_or(PacketError::BadLsaType(data[3]))?;
        let link_state_id = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
        let advertising_router = Ipv4Addr::new(data[8], data[9], data[10], data[11]);
        let ls_sequence_number = i32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let ls_checksum = u16::from_be_bytes([data[16], data[17]]);
        let length = u16::from_be_bytes([data[18], data[19]]);

        Ok(LsaHeader {
            ls_age,
            options,
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
        buf.push(self.options);
        buf.push(self.ls_type as u8);
        buf.extend_from_slice(&self.link_state_id.octets());
        buf.extend_from_slice(&self.advertising_router.octets());
        buf.extend_from_slice(&self.ls_sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.ls_checksum.to_be_bytes());
        buf.extend_from_slice(&self.length.to_be_bytes());
    }

    pub fn key(&self) -> LsaKey {
        LsaKey {
            ls_type: self.ls_type,
            link_state_id: self.link_state_id,
            advertising_router: self.advertising_router,
        }
    }

    /// Returns true if this LSA is more recent than `other` (RFC 2328 Section 13.1).
    pub fn is_more_recent_than(&self, other: &LsaHeader) -> std::cmp::Ordering {
        // 1. Higher sequence number is more recent
        match self.ls_sequence_number.cmp(&other.ls_sequence_number) {
            std::cmp::Ordering::Greater => return std::cmp::Ordering::Greater,
            std::cmp::Ordering::Less => return std::cmp::Ordering::Less,
            std::cmp::Ordering::Equal => {}
        }

        // 2. Higher checksum is more recent (unlikely tie-breaker)
        match self.ls_checksum.cmp(&other.ls_checksum) {
            std::cmp::Ordering::Greater => return std::cmp::Ordering::Greater,
            std::cmp::Ordering::Less => return std::cmp::Ordering::Less,
            std::cmp::Ordering::Equal => {}
        }

        // 3. If one has MaxAge and other doesn't, MaxAge is more recent
        if self.ls_age == MAX_AGE && other.ls_age != MAX_AGE {
            return std::cmp::Ordering::Greater;
        }
        if self.ls_age != MAX_AGE && other.ls_age == MAX_AGE {
            return std::cmp::Ordering::Less;
        }

        // 4. If ages differ by more than MaxAgeDiff (15 min = 900s), younger is more recent
        let age_diff = (self.ls_age as i32 - other.ls_age as i32).unsigned_abs();
        if age_diff > 900 {
            if self.ls_age < other.ls_age {
                return std::cmp::Ordering::Greater;
            } else {
                return std::cmp::Ordering::Less;
            }
        }

        // Same instance
        std::cmp::Ordering::Equal
    }
}

/// Router link types (within Router-LSA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RouterLinkType {
    PointToPoint = 1,
    TransitNetwork = 2,
    StubNetwork = 3,
    VirtualLink = 4,
}

impl RouterLinkType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::PointToPoint),
            2 => Some(Self::TransitNetwork),
            3 => Some(Self::StubNetwork),
            4 => Some(Self::VirtualLink),
            _ => None,
        }
    }
}

/// A single link within a Router-LSA.
#[derive(Debug, Clone)]
pub struct RouterLink {
    pub link_id: Ipv4Addr,
    pub link_data: Ipv4Addr,
    pub link_type: RouterLinkType,
    pub num_tos: u8,
    pub metric: u16,
}

impl RouterLink {
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < 12 {
            return Err(PacketError::TooShort {
                expected: 12,
                got: data.len(),
            });
        }
        let link_id = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
        let link_data = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
        let link_type =
            RouterLinkType::from_u8(data[8]).ok_or(PacketError::BadLsaType(data[8]))?;
        let num_tos = data[9];
        let metric = u16::from_be_bytes([data[10], data[11]]);
        Ok(RouterLink {
            link_id,
            link_data,
            link_type,
            num_tos,
            metric,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.link_id.octets());
        buf.extend_from_slice(&self.link_data.octets());
        buf.push(self.link_type as u8);
        buf.push(self.num_tos);
        buf.extend_from_slice(&self.metric.to_be_bytes());
    }

    /// Size of this link entry (12 bytes + TOS entries, but we only handle TOS 0).
    pub fn wire_size(&self) -> usize {
        12 + self.num_tos as usize * 4
    }
}

/// Router-LSA body (RFC 2328 Section A.4.2).
#[derive(Debug, Clone)]
pub struct RouterLsa {
    pub flags: u8, // V=0x01, E=0x02, B=0x04
    pub links: Vec<RouterLink>,
}

impl RouterLsa {
    pub const V_FLAG: u8 = 0x01; // Virtual link endpoint
    pub const E_FLAG: u8 = 0x02; // AS boundary router
    pub const B_FLAG: u8 = 0x04; // Area border router

    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < 4 {
            return Err(PacketError::TooShort {
                expected: 4,
                got: data.len(),
            });
        }
        // RFC 2328 §A.4.2 router-LSA body layout:
        //   Byte 0: |0 0 0 0 0|V|E|B|   (flags)
        //   Byte 1: reserved (0)
        //   Bytes 2-3: # links
        //
        // Earlier code had bytes 0/1 swapped (flags at byte 1, reserved
        // at byte 0). That round-tripped fine internally but every
        // RFC-conformant peer (FRR/VyOS, IOS, etc.) read flags as 0
        // regardless of what we set — making us look like neither an
        // ABR nor an ASBR even when we were redistributing externals,
        // so Type-5 LSAs we originated were ignored by every peer's
        // SPF (RFC 2328 §16.4 ASBR reachability rule).
        let flags = data[0];
        let num_links = u16::from_be_bytes([data[2], data[3]]) as usize;

        // Bound by buffer size — `num_links` is attacker-controlled.
        // Each RouterLink is at least 12 bytes (no TOS entries).
        const MIN_ROUTER_LINK_LEN: usize = 12;
        let bounded = num_links.min(data.len().saturating_sub(4) / MIN_ROUTER_LINK_LEN);
        let mut links = Vec::with_capacity(bounded);
        let mut off = 4;
        for _ in 0..num_links {
            if off + 12 > data.len() {
                break;
            }
            let link = RouterLink::parse(&data[off..])?;
            off += link.wire_size();
            links.push(link);
        }

        Ok(RouterLsa { flags, links })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        // RFC 2328 §A.4.2: byte 0 carries the V|E|B flags, byte 1 is
        // reserved. (See the matching note in parse() for the
        // backstory on why this ordering was wrong for a while.)
        buf.push(self.flags);
        buf.push(0); // reserved
        buf.extend_from_slice(&(self.links.len() as u16).to_be_bytes());
        for link in &self.links {
            link.encode(buf);
        }
    }
}

/// Network-LSA body (RFC 2328 Section A.4.3).
#[derive(Debug, Clone)]
pub struct NetworkLsa {
    pub network_mask: Ipv4Addr,
    pub attached_routers: Vec<Ipv4Addr>,
}

impl NetworkLsa {
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < 4 {
            return Err(PacketError::TooShort {
                expected: 4,
                got: data.len(),
            });
        }
        let network_mask = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
        let mut attached_routers = Vec::new();
        let mut off = 4;
        while off + 4 <= data.len() {
            attached_routers.push(Ipv4Addr::new(
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
            ));
            off += 4;
        }
        Ok(NetworkLsa {
            network_mask,
            attached_routers,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.network_mask.octets());
        for router in &self.attached_routers {
            buf.extend_from_slice(&router.octets());
        }
    }
}

/// AS-External-LSA body (Type 5, RFC 2328 Section A.4.5).
///
/// Used to advertise routes external to the OSPF domain (e.g., redistributed
/// connected, static, or BGP routes).
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Network Mask                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |E|     0       |                  metric                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Forwarding address                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      External Route Tag                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// The E bit distinguishes Type 1 externals (internal cost is added to the
/// metric) from Type 2 externals (only the external metric counts).
///
/// Phase 2 only handles a single TOS metric (TOS 0).
#[derive(Debug, Clone)]
pub struct AsExternalLsa {
    pub network_mask: Ipv4Addr,
    /// true = Type 2 external (E bit set), false = Type 1
    pub metric_type_2: bool,
    /// 24-bit metric.
    pub metric: u32,
    pub forwarding_address: Ipv4Addr,
    pub external_route_tag: u32,
}

impl AsExternalLsa {
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < 16 {
            return Err(PacketError::TooShort {
                expected: 16,
                got: data.len(),
            });
        }
        let network_mask = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
        let metric_type_2 = (data[4] & 0x80) != 0;
        let metric = u32::from_be_bytes([0, data[5], data[6], data[7]]);
        let forwarding_address = Ipv4Addr::new(data[8], data[9], data[10], data[11]);
        let external_route_tag = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        Ok(AsExternalLsa {
            network_mask,
            metric_type_2,
            metric,
            forwarding_address,
            external_route_tag,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.network_mask.octets());
        let e_bit = if self.metric_type_2 { 0x80 } else { 0 };
        buf.push(e_bit);
        let m = self.metric.to_be_bytes();
        buf.push(m[1]);
        buf.push(m[2]);
        buf.push(m[3]);
        buf.extend_from_slice(&self.forwarding_address.octets());
        buf.extend_from_slice(&self.external_route_tag.to_be_bytes());
    }
}

/// Summary-LSA body (Type 3 and Type 4, RFC 2328 Section A.4.4).
///
/// Type 3 (SummaryNetwork): inter-area destination network.
///   `link_state_id` in the header = destination network address.
///   `network_mask` here = destination network mask.
///   `metric` = cost from the originating ABR to the destination network.
///
/// Type 4 (SummaryAsbr): destination ASBR router.
///   `link_state_id` in the header = ASBR's router ID.
///   `network_mask` is set to 0.0.0.0 and ignored.
#[derive(Debug, Clone)]
pub struct SummaryLsa {
    pub network_mask: Ipv4Addr,
    /// 24-bit metric (top 8 bits are reserved/zero).
    pub metric: u32,
}

impl SummaryLsa {
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < 8 {
            return Err(PacketError::TooShort {
                expected: 8,
                got: data.len(),
            });
        }
        let network_mask = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
        // bytes 4-7: reserved(u8) + metric(u24)
        let metric = u32::from_be_bytes([0, data[5], data[6], data[7]]);
        Ok(SummaryLsa {
            network_mask,
            metric,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.network_mask.octets());
        // 1 reserved byte + 3 bytes of metric
        buf.push(0);
        let m = self.metric.to_be_bytes();
        buf.push(m[1]);
        buf.push(m[2]);
        buf.push(m[3]);
    }
}

/// A complete LSA: header + typed body.
#[derive(Debug, Clone)]
pub struct Lsa {
    pub header: LsaHeader,
    pub body: LsaBody,
}

/// LSA body variants.
#[derive(Debug, Clone)]
pub enum LsaBody {
    Router(RouterLsa),
    Network(NetworkLsa),
    /// Type 3 / Type 4 (Summary).
    Summary(SummaryLsa),
    /// Type 5 (AS-External).
    AsExternal(AsExternalLsa),
    /// Opaque body — fallback for unknown LSA types.
    Opaque(Vec<u8>),
}

impl Lsa {
    /// Parse a complete LSA (header + body) from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        let header = LsaHeader::parse(data)?;
        // RFC 2328: LSA `length` covers the full LSA including the 20-byte
        // header. A peer-supplied length below that underflows the body-len
        // subtraction below; reject before computing.
        if (header.length as usize) < LSA_HEADER_LEN {
            return Err(PacketError::TooShort {
                expected: LSA_HEADER_LEN,
                got: header.length as usize,
            });
        }
        let body_len = header.length as usize - LSA_HEADER_LEN;
        let body_data = &data[LSA_HEADER_LEN..LSA_HEADER_LEN + body_len.min(data.len() - LSA_HEADER_LEN)];

        let body = match header.ls_type {
            LsaType::Router => LsaBody::Router(RouterLsa::parse(body_data)?),
            LsaType::Network => LsaBody::Network(NetworkLsa::parse(body_data)?),
            LsaType::SummaryNetwork | LsaType::SummaryAsbr => {
                LsaBody::Summary(SummaryLsa::parse(body_data)?)
            }
            LsaType::AsExternal => {
                LsaBody::AsExternal(AsExternalLsa::parse(body_data)?)
            }
        };

        Ok(Lsa { header, body })
    }

    /// Encode the LSA (header + body) with correct length and checksum.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);

        // Write header (length and checksum will be fixed up)
        self.header.encode(&mut buf);

        // Write body
        match &self.body {
            LsaBody::Router(r) => r.encode(&mut buf),
            LsaBody::Network(n) => n.encode(&mut buf),
            LsaBody::Summary(s) => s.encode(&mut buf),
            LsaBody::AsExternal(e) => e.encode(&mut buf),
            LsaBody::Opaque(data) => buf.extend_from_slice(data),
        }

        // Fix length. Mirrors `lsa_total_length`: the wire field is u16, so
        // an encoded body that pushes total > 65,535 cannot be represented
        // and a silent `as u16` truncation would emit a corrupt LSA.
        let len = u16::try_from(buf.len())
            .expect("LSA encode: encoded length exceeds u16::MAX");
        buf[18] = (len >> 8) as u8;
        buf[19] = (len & 0xFF) as u8;

        // Compute Fletcher-16 checksum (covers everything except LS age, at offset 0-1).
        // The checksum field is at offset 16-17 from the start of the LSA.
        // Per RFC 2328, the checksum is computed over the entire LSA except the LS Age field.
        // So we compute over bytes 2..len, with checksum field at offset 16-2=14.
        let (c1, c2) = checksum::fletcher16(&buf[2..], 14);
        buf[16] = c1;
        buf[17] = c2;

        buf
    }

    /// Get the unique key for this LSA.
    pub fn key(&self) -> LsaKey {
        self.header.key()
    }

    /// Total wire size of this LSA.
    pub fn wire_size(&self) -> usize {
        self.header.length as usize
    }
}

/// LS Acknowledge packet body — a list of LSA headers.
#[derive(Debug, Clone)]
pub struct LsAckPacket {
    pub lsa_headers: Vec<LsaHeader>,
}

impl LsAckPacket {
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        let mut headers = Vec::new();
        let mut off = 0;
        while off + LSA_HEADER_LEN <= data.len() {
            headers.push(LsaHeader::parse(&data[off..])?);
            off += LSA_HEADER_LEN;
        }
        Ok(LsAckPacket {
            lsa_headers: headers,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        for header in &self.lsa_headers {
            header.encode(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsa_header_roundtrip() {
        let header = LsaHeader {
            ls_age: 100,
            options: 0x02,
            ls_type: LsaType::Router,
            link_state_id: Ipv4Addr::new(1, 1, 1, 1),
            advertising_router: Ipv4Addr::new(1, 1, 1, 1),
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: 36,
        };

        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert_eq!(buf.len(), LSA_HEADER_LEN);

        let parsed = LsaHeader::parse(&buf).unwrap();
        assert_eq!(parsed.ls_age, 100);
        assert_eq!(parsed.ls_type, LsaType::Router);
        assert_eq!(parsed.link_state_id, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(parsed.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
    }

    #[test]
    fn test_router_lsa_roundtrip() {
        let lsa = RouterLsa {
            flags: RouterLsa::E_FLAG,
            links: vec![
                RouterLink {
                    link_id: Ipv4Addr::new(10, 0, 0, 0),
                    link_data: Ipv4Addr::new(255, 255, 255, 0),
                    link_type: RouterLinkType::StubNetwork,
                    num_tos: 0,
                    metric: 10,
                },
                RouterLink {
                    link_id: Ipv4Addr::new(10, 0, 0, 1),
                    link_data: Ipv4Addr::new(10, 0, 0, 2),
                    link_type: RouterLinkType::PointToPoint,
                    num_tos: 0,
                    metric: 10,
                },
            ],
        };

        let mut buf = Vec::new();
        lsa.encode(&mut buf);

        let parsed = RouterLsa::parse(&buf).unwrap();
        assert_eq!(parsed.flags, RouterLsa::E_FLAG);
        assert_eq!(parsed.links.len(), 2);
        assert_eq!(parsed.links[0].link_type, RouterLinkType::StubNetwork);
        assert_eq!(parsed.links[0].metric, 10);
    }

    /// Wire-format test: pin the byte layout per RFC 2328 §A.4.2 so a
    /// future "looks symmetric so should round-trip" refactor can't
    /// re-introduce the bytes-0/1-swapped bug that hid the E flag from
    /// every peer's SPF for months.
    ///
    ///   Byte 0: |0 0 0 0 0|V|E|B|   (flags — E_FLAG=0x02, B_FLAG=0x04)
    ///   Byte 1: reserved (0)
    ///   Bytes 2-3: # links (big endian)
    #[test]
    fn router_lsa_wire_format_matches_rfc_2328() {
        let lsa = RouterLsa {
            flags: RouterLsa::E_FLAG | RouterLsa::B_FLAG,
            links: vec![RouterLink {
                link_id: Ipv4Addr::new(10, 0, 0, 0),
                link_data: Ipv4Addr::new(255, 255, 255, 0),
                link_type: RouterLinkType::StubNetwork,
                num_tos: 0,
                metric: 10,
            }],
        };
        let mut buf = Vec::new();
        lsa.encode(&mut buf);
        assert_eq!(buf[0], 0x06, "flags byte must be at offset 0");
        assert_eq!(buf[1], 0x00, "reserved byte must be at offset 1");
        assert_eq!(&buf[2..4], &[0x00, 0x01], "# links big-endian at 2..4");
    }

    #[test]
    fn test_summary_lsa_roundtrip() {
        let s = SummaryLsa {
            network_mask: Ipv4Addr::new(255, 255, 255, 0),
            metric: 0x123456,
        };
        let mut buf = Vec::new();
        s.encode(&mut buf);
        assert_eq!(buf.len(), 8);

        let parsed = SummaryLsa::parse(&buf).unwrap();
        assert_eq!(parsed.network_mask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(parsed.metric, 0x123456);
    }

    #[test]
    fn test_is_more_recent() {
        let h1 = LsaHeader {
            ls_age: 10,
            options: 0,
            ls_type: LsaType::Router,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: Ipv4Addr::UNSPECIFIED,
            ls_sequence_number: 100,
            ls_checksum: 0,
            length: 20,
        };
        let mut h2 = h1.clone();
        h2.ls_sequence_number = 99;

        assert_eq!(
            h1.is_more_recent_than(&h2),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            h2.is_more_recent_than(&h1),
            std::cmp::Ordering::Less
        );
    }

    /// Regression for F8: an LSA whose header `length < 20` previously
    /// underflowed `header.length - LSA_HEADER_LEN`, panicking in
    /// debug/fuzz builds. The parser must reject it cleanly instead.
    #[test]
    fn parse_lsa_with_length_below_header_len_does_not_panic() {
        // Valid 20-byte LSA header with length field (bytes 18-19) = 0,
        // matching the fuzz reproducer extracted from
        // fuzz/artifacts/parse_v2_lsu/crash-d97051ce... (LSA bytes only).
        let buf = [
            0x00, 0x60,                         // ls_age
            0x0b,                               // options
            0x03,                               // ls_type = SummaryNetwork
            0x0b, 0x0b, 0x0b, 0x0b,             // link_state_id
            0x0b, 0x0b, 0x0b, 0x0b,             // advertising_router
            0x0b, 0x0b, 0x0b, 0x0b,             // ls_sequence_number
            0x0b, 0x0b,                         // ls_checksum
            0x00, 0x00,                         // length = 0 (trigger)
        ];
        let res = Lsa::parse(&buf);
        assert!(matches!(
            res,
            Err(PacketError::TooShort { expected: LSA_HEADER_LEN, .. })
        ));
    }
}
