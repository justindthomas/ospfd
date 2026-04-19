//! OSPFv3 IPv6 prefix encoding (RFC 5340 Section 2.6 / A.4.1).
//!
//! IPv6 prefixes in OSPFv3 use a variable-length encoding:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | PrefixLength  | PrefixOptions |          PrefixOrMetric       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Address Prefix                         |
//! |                             ...                               |
//! ```
//!
//! - PrefixLength: u8 — length of the prefix in bits (0-128)
//! - PrefixOptions: u8 — LA/MC/P/DN/NU flags
//! - PrefixOrMetric: u16 — either a metric (in Inter-Area-Prefix-LSA and
//!   AS-External-LSA) or a referenced LS type (in Link-LSA / Intra-Area-
//!   Prefix-LSA the field is reserved and set to 0)
//! - Address Prefix: ceil(PrefixLength / 32) * 4 bytes of network prefix

use std::net::Ipv6Addr;

use super::PacketV3Error;

/// Prefix options flags (RFC 5340 A.4.1.1).
pub const PREFIX_OPT_NU: u8 = 0x01; // NU-bit: prefix is NoUnicast
pub const PREFIX_OPT_LA: u8 = 0x02; // LA-bit: prefix is a Local-Address
pub const PREFIX_OPT_MC: u8 = 0x04; // MC-bit: prefix is MultiCast-capable
pub const PREFIX_OPT_P: u8 = 0x08;  // P-bit: NSSA propagation
pub const PREFIX_OPT_DN: u8 = 0x10; // DN-bit: VPN

/// An IPv6 prefix as carried in OSPFv3 LSAs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ospfv3Prefix {
    /// Prefix length (0-128).
    pub prefix_length: u8,
    /// Prefix options flags (LA/NU/MC/P/DN).
    pub prefix_options: u8,
    /// PrefixOrMetric field: 0 for intra-area prefix, metric for
    /// inter-area and external prefixes.
    pub prefix_or_metric: u16,
    /// Prefix bits (up to 16 bytes, but only `prefix_length` bits are
    /// meaningful; the rest are zero).
    pub address: Ipv6Addr,
}

impl Ospfv3Prefix {
    /// Size in bytes on the wire: 4 bytes of header + ceil(prefix_length/32)*4.
    pub fn wire_size(&self) -> usize {
        4 + prefix_word_count(self.prefix_length) * 4
    }

    pub fn parse(data: &[u8]) -> Result<(Self, usize), PacketV3Error> {
        if data.len() < 4 {
            return Err(PacketV3Error::TooShort {
                expected: 4,
                got: data.len(),
            });
        }
        let prefix_length = data[0];
        let prefix_options = data[1];
        let prefix_or_metric = u16::from_be_bytes([data[2], data[3]]);
        let words = prefix_word_count(prefix_length);
        let prefix_bytes = words * 4;
        let total = 4 + prefix_bytes;
        if data.len() < total {
            return Err(PacketV3Error::TooShort {
                expected: total,
                got: data.len(),
            });
        }

        let mut octets = [0u8; 16];
        octets[..prefix_bytes.min(16)].copy_from_slice(&data[4..4 + prefix_bytes.min(16)]);
        let address = Ipv6Addr::from(octets);

        Ok((
            Ospfv3Prefix {
                prefix_length,
                prefix_options,
                prefix_or_metric,
                address,
            },
            total,
        ))
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.prefix_length);
        buf.push(self.prefix_options);
        buf.extend_from_slice(&self.prefix_or_metric.to_be_bytes());
        let words = prefix_word_count(self.prefix_length);
        let octets = self.address.octets();
        buf.extend_from_slice(&octets[..words * 4]);
    }
}

/// Number of 32-bit words needed to hold a prefix of the given length.
fn prefix_word_count(prefix_length: u8) -> usize {
    ((prefix_length as usize) + 31) / 32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_word_count() {
        assert_eq!(prefix_word_count(0), 0);
        assert_eq!(prefix_word_count(1), 1);
        assert_eq!(prefix_word_count(32), 1);
        assert_eq!(prefix_word_count(33), 2);
        assert_eq!(prefix_word_count(64), 2);
        assert_eq!(prefix_word_count(65), 3);
        assert_eq!(prefix_word_count(128), 4);
    }

    #[test]
    fn test_prefix_roundtrip_64() {
        let p = Ospfv3Prefix {
            prefix_length: 64,
            prefix_options: PREFIX_OPT_LA,
            prefix_or_metric: 0,
            address: "2001:db8::".parse().unwrap(),
        };
        let mut buf = Vec::new();
        p.encode(&mut buf);
        // 4 header + 8 (2 words) = 12 bytes
        assert_eq!(buf.len(), 12);
        assert_eq!(p.wire_size(), 12);

        let (parsed, consumed) = Ospfv3Prefix::parse(&buf).unwrap();
        assert_eq!(consumed, 12);
        assert_eq!(parsed.prefix_length, 64);
        assert_eq!(parsed.prefix_options, PREFIX_OPT_LA);
        assert_eq!(parsed.address, "2001:db8::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_prefix_roundtrip_128() {
        let p = Ospfv3Prefix {
            prefix_length: 128,
            prefix_options: 0,
            prefix_or_metric: 42,
            address: "2001:db8::1".parse().unwrap(),
        };
        let mut buf = Vec::new();
        p.encode(&mut buf);
        // 4 header + 16 (4 words) = 20 bytes
        assert_eq!(buf.len(), 20);

        let (parsed, _) = Ospfv3Prefix::parse(&buf).unwrap();
        assert_eq!(parsed.prefix_length, 128);
        assert_eq!(parsed.prefix_or_metric, 42);
        assert_eq!(parsed.address, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_prefix_default_route() {
        // 0.0.0.0/0 equivalent: prefix_length=0, no address words
        let p = Ospfv3Prefix {
            prefix_length: 0,
            prefix_options: 0,
            prefix_or_metric: 100,
            address: Ipv6Addr::UNSPECIFIED,
        };
        let mut buf = Vec::new();
        p.encode(&mut buf);
        // 4 bytes header, zero prefix bytes
        assert_eq!(buf.len(), 4);

        let (parsed, _) = Ospfv3Prefix::parse(&buf).unwrap();
        assert_eq!(parsed.prefix_length, 0);
        assert_eq!(parsed.prefix_or_metric, 100);
    }
}
