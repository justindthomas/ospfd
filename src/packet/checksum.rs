//! Checksum algorithms used by OSPF.
//!
//! - IP checksum (RFC 1071): Used for the OSPF packet header checksum.
//! - Fletcher-16 (RFC 905): Used for LSA checksums.

/// Compute the standard Internet checksum (RFC 1071) over a byte slice.
///
/// Returns the checksum in network byte order (big-endian).
pub fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Add trailing odd byte
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum into 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Verify an IP checksum: returns true if the checksum over data (including
/// the checksum field) is zero.
pub fn ip_checksum_verify(data: &[u8]) -> bool {
    ip_checksum(data) == 0
}

/// Compute the OSPF LSA Fletcher checksum (RFC 2328 Appendix A.4.1).
///
/// This is the "generate checksum" procedure. `data` is the LSA starting
/// from the LS Age field. `checksum_offset` is the byte offset of the
/// LS Checksum field within `data` (normally 16 for a full LSA).
/// The two checksum bytes at that offset are treated as zero.
///
/// Returns (C1, C2) to be placed at the checksum offset.
pub fn fletcher16(data: &[u8], checksum_offset: usize) -> (u8, u8) {
    let len = data.len() as i32;
    let mut c0: i32 = 0;
    let mut c1: i32 = 0;

    for (i, &byte) in data.iter().enumerate() {
        if i == checksum_offset || i == checksum_offset + 1 {
            // Treat checksum bytes as zero
        } else {
            c0 += byte as i32;
        }
        c1 += c0;
    }
    c0 %= 255;
    c1 %= 255;

    // q = (len - checksum_offset) in 1-based counting
    // But our offset is 0-based. The checksum byte is at position (checksum_offset+1)
    // from the start in 1-based counting. There are (len - checksum_offset - 1) bytes
    // after the second checksum byte.
    let q = len - checksum_offset as i32;

    // x = -c1 + (q-1)*c0, mod 255
    let mut x = (-(c1 as i64) + (q as i64 - 1) * c0 as i64) % 255;
    if x <= 0 {
        x += 255;
    }

    // y = c1 - q*c0, mod 255... but simpler: y = 255*2 - c0 - x
    let mut y = 510i64 - c0 as i64 - x;
    if y > 255 {
        y -= 255;
    }
    if y <= 0 {
        y += 255;
    }

    (x as u8, y as u8)
}

/// Verify an OSPF LSA Fletcher checksum.
///
/// With the correct C1, C2 values in place, summing over the entire
/// data (including the checksum bytes) should yield c0=0, c1=0 mod 255.
pub fn fletcher16_verify(data: &[u8]) -> bool {
    let mut c0: u32 = 0;
    let mut c1: u32 = 0;

    for &byte in data {
        c0 = (c0 + byte as u32) % 255;
        c1 = (c1 + c0) % 255;
    }

    c0 == 0 && c1 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_checksum_simple() {
        // Example from RFC 1071: IP header
        let data = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
            0x00, 0x00, // checksum field = 0
            0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let cksum = ip_checksum(&data);
        // Place checksum and verify
        let mut data_with_cksum = data;
        data_with_cksum[10] = (cksum >> 8) as u8;
        data_with_cksum[11] = (cksum & 0xFF) as u8;
        assert!(ip_checksum_verify(&data_with_cksum));
    }

    #[test]
    fn test_ip_checksum_zeros() {
        let data = [0u8; 20];
        assert_eq!(ip_checksum(&data), 0xFFFF);
    }

    #[test]
    fn test_ip_checksum_verify_roundtrip() {
        let mut data = vec![0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x07, 0x08];
        let cksum = ip_checksum(&data);
        data[4] = (cksum >> 8) as u8;
        data[5] = (cksum & 0xFF) as u8;
        assert!(ip_checksum_verify(&data));
    }

    #[test]
    fn test_fletcher16_roundtrip() {
        // Create a fake LSA with checksum field at offset 4
        let mut data = vec![0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x07, 0x08, 0x09, 0x0A];
        let (c1, c2) = fletcher16(&data, 4);
        data[4] = c1;
        data[5] = c2;
        assert!(fletcher16_verify(&data));
    }
}
