//! OSPF packet authentication (RFC 2328 Appendix D).
//!
//! Three authentication types are defined:
//! - **Null (type 0)**: no authentication — the 8-byte auth field is undefined
//! - **Simple (type 1)**: 8-byte cleartext password in the auth field
//! - **Cryptographic (type 2)**: MD5 (RFC 2104 HMAC) or SHA family; the 8-byte
//!   auth field holds (key_id, auth_data_len, crypto_seq_num) and a digest is
//!   appended after the OSPF packet body.

use md5::{Digest, Md5};

/// OSPF Authentication Type (RFC 2328 Appendix D.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AuType {
    Null = 0,
    Simple = 1,
    Crypto = 2,
}

impl AuType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0 => Some(Self::Null),
            1 => Some(Self::Simple),
            2 => Some(Self::Crypto),
            _ => None,
        }
    }
}

/// An OSPF authentication key for one interface.
#[derive(Clone)]
pub enum AuthKey {
    /// No authentication.
    None,
    /// Simple password: up to 8 bytes of cleartext.
    Simple(Vec<u8>),
    /// MD5 cryptographic authentication with a key_id and 16-byte key.
    Md5 { key_id: u8, key: Vec<u8> },
}

impl std::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthKey::None => write!(f, "None"),
            AuthKey::Simple(_) => write!(f, "Simple(***)"),
            AuthKey::Md5 { key_id, .. } => write!(f, "Md5 {{ key_id: {}, key: *** }}", key_id),
        }
    }
}

impl AuthKey {
    pub fn au_type(&self) -> AuType {
        match self {
            AuthKey::None => AuType::Null,
            AuthKey::Simple(_) => AuType::Simple,
            AuthKey::Md5 { .. } => AuType::Crypto,
        }
    }
}

/// Apply authentication to an outgoing OSPF packet.
///
/// `packet` is the full OSPF packet (24-byte header + body) with the regular
/// IP checksum already computed. For Simple auth, we overwrite the 8-byte
/// authentication field with the password. For Crypto (MD5), we zero the
/// checksum, put key/length/seq into the auth field, append a 16-byte MD5
/// digest, and update the packet length.
///
/// Returns the possibly-extended packet.
pub fn apply_auth(packet: Vec<u8>, key: &AuthKey, sequence: u32) -> Vec<u8> {
    match key {
        AuthKey::None => packet,
        AuthKey::Simple(password) => {
            let mut p = packet;
            if p.len() < 24 {
                return p;
            }
            // Set au_type to 1
            p[14] = 0;
            p[15] = 1;
            // Copy up to 8 bytes of password into the auth field
            p[16..24].fill(0);
            let n = password.len().min(8);
            p[16..16 + n].copy_from_slice(&password[..n]);
            p
        }
        AuthKey::Md5 { key_id, key } => {
            let mut p = packet;
            if p.len() < 24 {
                return p;
            }
            // AuType = 2
            p[14] = 0;
            p[15] = 2;
            // Packet checksum is always 0 for crypto auth
            p[12] = 0;
            p[13] = 0;
            // Auth field structure:
            //   bytes 16-17: 0
            //   byte 18: key_id
            //   byte 19: auth_data_length (16 for MD5)
            //   bytes 20-23: crypto_sequence_number (u32 BE)
            p[16] = 0;
            p[17] = 0;
            p[18] = *key_id;
            p[19] = 16;
            p[20..24].copy_from_slice(&sequence.to_be_bytes());

            // RFC 2328 Appendix D.4.3: the cryptographic authentication data
            // (the appended digest) is kept "outside the OSPF packet proper"
            // and is NOT included in the header's packet length field.

            // Compute MD5(packet || key). Key is right-padded with zeros to 16 bytes.
            let mut hasher = Md5::new();
            hasher.update(&p);
            let mut padded_key = [0u8; 16];
            let n = key.len().min(16);
            padded_key[..n].copy_from_slice(&key[..n]);
            hasher.update(padded_key);
            let digest = hasher.finalize();

            p.extend_from_slice(&digest);
            p
        }
    }
}

/// Verify authentication on an incoming packet.
///
/// Returns true if the packet's authentication is valid under the given key.
/// For Null auth, always returns true. For Simple, compares the 8-byte auth
/// field. For MD5, re-computes the digest and compares.
pub fn verify_auth(packet: &[u8], key: &AuthKey) -> bool {
    if packet.len() < 24 {
        return false;
    }
    let pkt_au_type = u16::from_be_bytes([packet[14], packet[15]]);
    let expected = key.au_type() as u16;
    if pkt_au_type != expected {
        return false;
    }

    match key {
        AuthKey::None => true,
        AuthKey::Simple(password) => {
            let mut padded = [0u8; 8];
            let n = password.len().min(8);
            padded[..n].copy_from_slice(&password[..n]);
            packet[16..24] == padded
        }
        AuthKey::Md5 { key_id, key } => {
            // Parse auth field
            if packet[18] != *key_id {
                return false;
            }
            let auth_len = packet[19] as usize;
            if auth_len != 16 {
                return false;
            }
            // The packet length in the header already accounts for the body
            // WITHOUT the digest. The digest is appended after.
            let pkt_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if packet.len() < pkt_len + 16 {
                return false;
            }
            let (header_and_body, digest_bytes) = packet.split_at(pkt_len);
            let received_digest = &digest_bytes[..16];

            // Re-compute: MD5(header+body || padded_key)
            let mut hasher = Md5::new();
            hasher.update(header_and_body);
            let mut padded_key = [0u8; 16];
            let n = key.len().min(16);
            padded_key[..n].copy_from_slice(&key[..n]);
            hasher.update(padded_key);
            let expected_digest = hasher.finalize();

            received_digest == expected_digest.as_slice()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_auth_noop() {
        let packet = vec![0u8; 48];
        let result = apply_auth(packet.clone(), &AuthKey::None, 0);
        assert_eq!(result, packet);
        assert!(verify_auth(&result, &AuthKey::None));
    }

    #[test]
    fn test_simple_auth_roundtrip() {
        let mut packet = vec![0u8; 48];
        // Pretend this is an OSPF packet with length 48 at bytes 2..4
        packet[0] = 2; // version
        packet[1] = 1; // type hello
        packet[2] = 0;
        packet[3] = 48;

        let key = AuthKey::Simple(b"mypass".to_vec());
        let authed = apply_auth(packet, &key, 0);

        // Auth type should be 1
        assert_eq!(u16::from_be_bytes([authed[14], authed[15]]), 1);
        // Auth field should start with "mypass"
        assert_eq!(&authed[16..22], b"mypass");
        assert_eq!(authed[22], 0);
        assert_eq!(authed[23], 0);

        assert!(verify_auth(&authed, &key));

        // Wrong key fails
        let wrong = AuthKey::Simple(b"wrongkey".to_vec());
        assert!(!verify_auth(&authed, &wrong));
    }

    #[test]
    fn test_md5_auth_roundtrip() {
        // Pretend this is a 48-byte OSPF packet
        let mut packet = vec![0u8; 48];
        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 0;
        packet[3] = 48;
        // Fill body with some dummy data
        for i in 24..48 {
            packet[i] = i as u8;
        }

        let key = AuthKey::Md5 {
            key_id: 5,
            key: b"my-md5-key".to_vec(),
        };
        let sequence = 0xDEADBEEF;
        let authed = apply_auth(packet, &key, sequence);

        // AuType = 2
        assert_eq!(u16::from_be_bytes([authed[14], authed[15]]), 2);
        // Checksum = 0
        assert_eq!(u16::from_be_bytes([authed[12], authed[13]]), 0);
        // key_id
        assert_eq!(authed[18], 5);
        // auth_data_length = 16
        assert_eq!(authed[19], 16);
        // sequence
        assert_eq!(
            u32::from_be_bytes([authed[20], authed[21], authed[22], authed[23]]),
            sequence
        );
        // Packet length in header is unchanged (digest is outside the OSPF packet)
        assert_eq!(u16::from_be_bytes([authed[2], authed[3]]), 48);
        // Total bytes = 48 + 16 digest
        assert_eq!(authed.len(), 48 + 16);

        assert!(verify_auth(&authed, &key));

        // Wrong key fails
        let wrong_key = AuthKey::Md5 {
            key_id: 5,
            key: b"different".to_vec(),
        };
        assert!(!verify_auth(&authed, &wrong_key));

        // Wrong key_id fails
        let wrong_kid = AuthKey::Md5 {
            key_id: 6,
            key: b"my-md5-key".to_vec(),
        };
        assert!(!verify_auth(&authed, &wrong_kid));
    }
}
