//! OSPF packet authentication (RFC 2328 Appendix D + RFC 5709).
//!
//! Three authentication types are defined:
//! - **Null (type 0)**: no authentication — the 8-byte auth field is undefined
//! - **Simple (type 1)**: 8-byte cleartext password in the auth field
//! - **Cryptographic (type 2)**: keyed-MD5 (RFC 2328) or HMAC-SHA-{256,384,512}
//!   per RFC 5709. The 8-byte auth field carries (key_id, auth_data_length,
//!   crypto_seq_num); the digest is appended after the OSPF packet body.
//!
//! MD5 is preserved for interop with legacy peers but is cryptographically
//! weak; new deployments should configure HMAC-SHA-256 or stronger.

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha2::{Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

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

/// HMAC-SHA hash family for RFC 5709 cryptographic authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacAlgo {
    Sha256,
    Sha384,
    Sha512,
}

impl HmacAlgo {
    /// Hash output length in octets — also the on-wire `auth_data_length`.
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
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
    /// RFC 2328 keyed-MD5. Cryptographically weak; kept for legacy interop.
    Md5 { key_id: u8, key: Vec<u8> },
    /// RFC 5709 HMAC-SHA cryptographic authentication.
    HmacSha { algo: HmacAlgo, key_id: u8, key: Vec<u8> },
}

impl std::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthKey::None => write!(f, "None"),
            AuthKey::Simple(_) => write!(f, "Simple(***)"),
            AuthKey::Md5 { key_id, .. } => write!(f, "Md5 {{ key_id: {}, key: *** }}", key_id),
            AuthKey::HmacSha { algo, key_id, .. } => write!(
                f,
                "HmacSha {{ algo: {:?}, key_id: {}, key: *** }}",
                algo, key_id
            ),
        }
    }
}

impl AuthKey {
    pub fn au_type(&self) -> AuType {
        match self {
            AuthKey::None => AuType::Null,
            AuthKey::Simple(_) => AuType::Simple,
            AuthKey::Md5 { .. } | AuthKey::HmacSha { .. } => AuType::Crypto,
        }
    }
}

/// RFC 5709 §3.3 Apad — fill pattern placed in the authentication trailer
/// before HMAC computation. 64 bytes covers the largest supported digest
/// (SHA-512); shorter algorithms slice the prefix.
const APAD: [u8; 64] = [
    0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
    0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
    0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
    0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
    0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
    0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
    0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
    0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
];

fn hmac_sha(algo: HmacAlgo, key: &[u8], data: &[u8]) -> Vec<u8> {
    match algo {
        HmacAlgo::Sha256 => {
            let mut mac = <Hmac<Sha256>>::new_from_slice(key)
                .expect("HMAC accepts any key length");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        HmacAlgo::Sha384 => {
            let mut mac = <Hmac<Sha384>>::new_from_slice(key)
                .expect("HMAC accepts any key length");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        HmacAlgo::Sha512 => {
            let mut mac = <Hmac<Sha512>>::new_from_slice(key)
                .expect("HMAC accepts any key length");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// Apply authentication to an outgoing OSPF packet.
///
/// `packet` is the full OSPF packet (24-byte header + body) with the regular
/// IP checksum already computed. For Simple auth, we overwrite the 8-byte
/// authentication field with the password. For Crypto (MD5 or HMAC-SHA), we
/// zero the checksum, put key/length/seq into the auth field, append the
/// digest, and leave the header's packet length field unchanged (the trailer
/// is "outside the OSPF packet proper" per RFC 2328 §D.4.3 / RFC 5709 §3.3).
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
        AuthKey::HmacSha { algo, key_id, key } => {
            let mut p = packet;
            if p.len() < 24 {
                return p;
            }
            let trailer_len = algo.digest_len();
            // AuType = 2 (Crypto), checksum cleared
            p[14] = 0;
            p[15] = 2;
            p[12] = 0;
            p[13] = 0;
            // Auth field: 0,0, key_id, auth_data_length, seq[4]
            p[16] = 0;
            p[17] = 0;
            p[18] = *key_id;
            // trailer_len <= 64, fits in u8
            p[19] = trailer_len as u8;
            p[20..24].copy_from_slice(&sequence.to_be_bytes());

            // RFC 5709 §3.3: fill the trailer with Apad, compute
            // HMAC-SHA-X(K, packet_with_Apad_trailer), then overwrite the
            // Apad with the resulting digest.
            p.extend_from_slice(&APAD[..trailer_len]);
            let digest = hmac_sha(*algo, key, &p);
            let trailer_start = p.len() - trailer_len;
            p[trailer_start..].copy_from_slice(&digest);
            p
        }
    }
}

/// Verify authentication on an incoming packet.
///
/// Returns true if the packet's authentication is valid under the given key.
/// All digest comparisons are constant-time to avoid timing oracles on the
/// authentication tag.
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
            packet[16..24].ct_eq(&padded).into()
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

            received_digest.ct_eq(expected_digest.as_slice()).into()
        }
        AuthKey::HmacSha { algo, key_id, key } => {
            if packet[18] != *key_id {
                return false;
            }
            let trailer_len = algo.digest_len();
            if packet[19] as usize != trailer_len {
                return false;
            }
            let pkt_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if packet.len() < pkt_len + trailer_len {
                return false;
            }
            let (header_and_body, trailer_bytes) = packet.split_at(pkt_len);
            let received = &trailer_bytes[..trailer_len];

            // RFC 5709 verify: rebuild the buffer with Apad in the trailer
            // slot, recompute HMAC, compare in constant time.
            let mut buf = Vec::with_capacity(pkt_len + trailer_len);
            buf.extend_from_slice(header_and_body);
            buf.extend_from_slice(&APAD[..trailer_len]);
            let expected = hmac_sha(*algo, key, &buf);

            received.ct_eq(&expected).into()
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

    fn build_ospf_packet(len: usize) -> Vec<u8> {
        assert!(len >= 24 && len <= u16::MAX as usize);
        let mut p = vec![0u8; len];
        p[0] = 2; // version
        p[1] = 1; // hello
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        for (i, b) in p.iter_mut().enumerate().take(len).skip(24) {
            *b = i as u8;
        }
        p
    }

    fn hmac_sha_roundtrip(algo: HmacAlgo, expected_trailer_len: usize) {
        let packet = build_ospf_packet(48);
        let key = AuthKey::HmacSha {
            algo,
            key_id: 7,
            key: b"super-secret-shared-key".to_vec(),
        };
        let seq = 0x1122_3344;
        let authed = apply_auth(packet, &key, seq);

        // AuType = 2, checksum cleared, key_id and auth_data_length set,
        // header length unchanged, trailer appended.
        assert_eq!(u16::from_be_bytes([authed[14], authed[15]]), 2);
        assert_eq!(u16::from_be_bytes([authed[12], authed[13]]), 0);
        assert_eq!(authed[18], 7);
        assert_eq!(authed[19] as usize, expected_trailer_len);
        assert_eq!(
            u32::from_be_bytes([authed[20], authed[21], authed[22], authed[23]]),
            seq
        );
        assert_eq!(u16::from_be_bytes([authed[2], authed[3]]), 48);
        assert_eq!(authed.len(), 48 + expected_trailer_len);

        // Trailer is NOT Apad (HMAC must have overwritten it).
        let trailer = &authed[48..];
        assert_ne!(trailer, &APAD[..expected_trailer_len]);

        assert!(verify_auth(&authed, &key));

        // Tampered trailer fails.
        let mut tampered = authed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(!verify_auth(&tampered, &key));

        // Wrong key fails.
        let wrong_key = AuthKey::HmacSha {
            algo,
            key_id: 7,
            key: b"different-key".to_vec(),
        };
        assert!(!verify_auth(&authed, &wrong_key));

        // Wrong key_id fails.
        let wrong_kid = AuthKey::HmacSha {
            algo,
            key_id: 8,
            key: b"super-secret-shared-key".to_vec(),
        };
        assert!(!verify_auth(&authed, &wrong_kid));

        // Wrong algorithm fails (different digest length / different MAC).
        let other_algo = match algo {
            HmacAlgo::Sha256 => HmacAlgo::Sha512,
            HmacAlgo::Sha384 => HmacAlgo::Sha256,
            HmacAlgo::Sha512 => HmacAlgo::Sha384,
        };
        let wrong_algo = AuthKey::HmacSha {
            algo: other_algo,
            key_id: 7,
            key: b"super-secret-shared-key".to_vec(),
        };
        assert!(!verify_auth(&authed, &wrong_algo));
    }

    #[test]
    fn test_hmac_sha256_roundtrip() {
        hmac_sha_roundtrip(HmacAlgo::Sha256, 32);
    }

    #[test]
    fn test_hmac_sha384_roundtrip() {
        hmac_sha_roundtrip(HmacAlgo::Sha384, 48);
    }

    #[test]
    fn test_hmac_sha512_roundtrip() {
        hmac_sha_roundtrip(HmacAlgo::Sha512, 64);
    }

    #[test]
    fn test_hmac_au_type_is_crypto() {
        let key = AuthKey::HmacSha {
            algo: HmacAlgo::Sha256,
            key_id: 1,
            key: b"k".to_vec(),
        };
        assert_eq!(key.au_type(), AuType::Crypto);
    }

    #[test]
    fn test_md5_packet_rejected_by_hmac_key() {
        // A receiver configured for HMAC-SHA-256 must not accept an MD5-authed
        // packet under the same key_id, even though both wear AuType=Crypto.
        let packet = build_ospf_packet(48);
        let md5_key = AuthKey::Md5 {
            key_id: 7,
            key: b"shared".to_vec(),
        };
        let md5_authed = apply_auth(packet, &md5_key, 1);

        let sha_key = AuthKey::HmacSha {
            algo: HmacAlgo::Sha256,
            key_id: 7,
            key: b"shared".to_vec(),
        };
        // auth_data_length on the wire is 16, sha256 expects 32 → reject.
        assert!(!verify_auth(&md5_authed, &sha_key));
    }
}
