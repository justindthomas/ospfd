//! Link State Database (LSDB).
//!
//! Stores all LSAs for an area. Handles LSA installation, aging, and lookup.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use crate::packet::lsa::*;

/// An LSA entry in the database, with metadata.
#[derive(Debug, Clone)]
pub struct LsdbEntry {
    pub lsa: Lsa,
    /// When this LSA was installed (for aging).
    pub installed_at: Instant,
    /// Whether this LSA was originated by us.
    pub self_originated: bool,
}

/// LSAs are refreshed every 1800 seconds (30 minutes) per RFC 2328.
pub const LS_REFRESH_TIME: u16 = 1800;

impl LsdbEntry {
    /// Current age of the LSA, accounting for elapsed time since installation.
    pub fn current_age(&self) -> u16 {
        let elapsed = self.installed_at.elapsed().as_secs() as u16;
        let age = self.lsa.header.ls_age.saturating_add(elapsed);
        age.min(MAX_AGE)
    }

    /// Returns true if this LSA has reached MaxAge.
    pub fn is_max_age(&self) -> bool {
        self.current_age() >= MAX_AGE
    }

    /// Returns true if this self-originated LSA is due for refresh.
    pub fn needs_refresh(&self) -> bool {
        self.self_originated && self.current_age() >= LS_REFRESH_TIME
    }
}

/// The Link State Database for a single OSPF area.
#[derive(Debug)]
pub struct Lsdb {
    /// All LSAs, keyed by (type, link_state_id, advertising_router).
    entries: HashMap<LsaKey, LsdbEntry>,
    /// Our router ID (for self-originated LSA detection).
    router_id: Ipv4Addr,
}

impl Lsdb {
    pub fn new(router_id: Ipv4Addr) -> Self {
        Lsdb {
            entries: HashMap::new(),
            router_id,
        }
    }

    /// Look up an LSA by its key.
    pub fn get(&self, key: &LsaKey) -> Option<&LsdbEntry> {
        self.entries.get(key)
    }

    /// Bump the sequence number of an existing entry to `new_seq`
    /// without re-encoding the body. Used by stale-self-LSA
    /// recovery: when we restart, peers may have cached a higher
    /// seq of our LSA than we just originated. Setting our local
    /// entry to the peer's seq + a subsequent `originate_*` call
    /// (which does `existing_seq + 1`) overrides the peer's stale
    /// copy without waiting for MaxAge. Returns `true` when the
    /// entry existed and was strictly bumped.
    pub fn bump_seq(&mut self, key: &LsaKey, new_seq: i32) -> bool {
        if let Some(existing) = self.entries.get_mut(key) {
            if existing.lsa.header.ls_sequence_number < new_seq {
                existing.lsa.header.ls_sequence_number = new_seq;
                return true;
            }
        }
        false
    }

    /// Get all LSAs in the database.
    pub fn all_entries(&self) -> impl Iterator<Item = (&LsaKey, &LsdbEntry)> {
        self.entries.iter()
    }

    /// Get all LSA headers (for DB Description exchange).
    pub fn all_headers(&self) -> Vec<LsaHeader> {
        self.entries
            .values()
            .filter(|e| !e.is_max_age())
            .map(|e| {
                let mut hdr = e.lsa.header.clone();
                hdr.ls_age = e.current_age();
                hdr
            })
            .collect()
    }

    /// Number of LSAs in the database.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Alternate accessor (for use in trace logging where `len` clashes
    /// with the macro field name).
    pub fn entries_count(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Install or update an LSA in the database.
    ///
    /// Returns `InstallResult` indicating what happened:
    /// - `New`: LSA was not in the database, now installed
    /// - `Updated`: LSA replaced an older instance
    /// - `Duplicate`: LSA is the same instance as what we have (no change)
    /// - `Older`: LSA is older than what we have (rejected)
    pub fn install(&mut self, lsa: Lsa) -> InstallResult {
        let key = lsa.key();
        let self_originated = lsa.header.advertising_router == self.router_id;

        if let Some(existing) = self.entries.get(&key) {
            match lsa.header.is_more_recent_than(&existing.lsa.header) {
                std::cmp::Ordering::Greater => {
                    // New LSA is more recent — replace
                    tracing::debug!(
                        ls_type = ?lsa.header.ls_type,
                        lsid = %lsa.header.link_state_id,
                        adv_router = %lsa.header.advertising_router,
                        seq = lsa.header.ls_sequence_number,
                        "LSDB: updated LSA"
                    );
                    self.entries.insert(
                        key,
                        LsdbEntry {
                            lsa,
                            installed_at: Instant::now(),
                            self_originated,
                        },
                    );
                    InstallResult::Updated
                }
                std::cmp::Ordering::Equal => InstallResult::Duplicate,
                std::cmp::Ordering::Less => InstallResult::Older,
            }
        } else {
            // New LSA
            tracing::debug!(
                ls_type = ?lsa.header.ls_type,
                lsid = %lsa.header.link_state_id,
                adv_router = %lsa.header.advertising_router,
                seq = lsa.header.ls_sequence_number,
                "LSDB: new LSA"
            );
            self.entries.insert(
                key,
                LsdbEntry {
                    lsa,
                    installed_at: Instant::now(),
                    self_originated,
                },
            );
            InstallResult::New
        }
    }

    /// Remove an LSA from the database (for MaxAge flushing).
    pub fn remove(&mut self, key: &LsaKey) -> Option<LsdbEntry> {
        self.entries.remove(key)
    }

    /// Remove all MaxAge LSAs that have been flushed (no neighbors on retransmit lists).
    pub fn flush_max_age(&mut self) -> Vec<LsaKey> {
        let max_age_keys: Vec<LsaKey> = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_max_age())
            .map(|(k, _)| *k)
            .collect();

        for key in &max_age_keys {
            self.entries.remove(key);
        }

        max_age_keys
    }

    /// Get all self-originated LSAs whose age has reached LSRefreshTime.
    pub fn self_originated_due_for_refresh(&self) -> Vec<LsaKey> {
        self.entries
            .iter()
            .filter(|(_, e)| e.needs_refresh())
            .map(|(k, _)| *k)
            .collect()
    }

    /// Get a HashMap reference to the raw LSA map (for SPF calculation).
    pub fn as_lsa_map(&self) -> HashMap<LsaKey, Lsa> {
        self.entries
            .iter()
            .filter(|(_, e)| !e.is_max_age())
            .map(|(k, e)| {
                let mut lsa = e.lsa.clone();
                lsa.header.ls_age = e.current_age();
                (*k, lsa)
            })
            .collect()
    }

    /// Originate or refresh our Router-LSA.
    ///
    /// Builds a Router-LSA from the current interface/neighbor state and
    /// installs it in the LSDB. Returns the LSA for flooding.
    pub fn originate_router_lsa(
        &mut self,
        router_id: Ipv4Addr,
        _area_id: Ipv4Addr,
        flags: u8,
        links: Vec<RouterLink>,
        options: u8,
    ) -> Lsa {
        let key = LsaKey {
            ls_type: LsaType::Router,
            link_state_id: router_id,
            advertising_router: router_id,
        };

        // Determine sequence number
        let seq = if let Some(existing) = self.entries.get(&key) {
            existing.lsa.header.ls_sequence_number.wrapping_add(1)
        } else {
            INITIAL_SEQUENCE_NUMBER
        };

        tracing::info!(
            router_id = %router_id,
            flags_in = format!("{:#04x}", flags),
            seq = format!("{:#x}", seq),
            link_count = links.len(),
            "lsdb::originate_router_lsa: building",
        );

        let body = RouterLsa { flags, links };

        // Calculate body size
        let mut body_buf = Vec::new();
        body.encode(&mut body_buf);
        let length = (LSA_HEADER_LEN + body_buf.len()) as u16;

        let lsa = Lsa {
            header: LsaHeader {
                ls_age: 0,
                options,
                ls_type: LsaType::Router,
                link_state_id: router_id,
                advertising_router: router_id,
                ls_sequence_number: seq,
                ls_checksum: 0, // Will be set by encode()
                length,
            },
            body: LsaBody::Router(body),
        };

        // Encode to compute checksum, then re-parse to get correct checksum
        let encoded = lsa.encode();
        let body_byte_after_header_offset_1 = encoded.get(21).copied().unwrap_or(0);
        tracing::info!(
            encoded_len = encoded.len(),
            body_flag_byte = format!("{:#04x}", body_byte_after_header_offset_1),
            "lsdb::originate_router_lsa: encoded",
        );
        let lsa_with_checksum = Lsa::parse(&encoded).expect("re-parse own LSA");
        if let LsaBody::Router(ref r) = lsa_with_checksum.body {
            tracing::info!(
                parsed_flags = format!("{:#04x}", r.flags),
                "lsdb::originate_router_lsa: re-parsed flags",
            );
        }

        self.install(lsa_with_checksum.clone());
        lsa_with_checksum
    }
}

/// Result of installing an LSA into the LSDB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallResult {
    /// LSA was new (not previously in database).
    New,
    /// LSA replaced an older instance.
    Updated,
    /// LSA is the same instance as what we have.
    Duplicate,
    /// LSA is older than what we have (rejected).
    Older,
}

impl InstallResult {
    /// Returns true if the LSA changed the database (New or Updated).
    pub fn changed(&self) -> bool {
        matches!(self, InstallResult::New | InstallResult::Updated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_router_lsa(router_id: Ipv4Addr, seq: i32) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaType::Router,
                link_state_id: router_id,
                advertising_router: router_id,
                ls_sequence_number: seq,
                ls_checksum: 0,
                length: 36,
            },
            body: LsaBody::Router(RouterLsa {
                flags: 0,
                links: vec![RouterLink {
                    link_id: Ipv4Addr::new(10, 0, 0, 0),
                    link_data: Ipv4Addr::new(255, 255, 255, 0),
                    link_type: RouterLinkType::StubNetwork,
                    num_tos: 0,
                    metric: 10,
                }],
            }),
        }
    }

    #[test]
    fn test_install_new_lsa() {
        let mut lsdb = Lsdb::new(Ipv4Addr::new(1, 1, 1, 1));
        let lsa = make_router_lsa(Ipv4Addr::new(2, 2, 2, 2), INITIAL_SEQUENCE_NUMBER);
        let result = lsdb.install(lsa);
        assert_eq!(result, InstallResult::New);
        assert_eq!(lsdb.len(), 1);
    }

    #[test]
    fn test_install_newer_replaces() {
        let mut lsdb = Lsdb::new(Ipv4Addr::new(1, 1, 1, 1));
        let lsa1 = make_router_lsa(Ipv4Addr::new(2, 2, 2, 2), INITIAL_SEQUENCE_NUMBER);
        let lsa2 = make_router_lsa(Ipv4Addr::new(2, 2, 2, 2), INITIAL_SEQUENCE_NUMBER + 1);
        lsdb.install(lsa1);
        let result = lsdb.install(lsa2);
        assert_eq!(result, InstallResult::Updated);
        assert_eq!(lsdb.len(), 1);
    }

    #[test]
    fn test_install_older_rejected() {
        let mut lsdb = Lsdb::new(Ipv4Addr::new(1, 1, 1, 1));
        let lsa1 = make_router_lsa(Ipv4Addr::new(2, 2, 2, 2), INITIAL_SEQUENCE_NUMBER + 1);
        let lsa2 = make_router_lsa(Ipv4Addr::new(2, 2, 2, 2), INITIAL_SEQUENCE_NUMBER);
        lsdb.install(lsa1);
        let result = lsdb.install(lsa2);
        assert_eq!(result, InstallResult::Older);
    }

    #[test]
    fn test_install_duplicate() {
        let mut lsdb = Lsdb::new(Ipv4Addr::new(1, 1, 1, 1));
        let lsa = make_router_lsa(Ipv4Addr::new(2, 2, 2, 2), INITIAL_SEQUENCE_NUMBER);
        lsdb.install(lsa.clone());
        let result = lsdb.install(lsa);
        assert_eq!(result, InstallResult::Duplicate);
    }

    #[test]
    fn test_all_headers() {
        let mut lsdb = Lsdb::new(Ipv4Addr::new(1, 1, 1, 1));
        lsdb.install(make_router_lsa(Ipv4Addr::new(2, 2, 2, 2), INITIAL_SEQUENCE_NUMBER));
        lsdb.install(make_router_lsa(Ipv4Addr::new(3, 3, 3, 3), INITIAL_SEQUENCE_NUMBER));
        let headers = lsdb.all_headers();
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn test_originate_router_lsa() {
        let mut lsdb = Lsdb::new(Ipv4Addr::new(1, 1, 1, 1));
        let lsa = lsdb.originate_router_lsa(
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::UNSPECIFIED,
            0,
            vec![RouterLink {
                link_id: Ipv4Addr::new(10, 0, 0, 0),
                link_data: Ipv4Addr::new(255, 255, 255, 0),
                link_type: RouterLinkType::StubNetwork,
                num_tos: 0,
                metric: 10,
            }],
            0x02,
        );
        assert_eq!(lsa.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
        assert_eq!(lsdb.len(), 1);

        // Originate again — sequence number should increment
        let lsa2 = lsdb.originate_router_lsa(
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::UNSPECIFIED,
            0,
            vec![],
            0x02,
        );
        assert_eq!(lsa2.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER + 1);
    }
}
