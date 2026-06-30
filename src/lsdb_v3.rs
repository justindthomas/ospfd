//! OSPFv3 Link State Database (skeleton).
//!
//! Stores LSAs keyed by (ls_type, link_state_id, advertising_router).
//! Unlike v2, OSPFv3 uses the full 16-bit LS type which encodes flooding
//! scope, so link-scope LSAs (Link-LSAs) live per-interface and must
//! be partitioned — for now we keep everything in a single map and
//! rely on type to disambiguate.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::packet_v3::lsa::{LsaV3Header, LsaV3Type};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LsaKeyV3 {
    /// Scope identifier: Some(area_id) for area-scope and link-scope
    /// LSAs, None for AS-scope (Type 5). Including area in the key
    /// lets an ABR hold a Router-LSA (ls_id 0, adv_router=self) in
    /// more than one area simultaneously.
    pub area: Option<Ipv4Addr>,
    pub ls_type: LsaV3Type,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
}

#[derive(Debug, Clone)]
pub struct LsaEntryV3 {
    pub header: LsaV3Header,
    /// Full on-wire LSA bytes (header + body).
    pub raw: Vec<u8>,
    /// The area this LSA belongs to. None for AS-scope LSAs
    /// (Type 5 AS-External); Some(area_id) for area-scope and
    /// link-scope LSAs (for link-scope, the interface's area).
    pub area: Option<Ipv4Addr>,
}

#[derive(Debug, Default)]
pub struct LsdbV3 {
    entries: HashMap<LsaKeyV3, LsaEntryV3>,
    /// Monotonic counter bumped whenever the LSDB's *content* changes
    /// — i.e. a new LSA instance is installed (new key, or a fresher
    /// instance of an existing key). Unchanged re-inserts (same
    /// sequence number and checksum) do NOT bump it.
    ///
    /// The OSPFv3 daemon loop schedules SPF on a change in this value
    /// rather than on `len()`, because an in-place LSA update (FRR
    /// re-originating its Intra-Area-Prefix-LSA to add a loopback
    /// prefix, say) keeps `len()` constant while genuinely changing
    /// the routing inputs. Gating SPF on `len()` alone silently
    /// dropped such updates (see daemon_v3 SPF tick).
    generation: u64,
}

impl LsdbV3 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, entry: LsaEntryV3) {
        let key = LsaKeyV3 {
            area: entry.area,
            ls_type: entry.header.ls_type,
            link_state_id: entry.header.link_state_id,
            advertising_router: entry.header.advertising_router,
        };
        // Only treat this as a content change (and bump the
        // generation) when the installed instance is genuinely
        // different from what we already hold. OSPF identifies a
        // distinct LSA instance by (sequence number, checksum); a
        // re-flood of the same instance must not perturb SPF
        // scheduling.
        let changed = match self.entries.get(&key) {
            Some(existing) => {
                existing.header.ls_sequence_number != entry.header.ls_sequence_number
                    || existing.header.ls_checksum != entry.header.ls_checksum
            }
            None => true,
        };
        if changed {
            self.generation = self.generation.wrapping_add(1);
        }
        self.entries.insert(key, entry);
    }

    /// Content-change generation counter. See the field doc.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn get(&self, key: &LsaKeyV3) -> Option<&LsaEntryV3> {
        self.entries.get(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn headers(&self) -> Vec<LsaV3Header> {
        self.entries.values().map(|e| e.header.clone()).collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = &LsaEntryV3> {
        self.entries.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_get() {
        let mut db = LsdbV3::new();
        let hdr = LsaV3Header {
            ls_age: 0,
            ls_type: LsaV3Type::Router,
            link_state_id: Ipv4Addr::new(0, 0, 0, 0),
            advertising_router: Ipv4Addr::new(1, 1, 1, 1),
            ls_sequence_number: 0x80000001u32 as i32,
            ls_checksum: 0,
            length: 24,
        };
        db.insert(LsaEntryV3 {
            header: hdr,
            raw: vec![0; 24],
            area: Some(Ipv4Addr::UNSPECIFIED),
        });
        assert_eq!(db.len(), 1);
        assert_eq!(db.headers().len(), 1);
        // Verify key lookup
        let key = LsaKeyV3 {
            area: Some(Ipv4Addr::UNSPECIFIED),
            ls_type: LsaV3Type::Router,
            link_state_id: Ipv4Addr::new(0, 0, 0, 0),
            advertising_router: Ipv4Addr::new(1, 1, 1, 1),
        };
        assert!(db.get(&key).is_some());
    }

    fn entry(seq: i32, checksum: u16) -> LsaEntryV3 {
        LsaEntryV3 {
            header: LsaV3Header {
                ls_age: 0,
                ls_type: LsaV3Type::IntraAreaPrefix,
                link_state_id: Ipv4Addr::new(0, 0, 0, 5),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                ls_sequence_number: seq,
                ls_checksum: checksum,
                length: 24,
            },
            raw: vec![0; 24],
            area: Some(Ipv4Addr::UNSPECIFIED),
        }
    }

    // Regression: SPF in the v3 daemon loop is scheduled on a change in
    // the generation counter. An in-place LSA update (same key, fresher
    // instance) must bump the generation even though len() is unchanged
    // — otherwise the recomputed route never reaches ribd / the FIB.
    #[test]
    fn generation_bumps_on_in_place_update_not_on_duplicate() {
        let mut db = LsdbV3::new();
        assert_eq!(db.generation(), 0);

        // First install of a key.
        db.insert(entry(0x80000001u32 as i32, 0x1111));
        assert_eq!(db.len(), 1);
        let g1 = db.generation();
        assert_eq!(g1, 1, "first install must bump generation");

        // Re-flood of the *same* instance (same seq + checksum): no
        // content change, generation must not move.
        db.insert(entry(0x80000001u32 as i32, 0x1111));
        assert_eq!(db.len(), 1);
        assert_eq!(db.generation(), g1, "duplicate re-flood must not bump");

        // Fresher instance (new seq): same key, len() unchanged, but
        // content changed — generation MUST bump so SPF re-runs.
        db.insert(entry(0x80000002u32 as i32, 0x2222));
        assert_eq!(db.len(), 1, "len unchanged on in-place update");
        assert_eq!(
            db.generation(),
            g1 + 1,
            "in-place LSA update must bump generation"
        );

        // Same seq but different checksum (defensive): treat as changed.
        db.insert(entry(0x80000002u32 as i32, 0x3333));
        assert_eq!(db.generation(), g1 + 2);
    }
}
