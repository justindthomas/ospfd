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
        self.entries.insert(key, entry);
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
}
