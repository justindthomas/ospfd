//! OSPF Area: a self-contained routing domain with its own LSDB.
//!
//! RFC 2328 Section 6 defines areas. Each area runs its own SPF on its own
//! LSDB. The backbone area (0.0.0.0) connects multiple areas through ABRs.

use std::net::Ipv4Addr;

use crate::lsdb::Lsdb;

/// Area type (RFC 2328 Section 3.6, RFC 3101).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AreaType {
    /// Standard area: full OSPF behavior, all LSA types accepted.
    Normal,
    /// Stub area: rejects Type 5 (AS-External) LSAs (Phase 2b).
    Stub,
    /// NSSA: stub-like, but supports Type 7 (NSSA-External) LSAs (Phase 2b).
    Nssa,
}

/// An OSPF area.
#[derive(Debug)]
pub struct Area {
    /// Area ID (4-byte address-like identifier).
    pub area_id: Ipv4Addr,
    /// Area type.
    pub area_type: AreaType,
    /// Default Summary-LSA cost for stub/NSSA areas (the metric ABRs use
    /// when originating the default-route Type 3 LSA into this area).
    pub default_cost: u32,
    /// Link State Database for this area.
    pub lsdb: Lsdb,
}

impl Area {
    /// Create a new area with an empty LSDB.
    pub fn new(area_id: Ipv4Addr, area_type: AreaType, router_id: Ipv4Addr) -> Self {
        Area {
            area_id,
            area_type,
            default_cost: 1,
            lsdb: Lsdb::new(router_id),
        }
    }

    /// Returns true if this is the backbone area.
    pub fn is_backbone(&self) -> bool {
        self.area_id.is_unspecified()
    }

    /// Returns true if Type 5 (AS-External) LSAs are allowed in this area.
    /// Stub and NSSA areas reject Type 5s.
    pub fn accepts_as_external(&self) -> bool {
        self.area_type == AreaType::Normal
    }
}
