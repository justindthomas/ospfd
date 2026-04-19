//! OSPFv2 route cache (post-cutover to ribd).
//!
//! Previously this module programmed VPP's IPv4 FIB directly. After
//! the ribd cutover (Phase 3), VPP programming lives in
//! ribd; this module keeps only the "last SPF output" in memory
//! so the control socket query (`ospfd query routes`) can serve
//! it without round-tripping to ribd.
//!
//! `apply_routes` is therefore now synchronous and infallible —
//! it's just a cache update. The daemon still calls it every SPF
//! cycle; the real route install happens via `RibClient::push_v4`.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::proto::spf::{OspfRouteKind, SpfRoute};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RouteKey {
    prefix: Ipv4Addr,
    prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteValue {
    next_hop: Ipv4Addr,
    cost: u32,
    sw_if_index: u32,
    kind: OspfRouteKind,
}

/// In-memory snapshot of the last SPF output. Exposed via the
/// control socket so operators can see what we'd push to ribd.
pub struct OspfRib {
    installed: HashMap<RouteKey, RouteValue>,
}

impl OspfRib {
    pub fn new() -> Self {
        OspfRib {
            installed: HashMap::new(),
        }
    }

    /// Update the cache to reflect `new_routes`. Returns (added,
    /// deleted) diffs for logging. Since this no longer touches VPP,
    /// it can't fail.
    pub fn apply_routes(&mut self, new_routes: &[SpfRoute]) -> (usize, usize) {
        let mut new_map: HashMap<RouteKey, RouteValue> = HashMap::new();
        for route in new_routes {
            let key = RouteKey {
                prefix: route.prefix,
                prefix_len: route.prefix_len,
            };
            let val = RouteValue {
                next_hop: route.next_hop,
                cost: route.cost,
                sw_if_index: route.sw_if_index,
                kind: route.kind,
            };
            new_map
                .entry(key)
                .and_modify(|existing| {
                    if route.cost < existing.cost {
                        *existing = val.clone();
                    }
                })
                .or_insert(val);
        }

        let mut added = 0;
        let mut deleted = 0;
        for key in self.installed.keys() {
            if !new_map.contains_key(key) {
                deleted += 1;
            }
        }
        for (key, val) in &new_map {
            match self.installed.get(key) {
                None => added += 1,
                Some(existing) if existing != val => added += 1,
                _ => {}
            }
        }
        self.installed = new_map;
        (added, deleted)
    }

    /// Clear the cache (on shutdown).
    pub fn clear(&mut self) {
        self.installed.clear();
    }

    pub fn route_count(&self) -> usize {
        self.installed.len()
    }

    pub fn installed_routes(&self) -> Vec<SpfRoute> {
        self.installed
            .iter()
            .map(|(k, v)| SpfRoute {
                prefix: k.prefix,
                prefix_len: k.prefix_len,
                next_hop: v.next_hop,
                cost: v.cost,
                sw_if_index: v.sw_if_index,
                kind: v.kind,
            })
            .collect()
    }
}

impl Default for OspfRib {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_routes_tracks_adds_and_deletes() {
        let mut rib = OspfRib::new();
        let r1 = SpfRoute {
            prefix: Ipv4Addr::new(10, 1, 0, 0),
            prefix_len: 24,
            next_hop: Ipv4Addr::new(172, 30, 0, 1),
            cost: 10,
            sw_if_index: 1,
            kind: OspfRouteKind::Intra,
        };
        let r2 = SpfRoute {
            prefix: Ipv4Addr::new(10, 2, 0, 0),
            prefix_len: 24,
            next_hop: Ipv4Addr::new(172, 30, 0, 1),
            cost: 10,
            sw_if_index: 1,
            kind: OspfRouteKind::Intra,
        };

        let (added, deleted) = rib.apply_routes(&[r1.clone(), r2.clone()]);
        assert_eq!(added, 2);
        assert_eq!(deleted, 0);
        assert_eq!(rib.route_count(), 2);

        // Re-apply same set: no changes.
        let (a, d) = rib.apply_routes(&[r1.clone(), r2.clone()]);
        assert_eq!(a, 0);
        assert_eq!(d, 0);

        // Drop r2.
        let (a, d) = rib.apply_routes(&[r1]);
        assert_eq!(a, 0);
        assert_eq!(d, 1);
        assert_eq!(rib.route_count(), 1);
    }
}
