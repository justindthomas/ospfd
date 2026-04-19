//! OSPFv3 route cache (post-cutover to ribd).
//!
//! Previously this module programmed VPP's IPv6 FIB directly. After
//! Phase 3 cutover, VPP programming lives in ribd; we keep only
//! the last SPF output in memory for the control query path.

use std::collections::HashMap;
use std::net::Ipv6Addr;

use crate::spf_v3::Ospfv3Route;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RouteKey {
    prefix: Ipv6Addr,
    prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteValue {
    next_hops: Vec<(Ipv6Addr, u32)>,
    cost: u32,
}

pub struct OspfRibV3 {
    installed: HashMap<RouteKey, RouteValue>,
}

impl OspfRibV3 {
    pub fn new() -> Self {
        OspfRibV3 {
            installed: HashMap::new(),
        }
    }

    pub fn route_count(&self) -> usize {
        self.installed.len()
    }

    /// Update the cache to reflect `new_routes`. Returns (added,
    /// deleted) diffs for logging.
    pub fn apply_routes(&mut self, new_routes: &[Ospfv3Route]) -> (usize, usize) {
        let mut new_map: HashMap<RouteKey, RouteValue> = HashMap::new();
        for route in new_routes {
            let key = RouteKey {
                prefix: route.prefix,
                prefix_len: route.prefix_len,
            };
            let val = RouteValue {
                next_hops: route.next_hops.clone(),
                cost: route.cost,
            };
            new_map
                .entry(key)
                .and_modify(|e| {
                    if route.cost < e.cost {
                        *e = val.clone();
                    } else if route.cost == e.cost {
                        for nh in &val.next_hops {
                            if !e.next_hops.contains(nh) {
                                e.next_hops.push(*nh);
                            }
                        }
                    }
                })
                .or_insert(val);
        }
        let mut added = 0;
        let mut deleted = 0;
        for k in self.installed.keys() {
            if !new_map.contains_key(k) {
                deleted += 1;
            }
        }
        for (k, v) in &new_map {
            match self.installed.get(k) {
                None => added += 1,
                Some(existing) if existing != v => added += 1,
                _ => {}
            }
        }
        self.installed = new_map;
        (added, deleted)
    }

    pub fn clear(&mut self) {
        self.installed.clear();
    }
}

impl Default for OspfRibV3 {
    fn default() -> Self {
        Self::new()
    }
}
