//! OSPF SPF (Shortest Path First) calculation (RFC 2328 Section 16).
//!
//! Implements Dijkstra's algorithm on the LSDB to compute a routing table.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::Ipv4Addr;

use crate::packet::lsa::*;

/// Route sub-type — determines which admin-distance bucket ribd puts
/// this in. All four are at AD 110 today, but keeping them distinct
/// lets operators tune per-sub-type later without refactoring the
/// wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OspfRouteKind {
    /// Intra-area route (learned from Router/Network-LSAs in our own
    /// area).
    Intra,
    /// Inter-area route (learned from a Type 3 Summary-LSA).
    Inter,
    /// External Type 1 (AS-External with E-bit clear). Total cost =
    /// cost-to-ASBR + external metric.
    External1,
    /// External Type 2 (AS-External with E-bit set). Cost = external
    /// metric alone; cost-to-ASBR is only a tiebreaker.
    External2,
}

/// A computed route from SPF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfRoute {
    /// Destination prefix.
    pub prefix: Ipv4Addr,
    /// Prefix length.
    pub prefix_len: u8,
    /// Next-hop IP address.
    pub next_hop: Ipv4Addr,
    /// Cost to reach this destination.
    pub cost: u32,
    /// Outgoing interface (VPP sw_if_index).
    pub sw_if_index: u32,
    /// Route sub-type. Used by rib_client to split routes into
    /// separate `Bulk` messages by Source so ribd's admin-distance
    /// arbitration can treat intra/inter/ext distinctly.
    pub kind: OspfRouteKind,
}

/// Node in the SPF tree during computation.
#[derive(Debug, Clone, Eq, PartialEq)]
struct SpfNode {
    router_id: Ipv4Addr,
    cost: u32,
}

impl Ord for SpfNode {
    fn cmp(&self, other: &Self) -> Ordering {
        // Min-heap: reverse the cost comparison
        other
            .cost
            .cmp(&self.cost)
            .then_with(|| self.router_id.cmp(&other.router_id))
    }
}

impl PartialOrd for SpfNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Input: info about one of our OSPF interfaces.
#[derive(Debug, Clone)]
pub struct SpfInterface {
    pub address: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub sw_if_index: u32,
    pub cost: u16,
}

/// Input: info about a direct neighbor we've formed at least 2-Way with.
#[derive(Debug, Clone)]
pub struct SpfNeighbor {
    /// Neighbor's router ID.
    pub router_id: Ipv4Addr,
    /// Neighbor's interface address (the Hello source address).
    pub address: Ipv4Addr,
    /// Our outgoing interface toward this neighbor.
    pub sw_if_index: u32,
}

/// Next-hop for a destination — resolved IP + outgoing interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NextHop {
    pub address: Ipv4Addr,
    pub sw_if_index: u32,
}

/// Run the SPF algorithm on the LSDB.
///
/// Returns a list of routes to install in the FIB.
pub fn calculate_spf(
    my_router_id: Ipv4Addr,
    lsdb: &HashMap<LsaKey, Lsa>,
    interfaces: &[SpfInterface],
    neighbors: &[SpfNeighbor],
) -> Vec<SpfRoute> {
    let mut dist: HashMap<Ipv4Addr, u32> = HashMap::new();
    let mut next_hops: HashMap<Ipv4Addr, NextHop> = HashMap::new();
    let mut visited: HashSet<Ipv4Addr> = HashSet::new();
    let mut heap = BinaryHeap::new();

    // Start with ourselves at cost 0
    dist.insert(my_router_id, 0);
    heap.push(SpfNode {
        router_id: my_router_id,
        cost: 0,
    });

    // Map of router_id -> Router-LSA for quick lookup
    let router_lsas: HashMap<Ipv4Addr, &Lsa> = lsdb
        .values()
        .filter(|lsa| lsa.header.ls_type == LsaType::Router)
        .map(|lsa| (lsa.header.advertising_router, lsa))
        .collect();

    // Map of (link_state_id = DR's interface address, adv_router = DR's router ID)
    // -> Network-LSA. Network-LSAs are keyed by the DR's interface IP as link_state_id.
    let network_lsas: HashMap<Ipv4Addr, &Lsa> = lsdb
        .values()
        .filter(|lsa| lsa.header.ls_type == LsaType::Network)
        .map(|lsa| (lsa.header.link_state_id, lsa))
        .collect();

    // Map of router_id -> direct neighbor for next-hop resolution
    let neighbor_map: HashMap<Ipv4Addr, &SpfNeighbor> =
        neighbors.iter().map(|n| (n.router_id, n)).collect();

    // Map of our interface addresses for direct-connected lookup
    let iface_by_addr: HashMap<Ipv4Addr, &SpfInterface> =
        interfaces.iter().map(|i| (i.address, i)).collect();

    // Dijkstra's algorithm
    while let Some(SpfNode { router_id, cost }) = heap.pop() {
        if visited.contains(&router_id) {
            continue;
        }
        visited.insert(router_id);

        let Some(lsa) = router_lsas.get(&router_id) else {
            continue;
        };

        let LsaBody::Router(ref router_lsa) = lsa.body else {
            continue;
        };

        for link in &router_lsa.links {
            match link.link_type {
                RouterLinkType::PointToPoint => {
                    // link_id = neighbor's router ID
                    let neighbor_id = link.link_id;
                    let new_cost = cost + link.metric as u32;

                    if new_cost >= *dist.get(&neighbor_id).unwrap_or(&u32::MAX) {
                        continue;
                    }
                    dist.insert(neighbor_id, new_cost);

                    // Resolve next-hop
                    let nh = if router_id == my_router_id {
                        // Direct neighbor — look up in neighbor table
                        if let Some(n) = neighbor_map.get(&neighbor_id) {
                            Some(NextHop {
                                address: n.address,
                                sw_if_index: n.sw_if_index,
                            })
                        } else {
                            None
                        }
                    } else {
                        // Inherit next-hop from our path to router_id
                        next_hops.get(&router_id).copied()
                    };

                    if let Some(nh) = nh {
                        next_hops.insert(neighbor_id, nh);
                    }
                    heap.push(SpfNode {
                        router_id: neighbor_id,
                        cost: new_cost,
                    });
                }

                RouterLinkType::TransitNetwork => {
                    // link_id = DR's interface address on the network
                    // link_data = our interface address on this network
                    let dr_addr = link.link_id;

                    // Look up the Network-LSA
                    let Some(net_lsa) = network_lsas.get(&dr_addr) else {
                        continue;
                    };
                    let LsaBody::Network(ref network_lsa) = net_lsa.body else {
                        continue;
                    };

                    // Cost to reach the network itself
                    let net_cost = cost + link.metric as u32;

                    // For each router attached to this network, add it as a candidate
                    for attached in &network_lsa.attached_routers {
                        if *attached == router_id {
                            continue; // skip the router we came from
                        }
                        if new_cost_better(&dist, *attached, net_cost) {
                            dist.insert(*attached, net_cost);

                            // Resolve next-hop
                            let nh = if router_id == my_router_id {
                                // We're attached to this network directly.
                                // Next-hop is the attached router's interface address
                                // on this network, which we can get two ways:
                                // 1. If they are a direct neighbor (in neighbor_map), use their
                                //    Hello source address.
                                // 2. Otherwise, look at their Router-LSA for a TransitNetwork
                                //    link with the same link_id (=dr_addr); its link_data is
                                //    their interface address.
                                let addr = neighbor_map
                                    .get(attached)
                                    .map(|n| n.address)
                                    .or_else(|| {
                                        find_router_iface_on_network(
                                            &router_lsas,
                                            *attached,
                                            dr_addr,
                                        )
                                    })
                                    .unwrap_or(*attached);

                                // Our outgoing interface is the one whose address == link.link_data
                                let sw_if_index = iface_by_addr
                                    .get(&link.link_data)
                                    .map(|i| i.sw_if_index)
                                    .unwrap_or(0);

                                Some(NextHop {
                                    address: addr,
                                    sw_if_index,
                                })
                            } else {
                                next_hops.get(&router_id).copied()
                            };

                            if let Some(nh) = nh {
                                next_hops.insert(*attached, nh);
                            }
                            heap.push(SpfNode {
                                router_id: *attached,
                                cost: net_cost,
                            });
                        }
                    }

                    // Also add a route for the transit network prefix itself
                    // (handled in the stub-pass phase below — we need the Network-LSA's
                    // mask, which is in its body).
                }

                RouterLinkType::StubNetwork => {
                    // Handled in pass 2 below
                }

                RouterLinkType::VirtualLink => {
                    // Phase 2
                }
            }
        }
    }

    // Pass 2: collect routes from stub links
    let mut routes = Vec::new();

    for (router_id, cost) in &dist {
        let Some(lsa) = router_lsas.get(router_id) else {
            continue;
        };
        let LsaBody::Router(ref router_lsa) = lsa.body else {
            continue;
        };

        for link in &router_lsa.links {
            if link.link_type == RouterLinkType::StubNetwork {
                let prefix = link.link_id;
                let mask = link.link_data;
                let prefix_len = mask_to_prefix_len(mask);
                let total_cost = cost + link.metric as u32;

                // Skip our own stub links: VPP already has the
                // connected route from `set interface ip address` and
                // the Linux kernel has it from the LCP TAP. Pushing a
                // route with ourselves as next-hop would clobber the
                // kernel's connected entry and break next-hop
                // resolution for *every other* OSPF route on this
                // segment. (Bug discovered 2026-04-14 on a
                // production /31 link.)
                if *router_id == my_router_id {
                    continue;
                }

                let nh = next_hops.get(router_id).copied().unwrap_or(NextHop {
                    address: Ipv4Addr::UNSPECIFIED,
                    sw_if_index: 0,
                });

                routes.push(SpfRoute {
                    prefix,
                    prefix_len,
                    next_hop: nh.address,
                    cost: total_cost,
                    sw_if_index: nh.sw_if_index,
                    kind: OspfRouteKind::Intra,
                });
            }
        }
    }

    // Pass 3: collect routes for transit network prefixes themselves
    // Each Network-LSA represents a network; its link_state_id is the DR's interface IP,
    // and its network_mask field gives us the prefix.
    for (dr_addr, net_lsa) in &network_lsas {
        let LsaBody::Network(ref network_lsa) = net_lsa.body else {
            continue;
        };
        // The DR's router-id is the advertising_router of the Network-LSA
        let dr_router = net_lsa.header.advertising_router;
        // Cost to the network = cost to DR (the network is reached via the DR)
        let dr_cost = match dist.get(&dr_router) {
            Some(c) => *c,
            None => continue,
        };

        let mask = network_lsa.network_mask;
        let prefix = apply_mask(*dr_addr, mask);
        let prefix_len = mask_to_prefix_len(mask);

        // If we're attached to this transit network, the prefix is
        // already a connected route in VPP/kernel — don't install
        // anything (same rationale as own-stub-link skip in Pass 2).
        if network_lsa
            .attached_routers
            .iter()
            .any(|r| *r == my_router_id)
        {
            continue;
        }

        let nh = next_hops.get(&dr_router).copied().unwrap_or(NextHop {
            address: Ipv4Addr::UNSPECIFIED,
            sw_if_index: 0,
        });

        routes.push(SpfRoute {
            prefix,
            prefix_len,
            next_hop: nh.address,
            cost: dr_cost,
            sw_if_index: nh.sw_if_index,
            kind: OspfRouteKind::Intra,
        });
    }

    routes
}

fn new_cost_better(dist: &HashMap<Ipv4Addr, u32>, id: Ipv4Addr, new_cost: u32) -> bool {
    new_cost < *dist.get(&id).unwrap_or(&u32::MAX)
}

/// Compute inter-area routes from Type 3 (Summary-Network) LSAs (RFC 2328
/// Section 16.2).
///
/// This is a post-pass that runs after intra-area SPF. For each Type 3 LSA
/// in the area's LSDB, we compute:
///   - destination prefix = link_state_id, masked by the LSA's network_mask
///   - cost = cost-to-the-ABR + metric in the Summary-LSA
///   - next-hop = inherited from the path to the ABR (advertising_router)
///
/// `intra_routes`: routes already computed by intra-area SPF for this area
///                 (used to look up the cost and next-hop to each ABR's
///                  router-id, which is itself reached via a Router-LSA)
/// `router_dist`: HashMap of router_id -> (cost, next-hop) for all routers
///                reachable in this area (output of intra-area SPF)
///
/// Returns a list of inter-area routes.
pub fn calculate_inter_area_routes(
    lsdb: &HashMap<LsaKey, Lsa>,
    router_paths: &HashMap<Ipv4Addr, (u32, NextHop)>,
) -> Vec<SpfRoute> {
    let mut routes = Vec::new();

    for (key, lsa) in lsdb {
        if key.ls_type != LsaType::SummaryNetwork {
            continue;
        }

        let LsaBody::Summary(ref summary) = lsa.body else {
            continue;
        };

        // The advertising router is the ABR. We need a path to it.
        let abr = lsa.header.advertising_router;
        let Some((abr_cost, nh)) = router_paths.get(&abr).copied() else {
            // ABR unreachable in this area — skip
            continue;
        };

        let prefix = apply_mask(lsa.header.link_state_id, summary.network_mask);
        let prefix_len = mask_to_prefix_len(summary.network_mask);
        let total_cost = abr_cost.saturating_add(summary.metric);

        routes.push(SpfRoute {
            prefix,
            prefix_len,
            next_hop: nh.address,
            cost: total_cost,
            sw_if_index: nh.sw_if_index,
            kind: OspfRouteKind::Inter,
        });
    }

    routes
}

/// Compute external routes from Type 5 (AS-External) LSAs.
///
/// RFC 2328 Section 16.4:
/// - For Type 1 externals: total cost = cost-to-ASBR + external metric
/// - For Type 2 externals: only the external metric is used (ASBR cost is
///   only a tiebreaker between equal-metric Type 2 routes)
///
/// `as_external_lsas`: HashMap of Type 5 LSAs (lives in the AS-wide LSDB)
/// `router_paths`: per-router (cost, next-hop) map from intra-area SPF
///
/// The advertising router must be reachable via the router paths table
/// (in any area) or the external route is not installed.
pub fn calculate_external_routes(
    as_external_lsas: &HashMap<LsaKey, Lsa>,
    router_paths: &HashMap<Ipv4Addr, (u32, NextHop)>,
) -> Vec<SpfRoute> {
    let mut routes = Vec::new();

    for (key, lsa) in as_external_lsas {
        if key.ls_type != LsaType::AsExternal {
            continue;
        }

        let LsaBody::AsExternal(ref ext) = lsa.body else {
            continue;
        };

        // Find the advertising router (ASBR) in the SPF tree
        let asbr = lsa.header.advertising_router;
        let Some((asbr_cost, asbr_nh)) = router_paths.get(&asbr).copied() else {
            continue;
        };

        let prefix = apply_mask(lsa.header.link_state_id, ext.network_mask);
        let prefix_len = mask_to_prefix_len(ext.network_mask);

        // Compute total cost
        let total_cost = if ext.metric_type_2 {
            // Type 2: only the external metric counts
            ext.metric
        } else {
            // Type 1: sum
            asbr_cost.saturating_add(ext.metric)
        };

        // Next-hop: if a forwarding address is set, use it; otherwise the
        // path-to-ASBR next-hop.
        let next_hop = if ext.forwarding_address.is_unspecified() {
            asbr_nh
        } else {
            // For a proper forwarding address lookup we'd resolve it through
            // our FIB. For Phase 2 we fall back to the ASBR next-hop since
            // connected redistribution never sets a forwarding address.
            asbr_nh
        };

        routes.push(SpfRoute {
            prefix,
            prefix_len,
            next_hop: next_hop.address,
            cost: total_cost,
            sw_if_index: next_hop.sw_if_index,
            kind: if ext.metric_type_2 {
                OspfRouteKind::External2
            } else {
                OspfRouteKind::External1
            },
        });
    }

    routes
}

/// Variant of calculate_spf that also returns the per-router (cost, next-hop)
/// table — needed for inter-area route calculation.
///
/// Returns (intra_area_routes, router_paths).
pub fn calculate_spf_with_paths(
    my_router_id: Ipv4Addr,
    lsdb: &HashMap<LsaKey, Lsa>,
    interfaces: &[SpfInterface],
    neighbors: &[SpfNeighbor],
) -> (Vec<SpfRoute>, HashMap<Ipv4Addr, (u32, NextHop)>) {
    // For now, this just calls calculate_spf and reconstructs the router
    // path table from the routes. A more efficient implementation would
    // hoist the dist/next_hops maps out of calculate_spf and return them
    // directly. We'll do the simple version first.

    let routes = calculate_spf(my_router_id, lsdb, interfaces, neighbors);

    // Re-derive the router paths by running a stripped-down Dijkstra.
    // (This is wasteful but keeps the API surface small. Refactor later.)
    let mut dist: HashMap<Ipv4Addr, u32> = HashMap::new();
    let mut next_hops: HashMap<Ipv4Addr, NextHop> = HashMap::new();
    let mut visited: HashSet<Ipv4Addr> = HashSet::new();
    let mut heap = BinaryHeap::new();

    dist.insert(my_router_id, 0);
    heap.push(SpfNode {
        router_id: my_router_id,
        cost: 0,
    });

    let router_lsas: HashMap<Ipv4Addr, &Lsa> = lsdb
        .values()
        .filter(|lsa| lsa.header.ls_type == LsaType::Router)
        .map(|lsa| (lsa.header.advertising_router, lsa))
        .collect();
    let network_lsas: HashMap<Ipv4Addr, &Lsa> = lsdb
        .values()
        .filter(|lsa| lsa.header.ls_type == LsaType::Network)
        .map(|lsa| (lsa.header.link_state_id, lsa))
        .collect();
    let neighbor_map: HashMap<Ipv4Addr, &SpfNeighbor> =
        neighbors.iter().map(|n| (n.router_id, n)).collect();
    let iface_by_addr: HashMap<Ipv4Addr, &SpfInterface> =
        interfaces.iter().map(|i| (i.address, i)).collect();

    while let Some(SpfNode { router_id, cost }) = heap.pop() {
        if visited.contains(&router_id) {
            continue;
        }
        visited.insert(router_id);

        let Some(lsa) = router_lsas.get(&router_id) else {
            continue;
        };
        let LsaBody::Router(ref router_lsa) = lsa.body else {
            continue;
        };

        for link in &router_lsa.links {
            match link.link_type {
                RouterLinkType::PointToPoint => {
                    let neighbor_id = link.link_id;
                    let new_cost = cost + link.metric as u32;
                    if new_cost >= *dist.get(&neighbor_id).unwrap_or(&u32::MAX) {
                        continue;
                    }
                    dist.insert(neighbor_id, new_cost);
                    let nh = if router_id == my_router_id {
                        neighbor_map.get(&neighbor_id).map(|n| NextHop {
                            address: n.address,
                            sw_if_index: n.sw_if_index,
                        })
                    } else {
                        next_hops.get(&router_id).copied()
                    };
                    if let Some(nh) = nh {
                        next_hops.insert(neighbor_id, nh);
                    }
                    heap.push(SpfNode {
                        router_id: neighbor_id,
                        cost: new_cost,
                    });
                }
                RouterLinkType::TransitNetwork => {
                    let dr_addr = link.link_id;
                    let Some(net_lsa) = network_lsas.get(&dr_addr) else {
                        continue;
                    };
                    let LsaBody::Network(ref network_lsa) = net_lsa.body else {
                        continue;
                    };
                    let net_cost = cost + link.metric as u32;
                    for attached in &network_lsa.attached_routers {
                        if *attached == router_id {
                            continue;
                        }
                        if new_cost_better(&dist, *attached, net_cost) {
                            dist.insert(*attached, net_cost);
                            let nh = if router_id == my_router_id {
                                let addr = neighbor_map
                                    .get(attached)
                                    .map(|n| n.address)
                                    .unwrap_or(*attached);
                                let sw_if_index = iface_by_addr
                                    .get(&link.link_data)
                                    .map(|i| i.sw_if_index)
                                    .unwrap_or(0);
                                Some(NextHop {
                                    address: addr,
                                    sw_if_index,
                                })
                            } else {
                                next_hops.get(&router_id).copied()
                            };
                            if let Some(nh) = nh {
                                next_hops.insert(*attached, nh);
                            }
                            heap.push(SpfNode {
                                router_id: *attached,
                                cost: net_cost,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let mut router_paths: HashMap<Ipv4Addr, (u32, NextHop)> = HashMap::new();
    for (rid, c) in dist {
        if let Some(nh) = next_hops.get(&rid) {
            router_paths.insert(rid, (c, *nh));
        } else if rid == my_router_id {
            router_paths.insert(
                rid,
                (
                    0,
                    NextHop {
                        address: Ipv4Addr::UNSPECIFIED,
                        sw_if_index: 0,
                    },
                ),
            );
        }
    }

    (routes, router_paths)
}

/// Look up a router's interface address on a given transit network by searching
/// its Router-LSA for a TransitNetwork link with the matching DR address.
fn find_router_iface_on_network(
    router_lsas: &HashMap<Ipv4Addr, &Lsa>,
    router_id: Ipv4Addr,
    dr_addr: Ipv4Addr,
) -> Option<Ipv4Addr> {
    let lsa = router_lsas.get(&router_id)?;
    let LsaBody::Router(ref router_lsa) = lsa.body else {
        return None;
    };
    for link in &router_lsa.links {
        if link.link_type == RouterLinkType::TransitNetwork && link.link_id == dr_addr {
            return Some(link.link_data);
        }
    }
    None
}

/// Convert a network mask to prefix length.
fn mask_to_prefix_len(mask: Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    bits.count_ones() as u8
}

/// Apply a mask to an address.
fn apply_mask(addr: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    let a = u32::from(addr);
    let m = u32::from(mask);
    Ipv4Addr::from(a & m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_to_prefix_len() {
        assert_eq!(mask_to_prefix_len(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(mask_to_prefix_len(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(mask_to_prefix_len(Ipv4Addr::new(255, 255, 255, 252)), 30);
        assert_eq!(mask_to_prefix_len(Ipv4Addr::new(255, 255, 255, 255)), 32);
    }

    fn make_router_lsa(router_id: Ipv4Addr, links: Vec<RouterLink>) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaType::Router,
                link_state_id: router_id,
                advertising_router: router_id,
                ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 20 + 4 + (12 * links.len()) as u16,
            },
            body: LsaBody::Router(RouterLsa { flags: 0, links }),
        }
    }

    #[test]
    fn test_spf_p2p_topology() {
        // R1 --P2P-- R2 with stub networks on each side
        let mut lsdb = HashMap::new();

        let r1 = make_router_lsa(
            Ipv4Addr::new(1, 1, 1, 1),
            vec![
                RouterLink {
                    link_id: Ipv4Addr::new(2, 2, 2, 2),
                    link_data: Ipv4Addr::new(10, 0, 0, 1),
                    link_type: RouterLinkType::PointToPoint,
                    num_tos: 0,
                    metric: 10,
                },
                RouterLink {
                    link_id: Ipv4Addr::new(10, 0, 0, 0),
                    link_data: Ipv4Addr::new(255, 255, 255, 0),
                    link_type: RouterLinkType::StubNetwork,
                    num_tos: 0,
                    metric: 10,
                },
            ],
        );
        lsdb.insert(r1.key(), r1);

        let r2 = make_router_lsa(
            Ipv4Addr::new(2, 2, 2, 2),
            vec![
                RouterLink {
                    link_id: Ipv4Addr::new(1, 1, 1, 1),
                    link_data: Ipv4Addr::new(10, 0, 0, 2),
                    link_type: RouterLinkType::PointToPoint,
                    num_tos: 0,
                    metric: 10,
                },
                RouterLink {
                    link_id: Ipv4Addr::new(10, 0, 1, 0),
                    link_data: Ipv4Addr::new(255, 255, 255, 0),
                    link_type: RouterLinkType::StubNetwork,
                    num_tos: 0,
                    metric: 10,
                },
            ],
        );
        lsdb.insert(r2.key(), r2);

        let interfaces = vec![SpfInterface {
            address: Ipv4Addr::new(10, 0, 0, 1),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            sw_if_index: 1,
            cost: 10,
        }];

        let neighbors = vec![SpfNeighbor {
            router_id: Ipv4Addr::new(2, 2, 2, 2),
            address: Ipv4Addr::new(10, 0, 0, 2),
            sw_if_index: 1,
        }];

        let routes = calculate_spf(Ipv4Addr::new(1, 1, 1, 1), &lsdb, &interfaces, &neighbors);

        // Should have routes to both stub networks
        let r2_stub = routes
            .iter()
            .find(|r| r.prefix == Ipv4Addr::new(10, 0, 1, 0))
            .expect("route to 10.0.1.0/24");
        assert_eq!(r2_stub.cost, 20);
        assert_eq!(r2_stub.next_hop, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(r2_stub.sw_if_index, 1);
    }

    #[test]
    fn test_spf_broadcast_transit_network() {
        // R1 (us) and R2 on a broadcast network 10.0.0.0/24, with R2 being DR.
        // R2 advertises a stub network 10.0.1.0/24 behind it.
        let mut lsdb = HashMap::new();

        // R1 (us) Router-LSA: TransitNetwork link pointing to R2 (DR)
        let r1 = make_router_lsa(
            Ipv4Addr::new(1, 1, 1, 1),
            vec![RouterLink {
                link_id: Ipv4Addr::new(10, 0, 0, 2), // DR's interface address
                link_data: Ipv4Addr::new(10, 0, 0, 1), // our interface address
                link_type: RouterLinkType::TransitNetwork,
                num_tos: 0,
                metric: 10,
            }],
        );
        lsdb.insert(r1.key(), r1);

        // R2 Router-LSA: TransitNetwork link on the same network + stub
        let r2 = make_router_lsa(
            Ipv4Addr::new(2, 2, 2, 2),
            vec![
                RouterLink {
                    link_id: Ipv4Addr::new(10, 0, 0, 2),
                    link_data: Ipv4Addr::new(10, 0, 0, 2),
                    link_type: RouterLinkType::TransitNetwork,
                    num_tos: 0,
                    metric: 10,
                },
                RouterLink {
                    link_id: Ipv4Addr::new(10, 0, 1, 0),
                    link_data: Ipv4Addr::new(255, 255, 255, 0),
                    link_type: RouterLinkType::StubNetwork,
                    num_tos: 0,
                    metric: 10,
                },
            ],
        );
        lsdb.insert(r2.key(), r2);

        // Network-LSA originated by R2 (DR), describing 10.0.0.0/24
        let net = Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaType::Network,
                link_state_id: Ipv4Addr::new(10, 0, 0, 2), // DR's interface address
                advertising_router: Ipv4Addr::new(2, 2, 2, 2),
                ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 32,
            },
            body: LsaBody::Network(NetworkLsa {
                network_mask: Ipv4Addr::new(255, 255, 255, 0),
                attached_routers: vec![
                    Ipv4Addr::new(1, 1, 1, 1),
                    Ipv4Addr::new(2, 2, 2, 2),
                ],
            }),
        };
        lsdb.insert(net.key(), net);

        let interfaces = vec![SpfInterface {
            address: Ipv4Addr::new(10, 0, 0, 1),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            sw_if_index: 5,
            cost: 10,
        }];

        let neighbors = vec![SpfNeighbor {
            router_id: Ipv4Addr::new(2, 2, 2, 2),
            address: Ipv4Addr::new(10, 0, 0, 2),
            sw_if_index: 5,
        }];

        let routes = calculate_spf(Ipv4Addr::new(1, 1, 1, 1), &lsdb, &interfaces, &neighbors);

        // Expect a route to 10.0.1.0/24 through R2, with proper next-hop
        let stub = routes
            .iter()
            .find(|r| r.prefix == Ipv4Addr::new(10, 0, 1, 0))
            .expect("route to R2's stub");
        assert_eq!(stub.next_hop, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(stub.sw_if_index, 5);
        // Cost: 10 (transit) + 10 (stub) = 20
        assert_eq!(stub.cost, 20);

        // The transit network 10.0.0.0/24 itself must NOT be in the
        // route table — it's a connected network we're attached to,
        // and VPP/kernel already have the connected route. Installing
        // an OSPF route with ourselves as next-hop would clobber
        // the kernel's connected entry. (Regression guard for the
        // 23.177.24.8/31 outage on root@10.11.64.155, 2026-04-14.)
        assert!(
            routes
                .iter()
                .all(|r| r.prefix != Ipv4Addr::new(10, 0, 0, 0)),
            "must not install own attached transit network as an OSPF route"
        );
    }

    #[test]
    fn test_spf_skips_own_stub_link() {
        // Regression guard for the production /31 outage on
        // root@10.11.64.155 (2026-04-14): with a single P2P link to a
        // peer, our own stub network for the link prefix used to be
        // installed with `next_hop = our_own_address`, which clobbered
        // the kernel's connected route via ribd and broke next-hop
        // resolution for every other OSPF route on that segment.
        let mut lsdb = HashMap::new();

        let r1 = make_router_lsa(
            Ipv4Addr::new(1, 1, 1, 1),
            vec![
                RouterLink {
                    link_id: Ipv4Addr::new(2, 2, 2, 2),
                    link_data: Ipv4Addr::new(23, 177, 24, 9),
                    link_type: RouterLinkType::PointToPoint,
                    num_tos: 0,
                    metric: 10,
                },
                // Our own stub for the /31 link subnet.
                RouterLink {
                    link_id: Ipv4Addr::new(23, 177, 24, 8),
                    link_data: Ipv4Addr::new(255, 255, 255, 254),
                    link_type: RouterLinkType::StubNetwork,
                    num_tos: 0,
                    metric: 10,
                },
            ],
        );
        lsdb.insert(r1.key(), r1);

        // Peer also advertises a useful loopback we WANT to learn.
        let r2 = make_router_lsa(
            Ipv4Addr::new(2, 2, 2, 2),
            vec![
                RouterLink {
                    link_id: Ipv4Addr::new(1, 1, 1, 1),
                    link_data: Ipv4Addr::new(23, 177, 24, 8),
                    link_type: RouterLinkType::PointToPoint,
                    num_tos: 0,
                    metric: 10,
                },
                RouterLink {
                    link_id: Ipv4Addr::new(10, 99, 0, 2),
                    link_data: Ipv4Addr::new(255, 255, 255, 255),
                    link_type: RouterLinkType::StubNetwork,
                    num_tos: 0,
                    metric: 1,
                },
            ],
        );
        lsdb.insert(r2.key(), r2);

        let interfaces = vec![SpfInterface {
            address: Ipv4Addr::new(23, 177, 24, 9),
            mask: Ipv4Addr::new(255, 255, 255, 254),
            sw_if_index: 1,
            cost: 10,
        }];

        let neighbors = vec![SpfNeighbor {
            router_id: Ipv4Addr::new(2, 2, 2, 2),
            address: Ipv4Addr::new(23, 177, 24, 8),
            sw_if_index: 1,
        }];

        let routes = calculate_spf(
            Ipv4Addr::new(1, 1, 1, 1),
            &lsdb,
            &interfaces,
            &neighbors,
        );

        // Our own stub /31 must NOT appear in the route table.
        assert!(
            routes
                .iter()
                .all(|r| r.prefix != Ipv4Addr::new(23, 177, 24, 8)),
            "own stub link 23.177.24.8/31 must not be installed as OSPF route, found: {:?}",
            routes,
        );

        // The peer's loopback should still be present and reachable
        // via the link's far side.
        let peer_lo = routes
            .iter()
            .find(|r| r.prefix == Ipv4Addr::new(10, 99, 0, 2))
            .expect("peer loopback /32 should be installed");
        assert_eq!(peer_lo.next_hop, Ipv4Addr::new(23, 177, 24, 8));
        assert_eq!(peer_lo.sw_if_index, 1);
    }
}
