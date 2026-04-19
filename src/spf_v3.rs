//! OSPFv3 SPF (Shortest Path First) calculation (RFC 5340 Section 3.8).
//!
//! Multi-pass algorithm:
//!   Pass 1: Dijkstra over Router-LSAs and Network-LSAs to build a tree
//!           of reachable routers/transit-networks and their costs.
//!   Pass 2: Walk Intra-Area-Prefix-LSAs and attach each prefix to its
//!           referenced node, producing intra-area routes.
//!   Pass 3: Walk Inter-Area-Prefix-LSAs (Type 3). Each Type 3 LSA is
//!           originated by an ABR. The resulting cost is the cost to
//!           the advertising ABR (from pass 1) plus the LSA metric.
//!   Pass 4: Walk AS-External-LSAs (Type 5) and NSSA-LSAs (Type 7).
//!           The advertising ASBR is resolved in the tree; metric
//!           type determines whether the intermediate path cost
//!           contributes (E1) or the external metric alone is used
//!           (E2). When a forwarding address is set, it's resolved
//!           via longest-prefix match against the routes computed
//!           in passes 2–3 and supplies both the intermediate cost
//!           and the next-hops (RFC 5340 §3.8.1.5). Externals whose
//!           fa is unreachable are dropped.
//!
//! ECMP is supported throughout: a node's next_hops is a Vec that
//! grows on equal-cost alternate relaxations. Routes inherit the
//! full next-hops vec for multipath installation.
//!
//! Differences from v2 SPF:
//!  - Tree nodes are (router_id, interface_id) for Network-LSAs since
//!    network LSId is not an IP address.
//!  - Prefixes are not in Router/Network LSAs — they come from Type 9
//!    Intra-Area-Prefix-LSAs that reference (ls_type, ls_id, adv_router).
//!  - Next hops are link-local IPv6 addresses learned from Hellos.
//!
//! Not yet implemented: Type 7 → Type 5 ABR translation (we're
//! never an ABR today), incremental SPF (full SPF is fine at
//! current LSDB sizes), recursive fa resolution against locally-
//! attached prefixes (resolved only against peer-advertised routes).

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::lsdb_v3::{LsaEntryV3, LsdbV3};
use crate::packet_v3::lsa::{
    AsExternalLsaV3, InterAreaPrefixLsaV3, IntraAreaPrefixLsaV3, LsaV3Type, NetworkLsaV3,
    RouterLinkV3, RouterLsaV3, LSA_V3_HEADER_LEN,
};

/// Return true if `addr` falls within `prefix/len`.
fn prefix_matches_v3(addr: Ipv6Addr, prefix: Ipv6Addr, len: u8) -> bool {
    if len == 0 {
        return true;
    }
    if len > 128 {
        return false;
    }
    let a = u128::from_be_bytes(addr.octets());
    let p = u128::from_be_bytes(prefix.octets());
    let mask = if len == 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - len as u32)
    };
    (a & mask) == (p & mask)
}

/// OSPFv3 route sub-type. Mirrors the v2 `OspfRouteKind` but kept as
/// a separate enum so the v3 module doesn't depend on `proto::spf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ospfv3RouteKind {
    Intra,
    Inter,
    External1,
    External2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ospfv3Route {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    /// Next-hops for this prefix. Length 1 = single path; length > 1
    /// = equal-cost multipath. Each entry is (link-local address,
    /// sw_if_index).
    pub next_hops: Vec<(Ipv6Addr, u32)>,
    pub cost: u32,
    /// Route sub-type. Used by rib_client to group into separate
    /// ribd `Bulk` messages per Source.
    pub kind: Ospfv3RouteKind,
}

/// Tree-node identifier: router id (for Router-LSAs) or
/// (DR router id, DR interface id) (for Network-LSAs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum NodeId {
    Router(Ipv4Addr),
    Network(Ipv4Addr, u32),
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct HeapNode {
    cost: u32,
    node: NodeId,
}

impl Ord for HeapNode {
    fn cmp(&self, other: &Self) -> Ordering {
        other.cost.cmp(&self.cost) // min-heap
    }
}
impl PartialOrd for HeapNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A neighbor learned via Hello — used to resolve next-hops.
#[derive(Debug, Clone)]
pub struct SpfNeighborV3 {
    pub router_id: Ipv4Addr,
    pub link_local: Ipv6Addr,
    pub sw_if_index: u32,
}

pub fn calculate_spf_v3(
    self_router_id: Ipv4Addr,
    lsdb: &LsdbV3,
    neighbors: &[SpfNeighborV3],
) -> Vec<Ospfv3Route> {
    // Index Router-LSAs by router_id and Network-LSAs by (rtr, ifid).
    let mut router_lsas: HashMap<Ipv4Addr, RouterLsaV3> = HashMap::new();
    let mut network_lsas: HashMap<(Ipv4Addr, u32), NetworkLsaV3> = HashMap::new();
    let mut intra_prefix_lsas: Vec<&LsaEntryV3> = Vec::new();
    let mut inter_prefix_lsas: Vec<&LsaEntryV3> = Vec::new();
    let mut as_external_lsas: Vec<&LsaEntryV3> = Vec::new();

    for entry in lsdb.iter() {
        match entry.header.ls_type {
            LsaV3Type::Router => {
                if entry.raw.len() <= LSA_V3_HEADER_LEN {
                    continue;
                }
                if let Ok(rlsa) = RouterLsaV3::parse(&entry.raw[LSA_V3_HEADER_LEN..]) {
                    router_lsas.insert(entry.header.advertising_router, rlsa);
                }
            }
            LsaV3Type::Network => {
                if entry.raw.len() <= LSA_V3_HEADER_LEN {
                    continue;
                }
                if let Ok(nlsa) = NetworkLsaV3::parse(&entry.raw[LSA_V3_HEADER_LEN..]) {
                    let ifid = u32::from_be_bytes(entry.header.link_state_id.octets());
                    network_lsas.insert((entry.header.advertising_router, ifid), nlsa);
                }
            }
            LsaV3Type::IntraAreaPrefix => {
                intra_prefix_lsas.push(entry);
            }
            LsaV3Type::InterAreaPrefix => {
                inter_prefix_lsas.push(entry);
            }
            LsaV3Type::AsExternal => {
                as_external_lsas.push(entry);
            }
            LsaV3Type::Nssa => {
                // Type 7 LSAs (NSSA-External) share the body format with
                // Type 5 AS-External LSAs (RFC 5340 §4.4.3.7). Route
                // installation logic is identical; they differ in scope
                // (area-local vs AS-wide) and in ABR translation (Type 7
                // → Type 5 at the NSSA ABR). For pure consumption on a
                // non-ABR, we treat them the same way as Type 5 but
                // store them separately to preserve the distinction.
                as_external_lsas.push(entry);
            }
            _ => {}
        }
    }

    // Pass 1: Dijkstra with ECMP tracking. On strict improvement we
    // replace dist+next_hops. On equal cost we append alternate
    // next_hops (deduplicated) to support equal-cost multipath.
    let mut dist: HashMap<NodeId, u32> = HashMap::new();
    let mut next_hops: HashMap<NodeId, Vec<(Ipv6Addr, u32)>> = HashMap::new();
    let mut heap = BinaryHeap::new();

    let start = NodeId::Router(self_router_id);
    dist.insert(start, 0);
    heap.push(HeapNode {
        cost: 0,
        node: start,
    });

    while let Some(HeapNode { cost, node }) = heap.pop() {
        if dist.get(&node).copied() != Some(cost) {
            continue;
        }
        // Iterate neighbors of this node.
        let edges: Vec<(NodeId, u32)> = match node {
            NodeId::Router(rid) => {
                let Some(rlsa) = router_lsas.get(&rid) else { continue };
                let mut out = Vec::new();
                for link in &rlsa.links {
                    match link.link_type {
                        x if x == RouterLinkV3::TYPE_POINT_TO_POINT => {
                            out.push((NodeId::Router(link.neighbor_router_id), link.metric as u32));
                        }
                        x if x == RouterLinkV3::TYPE_TRANSIT_NETWORK => {
                            // Edge into a Network-LSA: cost = link.metric
                            out.push((
                                NodeId::Network(link.neighbor_router_id, link.neighbor_interface_id),
                                link.metric as u32,
                            ));
                        }
                        _ => {}
                    }
                }
                out
            }
            NodeId::Network(rtr, ifid) => {
                let Some(nlsa) = network_lsas.get(&(rtr, ifid)) else { continue };
                // Network nodes have cost-0 edges back to attached routers.
                nlsa.attached_routers
                    .iter()
                    .map(|r| (NodeId::Router(*r), 0u32))
                    .collect()
            }
        };

        for (next, edge_cost) in edges {
            let new_cost = cost.saturating_add(edge_cost);
            let existing_cost = dist.get(&next).copied();
            let strictly_better = existing_cost.map_or(true, |e| new_cost < e);
            let equal_cost = existing_cost.map_or(false, |e| new_cost == e);
            if !strictly_better && !equal_cost {
                continue;
            }

            // Compute candidate next-hops for this edge using the parent
            // (`node`) and the child (`next`). RFC 5340 §3.8.1.2:
            //  - Parent is root, child is directly-attached P2P neighbor:
            //    child's link-local from neighbors.
            //  - Parent is root, child is a local transit network:
            //    no next-hop (network is local).
            //  - Parent is a directly-attached transit network with no
            //    next-hop set, child is a router on that network: use
            //    that router's link-local from neighbors.
            //  - Otherwise: inherit parent's next-hops (potentially
            //    multiple for ECMP).
            let edge_next_hops: Vec<(Ipv6Addr, u32)> = if node == start {
                match next {
                    NodeId::Router(rid) => neighbors
                        .iter()
                        .filter(|n| n.router_id == rid)
                        .map(|n| (n.link_local, n.sw_if_index))
                        .collect(),
                    NodeId::Network(_, _) => Vec::new(),
                }
            } else if matches!(node, NodeId::Network(_, _))
                && next_hops.get(&node).map_or(true, |v| v.is_empty())
            {
                if let NodeId::Router(rid) = next {
                    neighbors
                        .iter()
                        .filter(|n| n.router_id == rid)
                        .map(|n| (n.link_local, n.sw_if_index))
                        .collect()
                } else {
                    Vec::new()
                }
            } else {
                next_hops.get(&node).cloned().unwrap_or_default()
            };

            if strictly_better {
                dist.insert(next, new_cost);
                next_hops.insert(next, edge_next_hops);
                heap.push(HeapNode {
                    cost: new_cost,
                    node: next,
                });
            } else if equal_cost {
                // Append alternate paths, deduplicating.
                let entry = next_hops.entry(next).or_default();
                for nh in edge_next_hops {
                    if !entry.contains(&nh) {
                        entry.push(nh);
                    }
                }
                // No need to push to heap again — dist unchanged.
            }
        }
    }

    // Pass 2: walk Intra-Area-Prefix-LSAs and attach prefixes.
    let mut routes = Vec::new();
    for entry in &intra_prefix_lsas {
        if entry.raw.len() <= LSA_V3_HEADER_LEN {
            continue;
        }
        let Ok(iap) = IntraAreaPrefixLsaV3::parse(&entry.raw[LSA_V3_HEADER_LEN..]) else {
            continue;
        };
        // The LSA references (referenced_ls_type, referenced_ls_id, referenced_advertising_router).
        let ref_node = match LsaV3Type::from_u16(iap.referenced_ls_type) {
            Some(LsaV3Type::Router) => NodeId::Router(iap.referenced_advertising_router),
            Some(LsaV3Type::Network) => {
                let ifid = u32::from_be_bytes(iap.referenced_link_state_id.octets());
                NodeId::Network(iap.referenced_advertising_router, ifid)
            }
            _ => continue,
        };
        let Some(&node_cost) = dist.get(&ref_node) else { continue };
        let Some(nhs) = next_hops.get(&ref_node).cloned() else { continue };
        if nhs.is_empty() {
            continue;
        }
        for prefix in &iap.prefixes {
            // Skip our own attached prefixes (referenced node is us).
            if ref_node == start {
                continue;
            }
            routes.push(Ospfv3Route {
                prefix: prefix.address,
                prefix_len: prefix.prefix_length,
                next_hops: nhs.clone(),
                cost: node_cost.saturating_add(prefix.prefix_or_metric as u32),
                kind: Ospfv3RouteKind::Intra,
            });
        }
    }

    // Pass 3: walk Inter-Area-Prefix-LSAs. Each Type 3 LSA is
    // originated by an ABR advertising a prefix from another area.
    // The route's cost is (cost_to_ABR) + (LSA.metric).
    for entry in &inter_prefix_lsas {
        if entry.raw.len() <= LSA_V3_HEADER_LEN {
            continue;
        }
        let Ok(iap) = InterAreaPrefixLsaV3::parse(&entry.raw[LSA_V3_HEADER_LEN..]) else {
            continue;
        };
        let abr = NodeId::Router(entry.header.advertising_router);
        // Don't install routes "to ourselves".
        if abr == start {
            continue;
        }
        let Some(&abr_cost) = dist.get(&abr) else { continue };
        let Some(nhs) = next_hops.get(&abr).cloned() else { continue };
        if nhs.is_empty() {
            continue;
        }
        routes.push(Ospfv3Route {
            prefix: iap.prefix.address,
            prefix_len: iap.prefix.prefix_length,
            next_hops: nhs,
            cost: abr_cost.saturating_add(iap.metric),
            kind: Ospfv3RouteKind::Inter,
        });
    }

    // Build a longest-prefix-match table of reachable internal
    // destinations for recursive forwarding-address resolution (RFC
    // 5340 §3.8.1.5 / RFC 2328 §16.4). Sort by prefix length
    // descending so the first match wins.
    let mut reachable: Vec<(Ipv6Addr, u8, u32, Vec<(Ipv6Addr, u32)>)> = routes
        .iter()
        .map(|r| (r.prefix, r.prefix_len, r.cost, r.next_hops.clone()))
        .collect();
    reachable.sort_by(|a, b| b.1.cmp(&a.1));

    // Pass 4: walk AS-External-LSAs. Each Type 5 LSA is originated by
    // an ASBR. For E1 metric, cost = cost_to_ASBR + LSA.metric. For E2,
    // cost = LSA.metric alone (path length to the ASBR is ignored for
    // best-path selection; RFC 5340 §3.8.1.5). The forwarding_address
    // field, when set and non-zero, replaces the ASBR as the path's
    // "intermediate destination" — cost and next-hops come from
    // resolving the forwarding address via LPM against the reachable
    // table. If the fa is unreachable, the external route is dropped
    // (we cannot know how to forward to it).
    for entry in &as_external_lsas {
        if entry.raw.len() <= LSA_V3_HEADER_LEN {
            continue;
        }
        let Ok(ext) = AsExternalLsaV3::parse(&entry.raw[LSA_V3_HEADER_LEN..]) else {
            continue;
        };
        let asbr = NodeId::Router(entry.header.advertising_router);
        if asbr == start {
            continue; // don't reinstall our own originated external routes
        }
        let Some(&asbr_cost) = dist.get(&asbr) else { continue };
        let Some(asbr_nhs) = next_hops.get(&asbr).cloned() else { continue };
        if asbr_nhs.is_empty() {
            continue;
        }

        // Determine the "intermediate cost" and next-hops: either the
        // ASBR's (if no forwarding address) or the forwarding address's
        // resolved route (if fa is set and reachable).
        let (intermediate_cost, intermediate_nhs) = match ext.forwarding_address {
            Some(fa) if !fa.is_unspecified() => {
                let Some((_, _, fa_cost, fa_nhs)) = reachable
                    .iter()
                    .find(|(p, len, _, _)| prefix_matches_v3(fa, *p, *len))
                else {
                    // Unreachable forwarding address → drop this route.
                    tracing::debug!(
                        fa = %fa,
                        asbr = %entry.header.advertising_router,
                        "OSPFv3 external dropped: forwarding address unreachable"
                    );
                    continue;
                };
                (*fa_cost, fa_nhs.clone())
            }
            _ => (asbr_cost, asbr_nhs),
        };

        // Compute final cost based on metric type.
        let cost = if ext.metric_type_2 {
            // E2: external metric only (intermediate path cost ignored
            // for best-path selection).
            ext.metric
        } else {
            // E1: intermediate path cost + external metric.
            intermediate_cost.saturating_add(ext.metric)
        };

        routes.push(Ospfv3Route {
            prefix: ext.prefix.address,
            prefix_len: ext.prefix.prefix_length,
            next_hops: intermediate_nhs,
            cost,
            kind: if ext.metric_type_2 {
                Ospfv3RouteKind::External2
            } else {
                Ospfv3RouteKind::External1
            },
        });
    }

    routes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsdb_v3::LsaEntryV3;
    use crate::packet_v3::lsa::{LsaV3Header, INITIAL_SEQUENCE_NUMBER};

    fn router_lsa_entry(adv: Ipv4Addr, links: Vec<RouterLinkV3>) -> LsaEntryV3 {
        let lsa = RouterLsaV3 {
            flags: 0,
            options: 0,
            links,
        };
        let mut body = Vec::new();
        lsa.encode(&mut body);
        let header = LsaV3Header {
            ls_age: 1,
            ls_type: LsaV3Type::Router,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: adv,
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: (LSA_V3_HEADER_LEN + body.len()) as u16,
        };
        let mut raw = Vec::new();
        header.encode(&mut raw);
        raw.extend_from_slice(&body);
        LsaEntryV3 {
            header,
            raw,
            area: Some(Ipv4Addr::UNSPECIFIED),
        }
    }

    #[test]
    fn test_spf_no_neighbors_no_routes() {
        let mut lsdb = LsdbV3::new();
        lsdb.insert(router_lsa_entry(Ipv4Addr::new(1, 1, 1, 1), vec![]));
        let routes = calculate_spf_v3(Ipv4Addr::new(1, 1, 1, 1), &lsdb, &[]);
        assert!(routes.is_empty());
    }

    #[test]
    fn test_spf_p2p_reachable_router_no_prefix() {
        // 1.1.1.1 -> p2p link to 2.2.2.2, no Intra-Area-Prefix-LSA.
        // Both routers reachable but no prefixes to install.
        let mut lsdb = LsdbV3::new();
        lsdb.insert(router_lsa_entry(
            Ipv4Addr::new(1, 1, 1, 1),
            vec![RouterLinkV3 {
                link_type: RouterLinkV3::TYPE_POINT_TO_POINT,
                metric: 10,
                interface_id: 1,
                neighbor_interface_id: 1,
                neighbor_router_id: Ipv4Addr::new(2, 2, 2, 2),
            }],
        ));
        lsdb.insert(router_lsa_entry(Ipv4Addr::new(2, 2, 2, 2), vec![]));
        let nbrs = vec![SpfNeighborV3 {
            router_id: Ipv4Addr::new(2, 2, 2, 2),
            link_local: "fe80::2".parse().unwrap(),
            sw_if_index: 1,
        }];
        let routes = calculate_spf_v3(Ipv4Addr::new(1, 1, 1, 1), &lsdb, &nbrs);
        assert!(routes.is_empty());
    }

    fn lsa_entry(ls_type: LsaV3Type, ls_id: Ipv4Addr, adv: Ipv4Addr, body: Vec<u8>) -> LsaEntryV3 {
        let header = LsaV3Header {
            ls_age: 1,
            ls_type,
            link_state_id: ls_id,
            advertising_router: adv,
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: (LSA_V3_HEADER_LEN + body.len()) as u16,
        };
        let mut raw = Vec::new();
        header.encode(&mut raw);
        raw.extend_from_slice(&body);
        LsaEntryV3 {
            header,
            raw,
            area: Some(Ipv4Addr::UNSPECIFIED),
        }
    }

    fn p2p_topology(self_rid: Ipv4Addr, peer_rid: Ipv4Addr) -> (LsdbV3, Vec<SpfNeighborV3>) {
        let mut lsdb = LsdbV3::new();
        lsdb.insert(router_lsa_entry(
            self_rid,
            vec![RouterLinkV3 {
                link_type: RouterLinkV3::TYPE_POINT_TO_POINT,
                metric: 10,
                interface_id: 1,
                neighbor_interface_id: 1,
                neighbor_router_id: peer_rid,
            }],
        ));
        lsdb.insert(router_lsa_entry(peer_rid, vec![]));
        let nbrs = vec![SpfNeighborV3 {
            router_id: peer_rid,
            link_local: "fe80::2".parse().unwrap(),
            sw_if_index: 1,
        }];
        (lsdb, nbrs)
    }

    #[test]
    fn test_spf_inter_area_prefix() {
        // self -> ABR(2.2.2.2). ABR advertises an Inter-Area-Prefix-LSA
        // for 2001:db8:200::/56 with metric 5. Expected route cost:
        // 10 (to ABR) + 5 (LSA) = 15.
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let abr = Ipv4Addr::new(2, 2, 2, 2);
        let (mut lsdb, nbrs) = p2p_topology(self_rid, abr);

        let iap = InterAreaPrefixLsaV3 {
            metric: 5,
            prefix: crate::packet_v3::prefix::Ospfv3Prefix {
                prefix_length: 56,
                prefix_options: 0,
                prefix_or_metric: 0,
                address: "2001:db8:200::".parse().unwrap(),
            },
        };
        let mut body = Vec::new();
        iap.encode(&mut body);
        lsdb.insert(lsa_entry(
            LsaV3Type::InterAreaPrefix,
            Ipv4Addr::new(0, 0, 0, 1),
            abr,
            body,
        ));

        let routes = calculate_spf_v3(self_rid, &lsdb, &nbrs);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "2001:db8:200::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(routes[0].prefix_len, 56);
        assert_eq!(routes[0].cost, 15);
        assert_eq!(routes[0].next_hops.len(), 1);
        assert_eq!(
            routes[0].next_hops[0].0,
            "fe80::2".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn test_spf_as_external_e1() {
        // E1 metric: cost = path_to_asbr + external_metric = 10 + 50 = 60
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let asbr = Ipv4Addr::new(2, 2, 2, 2);
        let (mut lsdb, nbrs) = p2p_topology(self_rid, asbr);

        let ext = AsExternalLsaV3 {
            metric_type_2: false,
            forwarding_present: false,
            tag_present: false,
            metric: 50,
            prefix: crate::packet_v3::prefix::Ospfv3Prefix {
                prefix_length: 32,
                prefix_options: 0,
                prefix_or_metric: 0,
                address: "2001:db8:aaaa::".parse().unwrap(),
            },
            referenced_ls_type: 0,
            forwarding_address: None,
            external_route_tag: None,
            referenced_link_state_id: None,
        };
        let mut body = Vec::new();
        ext.encode(&mut body);
        lsdb.insert(lsa_entry(
            LsaV3Type::AsExternal,
            Ipv4Addr::new(0, 0, 0, 1),
            asbr,
            body,
        ));

        let routes = calculate_spf_v3(self_rid, &lsdb, &nbrs);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].cost, 60);
    }

    #[test]
    fn test_spf_ecmp_two_equal_p2p_paths() {
        // Topology: self has TWO p2p links to the same peer 2.2.2.2,
        // both with metric 10. Peer originates an Intra-Area-Prefix-
        // LSA with a prefix attached to its Router-LSA. Expect one
        // route with TWO next_hops (one per link).
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let peer = Ipv4Addr::new(2, 2, 2, 2);
        let mut lsdb = LsdbV3::new();
        lsdb.insert(router_lsa_entry(
            self_rid,
            vec![
                RouterLinkV3 {
                    link_type: RouterLinkV3::TYPE_POINT_TO_POINT,
                    metric: 10,
                    interface_id: 1,
                    neighbor_interface_id: 1,
                    neighbor_router_id: peer,
                },
                RouterLinkV3 {
                    link_type: RouterLinkV3::TYPE_POINT_TO_POINT,
                    metric: 10,
                    interface_id: 2,
                    neighbor_interface_id: 2,
                    neighbor_router_id: peer,
                },
            ],
        ));
        lsdb.insert(router_lsa_entry(peer, vec![]));

        // Intra-Area-Prefix-LSA from peer referencing its own Router-LSA.
        let iap_body = {
            let lsa = IntraAreaPrefixLsaV3 {
                referenced_ls_type: LsaV3Type::Router as u16,
                referenced_link_state_id: Ipv4Addr::UNSPECIFIED,
                referenced_advertising_router: peer,
                prefixes: vec![crate::packet_v3::prefix::Ospfv3Prefix {
                    prefix_length: 128,
                    prefix_options: 0,
                    prefix_or_metric: 0,
                    address: "2001:db8:ec::1".parse().unwrap(),
                }],
            };
            let mut b = Vec::new();
            lsa.encode(&mut b);
            b
        };
        lsdb.insert(lsa_entry(
            LsaV3Type::IntraAreaPrefix,
            Ipv4Addr::UNSPECIFIED,
            peer,
            iap_body,
        ));

        let nbrs = vec![
            SpfNeighborV3 {
                router_id: peer,
                link_local: "fe80::2".parse().unwrap(),
                sw_if_index: 1,
            },
            SpfNeighborV3 {
                router_id: peer,
                link_local: "fe80::3".parse().unwrap(),
                sw_if_index: 2,
            },
        ];

        let routes = calculate_spf_v3(self_rid, &lsdb, &nbrs);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hops.len(), 2, "expected ECMP next-hops");
        let hops: std::collections::HashSet<_> =
            routes[0].next_hops.iter().map(|(a, _)| *a).collect();
        assert!(hops.contains(&"fe80::2".parse::<Ipv6Addr>().unwrap()));
        assert!(hops.contains(&"fe80::3".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_spf_as_external_forwarding_address_resolved() {
        // Topology: self -> ASBR(2.2.2.2) at cost 10. ASBR advertises
        // an Intra-Area-Prefix-LSA for 2001:db8:fa::/64 attached to
        // its Router-LSA. ASBR also originates a Type 5 external for
        // 2001:db8:dead::/64 with forwarding_address 2001:db8:fa::1,
        // metric 50 E1.
        //
        // Expected: fa resolves via the intra-area route 2001:db8:fa::/64
        // (cost 10), so external cost = 10 + 50 = 60 (E1), next-hops
        // inherited from the intra-area route.
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let asbr = Ipv4Addr::new(2, 2, 2, 2);
        let (mut lsdb, nbrs) = p2p_topology(self_rid, asbr);

        // Intra-Area-Prefix-LSA from ASBR carrying 2001:db8:fa::/64.
        let iap_body = {
            let lsa = IntraAreaPrefixLsaV3 {
                referenced_ls_type: LsaV3Type::Router as u16,
                referenced_link_state_id: Ipv4Addr::UNSPECIFIED,
                referenced_advertising_router: asbr,
                prefixes: vec![crate::packet_v3::prefix::Ospfv3Prefix {
                    prefix_length: 64,
                    prefix_options: 0,
                    prefix_or_metric: 0,
                    address: "2001:db8:fa::".parse().unwrap(),
                }],
            };
            let mut b = Vec::new();
            lsa.encode(&mut b);
            b
        };
        lsdb.insert(lsa_entry(
            LsaV3Type::IntraAreaPrefix,
            Ipv4Addr::UNSPECIFIED,
            asbr,
            iap_body,
        ));

        // Type 5 external for 2001:db8:dead::/64 via fa 2001:db8:fa::1
        let ext = AsExternalLsaV3 {
            metric_type_2: false,
            forwarding_present: true,
            tag_present: false,
            metric: 50,
            prefix: crate::packet_v3::prefix::Ospfv3Prefix {
                prefix_length: 64,
                prefix_options: 0,
                prefix_or_metric: 0,
                address: "2001:db8:dead::".parse().unwrap(),
            },
            referenced_ls_type: 0,
            forwarding_address: Some("2001:db8:fa::1".parse().unwrap()),
            external_route_tag: None,
            referenced_link_state_id: None,
        };
        let mut ext_body = Vec::new();
        ext.encode(&mut ext_body);
        lsdb.insert(lsa_entry(
            LsaV3Type::AsExternal,
            Ipv4Addr::new(0, 0, 0, 1),
            asbr,
            ext_body,
        ));

        let routes = calculate_spf_v3(self_rid, &lsdb, &nbrs);
        // Expect two routes: the intra-area 2001:db8:fa::/64 and the
        // external 2001:db8:dead::/64.
        let external = routes
            .iter()
            .find(|r| r.prefix == "2001:db8:dead::".parse::<Ipv6Addr>().unwrap())
            .expect("external route missing");
        // fa intra-area cost is 10 (to ASBR); + ext.metric 50 = 60
        assert_eq!(external.cost, 60);
        assert_eq!(external.next_hops.len(), 1);
        assert_eq!(
            external.next_hops[0].0,
            "fe80::2".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn test_spf_as_external_forwarding_address_unreachable() {
        // Same topology, but the fa is unreachable. External route
        // should be dropped, not installed.
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let asbr = Ipv4Addr::new(2, 2, 2, 2);
        let (mut lsdb, nbrs) = p2p_topology(self_rid, asbr);

        let ext = AsExternalLsaV3 {
            metric_type_2: false,
            forwarding_present: true,
            tag_present: false,
            metric: 50,
            prefix: crate::packet_v3::prefix::Ospfv3Prefix {
                prefix_length: 64,
                prefix_options: 0,
                prefix_or_metric: 0,
                address: "2001:db8:dead::".parse().unwrap(),
            },
            referenced_ls_type: 0,
            // Unreachable — no intra-area route covers this fa.
            forwarding_address: Some("2001:db8:nowhere::1".parse().ok().unwrap_or_else(
                || "2001:db8:7777::1".parse::<Ipv6Addr>().unwrap(),
            )),
            external_route_tag: None,
            referenced_link_state_id: None,
        };
        let mut ext_body = Vec::new();
        ext.encode(&mut ext_body);
        lsdb.insert(lsa_entry(
            LsaV3Type::AsExternal,
            Ipv4Addr::new(0, 0, 0, 1),
            asbr,
            ext_body,
        ));

        let routes = calculate_spf_v3(self_rid, &lsdb, &nbrs);
        // External route should NOT be installed.
        assert!(
            routes
                .iter()
                .all(|r| r.prefix != "2001:db8:dead::".parse::<Ipv6Addr>().unwrap()),
            "external with unreachable forwarding address should be dropped"
        );
    }

    #[test]
    fn test_prefix_matches() {
        let in_net: Ipv6Addr = "2001:db8:fa::1".parse().unwrap();
        let net: Ipv6Addr = "2001:db8:fa::".parse().unwrap();
        assert!(prefix_matches_v3(in_net, net, 64));
        assert!(prefix_matches_v3(in_net, net, 48));
        assert!(!prefix_matches_v3(in_net, "2001:db8:fb::".parse().unwrap(), 64));
        assert!(prefix_matches_v3(in_net, Ipv6Addr::UNSPECIFIED, 0));
        let exact: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(prefix_matches_v3(exact, exact, 128));
    }

    #[test]
    fn test_spf_nssa_type7_routes() {
        // Type 7 NSSA-LSA should produce routes just like Type 5 in
        // SPF pass 4 (non-ABR consumption).
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let asbr = Ipv4Addr::new(2, 2, 2, 2);
        let (mut lsdb, nbrs) = p2p_topology(self_rid, asbr);

        let nssa = AsExternalLsaV3 {
            metric_type_2: false,
            forwarding_present: false,
            tag_present: false,
            metric: 30,
            prefix: crate::packet_v3::prefix::Ospfv3Prefix {
                prefix_length: 64,
                prefix_options: 0,
                prefix_or_metric: 0,
                address: "2001:db8:cccc::".parse().unwrap(),
            },
            referenced_ls_type: 0,
            forwarding_address: None,
            external_route_tag: None,
            referenced_link_state_id: None,
        };
        let mut body = Vec::new();
        nssa.encode(&mut body);
        lsdb.insert(lsa_entry(
            LsaV3Type::Nssa,
            Ipv4Addr::new(0, 0, 0, 1),
            asbr,
            body,
        ));

        let routes = calculate_spf_v3(self_rid, &lsdb, &nbrs);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "2001:db8:cccc::".parse::<Ipv6Addr>().unwrap());
        // E1 metric: 10 (path to ASBR) + 30 (LSA) = 40
        assert_eq!(routes[0].cost, 40);
    }

    #[test]
    fn test_spf_as_external_e2() {
        // E2 metric: cost = external_metric only, ignoring path cost.
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let asbr = Ipv4Addr::new(2, 2, 2, 2);
        let (mut lsdb, nbrs) = p2p_topology(self_rid, asbr);

        let ext = AsExternalLsaV3 {
            metric_type_2: true,
            forwarding_present: false,
            tag_present: false,
            metric: 50,
            prefix: crate::packet_v3::prefix::Ospfv3Prefix {
                prefix_length: 32,
                prefix_options: 0,
                prefix_or_metric: 0,
                address: "2001:db8:bbbb::".parse().unwrap(),
            },
            referenced_ls_type: 0,
            forwarding_address: None,
            external_route_tag: None,
            referenced_link_state_id: None,
        };
        let mut body = Vec::new();
        ext.encode(&mut body);
        lsdb.insert(lsa_entry(
            LsaV3Type::AsExternal,
            Ipv4Addr::new(0, 0, 0, 1),
            asbr,
            body,
        ));

        let routes = calculate_spf_v3(self_rid, &lsdb, &nbrs);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].cost, 50); // not 60 — E2 ignores path cost
    }
}
