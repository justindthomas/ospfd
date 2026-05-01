//! OSPFv3 Conformance Tests.
//!
//! Structured in the same style as `conformance.rs` but for OSPFv3
//! (RFC 5340). These are integration-level tests that exercise the
//! public surface of InstanceV3, packet encoders, and spf_v3 together,
//! rather than re-testing what the per-module unit tests already cover.
//!
//! Coverage bias: regression cases for the bugs we hit bringing v3 up
//! against live FRR (per-area Router-LSA scoping, DD area-filtered
//! summaries, flood_lsa area scoping, DD finalization, ABR/ASBR
//! origination, peer re-init detection).

use std::net::{Ipv4Addr, Ipv6Addr};

use ospfd::instance_v3::{InstanceV3, InterfaceStateV3, NeighborStateV3, NetworkTypeV3};
use ospfd::io_v3::IoInterfaceV3;
use ospfd::lsdb_v3::LsaKeyV3;
use ospfd::packet_v3::header::{Ospfv3Header, Ospfv3PacketType, OSPFV3_HEADER_LEN};
use ospfd::packet_v3::hello::{HelloV3Packet, Options};
use ospfd::packet_v3::lsa::{
    AsExternalLsaV3, InterAreaPrefixLsaV3, IntraAreaPrefixLsaV3, LinkLsaV3, LsaV3Header,
    LsaV3Type, NetworkLsaV3, RouterLinkV3, RouterLsaV3, INITIAL_SEQUENCE_NUMBER,
    LSA_V3_HEADER_LEN,
};
use ospfd::packet_v3::prefix::Ospfv3Prefix;
use ospfd::io_v3::RxPacketV3;

// ============================================================================
// Helpers
// ============================================================================

fn io(name: &str, sw_if_index: u32, ll: &str) -> IoInterfaceV3 {
    IoInterfaceV3 {
        name: name.to_string(),
        sw_if_index,
        kernel_ifindex: sw_if_index,
        link_local: ll.parse().unwrap(),
        mac_address: [0; 6],
    }
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn make_hello_rx(
    src_rid: Ipv4Addr,
    area: Ipv4Addr,
    interface_id: u32,
    dr: Ipv4Addr,
    bdr: Ipv4Addr,
    sw_if_index: u32,
    src_ll: Ipv6Addr,
    neighbors: Vec<Ipv4Addr>,
) -> RxPacketV3 {
    let hello = HelloV3Packet {
        interface_id,
        router_priority: 1,
        options: Options::standard(),
        hello_interval: 10,
        router_dead_interval: 40,
        designated_router_id: dr,
        backup_designated_router_id: bdr,
        neighbors,
    };
    let mut body = Vec::new();
    hello.encode(&mut body);
    let mut hdr = Ospfv3Header::new(Ospfv3PacketType::Hello, src_rid, area);
    hdr.packet_length = (OSPFV3_HEADER_LEN + body.len()) as u16;
    let mut data = Vec::with_capacity(hdr.packet_length as usize);
    hdr.encode(&mut data);
    data.extend_from_slice(&body);
    RxPacketV3 {
        sw_if_index,
        src_addr: src_ll,
        dst_addr: Ipv6Addr::UNSPECIFIED,
        data,
    }
}

// ============================================================================
// Group 1: Packet Format Roundtrips (RFC 5340 §A)
// ============================================================================

#[test]
fn fmt_v3_1_router_lsa_roundtrip() {
    let lsa = RouterLsaV3 {
        flags: RouterLsaV3::FLAG_B | RouterLsaV3::FLAG_E,
        options: Options::standard().0,
        links: vec![
            RouterLinkV3 {
                link_type: RouterLinkV3::TYPE_POINT_TO_POINT,
                metric: 10,
                interface_id: 74,
                neighbor_interface_id: 3,
                neighbor_router_id: v4(2, 2, 2, 2),
            },
            RouterLinkV3 {
                link_type: RouterLinkV3::TYPE_TRANSIT_NETWORK,
                metric: 5,
                interface_id: 75,
                neighbor_interface_id: 75,
                neighbor_router_id: v4(1, 1, 1, 1),
            },
        ],
    };
    let mut buf = Vec::new();
    lsa.encode(&mut buf);
    let parsed = RouterLsaV3::parse(&buf).unwrap();
    assert_eq!(parsed.flags, RouterLsaV3::FLAG_B | RouterLsaV3::FLAG_E);
    assert_eq!(parsed.links.len(), 2);
    assert_eq!(parsed.links[0].metric, 10);
    assert_eq!(parsed.links[1].link_type, RouterLinkV3::TYPE_TRANSIT_NETWORK);
    assert_eq!(parsed.links[1].neighbor_router_id, v4(1, 1, 1, 1));
}

#[test]
fn fmt_v3_2_network_lsa_roundtrip() {
    let lsa = NetworkLsaV3 {
        options: Options::standard().0,
        attached_routers: vec![v4(1, 1, 1, 1), v4(2, 2, 2, 2), v4(3, 3, 3, 3)],
    };
    let mut buf = Vec::new();
    lsa.encode(&mut buf);
    let parsed = NetworkLsaV3::parse(&buf).unwrap();
    assert_eq!(parsed.attached_routers.len(), 3);
    assert_eq!(parsed.attached_routers[2], v4(3, 3, 3, 3));
}

#[test]
fn fmt_v3_3_intra_area_prefix_lsa_roundtrip() {
    let lsa = IntraAreaPrefixLsaV3 {
        referenced_ls_type: LsaV3Type::Router as u16,
        referenced_link_state_id: Ipv4Addr::UNSPECIFIED,
        referenced_advertising_router: v4(1, 1, 1, 1),
        prefixes: vec![
            Ospfv3Prefix {
                prefix_length: 64,
                prefix_options: 0,
                prefix_or_metric: 0,
                address: v6("2001:db8:30::"),
            },
            Ospfv3Prefix {
                prefix_length: 128,
                prefix_options: 0,
                prefix_or_metric: 10,
                address: v6("2001:db8:99::1"),
            },
        ],
    };
    let mut buf = Vec::new();
    lsa.encode(&mut buf);
    let parsed = IntraAreaPrefixLsaV3::parse(&buf).unwrap();
    assert_eq!(parsed.prefixes.len(), 2);
    assert_eq!(parsed.prefixes[0].prefix_length, 64);
    assert_eq!(parsed.prefixes[1].address, v6("2001:db8:99::1"));
    assert_eq!(parsed.prefixes[1].prefix_or_metric, 10);
}

#[test]
fn fmt_v3_4_inter_area_prefix_lsa_roundtrip() {
    let lsa = InterAreaPrefixLsaV3 {
        metric: 25,
        prefix: Ospfv3Prefix {
            prefix_length: 64,
            prefix_options: 0,
            prefix_or_metric: 0,
            address: v6("2001:db8:31::"),
        },
    };
    let mut buf = Vec::new();
    lsa.encode(&mut buf);
    let parsed = InterAreaPrefixLsaV3::parse(&buf).unwrap();
    assert_eq!(parsed.metric, 25);
    assert_eq!(parsed.prefix.prefix_length, 64);
    assert_eq!(parsed.prefix.address, v6("2001:db8:31::"));
}

#[test]
fn fmt_v3_5_as_external_lsa_roundtrip_type1_metric() {
    let lsa = AsExternalLsaV3 {
        metric_type_2: false,
        forwarding_present: false,
        tag_present: true,
        metric: 100,
        prefix: Ospfv3Prefix {
            prefix_length: 96,
            prefix_options: 0,
            prefix_or_metric: 0,
            address: v6("2001:db8:ff::"),
        },
        referenced_ls_type: 0,
        forwarding_address: None,
        external_route_tag: Some(0xdeadbeef),
        referenced_link_state_id: None,
    };
    let mut buf = Vec::new();
    lsa.encode(&mut buf);
    let parsed = AsExternalLsaV3::parse(&buf).unwrap();
    assert!(!parsed.metric_type_2);
    assert!(parsed.tag_present);
    assert_eq!(parsed.metric, 100);
    assert_eq!(parsed.external_route_tag, Some(0xdeadbeef));
}

#[test]
fn fmt_v3_6_as_external_lsa_roundtrip_with_forwarding_address() {
    let lsa = AsExternalLsaV3 {
        metric_type_2: true,
        forwarding_present: true,
        tag_present: false,
        metric: 200,
        prefix: Ospfv3Prefix {
            prefix_length: 64,
            prefix_options: 0,
            prefix_or_metric: 0,
            address: v6("2001:db8:ee::"),
        },
        referenced_ls_type: 0,
        forwarding_address: Some(v6("2001:db8:30::42")),
        external_route_tag: None,
        referenced_link_state_id: None,
    };
    let mut buf = Vec::new();
    lsa.encode(&mut buf);
    let parsed = AsExternalLsaV3::parse(&buf).unwrap();
    assert!(parsed.metric_type_2);
    assert!(parsed.forwarding_present);
    assert_eq!(parsed.forwarding_address, Some(v6("2001:db8:30::42")));
}

#[test]
fn fmt_v3_7_link_lsa_roundtrip() {
    let lsa = LinkLsaV3 {
        router_priority: 1,
        options: Options::standard().0,
        link_local_address: v6("fe80::1"),
        prefixes: vec![Ospfv3Prefix {
            prefix_length: 64,
            prefix_options: 0,
            prefix_or_metric: 0,
            address: v6("2001:db8:30::"),
        }],
    };
    let mut buf = Vec::new();
    lsa.encode(&mut buf);
    let parsed = LinkLsaV3::parse(&buf).unwrap();
    assert_eq!(parsed.router_priority, 1);
    assert_eq!(parsed.link_local_address, v6("fe80::1"));
    assert_eq!(parsed.prefixes.len(), 1);
}

// ============================================================================
// Group 2: Neighbor/Interface State Machine (RFC 5340 §4, §7)
// ============================================================================

#[test]
fn nsm_v3_1_hello_creates_neighbor_and_sets_twoway() {
    // Purpose: a Hello that lists our router-id in its neighbor list
    // must drive the peer to 2-Way from Init.
    let self_rid = v4(1, 1, 1, 1);
    let mut inst = InstanceV3::new(self_rid);
    inst.add_interface(
        io("eth0", 1, "fe80::1"),
        Ipv4Addr::UNSPECIFIED,
        NetworkTypeV3::Broadcast,
        10,
        40,
        1,
        Vec::new(),
    );

    let peer_rid = v4(2, 2, 2, 2);
    let peer_ll = v6("fe80::2");
    // Peer lists us in its neighbor list → we should see 2-Way.
    let rx = make_hello_rx(
        peer_rid,
        Ipv4Addr::UNSPECIFIED,
        5,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        1,
        peer_ll,
        vec![self_rid],
    );
    inst.handle_rx(rx).unwrap();

    let iface = inst.interfaces.get(&1).unwrap();
    let nb = iface.neighbors.get(&peer_rid).unwrap();
    assert!(nb.state >= NeighborStateV3::TwoWay);
}

#[test]
fn ism_v3_1_broadcast_higher_rid_wins_dr() {
    // Purpose: with two routers on a broadcast link at equal priority,
    // the higher router-id wins DR. RFC 5340 §4.3.
    let self_rid = v4(1, 1, 1, 1);
    let mut inst = InstanceV3::new(self_rid);
    inst.add_interface(
        io("eth0", 1, "fe80::1"),
        Ipv4Addr::UNSPECIFIED,
        NetworkTypeV3::Broadcast,
        10,
        40,
        1,
        Vec::new(),
    );
    let peer_rid = v4(2, 2, 2, 2);
    let rx = make_hello_rx(
        peer_rid,
        Ipv4Addr::UNSPECIFIED,
        5,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        1,
        v6("fe80::2"),
        vec![self_rid],
    );
    inst.handle_rx(rx).unwrap();

    let iface = inst.interfaces.get(&1).unwrap();
    // Higher RID wins DR, lower RID becomes BDR. On a 2-router
    // segment that means we (lower RID) end up in Backup state.
    assert_eq!(iface.dr, peer_rid, "higher RID should win DR");
    assert_eq!(
        iface.bdr,
        self_rid,
        "lower RID should become BDR on 2-router segment"
    );
    assert_eq!(iface.state, InterfaceStateV3::Backup);
}

#[test]
fn ism_v3_2_point_to_point_skips_dr_election() {
    // Purpose: P2P interfaces don't run DR election — state jumps
    // straight to PointToPoint.
    let mut inst = InstanceV3::new(v4(1, 1, 1, 1));
    inst.add_interface(
        io("eth0", 1, "fe80::1"),
        Ipv4Addr::UNSPECIFIED,
        NetworkTypeV3::PointToPoint,
        10,
        40,
        1,
        Vec::new(),
    );
    let iface = inst.interfaces.get(&1).unwrap();
    assert_eq!(iface.state, InterfaceStateV3::PointToPoint);
    assert_eq!(iface.dr, Ipv4Addr::UNSPECIFIED);
}

// ============================================================================
// Group 3: ABR / ASBR Behavior (RFC 5340 §3.8, §4.4.3.4, §4.4.3.5)
// ============================================================================

#[test]
fn abr_v3_1_b_flag_set_when_two_areas() {
    // Purpose: a router with interfaces in the backbone and at least
    // one other area is an ABR and must set the B flag in its
    // Router-LSA.
    let self_rid = v4(1, 1, 1, 1);
    let mut inst = InstanceV3::new(self_rid);
    inst.add_interface(
        io("wan", 1, "fe80::1"),
        Ipv4Addr::UNSPECIFIED,
        NetworkTypeV3::PointToPoint,
        10,
        40,
        1,
        Vec::new(),
    );
    inst.add_interface(
        io("lan", 2, "fe80::2"),
        v4(0, 0, 0, 1),
        NetworkTypeV3::PointToPoint,
        10,
        40,
        1,
        Vec::new(),
    );
    assert!(inst.is_abr());
    inst.originate_router_lsa();

    // Each area should now have a Router-LSA with B flag set.
    for area in [Ipv4Addr::UNSPECIFIED, v4(0, 0, 0, 1)] {
        let key = LsaKeyV3 {
            area: Some(area),
            ls_type: LsaV3Type::Router,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: self_rid,
        };
        let entry = inst.lsdb.get(&key).expect("per-area Router-LSA");
        // Router-LSA body starts at LSA_V3_HEADER_LEN; byte 0 is flags.
        let flags = entry.raw[LSA_V3_HEADER_LEN];
        assert!(
            flags & RouterLsaV3::FLAG_B != 0,
            "B flag must be set in area {}",
            area
        );
    }
}

#[test]
fn abr_v3_2_per_area_router_lsa_scopes_links() {
    // Purpose: regression for the live-wire bug where our Router-LSA
    // bundled links from all interfaces into one area, causing peers
    // to reject it. Each per-area Router-LSA must list ONLY the
    // interfaces in that area.
    let self_rid = v4(1, 1, 1, 1);
    let mut inst = InstanceV3::new(self_rid);
    inst.add_interface(
        io("wan", 1, "fe80::1"),
        Ipv4Addr::UNSPECIFIED,
        NetworkTypeV3::PointToPoint,
        10,
        40,
        1,
        Vec::new(),
    );
    inst.add_interface(
        io("lan", 2, "fe80::2"),
        v4(0, 0, 0, 1),
        NetworkTypeV3::PointToPoint,
        10,
        40,
        1,
        Vec::new(),
    );

    // Inject a Full peer on each interface so links get emitted.
    for (sw, peer_rid, peer_ll, iface_id) in [
        (1u32, v4(10, 0, 0, 1), v6("fe80::10"), 77u32),
        (2u32, v4(10, 0, 0, 2), v6("fe80::11"), 78u32),
    ] {
        let iface = inst.interfaces.get_mut(&sw).unwrap();
        let nb = ospfd::instance_v3::NeighborV3 {
            router_id: peer_rid,
            interface_id: iface_id,
            link_local: peer_ll,
            priority: 1,
            dr: Ipv4Addr::UNSPECIFIED,
            bdr: Ipv4Addr::UNSPECIFIED,
            state: NeighborStateV3::Full,
            last_hello: std::time::Instant::now(),
            dd_master: true,
            dd_seq: 0,
            dd_summary_recv: Vec::new(),
            dd_summary_tx: Vec::new(),
            last_dd_tx: None,
            last_dd_sent: std::time::Instant::now(),
            dd_response_pending: false,
            request_list: Vec::new(),
            pending_acks: Vec::new(),
            pending_lsu: Vec::new(),
            lsr_pending: false,
            dd_send_final: false,
            dd_peer_done: false,
        };
        iface.neighbors.insert(peer_rid, nb);
    }

    inst.originate_router_lsa();

    // Parse each area's Router-LSA and verify link count == 1 and
    // the link points to the correct peer.
    for (area, expected_peer) in
        [(Ipv4Addr::UNSPECIFIED, v4(10, 0, 0, 1)), (v4(0, 0, 0, 1), v4(10, 0, 0, 2))]
    {
        let key = LsaKeyV3 {
            area: Some(area),
            ls_type: LsaV3Type::Router,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: self_rid,
        };
        let entry = inst.lsdb.get(&key).unwrap();
        let body = &entry.raw[LSA_V3_HEADER_LEN..];
        let rlsa = RouterLsaV3::parse(body).unwrap();
        assert_eq!(rlsa.links.len(), 1, "area {} must have exactly 1 link", area);
        assert_eq!(
            rlsa.links[0].neighbor_router_id, expected_peer,
            "area {} link must point to its own peer",
            area
        );
    }
}

#[test]
fn abr_v3_3_type3_originated_in_other_area() {
    // Purpose: an ABR summarizes each area's prefixes into every
    // other area via Type 3 Inter-Area-Prefix-LSAs.
    let self_rid = v4(1, 1, 1, 1);
    let mut inst = InstanceV3::new(self_rid);
    inst.add_interface(
        io("wan", 1, "fe80::1"),
        Ipv4Addr::UNSPECIFIED,
        NetworkTypeV3::PointToPoint,
        10,
        40,
        1,
        vec![(v6("2001:db8:30::"), 64)],
    );
    inst.add_interface(
        io("lan", 2, "fe80::2"),
        v4(0, 0, 0, 1),
        NetworkTypeV3::PointToPoint,
        10,
        40,
        1,
        vec![(v6("2001:db8:31::"), 64)],
    );
    assert!(inst.is_abr());

    inst.originate_router_lsa();
    inst.originate_intra_area_prefix_lsas();
    inst.originate_inter_area_prefix_lsas();

    let mut area0_has_31 = false;
    let mut area1_has_30 = false;
    for e in inst.lsdb.iter() {
        if e.header.ls_type != LsaV3Type::InterAreaPrefix {
            continue;
        }
        if e.header.advertising_router != self_rid {
            continue;
        }
        let body = &e.raw[LSA_V3_HEADER_LEN..];
        let iap = InterAreaPrefixLsaV3::parse(body).unwrap();
        if e.area == Some(Ipv4Addr::UNSPECIFIED) && iap.prefix.address == v6("2001:db8:31::") {
            area0_has_31 = true;
        }
        if e.area == Some(v4(0, 0, 0, 1)) && iap.prefix.address == v6("2001:db8:30::") {
            area1_has_30 = true;
        }
    }
    assert!(area0_has_31, "area 0 must have Type 3 for 2001:db8:31::/64");
    assert!(area1_has_30, "area 1 must have Type 3 for 2001:db8:30::/64");
}

#[test]
fn asbr_v3_1_e_flag_and_type5_origination() {
    // Purpose: an ASBR sets E flag and originates AS-External LSAs
    // for configured redistribute-connected prefixes.
    let self_rid = v4(1, 1, 1, 1);
    let mut inst = InstanceV3::new(self_rid);
    inst.add_interface(
        io("wan", 1, "fe80::1"),
        Ipv4Addr::UNSPECIFIED,
        NetworkTypeV3::PointToPoint,
        10,
        40,
        1,
        Vec::new(),
    );
    inst.set_asbr(true);
    inst.redistribute = vec![ospfd::config::RedistributeConfig {
        source: ospfd::config::RedistributeSource::Connected,
        metric: 20,
        metric_type: 2,
        route_map: None,
    }];

    inst.originate_router_lsa();
    inst.originate_external_lsas(vec![(v6("2001:db8:ff::"), 64)], &[]);

    // Type 5 present at AS-scope (area = None).
    let t5: Vec<_> = inst
        .lsdb
        .iter()
        .filter(|e| {
            e.header.ls_type == LsaV3Type::AsExternal
                && e.header.advertising_router == self_rid
                && e.area.is_none()
        })
        .collect();
    assert_eq!(t5.len(), 1, "one Type 5 expected");

    // E flag set in Router-LSA.
    let key = LsaKeyV3 {
        area: Some(Ipv4Addr::UNSPECIFIED),
        ls_type: LsaV3Type::Router,
        link_state_id: Ipv4Addr::UNSPECIFIED,
        advertising_router: self_rid,
    };
    let rlsa = inst.lsdb.get(&key).unwrap();
    let flags = rlsa.raw[LSA_V3_HEADER_LEN];
    assert!(flags & RouterLsaV3::FLAG_E != 0, "E flag must be set");
}

// ============================================================================
// Group 4: SPF (RFC 5340 §3.8)
// ============================================================================

#[test]
fn spf_v3_1_intra_area_prefix_route() {
    // Purpose: end-to-end SPF produces a route for a prefix attached
    // to a peer's Router-LSA via an Intra-Area-Prefix-LSA.
    use ospfd::lsdb_v3::{LsaEntryV3, LsdbV3};
    use ospfd::spf_v3::{calculate_spf_v3, SpfNeighborV3};

    let self_rid = v4(1, 1, 1, 1);
    let peer_rid = v4(2, 2, 2, 2);
    let mut lsdb = LsdbV3::new();

    // Our own Router-LSA (p2p link to peer at cost 10)
    let mut our_rlsa_body = Vec::new();
    RouterLsaV3 {
        flags: 0,
        options: Options::standard().0,
        links: vec![RouterLinkV3 {
            link_type: RouterLinkV3::TYPE_POINT_TO_POINT,
            metric: 10,
            interface_id: 77,
            neighbor_interface_id: 88,
            neighbor_router_id: peer_rid,
        }],
    }
    .encode(&mut our_rlsa_body);
    lsdb.insert(LsaEntryV3 {
        header: LsaV3Header {
            ls_age: 0,
            ls_type: LsaV3Type::Router,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: self_rid,
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: (LSA_V3_HEADER_LEN + our_rlsa_body.len()) as u16,
        },
        raw: {
            let mut r = Vec::new();
            // Header bytes don't matter for SPF — it only reads body.
            r.resize(LSA_V3_HEADER_LEN, 0);
            r.extend_from_slice(&our_rlsa_body);
            r
        },
        area: Some(Ipv4Addr::UNSPECIFIED),
    });

    // Peer's Router-LSA (p2p back to us)
    let mut peer_rlsa_body = Vec::new();
    RouterLsaV3 {
        flags: 0,
        options: Options::standard().0,
        links: vec![RouterLinkV3 {
            link_type: RouterLinkV3::TYPE_POINT_TO_POINT,
            metric: 10,
            interface_id: 88,
            neighbor_interface_id: 77,
            neighbor_router_id: self_rid,
        }],
    }
    .encode(&mut peer_rlsa_body);
    lsdb.insert(LsaEntryV3 {
        header: LsaV3Header {
            ls_age: 0,
            ls_type: LsaV3Type::Router,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: peer_rid,
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: (LSA_V3_HEADER_LEN + peer_rlsa_body.len()) as u16,
        },
        raw: {
            let mut r = Vec::new();
            r.resize(LSA_V3_HEADER_LEN, 0);
            r.extend_from_slice(&peer_rlsa_body);
            r
        },
        area: Some(Ipv4Addr::UNSPECIFIED),
    });

    // Peer's Intra-Area-Prefix-LSA attaching a /64 to peer's Router-LSA
    let mut iap_body = Vec::new();
    IntraAreaPrefixLsaV3 {
        referenced_ls_type: LsaV3Type::Router as u16,
        referenced_link_state_id: Ipv4Addr::UNSPECIFIED,
        referenced_advertising_router: peer_rid,
        prefixes: vec![Ospfv3Prefix {
            prefix_length: 64,
            prefix_options: 0,
            prefix_or_metric: 0,
            address: v6("2001:db8:dead::"),
        }],
    }
    .encode(&mut iap_body);
    lsdb.insert(LsaEntryV3 {
        header: LsaV3Header {
            ls_age: 0,
            ls_type: LsaV3Type::IntraAreaPrefix,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: peer_rid,
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: (LSA_V3_HEADER_LEN + iap_body.len()) as u16,
        },
        raw: {
            let mut r = Vec::new();
            r.resize(LSA_V3_HEADER_LEN, 0);
            r.extend_from_slice(&iap_body);
            r
        },
        area: Some(Ipv4Addr::UNSPECIFIED),
    });

    let neighbors = vec![SpfNeighborV3 {
        router_id: peer_rid,
        link_local: v6("fe80::2"),
        sw_if_index: 1,
    }];
    let routes = calculate_spf_v3(self_rid, &lsdb, &neighbors);

    let r = routes
        .iter()
        .find(|r| r.prefix == v6("2001:db8:dead::") && r.prefix_len == 64)
        .expect("SPF must produce the intra-area prefix route");
    assert_eq!(r.cost, 10);
    assert_eq!(r.next_hops.len(), 1);
    assert_eq!(r.next_hops[0].0, v6("fe80::2"));
}
