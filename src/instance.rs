//! OSPF protocol instance.
//!
//! Ties together the interface/neighbor state machines, LSDB, SPF,
//! and VPP FIB programming into a single event-driven protocol engine.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::area::{Area, AreaType};
use crate::config::OspfDaemonConfig;
use crate::lsdb::InstallResult;
use crate::packet::hello::{HelloPacket, OspfOptions};
use crate::packet::lsa::*;
use crate::packet::*;
use crate::proto::interface::*;
use crate::proto::neighbor::*;
use crate::proto::spf;
use crate::rib::OspfRib;

/// The OSPF protocol instance.
pub struct OspfInstance {
    /// VRF this instance serves. None for the default VRF (FIB
    /// table 0); Some(name) for an entry sourced from
    /// `ospf.vrfs[<name>]`. Plumbed into status replies so an
    /// operator running `imp-ospfd query status` against any per-
    /// VRF control socket can see at a glance which instance is
    /// responding.
    pub vrf_name: Option<String>,
    /// Our router ID.
    pub router_id: Ipv4Addr,
    /// Areas, keyed by area_id. Each has its own LSDB.
    pub areas: HashMap<Ipv4Addr, Area>,
    /// AS-wide LSDB for Type 5 (AS-External) LSAs. These are flooded
    /// throughout the AS, not bound to any single area.
    pub as_external_lsdb: crate::lsdb::Lsdb,
    /// Redistribution configuration.
    pub redistribute: Vec<crate::config::RedistributeConfig>,
    /// OSPF interfaces.
    pub interfaces: Vec<OspfInterface>,
    /// SPF throttle state.
    spf_scheduled: Option<Instant>,
    spf_last_run: Option<Instant>,
    spf_hold_multiplier: u32,
    /// SPF throttle parameters.
    spf_delay_ms: u64,
    spf_holdtime_ms: u64,
    spf_max_holdtime_ms: u64,
    /// Route installation.
    pub rib: OspfRib,
    /// Summary-address aggregates (ASBR external aggregation). Kept
    /// here so the control-socket status query can report them back
    /// to the `ospfd query status` CLI without plumbing the daemon
    /// config through to the query path.
    pub summary_addresses: Vec<crate::config::ParsedSummaryAddress>,
    /// Compiled route-maps from the top-level `route_maps:` block,
    /// keyed by name. `originate_external_lsas` resolves
    /// per-redistribute `route_map` references against this set
    /// when filtering candidate prefixes.
    pub route_maps: std::collections::HashMap<String, ribd_routemap::RouteMap>,
}

impl OspfInstance {
    /// Create a new OSPF instance from configuration.
    pub fn new(config: &OspfDaemonConfig) -> Self {
        let mut interfaces = Vec::new();
        let mut areas: HashMap<Ipv4Addr, Area> = HashMap::new();

        // Build a lookup from config.areas so we can set area_type correctly
        let area_types: HashMap<Ipv4Addr, (AreaType, u32)> = config
            .areas
            .iter()
            .map(|a| {
                let atype = match a.area_type {
                    crate::config::AreaType::Normal => AreaType::Normal,
                    crate::config::AreaType::Stub => AreaType::Stub,
                    crate::config::AreaType::Nssa => AreaType::Nssa,
                };
                (a.area_id, (atype, a.default_cost))
            })
            .collect();

        for iface_cfg in &config.interfaces {
            // Ensure the area exists for every interface (including passive
            // ones, since their networks are advertised in our Router-LSA).
            let (area_type, default_cost) = area_types
                .get(&iface_cfg.area_id)
                .copied()
                .unwrap_or((AreaType::Normal, 1));
            areas.entry(iface_cfg.area_id).or_insert_with(|| {
                let mut a = Area::new(iface_cfg.area_id, area_type, config.router_id);
                a.default_cost = default_cost;
                a
            });

            if iface_cfg.passive {
                continue;
            }

            let network_type = match iface_cfg.network_type.as_str() {
                "point-to-point" => NetworkType::PointToPoint,
                "non-broadcast" => NetworkType::NonBroadcast,
                "point-to-multipoint" => NetworkType::PointToMultipoint,
                _ => NetworkType::Broadcast,
            };

            let mask = prefix_len_to_mask(iface_cfg.prefix_len);

            let mut iface = OspfInterface::new(
                iface_cfg.name.clone(),
                0, // sw_if_index resolved later from VPP
                iface_cfg.address,
                mask,
                iface_cfg.area_id,
                network_type,
                config.router_id,
            );
            iface.hello_interval = iface_cfg.hello_interval;
            iface.dead_interval = iface_cfg.dead_interval;
            iface.rxmt_interval = iface_cfg.retransmit_interval;
            iface.cost = iface_cfg.cost;
            iface.priority = iface_cfg.priority;
            iface.auth_key = iface_cfg.auth_key.clone();
            iface.static_neighbors = iface_cfg
                .static_neighbors
                .iter()
                .map(|(addr, priority)| crate::proto::interface::StaticNeighbor {
                    address: *addr,
                    priority: *priority,
                })
                .collect();

            interfaces.push(iface);
        }

        // Always have a backbone area, even if no interfaces are in it directly
        // (we may need it for ABR behavior).
        areas
            .entry(Ipv4Addr::UNSPECIFIED)
            .or_insert_with(|| {
                Area::new(Ipv4Addr::UNSPECIFIED, AreaType::Normal, config.router_id)
            });

        OspfInstance {
            vrf_name: config.vrf_name.clone(),
            router_id: config.router_id,
            areas,
            as_external_lsdb: crate::lsdb::Lsdb::new(config.router_id),
            redistribute: config.redistribute.clone(),
            interfaces,
            spf_scheduled: None,
            spf_last_run: None,
            spf_hold_multiplier: 0,
            spf_delay_ms: config.spf_delay_ms,
            spf_holdtime_ms: config.spf_holdtime_ms,
            spf_max_holdtime_ms: config.spf_max_holdtime_ms,
            rib: OspfRib::new(),
            summary_addresses: config.summary_addresses.clone(),
            route_maps: config.route_maps.clone(),
        }
    }

    /// Get the LSDB for a specific area.
    pub fn lsdb(&self, area_id: Ipv4Addr) -> Option<&crate::lsdb::Lsdb> {
        self.areas.get(&area_id).map(|a| &a.lsdb)
    }

    /// Returns true if this router is an Area Border Router (has interfaces in
    /// at least two distinct areas, one of which is the backbone).
    pub fn is_abr(&self) -> bool {
        let areas: std::collections::HashSet<Ipv4Addr> =
            self.interfaces.iter().map(|i| i.area_id).collect();
        areas.len() >= 2 && areas.contains(&Ipv4Addr::UNSPECIFIED)
    }

    /// Process a received OSPF packet.
    ///
    /// Returns a list of packets to send in response.
    pub fn process_packet(
        &mut self,
        sw_if_index: u32,
        src_addr: Ipv4Addr,
        packet: &OspfPacket,
    ) -> Vec<(u32, Ipv4Addr, OspfPacket)> {
        let mut responses = Vec::new();

        // Find the interface this packet came in on
        let iface_idx = match self.find_interface(sw_if_index) {
            Some(idx) => idx,
            None => {
                tracing::debug!(sw_if_index, "packet on unknown interface, ignoring");
                return responses;
            }
        };

        // Verify area ID matches
        let pkt_area = packet.header().area_id;
        if pkt_area != self.interfaces[iface_idx].area_id {
            tracing::debug!(
                expected = %self.interfaces[iface_idx].area_id,
                got = %pkt_area,
                "area mismatch, ignoring"
            );
            return responses;
        }

        match packet {
            OspfPacket::Hello(header, hello) => {
                self.process_hello(iface_idx, src_addr, header, hello, &mut responses);
            }
            OspfPacket::DatabaseDescription(header, dd) => {
                self.process_dd(iface_idx, src_addr, header, dd, &mut responses);
            }
            OspfPacket::LinkStateUpdate(header, lsu) => {
                self.process_lsu(iface_idx, src_addr, header, lsu, &mut responses);
            }
            OspfPacket::LinkStateRequest(header, lsr) => {
                self.process_lsr(iface_idx, src_addr, header, lsr, &mut responses);
            }
            OspfPacket::LinkStateAck(_header, _ack) => {
                // No-op until we add a retransmit queue. Acks from
                // peers are currently accepted implicitly: we don't
                // retransmit, so there's nothing to clear.
            }
        }

        responses
    }

    /// Process a received Hello packet (RFC 2328 Section 10.5).
    fn process_hello(
        &mut self,
        iface_idx: usize,
        src_addr: Ipv4Addr,
        header: &OspfHeader,
        hello: &HelloPacket,
        _responses: &mut Vec<(u32, Ipv4Addr, OspfPacket)>,
    ) {
        let iface = &mut self.interfaces[iface_idx];

        // Validate Hello parameters match
        if hello.hello_interval != iface.hello_interval
            || hello.router_dead_interval != iface.dead_interval
        {
            tracing::debug!(
                neighbor = %header.router_id,
                "Hello parameter mismatch, ignoring"
            );
            return;
        }

        let neighbor_id = header.router_id;

        // Create neighbor if new
        if !iface.neighbors.contains_key(&neighbor_id) {
            tracing::info!(
                interface = %iface.name,
                neighbor = %neighbor_id,
                address = %src_addr,
                "new neighbor"
            );
            iface.neighbors.insert(
                neighbor_id,
                Neighbor::new(neighbor_id, src_addr),
            );
        }

        // Snapshot the neighbor's pre-Hello state so we can decide
        // whether this Hello crossed a boundary that requires a
        // NeighborChange event on the interface (RFC 2328 §10.3):
        //   - a bidirectional relationship was established or lost
        //   - declared DR or BDR changed.
        let (old_state, old_dr, old_bdr) = {
            let n = iface.neighbors.get(&neighbor_id).unwrap();
            (n.state, n.dr, n.bdr)
        };

        {
            let neighbor = iface.neighbors.get_mut(&neighbor_id).unwrap();
            neighbor.priority = hello.router_priority;
            neighbor.dr = hello.designated_router;
            neighbor.bdr = hello.backup_designated_router;
            neighbor.address = src_addr;

            // HelloReceived event
            neighbor.handle_event(&NeighborEvent::HelloReceived, false);

            // Check if our router ID is in the neighbor's list (2-Way check)
            let two_way = hello.neighbors.contains(&self.router_id);

            if two_way && neighbor.state == NeighborState::Init {
                // Determine adjacency eligibility without borrowing iface
                // On P2P: always. On broadcast: if either end is DR/BDR.
                let adj = match iface.network_type {
                    NetworkType::PointToPoint | NetworkType::PointToMultipoint => true,
                    NetworkType::Broadcast | NetworkType::NonBroadcast => {
                        matches!(iface.state, InterfaceState::DR | InterfaceState::Backup)
                            || neighbor.dr == neighbor.address
                            || neighbor.bdr == neighbor.address
                    }
                };
                neighbor.handle_event(&NeighborEvent::TwoWayReceived, adj);
            } else if !two_way && neighbor.state >= NeighborState::TwoWay {
                neighbor.handle_event(&NeighborEvent::OneWay, false);
            }
        }

        // Check if we need to run DR election
        // (BackupSeen event if neighbor is declaring BDR and we're in Waiting)
        let (new_state, new_dr, new_bdr) = {
            let n = iface.neighbors.get(&neighbor_id).unwrap();
            (n.state, n.dr, n.bdr)
        };
        if iface.state == InterfaceState::Waiting {
            if !new_bdr.is_unspecified() || !new_dr.is_unspecified() {
                iface.handle_event(&InterfaceEvent::BackupSeen);
            }
        }

        // RFC 2328 §10.3: fire NeighborChange when a post-2-Way
        // state boundary was crossed or the neighbor's declared
        // DR/BDR changed. Without this, the interface FSM never
        // re-runs DR election after the initial Wait-timer expiry
        // — a peer returning from a flap leaves us pinned at
        // whatever role we held during the outage, so the DR-
        // dependent Network-LSA origination never fires.
        let two_way_boundary_crossed = (old_state >= NeighborState::TwoWay)
            != (new_state >= NeighborState::TwoWay);
        let dr_changed = old_dr != new_dr;
        let bdr_changed = old_bdr != new_bdr;
        if two_way_boundary_crossed || dr_changed || bdr_changed {
            iface.handle_event(&InterfaceEvent::NeighborChange);
        }
    }

    /// Process a Database Description packet.
    fn process_dd(
        &mut self,
        iface_idx: usize,
        src_addr: Ipv4Addr,
        header: &OspfHeader,
        dd: &crate::packet::dd::DbDescPacket,
        responses: &mut Vec<(u32, Ipv4Addr, OspfPacket)>,
    ) {
        let neighbor_id = header.router_id;
        let area_id = self.interfaces[iface_idx].area_id;
        let my_router_id = self.router_id;

        // Stale-self-LSA recovery (mirrors the v3 path in
        // instance_v3.rs::process_packet). When we restart we
        // originate at INITIAL_SEQUENCE_NUMBER, but peers may have
        // cached a higher-seq copy of our LSA from the previous
        // process. RFC 2328 §13.4 wants us to bump our seq past the
        // peer's and re-flood so our new LSA wins. Without this
        // step, any change to the LSA body across a restart
        // (flag bits, link list, etc.) silently fails to propagate
        // — the peer keeps using its stale copy until MaxAge.
        let mut bumped_self_lsa = false;
        for lsa_hdr in &dd.lsa_headers {
            if lsa_hdr.advertising_router != my_router_id {
                continue;
            }
            let key = lsa_hdr.key();
            let (our_seq, bumped) = if lsa_hdr.ls_type == LsaType::AsExternal {
                let s = self
                    .as_external_lsdb
                    .get(&key)
                    .map(|e| e.lsa.header.ls_sequence_number);
                let b = self
                    .as_external_lsdb
                    .bump_seq(&key, lsa_hdr.ls_sequence_number);
                (s, b)
            } else if let Some(area) = self.areas.get_mut(&area_id) {
                let s = area.lsdb.get(&key).map(|e| e.lsa.header.ls_sequence_number);
                let b = area.lsdb.bump_seq(&key, lsa_hdr.ls_sequence_number);
                (s, b)
            } else {
                continue;
            };
            if bumped {
                tracing::info!(
                    ls_type = ?lsa_hdr.ls_type,
                    ls_id = %lsa_hdr.link_state_id,
                    local_seq = format!("{:#x}", our_seq.unwrap_or(0)),
                    peer_seq = format!("{:#x}", lsa_hdr.ls_sequence_number),
                    "OSPFv2 stale self-LSA detected, bumping local seq",
                );
                bumped_self_lsa = true;
            }
        }
        if bumped_self_lsa {
            // Bumping the LSDB entry's seq is enough on its own —
            // the existing origination paths (neighbor_reached_full
            // in process_lsu, periodic_maintenance, reload_config)
            // will pick up the bumped seq and emit `existing.seq + 1`
            // when they next run, with the correct interface state.
            //
            // Re-originating directly here would be wrong: at the
            // time we receive an Exchange-phase DD, neighbors are
            // still in Exchange (not Full), so `has_full_adj` is
            // false and `originate_router_lsas` would emit a
            // StubNetwork link instead of the TransitNetwork the
            // Full-state path produces — and the StubNetwork LSA
            // is what would then win against the peer's cache,
            // hiding us from SPF's ASBR-reachability check.
            //
            // Schedule SPF since the bumped seq counts as a
            // self-LSA change as far as the local SPF view is
            // concerned.
            self.schedule_spf();
        }

        // Phase 1: state machine update (mut borrow on neighbor).
        // Pre-fetch the existing_hdr for each DD-listed LSA outside the
        // neighbor mut borrow (so we can cross-check against area + AS-ext LSDBs).
        let lsa_exists: Vec<(LsaKey, Option<LsaHeader>)> = dd
            .lsa_headers
            .iter()
            .map(|lsa_hdr| {
                let key = lsa_hdr.key();
                let existing_hdr = if lsa_hdr.ls_type == LsaType::AsExternal {
                    self.as_external_lsdb
                        .get(&key)
                        .map(|e| e.lsa.header.clone())
                } else {
                    self.areas
                        .get(&area_id)
                        .and_then(|a| a.lsdb.get(&key))
                        .map(|e| e.lsa.header.clone())
                };
                (key, existing_hdr)
            })
            .collect();

        // Pre-fetch our own LSDB headers in case we're about to enter
        // Exchange and need to seed db_summary_list (the per-neighbor
        // TX queue used by paged DD transmission).
        let our_headers: Vec<LsaHeader> = {
            let area_headers = self
                .areas
                .get(&area_id)
                .map(|a| a.lsdb.all_headers())
                .unwrap_or_default();
            let mut combined = area_headers;
            combined.extend(self.as_external_lsdb.all_headers());
            combined
        };

        // Now take the neighbor mut borrow and run the state machine
        let (final_state, needs_lsr) = {
            let iface = &mut self.interfaces[iface_idx];
            let Some(neighbor) = iface.neighbors.get_mut(&neighbor_id) else {
                return;
            };

            match neighbor.state {
                NeighborState::ExStart => {
                    // Negotiation phase (RFC 2328 Section 10.6)
                    if dd.is_init()
                        && dd.has_more()
                        && dd.is_master()
                        && dd.lsa_headers.is_empty()
                    {
                        if header.router_id > my_router_id {
                            // They win — we become slave, adopt their seq.
                            // Seed our TX queue with the LSDB headers we
                            // owe the peer; build_dd drains it in chunks.
                            neighbor.is_master = false;
                            neighbor.dd_seq_number = dd.dd_sequence_number;
                            neighbor.sent_m_clear = false;
                            neighbor.db_summary_list = our_headers.clone();
                            neighbor.handle_event(&NeighborEvent::NegotiationDone, true);
                        }
                        // If we have higher router ID, ignore this DD and
                        // keep sending our initial DDs until they accept.
                    } else if !dd.is_init() && !dd.is_master() {
                        // Slave accepted our mastery (I=0, MS=0, our seq).
                        // Mark ourselves as master — future build_dd calls
                        // for this neighbor produce MS=1 DDs and the master
                        // drives sequence increments.
                        if header.router_id < my_router_id
                            && dd.dd_sequence_number == neighbor.dd_seq_number
                        {
                            neighbor.is_master = true;
                            neighbor.sent_m_clear = false;
                            neighbor.db_summary_list = our_headers.clone();
                            neighbor.handle_event(&NeighborEvent::NegotiationDone, true);
                        }
                    }

                    // If we just transitioned to Exchange, process any DD
                    // headers the peer included. NOTE: do NOT fire
                    // ExchangeDone here even if peer's M=0 — the master
                    // still has to describe its own LSDB to the peer, and
                    // RFC 2328 §10.8 requires *both* sides' final DDs to
                    // carry M=0 before ExchangeDone can fire.
                    if neighbor.state == NeighborState::Exchange {
                        for (key, existing_hdr) in &lsa_exists {
                            let need = match existing_hdr {
                                None => true,
                                Some(existing) => {
                                    dd.lsa_headers
                                        .iter()
                                        .find(|h| h.key() == *key)
                                        .map(|h| {
                                            h.is_more_recent_than(existing)
                                                == std::cmp::Ordering::Greater
                                        })
                                        .unwrap_or(false)
                                }
                            };
                            if need {
                                neighbor.ls_request_list.push(*key);
                            }
                        }
                    }
                }
                NeighborState::Exchange => {
                    for (key, existing_hdr) in &lsa_exists {
                        let need = match existing_hdr {
                            None => true,
                            Some(existing) => dd
                                .lsa_headers
                                .iter()
                                .find(|h| h.key() == *key)
                                .map(|h| {
                                    h.is_more_recent_than(existing)
                                        == std::cmp::Ordering::Greater
                                })
                                .unwrap_or(false),
                        };
                        if need {
                            neighbor.ls_request_list.push(*key);
                        }
                    }
                    // Only declare ExchangeDone when *both* sides have
                    // sent a DD with M=0 (RFC 2328 §10.8). sent_m_clear
                    // is set inside build_dd once we emit our final DD.
                    if !dd.has_more() && neighbor.sent_m_clear {
                        neighbor.handle_event(&NeighborEvent::ExchangeDone, true);
                    }
                }
                _ => {}
            }

            neighbor.last_dd = Some(dd.clone());

            // Sequence-number rules for Exchange (RFC 2328 §10.8):
            //   master: dd_seq_number is incremented *after* sending each
            //           DD; we do the bump inside build_dd, not here.
            //   slave:  dd_seq_number is set to whatever the master's
            //           latest DD carried.
            if neighbor.state == NeighborState::Exchange && !neighbor.is_master {
                neighbor.dd_seq_number = dd.dd_sequence_number;
            }
            neighbor.last_dd_sent = Instant::now();

            (
                neighbor.state,
                neighbor.state >= NeighborState::Exchange
                    && !neighbor.ls_request_list.is_empty(),
            )
        }; // ← neighbor / iface mut borrow ends here

        // Phase 2: build the response DD and push it (no neighbor borrow held)
        let dd_to_send = match final_state {
            NeighborState::ExStart => self.build_dd(iface_idx, neighbor_id, true),
            NeighborState::Exchange => self.build_dd(iface_idx, neighbor_id, false),
            _ => None,
        };
        if let Some(pkt) = dd_to_send {
            responses.push((
                self.interfaces[iface_idx].sw_if_index,
                src_addr,
                pkt,
            ));
        }
        let router_id = self.router_id;
        if needs_lsr {
            let iface = &mut self.interfaces[iface_idx];
            let (requests, area_id, sw_if_index) = {
                let n = match iface.neighbors.get_mut(&header.router_id) {
                    Some(n) => n,
                    None => return,
                };
                let reqs: Vec<crate::packet::lsr::LsRequest> = n
                    .ls_request_list
                    .iter()
                    .take(20) // cap per packet
                    .map(|key| crate::packet::lsr::LsRequest {
                        ls_type: key.ls_type,
                        link_state_id: key.link_state_id,
                        advertising_router: key.advertising_router,
                    })
                    .collect();
                if !reqs.is_empty() {
                    n.last_lsr_sent = Instant::now();
                }
                (reqs, iface.area_id, iface.sw_if_index)
            };

            if !requests.is_empty() {
                let lsr_pkt = OspfPacket::LinkStateRequest(
                    OspfHeader::new(
                        OspfPacketType::LinkStateRequest,
                        router_id,
                        area_id,
                    ),
                    crate::packet::lsr::LsRequestPacket { requests },
                );
                responses.push((sw_if_index, src_addr, lsr_pkt));
            }
        }
    }

    /// Retransmit Link State Requests for any neighbor in Exchange or
    /// Loading state that has a non-empty `ls_request_list` and hasn't
    /// been sent an LSR in the last `RxmtInterval`. RFC 2328 §10.9
    /// requires retransmission until the request list drains or the
    /// neighbor leaves Loading; without it, a single dropped or
    /// truncated LSU response from the peer wedges the adjacency in
    /// Loading until the dead-timer fires (or impd is restarted).
    ///
    /// Called from the same `hello_tick` branch in the daemon loop
    /// that drives `emit_pending_dds`, so the retransmit cadence is
    /// bounded by the 1-second tick AND each interface's
    /// `rxmt_interval` (5s by default).
    pub fn emit_pending_lsrs(&mut self) -> Vec<(u32, Ipv4Addr, OspfPacket)> {
        let mut responses = Vec::new();
        let now = Instant::now();
        let router_id = self.router_id;

        // Snapshot which (iface_idx, neighbor_id) pairs are due for
        // an LSR retransmit, holding only the immutable borrow we
        // need to read state.
        struct Due {
            iface_idx: usize,
            neighbor_id: Ipv4Addr,
            address: Ipv4Addr,
            area_id: Ipv4Addr,
            sw_if_index: u32,
        }
        let due: Vec<Due> = self
            .interfaces
            .iter()
            .enumerate()
            .flat_map(|(idx, iface)| {
                let rxmt = Duration::from_secs(iface.rxmt_interval.max(1) as u64);
                let area_id = iface.area_id;
                let sw_if_index = iface.sw_if_index;
                iface
                    .neighbors
                    .values()
                    .filter(move |n| {
                        matches!(n.state, NeighborState::Exchange | NeighborState::Loading)
                            && !n.ls_request_list.is_empty()
                            && now.saturating_duration_since(n.last_lsr_sent) >= rxmt
                    })
                    .map(move |n| Due {
                        iface_idx: idx,
                        neighbor_id: n.router_id,
                        address: n.address,
                        area_id,
                        sw_if_index,
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        for d in due {
            // Build the LSR with the current request list, stamping
            // last_lsr_sent so we don't double-fire on the next tick.
            let iface = match self.interfaces.get_mut(d.iface_idx) {
                Some(i) => i,
                None => continue,
            };
            let n = match iface.neighbors.get_mut(&d.neighbor_id) {
                Some(n) => n,
                None => continue,
            };
            let requests: Vec<crate::packet::lsr::LsRequest> = n
                .ls_request_list
                .iter()
                .take(20)
                .map(|key| crate::packet::lsr::LsRequest {
                    ls_type: key.ls_type,
                    link_state_id: key.link_state_id,
                    advertising_router: key.advertising_router,
                })
                .collect();
            if requests.is_empty() {
                continue;
            }
            n.last_lsr_sent = now;
            tracing::debug!(
                neighbor = %d.neighbor_id,
                count = requests.len(),
                "retransmitting LSR (request list non-empty)",
            );
            let lsr_pkt = OspfPacket::LinkStateRequest(
                OspfHeader::new(OspfPacketType::LinkStateRequest, router_id, d.area_id),
                crate::packet::lsr::LsRequestPacket { requests },
            );
            responses.push((d.sw_if_index, d.address, lsr_pkt));
        }

        responses
    }

    /// Process a Link State Update packet (RFC 2328 Section 13).
    fn process_lsu(
        &mut self,
        iface_idx: usize,
        src_addr: Ipv4Addr,
        header: &OspfHeader,
        lsu: &crate::packet::lsu::LsUpdatePacket,
        responses: &mut Vec<(u32, Ipv4Addr, OspfPacket)>,
    ) {
        let mut ack_headers = Vec::new();
        let mut to_flood: Vec<Lsa> = Vec::new();
        let mut schedule_spf = false;
        let mut neighbor_reached_full = false;
        let area_id = self.interfaces[iface_idx].area_id;

        // Reject Type 5 LSAs arriving in a stub area (RFC 2328 Section 3.6)
        let area_is_stub = self
            .areas
            .get(&area_id)
            .map(|a| !a.accepts_as_external())
            .unwrap_or(false);

        for lsa in &lsu.lsas {
            if lsa.header.ls_type == LsaType::AsExternal && area_is_stub {
                tracing::debug!(
                    area = %area_id,
                    lsid = %lsa.header.link_state_id,
                    "dropping Type 5 LSA on stub area"
                );
                continue;
            }

            // Type 5 (AS-External) LSAs live in the AS-wide LSDB, not the
            // per-area LSDB. Every other LSA type goes into the area LSDB.
            let result = if lsa.header.ls_type == LsaType::AsExternal {
                self.as_external_lsdb.install(lsa.clone())
            } else {
                match self.areas.get_mut(&area_id) {
                    Some(area) => area.lsdb.install(lsa.clone()),
                    None => {
                        tracing::warn!(area = %area_id, "LSU received for unknown area");
                        continue;
                    }
                }
            };

            match result {
                InstallResult::New | InstallResult::Updated => {
                    // Acknowledge the LSA
                    ack_headers.push(lsa.header.clone());

                    // Remove from request list if present
                    let key = lsa.key();
                    let iface = &mut self.interfaces[iface_idx];
                    if let Some(neighbor) = iface.neighbors.get_mut(&header.router_id) {
                        neighbor.ls_request_list.retain(|k| *k != key);

                        // Check if Loading -> Full
                        if neighbor.state == NeighborState::Loading
                            && neighbor.ls_request_list.is_empty()
                        {
                            if let Some(NeighborState::Full) =
                                neighbor.handle_event(&NeighborEvent::LoadingDone, true)
                            {
                                neighbor_reached_full = true;
                            }
                        }
                    }

                    // Schedule SPF for Router/Network/Summary LSA changes
                    if matches!(
                        lsa.header.ls_type,
                        LsaType::Router | LsaType::Network | LsaType::SummaryNetwork
                    ) {
                        schedule_spf = true;
                    }

                    // Flood the LSA to other neighbors (RFC 2328 Section 13.3)
                    to_flood.push(lsa.clone());
                }
                InstallResult::Duplicate => {
                    // Acknowledge anyway (implicit ack)
                    ack_headers.push(lsa.header.clone());
                }
                InstallResult::Older => {
                    // Send our newer copy back to the sender
                    let key = lsa.key();
                    let our_lsa = self
                        .areas
                        .get(&area_id)
                        .and_then(|a| a.lsdb.get(&key))
                        .map(|e| e.lsa.clone());
                    if let Some(our_lsa_data) = our_lsa {
                        let our_pkt = OspfPacket::LinkStateUpdate(
                            OspfHeader::new(
                                OspfPacketType::LinkStateUpdate,
                                self.router_id,
                                area_id,
                            ),
                            crate::packet::lsu::LsUpdatePacket {
                                lsas: vec![our_lsa_data],
                            },
                        );
                        responses.push((
                            self.interfaces[iface_idx].sw_if_index,
                            src_addr,
                            our_pkt,
                        ));
                    }
                }
            }
        }

        // Send LS Acknowledgment
        if !ack_headers.is_empty() {
            let iface = &self.interfaces[iface_idx];
            let ack_pkt = OspfPacket::LinkStateAck(
                OspfHeader::new(OspfPacketType::LinkStateAck, self.router_id, iface.area_id),
                LsAckPacket {
                    lsa_headers: ack_headers,
                },
            );
            // Send to the source (unicast ack)
            responses.push((iface.sw_if_index, src_addr, ack_pkt));
        }

        // Flood new/updated LSAs to all other neighbors in the same area.
        // For Phase 2 simplicity we send to AllSPFRouters on each interface
        // (excluding the input interface).
        if !to_flood.is_empty() {
            self.flood_lsas_to_others(iface_idx, header.router_id, &to_flood, responses);
        }

        // If a neighbor just reached Full, re-originate our Router-LSAs in
        // every area (their links may now include the transit network instead
        // of a stub), and flood them to peers.
        if neighbor_reached_full {
            let new_lsas = self.originate_router_lsas();
            for (_area_id, lsa) in new_lsas {
                self.flood_lsas_to_others(usize::MAX, self.router_id, &[lsa], responses);
            }
            // If we're DR on any broadcast interface, originate/refresh
            // Network-LSAs for those interfaces.
            let net_lsas = self.originate_network_lsas();
            for (_area_id, lsa) in net_lsas {
                self.flood_lsas_to_others(usize::MAX, self.router_id, &[lsa], responses);
            }
            // If we're an ABR, also originate Summary-LSAs
            if self.is_abr() {
                let summaries = self.originate_summary_lsas();
                for (_area_id, lsa) in summaries {
                    self.flood_lsas_to_others(
                        usize::MAX,
                        self.router_id,
                        &[lsa],
                        responses,
                    );
                }
            }
            schedule_spf = true;
        }

        if schedule_spf {
            self.schedule_spf();
        }
    }

    /// Flood a set of LSAs to all eligible neighbors except the one we
    /// received them from.
    ///
    /// `input_iface_idx`: the interface the LSAs came in on (`usize::MAX` if
    /// the LSAs are self-originated)
    /// `from_router`: the router that sent us the LSAs (or our router ID for
    /// self-originated)
    pub fn flood_lsas_to_others(
        &self,
        input_iface_idx: usize,
        from_router: Ipv4Addr,
        lsas: &[Lsa],
        responses: &mut Vec<(u32, Ipv4Addr, OspfPacket)>,
    ) {
        for (idx, iface) in self.interfaces.iter().enumerate() {
            if iface.state == InterfaceState::Down {
                continue;
            }

            // For LSAs received from a neighbor, don't reflood out the same
            // interface to that same neighbor. (RFC 2328 Section 13.3 step 1b
            // is more nuanced, but this is correct for the simple case.)
            //
            // Even for the input interface we should reflood to OTHER neighbors
            // on the same broadcast network — but a simple correct approach is
            // to skip the input interface entirely on the assumption that the
            // sender has already flooded to all its neighbors. This is what
            // many implementations do for non-DR routers.
            if idx == input_iface_idx {
                continue;
            }

            // Are there any neighbors here in Exchange or higher state?
            let any_eligible = iface
                .neighbors
                .values()
                .any(|n| n.state >= NeighborState::Exchange && n.router_id != from_router);
            if !any_eligible {
                continue;
            }

            // Filter Type 5 LSAs out of stub area flooding (RFC 2328 3.6)
            let area_accepts_ext = self
                .areas
                .get(&iface.area_id)
                .map(|a| a.accepts_as_external())
                .unwrap_or(true);

            let filtered_lsas: Vec<Lsa> = lsas
                .iter()
                .filter(|l| {
                    area_accepts_ext || l.header.ls_type != LsaType::AsExternal
                })
                .cloned()
                .collect();

            if filtered_lsas.is_empty() {
                continue;
            }

            let lsu_pkt = OspfPacket::LinkStateUpdate(
                OspfHeader::new(
                    OspfPacketType::LinkStateUpdate,
                    self.router_id,
                    iface.area_id,
                ),
                crate::packet::lsu::LsUpdatePacket {
                    lsas: filtered_lsas,
                },
            );

            // Multicast to AllSPFRouters on this interface
            responses.push((iface.sw_if_index, ALL_SPF_ROUTERS, lsu_pkt));
        }
    }

    /// Process a Link State Request packet.
    fn process_lsr(
        &mut self,
        iface_idx: usize,
        src_addr: Ipv4Addr,
        header: &OspfHeader,
        lsr: &crate::packet::lsr::LsRequestPacket,
        responses: &mut Vec<(u32, Ipv4Addr, OspfPacket)>,
    ) {
        let mut lsas = Vec::new();
        let area_id = self.interfaces[iface_idx].area_id;
        let area = self.areas.get(&area_id);

        for req in &lsr.requests {
            let key = LsaKey {
                ls_type: req.ls_type,
                link_state_id: req.link_state_id,
                advertising_router: req.advertising_router,
            };

            let entry = if req.ls_type == LsaType::AsExternal {
                self.as_external_lsdb.get(&key)
            } else {
                area.and_then(|a| a.lsdb.get(&key))
            };

            if let Some(entry) = entry {
                lsas.push(entry.lsa.clone());
            } else {
                // BadLSReq — we don't have this LSA
                let iface = &mut self.interfaces[iface_idx];
                if let Some(neighbor) = iface.neighbors.get_mut(&header.router_id) {
                    neighbor.handle_event(&NeighborEvent::BadLsReq, false);
                }
                return;
            }
        }

        if !lsas.is_empty() {
            let iface = &self.interfaces[iface_idx];
            let lsu_pkt = OspfPacket::LinkStateUpdate(
                OspfHeader::new(OspfPacketType::LinkStateUpdate, self.router_id, iface.area_id),
                crate::packet::lsu::LsUpdatePacket { lsas },
            );
            responses.push((iface.sw_if_index, src_addr, lsu_pkt));
        }
    }

    /// Emit initial Database Description packets for any neighbor in ExStart
    /// state that needs a retransmit (timer-driven, every ~1 second).
    ///
    /// Returns a list of (sw_if_index, dst_addr, packet) to send.
    pub fn emit_pending_dds(&mut self) -> Vec<(u32, Ipv4Addr, OspfPacket)> {
        let mut responses = Vec::new();
        let now = Instant::now();

        // Collect which neighbors need a DD retransmit (ExStart + stale)
        let pending: Vec<(usize, Ipv4Addr, Ipv4Addr)> = self
            .interfaces
            .iter()
            .enumerate()
            .flat_map(|(idx, iface)| {
                let sw_if = iface.sw_if_index;
                iface
                    .neighbors
                    .values()
                    .filter(move |n| {
                        n.state == NeighborState::ExStart
                            && now.saturating_duration_since(n.last_dd_sent)
                                >= Duration::from_secs(1)
                    })
                    .map(move |n| (idx, n.router_id, n.address))
                    .map(move |(i, r, a)| {
                        let _ = sw_if;
                        (i, r, a)
                    })
            })
            .collect();

        for (iface_idx, neighbor_id, neighbor_addr) in pending {
            // Initialize a DD seq number if needed
            if let Some(n) = self.interfaces[iface_idx]
                .neighbors
                .get_mut(&neighbor_id)
            {
                if n.dd_seq_number == 0 {
                    n.dd_seq_number = 0x8000_0000 + (now.elapsed().as_millis() as u32 & 0xFFFF);
                }
                n.last_dd_sent = now;
            }
            if let Some(pkt) = self.build_dd(iface_idx, neighbor_id, true) {
                responses.push((
                    self.interfaces[iface_idx].sw_if_index,
                    neighbor_addr,
                    pkt,
                ));
            }
        }

        responses
    }

    /// Build a Database Description packet for a specific neighbor.
    ///
    /// Returns the DD packet to send. Should be called from:
    ///   - ExStart neighbors: sends initial DD (I+M+MS, empty LSA list)
    ///   - Exchange (as master): bumps sequence, sends next batch of headers
    ///   - Exchange (as slave): echoes the master's sequence with our batch
    ///
    /// `initial` indicates whether this is the very first DD we're sending for
    /// this neighbor (ExStart negotiation).
    fn build_dd(
        &mut self,
        iface_idx: usize,
        neighbor_id: Ipv4Addr,
        initial: bool,
    ) -> Option<OspfPacket> {
        let (area_id, options, dd_mtu) = {
            let iface = self.interfaces.get(iface_idx)?;
            (iface.area_id, iface.options, iface.dd_mtu)
        };

        let iface = self.interfaces.get_mut(iface_idx)?;
        let neighbor = iface.neighbors.get_mut(&neighbor_id)?;

        // For the initial DD: I=1, M=1, MS=1, empty LSA list.
        // For subsequent DDs, flag bits are:
        //   I=0 always
        //   MS=1 if we're master, 0 if slave
        //   M=1 if more headers remain in db_summary_list after this
        //        drain, M=0 if this packet sends the last chunk.
        //
        // db_summary_list is populated when we transition into
        // Exchange (in process_dd's NegotiationDone branches). Each
        // build_dd call drains up to MAX_HEADERS_PER_DD entries.
        // sent_m_clear flips true when we emit our final M=0 DD,
        // which is the gate for ExchangeDone on receipt of peer's
        // M=0 (RFC 2328 §10.8).
        const MAX_HEADERS_PER_DD: usize = 60;

        let mut flags = 0u8;
        let (lsa_headers, seq_used) = if initial {
            flags |= crate::packet::dd::DD_FLAG_I;
            flags |= crate::packet::dd::DD_FLAG_M;
            flags |= crate::packet::dd::DD_FLAG_MS;
            // Initial DD uses the seed sequence (set in emit_pending_dds).
            (Vec::new(), neighbor.dd_seq_number)
        } else {
            if neighbor.is_master {
                // Master: MS=1, bump our sequence *before* sending.
                flags |= crate::packet::dd::DD_FLAG_MS;
                neighbor.dd_seq_number = neighbor.dd_seq_number.wrapping_add(1);
            }
            // Slave: echo the sequence the master handed us (left alone
            // in dd_seq_number by process_dd).

            // Drain the next chunk from the per-neighbor TX queue.
            let take = neighbor.db_summary_list.len().min(MAX_HEADERS_PER_DD);
            let chunk: Vec<LsaHeader> =
                neighbor.db_summary_list.drain(..take).collect();
            if !neighbor.db_summary_list.is_empty() {
                // More to come — set M.
                flags |= crate::packet::dd::DD_FLAG_M;
            } else {
                // Last DD in our exchange — record so ExchangeDone
                // can fire on the next peer M=0.
                neighbor.sent_m_clear = true;
            }
            (chunk, neighbor.dd_seq_number)
        };

        let dd = crate::packet::dd::DbDescPacket {
            // Per-interface (RFC 2328 §10.6). 1500 for Ethernet (matches
            // the peer; VPP's reported L3 MTU is the jumbo internal
            // value, not the wire MTU); the tunnel's real IP MTU for a
            // GRE/IPIP interface, read from VPP at resolution.
            interface_mtu: dd_mtu,
            options,
            flags,
            dd_sequence_number: seq_used,
            lsa_headers,
        };

        let header =
            OspfHeader::new(OspfPacketType::DatabaseDescription, self.router_id, area_id);
        Some(OspfPacket::DatabaseDescription(header, dd))
    }

    /// Build a Hello packet for an interface.
    pub fn build_hello(&self, iface: &OspfInterface) -> OspfPacket {
        let neighbor_ids: Vec<Ipv4Addr> = iface
            .neighbors
            .values()
            .filter(|n| n.state >= NeighborState::Init)
            .map(|n| n.router_id)
            .collect();

        let hello = HelloPacket {
            network_mask: iface.mask,
            hello_interval: iface.hello_interval,
            options: iface.options,
            router_priority: iface.priority,
            router_dead_interval: iface.dead_interval,
            designated_router: iface.dr,
            backup_designated_router: iface.bdr,
            neighbors: neighbor_ids,
        };

        let header = OspfHeader::new(OspfPacketType::Hello, self.router_id, iface.area_id);

        OspfPacket::Hello(header, hello)
    }

    /// Originate our Router-LSA in every area we participate in.
    ///
    /// Each area gets its own Router-LSA whose link list contains only the
    /// links for interfaces in that area. Returns a Vec of (area_id, lsa)
    /// for the freshly originated LSAs.
    pub fn originate_router_lsas(&mut self) -> Vec<(Ipv4Addr, Lsa)> {
        let area_ids: Vec<Ipv4Addr> = self.areas.keys().copied().collect();
        let is_abr = self.is_abr();
        // We're an ASBR whenever we have any active redistribute
        // entry — `originate_external_lsas` emits the Type-5 LSAs
        // for those routes, and the Router-LSA's E bit is the
        // companion signal that lets peers compute SPF paths to us
        // as an ASBR (RFC 2328 §16.4). Without the E flag, peer
        // routers know about the Type-5 LSAs we originate but refuse
        // to install them — they can't resolve the advertising
        // router via an intra/inter-area path.
        let is_asbr = !self.redistribute.is_empty();
        let mut originated = Vec::new();

        for area_id in area_ids {
            let mut links = Vec::new();

            for iface in &self.interfaces {
                if iface.area_id != area_id || iface.state == InterfaceState::Down {
                    continue;
                }

                match iface.network_type {
                    NetworkType::PointToPoint => {
                        for neighbor in iface.neighbors.values() {
                            if neighbor.state == NeighborState::Full {
                                links.push(RouterLink {
                                    link_id: neighbor.router_id,
                                    link_data: iface.address,
                                    link_type: RouterLinkType::PointToPoint,
                                    num_tos: 0,
                                    metric: iface.cost,
                                });
                            }
                        }
                        links.push(RouterLink {
                            link_id: apply_mask(iface.address, iface.mask),
                            link_data: iface.mask,
                            link_type: RouterLinkType::StubNetwork,
                            num_tos: 0,
                            metric: iface.cost,
                        });
                    }
                    // P2MP (RFC 2328 §A.4.5): one PointToPoint link
                    // per fully-adjacent neighbor, with link_id =
                    // neighbor router-id and link_data = OUR
                    // interface address. Plus a single host-route
                    // stub for our own /32 on the segment so the
                    // local interface address is reachable from
                    // peers' SPF.
                    NetworkType::PointToMultipoint => {
                        for neighbor in iface.neighbors.values() {
                            if neighbor.state == NeighborState::Full {
                                links.push(RouterLink {
                                    link_id: neighbor.router_id,
                                    link_data: iface.address,
                                    link_type: RouterLinkType::PointToPoint,
                                    num_tos: 0,
                                    metric: iface.cost,
                                });
                            }
                        }
                        // Host route for our own interface IP.
                        links.push(RouterLink {
                            link_id: iface.address,
                            link_data: Ipv4Addr::new(255, 255, 255, 255),
                            link_type: RouterLinkType::StubNetwork,
                            num_tos: 0,
                            metric: 0,
                        });
                    }
                    // NBMA uses the same Router-LSA transit-network
                    // path as Broadcast (one Network-LSA per subnet
                    // referencing the DR).
                    NetworkType::Broadcast | NetworkType::NonBroadcast => {
                        let has_full_adj = iface
                            .neighbors
                            .values()
                            .any(|n| n.state == NeighborState::Full);

                        if has_full_adj {
                            links.push(RouterLink {
                                link_id: iface.dr,
                                link_data: iface.address,
                                link_type: RouterLinkType::TransitNetwork,
                                num_tos: 0,
                                metric: iface.cost,
                            });
                        } else {
                            links.push(RouterLink {
                                link_id: apply_mask(iface.address, iface.mask),
                                link_data: iface.mask,
                                link_type: RouterLinkType::StubNetwork,
                                num_tos: 0,
                                metric: iface.cost,
                            });
                        }
                    }
                }
            }

            // Skip empty areas (no interfaces in this area)
            if links.is_empty() {
                continue;
            }

            // Set the B (border router) flag if we are an ABR and
            // the E (AS boundary router) flag if we are an ASBR.
            // Both flags coexist on the same router-LSA in OSPFv2
            // (RFC 2328 §A.4.2) — a router may be both at once.
            let mut flags = 0u8;
            if is_abr {
                flags |= RouterLsa::B_FLAG;
            }
            if is_asbr {
                flags |= RouterLsa::E_FLAG;
            }

            if let Some(area) = self.areas.get_mut(&area_id) {
                let lsa = area.lsdb.originate_router_lsa(
                    self.router_id,
                    area_id,
                    flags,
                    links,
                    OspfOptions::standard().0,
                );
                originated.push((area_id, lsa));
            }
        }

        originated
    }

    /// Originate Network-LSAs as the DR on each broadcast interface where
    /// we're the DR and have at least one fully adjacent neighbor.
    ///
    /// RFC 2328 Section 12.4.2: a Network-LSA describes a broadcast network
    /// by listing all routers attached to it (including the DR itself). The
    /// DR is solely responsible for originating this LSA.
    ///
    /// Returns a Vec of (area_id, lsa) for newly originated LSAs.
    pub fn originate_network_lsas(&mut self) -> Vec<(Ipv4Addr, Lsa)> {
        let mut originated = Vec::new();

        // Find interfaces where we're the DR with at least one Full neighbor
        let dr_ifaces: Vec<(usize, Ipv4Addr, Ipv4Addr, Ipv4Addr, Vec<Ipv4Addr>)> = self
            .interfaces
            .iter()
            .enumerate()
            .filter(|(_, i)| {
                i.state == InterfaceState::DR
                    && i.network_type == NetworkType::Broadcast
                    && i.neighbors
                        .values()
                        .any(|n| n.state == NeighborState::Full)
            })
            .map(|(idx, iface)| {
                // Attached routers: ourselves + all Full neighbors
                let mut attached: Vec<Ipv4Addr> = iface
                    .neighbors
                    .values()
                    .filter(|n| n.state == NeighborState::Full)
                    .map(|n| n.router_id)
                    .collect();
                attached.push(self.router_id);
                attached.sort();
                (idx, iface.area_id, iface.address, iface.mask, attached)
            })
            .collect();

        for (_idx, area_id, dr_addr, mask, attached) in dr_ifaces {
            let key = LsaKey {
                ls_type: LsaType::Network,
                // Network-LSA's link_state_id is the DR's interface address
                link_state_id: dr_addr,
                advertising_router: self.router_id,
            };

            // Determine sequence number
            let seq = if let Some(area) = self.areas.get(&area_id) {
                match area.lsdb.get(&key) {
                    Some(e) => e.lsa.header.ls_sequence_number.wrapping_add(1),
                    None => INITIAL_SEQUENCE_NUMBER,
                }
            } else {
                INITIAL_SEQUENCE_NUMBER
            };

            let body = NetworkLsa {
                network_mask: mask,
                attached_routers: attached,
            };
            let mut body_buf = Vec::new();
            body.encode(&mut body_buf);
            let length = lsa_total_length(body_buf.len());

            let lsa = Lsa {
                header: LsaHeader {
                    ls_age: 0,
                    options: OspfOptions::standard().0,
                    ls_type: LsaType::Network,
                    link_state_id: dr_addr,
                    advertising_router: self.router_id,
                    ls_sequence_number: seq,
                    ls_checksum: 0,
                    length,
                },
                body: LsaBody::Network(body),
            };

            let encoded = lsa.encode();
            let with_cksum = match Lsa::parse(&encoded) {
                Ok(l) => l,
                Err(_) => continue,
            };

            if let Some(area) = self.areas.get_mut(&area_id) {
                area.lsdb.install(with_cksum.clone());
                originated.push((area_id, with_cksum));
            }
        }

        originated
    }

    /// Convenience: originate Router-LSAs in all areas and return the first one
    /// (compatibility shim — old code expected a single Router-LSA).
    pub fn originate_router_lsa(&mut self) -> Lsa {
        let lsas = self.originate_router_lsas();
        // For compatibility, return the first LSA or an empty placeholder.
        // Callers that need all LSAs should use originate_router_lsas directly.
        lsas.into_iter()
            .next()
            .map(|(_, lsa)| lsa)
            .unwrap_or_else(|| Lsa {
                header: LsaHeader {
                    ls_age: 0,
                    options: 0,
                    ls_type: LsaType::Router,
                    link_state_id: self.router_id,
                    advertising_router: self.router_id,
                    ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                    ls_checksum: 0,
                    length: 24,
                },
                body: LsaBody::Router(RouterLsa {
                    flags: 0,
                    links: vec![],
                }),
            })
    }

    /// Originate Type 3 (Summary-Network) LSAs as an ABR.
    ///
    /// For each "source" area we have an interface in, take the intra-area
    /// routes from that area and generate a Type 3 Summary-LSA in each
    /// "destination" area we participate in.
    ///
    /// Phase 2 simplification:
    /// - We summarize routes by exact prefix (no aggregation)
    /// - We don't honor stub-area no-summary
    /// - We use the same metric the source area computed
    ///
    /// Returns a list of (destination_area_id, lsa) for newly originated
    /// Summary-LSAs that need to be flooded.
    pub fn originate_summary_lsas(&mut self) -> Vec<(Ipv4Addr, Lsa)> {
        if !self.is_abr() {
            return Vec::new();
        }

        let mut originated = Vec::new();
        let area_ids: Vec<Ipv4Addr> = self.areas.keys().copied().collect();

        // For each source area, compute its intra-area routes
        let mut source_routes: HashMap<Ipv4Addr, Vec<spf::SpfRoute>> = HashMap::new();
        for source_area in &area_ids {
            let interfaces: Vec<spf::SpfInterface> = self
                .interfaces
                .iter()
                .filter(|i| i.state != InterfaceState::Down && i.area_id == *source_area)
                .map(|i| spf::SpfInterface {
                    address: i.address,
                    mask: i.mask,
                    sw_if_index: i.sw_if_index,
                    cost: i.cost,
                })
                .collect();
            if interfaces.is_empty() {
                continue;
            }
            let mut neighbors: Vec<spf::SpfNeighbor> = Vec::new();
            for iface in &self.interfaces {
                if iface.state == InterfaceState::Down || iface.area_id != *source_area {
                    continue;
                }
                for n in iface.neighbors.values() {
                    if n.state >= NeighborState::TwoWay {
                        neighbors.push(spf::SpfNeighbor {
                            router_id: n.router_id,
                            address: n.address,
                            sw_if_index: iface.sw_if_index,
                        });
                    }
                }
            }
            if let Some(area) = self.areas.get(source_area) {
                let lsa_map = area.lsdb.as_lsa_map();
                let routes = spf::calculate_spf(
                    self.router_id,
                    &lsa_map,
                    &interfaces,
                    &neighbors,
                );
                source_routes.insert(*source_area, routes);
            }
        }

        // Stub areas: originate a default-route Summary-LSA (0.0.0.0/0)
        // in each stub area we participate in. RFC 2328 Section 12.4.3.
        for dest_area_id in &area_ids {
            let Some(dest_area) = self.areas.get(dest_area_id) else {
                continue;
            };
            if dest_area.area_type == crate::area::AreaType::Normal {
                continue;
            }
            // Only ABRs inject the default
            if !self.is_abr() {
                continue;
            }
            let default_cost = dest_area.default_cost;
            let default_lsa_key = LsaKey {
                ls_type: LsaType::SummaryNetwork,
                link_state_id: Ipv4Addr::UNSPECIFIED,
                advertising_router: self.router_id,
            };
            let dest_area_mut = self.areas.get_mut(dest_area_id).unwrap();
            let seq = match dest_area_mut.lsdb.get(&default_lsa_key) {
                Some(e) => e.lsa.header.ls_sequence_number.wrapping_add(1),
                None => INITIAL_SEQUENCE_NUMBER,
            };
            let body = SummaryLsa {
                network_mask: Ipv4Addr::UNSPECIFIED,
                metric: default_cost,
            };
            let mut body_buf = Vec::new();
            body.encode(&mut body_buf);
            let length = lsa_total_length(body_buf.len());
            let lsa = Lsa {
                header: LsaHeader {
                    ls_age: 0,
                    options: OspfOptions::standard().0,
                    ls_type: LsaType::SummaryNetwork,
                    link_state_id: Ipv4Addr::UNSPECIFIED,
                    advertising_router: self.router_id,
                    ls_sequence_number: seq,
                    ls_checksum: 0,
                    length,
                },
                body: LsaBody::Summary(body),
            };
            let encoded = lsa.encode();
            if let Ok(with_cksum) = Lsa::parse(&encoded) {
                dest_area_mut.lsdb.install(with_cksum.clone());
                originated.push((*dest_area_id, with_cksum));
            }
        }

        // For each (source, destination) area pair, originate Type 3 LSAs in
        // the destination summarizing routes from the source.
        for source_area in &area_ids {
            let Some(routes) = source_routes.get(source_area) else {
                continue;
            };
            for dest_area in &area_ids {
                if source_area == dest_area {
                    continue;
                }
                // RFC 2328 Section 12.4.3: only originate into backbone, or only
                // out of backbone (depending on dest area type). For Phase 2 we
                // originate everything in both directions for normal areas.

                let Some(area) = self.areas.get_mut(dest_area) else {
                    continue;
                };

                for route in routes {
                    // Skip routes whose prefix matches one of our own interfaces
                    // in the destination area (would create a loop)
                    let already_local = self.interfaces.iter().any(|i| {
                        i.area_id == *dest_area
                            && apply_mask(i.address, i.mask) == route.prefix
                    });
                    if already_local {
                        continue;
                    }

                    let mask = prefix_len_to_mask(route.prefix_len);
                    let body = SummaryLsa {
                        network_mask: mask,
                        metric: route.cost,
                    };

                    let mut body_buf = Vec::new();
                    body.encode(&mut body_buf);
                    let length = lsa_total_length(body_buf.len());

                    let key = LsaKey {
                        ls_type: LsaType::SummaryNetwork,
                        link_state_id: route.prefix,
                        advertising_router: self.router_id,
                    };
                    // Determine sequence number (increment if existing)
                    let seq = match area.lsdb.get(&key) {
                        Some(e) => e.lsa.header.ls_sequence_number.wrapping_add(1),
                        None => INITIAL_SEQUENCE_NUMBER,
                    };

                    let lsa = Lsa {
                        header: LsaHeader {
                            ls_age: 0,
                            options: OspfOptions::standard().0,
                            ls_type: LsaType::SummaryNetwork,
                            link_state_id: route.prefix,
                            advertising_router: self.router_id,
                            ls_sequence_number: seq,
                            ls_checksum: 0,
                            length,
                        },
                        body: LsaBody::Summary(body),
                    };

                    let encoded = lsa.encode();
                    let with_cksum = match Lsa::parse(&encoded) {
                        Ok(l) => l,
                        Err(_) => continue,
                    };
                    area.lsdb.install(with_cksum.clone());
                    originated.push((*dest_area, with_cksum));
                }
            }
        }

        originated
    }

    /// Originate Type 5 (AS-External) LSAs for redistributed routes.
    ///
    /// Caller is responsible for discovering the prefix set: typically
    /// VPP interfaces that are NOT enrolled in any OSPF area. See
    /// `discover_externals_v4` in `main.rs` for the production
    /// callsite. Each (prefix, mask) tuple becomes one Type 5 LSA
    /// keyed on the prefix as link-state-id. Existing LSAs for the
    /// same key are refreshed with a bumped sequence number; entries
    /// removed from the input set are MaxAge-flushed.
    ///
    /// Only "connected" redistribution is honored today. The metric
    /// and metric-type come from the matching `redistribute` entry.
    ///
    /// Returns a list of newly originated Type 5 LSAs that need to be
    /// flooded to all neighbors in non-stub areas.
    pub fn originate_external_lsas(
        &mut self,
        redistribute: &[crate::config::RedistributeConfig],
        externals: &[(Ipv4Addr, Ipv4Addr)],
        summaries: &[crate::config::ParsedSummaryAddress],
    ) -> Vec<Lsa> {
        let connected = redistribute
            .iter()
            .find(|r| r.source == crate::config::RedistributeSource::Connected);
        let Some(cfg) = connected else {
            // No connected redistribution: flush anything we'd previously
            // originated in case the user just disabled it at runtime.
            self.flush_self_externals_outside(&[]);
            return Vec::new();
        };

        // Resolve the optional route-map by name. If the rule
        // references a name we don't know, treat as deny-all
        // (operator typo shouldn't silently leak routes).
        let route_map = match &cfg.route_map {
            None => None,
            Some(name) => match self.route_maps.get(name) {
                Some(m) => Some(m.clone()),
                None => {
                    tracing::warn!(
                        route_map = %name,
                        "redistribute references unknown route-map; treating as deny"
                    );
                    self.flush_self_externals_outside(&[]);
                    return Vec::new();
                }
            },
        };

        // Filter externals to those NOT covered by a configured
        // summary range. Components inside a summary are suppressed
        // regardless of the summary's no_advertise flag — that flag
        // only controls whether the aggregate itself is emitted (in
        // originate_summary_address_lsas), not the suppression
        // behavior. Matches Cisco/Juniper semantics for
        // \`summary-address X.X.X.X/N\` and
        // \`summary-address X.X.X.X/N not-advertise\`.
        // The route-map (if any) runs alongside summary suppression:
        // a prefix must pass both the summary check and the map.
        let kept: Vec<(Ipv4Addr, Ipv4Addr)> = externals
            .iter()
            .copied()
            .filter(|(prefix, mask)| {
                if let Some(s) = summaries
                    .iter()
                    .find(|s| prefix_covered_by(*prefix, s.prefix, s.prefix_len))
                {
                    tracing::debug!(
                        prefix = %prefix,
                        summary = %format!("{}/{}", s.prefix, s.prefix_len),
                        "suppressing component external — covered by summary range"
                    );
                    return false;
                }
                if let Some(rm) = &route_map {
                    let len = mask_to_prefix_len_v4(*mask);
                    let ribd_pfx = ribd_proto::Prefix::v4(*prefix, len);
                    if !evaluate_route_map(rm, ribd_pfx, ribd_proto::Source::Connected) {
                        tracing::debug!(
                            prefix = %prefix,
                            route_map = %rm.name,
                            "route-map denied external"
                        );
                        return false;
                    }
                }
                true
            })
            .collect();

        // MaxAge-flush any previously-self-originated Type 5 whose
        // link-state-id (the prefix) is no longer in the kept set.
        // Summary aggregates at their own link-state-ids must be
        // preserved — they're managed by originate_summary_address_lsas.
        // Default-route Type 5 (link_state_id = 0.0.0.0) likewise.
        let mut keep_keys: Vec<Ipv4Addr> = kept.iter().map(|(p, _)| *p).collect();
        for s in summaries {
            keep_keys.push(s.prefix);
        }
        keep_keys.push(Ipv4Addr::UNSPECIFIED); // default route
        self.flush_self_externals_outside(&keep_keys);

        let mut originated = Vec::new();
        for (prefix, mask) in &kept {
            let key = LsaKey {
                ls_type: LsaType::AsExternal,
                link_state_id: *prefix,
                advertising_router: self.router_id,
            };

            let seq = match self.as_external_lsdb.get(&key) {
                Some(e) => e.lsa.header.ls_sequence_number.wrapping_add(1),
                None => INITIAL_SEQUENCE_NUMBER,
            };

            let body = AsExternalLsa {
                network_mask: *mask,
                metric_type_2: cfg.metric_type == 2,
                metric: cfg.metric,
                forwarding_address: Ipv4Addr::UNSPECIFIED,
                external_route_tag: 0,
            };

            let mut body_buf = Vec::new();
            body.encode(&mut body_buf);
            let length = lsa_total_length(body_buf.len());

            let lsa = Lsa {
                header: LsaHeader {
                    ls_age: 0,
                    options: OspfOptions::standard().0,
                    ls_type: LsaType::AsExternal,
                    link_state_id: *prefix,
                    advertising_router: self.router_id,
                    ls_sequence_number: seq,
                    ls_checksum: 0,
                    length,
                },
                body: LsaBody::AsExternal(body),
            };

            let encoded = lsa.encode();
            let with_cksum = match Lsa::parse(&encoded) {
                Ok(l) => l,
                Err(_) => continue,
            };
            self.as_external_lsdb.install(with_cksum.clone());
            originated.push(with_cksum);
        }

        originated
    }

    /// MaxAge-flush every self-originated AS-External LSA whose
    /// link-state-id (the prefix) is NOT in `keep`. Used by
    /// `originate_external_lsas` to withdraw prefixes that disappear
    /// from the input set between refresh ticks. Mirrors the v3
    /// `flush_self_externals_outside` logic.
    fn flush_self_externals_outside(&mut self, keep: &[Ipv4Addr]) {
        use crate::packet::lsa::MAX_AGE;
        let router_id = self.router_id;
        let to_flush: Vec<LsaKey> = self
            .as_external_lsdb
            .all_headers()
            .into_iter()
            .filter(|h| {
                h.advertising_router == router_id && !keep.contains(&h.link_state_id)
            })
            .map(|h| LsaKey {
                ls_type: h.ls_type,
                link_state_id: h.link_state_id,
                advertising_router: h.advertising_router,
            })
            .collect();
        for key in to_flush {
            let Some(entry) = self.as_external_lsdb.get(&key).cloned() else {
                continue;
            };
            let mut lsa = entry.lsa.clone();
            lsa.header.ls_age = MAX_AGE;
            lsa.header.ls_sequence_number =
                lsa.header.ls_sequence_number.wrapping_add(1);
            // Re-encode + re-parse to refresh the checksum.
            let encoded = lsa.encode();
            let Ok(refreshed) = Lsa::parse(&encoded) else {
                continue;
            };
            self.as_external_lsdb.install(refreshed);
            tracing::info!(
                prefix = %key.link_state_id,
                "MaxAge-flushed withdrawn AS-External LSA"
            );
        }
    }

    /// Originate Type 5 aggregate LSAs for each configured
    /// summary-address. Phase 1: we emit the aggregate but do NOT
    /// suppress the component (matching-prefix) Type 5 LSAs —
    /// full exclusion is a follow-up. `no_advertise` entries are
    /// skipped entirely.
    pub fn originate_summary_address_lsas(
        &mut self,
        entries: &[crate::config::ParsedSummaryAddress],
    ) -> Vec<Lsa> {
        let mut out = Vec::new();
        for e in entries {
            if e.no_advertise {
                continue;
            }
            let mask = prefix_len_to_mask(e.prefix_len);
            let key = LsaKey {
                ls_type: LsaType::AsExternal,
                link_state_id: e.prefix,
                advertising_router: self.router_id,
            };
            let seq = match self.as_external_lsdb.get(&key) {
                Some(existing) => existing.lsa.header.ls_sequence_number.wrapping_add(1),
                None => INITIAL_SEQUENCE_NUMBER,
            };
            let body = AsExternalLsa {
                network_mask: mask,
                metric_type_2: e.metric_type == 2,
                metric: e.metric,
                forwarding_address: Ipv4Addr::UNSPECIFIED,
                external_route_tag: e.tag,
            };
            let mut body_buf = Vec::new();
            body.encode(&mut body_buf);
            let length = lsa_total_length(body_buf.len());
            let lsa = Lsa {
                header: LsaHeader {
                    ls_age: 0,
                    options: OspfOptions::standard().0,
                    ls_type: LsaType::AsExternal,
                    link_state_id: e.prefix,
                    advertising_router: self.router_id,
                    ls_sequence_number: seq,
                    ls_checksum: 0,
                    length,
                },
                body: LsaBody::AsExternal(body),
            };
            let encoded = lsa.encode();
            if let Ok(with_cksum) = Lsa::parse(&encoded) {
                self.as_external_lsdb.install(with_cksum.clone());
                out.push(with_cksum);
            }
        }
        out
    }

    /// Originate a Type 5 default-route LSA (0.0.0.0/0) — used when
    /// `ospf.default_originate` is set. Call separately from
    /// `originate_external_lsas` so the caller can opt in.
    pub fn originate_default_route_lsa(&mut self, metric: u32, metric_type: u8) -> Option<Lsa> {
        let prefix = Ipv4Addr::UNSPECIFIED;
        let mask = Ipv4Addr::UNSPECIFIED;
        let key = LsaKey {
            ls_type: LsaType::AsExternal,
            link_state_id: prefix,
            advertising_router: self.router_id,
        };
        let seq = match self.as_external_lsdb.get(&key) {
            Some(e) => e.lsa.header.ls_sequence_number.wrapping_add(1),
            None => INITIAL_SEQUENCE_NUMBER,
        };
        let body = AsExternalLsa {
            network_mask: mask,
            metric_type_2: metric_type == 2,
            metric,
            forwarding_address: Ipv4Addr::UNSPECIFIED,
            external_route_tag: 0,
        };
        let mut body_buf = Vec::new();
        body.encode(&mut body_buf);
        let length = lsa_total_length(body_buf.len());
        let lsa = Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: OspfOptions::standard().0,
                ls_type: LsaType::AsExternal,
                link_state_id: prefix,
                advertising_router: self.router_id,
                ls_sequence_number: seq,
                ls_checksum: 0,
                length,
            },
            body: LsaBody::AsExternal(body),
        };
        let encoded = lsa.encode();
        let with_cksum = Lsa::parse(&encoded).ok()?;
        self.as_external_lsdb.install(with_cksum.clone());
        Some(with_cksum)
    }

    /// Reconcile a refreshed snapshot of one interface's VPP state
    /// (address, prefix, admin/link up). Returns true if anything
    /// changed that requires re-originating LSAs and re-running SPF.
    ///
    /// Caller is responsible for the side effects (call
    /// originate_router_lsa() / schedule_spf() if true).
    pub fn refresh_interface_state(
        &mut self,
        sw_if_index: u32,
        new_address: Ipv4Addr,
        new_mask: Ipv4Addr,
        oper_up: bool,
    ) -> bool {
        use crate::proto::interface::{InterfaceEvent, InterfaceState};

        let Some(iface) = self
            .interfaces
            .iter_mut()
            .find(|i| i.sw_if_index == sw_if_index)
        else {
            return false;
        };

        let mut changed = false;

        // Address change
        if iface.address != new_address || iface.mask != new_mask {
            tracing::info!(
                name = %iface.name,
                old_addr = %iface.address,
                old_mask = %iface.mask,
                new_addr = %new_address,
                new_mask = %new_mask,
                "OSPFv2: interface address changed in VPP"
            );
            iface.address = new_address;
            iface.mask = new_mask;
            changed = true;
        }

        // Admin/link state change
        let was_up = iface.state != InterfaceState::Down;
        if oper_up && !was_up {
            tracing::info!(
                name = %iface.name,
                "OSPFv2: interface came up"
            );
            iface.handle_event(&InterfaceEvent::InterfaceUp);
            changed = true;
        } else if !oper_up && was_up {
            tracing::info!(
                name = %iface.name,
                "OSPFv2: interface went down — tearing down adjacencies"
            );
            iface.handle_event(&InterfaceEvent::InterfaceDown);
            changed = true;
        }

        changed
    }

    /// Schedule an SPF calculation with exponential backoff throttling.
    pub fn schedule_spf(&mut self) {
        let now = Instant::now();

        let delay = if let Some(last_run) = self.spf_last_run {
            let since_last = now.duration_since(last_run).as_millis() as u64;
            let hold = self.spf_holdtime_ms * (1 << self.spf_hold_multiplier.min(10));
            let hold = hold.min(self.spf_max_holdtime_ms);

            if since_last >= hold {
                // Enough time has passed — run with minimum delay
                self.spf_hold_multiplier = 0;
                Duration::from_millis(self.spf_delay_ms)
            } else {
                // Too soon — schedule at the hold time
                self.spf_hold_multiplier = self.spf_hold_multiplier.saturating_add(1);
                Duration::from_millis(hold - since_last)
            }
        } else {
            // First SPF — use minimum delay
            Duration::from_millis(self.spf_delay_ms)
        };

        let scheduled_at = now + delay;
        match self.spf_scheduled {
            Some(existing) if existing <= scheduled_at => {
                // Already scheduled sooner
            }
            _ => {
                self.spf_scheduled = Some(scheduled_at);
                tracing::debug!(delay_ms = delay.as_millis() as u64, "SPF scheduled");
            }
        }
    }

    /// Check if SPF should run now.
    pub fn spf_due(&self) -> Option<Instant> {
        self.spf_scheduled
    }

    /// Run SPF in every area we participate in and return the union of routes.
    ///
    /// Each area is computed independently using its own LSDB. Inter-area
    /// routes are computed from Type 3 (Summary-Network) LSAs after the
    /// intra-area SPF runs.
    pub fn run_spf(&mut self) -> Vec<spf::SpfRoute> {
        self.spf_scheduled = None;
        self.spf_last_run = Some(Instant::now());

        let mut all_routes = Vec::new();
        let mut total_lsdb_size = 0usize;

        let area_ids: Vec<Ipv4Addr> = self.areas.keys().copied().collect();

        for area_id in area_ids {
            let interfaces: Vec<spf::SpfInterface> = self
                .interfaces
                .iter()
                .filter(|i| i.state != InterfaceState::Down && i.area_id == area_id)
                .map(|i| spf::SpfInterface {
                    address: i.address,
                    mask: i.mask,
                    sw_if_index: i.sw_if_index,
                    cost: i.cost,
                })
                .collect();

            let mut neighbors: Vec<spf::SpfNeighbor> = Vec::new();
            for iface in &self.interfaces {
                if iface.state == InterfaceState::Down || iface.area_id != area_id {
                    continue;
                }
                for neighbor in iface.neighbors.values() {
                    if neighbor.state >= NeighborState::TwoWay {
                        neighbors.push(spf::SpfNeighbor {
                            router_id: neighbor.router_id,
                            address: neighbor.address,
                            sw_if_index: iface.sw_if_index,
                        });
                    }
                }
            }

            if interfaces.is_empty() {
                continue;
            }

            let Some(area) = self.areas.get(&area_id) else {
                continue;
            };
            let lsa_map = area.lsdb.as_lsa_map();
            total_lsdb_size += area.lsdb.entries_count();

            // Intra-area SPF + collect router paths (for inter-area calc)
            let (intra_routes, router_paths) = spf::calculate_spf_with_paths(
                self.router_id,
                &lsa_map,
                &interfaces,
                &neighbors,
            );

            tracing::info!(
                area = %area_id,
                routes = intra_routes.len(),
                lsdb_size = area.lsdb.entries_count(),
                "intra-area SPF complete"
            );
            all_routes.extend(intra_routes);

            // Inter-area route calculation (Section 16.2)
            let inter_routes = spf::calculate_inter_area_routes(&lsa_map, &router_paths);
            if !inter_routes.is_empty() {
                tracing::info!(
                    area = %area_id,
                    routes = inter_routes.len(),
                    "inter-area routes computed"
                );
                all_routes.extend(inter_routes);
            }
        }

        // Now calculate external (Type 5) routes. We aggregate router paths
        // from every area (for picking the best ASBR path across areas).
        //
        // Phase 2 simplification: we use the paths from the backbone area
        // only. A full implementation would take the best path across all
        // areas the ASBR appears in.
        let backbone = Ipv4Addr::UNSPECIFIED;
        let backbone_paths: HashMap<Ipv4Addr, (u32, spf::NextHop)> =
            if let Some(area) = self.areas.get(&backbone) {
                let interfaces: Vec<spf::SpfInterface> = self
                    .interfaces
                    .iter()
                    .filter(|i| i.state != InterfaceState::Down && i.area_id == backbone)
                    .map(|i| spf::SpfInterface {
                        address: i.address,
                        mask: i.mask,
                        sw_if_index: i.sw_if_index,
                        cost: i.cost,
                    })
                    .collect();
                let mut neighbors: Vec<spf::SpfNeighbor> = Vec::new();
                for iface in &self.interfaces {
                    if iface.state == InterfaceState::Down || iface.area_id != backbone {
                        continue;
                    }
                    for n in iface.neighbors.values() {
                        if n.state >= NeighborState::TwoWay {
                            neighbors.push(spf::SpfNeighbor {
                                router_id: n.router_id,
                                address: n.address,
                                sw_if_index: iface.sw_if_index,
                            });
                        }
                    }
                }
                if interfaces.is_empty() {
                    HashMap::new()
                } else {
                    let lsa_map = area.lsdb.as_lsa_map();
                    let (_, paths) = spf::calculate_spf_with_paths(
                        self.router_id,
                        &lsa_map,
                        &interfaces,
                        &neighbors,
                    );
                    paths
                }
            } else {
                HashMap::new()
            };

        let ext_map = self.as_external_lsdb.as_lsa_map();
        let ext_routes = spf::calculate_external_routes(&ext_map, &backbone_paths);
        if !ext_routes.is_empty() {
            tracing::info!(
                routes = ext_routes.len(),
                "AS-external routes computed"
            );
            all_routes.extend(ext_routes);
        }

        tracing::info!(
            total_routes = all_routes.len(),
            total_lsdb_size,
            "SPF calculation complete"
        );

        all_routes
    }

    /// Periodic LSDB maintenance: refresh self-originated LSAs near LSRefreshTime,
    /// purge MaxAge LSAs, etc.
    ///
    /// Returns true if any LSAs were re-originated (caller should schedule SPF
    /// and flood the new LSAs).
    pub fn periodic_maintenance(
        &mut self,
        responses: &mut Vec<(u32, Ipv4Addr, OspfPacket)>,
    ) -> bool {
        let mut changed = false;

        // Refresh self-originated LSAs that have aged past LSRefreshTime
        // (across all areas).
        let area_ids: Vec<Ipv4Addr> = self.areas.keys().copied().collect();
        let mut any_refresh_due = false;
        for area_id in &area_ids {
            if let Some(area) = self.areas.get(area_id) {
                if !area.lsdb.self_originated_due_for_refresh().is_empty() {
                    any_refresh_due = true;
                    break;
                }
            }
        }

        if any_refresh_due {
            tracing::info!("refreshing self-originated LSAs");
            let new_lsas = self.originate_router_lsas();
            for (_area_id, lsa) in new_lsas {
                self.flood_lsas_to_others(usize::MAX, self.router_id, &[lsa], responses);
            }
            changed = true;
        }

        // Purge MaxAge LSAs from each area's database
        let mut total_purged = 0usize;
        for area_id in &area_ids {
            if let Some(area) = self.areas.get_mut(area_id) {
                let purged = area.lsdb.flush_max_age();
                total_purged += purged.len();
            }
        }
        // Same purge sweep for AS-external LSAs (Type 5). The
        // re-origination decision for Type-5 lives on the daemon
        // side (it needs to walk VPP to re-discover externals) —
        // see `as_external_refresh_due` and the daemon's
        // lsdb_tick handler.
        let ext_purged = self.as_external_lsdb.flush_max_age();
        if !ext_purged.is_empty() {
            tracing::info!(
                count = ext_purged.len(),
                "purged MaxAge AS-external LSAs",
            );
            total_purged += ext_purged.len();
        }
        if total_purged > 0 {
            changed = true;
        }

        changed
    }

    /// True when any self-originated AS-external LSA (Type 5) has
    /// aged past LSRefreshTime and is due for re-origination. Used
    /// by the daemon's periodic tick to gate the externals
    /// re-discovery + re-originate path — that path is expensive
    /// (one VPP API dump per call) so we only run it when an LSA
    /// actually needs to flood.
    ///
    /// Without this hook the Type-5 refresh path never fires from
    /// inside `periodic_maintenance` (which only sees area LSDBs),
    /// and self-originated externals age to MaxAge (1h) and get
    /// flushed from every peer's LSDB — silently dropping every
    /// redistributed prefix from downstream routing tables.
    pub fn as_external_refresh_due(&self) -> bool {
        !self.as_external_lsdb.self_originated_due_for_refresh().is_empty()
    }

    /// Check all neighbors for inactivity timer expiry.
    pub fn check_neighbor_timers(&mut self) -> bool {
        let mut changed = false;

        for iface in &mut self.interfaces {
            let dead_duration = iface.dead_duration();
            let expired: Vec<Ipv4Addr> = iface
                .neighbors
                .iter()
                .filter(|(_, n)| {
                    n.state != NeighborState::Down && n.last_heard.elapsed() >= dead_duration
                })
                .map(|(id, _)| *id)
                .collect();

            for neighbor_id in expired {
                tracing::warn!(
                    interface = %iface.name,
                    neighbor = %neighbor_id,
                    "inactivity timer expired"
                );
                let mut crossed_two_way = false;
                if let Some(neighbor) = iface.neighbors.get_mut(&neighbor_id) {
                    let was_two_way_plus = neighbor.state >= NeighborState::TwoWay;
                    neighbor.handle_event(&NeighborEvent::InactivityTimer, false);
                    let is_two_way_plus = neighbor.state >= NeighborState::TwoWay;
                    crossed_two_way = was_two_way_plus && !is_two_way_plus;
                    changed = true;
                }
                // Dropping a bidirectional relationship must trigger
                // DR re-election; otherwise we can stay Backup with
                // nobody left acting as DR.
                if crossed_two_way {
                    iface.handle_event(&InterfaceEvent::NeighborChange);
                }
            }
        }

        changed
    }

    /// Find the interface index for a given sw_if_index.
    fn find_interface(&self, sw_if_index: u32) -> Option<usize> {
        self.interfaces
            .iter()
            .position(|i| i.sw_if_index == sw_if_index)
    }

    /// Apply a freshly-parsed `OspfDaemonConfig` over the live
    /// instance, mutating what can be changed without bouncing
    /// adjacencies. Returns true if anything changed (caller should
    /// schedule SPF / flood the re-originated Router-LSAs).
    ///
    /// Scope for this v1:
    ///
    /// - Per-interface `cost`, `priority`, `hello_interval`,
    ///   `dead_interval`, `retransmit_interval`, `passive` —
    ///   patched in place. Changing cost forces a Router-LSA
    ///   re-origination so peers pick up the new metric.
    /// - `summary_addresses` — replaced wholesale (caller should
    ///   re-run origination so the ASE LSDB reflects the new set).
    /// - `redistribute` — list replaced (main loop picks up the
    ///   new sources on the next push).
    /// - `distance` / per-sub-type admin distance — copied over so
    ///   the next RIB push uses the new AD.
    ///
    /// Out of scope (operator must restart to apply):
    ///
    /// - `router_id`, area add/remove, interface add/remove,
    ///   area_type / stub-default-cost changes, auth key changes.
    ///   We ignore these fields here; the daemon keeps running
    ///   with the old values and logs a warning listing what the
    ///   operator needs to restart for.
    pub fn reload_config(&mut self, new: &OspfDaemonConfig) -> bool {
        use crate::proto::interface::NetworkType;

        let mut changed = false;
        let mut router_lsa_dirty = false;

        if self.router_id != new.router_id {
            tracing::warn!(
                old_router_id = %self.router_id,
                new_router_id = %new.router_id,
                "reload: router_id change requires daemon restart; ignoring"
            );
        }

        // Per-interface patch.
        for new_iface in &new.interfaces {
            let Some(live) = self
                .interfaces
                .iter_mut()
                .find(|i| i.name == new_iface.name)
            else {
                tracing::warn!(
                    name = %new_iface.name,
                    "reload: interface is new in config but daemon restart needed to add it"
                );
                continue;
            };

            if live.area_id != new_iface.area_id {
                tracing::warn!(
                    name = %live.name,
                    old = %live.area_id,
                    new = %new_iface.area_id,
                    "reload: area_id change requires restart; ignoring"
                );
            }

            let new_net_type = match new_iface.network_type.as_str() {
                "point-to-point" => NetworkType::PointToPoint,
                "point-to-multipoint" => NetworkType::PointToMultipoint,
                "non-broadcast" => NetworkType::NonBroadcast,
                _ => NetworkType::Broadcast,
            };
            if live.network_type != new_net_type {
                tracing::warn!(
                    name = %live.name,
                    "reload: network_type change requires restart; ignoring"
                );
            }

            if live.cost != new_iface.cost {
                tracing::info!(
                    name = %live.name,
                    old = live.cost,
                    new = new_iface.cost,
                    "reload: cost"
                );
                live.cost = new_iface.cost;
                router_lsa_dirty = true;
                changed = true;
            }
            if live.priority != new_iface.priority {
                tracing::info!(
                    name = %live.name,
                    old = live.priority,
                    new = new_iface.priority,
                    "reload: priority"
                );
                live.priority = new_iface.priority;
                changed = true;
            }
            if live.hello_interval != new_iface.hello_interval {
                tracing::info!(
                    name = %live.name,
                    old = live.hello_interval,
                    new = new_iface.hello_interval,
                    "reload: hello_interval"
                );
                live.hello_interval = new_iface.hello_interval;
                changed = true;
            }
            if live.dead_interval != new_iface.dead_interval {
                tracing::info!(
                    name = %live.name,
                    old = live.dead_interval,
                    new = new_iface.dead_interval,
                    "reload: dead_interval"
                );
                live.dead_interval = new_iface.dead_interval;
                changed = true;
            }
            if live.rxmt_interval != new_iface.retransmit_interval {
                live.rxmt_interval = new_iface.retransmit_interval;
                changed = true;
            }
            if live.passive != new_iface.passive {
                tracing::info!(
                    name = %live.name,
                    passive = new_iface.passive,
                    "reload: passive flag"
                );
                live.passive = new_iface.passive;
                router_lsa_dirty = true;
                changed = true;
            }
        }

        // Note interfaces that disappeared — out of scope to tear
        // down live, but log so it's not silent.
        for live in &self.interfaces {
            if !new.interfaces.iter().any(|n| n.name == live.name) {
                tracing::warn!(
                    name = %live.name,
                    "reload: interface removed in config but daemon restart needed to tear it down"
                );
            }
        }

        // Summary addresses — replace wholesale. Origination
        // happens on the next SPF / periodic origination cycle.
        if self.summary_addresses.len() != new.summary_addresses.len()
            || self
                .summary_addresses
                .iter()
                .zip(new.summary_addresses.iter())
                .any(|(a, b)| {
                    a.prefix != b.prefix
                        || a.prefix_len != b.prefix_len
                        || a.no_advertise != b.no_advertise
                        || a.metric != b.metric
                        || a.metric_type != b.metric_type
                        || a.tag != b.tag
                })
        {
            tracing::info!(
                old = self.summary_addresses.len(),
                new = new.summary_addresses.len(),
                "reload: summary_addresses replaced"
            );
            self.summary_addresses = new.summary_addresses.clone();
            changed = true;
        }

        // Redistribute — copy across so the next SPF / origination
        // cycle picks up the new sources.
        if self.redistribute.len() != new.redistribute.len()
            || self
                .redistribute
                .iter()
                .zip(new.redistribute.iter())
                .any(|(a, b)| {
                    a.source != b.source
                        || a.metric != b.metric
                        || a.metric_type != b.metric_type
                })
        {
            tracing::info!(
                old = self.redistribute.len(),
                new = new.redistribute.len(),
                "reload: redistribute replaced"
            );
            let was_asbr = !self.redistribute.is_empty();
            let is_asbr = !new.redistribute.is_empty();
            self.redistribute = new.redistribute.clone();
            changed = true;
            // Flip ASBR state means the Router-LSA's E flag needs
            // refreshing in every area we participate in so peers
            // can (or can no longer) compute SPF paths to us as an
            // ASBR — otherwise our Type-5 LSAs are advertised but
            // never installed downstream.
            if was_asbr != is_asbr {
                router_lsa_dirty = true;
            }
        }

        if router_lsa_dirty {
            // Re-originate in every area we participate in so
            // cost/passive changes propagate. originate_router_lsas
            // bumps seq and updates LSDB; the caller is expected
            // to schedule SPF + flood.
            let _ = self.originate_router_lsas();
            self.schedule_spf();
        }

        changed
    }
}

/// Convert prefix length to network mask.
/// Convert a 4-octet network mask back into a CIDR prefix length.
/// Counts leading 1-bits — the OSPF Type 5 wire encoding carries
/// the mask, but the route-map evaluator wants a length.
fn mask_to_prefix_len_v4(mask: Ipv4Addr) -> u8 {
    u32::from(mask).leading_ones() as u8
}

/// Walk the statements of a compiled route-map and return whether
/// the route is permitted. Universal-clause-only in v1; ospfd
/// extras (`E = NoExtras`) are vacuously satisfied. No-statement-
/// matched defaults to deny, matching FRR/Cisco semantics and the
/// bgpd implementation in `bgpd::instance`. Shared with the v3
/// origination path (`instance_v3.rs`) so both AFIs evaluate maps
/// identically.
pub(crate) fn evaluate_route_map(
    map: &ribd_routemap::RouteMap,
    prefix: ribd_proto::Prefix,
    source: ribd_proto::Source,
) -> bool {
    struct Ctx {
        prefix: ribd_proto::Prefix,
        source: ribd_proto::Source,
    }
    impl ribd_routemap::MatchContext for Ctx {
        fn prefix(&self) -> ribd_proto::Prefix {
            self.prefix
        }
        fn source(&self) -> ribd_proto::Source {
            self.source
        }
    }
    let ctx = Ctx { prefix, source };
    for stmt in &map.statements {
        if !stmt.match_.evaluate_universal(&ctx) {
            continue;
        }
        return matches!(stmt.action, ribd_routemap::Action::Permit);
    }
    false
}

fn prefix_len_to_mask(len: u8) -> Ipv4Addr {
    if len == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let mask = !0u32 << (32 - len);
    Ipv4Addr::from(mask)
}

/// Apply a network mask to an address.
fn apply_mask(addr: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    let a = u32::from(addr);
    let m = u32::from(mask);
    Ipv4Addr::from(a & m)
}

/// Returns true if `addr` is contained within the prefix
/// `summary_prefix/summary_len`. Used to suppress component Type 5
/// LSAs that fall inside a configured summary range.
fn prefix_covered_by(addr: Ipv4Addr, summary_prefix: Ipv4Addr, summary_len: u8) -> bool {
    if summary_len == 0 {
        return true;
    }
    if summary_len > 32 {
        return false;
    }
    let mask: u32 = (!0u32) << (32 - summary_len);
    (u32::from(addr) & mask) == (u32::from(summary_prefix) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_len_to_mask() {
        assert_eq!(prefix_len_to_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_len_to_mask(30), Ipv4Addr::new(255, 255, 255, 252));
        assert_eq!(prefix_len_to_mask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(prefix_len_to_mask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(prefix_len_to_mask(0), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_build_hello() {
        let config = OspfDaemonConfig {
            vrf_name: None,
            table_id_v4: 0,
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            reference_bandwidth: 100,
            spf_delay_ms: 50,
            spf_holdtime_ms: 200,
            spf_max_holdtime_ms: 5000,
            interfaces: vec![crate::config::OspfInterfaceConfig {
                name: "wan".to_string(),
                address: Ipv4Addr::new(10, 0, 0, 1),
                prefix_len: 24,
                area_id: Ipv4Addr::UNSPECIFIED,
                cost: 10,
                passive: false,
                network_type: "broadcast".to_string(),
                hello_interval: 10,
                dead_interval: 40,
                retransmit_interval: 5,
                priority: 1,
                auth_key: crate::packet::auth::AuthKey::None,
                static_neighbors: Vec::new(),
            }],
            redistribute: Vec::new(),
            areas: Vec::new(),
            distance: None,
            distance_intra: None,
            distance_inter: None,
            distance_external: None,
            default_originate: false,
            default_originate_metric: 1,
            default_originate_metric_type: 2,
            summary_addresses: Vec::new(),
            route_maps: std::collections::HashMap::new(),
        };

        let instance = OspfInstance::new(&config);
        assert_eq!(instance.interfaces.len(), 1);

        let hello_pkt = instance.build_hello(&instance.interfaces[0]);
        let encoded = hello_pkt.encode();
        assert!(verify_ospf_checksum(&encoded));

        match hello_pkt {
            OspfPacket::Hello(header, hello) => {
                assert_eq!(header.router_id, Ipv4Addr::new(1, 1, 1, 1));
                assert_eq!(hello.hello_interval, 10);
                assert_eq!(hello.router_dead_interval, 40);
            }
            _ => panic!("expected Hello"),
        }
    }

    /// Regression test for the ExchangeDone oscillation bug (2026-04-14):
    ///
    /// Previously, when a lower-RID slave sent its first post-negotiation
    /// DD with M=0 (because its LSDB fit in a single empty/small packet),
    /// the master would fire ExchangeDone immediately upon receipt — before
    /// ever transmitting a DD describing its own LSDB. The slave would
    /// then sit in Exchange forever, waiting for the master's headers.
    ///
    /// The fix: ExchangeDone in the master path now requires both peer
    /// M=0 AND our own `sent_m_clear == true` (we must have emitted at
    /// least one DD carrying our final chunk of headers with M=0).
    #[test]
    fn dd_master_defers_exchange_done_until_own_dd_sent() {
        use crate::packet::dd::{DbDescPacket, DD_FLAG_MS};
        use crate::packet::OspfHeader;

        let config = OspfDaemonConfig {
            vrf_name: None,
            table_id_v4: 0,
            // High router-id — we'll be master.
            router_id: Ipv4Addr::new(10, 0, 0, 2),
            reference_bandwidth: 100,
            spf_delay_ms: 50,
            spf_holdtime_ms: 200,
            spf_max_holdtime_ms: 5000,
            interfaces: vec![crate::config::OspfInterfaceConfig {
                name: "wan".to_string(),
                address: Ipv4Addr::new(10, 0, 0, 2),
                prefix_len: 24,
                area_id: Ipv4Addr::UNSPECIFIED,
                cost: 10,
                passive: false,
                network_type: "broadcast".to_string(),
                hello_interval: 10,
                dead_interval: 40,
                retransmit_interval: 5,
                priority: 1,
                auth_key: crate::packet::auth::AuthKey::None,
                static_neighbors: Vec::new(),
            }],
            redistribute: Vec::new(),
            areas: Vec::new(),
            distance: None,
            distance_intra: None,
            distance_inter: None,
            distance_external: None,
            default_originate: false,
            default_originate_metric: 1,
            default_originate_metric_type: 2,
            summary_addresses: Vec::new(),
            route_maps: std::collections::HashMap::new(),
        };
        let mut instance = OspfInstance::new(&config);
        instance.interfaces[0].state = InterfaceState::DR;
        instance.interfaces[0].dr = Ipv4Addr::new(10, 0, 0, 2);

        // Lower-RID peer in ExStart, is_master=false (peer is slave).
        let peer_rid = Ipv4Addr::new(10, 0, 0, 1);
        let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
        let mut neighbor = Neighbor::new(peer_rid, peer_addr);
        neighbor.state = NeighborState::ExStart;
        // Our seed seq we sent in our initial I+M+MS DD.
        neighbor.dd_seq_number = 0x8000_0001;
        neighbor.priority = 1;
        instance.interfaces[0]
            .neighbors
            .insert(peer_rid, neighbor);

        // Add a Router-LSA to our area LSDB so build_dd has something
        // to describe. We reuse our own Router-LSA via originate.
        instance.originate_router_lsa();
        assert!(
            !instance
                .areas
                .get(&Ipv4Addr::UNSPECIFIED)
                .unwrap()
                .lsdb
                .all_headers()
                .is_empty(),
            "precondition: area LSDB must not be empty"
        );

        // Peer's post-negotiation DD: I=0, M=0, MS=0, echo our seq,
        // empty content (slave's LSDB happens to be small enough to
        // fit nothing in a single DD — the "M=0 on first content DD"
        // case that used to trip the bug).
        let peer_dd = DbDescPacket {
            interface_mtu: 1500,
            options: crate::packet::hello::OspfOptions::standard(),
            flags: 0, // I=0, M=0, MS=0
            dd_sequence_number: 0x8000_0001,
            lsa_headers: Vec::new(),
        };
        let peer_header = OspfHeader::new(
            OspfPacketType::DatabaseDescription,
            peer_rid,
            Ipv4Addr::UNSPECIFIED,
        );

        let mut responses = Vec::new();
        instance.process_dd(0, peer_addr, &peer_header, &peer_dd, &mut responses);

        // We must transition into Exchange, NOT jump all the way to
        // Loading/Full on the first DD exchange.
        let ns = instance.interfaces[0]
            .neighbors
            .get(&peer_rid)
            .unwrap();
        assert_eq!(
            ns.state,
            NeighborState::Exchange,
            "master must stay in Exchange until its own LSDB has been described"
        );
        assert!(ns.is_master, "we have the higher router-id, so we are master");
        assert!(
            ns.sent_m_clear,
            "build_dd should have fired once, emitting our M=0 final DD"
        );

        // And a response DD must have been queued for the peer, carrying
        // our content.
        let response_dd = responses
            .iter()
            .find_map(|(_sw, _dst, pkt)| match pkt {
                OspfPacket::DatabaseDescription(_h, d) => Some(d),
                _ => None,
            })
            .expect("process_dd must emit a DD response to peer");
        assert!(
            !response_dd.lsa_headers.is_empty(),
            "our content DD must carry at least our Router-LSA header"
        );
        assert!(
            (response_dd.flags & DD_FLAG_MS) != 0,
            "master DDs have MS=1"
        );
        // Now simulate the peer's follow-up empty M=0 DD echoing our
        // new sequence — THIS is when ExchangeDone should fire.
        let next_seq = instance.interfaces[0]
            .neighbors
            .get(&peer_rid)
            .unwrap()
            .dd_seq_number;
        let peer_ack = DbDescPacket {
            interface_mtu: 1500,
            options: crate::packet::hello::OspfOptions::standard(),
            flags: 0,
            dd_sequence_number: next_seq,
            lsa_headers: Vec::new(),
        };
        let mut responses2 = Vec::new();
        instance.process_dd(0, peer_addr, &peer_header, &peer_ack, &mut responses2);
        let final_state = instance.interfaces[0]
            .neighbors
            .get(&peer_rid)
            .unwrap()
            .state;
        assert!(
            final_state >= NeighborState::Loading,
            "second peer DD with M=0 should finally trigger ExchangeDone; got {final_state:?}"
        );
    }

    /// Verifies v2 P2MP Router-LSA generation: each Full neighbor
    /// must appear as a TYPE_POINT_TO_POINT link (link_id =
    /// neighbor router-id), plus exactly one host stub for our
    /// own /32 interface address.
    #[test]
    fn p2mp_router_lsa_emits_per_neighbor_host_links() {
        use crate::packet::lsa::{LsaBody, RouterLinkType};
        use crate::proto::interface::NetworkType;
        use crate::proto::neighbor::{Neighbor, NeighborState};

        let config = OspfDaemonConfig {
            vrf_name: None,
            table_id_v4: 0,
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            reference_bandwidth: 100,
            spf_delay_ms: 50,
            spf_holdtime_ms: 200,
            spf_max_holdtime_ms: 5000,
            interfaces: vec![crate::config::OspfInterfaceConfig {
                name: "p2mp0".to_string(),
                address: Ipv4Addr::new(10, 0, 0, 1),
                prefix_len: 24,
                area_id: Ipv4Addr::UNSPECIFIED,
                cost: 10,
                passive: false,
                network_type: "point-to-multipoint".to_string(),
                hello_interval: 30,
                dead_interval: 120,
                retransmit_interval: 5,
                priority: 1,
                auth_key: crate::packet::auth::AuthKey::None,
                static_neighbors: Vec::new(),
            }],
            redistribute: Vec::new(),
            areas: Vec::new(),
            distance: None,
            distance_intra: None,
            distance_inter: None,
            distance_external: None,
            default_originate: false,
            default_originate_metric: 1,
            default_originate_metric_type: 2,
            summary_addresses: Vec::new(),
            route_maps: std::collections::HashMap::new(),
        };
        let mut instance = OspfInstance::new(&config);
        // Verify the network_type parsed correctly.
        assert_eq!(
            instance.interfaces[0].network_type,
            NetworkType::PointToMultipoint
        );

        // Inject two Full peers on this segment.
        for (rid, addr) in [
            (Ipv4Addr::new(2, 2, 2, 2), Ipv4Addr::new(10, 0, 0, 2)),
            (Ipv4Addr::new(3, 3, 3, 3), Ipv4Addr::new(10, 0, 0, 3)),
        ] {
            let mut n = Neighbor::new(rid, addr);
            n.state = NeighborState::Full;
            instance.interfaces[0].neighbors.insert(rid, n);
        }
        instance.interfaces[0].state = InterfaceState::PointToPoint;

        // Originate the Router-LSA. It should contain:
        //   - 2 P2P link entries (one per peer)
        //   - 1 host stub for our own 10.0.0.1/32
        let lsas = instance.originate_router_lsas();
        assert_eq!(lsas.len(), 1);
        let LsaBody::Router(rlsa) = &lsas[0].1.body else {
            panic!("expected Router-LSA");
        };
        let p2p_links: Vec<_> = rlsa
            .links
            .iter()
            .filter(|l| l.link_type == RouterLinkType::PointToPoint)
            .collect();
        assert_eq!(p2p_links.len(), 2, "two P2P link entries (one per Full peer)");
        let stubs: Vec<_> = rlsa
            .links
            .iter()
            .filter(|l| l.link_type == RouterLinkType::StubNetwork)
            .collect();
        assert_eq!(stubs.len(), 1, "one host stub for our own /32");
        assert_eq!(stubs[0].link_id, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(stubs[0].link_data, Ipv4Addr::new(255, 255, 255, 255));
    }

    /// An instance with at least one redistribute entry must set
    /// the E (AS boundary router) flag in every Router-LSA it
    /// originates. Without this, peers see our Type-5 LSAs in their
    /// LSDB but refuse to install them (RFC 2328 §16.4): SPF can't
    /// classify the advertising router as an ASBR via the Router-
    /// LSA, so the Type-5's forwarding address resolution fails.
    #[test]
    fn router_lsa_sets_e_flag_when_redistribute_configured() {
        use crate::config::{RedistributeConfig, RedistributeSource};
        use crate::packet::lsa::{LsaBody, RouterLsa};

        let mut config = OspfDaemonConfig {
            vrf_name: None,
            table_id_v4: 0,
            router_id: Ipv4Addr::new(10, 100, 0, 18),
            reference_bandwidth: 100,
            spf_delay_ms: 50,
            spf_holdtime_ms: 200,
            spf_max_holdtime_ms: 5000,
            interfaces: vec![crate::config::OspfInterfaceConfig {
                name: "lan.110".to_string(),
                address: Ipv4Addr::new(192, 168, 37, 5),
                prefix_len: 24,
                area_id: Ipv4Addr::UNSPECIFIED,
                cost: 10,
                passive: false,
                network_type: "broadcast".to_string(),
                hello_interval: 10,
                dead_interval: 40,
                retransmit_interval: 5,
                priority: 1,
                auth_key: crate::packet::auth::AuthKey::None,
                static_neighbors: Vec::new(),
            }],
            redistribute: vec![RedistributeConfig {
                source: RedistributeSource::Connected,
                metric: 20,
                metric_type: 2,
                route_map: None,
            }],
            areas: Vec::new(),
            distance: None,
            distance_intra: None,
            distance_inter: None,
            distance_external: None,
            default_originate: false,
            default_originate_metric: 1,
            default_originate_metric_type: 2,
            summary_addresses: Vec::new(),
            route_maps: std::collections::HashMap::new(),
        };
        let mut instance = OspfInstance::new(&config);
        instance.interfaces[0].state = InterfaceState::Waiting;

        let lsas = instance.originate_router_lsas();
        assert!(!lsas.is_empty(), "should originate at least one Router-LSA");
        for (_, lsa) in &lsas {
            let LsaBody::Router(rlsa) = &lsa.body else {
                panic!("expected Router-LSA");
            };
            assert!(
                rlsa.flags & RouterLsa::E_FLAG != 0,
                "E flag must be set when redistribute is configured (flags=0x{:02x})",
                rlsa.flags,
            );
            assert!(
                rlsa.flags & RouterLsa::B_FLAG == 0,
                "B flag must NOT be set on a single-area instance (flags=0x{:02x})",
                rlsa.flags,
            );
        }

        // Toggle redistribute off via reload_config — the LSA's E
        // flag must clear on the next origination.
        config.redistribute.clear();
        let _ = instance.reload_config(&config);
        let lsas = instance.originate_router_lsas();
        for (_, lsa) in &lsas {
            let LsaBody::Router(rlsa) = &lsa.body else {
                panic!("expected Router-LSA");
            };
            assert!(
                rlsa.flags & RouterLsa::E_FLAG == 0,
                "E flag must clear when redistribute drops to empty (flags=0x{:02x})",
                rlsa.flags,
            );
        }
    }

    /// Verifies multi-DD paging: when our LSDB has more than
    /// MAX_HEADERS_PER_DD entries to describe, we must split the
    /// summary across multiple DDs with M=1 set on all but the
    /// final one. Without this, large LSDBs silently truncated to
    /// the first packet's worth of headers and peers never learned
    /// about the rest.
    #[test]
    fn dd_paging_splits_large_lsdb_across_multiple_dds() {
        use crate::config::{RedistributeConfig, RedistributeSource};

        let config = OspfDaemonConfig {
            vrf_name: None,
            table_id_v4: 0,
            router_id: Ipv4Addr::new(2, 2, 2, 2),
            reference_bandwidth: 100,
            spf_delay_ms: 50,
            spf_holdtime_ms: 200,
            spf_max_holdtime_ms: 5000,
            interfaces: vec![crate::config::OspfInterfaceConfig {
                name: "wan".to_string(),
                address: Ipv4Addr::new(10, 0, 0, 2),
                prefix_len: 24,
                area_id: Ipv4Addr::UNSPECIFIED,
                cost: 10,
                passive: false,
                network_type: "broadcast".to_string(),
                hello_interval: 10,
                dead_interval: 40,
                retransmit_interval: 5,
                priority: 1,
                auth_key: crate::packet::auth::AuthKey::None,
                static_neighbors: Vec::new(),
            }],
            redistribute: vec![RedistributeConfig {
                source: RedistributeSource::Connected,
                metric: 20,
                metric_type: 2,
                route_map: None,
            }],
            areas: Vec::new(),
            distance: None,
            distance_intra: None,
            distance_inter: None,
            distance_external: None,
            default_originate: false,
            default_originate_metric: 1,
            default_originate_metric_type: 2,
            summary_addresses: Vec::new(),
            route_maps: std::collections::HashMap::new(),
        };
        let mut instance = OspfInstance::new(&config);

        // Inject 150 distinct AS-External LSAs so the DD summary
        // exceeds the 60-header per-DD cap.
        let externals: Vec<(Ipv4Addr, Ipv4Addr)> = (0..150u8)
            .map(|i| {
                (
                    Ipv4Addr::new(100, 0, i, 0),
                    Ipv4Addr::new(255, 255, 255, 0),
                )
            })
            .collect();
        instance.originate_external_lsas(&config.redistribute, &externals, &[]);
        let lsdb_size = instance.as_external_lsdb.all_headers().len();
        assert_eq!(lsdb_size, 150);

        // Set up a peer in ExStart with us as master.
        let peer_rid = Ipv4Addr::new(1, 1, 1, 1);
        let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
        let mut neighbor = Neighbor::new(peer_rid, peer_addr);
        neighbor.state = NeighborState::ExStart;
        neighbor.dd_seq_number = 0x8000_0001;
        instance.interfaces[0]
            .neighbors
            .insert(peer_rid, neighbor);
        instance.interfaces[0].state = InterfaceState::DR;

        // Drive the slave-accepts-our-mastery DD.
        let peer_dd = crate::packet::dd::DbDescPacket {
            interface_mtu: 1500,
            options: crate::packet::hello::OspfOptions::standard(),
            flags: 0,
            dd_sequence_number: 0x8000_0001,
            lsa_headers: Vec::new(),
        };
        let peer_header = OspfHeader::new(
            OspfPacketType::DatabaseDescription,
            peer_rid,
            Ipv4Addr::UNSPECIFIED,
        );
        let mut responses = Vec::new();
        instance.process_dd(0, peer_addr, &peer_header, &peer_dd, &mut responses);

        // First DD response should carry M=1 (more to come) and
        // exactly 60 LSA headers.
        let first_dd = responses
            .iter()
            .find_map(|(_, _, p)| match p {
                OspfPacket::DatabaseDescription(_, d) => Some(d),
                _ => None,
            })
            .expect("first DD should have been emitted");
        assert!(
            first_dd.has_more(),
            "first DD must have M=1 — more chunks remain"
        );
        assert_eq!(first_dd.lsa_headers.len(), 60);
        assert!(
            !instance.interfaces[0].neighbors[&peer_rid].sent_m_clear,
            "sent_m_clear must NOT be true after the first chunk"
        );
        assert_eq!(
            instance.interfaces[0].neighbors[&peer_rid].db_summary_list.len(),
            90,
            "queue should have 150 - 60 = 90 headers remaining"
        );

        // Drain remaining chunks by simulating the peer ack-DD ping-pong.
        let mut total_headers_sent = first_dd.lsa_headers.len();
        let mut iterations = 0;
        while !instance.interfaces[0].neighbors[&peer_rid]
            .db_summary_list
            .is_empty()
            || !instance.interfaces[0].neighbors[&peer_rid].sent_m_clear
        {
            iterations += 1;
            assert!(iterations < 10, "should converge in well under 10 ticks");
            let next_seq =
                instance.interfaces[0].neighbors[&peer_rid].dd_seq_number;
            // Slave echoes our seq with empty content + M=1 (still
            // exchanging) until our queue is drained.
            let still_more = !instance.interfaces[0].neighbors[&peer_rid]
                .db_summary_list
                .is_empty();
            let peer_flags = if still_more {
                crate::packet::dd::DD_FLAG_M
            } else {
                0
            };
            let echo = crate::packet::dd::DbDescPacket {
                interface_mtu: 1500,
                options: crate::packet::hello::OspfOptions::standard(),
                flags: peer_flags,
                dd_sequence_number: next_seq,
                lsa_headers: Vec::new(),
            };
            let mut r = Vec::new();
            instance.process_dd(0, peer_addr, &peer_header, &echo, &mut r);
            for (_, _, p) in &r {
                if let OspfPacket::DatabaseDescription(_, d) = p {
                    total_headers_sent += d.lsa_headers.len();
                }
            }
        }
        assert_eq!(
            total_headers_sent, 150,
            "all 150 LSDB headers must reach the wire across multiple DDs"
        );
        assert!(
            instance.interfaces[0].neighbors[&peer_rid].sent_m_clear,
            "after queue drain, sent_m_clear must be true so peer M=0 ends Exchange"
        );
    }

    /// Regression test for the v2 Type 5 redistribution bug:
    /// `originate_external_lsas` used to walk `self.interfaces` (the
    /// OSPF-enrolled set) and emit a Type 5 for each prefix. That
    /// double-advertised every OSPF-enabled interface (once intra-
    /// area via Router-LSA stub link, once as Type 5 external).
    /// Fixed by taking the externals as an input parameter, leaving
    /// it to the daemon to discover non-enrolled prefixes.
    ///
    /// This test exercises the new shape: pass an externals list,
    /// verify Type 5s appear; shrink the list, verify the dropped
    /// prefixes get MaxAge-flushed.
    #[test]
    fn external_lsas_originated_from_input_set_and_flushed_on_shrink() {
        use crate::config::{RedistributeConfig, RedistributeSource};

        let config = OspfDaemonConfig {
            vrf_name: None,
            table_id_v4: 0,
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            reference_bandwidth: 100,
            spf_delay_ms: 50,
            spf_holdtime_ms: 200,
            spf_max_holdtime_ms: 5000,
            interfaces: Vec::new(),
            redistribute: vec![RedistributeConfig {
                source: RedistributeSource::Connected,
                metric: 20,
                metric_type: 2,
                route_map: None,
            }],
            areas: Vec::new(),
            distance: None,
            distance_intra: None,
            distance_inter: None,
            distance_external: None,
            default_originate: false,
            default_originate_metric: 1,
            default_originate_metric_type: 2,
            summary_addresses: Vec::new(),
            route_maps: std::collections::HashMap::new(),
        };
        let mut instance = OspfInstance::new(&config);

        let three: Vec<(Ipv4Addr, Ipv4Addr)> = vec![
            (Ipv4Addr::new(10, 1, 0, 0), Ipv4Addr::new(255, 255, 0, 0)),
            (Ipv4Addr::new(10, 2, 0, 0), Ipv4Addr::new(255, 255, 0, 0)),
            (Ipv4Addr::new(10, 3, 0, 0), Ipv4Addr::new(255, 255, 0, 0)),
        ];
        instance.originate_external_lsas(&config.redistribute, &three, &[]);

        // all_headers() filters out MaxAge entries by design (so peers
        // don't get them via DD), so we count via all_entries() to see
        // both alive and aged-out LSAs.
        let alive_count = |inst: &OspfInstance| -> usize {
            inst.as_external_lsdb
                .all_entries()
                .filter(|(_, e)| {
                    e.lsa.header.advertising_router == config.router_id && !e.is_max_age()
                })
                .count()
        };
        let max_age_count = |inst: &OspfInstance| -> usize {
            inst.as_external_lsdb
                .all_entries()
                .filter(|(_, e)| {
                    e.lsa.header.advertising_router == config.router_id && e.is_max_age()
                })
                .count()
        };

        assert_eq!(alive_count(&instance), 3, "three externals alive");
        assert_eq!(max_age_count(&instance), 0);

        // Shrink to one — the other two must be MaxAge-flushed.
        let one = vec![(Ipv4Addr::new(10, 1, 0, 0), Ipv4Addr::new(255, 255, 0, 0))];
        instance.originate_external_lsas(&config.redistribute, &one, &[]);
        assert_eq!(alive_count(&instance), 1);
        assert_eq!(max_age_count(&instance), 2);

        // Empty: everything we ever originated should be flushed.
        instance.originate_external_lsas(&config.redistribute, &[], &[]);
        assert_eq!(alive_count(&instance), 0);
        assert_eq!(max_age_count(&instance), 3);
    }

    /// Prefixes inside a configured summary range must NOT be
    /// emitted as their own component Type 5 LSAs — only the
    /// aggregate (which is emitted by originate_summary_address_lsas
    /// at a separate link-state-id) should be visible to peers.
    #[test]
    fn external_components_inside_summary_are_suppressed() {
        use crate::config::{
            ParsedSummaryAddress, RedistributeConfig, RedistributeSource,
        };

        let config = OspfDaemonConfig {
            vrf_name: None,
            table_id_v4: 0,
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            reference_bandwidth: 100,
            spf_delay_ms: 50,
            spf_holdtime_ms: 200,
            spf_max_holdtime_ms: 5000,
            interfaces: Vec::new(),
            redistribute: vec![RedistributeConfig {
                source: RedistributeSource::Connected,
                metric: 20,
                metric_type: 2,
                route_map: None,
            }],
            areas: Vec::new(),
            distance: None,
            distance_intra: None,
            distance_inter: None,
            distance_external: None,
            default_originate: false,
            default_originate_metric: 1,
            default_originate_metric_type: 2,
            summary_addresses: Vec::new(),
            route_maps: std::collections::HashMap::new(),
        };
        let mut instance = OspfInstance::new(&config);

        // 10.0.0.0/8 covers 10.1.0.0/16 and 10.2.0.0/16, so those
        // should be suppressed. 192.168.1.0/24 is outside the
        // range and should pass through.
        let summaries = vec![ParsedSummaryAddress {
            prefix: Ipv4Addr::new(10, 0, 0, 0),
            prefix_len: 8,
            no_advertise: false,
            tag: 0,
            metric: 100,
            metric_type: 2,
        }];
        let externals = vec![
            (Ipv4Addr::new(10, 1, 0, 0), Ipv4Addr::new(255, 255, 0, 0)),
            (Ipv4Addr::new(10, 2, 0, 0), Ipv4Addr::new(255, 255, 0, 0)),
            (
                Ipv4Addr::new(192, 168, 1, 0),
                Ipv4Addr::new(255, 255, 255, 0),
            ),
        ];
        let result =
            instance.originate_external_lsas(&config.redistribute, &externals, &summaries);
        assert_eq!(
            result.len(),
            1,
            "only the non-covered prefix should be emitted"
        );
        assert_eq!(result[0].header.link_state_id, Ipv4Addr::new(192, 168, 1, 0));

        // Verify the LSDB has just the one component Type 5
        // (no aggregate yet — that comes from a separate call).
        let alive: Vec<_> = instance
            .as_external_lsdb
            .all_entries()
            .filter(|(_, e)| {
                e.lsa.header.advertising_router == config.router_id && !e.is_max_age()
            })
            .collect();
        assert_eq!(alive.len(), 1);
        assert_eq!(alive[0].0.link_state_id, Ipv4Addr::new(192, 168, 1, 0));
    }

    #[test]
    fn prefix_covered_by_handles_edge_cases() {
        // Default (0/0) covers everything.
        assert!(prefix_covered_by(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::UNSPECIFIED,
            0
        ));
        // /32 only matches itself.
        assert!(prefix_covered_by(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            32
        ));
        assert!(!prefix_covered_by(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            32
        ));
        // /24 covers all hosts in subnet.
        assert!(prefix_covered_by(
            Ipv4Addr::new(10, 0, 0, 100),
            Ipv4Addr::new(10, 0, 0, 0),
            24
        ));
        // Non-matching higher bits.
        assert!(!prefix_covered_by(
            Ipv4Addr::new(11, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 0),
            8
        ));
    }

    fn compile_test_map(yaml: &str) -> ribd_routemap::RouteMap {
        let parsed: ribd_routemap::RouteMapYaml = serde_yaml::from_str(yaml).unwrap();
        parsed.compile().unwrap()
    }

    #[test]
    fn route_map_filters_externals_in_originate() {
        use crate::config::{
            OspfDaemonConfig, RedistributeConfig, RedistributeSource,
        };
        // Map permits the /24 we care about; denies everything else.
        let map = compile_test_map(
            r#"
name: edge-out
statements:
  - seq: 10
    action: permit
    match:
      prefix_list: ["10.0.0.0/24"]
  - seq: 20
    action: deny
"#,
        );
        let mut route_maps = std::collections::HashMap::new();
        route_maps.insert("edge-out".to_string(), map);

        let config = OspfDaemonConfig {
            vrf_name: None,
            table_id_v4: 0,
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            reference_bandwidth: 100,
            spf_delay_ms: 50,
            spf_holdtime_ms: 200,
            spf_max_holdtime_ms: 5000,
            interfaces: Vec::new(),
            redistribute: vec![RedistributeConfig {
                source: RedistributeSource::Connected,
                metric: 20,
                metric_type: 2,
                route_map: Some("edge-out".into()),
            }],
            areas: Vec::new(),
            distance: None,
            distance_intra: None,
            distance_inter: None,
            distance_external: None,
            default_originate: false,
            default_originate_metric: 1,
            default_originate_metric_type: 2,
            summary_addresses: Vec::new(),
            route_maps,
        };
        let mut instance = OspfInstance::new(&config);

        let externals = vec![
            // Permitted by route-map.
            (Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 0)),
            // Denied by the route-map (default-deny on no match).
            (Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(255, 255, 255, 0)),
        ];
        let lsas = instance.originate_external_lsas(&config.redistribute, &externals, &[]);
        // Only the permitted prefix should be originated.
        assert_eq!(lsas.len(), 1);
        assert_eq!(lsas[0].header.link_state_id, Ipv4Addr::new(10, 0, 0, 0));
    }

    #[test]
    fn unknown_route_map_name_is_treated_as_deny() {
        use crate::config::{
            OspfDaemonConfig, RedistributeConfig, RedistributeSource,
        };
        let config = OspfDaemonConfig {
            vrf_name: None,
            table_id_v4: 0,
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            reference_bandwidth: 100,
            spf_delay_ms: 50,
            spf_holdtime_ms: 200,
            spf_max_holdtime_ms: 5000,
            interfaces: Vec::new(),
            redistribute: vec![RedistributeConfig {
                source: RedistributeSource::Connected,
                metric: 20,
                metric_type: 2,
                route_map: Some("does-not-exist".into()),
            }],
            areas: Vec::new(),
            distance: None,
            distance_intra: None,
            distance_inter: None,
            distance_external: None,
            default_originate: false,
            default_originate_metric: 1,
            default_originate_metric_type: 2,
            summary_addresses: Vec::new(),
            route_maps: std::collections::HashMap::new(),
        };
        let mut instance = OspfInstance::new(&config);
        let externals = vec![(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 0),
        )];
        let lsas = instance.originate_external_lsas(&config.redistribute, &externals, &[]);
        assert!(lsas.is_empty());
    }

    #[test]
    fn evaluate_route_map_default_deny_on_no_match() {
        let map = compile_test_map(
            r#"
name: only-23
statements:
  - seq: 10
    action: permit
    match:
      prefix_list: ["23.0.0.0/8"]
"#,
        );
        let inside = ribd_proto::Prefix::v4(Ipv4Addr::new(23, 1, 0, 0), 8);
        let outside = ribd_proto::Prefix::v4(Ipv4Addr::new(10, 0, 0, 0), 8);
        assert!(evaluate_route_map(&map, inside, ribd_proto::Source::Connected));
        assert!(!evaluate_route_map(&map, outside, ribd_proto::Source::Connected));
    }

    #[test]
    fn mask_to_prefix_len_basic() {
        assert_eq!(
            mask_to_prefix_len_v4(Ipv4Addr::new(255, 255, 255, 0)),
            24
        );
        assert_eq!(
            mask_to_prefix_len_v4(Ipv4Addr::new(255, 0, 0, 0)),
            8
        );
        assert_eq!(mask_to_prefix_len_v4(Ipv4Addr::UNSPECIFIED), 0);
        assert_eq!(
            mask_to_prefix_len_v4(Ipv4Addr::new(255, 255, 255, 255)),
            32
        );
    }
}
