//! OSPFv3 protocol instance (skeleton).
//!
//! Minimal v3 instance: Hello send/receive, neighbor discovery,
//! inactivity timeout, 2-Way state, and DR/BDR election.
//!
//! Not yet implemented: DD exchange, LSU/LSR/LSAck, flooding, SPF,
//! LSDB synchronization, FIB programming. Those follow once we have
//! adjacency bring-up working on the wire.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::io_v3::{IoInterfaceV3, RxPacketV3, TxPacketV3};
use crate::lsdb_v3::{LsaEntryV3, LsdbV3};
use crate::packet::checksum::fletcher16;
use crate::packet_v3::dd::{DbDescV3Packet, DD_V3_FLAG_I, DD_V3_FLAG_M, DD_V3_FLAG_MS};
use crate::packet_v3::hello::{HelloV3Packet, Options, HELLO_V3_MIN_LEN};
use crate::packet_v3::header::{Ospfv3Header, Ospfv3PacketType, OSPFV3_HEADER_LEN};
use crate::packet_v3::lsa::{
    IntraAreaPrefixLsaV3, LinkLsaV3, LsaV3Header, LsaV3Type, NetworkLsaV3, RouterLinkV3,
    RouterLsaV3, INITIAL_SEQUENCE_NUMBER, LSA_V3_HEADER_LEN,
};
use crate::packet_v3::prefix::Ospfv3Prefix;
use crate::packet_v3::lsack::LsAckV3Packet;
use crate::packet_v3::lsr::{LsRequestV3, LsRequestV3Packet};
use crate::packet_v3::lsu::{LsUpdateV3Packet, LsaV3Raw};
use crate::packet_v3::{ALL_SPF_ROUTERS_V6, PacketV3Error};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NeighborStateV3 {
    Down,
    Init,
    TwoWay,
    ExStart,
    Exchange,
    Loading,
    Full,
}

#[derive(Debug)]
pub struct NeighborV3 {
    pub router_id: Ipv4Addr,
    pub interface_id: u32,
    pub link_local: Ipv6Addr,
    pub priority: u8,
    pub dr: Ipv4Addr,
    pub bdr: Ipv4Addr,
    pub state: NeighborStateV3,
    pub last_hello: Instant,
    /// Master/slave role for the DD exchange. True = we are master.
    pub dd_master: bool,
    /// Our current DD sequence number.
    pub dd_seq: u32,
    /// Headers from peer DDs we've received during Exchange.
    pub dd_summary_recv: Vec<LsaV3Header>,
    /// Our own DD header list remaining to send (unsent tail).
    pub dd_summary_tx: Vec<LsaV3Header>,
    /// Last DD packet we sent (for retransmit on drop).
    pub last_dd_tx: Option<DbDescV3Packet>,
    pub last_dd_sent: Instant,
    /// Set when we owe peer a DD response (after receiving one in
    /// Exchange). Cleared on emit. Independent of dd_summary_tx so we
    /// also send empty DDs to ack peer's mid-stream chunks.
    pub dd_response_pending: bool,
    /// LSAs we still need to request from this peer (Loading state).
    pub request_list: Vec<LsaV3Header>,
    /// Pending acks to send to this peer.
    pub pending_acks: Vec<LsaV3Header>,
    /// LSAs queued to send back in response to a LSR.
    pub pending_lsu: Vec<LsaV3Raw>,
    /// Whether we need to send a LSR for our request_list.
    pub lsr_pending: bool,
    /// Slave only: set when the slave has finished its DD exchange
    /// and must emit one final DD echo to the master before the
    /// neighbor state transitions fully (RFC 2328 §10.8). Cleared on
    /// emit in build_dd.
    pub dd_send_final: bool,
    /// Set when the peer sent a DD with M=0 — they have nothing more
    /// to send. Used by the master's finalization check: we can
    /// advance to Loading/Full only once both sides have drained.
    pub dd_peer_done: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceStateV3 {
    Down,
    Waiting,
    DR,
    Backup,
    DROther,
    PointToPoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkTypeV3 {
    Broadcast,
    PointToPoint,
    /// Non-Broadcast Multi-Access (RFC 5340 §2.4). Uses the same DR
    /// election FSM as Broadcast — the only difference is that
    /// Hellos are unicast to a statically-configured list of peer
    /// link-local addresses instead of multicast to ff02::5. Use
    /// when the underlying L2 segment can't carry IPv6 multicast.
    NonBroadcast,
    /// Point-to-Multipoint (RFC 5340 §2.4). Treats the segment as
    /// a collection of P2P adjacencies — no DR election, every
    /// neighbor forms a full adjacency, each adjacency gets a P2P
    /// link entry in the Router-LSA. Useful for hub-and-spoke
    /// topologies. Hellos are multicast to ff02::5.
    PointToMultipoint,
}

/// A statically-configured NBMA neighbor for OSPFv3. Populated from
/// `ospf6_neighbors`. in the config file at interface creation time.
#[derive(Debug, Clone)]
pub struct StaticNeighborV3 {
    /// Link-local IPv6 address — used as both unicast Hello
    /// destination and (since OSPFv3 keys neighbors by link-local
    /// address) as the identifier before the peer's first Hello
    /// reveals its router-id.
    pub link_local: Ipv6Addr,
    /// Priority used for DR election while we haven't received a
    /// live Hello from this neighbor.
    pub priority: u8,
}

pub struct InterfaceV3 {
    pub io: IoInterfaceV3,
    pub area_id: Ipv4Addr,
    pub interface_id: u32,
    pub network_type: NetworkTypeV3,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub retransmit_interval: u16,
    pub transmit_delay: u16,
    pub priority: u8,
    pub instance_id: u8,
    pub state: InterfaceStateV3,
    pub dr: Ipv4Addr,
    pub bdr: Ipv4Addr,
    pub neighbors: HashMap<Ipv4Addr, NeighborV3>,
    pub last_hello_sent: Instant,
    /// Set when adjacency state changed; instance-level tick will
    /// re-originate the Router-LSA.
    pub needs_router_lsa_refresh: bool,
    /// Global IPv6 prefixes attached to this interface, used for
    /// Intra-Area-Prefix-LSA origination.
    pub global_prefixes: Vec<(Ipv6Addr, u8)>,
    /// Statically-configured NBMA neighbors. Only populated when
    /// `network_type == NonBroadcast`. Hellos are unicast to each
    /// entry's link-local address.
    pub static_neighbors: Vec<StaticNeighborV3>,
}

pub struct InstanceV3 {
    pub router_id: Ipv4Addr,
    pub interfaces: HashMap<u32, InterfaceV3>,
    pub lsdb: LsdbV3,
    /// Per-area configuration: area_type determines whether Type 5
    /// AS-External-LSAs are accepted/flooded (Normal only) and
    /// whether Type 7 NSSA-LSAs are accepted (NSSA only).
    pub area_types: HashMap<Ipv4Addr, crate::area::AreaType>,
    /// True when this router redistributes routes from another
    /// protocol into OSPFv3 (set by daemon from config).
    pub asbr: bool,
    /// Configured redistribute sources (carried for Type 5
    /// origination). Each entry is (source, metric, metric_type).
    pub redistribute: Vec<(crate::config::RedistributeSource, u32, u8)>,
    /// Configured summary-address aggregates. Surfaced through the
    /// control socket's Status6 reply so the `ospfd query
    /// status6` CLI can show what was configured.
    pub summary_addresses: Vec<crate::config::ParsedSummaryAddress6>,
}

impl InstanceV3 {
    pub fn new(router_id: Ipv4Addr) -> Self {
        Self {
            router_id,
            interfaces: HashMap::new(),
            lsdb: LsdbV3::new(),
            area_types: HashMap::new(),
            asbr: false,
            redistribute: Vec::new(),
            summary_addresses: Vec::new(),
        }
    }

    /// Register an area with its type. Defaults to Normal if not set.
    pub fn set_area_type(&mut self, area_id: Ipv4Addr, area_type: crate::area::AreaType) {
        self.area_types.insert(area_id, area_type);
    }

    /// Look up an area's type, defaulting to Normal for unknown areas.
    fn area_type(&self, area_id: Ipv4Addr) -> crate::area::AreaType {
        self.area_types
            .get(&area_id)
            .copied()
            .unwrap_or(crate::area::AreaType::Normal)
    }

    /// Returns true if this router is an Area Border Router: at least
    /// two distinct non-Down areas, one of which is the backbone.
    pub fn is_abr(&self) -> bool {
        let areas: std::collections::HashSet<Ipv4Addr> = self
            .interfaces
            .values()
            .filter(|i| i.state != InterfaceStateV3::Down)
            .map(|i| i.area_id)
            .collect();
        areas.len() >= 2 && areas.contains(&Ipv4Addr::UNSPECIFIED)
    }

    /// Returns true if this router is an AS Boundary Router — i.e.,
    /// we have at least one redistributed route source configured.
    /// Set at daemon startup via `set_asbr`.
    pub fn is_asbr(&self) -> bool {
        self.asbr
    }

    /// Mark this instance as an ASBR. Called by the daemon when there
    /// are any redistribute entries in the config.
    pub fn set_asbr(&mut self, asbr: bool) {
        self.asbr = asbr;
    }

    /// Apply a new configuration to a live v3 instance without
    /// bouncing adjacencies. Mirrors `OspfInstance::reload_config`
    /// on the v2 side. Returns true if any effective change was
    /// applied.
    ///
    /// Live-updatable (applied in place):
    /// - per-interface timing: hello_interval, dead_interval,
    ///   retransmit_interval, transmit_delay
    /// - per-interface priority (DR election recomputes naturally)
    /// - redistribute sources + derived ASBR flag
    /// - summary_addresses
    ///
    /// Not live-updatable (logged as "restart required", ignored):
    /// - router_id, network_type, area_id
    /// - interface add/remove (restart required to (un)enroll)
    ///
    /// Area-type changes are not handled here — mutating a running
    /// area's type has subtle LSA-re-origination implications we'd
    /// rather not get wrong silently.
    pub fn reload_config(&mut self, new: &crate::config::Ospf6DaemonConfig) -> bool {
        let mut changed = false;
        let mut router_lsa_dirty = false;

        if self.router_id != new.router_id {
            tracing::warn!(
                old_router_id = %self.router_id,
                new_router_id = %new.router_id,
                "reload (v3): router_id change requires daemon restart; ignoring"
            );
        }

        for new_iface in &new.interfaces {
            let Some((_, live)) = self
                .interfaces
                .iter_mut()
                .find(|(_, i)| i.io.name == new_iface.name)
            else {
                tracing::warn!(
                    name = %new_iface.name,
                    "reload (v3): interface is new in config but daemon restart needed to add it"
                );
                continue;
            };

            if live.area_id != new_iface.area_id {
                tracing::warn!(
                    name = %live.io.name,
                    old = %live.area_id,
                    new = %new_iface.area_id,
                    "reload (v3): area_id change requires restart; ignoring"
                );
            }

            let new_net_type = match new_iface.network_type.as_str() {
                "point-to-point" => NetworkTypeV3::PointToPoint,
                "point-to-multipoint" => NetworkTypeV3::PointToMultipoint,
                "non-broadcast" => NetworkTypeV3::NonBroadcast,
                _ => NetworkTypeV3::Broadcast,
            };
            if live.network_type != new_net_type {
                tracing::warn!(
                    name = %live.io.name,
                    "reload (v3): network_type change requires restart; ignoring"
                );
            }

            if live.priority != new_iface.priority {
                tracing::info!(
                    name = %live.io.name,
                    old = live.priority,
                    new = new_iface.priority,
                    "reload (v3): priority"
                );
                live.priority = new_iface.priority;
                router_lsa_dirty = true;
                live.needs_router_lsa_refresh = true;
                changed = true;
            }
            if live.hello_interval != new_iface.hello_interval {
                tracing::info!(
                    name = %live.io.name,
                    old = live.hello_interval,
                    new = new_iface.hello_interval,
                    "reload (v3): hello_interval"
                );
                live.hello_interval = new_iface.hello_interval;
                changed = true;
            }
            let new_dead = new_iface.dead_interval as u16;
            if live.dead_interval != new_dead {
                tracing::info!(
                    name = %live.io.name,
                    old = live.dead_interval,
                    new = new_dead,
                    "reload (v3): dead_interval"
                );
                live.dead_interval = new_dead;
                changed = true;
            }
            if live.retransmit_interval != new_iface.retransmit_interval {
                live.retransmit_interval = new_iface.retransmit_interval;
                changed = true;
            }
            if live.transmit_delay != new_iface.transmit_delay {
                live.transmit_delay = new_iface.transmit_delay;
                changed = true;
            }
        }

        for live in self.interfaces.values() {
            if !new.interfaces.iter().any(|n| n.name == live.io.name) {
                tracing::warn!(
                    name = %live.io.name,
                    "reload (v3): interface removed in config but daemon restart needed to tear it down"
                );
            }
        }

        // redistribute — replace wholesale; update derived ASBR flag.
        let new_redist: Vec<_> = new
            .redistribute
            .iter()
            .map(|r| (r.source, r.metric, r.metric_type))
            .collect();
        if self.redistribute.len() != new_redist.len()
            || self
                .redistribute
                .iter()
                .zip(new_redist.iter())
                .any(|(a, b)| a != b)
        {
            tracing::info!(
                old = self.redistribute.len(),
                new = new_redist.len(),
                "reload (v3): redistribute replaced"
            );
            self.redistribute = new_redist;
            self.asbr = !self.redistribute.is_empty();
            changed = true;
        }

        // summary_addresses — replace wholesale. Origination happens
        // on the next SPF / periodic origination cycle.
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
                "reload (v3): summary_addresses replaced"
            );
            self.summary_addresses = new.summary_addresses.clone();
            changed = true;
        }

        if router_lsa_dirty {
            tracing::debug!("reload (v3): router-LSA refresh flagged on affected interfaces");
        }

        changed
    }

    /// Return the set of distinct areas the router has interfaces in.
    pub fn areas(&self) -> std::collections::HashSet<Ipv4Addr> {
        self.interfaces.values().map(|i| i.area_id).collect()
    }

    pub fn add_interface(
        &mut self,
        io: IoInterfaceV3,
        area_id: Ipv4Addr,
        network_type: NetworkTypeV3,
        hello_interval: u16,
        dead_interval: u16,
        priority: u8,
        global_prefixes: Vec<(Ipv6Addr, u8)>,
    ) {
        self.add_interface_full(
            io,
            area_id,
            network_type,
            hello_interval,
            dead_interval,
            priority,
            global_prefixes,
            5, // retransmit_interval default
            1, // transmit_delay default
        );
    }

    /// Extended variant that takes retransmit_interval and
    /// transmit_delay. Callers that don't care use [`add_interface`].
    #[allow(clippy::too_many_arguments)]
    pub fn add_interface_full(
        &mut self,
        io: IoInterfaceV3,
        area_id: Ipv4Addr,
        network_type: NetworkTypeV3,
        hello_interval: u16,
        dead_interval: u16,
        priority: u8,
        global_prefixes: Vec<(Ipv6Addr, u8)>,
        retransmit_interval: u16,
        transmit_delay: u16,
    ) {
        let interface_id = io.kernel_ifindex;
        let sw_if_index = io.sw_if_index;
        // NBMA enters Waiting like Broadcast — same DR election FSM.
        let state = match network_type {
            NetworkTypeV3::Broadcast | NetworkTypeV3::NonBroadcast => InterfaceStateV3::Waiting,
            // P2P and P2MP both skip DR election and jump straight
            // to the operational state.
            NetworkTypeV3::PointToPoint | NetworkTypeV3::PointToMultipoint => {
                InterfaceStateV3::PointToPoint
            }
        };
        self.interfaces.insert(
            sw_if_index,
            InterfaceV3 {
                io,
                area_id,
                interface_id,
                network_type,
                hello_interval,
                dead_interval,
                retransmit_interval,
                transmit_delay,
                priority,
                instance_id: 0,
                state,
                dr: Ipv4Addr::UNSPECIFIED,
                bdr: Ipv4Addr::UNSPECIFIED,
                neighbors: HashMap::new(),
                last_hello_sent: Instant::now() - Duration::from_secs(3600),
                needs_router_lsa_refresh: true,
                global_prefixes,
                static_neighbors: Vec::new(),
            },
        );
    }

    /// Set the static NBMA neighbor list for an existing interface.
    /// Called by the daemon after `add_interface_full` when the
    /// config has `ospf6_neighbors:` entries. Has no effect unless
    /// the interface is `NetworkTypeV3::NonBroadcast`.
    pub fn set_static_neighbors_v3(
        &mut self,
        sw_if_index: u32,
        neighbors: Vec<StaticNeighborV3>,
    ) {
        if let Some(iface) = self.interfaces.get_mut(&sw_if_index) {
            iface.static_neighbors = neighbors;
        }
    }

    fn encode_hello(router_id: Ipv4Addr, iface: &InterfaceV3) -> Vec<u8> {
        let neighbors: Vec<Ipv4Addr> = iface.neighbors.keys().copied().collect();
        let hello = HelloV3Packet {
            interface_id: iface.interface_id,
            router_priority: iface.priority,
            options: Options::standard(),
            hello_interval: iface.hello_interval,
            router_dead_interval: iface.dead_interval,
            designated_router_id: iface.dr,
            backup_designated_router_id: iface.bdr,
            neighbors,
        };
        let mut body = Vec::with_capacity(HELLO_V3_MIN_LEN + 4 * hello.neighbors.len());
        hello.encode(&mut body);

        let mut hdr = Ospfv3Header::new(Ospfv3PacketType::Hello, router_id, iface.area_id);
        hdr.packet_length = (OSPFV3_HEADER_LEN + body.len()) as u16;
        hdr.instance_id = iface.instance_id;

        let mut buf = Vec::with_capacity(hdr.packet_length as usize);
        hdr.encode(&mut buf);
        buf.extend_from_slice(&body);
        buf
    }

    /// Reconcile a refreshed snapshot of one interface's VPP state for
    /// OSPFv3. Returns true if anything changed that requires re-
    /// originating LSAs and re-running SPF.
    pub fn refresh_interface_state(
        &mut self,
        sw_if_index: u32,
        new_link_local: Option<Ipv6Addr>,
        new_prefixes: Vec<(Ipv6Addr, u8)>,
        oper_up: bool,
    ) -> bool {
        let Some(iface) = self.interfaces.get_mut(&sw_if_index) else {
            return false;
        };
        let mut changed = false;

        // Link-local change
        if let Some(ll) = new_link_local {
            if iface.io.link_local != ll {
                tracing::info!(
                    name = %iface.io.name,
                    old = %iface.io.link_local,
                    new = %ll,
                    "OSPFv3: link-local address changed in VPP"
                );
                iface.io.link_local = ll;
                changed = true;
            }
        } else {
            // No link-local — interface is unusable for v3
            if iface.state != InterfaceStateV3::Down {
                tracing::warn!(
                    name = %iface.io.name,
                    "OSPFv3: link-local address gone, marking interface down"
                );
                iface.state = InterfaceStateV3::Down;
                iface.neighbors.clear();
                iface.dr = Ipv4Addr::UNSPECIFIED;
                iface.bdr = Ipv4Addr::UNSPECIFIED;
                changed = true;
            }
        }

        // Global prefix change
        if iface.global_prefixes != new_prefixes {
            tracing::info!(
                name = %iface.io.name,
                old_count = iface.global_prefixes.len(),
                new_count = new_prefixes.len(),
                "OSPFv3: global prefixes changed in VPP"
            );
            iface.global_prefixes = new_prefixes;
            changed = true;
        }

        // Admin/link state change
        let was_up = iface.state != InterfaceStateV3::Down;
        if oper_up && !was_up {
            tracing::info!(
                name = %iface.io.name,
                "OSPFv3: interface came up"
            );
            iface.state = match iface.network_type {
                NetworkTypeV3::PointToPoint | NetworkTypeV3::PointToMultipoint => {
                    InterfaceStateV3::PointToPoint
                }
                NetworkTypeV3::Broadcast | NetworkTypeV3::NonBroadcast => {
                    InterfaceStateV3::Waiting
                }
            };
            changed = true;
        } else if !oper_up && was_up {
            tracing::info!(
                name = %iface.io.name,
                "OSPFv3: interface went down — tearing down adjacencies"
            );
            iface.state = InterfaceStateV3::Down;
            iface.neighbors.clear();
            iface.dr = Ipv4Addr::UNSPECIFIED;
            iface.bdr = Ipv4Addr::UNSPECIFIED;
            changed = true;
        }

        if changed {
            iface.needs_router_lsa_refresh = true;
        }
        changed
    }

    /// If any interface flagged needs_router_lsa_refresh, clear it and
    /// re-originate the full set of self-LSAs (Router, Network if DR,
    /// Intra-Area-Prefix, Link). Call from the daemon tick.
    pub fn refresh_router_lsa_if_needed(&mut self) {
        let dirty = self
            .interfaces
            .values_mut()
            .any(|i| std::mem::take(&mut i.needs_router_lsa_refresh));
        if dirty {
            self.originate_router_lsa();
            self.originate_network_lsas();
            self.originate_intra_area_prefix_lsas();
            self.originate_link_lsas();
        }
    }

    /// Generate Hello packets for interfaces whose hello timer has fired.
    pub fn hello_tick(&mut self, now: Instant) -> Vec<TxPacketV3> {
        let mut out = Vec::new();
        let router_id = self.router_id;
        for iface in self.interfaces.values_mut() {
            if iface.state == InterfaceStateV3::Down {
                continue;
            }
            if now.duration_since(iface.last_hello_sent)
                >= Duration::from_secs(iface.hello_interval as u64)
            {
                iface.last_hello_sent = now;
                let data = Self::encode_hello(router_id, iface);
                // NBMA: unicast a copy to each statically-configured
                // peer link-local address. Broadcast / P2P: a single
                // multicast send to ff02::5.
                let destinations: Vec<Ipv6Addr> = if iface.network_type
                    == NetworkTypeV3::NonBroadcast
                {
                    iface
                        .static_neighbors
                        .iter()
                        .map(|n| n.link_local)
                        .collect()
                } else {
                    vec![ALL_SPF_ROUTERS_V6]
                };
                for dst in destinations {
                    out.push(TxPacketV3 {
                        sw_if_index: iface.io.sw_if_index,
                        src_addr: iface.io.link_local,
                        dst_addr: dst,
                        data: data.clone(),
                    });
                }
            }
        }
        out
    }

    /// Expire neighbors whose dead timer has elapsed.
    pub fn expire_neighbors(&mut self, now: Instant) {
        let router_id = self.router_id;
        for iface in self.interfaces.values_mut() {
            let dead = Duration::from_secs(iface.dead_interval as u64);
            let before = iface.neighbors.len();
            iface.neighbors.retain(|_, n| {
                let alive = now.duration_since(n.last_hello) < dead;
                if !alive {
                    tracing::info!(router_id = %n.router_id, "OSPFv3 neighbor dead");
                }
                alive
            });
            if iface.neighbors.len() != before
                && matches!(
                    iface.network_type,
                    NetworkTypeV3::Broadcast | NetworkTypeV3::NonBroadcast
                )
            {
                Self::dr_election(router_id, iface);
            }
        }
    }

    /// Handle an incoming v3 packet.
    pub fn handle_rx(&mut self, rx: RxPacketV3) -> Result<(), PacketV3Error> {
        if rx.data.len() < OSPFV3_HEADER_LEN {
            return Err(PacketV3Error::TooShort {
                expected: OSPFV3_HEADER_LEN,
                got: rx.data.len(),
            });
        }
        let hdr = Ospfv3Header::parse(&rx.data)?;
        if hdr.router_id == self.router_id {
            return Ok(()); // our own packet
        }
        let router_id = self.router_id;

        let Some(iface) = self.interfaces.get_mut(&rx.sw_if_index) else {
            return Ok(());
        };
        if hdr.area_id != iface.area_id || hdr.instance_id != iface.instance_id {
            return Ok(());
        }

        let end = (hdr.packet_length as usize).min(rx.data.len());
        let body = rx.data[OSPFV3_HEADER_LEN..end].to_vec();
        let sw_if_index = rx.sw_if_index;
        let src_router_id = hdr.router_id;
        let src_addr = rx.src_addr;

        match hdr.packet_type {
            Ospfv3PacketType::Hello => {
                let hello = HelloV3Packet::parse(&body)?;
                let iface = self.interfaces.get_mut(&sw_if_index).unwrap();
                Self::process_hello(router_id, iface, src_router_id, src_addr, hello);
            }
            Ospfv3PacketType::DatabaseDescription => {
                let dd = DbDescV3Packet::parse(&body)?;
                let router_id = router_id;
                // Headers visible on THIS interface for DD purposes:
                // all area-scope and AS-scope LSAs, plus link-scope
                // LSAs whose link_state_id is our interface_id on
                // this link. Link-scope LSAs from other interfaces
                // must never appear in a DD on this interface —
                // FRR (correctly) rejects such DDs as malformed.
                let iface_interface_id = self
                    .interfaces
                    .get(&sw_if_index)
                    .map(|i| i.interface_id)
                    .unwrap_or(0);
                let dd_iface_area = self
                    .interfaces
                    .get(&sw_if_index)
                    .map(|i| i.area_id)
                    .unwrap_or(Ipv4Addr::UNSPECIFIED);
                // Scope filter for DD summary: area-scope LSAs only
                // if they belong to the interface's area; link-scope
                // only if they match the interface's interface_id;
                // AS-scope always included (RFC 5340 §4.2.2).
                let lsdb_headers: Vec<LsaV3Header> = self
                    .lsdb
                    .iter()
                    .filter(|e| match e.header.ls_type {
                        LsaV3Type::Link => {
                            u32::from_be_bytes(e.header.link_state_id.octets())
                                == iface_interface_id
                        }
                        LsaV3Type::AsExternal => true,
                        _ => e.area == Some(dd_iface_area),
                    })
                    .map(|e| e.header.clone())
                    .collect();

                // Restart-seq recovery: if the peer's DD describes any of
                // our own LSAs at a sequence number >= what we currently
                // hold, bump our local entry so the next refresh outranks
                // the peer's cached copy. Without this, a daemon restart
                // starts at INITIAL_SEQUENCE_NUMBER and peers reject our
                // LSAs as stale vs what they still remember from the
                // previous run.
                let iface_area = self
                    .interfaces
                    .get(&sw_if_index)
                    .map(|i| i.area_id)
                    .unwrap_or(Ipv4Addr::UNSPECIFIED);
                for h in &dd.lsa_headers {
                    if h.advertising_router != router_id {
                        continue;
                    }
                    let scope = match h.ls_type {
                        LsaV3Type::AsExternal => None,
                        _ => Some(iface_area),
                    };
                    let key = crate::lsdb_v3::LsaKeyV3 {
                        area: scope,
                        ls_type: h.ls_type,
                        link_state_id: h.link_state_id,
                        advertising_router: router_id,
                    };
                    let Some(existing) = self.lsdb.get(&key).cloned() else {
                        continue;
                    };
                    if h.ls_sequence_number >= existing.header.ls_sequence_number {
                        tracing::info!(
                            ls_type = ?h.ls_type,
                            ls_id = %h.link_state_id,
                            local_seq = format!("{:#x}", existing.header.ls_sequence_number),
                            peer_seq = format!("{:#x}", h.ls_sequence_number),
                            "OSPFv3 stale self-LSA detected, bumping local seq"
                        );
                        let mut bumped = existing.clone();
                        bumped.header.ls_sequence_number = h.ls_sequence_number;
                        self.lsdb.insert(bumped);
                        // Also mark the owning interface dirty so the
                        // next tick re-originates with an incremented
                        // seq (existing_seq + 1 > peer_seq).
                        for i in self.interfaces.values_mut() {
                            i.needs_router_lsa_refresh = true;
                        }
                    }
                }
                let iface = self.interfaces.get_mut(&sw_if_index).unwrap();
                Self::process_dd(router_id, iface, src_router_id, dd, &lsdb_headers);
            }
            Ospfv3PacketType::LinkStateRequest => {
                let pkt = LsRequestV3Packet::parse(&body)?;
                self.process_lsr(sw_if_index, src_router_id, pkt);
            }
            Ospfv3PacketType::LinkStateUpdate => {
                let pkt = LsUpdateV3Packet::parse(&body)?;
                self.process_lsu(sw_if_index, src_router_id, pkt);
            }
            Ospfv3PacketType::LinkStateAck => {
                let pkt = LsAckV3Packet::parse(&body)?;
                self.process_lsack(sw_if_index, src_router_id, pkt);
            }
        }
        Ok(())
    }

    fn process_lsr(&mut self, sw_if_index: u32, src: Ipv4Addr, pkt: LsRequestV3Packet) {
        // Build LSU body containing each requested LSA from our LSDB.
        let iface_area = self
            .interfaces
            .get(&sw_if_index)
            .map(|i| i.area_id)
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        let mut lsas = Vec::new();
        for req in &pkt.requests {
            let scope = match req.ls_type {
                LsaV3Type::AsExternal => None,
                _ => Some(iface_area),
            };
            let key = crate::lsdb_v3::LsaKeyV3 {
                area: scope,
                ls_type: req.ls_type,
                link_state_id: req.link_state_id,
                advertising_router: req.advertising_router,
            };
            if let Some(entry) = self.lsdb.get(&key) {
                lsas.push(LsaV3Raw {
                    header: entry.header.clone(),
                    raw: entry.raw.clone(),
                });
            }
        }
        let Some(iface) = self.interfaces.get_mut(&sw_if_index) else { return };
        let Some(neighbor) = iface.neighbors.get_mut(&src) else { return };
        let queued_count = lsas.len();
        neighbor.pending_lsu.extend(lsas);
        tracing::debug!(
            router_id = %src,
            requested = pkt.requests.len(),
            queued = queued_count,
            "OSPFv3 LSR received, queued LSU response"
        );
    }

    fn process_lsu(&mut self, sw_if_index: u32, src: Ipv4Addr, pkt: LsUpdateV3Packet) {
        // Determine the area this LSU came in on so we can enforce
        // area-type rules (Stub/NSSA reject Type 5).
        let iface_area = self
            .interfaces
            .get(&sw_if_index)
            .map(|i| i.area_id)
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        let iface_area_type = self.area_type(iface_area);
        let accepts_type5 = iface_area_type == crate::area::AreaType::Normal;

        let mut installed_headers = Vec::new();
        let mut installed_entries = Vec::new();
        for lsa in pkt.lsas {
            // Stub and NSSA areas do not accept Type 5 AS-External LSAs.
            // NSSA areas DO accept Type 7 NSSA-LSAs (area-scope externals).
            if lsa.header.ls_type == LsaV3Type::AsExternal && !accepts_type5 {
                tracing::debug!(
                    ls_id = %lsa.header.link_state_id,
                    area = %iface_area,
                    "OSPFv3 dropping Type 5 in non-normal area"
                );
                continue;
            }

            let scope = match lsa.header.ls_type {
                LsaV3Type::AsExternal => None,
                _ => Some(iface_area),
            };
            let entry = crate::lsdb_v3::LsaEntryV3 {
                header: lsa.header.clone(),
                raw: lsa.raw,
                area: scope,
            };
            self.lsdb.insert(entry.clone());
            installed_headers.push(lsa.header);
            installed_entries.push(entry);
        }
        let installed_count = installed_headers.len();

        // Flood newly installed LSAs to all OTHER Full neighbors.
        for entry in &installed_entries {
            self.flood_lsa(entry, Some((sw_if_index, src)));
        }

        let Some(iface) = self.interfaces.get_mut(&sw_if_index) else { return };
        let Some(neighbor) = iface.neighbors.get_mut(&src) else { return };

        // Drop installed LSAs from the request list and queue acks.
        for h in &installed_headers {
            neighbor.request_list.retain(|r| {
                !(r.ls_type == h.ls_type
                    && r.link_state_id == h.link_state_id
                    && r.advertising_router == h.advertising_router)
            });
        }
        neighbor.pending_acks.extend(installed_headers);

        tracing::debug!(
            router_id = %src,
            installed = installed_count,
            remaining = neighbor.request_list.len(),
            "OSPFv3 LSU processed"
        );

        if neighbor.state == NeighborStateV3::Loading && neighbor.request_list.is_empty() {
            neighbor.state = NeighborStateV3::Full;
            tracing::info!(
                router_id = %src,
                "OSPFv3 neighbor → Full (loading complete)"
            );
            iface.needs_router_lsa_refresh = true;
        }
    }

    /// Queue an LSA for flooding to all Full neighbors except `exclude`.
    /// `exclude` is the (sw_if_index, router_id) of the neighbor we
    /// received the LSA from (None for self-originated LSAs).
    fn flood_lsa(
        &mut self,
        lsa: &LsaEntryV3,
        exclude: Option<(u32, Ipv4Addr)>,
    ) {
        // Scope enforcement for flooding:
        //  - AsExternal (Type 5): AS-scope, but only flood into areas
        //    that accept Type 5. Stub/NSSA areas do not accept them.
        //  - Nssa (Type 7): area-scope. Only flood to neighbors in the
        //    originating area. Non-self-originated floods use the
        //    receiving neighbor's interface area.
        //  - Router/Network/InterAreaPrefix/IntraAreaPrefix: area-scope.
        //    Non-self-originated floods happen within the same area.
        //    We don't track inbound source area yet; we flood to all
        //    area-matching neighbors based on advertising_router area
        //    membership (not perfect, but works for the single-area
        //    case and for LSAs we ourselves originated).
        //  - Link-LSA: never reaches this function; uses flood_lsa_link_scope.
        let ls_type = lsa.header.ls_type;
        let area_types = self.area_types.clone();
        let mut count = 0;
        for iface in self.interfaces.values_mut() {
            let iface_area = iface.area_id;
            let area_type = area_types
                .get(&iface_area)
                .copied()
                .unwrap_or(crate::area::AreaType::Normal);
            // Don't flood Type 5 into Stub/NSSA.
            if ls_type == LsaV3Type::AsExternal && area_type != crate::area::AreaType::Normal {
                continue;
            }
            // Type 7 only floods within NSSA areas.
            if ls_type == LsaV3Type::Nssa && area_type != crate::area::AreaType::Nssa {
                continue;
            }
            // Area-scope LSAs (Router, Network, InterAreaPrefix,
            // InterAreaRouter, IntraAreaPrefix) must only flood to
            // interfaces in the LSA's originating area.
            if let Some(lsa_area) = lsa.area {
                if !matches!(ls_type, LsaV3Type::AsExternal | LsaV3Type::Link)
                    && iface_area != lsa_area
                {
                    continue;
                }
            }
            for (nid, neighbor) in iface.neighbors.iter_mut() {
                if neighbor.state != NeighborStateV3::Full {
                    continue;
                }
                if let Some((ex_iface, ex_rid)) = exclude {
                    if iface.io.sw_if_index == ex_iface && *nid == ex_rid {
                        continue;
                    }
                }
                neighbor.pending_lsu.push(LsaV3Raw {
                    header: lsa.header.clone(),
                    raw: lsa.raw.clone(),
                });
                count += 1;
            }
        }
        if count > 0 {
            tracing::debug!(
                ls_type = ?lsa.header.ls_type,
                ls_id = %lsa.header.link_state_id,
                adv_router = %lsa.header.advertising_router,
                neighbors = count,
                "OSPFv3 flooding LSA"
            );
        }
    }

    fn process_lsack(&mut self, _sw_if_index: u32, src: Ipv4Addr, pkt: LsAckV3Packet) {
        // No retransmit queue to clear yet (flooding not implemented).
        tracing::debug!(
            router_id = %src,
            acked = pkt.headers.len(),
            "OSPFv3 LSAck received (ignored, no retransmit queue)"
        );
    }

    /// Process an incoming DD packet and advance the neighbor's DD state.
    /// On entry, the neighbor has already been registered via Hello.
    fn process_dd(
        router_id: Ipv4Addr,
        iface: &mut InterfaceV3,
        src_router_id: Ipv4Addr,
        dd: DbDescV3Packet,
        our_headers: &[LsaV3Header],
    ) {
        let Some(neighbor) = iface.neighbors.get_mut(&src_router_id) else {
            return;
        };

        // Peer re-initializes (I|M|MS set, empty headers): if we're
        // already past ExStart, the peer is signalling that it wants
        // to restart the exchange. Drop back to ExStart and re-run
        // negotiation. Without this, after a FRR-peer flap we'd sit
        // in Full while the peer is stuck in ExStart forever.
        if dd.is_init()
            && dd.has_more()
            && dd.is_master()
            && dd.lsa_headers.is_empty()
            && neighbor.state > NeighborStateV3::ExStart
        {
            tracing::info!(
                router_id = %src_router_id,
                state = ?neighbor.state,
                "OSPFv3 neighbor sent fresh init DD, resetting to ExStart"
            );
            neighbor.state = NeighborStateV3::ExStart;
            neighbor.dd_seq = (Instant::now().elapsed().as_secs() as u32).max(1);
            neighbor.dd_master = router_id > src_router_id;
            neighbor.dd_summary_tx.clear();
            neighbor.dd_summary_recv.clear();
            neighbor.dd_peer_done = false;
            neighbor.dd_send_final = false;
            neighbor.request_list.clear();
        }

        // NegotiationDone: happens when we're in ExStart and receive a DD
        // that establishes master/slave.
        if neighbor.state == NeighborStateV3::TwoWay {
            // Promote to ExStart: send initial DD (I|M|MS) next timer tick.
            neighbor.state = NeighborStateV3::ExStart;
            neighbor.dd_seq = (Instant::now().elapsed().as_secs() as u32).max(1);
            neighbor.dd_master = router_id > src_router_id;
            tracing::info!(router_id = %src_router_id, "OSPFv3 neighbor → ExStart");
        }

        if neighbor.state == NeighborStateV3::ExStart {
            // RFC 2328 §10.6: negotiation rules
            // - We are slave iff peer's RID > ours AND its DD has I,M,MS set and no LSAs
            // - We are master iff our RID > peer's AND its DD has I,M,MS clear (ack of our init)
            let peer_i = dd.is_init();
            let peer_m = dd.has_more();
            let peer_ms = dd.is_master();

            if src_router_id > router_id && peer_i && peer_m && peer_ms && dd.lsa_headers.is_empty() {
                // We're slave.
                neighbor.dd_master = false;
                neighbor.dd_seq = dd.dd_sequence_number;
                neighbor.state = NeighborStateV3::Exchange;
                neighbor.dd_summary_tx = our_headers.to_vec();
                neighbor.dd_response_pending = true;
                tracing::info!(
                    router_id = %src_router_id,
                    summary_count = our_headers.len(),
                    "OSPFv3 neighbor → Exchange (slave)"
                );
            } else if src_router_id < router_id && !peer_i && !peer_ms
                && dd.dd_sequence_number == neighbor.dd_seq
            {
                // We're master — peer has acknowledged our initial DD with
                // our sequence number.
                neighbor.dd_master = true;
                neighbor.state = NeighborStateV3::Exchange;
                neighbor.dd_summary_tx = our_headers.to_vec();
                neighbor.dd_response_pending = true;
                tracing::info!(
                    router_id = %src_router_id,
                    summary_count = our_headers.len(),
                    "OSPFv3 neighbor → Exchange (master)"
                );
            } else {
                // Not yet — stay in ExStart and retransmit.
                return;
            }
        }

        // Only process DD content in Exchange state. DDs received in
        // Loading/Full are duplicate retransmits — the peer is acking
        // our retransmit queue or hasn't caught up yet. Responding
        // with finish_dd again causes state flaps. Fresh-init DDs
        // (handled above) bypass this guard via the reset path.
        if neighbor.state == NeighborStateV3::Exchange {
            neighbor.dd_summary_recv.extend(dd.lsa_headers.iter().cloned());

            let more_from_peer = dd.has_more();
            if !more_from_peer {
                neighbor.dd_peer_done = true;
            }

            if neighbor.dd_master {
                neighbor.dd_seq = neighbor.dd_seq.wrapping_add(1);
            } else {
                neighbor.dd_seq = dd.dd_sequence_number;
            }
            // Always echo — master sends next chunk (or final),
            // slave echoes with peer's seq. emit_pending_dds runs
            // finish_dd after the final drain-send, so we don't
            // advance state here.
            neighbor.dd_response_pending = true;
        }
    }

    fn finish_dd(neighbor: &mut NeighborV3, our_headers: &[LsaV3Header]) -> bool {
        // RFC 2328 §10.8: at end of DD exchange, build the request list
        // from peer headers we don't have or which are newer than ours.
        // Then transition to Loading (or Full if request_list is empty).
        let mut req = Vec::new();
        for h in &neighbor.dd_summary_recv {
            let have = our_headers.iter().find(|o| {
                o.ls_type == h.ls_type
                    && o.link_state_id == h.link_state_id
                    && o.advertising_router == h.advertising_router
            });
            let need = match have {
                None => true,
                Some(o) => h.ls_sequence_number > o.ls_sequence_number,
            };
            if need {
                req.push(h.clone());
            }
        }
        neighbor.request_list = req;

        if neighbor.request_list.is_empty() {
            let was = neighbor.state;
            neighbor.state = NeighborStateV3::Full;
            if was != NeighborStateV3::Full {
                tracing::info!(
                    router_id = %neighbor.router_id,
                    "OSPFv3 neighbor → Full (no LSAs to request)"
                );
                return true;
            }
        } else {
            neighbor.state = NeighborStateV3::Loading;
            neighbor.lsr_pending = true;
            tracing::info!(
                router_id = %neighbor.router_id,
                requests = neighbor.request_list.len(),
                "OSPFv3 neighbor → Loading"
            );
        }
        false
    }

    /// Snapshot the list of Full neighbors with their link-locals,
    /// for SPF next-hop resolution.
    pub fn spf_neighbors(&self) -> Vec<crate::spf_v3::SpfNeighborV3> {
        let mut out = Vec::new();
        for iface in self.interfaces.values() {
            for n in iface.neighbors.values() {
                if n.state == NeighborStateV3::Full {
                    out.push(crate::spf_v3::SpfNeighborV3 {
                        router_id: n.router_id,
                        link_local: n.link_local,
                        sw_if_index: iface.io.sw_if_index,
                    });
                }
            }
        }
        out
    }

    /// Originate (or refresh) our Router-LSA. Called whenever the set
    /// of adjacent neighbors changes.
    ///
    /// OSPFv3 Router-LSAs describe link-local connectivity only — no
    /// prefixes. For each interface we emit one link entry:
    ///   - Broadcast networks with a Full neighbor that is DR: a
    ///     transit link pointing at the DR's interface.
    ///   - Point-to-point: a P2P link pointing at the neighbor router.
    ///
    /// Without LSR/LSU implemented yet we never reach Full, so the
    /// initial Router-LSA is empty — but the LSDB still has it so DDs
    /// can describe our self-originated state.
    pub fn originate_router_lsa(&mut self) {
        let router_id = self.router_id;
        let is_abr = self.is_abr();
        let is_asbr = self.is_asbr();
        let mut rtr_flags: u8 = 0;
        if is_abr {
            rtr_flags |= RouterLsaV3::FLAG_B;
        }
        if is_asbr {
            rtr_flags |= RouterLsaV3::FLAG_E;
        }

        // Build one Router-LSA per area. Each LSA lists only the
        // links (interfaces) in that area — an ABR advertises a
        // separate topology view into each area.
        let areas: std::collections::HashSet<Ipv4Addr> =
            self.interfaces.values().map(|i| i.area_id).collect();

        for area_id in areas {
            let mut links = Vec::new();
            for iface in self.interfaces.values() {
                if iface.area_id != area_id {
                    continue;
                }
                match iface.network_type {
                    // P2P and P2MP both emit a TYPE_POINT_TO_POINT
                    // link entry per Full adjacency. P2MP differs
                    // only in that there can be multiple Full
                    // neighbors on one interface — the loop already
                    // handles that.
                    NetworkTypeV3::PointToPoint | NetworkTypeV3::PointToMultipoint => {
                        for n in iface.neighbors.values() {
                            if n.state == NeighborStateV3::Full {
                                links.push(RouterLinkV3 {
                                    link_type: RouterLinkV3::TYPE_POINT_TO_POINT,
                                    metric: 1,
                                    interface_id: iface.interface_id,
                                    neighbor_interface_id: n.interface_id,
                                    neighbor_router_id: n.router_id,
                                });
                            }
                        }
                    }
                    NetworkTypeV3::Broadcast | NetworkTypeV3::NonBroadcast => {
                        let dr = iface.dr;
                        if dr == Ipv4Addr::UNSPECIFIED {
                            continue;
                        }
                        let dr_iface_id = if dr == router_id {
                            iface.interface_id
                        } else if let Some(n) = iface.neighbors.get(&dr) {
                            if n.state != NeighborStateV3::Full {
                                continue;
                            }
                            n.interface_id
                        } else {
                            continue;
                        };
                        links.push(RouterLinkV3 {
                            link_type: RouterLinkV3::TYPE_TRANSIT_NETWORK,
                            metric: 1,
                            interface_id: iface.interface_id,
                            neighbor_interface_id: dr_iface_id,
                            neighbor_router_id: dr,
                        });
                    }
                }
            }

            let body = {
                let lsa = RouterLsaV3 {
                    flags: rtr_flags,
                    options: Options::standard().0,
                    links,
                };
                let mut b = Vec::new();
                lsa.encode(&mut b);
                b
            };

            self.insert_self_lsa(
                LsaV3Type::Router,
                Ipv4Addr::UNSPECIFIED,
                body,
                Some(area_id),
            );
        }
    }

    /// Originate Network-LSAs for each broadcast interface where we are
    /// the DR and have at least one Full neighbor. The link-state-id is
    /// our interface_id; the body lists ourselves plus all Full attached
    /// routers.
    pub fn originate_network_lsas(&mut self) {
        let router_id = self.router_id;
        let mut to_emit: Vec<(u32, Ipv4Addr, Vec<Ipv4Addr>)> = Vec::new();

        for iface in self.interfaces.values() {
            // Network-LSAs are originated by the DR on transit
            // multi-access segments — broadcast and NBMA both qualify.
            if !matches!(
                iface.network_type,
                NetworkTypeV3::Broadcast | NetworkTypeV3::NonBroadcast
            ) || iface.state != InterfaceStateV3::DR
            {
                continue;
            }
            let mut routers = vec![router_id];
            for n in iface.neighbors.values() {
                if n.state == NeighborStateV3::Full {
                    routers.push(n.router_id);
                }
            }
            if routers.len() < 2 {
                // Need at least one full adjacency to advertise as a transit network.
                continue;
            }
            to_emit.push((iface.interface_id, iface.area_id, routers));
        }

        for (interface_id, area_id, routers) in to_emit {
            let nlsa = NetworkLsaV3 {
                options: Options::standard().0,
                attached_routers: routers,
            };
            let mut body = Vec::new();
            nlsa.encode(&mut body);

            let link_state_id = Ipv4Addr::from(interface_id.to_be_bytes());
            let mut header = LsaV3Header {
                ls_age: 0,
                ls_type: LsaV3Type::Network,
                link_state_id,
                advertising_router: router_id,
                ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: (LSA_V3_HEADER_LEN + body.len()) as u16,
            };
            let area = Some(area_id);
            // Bump sequence if existing.
            if let Some(existing) = self.lsdb.get(&crate::lsdb_v3::LsaKeyV3 {
                area,
                ls_type: LsaV3Type::Network,
                link_state_id,
                advertising_router: router_id,
            }) {
                header.ls_sequence_number = existing.header.ls_sequence_number.wrapping_add(1);
            }

            let mut raw = Vec::with_capacity(header.length as usize);
            header.encode(&mut raw);
            raw.extend_from_slice(&body);
            let (c0, c1) = fletcher16(&raw[2..], 14);
            raw[16] = c0;
            raw[17] = c1;
            header.ls_checksum = ((c0 as u16) << 8) | c1 as u16;

            let entry = LsaEntryV3 {
                header: header.clone(),
                raw,
                area,
            };
            self.lsdb.insert(entry.clone());
            tracing::debug!(
                interface_id,
                seq = format!("{:#x}", header.ls_sequence_number),
                attached = body.len() / 4 - 1,
                "originated OSPFv3 Network-LSA"
            );
            self.flood_lsa(&entry, None);
        }
    }

    /// Originate one Link-LSA per interface that has a link-local
    /// address. Link-LSAs have link-local scope — they are flooded
    /// only on the originating interface, never to other interfaces.
    /// Body carries our router priority, options, link-local address,
    /// and the list of global IPv6 prefixes attached to the interface.
    ///
    /// RFC 5340 §4.4.3.8. LinkStateId is our interface_id on the link.
    pub fn originate_link_lsas(&mut self) {
        let mut to_emit: Vec<(u32, u32, Ipv4Addr, LinkLsaV3)> = Vec::new();

        for iface in self.interfaces.values() {
            if iface.state == InterfaceStateV3::Down {
                continue;
            }
            if iface.io.link_local.is_unspecified() {
                continue;
            }
            let prefixes: Vec<Ospfv3Prefix> = iface
                .global_prefixes
                .iter()
                .map(|(addr, len)| Ospfv3Prefix {
                    prefix_length: *len,
                    prefix_options: 0,
                    prefix_or_metric: 0,
                    address: *addr,
                })
                .collect();
            let lsa = LinkLsaV3 {
                router_priority: iface.priority,
                options: Options::standard().0,
                link_local_address: iface.io.link_local,
                prefixes,
            };
            to_emit.push((iface.interface_id, iface.io.sw_if_index, iface.area_id, lsa));
        }

        for (interface_id, sw_if_index, area_id, lsa) in to_emit {
            let mut body = Vec::new();
            lsa.encode(&mut body);
            let link_state_id = Ipv4Addr::from(interface_id.to_be_bytes());
            let entry =
                self.build_self_lsa(LsaV3Type::Link, link_state_id, body, Some(area_id));
            self.lsdb.insert(entry.clone());
            tracing::debug!(
                interface_id,
                seq = format!("{:#x}", entry.header.ls_sequence_number),
                prefixes = (entry.raw.len() - LSA_V3_HEADER_LEN - 24) / 4,
                "originated OSPFv3 Link-LSA"
            );
            // Link-scope flooding: only to neighbors on the originating
            // interface. Never cross-interface.
            self.flood_lsa_link_scope(&entry, sw_if_index);
        }
    }

    /// Originate Type 5 aggregate LSAs for each configured
    /// summary-address. Phase 1 emits the aggregate but does NOT
    /// suppress component-prefix Type 5s. `no_advertise` entries
    /// are skipped. Aggregates use ls_ids starting at 0x1000 to
    /// avoid colliding with redistribute-connected (1..=N) and
    /// the default-route reserved slot (0).
    pub fn originate_summary_address_lsas(
        &mut self,
        entries: &[crate::config::ParsedSummaryAddress6],
    ) {
        use crate::packet_v3::lsa::AsExternalLsaV3;
        for (idx, e) in entries.iter().enumerate() {
            if e.no_advertise {
                continue;
            }
            let ls_id = Ipv4Addr::from((0x1000u32 + idx as u32).to_be_bytes());
            let ext = AsExternalLsaV3 {
                metric_type_2: e.metric_type == 2,
                forwarding_present: false,
                tag_present: e.tag != 0,
                metric: e.metric,
                prefix: Ospfv3Prefix {
                    prefix_length: e.prefix_len,
                    prefix_options: 0,
                    prefix_or_metric: 0,
                    address: e.prefix,
                },
                referenced_ls_type: 0,
                forwarding_address: None,
                external_route_tag: if e.tag != 0 { Some(e.tag) } else { None },
                referenced_link_state_id: None,
            };
            let mut body = Vec::new();
            ext.encode(&mut body);
            self.insert_self_lsa(LsaV3Type::AsExternal, ls_id, body, None);
        }
        if entries.iter().any(|e| !e.no_advertise) {
            tracing::info!(
                count = entries.iter().filter(|e| !e.no_advertise).count(),
                "OSPFv3 originated summary-address Type 5 LSAs"
            );
        }
    }

    /// Originate a single Type 5 AS-External-LSA for the ::/0
    /// default route. Uses ls_id 0.0.0.0 (reserved slot for the
    /// default) so it doesn't collide with the sequentially-
    /// assigned `originate_external_lsas` ids (1..=N).
    pub fn originate_default_route_lsa(&mut self, metric: u32, metric_type: u8) {
        use crate::packet_v3::lsa::AsExternalLsaV3;
        let ext = AsExternalLsaV3 {
            metric_type_2: metric_type == 2,
            forwarding_present: false,
            tag_present: false,
            metric,
            prefix: Ospfv3Prefix {
                prefix_length: 0,
                prefix_options: 0,
                prefix_or_metric: 0,
                address: Ipv6Addr::UNSPECIFIED,
            },
            referenced_ls_type: 0,
            forwarding_address: None,
            external_route_tag: None,
            referenced_link_state_id: None,
        };
        let mut body = Vec::new();
        ext.encode(&mut body);
        self.insert_self_lsa(
            LsaV3Type::AsExternal,
            Ipv4Addr::UNSPECIFIED,
            body,
            None,
        );
        tracing::info!(metric, metric_type, "OSPFv3 originated default-route Type 5 LSA");
    }

    /// Originate Type 5 AS-External-LSAs for the given prefixes.
    ///
    /// The daemon is responsible for discovering the set of prefixes
    /// to redistribute (typically connected prefixes on interfaces
    /// not enrolled in OSPFv3) and passing them here. Metric and
    /// metric-type come from the first matching `redistribute` entry.
    ///
    /// AS-scope (area = None). Only emitted when `asbr` is set.
    /// Prefixes are assigned sequential link-state-ids (0.0.0.1+).
    /// Existing LSAs for the same link-state-id are refreshed with a
    /// bumped sequence number. When the input set shrinks, any
    /// previously-originated link-state-id that's no longer in the
    /// new set is MaxAge-flushed so peers withdraw the prefix
    /// immediately (instead of waiting up to LSRefreshTime).
    pub fn originate_external_lsas(
        &mut self,
        externals: Vec<(Ipv6Addr, u8)>,
        summaries: &[crate::config::ParsedSummaryAddress6],
    ) {
        use crate::packet_v3::lsa::AsExternalLsaV3;

        if !self.asbr || self.redistribute.is_empty() {
            // We're not (or no longer) an ASBR: flush every Type 5
            // we previously originated. The early return path needs
            // this too — if redistribute was disabled at runtime,
            // someone has to clean up.
            self.flush_self_externals_outside(&[]);
            return;
        }
        let Some((_, metric, metric_type)) = self
            .redistribute
            .iter()
            .find(|(s, _, _)| *s == crate::config::RedistributeSource::Connected)
            .copied()
        else {
            self.flush_self_externals_outside(&[]);
            return;
        };

        // Filter out components covered by a configured summary
        // range. The aggregate itself is emitted by
        // originate_summary_address_lsas at a separate link-state-id;
        // no_advertise on the summary suppresses the aggregate but
        // does not change component-suppression behavior.
        let kept: Vec<(Ipv6Addr, u8)> = externals
            .into_iter()
            .filter(|(addr, _len)| {
                if let Some(s) = summaries
                    .iter()
                    .find(|s| prefix_covered_by_v6(*addr, s.prefix, s.prefix_len))
                {
                    tracing::debug!(
                        prefix = %addr,
                        summary = %format!("{}/{}", s.prefix, s.prefix_len),
                        "OSPFv3 suppressing component external — covered by summary range"
                    );
                    false
                } else {
                    true
                }
            })
            .collect();

        // Compute the link-state-id set we're about to (re-)originate
        // so we can MaxAge-flush anything previously-self-originated
        // that falls outside it. Summary aggregates live at 0x1000+
        // and the default-route Type 5 lives at 0.0.0.0 — preserve
        // both classes so we don't accidentally flush them here.
        let new_ids: Vec<Ipv4Addr> = (0..kept.len())
            .map(|i| Ipv4Addr::from(((i as u32) + 1).to_be_bytes()))
            .collect();
        let mut keep_ids = new_ids.clone();
        for (idx, _) in summaries.iter().enumerate() {
            keep_ids.push(Ipv4Addr::from((0x1000u32 + idx as u32).to_be_bytes()));
        }
        keep_ids.push(Ipv4Addr::UNSPECIFIED);
        self.flush_self_externals_outside(&keep_ids);

        for (idx, (addr, len)) in kept.iter().enumerate() {
            let link_state_id = Ipv4Addr::from((idx as u32 + 1).to_be_bytes());
            let ext = AsExternalLsaV3 {
                metric_type_2: metric_type == 2,
                forwarding_present: false,
                tag_present: false,
                metric,
                prefix: Ospfv3Prefix {
                    prefix_length: *len,
                    prefix_options: 0,
                    prefix_or_metric: 0,
                    address: *addr,
                },
                referenced_ls_type: 0,
                forwarding_address: None,
                external_route_tag: None,
                referenced_link_state_id: None,
            };
            let mut body = Vec::new();
            ext.encode(&mut body);
            self.insert_self_lsa(LsaV3Type::AsExternal, link_state_id, body, None);
        }
        if !kept.is_empty() {
            tracing::info!(
                count = kept.len(),
                "OSPFv3 originated AS-External LSAs"
            );
        }
    }

    /// MaxAge-flush every self-originated Type 5 (AS-External) LSA
    /// whose link-state-id is NOT in `keep`. Used by
    /// `originate_external_lsas` to withdraw prefixes that disappear
    /// from the input set between refresh ticks. Per RFC 2328 §14.1:
    /// premature aging only happens for LSAs we originated ourselves,
    /// and we set ls_age = MAX_AGE then re-flood — peers treat the
    /// MaxAge LSA as a deletion request and remove it from their
    /// own LSDBs after the flush LSAck round-trip.
    fn flush_self_externals_outside(&mut self, keep: &[Ipv4Addr]) {
        use crate::packet_v3::lsa::MAX_AGE;

        let router_id = self.router_id;
        let to_flush: Vec<crate::lsdb_v3::LsaKeyV3> = self
            .lsdb
            .iter()
            .filter(|e| {
                e.header.ls_type == LsaV3Type::AsExternal
                    && e.header.advertising_router == router_id
                    && !keep.contains(&e.header.link_state_id)
            })
            .map(|e| crate::lsdb_v3::LsaKeyV3 {
                area: e.area,
                ls_type: e.header.ls_type,
                link_state_id: e.header.link_state_id,
                advertising_router: e.header.advertising_router,
            })
            .collect();

        for key in to_flush {
            // Pull a copy of the existing entry, bump age + seq, re-flood.
            let Some(existing) = self.lsdb.get(&key).cloned() else {
                continue;
            };
            let mut header = existing.header.clone();
            header.ls_age = MAX_AGE;
            header.ls_sequence_number = header.ls_sequence_number.wrapping_add(1);
            // Recompute checksum over the updated header + original body.
            let body = &existing.raw[LSA_V3_HEADER_LEN..];
            let mut raw = Vec::with_capacity(LSA_V3_HEADER_LEN + body.len());
            header.encode(&mut raw);
            raw.extend_from_slice(body);
            let (c0, c1) = fletcher16(&raw[2..], 14);
            raw[16] = c0;
            raw[17] = c1;
            header.ls_checksum = ((c0 as u16) << 8) | c1 as u16;
            let entry = LsaEntryV3 {
                header,
                raw,
                area: existing.area,
            };
            self.lsdb.insert(entry.clone());
            tracing::info!(
                link_state_id = %key.link_state_id,
                "OSPFv3 MaxAge-flushed withdrawn AS-External LSA"
            );
            self.flood_lsa(&entry, None);
        }
    }

    /// Originate Type 3 Inter-Area-Prefix-LSAs as an ABR.
    ///
    /// For each (source_area, dest_area) pair where we have interfaces
    /// in both, summarize the intra-area prefixes of source_area into
    /// dest_area with the intra-area cost to reach each prefix.
    ///
    /// Per-area SPF is computed by running calculate_spf_v3 over a
    /// filtered LSDB containing only entries whose area matches the
    /// source. This is wasteful for large LSDBs but correct and
    /// simple. Link-state-ids are assigned as (dest_area_counter + 1)
    /// in host-order-encoded Ipv4Addr — deterministic as long as the
    /// prefix set is iterated in stable order (routes are returned
    /// in SPF relaxation order).
    ///
    /// Self-attached prefixes in the destination area are skipped —
    /// we'd be summarizing a route back into the area that already
    /// knows it intra-area, which causes SPF to prefer the loop.
    pub fn originate_inter_area_prefix_lsas(&mut self) {
        use crate::packet_v3::lsa::InterAreaPrefixLsaV3;
        use crate::spf_v3::calculate_spf_v3;

        if !self.is_abr() {
            return;
        }
        let router_id = self.router_id;
        let neighbors = self.spf_neighbors();
        let areas: Vec<Ipv4Addr> = self.areas().into_iter().collect();

        // Per-area gathered prefixes: (prefix, prefix_len) -> cost
        // from us (ABR) as the path origin. Collected two ways:
        //   1. Self-originated Router IAPs in each area — cost 0,
        //      they're our directly-attached prefixes.
        //   2. Peer-originated IAPs in each area — cost comes from
        //      per-area SPF (which correctly skips self but does
        //      compute paths to peers).
        let mut area_prefix_costs: HashMap<
            Ipv4Addr,
            HashMap<(Ipv6Addr, u8), u32>,
        > = HashMap::new();

        // 1. Self IAPs — directly from LSDB
        for entry in self.lsdb.iter() {
            if entry.header.ls_type != LsaV3Type::IntraAreaPrefix {
                continue;
            }
            if entry.header.advertising_router != router_id {
                continue;
            }
            let Some(area) = entry.area else { continue };
            let body_off = crate::packet_v3::lsa::LSA_V3_HEADER_LEN;
            let Ok(iap) = IntraAreaPrefixLsaV3::parse(&entry.raw[body_off..]) else {
                continue;
            };
            let map = area_prefix_costs.entry(area).or_default();
            for p in iap.prefixes {
                // Self-attached prefix — ABR cost 0 (we're on the link).
                map.entry((p.address, p.prefix_length))
                    .and_modify(|c| *c = (*c).min(0))
                    .or_insert(0);
            }
        }

        // 2. Peer prefixes via per-area SPF
        for src in &areas {
            let mut filtered = LsdbV3::new();
            for e in self.lsdb.iter() {
                if e.area == Some(*src) {
                    filtered.insert(e.clone());
                }
            }
            let routes = calculate_spf_v3(router_id, &filtered, &neighbors);
            let map = area_prefix_costs.entry(*src).or_default();
            for r in routes {
                map.entry((r.prefix, r.prefix_len))
                    .and_modify(|c| *c = (*c).min(r.cost))
                    .or_insert(r.cost);
            }
        }

        for src in &areas {
            let Some(src_prefixes) = area_prefix_costs.get(src) else {
                continue;
            };
            for dest in &areas {
                if dest == src {
                    continue;
                }
                // Skip summarizing prefixes that are locally attached
                // in the destination area (would create a loop).
                let dest_local: std::collections::HashSet<(Ipv6Addr, u8)> = area_prefix_costs
                    .get(dest)
                    .map(|m| {
                        m.iter()
                            .filter_map(|(k, v)| if *v == 0 { Some(*k) } else { None })
                            .collect()
                    })
                    .unwrap_or_default();
                let mut counter: u32 = 0;
                // Sort for determinism
                let mut entries: Vec<(&(Ipv6Addr, u8), &u32)> = src_prefixes.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                for ((addr, len), cost) in entries {
                    if dest_local.contains(&(*addr, *len)) {
                        continue;
                    }
                    counter += 1;
                    let link_state_id = Ipv4Addr::from(counter.to_be_bytes());
                    let ia = InterAreaPrefixLsaV3 {
                        metric: *cost,
                        prefix: Ospfv3Prefix {
                            prefix_length: *len,
                            prefix_options: 0,
                            prefix_or_metric: 0,
                            address: *addr,
                        },
                    };
                    let mut body = Vec::new();
                    ia.encode(&mut body);
                    self.insert_self_lsa(
                        LsaV3Type::InterAreaPrefix,
                        link_state_id,
                        body,
                        Some(*dest),
                    );
                }
                if counter > 0 {
                    tracing::info!(
                        source_area = %src,
                        dest_area = %dest,
                        count = counter,
                        "OSPFv3 ABR originated Type 3 Inter-Area-Prefix-LSAs"
                    );
                }
            }
        }
    }

    /// Build a self-originated LSA (header + body, with checksum and
    /// sequence number bumped if a prior copy exists) without
    /// inserting it into the LSDB. Returns the entry; caller stores
    /// and floods. Shared helper for link-scope LSAs that need a
    /// custom flood path.
    fn build_self_lsa(
        &self,
        ls_type: LsaV3Type,
        link_state_id: Ipv4Addr,
        body: Vec<u8>,
        area: Option<Ipv4Addr>,
    ) -> LsaEntryV3 {
        let router_id = self.router_id;
        let mut header = LsaV3Header {
            ls_age: 0,
            ls_type,
            link_state_id,
            advertising_router: router_id,
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: (LSA_V3_HEADER_LEN + body.len()) as u16,
        };
        if let Some(existing) = self.lsdb.get(&crate::lsdb_v3::LsaKeyV3 {
            area,
            ls_type,
            link_state_id,
            advertising_router: router_id,
        }) {
            header.ls_sequence_number = existing.header.ls_sequence_number.wrapping_add(1);
        }
        let mut raw = Vec::with_capacity(header.length as usize);
        header.encode(&mut raw);
        raw.extend_from_slice(&body);
        let (c0, c1) = fletcher16(&raw[2..], 14);
        raw[16] = c0;
        raw[17] = c1;
        header.ls_checksum = ((c0 as u16) << 8) | c1 as u16;
        LsaEntryV3 { header, raw, area }
    }

    /// Queue a link-scope LSA for flooding to Full neighbors on a
    /// single interface. Never crosses to other interfaces.
    fn flood_lsa_link_scope(&mut self, lsa: &LsaEntryV3, sw_if_index: u32) {
        let Some(iface) = self.interfaces.get_mut(&sw_if_index) else {
            return;
        };
        let mut count = 0;
        for neighbor in iface.neighbors.values_mut() {
            if neighbor.state != NeighborStateV3::Full {
                continue;
            }
            neighbor.pending_lsu.push(LsaV3Raw {
                header: lsa.header.clone(),
                raw: lsa.raw.clone(),
            });
            count += 1;
        }
        if count > 0 {
            tracing::debug!(
                ls_id = %lsa.header.link_state_id,
                sw_if_index,
                neighbors = count,
                "OSPFv3 flooding Link-LSA (link-scope)"
            );
        }
    }

    /// Originate Intra-Area-Prefix-LSAs.
    ///
    /// Two cases (RFC 5340 §4.4.3.9):
    ///  - Per Network-LSA we originate (we're DR on a transit broadcast
    ///    network): one IAP-LSA referencing that Network-LSA and listing
    ///    the prefixes attached to that interface.
    ///  - One IAP-LSA referencing our own Router-LSA and listing prefixes
    ///    from interfaces that are not transit (PtP, loopback, passive,
    ///    or DROther — anywhere we're not advertising via a Network-LSA).
    pub fn originate_intra_area_prefix_lsas(&mut self) {
        let router_id = self.router_id;

        // Case 1: per-network IAPs (one per interface where we're DR
        // with a Network-LSA).
        // Case 2: per-area router IAPs — one Router IAP per area we
        // have an interface in, listing that area's non-transit
        // prefixes. Needed for ABR so each area's LSDB contains its
        // own prefix set (not everything we know globally).
        let mut network_iaps: Vec<(u32, Ipv4Addr, Vec<Ospfv3Prefix>)> = Vec::new();
        let mut router_prefixes_by_area: HashMap<Ipv4Addr, Vec<Ospfv3Prefix>> = HashMap::new();

        for iface in self.interfaces.values() {
            let prefixes: Vec<Ospfv3Prefix> = iface
                .global_prefixes
                .iter()
                .map(|(addr, len)| Ospfv3Prefix {
                    prefix_length: *len,
                    prefix_options: 0,
                    prefix_or_metric: 0,
                    address: *addr,
                })
                .collect();
            if prefixes.is_empty() {
                continue;
            }
            let attached_via_network_lsa = matches!(
                iface.network_type,
                NetworkTypeV3::Broadcast | NetworkTypeV3::NonBroadcast
            )
                && iface.state == InterfaceStateV3::DR
                && iface
                    .neighbors
                    .values()
                    .any(|n| n.state == NeighborStateV3::Full);
            if attached_via_network_lsa {
                network_iaps.push((iface.interface_id, iface.area_id, prefixes));
            } else {
                router_prefixes_by_area
                    .entry(iface.area_id)
                    .or_default()
                    .extend(prefixes);
            }
        }

        // Per-network IAPs
        for (interface_id, area_id, prefixes) in network_iaps {
            let lsa = IntraAreaPrefixLsaV3 {
                referenced_ls_type: LsaV3Type::Network as u16,
                referenced_link_state_id: Ipv4Addr::from(interface_id.to_be_bytes()),
                referenced_advertising_router: router_id,
                prefixes,
            };
            let mut body = Vec::new();
            lsa.encode(&mut body);
            // LinkStateId for IAP-LSAs is per-instance; use interface_id
            // to keep network-referencing IAPs unique from the router one.
            let ls_id = Ipv4Addr::from(interface_id.to_be_bytes());
            self.insert_self_lsa(
                LsaV3Type::IntraAreaPrefix,
                ls_id,
                body,
                Some(area_id),
            );
        }

        // Per-area Router IAPs — one per area we participate in.
        // Emit for every area even if the prefix set is empty, so
        // peers always see our router's prefix list in that area.
        let all_areas: std::collections::HashSet<Ipv4Addr> =
            self.interfaces.values().map(|i| i.area_id).collect();
        for area_id in all_areas {
            let prefixes = router_prefixes_by_area.remove(&area_id).unwrap_or_default();
            let lsa = IntraAreaPrefixLsaV3 {
                referenced_ls_type: LsaV3Type::Router as u16,
                referenced_link_state_id: Ipv4Addr::UNSPECIFIED,
                referenced_advertising_router: router_id,
                prefixes,
            };
            let mut body = Vec::new();
            lsa.encode(&mut body);
            self.insert_self_lsa(
                LsaV3Type::IntraAreaPrefix,
                Ipv4Addr::UNSPECIFIED,
                body,
                Some(area_id),
            );
        }
    }

    /// Insert/refresh a self-originated LSA with the given type, link-state-id,
    /// and pre-encoded body. Computes the Fletcher checksum, bumps the sequence
    /// number if the LSA already exists, stores in the LSDB, and floods.
    fn insert_self_lsa(
        &mut self,
        ls_type: LsaV3Type,
        link_state_id: Ipv4Addr,
        body: Vec<u8>,
        area: Option<Ipv4Addr>,
    ) {
        let router_id = self.router_id;
        let mut header = LsaV3Header {
            ls_age: 0,
            ls_type,
            link_state_id,
            advertising_router: router_id,
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: (LSA_V3_HEADER_LEN + body.len()) as u16,
        };
        if let Some(existing) = self.lsdb.get(&crate::lsdb_v3::LsaKeyV3 {
            area,
            ls_type,
            link_state_id,
            advertising_router: router_id,
        }) {
            header.ls_sequence_number = existing.header.ls_sequence_number.wrapping_add(1);
        }
        let mut raw = Vec::with_capacity(header.length as usize);
        header.encode(&mut raw);
        raw.extend_from_slice(&body);
        let (c0, c1) = fletcher16(&raw[2..], 14);
        raw[16] = c0;
        raw[17] = c1;
        header.ls_checksum = ((c0 as u16) << 8) | c1 as u16;
        let entry = LsaEntryV3 {
            header: header.clone(),
            raw,
            area,
        };
        self.lsdb.insert(entry.clone());
        tracing::debug!(
            ls_type = ?ls_type,
            link_state_id = %link_state_id,
            seq = format!("{:#x}", header.ls_sequence_number),
            "originated OSPFv3 self LSA"
        );
        self.flood_lsa(&entry, None);
    }

    /// Emit pending LSR/LSU/LSAck packets for all neighbors.
    pub fn emit_pending_lsdb_packets(&mut self) -> Vec<TxPacketV3> {
        let router_id = self.router_id;
        let mut out = Vec::new();
        for iface in self.interfaces.values_mut() {
            if iface.state == InterfaceStateV3::Down {
                continue;
            }
            let area_id = iface.area_id;
            let instance_id = iface.instance_id;
            let sw_if_index = iface.io.sw_if_index;
            let src_addr = iface.io.link_local;

            for neighbor in iface.neighbors.values_mut() {
                if neighbor.state < NeighborStateV3::Exchange {
                    continue;
                }
                let dst = neighbor.link_local;

                // 1. LSR — drain request_list (we send one LSR with all)
                if neighbor.lsr_pending && !neighbor.request_list.is_empty() {
                    neighbor.lsr_pending = false;
                    let requests: Vec<LsRequestV3> = neighbor
                        .request_list
                        .iter()
                        .map(|h| LsRequestV3 {
                            ls_type: h.ls_type,
                            link_state_id: h.link_state_id,
                            advertising_router: h.advertising_router,
                        })
                        .collect();
                    tracing::debug!(
                        router_id = %neighbor.router_id,
                        count = requests.len(),
                        "OSPFv3 sending LSR"
                    );
                    let pkt = LsRequestV3Packet { requests };
                    let mut body = Vec::new();
                    pkt.encode(&mut body);
                    out.push(Self::build_v3_packet(
                        router_id,
                        area_id,
                        instance_id,
                        Ospfv3PacketType::LinkStateRequest,
                        body,
                        sw_if_index,
                        src_addr,
                        dst,
                    ));
                }

                // 2. LSU — drain pending_lsu (response to peer's LSR)
                if !neighbor.pending_lsu.is_empty() {
                    let lsas = std::mem::take(&mut neighbor.pending_lsu);
                    let pkt = LsUpdateV3Packet { lsas };
                    let mut body = Vec::new();
                    pkt.encode(&mut body);
                    out.push(Self::build_v3_packet(
                        router_id,
                        area_id,
                        instance_id,
                        Ospfv3PacketType::LinkStateUpdate,
                        body,
                        sw_if_index,
                        src_addr,
                        dst,
                    ));
                }

                // 3. LSAck — drain pending_acks
                if !neighbor.pending_acks.is_empty() {
                    let headers = std::mem::take(&mut neighbor.pending_acks);
                    let pkt = LsAckV3Packet { headers };
                    let mut body = Vec::new();
                    pkt.encode(&mut body);
                    out.push(Self::build_v3_packet(
                        router_id,
                        area_id,
                        instance_id,
                        Ospfv3PacketType::LinkStateAck,
                        body,
                        sw_if_index,
                        src_addr,
                        dst,
                    ));
                }
            }
        }
        out
    }

    fn build_v3_packet(
        router_id: Ipv4Addr,
        area_id: Ipv4Addr,
        instance_id: u8,
        packet_type: Ospfv3PacketType,
        body: Vec<u8>,
        sw_if_index: u32,
        src_addr: Ipv6Addr,
        dst_addr: Ipv6Addr,
    ) -> TxPacketV3 {
        let mut hdr = Ospfv3Header::new(packet_type, router_id, area_id);
        hdr.packet_length = (OSPFV3_HEADER_LEN + body.len()) as u16;
        hdr.instance_id = instance_id;
        let mut buf = Vec::with_capacity(hdr.packet_length as usize);
        hdr.encode(&mut buf);
        buf.extend_from_slice(&body);
        TxPacketV3 {
            sw_if_index,
            src_addr,
            dst_addr,
            data: buf,
        }
    }

    /// Emit DD packets for any neighbor that needs one (initial DD in
    /// ExStart, or next chunk in Exchange as master). Retransmits last
    /// DD for ExStart peers if the retransmit interval has elapsed.
    pub fn emit_pending_dds(&mut self, now: Instant) -> Vec<TxPacketV3> {
        let router_id = self.router_id;
        let our_headers = self.lsdb.headers();
        let mut out = Vec::new();
        const RXMT: Duration = Duration::from_secs(5);

        for iface in self.interfaces.values_mut() {
            if iface.state == InterfaceStateV3::Down {
                continue;
            }
            let area_id = iface.area_id;
            let instance_id = iface.instance_id;
            let sw_if_index = iface.io.sw_if_index;
            let src_addr = iface.io.link_local;

            let candidates: Vec<Ipv4Addr> = iface
                .neighbors
                .iter()
                .filter(|(_, n)| match n.state {
                    NeighborStateV3::ExStart => {
                        n.last_dd_tx.is_none() || now.duration_since(n.last_dd_sent) >= RXMT
                    }
                    NeighborStateV3::Exchange => {
                        n.dd_response_pending
                            || (n.dd_master && !n.dd_summary_tx.is_empty())
                            || now.duration_since(n.last_dd_sent) >= RXMT
                    }
                    // Slave post-finish: emit the final echo DD.
                    NeighborStateV3::Loading | NeighborStateV3::Full => n.dd_send_final,
                    _ => false,
                })
                .map(|(id, _)| *id)
                .collect();

            for nid in candidates {
                let Some(neighbor) = iface.neighbors.get_mut(&nid) else { continue };
                if neighbor.state == NeighborStateV3::ExStart && neighbor.dd_seq == 0 {
                    neighbor.dd_seq = (now.elapsed().as_secs() as u32).max(1);
                }
                let data = Self::build_dd(router_id, area_id, instance_id, neighbor, 1500);
                let dst = neighbor.link_local;
                out.push(TxPacketV3 {
                    sw_if_index,
                    src_addr,
                    dst_addr: dst,
                    data,
                });
                // DD exchange finalization: after the final drain-
                // send, if our tx is empty AND peer has said done,
                // both sides have exchanged all headers. Advance
                // to Loading/Full. Works for both master and slave;
                // build_dd already emitted the actual packet.
                if neighbor.state == NeighborStateV3::Exchange
                    && neighbor.dd_peer_done
                    && neighbor.dd_summary_tx.is_empty()
                {
                    Self::finish_dd(neighbor, &our_headers);
                    // Mark the interface dirty so the next tick
                    // refreshes our Router-LSA with this new Full
                    // adjacency's link.
                    iface.needs_router_lsa_refresh = true;
                }
            }
        }
        out
    }

    /// Build a DD packet body for a neighbor given the max headers to include.
    pub fn build_dd(
        router_id: Ipv4Addr,
        area_id: Ipv4Addr,
        instance_id: u8,
        neighbor: &mut NeighborV3,
        mtu: u16,
    ) -> Vec<u8> {
        let max_headers = ((mtu as usize).saturating_sub(OSPFV3_HEADER_LEN + 12)) / 20;
        let mut flags = 0u8;
        let mut headers = Vec::new();

        if neighbor.state == NeighborStateV3::ExStart {
            // Initial DD: empty headers, I|M|MS set, our seq.
            flags = DD_V3_FLAG_I | DD_V3_FLAG_M | DD_V3_FLAG_MS;
        } else if neighbor.state == NeighborStateV3::Exchange {
            let take = neighbor.dd_summary_tx.len().min(max_headers);
            headers = neighbor.dd_summary_tx.drain(..take).collect();
            if !neighbor.dd_summary_tx.is_empty() {
                flags |= DD_V3_FLAG_M;
            }
            if neighbor.dd_master {
                flags |= DD_V3_FLAG_MS;
            }
        }
        // Master finalization: after the drain above, if we're
        // master, our tx list is fully drained AND the peer already
        // signalled done (dd_peer_done), THEN the DD we're about to
        // send is our final one. Emit it, then advance to finish_dd
        // out-of-band so we don't keep the Exchange state around.
        let master_should_finalize = neighbor.state == NeighborStateV3::Exchange
            && neighbor.dd_master
            && neighbor.dd_peer_done
            && neighbor.dd_summary_tx.is_empty();
        // Slave post-finish: emit one final empty DD (no flags) echoing
        // master's seq. Clears dd_send_final.
        if neighbor.dd_send_final {
            neighbor.dd_send_final = false;
        }

        let dd = DbDescV3Packet {
            options: Options::standard().0,
            interface_mtu: mtu,
            flags,
            dd_sequence_number: neighbor.dd_seq,
            lsa_headers: headers,
        };
        let mut body = Vec::new();
        dd.encode(&mut body);

        let mut hdr = Ospfv3Header::new(
            Ospfv3PacketType::DatabaseDescription,
            router_id,
            area_id,
        );
        hdr.packet_length = (OSPFV3_HEADER_LEN + body.len()) as u16;
        hdr.instance_id = instance_id;

        let mut buf = Vec::with_capacity(hdr.packet_length as usize);
        hdr.encode(&mut buf);
        buf.extend_from_slice(&body);

        neighbor.last_dd_tx = Some(dd);
        neighbor.last_dd_sent = Instant::now();
        neighbor.dd_response_pending = false;
        let _ = master_should_finalize;
        buf
    }

    fn process_hello(
        router_id: Ipv4Addr,
        iface: &mut InterfaceV3,
        src_router_id: Ipv4Addr,
        src_addr: Ipv6Addr,
        hello: HelloV3Packet,
    ) {
        // Drop Hellos on an administratively/operationally Down
        // interface. VPP may have marked the interface down while the
        // kernel TAP still delivers packets to our raw socket — we must
        // not let an incoming Hello clobber the Down state set by the
        // refresh path.
        if iface.state == InterfaceStateV3::Down {
            return;
        }

        if hello.hello_interval != iface.hello_interval
            || hello.router_dead_interval != iface.dead_interval
        {
            tracing::warn!(
                "OSPFv3 hello mismatch from {}: intervals differ",
                src_router_id
            );
            return;
        }

        let now = Instant::now();
        let peer_saw_us = hello.neighbors.iter().any(|rid| *rid == router_id);

        let neighbor = iface
            .neighbors
            .entry(src_router_id)
            .or_insert_with(|| NeighborV3 {
                router_id: src_router_id,
                interface_id: hello.interface_id,
                link_local: src_addr,
                priority: hello.router_priority,
                dr: hello.designated_router_id,
                bdr: hello.backup_designated_router_id,
                state: NeighborStateV3::Down,
                last_hello: now,
                dd_master: false,
                dd_seq: 0,
                dd_summary_recv: Vec::new(),
                dd_summary_tx: Vec::new(),
                last_dd_tx: None,
                last_dd_sent: now - Duration::from_secs(3600),
                request_list: Vec::new(),
                pending_acks: Vec::new(),
                pending_lsu: Vec::new(),
                lsr_pending: false,
                dd_response_pending: false,
                dd_send_final: false,
                dd_peer_done: false,
            });

        let prev_state = neighbor.state;
        neighbor.last_hello = now;
        neighbor.interface_id = hello.interface_id;
        neighbor.link_local = src_addr;
        neighbor.priority = hello.router_priority;
        neighbor.dr = hello.designated_router_id;
        neighbor.bdr = hello.backup_designated_router_id;

        // HelloReceived: Down -> Init (1-Way)
        if neighbor.state == NeighborStateV3::Down {
            neighbor.state = NeighborStateV3::Init;
        }

        // 2-WayReceived: peer lists us -> at least 2-Way
        // 1-WayReceived: peer dropped us -> back to Init
        if peer_saw_us {
            if neighbor.state == NeighborStateV3::Init {
                neighbor.state = NeighborStateV3::TwoWay;
                tracing::info!(
                    router_id = %src_router_id,
                    "OSPFv3 neighbor reached 2-Way"
                );
            }
        } else if neighbor.state >= NeighborStateV3::TwoWay {
            neighbor.state = NeighborStateV3::Init;
        }

        if prev_state != neighbor.state {
            tracing::debug!(
                router_id = %src_router_id,
                from = ?prev_state,
                to = ?neighbor.state,
                "OSPFv3 neighbor state change"
            );
        }

        if matches!(
            iface.network_type,
            NetworkTypeV3::Broadcast | NetworkTypeV3::NonBroadcast
        ) {
            Self::dr_election(router_id, iface);
        }

        // AdjOk: on PtP always form adjacency; on broadcast only if we
        // or the peer is DR/BDR.
        let iface_state = iface.state;
        let network_type = iface.network_type;
        if let Some(neighbor) = iface.neighbors.get_mut(&src_router_id) {
            let should_adj = match network_type {
                NetworkTypeV3::PointToPoint | NetworkTypeV3::PointToMultipoint => true,
                NetworkTypeV3::Broadcast | NetworkTypeV3::NonBroadcast => {
                    iface_state == InterfaceStateV3::DR
                        || iface_state == InterfaceStateV3::Backup
                        || neighbor.dr == neighbor.router_id
                        || neighbor.bdr == neighbor.router_id
                        || neighbor.dr == router_id
                        || neighbor.bdr == router_id
                }
            };
            if should_adj && neighbor.state == NeighborStateV3::TwoWay {
                neighbor.state = NeighborStateV3::ExStart;
                neighbor.dd_seq = 0;
                tracing::info!(
                    router_id = %src_router_id,
                    "OSPFv3 neighbor → ExStart (AdjOk)"
                );
            }
        }
    }

    /// DR/BDR election per RFC 5340 §4.2.5 (which references RFC 2328
    /// §9.4 — the OSPFv2 algorithm applies unchanged to v3, with
    /// router-ids replacing IP addresses as the candidate identity).
    ///
    /// Three passes:
    ///   1. BDR candidates: 2-Way+ neighbors and ourselves with
    ///      priority > 0 who do NOT declare themselves DR. Prefer
    ///      those declaring themselves BDR, break ties by priority,
    ///      then router-id.
    ///   2. DR candidates: same set, but only those declaring
    ///      themselves DR. If empty, the BDR is promoted.
    ///   3. Rerun-on-self-change: if the newly elected DR or BDR
    ///      includes ourselves but didn't before (or vice-versa),
    ///      re-run with our updated declarations folded in. This is
    ///      the RFC step that gives incumbent preference and
    ///      prevents transient flap when our own state changes.
    fn dr_election(self_router_id: Ipv4Addr, iface: &mut InterfaceV3) {
        struct Candidate {
            router_id: Ipv4Addr,
            priority: u8,
            declared_dr: Ipv4Addr,
            declared_bdr: Ipv4Addr,
        }

        // Up to two iterations: first with our existing declarations,
        // second (if we're in or out) with the freshly elected
        // declarations folded in.
        let mut self_declared_dr = iface.dr;
        let mut self_declared_bdr = iface.bdr;
        let mut new_dr;
        let mut new_bdr;
        let mut iteration = 0;
        loop {
            iteration += 1;
            let mut candidates: Vec<Candidate> = iface
                .neighbors
                .values()
                .filter(|n| n.state >= NeighborStateV3::TwoWay && n.priority > 0)
                .map(|n| Candidate {
                    router_id: n.router_id,
                    priority: n.priority,
                    declared_dr: n.dr,
                    declared_bdr: n.bdr,
                })
                .collect();
            if iface.priority > 0 {
                candidates.push(Candidate {
                    router_id: self_router_id,
                    priority: iface.priority,
                    declared_dr: self_declared_dr,
                    declared_bdr: self_declared_bdr,
                });
            }

            // Step 2: BDR. Among candidates not declaring themselves
            // DR, prefer those declaring themselves BDR, then by
            // priority, then router-id.
            let bdr = candidates
                .iter()
                .filter(|c| c.declared_dr != c.router_id)
                .max_by(|a, b| {
                    let a_self_bdr = a.declared_bdr == a.router_id;
                    let b_self_bdr = b.declared_bdr == b.router_id;
                    a_self_bdr
                        .cmp(&b_self_bdr)
                        .then(a.priority.cmp(&b.priority))
                        .then(a.router_id.cmp(&b.router_id))
                })
                .map(|c| c.router_id);

            // Step 3: DR. Among candidates declaring themselves DR,
            // pick by priority then router-id. Fallback to BDR.
            let dr_declarer = candidates
                .iter()
                .filter(|c| c.declared_dr == c.router_id)
                .max_by(|a, b| {
                    a.priority
                        .cmp(&b.priority)
                        .then(a.router_id.cmp(&b.router_id))
                })
                .map(|c| c.router_id);
            new_dr = dr_declarer.or(bdr).unwrap_or(Ipv4Addr::UNSPECIFIED);

            // If the BDR candidate just got promoted to DR, re-elect
            // BDR from the remaining candidates (otherwise we'd have
            // no BDR at all on a 2-router segment).
            new_bdr = if Some(new_dr) == bdr {
                candidates
                    .iter()
                    .filter(|c| c.router_id != new_dr)
                    .max_by(|a, b| {
                        a.priority
                            .cmp(&b.priority)
                            .then(a.router_id.cmp(&b.router_id))
                    })
                    .map(|c| c.router_id)
                    .unwrap_or(Ipv4Addr::UNSPECIFIED)
            } else {
                bdr.unwrap_or(Ipv4Addr::UNSPECIFIED)
            };

            // Step 4 (rerun, RFC 2328 §9.4): if the election result
            // changed our own role, re-run once with our updated
            // declarations. This is the incumbent-preference step
            // — it ensures that, e.g., when the DR fails and we get
            // promoted from BDR to DR, the second pass produces a
            // self-consistent result (self.declared_dr == self).
            //
            // The rerun is only meaningful if we had a PRIOR role.
            // On a fresh segment where both routers boot from
            // declared_dr/bdr = UNSPEC, the rerun would oscillate
            // between candidate roles (each iteration flipping who
            // is DR vs. BDR) because there's no incumbent to
            // stabilise around. Skip it in that case.
            let had_prior_role = self_declared_dr == self_router_id
                || self_declared_bdr == self_router_id;
            let was_dr = self_declared_dr == self_router_id;
            let was_bdr = self_declared_bdr == self_router_id;
            let is_dr = new_dr == self_router_id;
            let is_bdr = new_bdr == self_router_id;
            if iteration < 2
                && had_prior_role
                && (was_dr != is_dr || was_bdr != is_bdr)
            {
                self_declared_dr = new_dr;
                self_declared_bdr = new_bdr;
                continue;
            }
            break;
        }

        let new_state = if new_dr == self_router_id {
            InterfaceStateV3::DR
        } else if new_bdr == self_router_id {
            InterfaceStateV3::Backup
        } else {
            InterfaceStateV3::DROther
        };

        if iface.dr != new_dr || iface.bdr != new_bdr || iface.state != new_state {
            tracing::info!(
                iface = %iface.io.name,
                dr = %new_dr,
                bdr = %new_bdr,
                state = ?new_state,
                "OSPFv3 DR election result"
            );
        }
        iface.dr = new_dr;
        iface.bdr = new_bdr;
        iface.state = new_state;
    }
}

/// Returns true if `addr` is contained within the IPv6 prefix
/// `summary_prefix/summary_len`. Component suppression for v3
/// summary-address ranges.
fn prefix_covered_by_v6(addr: Ipv6Addr, summary_prefix: Ipv6Addr, summary_len: u8) -> bool {
    if summary_len == 0 {
        return true;
    }
    if summary_len > 128 {
        return false;
    }
    let addr_bits = u128::from_be_bytes(addr.octets());
    let prefix_bits = u128::from_be_bytes(summary_prefix.octets());
    let mask: u128 = (!0u128) << (128 - summary_len);
    (addr_bits & mask) == (prefix_bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_io(name: &str, sw_if_index: u32) -> IoInterfaceV3 {
        IoInterfaceV3 {
            name: name.to_string(),
            sw_if_index,
            kernel_ifindex: sw_if_index,
            link_local: "fe80::1".parse().unwrap(),
            mac_address: [0; 6],
        }
    }

    #[test]
    fn test_instance_creation() {
        let mut inst = InstanceV3::new(Ipv4Addr::new(1, 1, 1, 1));
        inst.add_interface(
            test_io("eth0", 1),
            Ipv4Addr::UNSPECIFIED,
            NetworkTypeV3::Broadcast,
            10,
            40,
            1,
            Vec::new(),
        );
        assert_eq!(inst.interfaces.len(), 1);
        let iface = inst.interfaces.get(&1).unwrap();
        assert_eq!(iface.state, InterfaceStateV3::Waiting);
    }

    #[test]
    fn test_originate_inter_area_prefix_lsas_as_abr() {
        // Two interfaces in two areas (backbone + area 1) → ABR.
        // Each area has a local prefix on our interface. As an ABR
        // we should emit Type 3 into each area summarizing the OTHER.
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let mut inst = InstanceV3::new(self_rid);
        let area0 = Ipv4Addr::UNSPECIFIED;
        let area1 = Ipv4Addr::new(0, 0, 0, 1);
        let mut io0 = test_io("eth0", 1);
        io0.link_local = "fe80::1".parse().unwrap();
        let mut io1 = test_io("eth1", 2);
        io1.link_local = "fe80::2".parse().unwrap();
        inst.add_interface(
            io0,
            area0,
            NetworkTypeV3::PointToPoint,
            10,
            40,
            1,
            vec![("2001:db8:0::".parse().unwrap(), 64)],
        );
        inst.add_interface(
            io1,
            area1,
            NetworkTypeV3::PointToPoint,
            10,
            40,
            1,
            vec![("2001:db8:1::".parse().unwrap(), 64)],
        );
        assert!(inst.is_abr(), "should be ABR with backbone + area1");

        // Originate our own Router-LSA + IAP-LSAs. Since both areas
        // see only our own Router-LSA (no peers), the per-area SPF
        // will produce only our own prefixes as intra-area routes.
        inst.originate_router_lsa();
        inst.originate_intra_area_prefix_lsas();
        inst.originate_inter_area_prefix_lsas();

        // Check: in area1, a Type 3 exists for 2001:db8:0::/64.
        // In area0, a Type 3 exists for 2001:db8:1::/64.
        let mut area0_has_area1_prefix = false;
        let mut area1_has_area0_prefix = false;
        for entry in inst.lsdb.iter() {
            if entry.header.ls_type != LsaV3Type::InterAreaPrefix {
                continue;
            }
            if entry.header.advertising_router != self_rid {
                continue;
            }
            let body =
                &entry.raw[crate::packet_v3::lsa::LSA_V3_HEADER_LEN..];
            let ia = crate::packet_v3::lsa::InterAreaPrefixLsaV3::parse(body).unwrap();
            let addr = ia.prefix.address;
            if entry.area == Some(area0) && addr == "2001:db8:1::".parse::<Ipv6Addr>().unwrap() {
                area0_has_area1_prefix = true;
            }
            if entry.area == Some(area1) && addr == "2001:db8:0::".parse::<Ipv6Addr>().unwrap() {
                area1_has_area0_prefix = true;
            }
        }
        assert!(area0_has_area1_prefix, "area 0 should summarize area 1");
        assert!(area1_has_area0_prefix, "area 1 should summarize area 0");
    }

    #[test]
    fn test_originate_external_lsas() {
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let mut inst = InstanceV3::new(self_rid);
        inst.add_interface(
            test_io("eth0", 1),
            Ipv4Addr::UNSPECIFIED,
            NetworkTypeV3::Broadcast,
            10,
            40,
            1,
            Vec::new(),
        );
        inst.set_asbr(true);
        inst.redistribute = vec![(crate::config::RedistributeSource::Connected, 20, 2)];

        let externals = vec![
            ("2001:db8:1::".parse::<Ipv6Addr>().unwrap(), 64u8),
            ("2001:db8:2::".parse::<Ipv6Addr>().unwrap(), 64u8),
        ];
        inst.originate_external_lsas(externals, &[]);

        // Two Type 5 LSAs should exist in the LSDB, AS-scope (area = None)
        let type5: Vec<_> = inst
            .lsdb
            .iter()
            .filter(|e| {
                e.header.ls_type == LsaV3Type::AsExternal
                    && e.header.advertising_router == self_rid
                    && e.area.is_none()
            })
            .collect();
        assert_eq!(type5.len(), 2, "expected 2 self-originated Type 5 LSAs");

        // Re-originating with the same set should bump sequence numbers
        let old_seq: i32 = type5[0].header.ls_sequence_number;
        let key = crate::lsdb_v3::LsaKeyV3 {
            area: None,
            ls_type: LsaV3Type::AsExternal,
            link_state_id: type5[0].header.link_state_id,
            advertising_router: self_rid,
        };
        let externals2 = vec![
            ("2001:db8:1::".parse::<Ipv6Addr>().unwrap(), 64u8),
            ("2001:db8:2::".parse::<Ipv6Addr>().unwrap(), 64u8),
        ];
        inst.originate_external_lsas(externals2, &[]);
        let new_seq = inst.lsdb.get(&key).unwrap().header.ls_sequence_number;
        assert!(new_seq > old_seq, "sequence should bump on refresh");

        // Router-LSA must carry the E flag
        let rlsa_key = crate::lsdb_v3::LsaKeyV3 {
            area: Some(Ipv4Addr::UNSPECIFIED),
            ls_type: LsaV3Type::Router,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: self_rid,
        };
        inst.originate_router_lsa();
        let rlsa = inst.lsdb.get(&rlsa_key).unwrap();
        // Router-LSA body starts at offset LSA_V3_HEADER_LEN; first byte is flags
        let flags = rlsa.raw[LSA_V3_HEADER_LEN];
        assert!(
            flags & RouterLsaV3::FLAG_E != 0,
            "E flag should be set when ASBR"
        );
    }

    #[test]
    fn test_external_lsa_flush_on_shrinking_set() {
        // When the externals set shrinks between calls to
        // originate_external_lsas, the previously-emitted Type 5
        // LSAs that no longer have a backing prefix must be
        // MaxAge-flushed (RFC 2328 §14.1: premature aging of self-
        // originated LSAs). Without this, withdrawn prefixes hang
        // around on peers until LSRefreshTime ticks them out.
        use crate::packet_v3::lsa::MAX_AGE;

        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let mut inst = InstanceV3::new(self_rid);
        inst.add_interface(
            test_io("eth0", 1),
            Ipv4Addr::UNSPECIFIED,
            NetworkTypeV3::Broadcast,
            10,
            40,
            1,
            Vec::new(),
        );
        inst.set_asbr(true);
        inst.redistribute = vec![(crate::config::RedistributeSource::Connected, 20, 2)];

        // Originate three externals, then shrink to one.
        let three = vec![
            ("2001:db8:1::".parse::<Ipv6Addr>().unwrap(), 64u8),
            ("2001:db8:2::".parse::<Ipv6Addr>().unwrap(), 64u8),
            ("2001:db8:3::".parse::<Ipv6Addr>().unwrap(), 64u8),
        ];
        inst.originate_external_lsas(three, &[]);

        let alive_count = |inst: &InstanceV3| -> usize {
            inst.lsdb
                .iter()
                .filter(|e| {
                    e.header.ls_type == LsaV3Type::AsExternal
                        && e.header.advertising_router == self_rid
                        && e.header.ls_age < MAX_AGE
                })
                .count()
        };
        let max_age_count = |inst: &InstanceV3| -> usize {
            inst.lsdb
                .iter()
                .filter(|e| {
                    e.header.ls_type == LsaV3Type::AsExternal
                        && e.header.advertising_router == self_rid
                        && e.header.ls_age == MAX_AGE
                })
                .count()
        };
        assert_eq!(alive_count(&inst), 3, "three externals should be alive");
        assert_eq!(max_age_count(&inst), 0);

        // Shrink to one.
        let one = vec![("2001:db8:1::".parse::<Ipv6Addr>().unwrap(), 64u8)];
        inst.originate_external_lsas(one, &[]);

        // Now: 1 alive (the surviving prefix at link-state-id 0.0.0.1),
        // 2 MaxAge-flushed (link-state-ids 0.0.0.2 and 0.0.0.3).
        assert_eq!(
            alive_count(&inst),
            1,
            "exactly one external should remain alive"
        );
        assert_eq!(
            max_age_count(&inst),
            2,
            "two flushed externals should be MaxAge-marked"
        );

        // Empty list: everything we ever originated should be flushed.
        inst.originate_external_lsas(Vec::new(), &[]);
        assert_eq!(alive_count(&inst), 0);
        assert_eq!(max_age_count(&inst), 3);
    }

    /// Verifies v3 P2MP behavior: the interface starts in
    /// PointToPoint state (skipping Wait/election), and the
    /// Router-LSA emits one TYPE_POINT_TO_POINT link per Full
    /// neighbor — same shape as plain P2P but with potentially
    /// many neighbors on a single interface.
    #[test]
    fn p2mp_v3_skips_election_and_emits_per_neighbor_links() {
        use crate::packet_v3::lsa::RouterLsaV3;

        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let mut inst = InstanceV3::new(self_rid);
        inst.add_interface(
            test_io("eth0", 1),
            Ipv4Addr::UNSPECIFIED,
            NetworkTypeV3::PointToMultipoint,
            10,
            40,
            1,
            Vec::new(),
        );
        let iface = inst.interfaces.get(&1).unwrap();
        assert_eq!(
            iface.state,
            InterfaceStateV3::PointToPoint,
            "P2MP starts in PointToPoint state, not Waiting"
        );

        // Inject two Full peers.
        for (rid, ll) in [
            (
                Ipv4Addr::new(2, 2, 2, 2),
                "fe80::2".parse::<Ipv6Addr>().unwrap(),
            ),
            (
                Ipv4Addr::new(3, 3, 3, 3),
                "fe80::3".parse::<Ipv6Addr>().unwrap(),
            ),
        ] {
            add_neighbor(&mut inst, 1, rid, NeighborStateV3::Full);
            // Set link-local on the freshly-added neighbor so the
            // LSA build path has something to refer to.
            let n = inst
                .interfaces
                .get_mut(&1)
                .unwrap()
                .neighbors
                .get_mut(&rid)
                .unwrap();
            n.link_local = ll;
        }

        inst.originate_router_lsa();
        let area_id = Ipv4Addr::UNSPECIFIED;
        let key = crate::lsdb_v3::LsaKeyV3 {
            area: Some(area_id),
            ls_type: LsaV3Type::Router,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: self_rid,
        };
        let entry = inst.lsdb.get(&key).expect("self Router-LSA present");
        let body = &entry.raw[crate::packet_v3::lsa::LSA_V3_HEADER_LEN..];
        let lsa = RouterLsaV3::parse(body).expect("parses");
        // Both peers in Full → 2 P2P link entries in the Router-LSA.
        let p2p_count = lsa
            .links
            .iter()
            .filter(|l| l.link_type == crate::packet_v3::lsa::RouterLinkV3::TYPE_POINT_TO_POINT)
            .count();
        assert_eq!(
            p2p_count, 2,
            "P2MP Router-LSA should have one TYPE_POINT_TO_POINT link per Full peer"
        );
    }

    /// Verifies the v3 DR election now properly tracks BDR (it
    /// used to ignore BDR entirely) and that the rerun step
    /// preserves an incumbent DR when a higher-priority router
    /// shows up later.
    #[test]
    fn dr_election_v3_incumbent_preserved_against_higher_priority_arrival() {
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let mut inst = InstanceV3::new(self_rid);
        inst.add_interface(
            test_io("eth0", 1),
            Ipv4Addr::UNSPECIFIED,
            NetworkTypeV3::Broadcast,
            10,
            40,
            5, // priority — high enough to start as DR
            Vec::new(),
        );

        // Step 1: alone on the segment, we should become DR after
        // the first election (call dr_election directly to skip
        // the wait timer).
        InstanceV3::dr_election(self_rid, inst.interfaces.get_mut(&1).unwrap());
        assert_eq!(
            inst.interfaces[&1].dr,
            self_rid,
            "alone on segment, we should be DR"
        );

        // Step 2: a higher-priority router appears via Hello.
        // Its declared_dr/_bdr are UNSPEC (it just booted). Despite
        // its higher priority, our incumbency should preserve us
        // as DR.
        let intruder = Ipv4Addr::new(2, 2, 2, 2);
        let iface = inst.interfaces.get_mut(&1).unwrap();
        iface.neighbors.insert(
            intruder,
            NeighborV3 {
                router_id: intruder,
                interface_id: 99,
                link_local: "fe80::2".parse().unwrap(),
                priority: 250, // way higher than ours
                dr: Ipv4Addr::UNSPECIFIED,
                bdr: Ipv4Addr::UNSPECIFIED,
                state: NeighborStateV3::TwoWay,
                last_hello: Instant::now(),
                dd_master: false,
                dd_seq: 0,
                dd_summary_recv: Vec::new(),
                dd_summary_tx: Vec::new(),
                last_dd_tx: None,
                last_dd_sent: Instant::now(),
                dd_response_pending: false,
                request_list: Vec::new(),
                pending_acks: Vec::new(),
                pending_lsu: Vec::new(),
                lsr_pending: false,
                dd_send_final: false,
                dd_peer_done: false,
            },
        );
        InstanceV3::dr_election(self_rid, inst.interfaces.get_mut(&1).unwrap());
        let iface = &inst.interfaces[&1];
        assert_eq!(
            iface.dr, self_rid,
            "incumbent DR must NOT be displaced by higher-priority newcomer"
        );
        assert_eq!(
            iface.bdr, intruder,
            "newcomer should become BDR (no other candidates)"
        );
    }

    #[test]
    fn external_components_inside_summary_v6_are_suppressed() {
        // 2001:db8::/32 covers 2001:db8:1::/48 and 2001:db8:2::/48,
        // so they get suppressed. 2001:dead::/48 falls outside and
        // passes through.
        use crate::config::ParsedSummaryAddress6;

        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let mut inst = InstanceV3::new(self_rid);
        inst.add_interface(
            test_io("eth0", 1),
            Ipv4Addr::UNSPECIFIED,
            NetworkTypeV3::Broadcast,
            10,
            40,
            1,
            Vec::new(),
        );
        inst.set_asbr(true);
        inst.redistribute = vec![(crate::config::RedistributeSource::Connected, 20, 2)];

        let summaries = vec![ParsedSummaryAddress6 {
            prefix: "2001:db8::".parse().unwrap(),
            prefix_len: 32,
            no_advertise: false,
            tag: 0,
            metric: 100,
            metric_type: 2,
        }];
        let externals = vec![
            ("2001:db8:1::".parse::<Ipv6Addr>().unwrap(), 48u8),
            ("2001:db8:2::".parse::<Ipv6Addr>().unwrap(), 48u8),
            ("2001:dead::".parse::<Ipv6Addr>().unwrap(), 48u8),
        ];
        inst.originate_external_lsas(externals, &summaries);

        // Only the non-covered prefix should be alive at one of
        // the sequential link-state-ids (0.0.0.1+).
        let alive: Vec<_> = inst
            .lsdb
            .iter()
            .filter(|e| {
                e.header.ls_type == LsaV3Type::AsExternal
                    && e.header.advertising_router == self_rid
                    && e.header.ls_age < crate::packet_v3::lsa::MAX_AGE
            })
            .collect();
        assert_eq!(
            alive.len(),
            1,
            "only the 2001:dead::/48 component should be present"
        );
        // ls_id should be 0.0.0.1 — first (and only) sequential id.
        assert_eq!(alive[0].header.link_state_id, Ipv4Addr::new(0, 0, 0, 1));
    }

    #[test]
    fn prefix_covered_by_v6_handles_edge_cases() {
        let cover = "2001:db8::".parse().unwrap();
        // /0 covers everything.
        assert!(prefix_covered_by_v6(
            "2001:db8:1::1".parse().unwrap(),
            "::".parse().unwrap(),
            0
        ));
        // /32 matches 2001:db8::/32.
        assert!(prefix_covered_by_v6(
            "2001:db8:1::1".parse().unwrap(),
            cover,
            32
        ));
        // Outside.
        assert!(!prefix_covered_by_v6(
            "2001:dead::1".parse().unwrap(),
            cover,
            32
        ));
        // /128 only matches itself.
        let host: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(prefix_covered_by_v6(host, host, 128));
        assert!(!prefix_covered_by_v6(
            "2001:db8::2".parse().unwrap(),
            host,
            128
        ));
    }

    #[test]
    fn test_hello_tick_emits_packet() {
        let mut inst = InstanceV3::new(Ipv4Addr::new(1, 1, 1, 1));
        inst.add_interface(
            test_io("eth0", 1),
            Ipv4Addr::UNSPECIFIED,
            NetworkTypeV3::Broadcast,
            10,
            40,
            1,
            Vec::new(),
        );
        let now = Instant::now();
        let packets = inst.hello_tick(now);
        assert_eq!(packets.len(), 1);
        // Header parses correctly
        let hdr = Ospfv3Header::parse(&packets[0].data).unwrap();
        assert_eq!(hdr.packet_type, Ospfv3PacketType::Hello);
        assert_eq!(hdr.router_id, Ipv4Addr::new(1, 1, 1, 1));
    }

    #[test]
    fn test_neighbor_discovery_one_way() {
        let mut inst = InstanceV3::new(Ipv4Addr::new(1, 1, 1, 1));
        inst.add_interface(
            test_io("eth0", 1),
            Ipv4Addr::UNSPECIFIED,
            NetworkTypeV3::Broadcast,
            10,
            40,
            1,
            Vec::new(),
        );

        // Build a Hello from a peer that doesn't list us
        let peer_hello = HelloV3Packet {
            interface_id: 5,
            router_priority: 1,
            options: Options::standard(),
            hello_interval: 10,
            router_dead_interval: 40,
            designated_router_id: Ipv4Addr::UNSPECIFIED,
            backup_designated_router_id: Ipv4Addr::UNSPECIFIED,
            neighbors: vec![],
        };
        let mut body = Vec::new();
        peer_hello.encode(&mut body);
        let mut hdr = Ospfv3Header::new(
            Ospfv3PacketType::Hello,
            Ipv4Addr::new(2, 2, 2, 2),
            Ipv4Addr::UNSPECIFIED,
        );
        hdr.packet_length = (OSPFV3_HEADER_LEN + body.len()) as u16;
        let mut data = Vec::new();
        hdr.encode(&mut data);
        data.extend_from_slice(&body);

        inst.handle_rx(RxPacketV3 {
            sw_if_index: 1,
            src_addr: "fe80::2".parse().unwrap(),
            dst_addr: Ipv6Addr::UNSPECIFIED,
            data,
        })
        .unwrap();

        let iface = inst.interfaces.get(&1).unwrap();
        let nb = iface.neighbors.get(&Ipv4Addr::new(2, 2, 2, 2)).unwrap();
        assert_eq!(nb.state, NeighborStateV3::Init);
    }

    #[test]
    fn test_router_lsa_origination_empty() {
        let mut inst = InstanceV3::new(Ipv4Addr::new(1, 1, 1, 1));
        inst.add_interface(
            test_io("eth0", 1),
            Ipv4Addr::UNSPECIFIED,
            NetworkTypeV3::Broadcast,
            10,
            40,
            1,
            Vec::new(),
        );
        inst.originate_router_lsa();
        assert_eq!(inst.lsdb.len(), 1);
        let hdr = &inst.lsdb.headers()[0];
        assert_eq!(hdr.ls_type, LsaV3Type::Router);
        assert_eq!(hdr.advertising_router, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(hdr.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
        // Re-originating should bump the sequence.
        inst.originate_router_lsa();
        let hdr = &inst.lsdb.headers()[0];
        assert_eq!(
            hdr.ls_sequence_number,
            INITIAL_SEQUENCE_NUMBER.wrapping_add(1)
        );
    }

    #[test]
    fn test_neighbor_two_way_when_peer_lists_us() {
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let mut inst = InstanceV3::new(self_rid);
        inst.add_interface(
            test_io("eth0", 1),
            Ipv4Addr::UNSPECIFIED,
            NetworkTypeV3::Broadcast,
            10,
            40,
            1,
            Vec::new(),
        );

        let peer_hello = HelloV3Packet {
            interface_id: 5,
            router_priority: 1,
            options: Options::standard(),
            hello_interval: 10,
            router_dead_interval: 40,
            designated_router_id: Ipv4Addr::UNSPECIFIED,
            backup_designated_router_id: Ipv4Addr::UNSPECIFIED,
            neighbors: vec![self_rid], // peer has seen us
        };
        let mut body = Vec::new();
        peer_hello.encode(&mut body);
        let mut hdr = Ospfv3Header::new(
            Ospfv3PacketType::Hello,
            Ipv4Addr::new(2, 2, 2, 2),
            Ipv4Addr::UNSPECIFIED,
        );
        hdr.packet_length = (OSPFV3_HEADER_LEN + body.len()) as u16;
        let mut data = Vec::new();
        hdr.encode(&mut data);
        data.extend_from_slice(&body);

        inst.handle_rx(RxPacketV3 {
            sw_if_index: 1,
            src_addr: "fe80::2".parse().unwrap(),
            dst_addr: Ipv6Addr::UNSPECIFIED,
            data,
        })
        .unwrap();

        let iface = inst.interfaces.get(&1).unwrap();
        let nb = iface.neighbors.get(&Ipv4Addr::new(2, 2, 2, 2)).unwrap();
        // Two equal-priority routers on a fresh broadcast segment:
        // higher RID becomes DR, lower RID becomes BDR. Both
        // routers form full adjacencies (DR<->BDR), so we
        // immediately promote past TwoWay to ExStart per the
        // AdjOk? rule (we're in Backup state).
        assert_eq!(nb.state, NeighborStateV3::ExStart);
        assert_eq!(iface.dr, Ipv4Addr::new(2, 2, 2, 2));
        assert_eq!(iface.bdr, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(iface.state, InterfaceStateV3::Backup);
    }

    #[test]
    fn test_nssa_rejects_type5_lsa() {
        use crate::area::AreaType;
        use crate::packet_v3::lsa::AsExternalLsaV3;
        use crate::packet_v3::lsu::{LsUpdateV3Packet, LsaV3Raw};

        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let area_id = Ipv4Addr::new(0, 0, 0, 10);
        let mut inst = InstanceV3::new(self_rid);
        inst.set_area_type(area_id, AreaType::Nssa);
        inst.add_interface(
            test_io("eth0", 1),
            area_id,
            NetworkTypeV3::Broadcast,
            10,
            40,
            1,
            Vec::new(),
        );

        // Build a Type 5 LSA and try to inject it via process_lsu.
        let ext = AsExternalLsaV3 {
            metric_type_2: false,
            forwarding_present: false,
            tag_present: false,
            metric: 100,
            prefix: crate::packet_v3::prefix::Ospfv3Prefix {
                prefix_length: 64,
                prefix_options: 0,
                prefix_or_metric: 0,
                address: "2001:db8:ffff::".parse().unwrap(),
            },
            referenced_ls_type: 0,
            forwarding_address: None,
            external_route_tag: None,
            referenced_link_state_id: None,
        };
        let mut body = Vec::new();
        ext.encode(&mut body);
        let header = LsaV3Header {
            ls_age: 0,
            ls_type: LsaV3Type::AsExternal,
            link_state_id: Ipv4Addr::new(0, 0, 0, 1),
            advertising_router: Ipv4Addr::new(2, 2, 2, 2),
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: (LSA_V3_HEADER_LEN + body.len()) as u16,
        };
        let mut raw = Vec::new();
        header.encode(&mut raw);
        raw.extend_from_slice(&body);

        let pkt = LsUpdateV3Packet {
            lsas: vec![LsaV3Raw { header: header.clone(), raw }],
        };
        inst.process_lsu(1, Ipv4Addr::new(2, 2, 2, 2), pkt);

        // LSDB should NOT contain the Type 5 entry.
        let key = crate::lsdb_v3::LsaKeyV3 {
            area: None, // AS-scope
            ls_type: LsaV3Type::AsExternal,
            link_state_id: Ipv4Addr::new(0, 0, 0, 1),
            advertising_router: Ipv4Addr::new(2, 2, 2, 2),
        };
        assert!(
            inst.lsdb.get(&key).is_none(),
            "Type 5 LSA should have been rejected by NSSA area"
        );
    }

    // ------------------------------------------------------------------
    // Test helpers for the state-machine batch below.
    // ------------------------------------------------------------------

    fn inst_with_iface(self_rid: Ipv4Addr, sw_if_index: u32) -> InstanceV3 {
        let mut inst = InstanceV3::new(self_rid);
        inst.add_interface(
            test_io("eth0", sw_if_index),
            Ipv4Addr::UNSPECIFIED,
            NetworkTypeV3::Broadcast,
            10,
            40,
            1,
            Vec::new(),
        );
        inst
    }

    /// Encode a v3 DD packet with the given flags, seq, and headers.
    fn dd_packet_bytes(
        src_rid: Ipv4Addr,
        flags: u8,
        seq: u32,
        headers: Vec<LsaV3Header>,
    ) -> Vec<u8> {
        let dd = DbDescV3Packet {
            options: Options::standard().0,
            interface_mtu: 1500,
            flags,
            dd_sequence_number: seq,
            lsa_headers: headers,
        };
        let mut body = Vec::new();
        dd.encode(&mut body);
        let mut hdr = Ospfv3Header::new(
            Ospfv3PacketType::DatabaseDescription,
            src_rid,
            Ipv4Addr::UNSPECIFIED,
        );
        hdr.packet_length = (OSPFV3_HEADER_LEN + body.len()) as u16;
        let mut buf = Vec::new();
        hdr.encode(&mut buf);
        buf.extend_from_slice(&body);
        buf
    }

    /// Inject an arbitrary neighbor directly into an interface in the
    /// given state. Used to set up state-machine tests without driving
    /// through the Hello → 2-Way path every time.
    fn add_neighbor(
        inst: &mut InstanceV3,
        sw_if_index: u32,
        router_id: Ipv4Addr,
        state: NeighborStateV3,
    ) {
        let iface = inst.interfaces.get_mut(&sw_if_index).unwrap();
        let now = Instant::now();
        let last = router_id.octets()[3] as u16;
        iface.neighbors.insert(
            router_id,
            NeighborV3 {
                router_id,
                interface_id: 5,
                link_local: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, last),
                priority: 1,
                dr: Ipv4Addr::UNSPECIFIED,
                bdr: Ipv4Addr::UNSPECIFIED,
                state,
                last_hello: now,
                dd_master: false,
                dd_seq: 0,
                dd_summary_recv: Vec::new(),
                dd_summary_tx: Vec::new(),
                last_dd_tx: None,
                last_dd_sent: now - Duration::from_secs(3600),
                request_list: Vec::new(),
                pending_acks: Vec::new(),
                pending_lsu: Vec::new(),
                lsr_pending: false,
                dd_response_pending: false,
                dd_send_final: false,
                dd_peer_done: false,
            },
        );
    }

    // ------------------------------------------------------------------
    // DD master/slave negotiation
    // ------------------------------------------------------------------

    #[test]
    fn test_dd_master_negotiation() {
        // self RID > peer RID → we are master. Peer's ack DD arrives
        // with I=0, MS=0, seq matching ours. Expected transition: ExStart
        // → Exchange (master) with dd_summary_tx populated from LSDB.
        let self_rid = Ipv4Addr::new(2, 2, 2, 2);
        let peer = Ipv4Addr::new(1, 1, 1, 1);
        let mut inst = inst_with_iface(self_rid, 1);
        // Seed the LSDB with one self-LSA so dd_summary_tx is non-empty.
        inst.originate_router_lsa();

        add_neighbor(&mut inst, 1, peer, NeighborStateV3::ExStart);
        // Set our initial seq so peer's echo matches.
        let our_seq = 42;
        inst.interfaces
            .get_mut(&1)
            .unwrap()
            .neighbors
            .get_mut(&peer)
            .unwrap()
            .dd_seq = our_seq;

        let dd = dd_packet_bytes(peer, 0, our_seq, Vec::new());
        inst.handle_rx(RxPacketV3 {
            sw_if_index: 1,
            src_addr: "fe80::1".parse().unwrap(),
            dst_addr: Ipv6Addr::UNSPECIFIED,
            data: dd,
        })
        .unwrap();

        let neigh = inst.interfaces[&1].neighbors[&peer].state;
        assert_eq!(neigh, NeighborStateV3::Exchange);
        assert!(inst.interfaces[&1].neighbors[&peer].dd_master);
    }

    /// Regression guard for the OSPFv2 ExchangeDone-too-early bug
    /// (commit 2245e84) ported to v3. When the master receives a
    /// peer DD with M=0, it must NOT immediately fire ExchangeDone
    /// before describing its own LSDB to the peer — otherwise the
    /// peer is left waiting in Exchange forever.
    ///
    /// In v3 the gate is `dd_peer_done && dd_summary_tx.is_empty()`
    /// inside `emit_pending_dds`, evaluated after `build_dd` has
    /// already drained one chunk of headers and pushed the packet
    /// to the TX queue. That ordering means we always emit at least
    /// one content DD before finishing.
    #[test]
    fn dd_v3_master_defers_exchange_done_until_own_dd_sent() {
        let self_rid = Ipv4Addr::new(2, 2, 2, 2);
        let peer = Ipv4Addr::new(1, 1, 1, 1);
        let mut inst = inst_with_iface(self_rid, 1);
        // Seed the LSDB with one self-LSA so dd_summary_tx is
        // non-empty when we enter Exchange.
        inst.originate_router_lsa();
        let our_lsdb_size = inst.lsdb.headers().len();
        assert!(
            our_lsdb_size > 0,
            "precondition: LSDB must have at least one header"
        );

        add_neighbor(&mut inst, 1, peer, NeighborStateV3::ExStart);
        let our_seq = 42;
        inst.interfaces
            .get_mut(&1)
            .unwrap()
            .neighbors
            .get_mut(&peer)
            .unwrap()
            .dd_seq = our_seq;

        // Peer's slave-accept DD: I=0, M=0, MS=0, echoes our seq,
        // empty content. This is exactly the FRR-as-slave case that
        // tripped the v2 bug.
        let dd = dd_packet_bytes(peer, 0, our_seq, Vec::new());
        inst.handle_rx(RxPacketV3 {
            sw_if_index: 1,
            src_addr: "fe80::1".parse().unwrap(),
            dst_addr: Ipv6Addr::UNSPECIFIED,
            data: dd,
        })
        .unwrap();

        // We must be in Exchange — NOT Loading or Full — and our
        // tx queue must contain the headers we still owe the peer.
        {
            let n = &inst.interfaces[&1].neighbors[&peer];
            assert_eq!(
                n.state,
                NeighborStateV3::Exchange,
                "master must stay in Exchange until its own LSDB has been sent"
            );
            assert!(n.dd_master, "we have higher RID, so master");
            assert!(n.dd_peer_done, "peer's M=0 should be remembered");
            assert_eq!(
                n.dd_summary_tx.len(),
                our_lsdb_size,
                "tx queue should hold our headers, ready to send"
            );
        }

        // Now drive emit_pending_dds. This should drain
        // dd_summary_tx into a TX packet AND only then promote past
        // Exchange (dd_peer_done && tx empty → finish_dd).
        let pkts = inst.emit_pending_dds(Instant::now());
        assert!(
            !pkts.is_empty(),
            "emit_pending_dds must produce a content DD before finalising"
        );
        let n = &inst.interfaces[&1].neighbors[&peer];
        assert!(
            n.dd_summary_tx.is_empty(),
            "tx queue should be drained after build_dd"
        );
        assert!(
            n.state >= NeighborStateV3::Loading,
            "with peer M=0 and our tx empty, must finalise to Loading or Full"
        );
    }

    #[test]
    fn test_dd_slave_negotiation() {
        // self RID < peer RID → we are slave. Peer's init DD arrives
        // with I=1, M=1, MS=1 and empty LSA list. Expected transition:
        // ExStart → Exchange (slave), dd_seq echoed from peer.
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let peer = Ipv4Addr::new(2, 2, 2, 2);
        let mut inst = inst_with_iface(self_rid, 1);
        inst.originate_router_lsa();

        add_neighbor(&mut inst, 1, peer, NeighborStateV3::ExStart);

        let peer_seq = 1234;
        let flags = DD_V3_FLAG_I | DD_V3_FLAG_M | DD_V3_FLAG_MS;
        let dd = dd_packet_bytes(peer, flags, peer_seq, Vec::new());
        inst.handle_rx(RxPacketV3 {
            sw_if_index: 1,
            src_addr: "fe80::2".parse().unwrap(),
            dst_addr: Ipv6Addr::UNSPECIFIED,
            data: dd,
        })
        .unwrap();

        let n = &inst.interfaces[&1].neighbors[&peer];
        assert_eq!(n.state, NeighborStateV3::Exchange);
        assert_eq!(n.dd_master, false);
        assert_eq!(n.dd_seq, peer_seq);
    }

    // ------------------------------------------------------------------
    // Loading → Full on request_list drain
    // ------------------------------------------------------------------

    #[test]
    fn test_loading_to_full_on_request_drain() {
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let peer = Ipv4Addr::new(2, 2, 2, 2);
        let mut inst = inst_with_iface(self_rid, 1);
        add_neighbor(&mut inst, 1, peer, NeighborStateV3::Loading);

        // Put one pending request on the neighbor.
        let needed_header = LsaV3Header {
            ls_age: 0,
            ls_type: LsaV3Type::Router,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: peer,
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: LSA_V3_HEADER_LEN as u16 + 4,
        };
        inst.interfaces
            .get_mut(&1)
            .unwrap()
            .neighbors
            .get_mut(&peer)
            .unwrap()
            .request_list
            .push(needed_header.clone());

        // Inject an LSU containing that LSA.
        let mut raw = Vec::new();
        needed_header.encode(&mut raw);
        raw.extend_from_slice(&[0, 0, 0, 0]);
        let pkt = LsUpdateV3Packet {
            lsas: vec![LsaV3Raw {
                header: needed_header,
                raw,
            }],
        };
        inst.process_lsu(1, peer, pkt);

        assert_eq!(
            inst.interfaces[&1].neighbors[&peer].state,
            NeighborStateV3::Full
        );
        assert!(
            inst.interfaces[&1].neighbors[&peer].request_list.is_empty()
        );
    }

    // ------------------------------------------------------------------
    // Restart-seq recovery
    // ------------------------------------------------------------------

    #[test]
    fn test_restart_seq_bumps_stale_self_lsa() {
        // Simulate a daemon restart: our LSDB has a self-LSA at seq X,
        // peer still holds our older instance at seq Y > X. A DD from
        // peer describing (Router, 0.0.0.0, self_rid) at seq Y should
        // cause our local entry's seq to bump so the next refresh
        // outranks the peer's cached copy.
        let self_rid = Ipv4Addr::new(2, 2, 2, 2);
        let peer = Ipv4Addr::new(1, 1, 1, 1);
        let mut inst = inst_with_iface(self_rid, 1);
        inst.originate_router_lsa();
        add_neighbor(&mut inst, 1, peer, NeighborStateV3::ExStart);
        inst.interfaces
            .get_mut(&1)
            .unwrap()
            .neighbors
            .get_mut(&peer)
            .unwrap()
            .dd_seq = 10;
        // Clear the dirty flag so we can check it was re-set.
        inst.interfaces.get_mut(&1).unwrap().needs_router_lsa_refresh = false;

        let stale_seq: i32 = 0x8000_0050u32 as i32;
        let stale_header = LsaV3Header {
            ls_age: 60,
            ls_type: LsaV3Type::Router,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: self_rid,
            ls_sequence_number: stale_seq,
            ls_checksum: 0,
            length: 24,
        };
        let dd = dd_packet_bytes(peer, 0, 10, vec![stale_header]);
        inst.handle_rx(RxPacketV3 {
            sw_if_index: 1,
            src_addr: "fe80::1".parse().unwrap(),
            dst_addr: Ipv6Addr::UNSPECIFIED,
            data: dd,
        })
        .unwrap();

        // Our local Router-LSA's seq should now be at least stale_seq.
        let key = crate::lsdb_v3::LsaKeyV3 {
            area: Some(Ipv4Addr::UNSPECIFIED),
            ls_type: LsaV3Type::Router,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: self_rid,
        };
        let bumped = inst.lsdb.get(&key).unwrap();
        assert_eq!(bumped.header.ls_sequence_number, stale_seq);
        assert!(inst.interfaces[&1].needs_router_lsa_refresh);
    }

    // ------------------------------------------------------------------
    // Interface refresh
    // ------------------------------------------------------------------

    #[test]
    fn test_refresh_detects_link_local_change() {
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let mut inst = inst_with_iface(self_rid, 1);
        // Start with link-local fe80::1 (from test_io)
        let new_ll: Ipv6Addr = "fe80::feed".parse().unwrap();
        let changed = inst.refresh_interface_state(1, Some(new_ll), Vec::new(), true);
        assert!(changed);
        assert_eq!(inst.interfaces[&1].io.link_local, new_ll);
        assert!(inst.interfaces[&1].needs_router_lsa_refresh);
    }

    #[test]
    fn test_refresh_down_clears_neighbors() {
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let peer = Ipv4Addr::new(2, 2, 2, 2);
        let mut inst = inst_with_iface(self_rid, 1);
        // Move the iface past Waiting so we can detect the down.
        inst.interfaces.get_mut(&1).unwrap().state = InterfaceStateV3::DR;
        add_neighbor(&mut inst, 1, peer, NeighborStateV3::Full);
        assert_eq!(inst.interfaces[&1].neighbors.len(), 1);

        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let changed = inst.refresh_interface_state(1, Some(ll), Vec::new(), false);
        assert!(changed);
        assert_eq!(inst.interfaces[&1].state, InterfaceStateV3::Down);
        assert!(inst.interfaces[&1].neighbors.is_empty());
    }

    #[test]
    fn test_refresh_up_transitions_to_waiting() {
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let mut inst = inst_with_iface(self_rid, 1);
        inst.interfaces.get_mut(&1).unwrap().state = InterfaceStateV3::Down;

        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let changed = inst.refresh_interface_state(1, Some(ll), Vec::new(), true);
        assert!(changed);
        assert_eq!(inst.interfaces[&1].state, InterfaceStateV3::Waiting);
    }

    // ------------------------------------------------------------------
    // Network-LSA and IntraAreaPrefix origination
    // ------------------------------------------------------------------

    #[test]
    fn test_network_lsa_originated_when_dr_with_full_neighbor() {
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let peer = Ipv4Addr::new(2, 2, 2, 2);
        let mut inst = inst_with_iface(self_rid, 1);
        inst.interfaces.get_mut(&1).unwrap().state = InterfaceStateV3::DR;
        add_neighbor(&mut inst, 1, peer, NeighborStateV3::Full);

        inst.originate_network_lsas();

        let key = crate::lsdb_v3::LsaKeyV3 {
            area: Some(Ipv4Addr::UNSPECIFIED),
            ls_type: LsaV3Type::Network,
            link_state_id: Ipv4Addr::from(1u32.to_be_bytes()),
            advertising_router: self_rid,
        };
        let entry = inst.lsdb.get(&key).expect("Network-LSA not originated");
        // Body = 4-byte options + 2 routers × 4 bytes = 12 bytes
        assert_eq!(entry.raw.len(), LSA_V3_HEADER_LEN + 12);
    }

    #[test]
    fn test_network_lsa_not_originated_without_full_neighbor() {
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let mut inst = inst_with_iface(self_rid, 1);
        inst.interfaces.get_mut(&1).unwrap().state = InterfaceStateV3::DR;
        // No neighbors.
        inst.originate_network_lsas();
        let key = crate::lsdb_v3::LsaKeyV3 {
            area: Some(Ipv4Addr::UNSPECIFIED),
            ls_type: LsaV3Type::Network,
            link_state_id: Ipv4Addr::from(1u32.to_be_bytes()),
            advertising_router: self_rid,
        };
        assert!(inst.lsdb.get(&key).is_none());
    }

    #[test]
    fn test_intra_area_prefix_lsa_originated_from_router() {
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let mut inst = InstanceV3::new(self_rid);
        // Interface with one global prefix and no peer — the prefix
        // lands in the "router" IAP (ls_id 0.0.0.0).
        let prefixes: Vec<(Ipv6Addr, u8)> = vec![("2001:db8:cafe::".parse().unwrap(), 64)];
        inst.add_interface(
            test_io("eth0", 1),
            Ipv4Addr::UNSPECIFIED,
            NetworkTypeV3::Broadcast,
            10,
            40,
            1,
            prefixes,
        );
        inst.originate_intra_area_prefix_lsas();

        let key = crate::lsdb_v3::LsaKeyV3 {
            area: Some(Ipv4Addr::UNSPECIFIED),
            ls_type: LsaV3Type::IntraAreaPrefix,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: self_rid,
        };
        assert!(inst.lsdb.get(&key).is_some());
    }

    // ------------------------------------------------------------------
    // Flood split-horizon
    // ------------------------------------------------------------------

    #[test]
    fn test_flood_lsa_split_horizon() {
        let self_rid = Ipv4Addr::new(1, 1, 1, 1);
        let peer_a = Ipv4Addr::new(2, 2, 2, 2);
        let peer_b = Ipv4Addr::new(3, 3, 3, 3);
        let mut inst = inst_with_iface(self_rid, 1);
        inst.add_interface(
            test_io("eth1", 2),
            Ipv4Addr::UNSPECIFIED,
            NetworkTypeV3::Broadcast,
            10,
            40,
            1,
            Vec::new(),
        );
        add_neighbor(&mut inst, 1, peer_a, NeighborStateV3::Full);
        add_neighbor(&mut inst, 2, peer_b, NeighborStateV3::Full);

        // Fabricate a dummy Router-LSA to flood.
        let header = LsaV3Header {
            ls_age: 0,
            ls_type: LsaV3Type::Router,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: Ipv4Addr::new(9, 9, 9, 9),
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: 24,
        };
        let mut raw = Vec::new();
        header.encode(&mut raw);
        raw.extend_from_slice(&[0, 0, 0, 0]);
        let entry = crate::lsdb_v3::LsaEntryV3 {
            header,
            raw,
            area: Some(Ipv4Addr::UNSPECIFIED),
        };

        // Flood from peer_a on iface 1 — should skip peer_a, push to peer_b.
        inst.flood_lsa(&entry, Some((1, peer_a)));

        let n_a = &inst.interfaces[&1].neighbors[&peer_a];
        let n_b = &inst.interfaces[&2].neighbors[&peer_b];
        assert!(
            n_a.pending_lsu.is_empty(),
            "source neighbor must not receive the flood"
        );
        assert_eq!(
            n_b.pending_lsu.len(),
            1,
            "non-source neighbor should receive the flood"
        );
    }
}
