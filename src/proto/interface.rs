//! OSPF Interface state machine (RFC 2328 Section 9).
//!
//! Each OSPF-enabled interface has a state machine that handles:
//! - DR/BDR election (broadcast networks)
//! - Hello protocol timing
//! - Neighbor management

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::packet::hello::OspfOptions;
use crate::proto::neighbor::Neighbor;

/// Interface states (RFC 2328 Section 9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceState {
    Down,
    Loopback,
    Waiting,
    PointToPoint,
    DROther,
    Backup,
    DR,
}

impl std::fmt::Display for InterfaceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Down => write!(f, "Down"),
            Self::Loopback => write!(f, "Loopback"),
            Self::Waiting => write!(f, "Waiting"),
            Self::PointToPoint => write!(f, "Point-to-Point"),
            Self::DROther => write!(f, "DROther"),
            Self::Backup => write!(f, "Backup"),
            Self::DR => write!(f, "DR"),
        }
    }
}

/// Network types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    Broadcast,
    PointToPoint,
    /// Non-Broadcast Multi-Access (RFC 2328 §A.4.5). Uses unicast
    /// Hellos to a statically-configured neighbor list, runs DR
    /// election against those neighbors. Use on media that don't
    /// support IP multicast (ATM, Frame Relay, layer-2 switches
    /// that drop OSPF multicast).
    NonBroadcast,
    /// Point-to-Multipoint (RFC 2328 §A.4.5). Treats the interface
    /// as a collection of P2P links — no DR/BDR election, every
    /// neighbor forms a full adjacency, and each adjacency is
    /// advertised in the Router-LSA as a /32 host route. Useful
    /// for hub-and-spoke topologies and partial-mesh segments.
    /// Hellos are multicast (broadcast variant); the
    /// `point-to-multipoint non-broadcast` Cisco extension
    /// (unicast Hellos) is not implemented — operators who need
    /// that should use NBMA instead.
    PointToMultipoint,
}

/// A statically-configured NBMA neighbor. Populated from
/// `ospf.neighbors` in the config file at interface creation time.
#[derive(Debug, Clone)]
pub struct StaticNeighbor {
    /// IP address — used as unicast Hello destination and as the
    /// initial neighbor address before we hear the peer's router-id.
    pub address: Ipv4Addr,
    /// Priority used for DR election while we haven't yet received
    /// a Hello from this neighbor. Once the neighbor responds, its
    /// live Hello priority takes over.
    pub priority: u8,
}

/// Events that drive the interface state machine.
#[derive(Debug, Clone)]
pub enum InterfaceEvent {
    InterfaceUp,
    WaitTimer,
    BackupSeen,
    NeighborChange,
    LoopInd,
    UnloopInd,
    InterfaceDown,
}

/// An OSPF interface.
#[derive(Debug)]
pub struct OspfInterface {
    /// Interface name (e.g., "wan", "lan").
    pub name: String,
    /// VPP sw_if_index.
    pub sw_if_index: u32,
    /// Interface IP address.
    pub address: Ipv4Addr,
    /// Network mask.
    pub mask: Ipv4Addr,
    /// Current state.
    pub state: InterfaceState,
    /// Network type.
    pub network_type: NetworkType,
    /// OSPF area ID.
    pub area_id: Ipv4Addr,
    /// Hello interval in seconds.
    pub hello_interval: u16,
    /// Dead interval in seconds.
    pub dead_interval: u32,
    /// Retransmit interval in seconds.
    pub rxmt_interval: u16,
    /// Interface cost.
    pub cost: u16,
    /// Router priority for DR election.
    pub priority: u8,
    /// Whether this is a passive interface.
    pub passive: bool,
    /// Statically-configured neighbors. Only used for
    /// `NetworkType::NonBroadcast` — pre-populated from
    /// `ospf.neighbors` in the config file at interface creation.
    /// Hellos are unicast to each entry's address.
    pub static_neighbors: Vec<StaticNeighbor>,
    /// Elected Designated Router (IP address).
    pub dr: Ipv4Addr,
    /// Elected Backup Designated Router (IP address).
    pub bdr: Ipv4Addr,
    /// Options we advertise.
    pub options: OspfOptions,
    /// Neighbors on this interface, keyed by router ID.
    pub neighbors: HashMap<Ipv4Addr, Neighbor>,
    /// When the next Hello should be sent.
    pub next_hello: Instant,
    /// When the Wait timer expires (for DR election).
    pub wait_timer_expiry: Option<Instant>,
    /// Authentication key for packets on this interface.
    pub auth_key: crate::packet::auth::AuthKey,
    /// Outbound crypto sequence number (monotonic, for MD5 auth replay prevention).
    pub crypto_seq: u32,
    /// Our router ID — duplicated from the instance so the interface
    /// FSM (and DR election in particular) has the authoritative
    /// identifier without needing a back-reference to the instance.
    pub router_id: Ipv4Addr,
    /// Interface MTU to advertise in the Database Description packet's
    /// Interface-MTU field (RFC 2328 §10.6). OSPF refuses adjacency on
    /// a mismatch, so this must equal the peer's.
    ///
    /// Plain Ethernet uses 1500 (the working default that matches FRR
    /// et al; VPP's reported L3 MTU is the jumbo-capable 9000 internal
    /// value, not the on-the-wire MTU). A GRE/IPIP tunnel carries its
    /// real IP MTU here, read from VPP at resolution — ecrd sets the
    /// tunnel's VPP MTU to underlay-minus-overhead (1476 for GRE over a
    /// 1500 underlay), which both ends then advertise so the check
    /// passes without `mtu-ignore`.
    pub dd_mtu: u16,
}

impl OspfInterface {
    pub fn new(
        name: String,
        sw_if_index: u32,
        address: Ipv4Addr,
        mask: Ipv4Addr,
        area_id: Ipv4Addr,
        network_type: NetworkType,
        router_id: Ipv4Addr,
    ) -> Self {
        OspfInterface {
            name,
            sw_if_index,
            address,
            mask,
            state: InterfaceState::Down,
            network_type,
            area_id,
            hello_interval: 10,
            dead_interval: 40,
            rxmt_interval: 5,
            cost: 10,
            priority: 1,
            passive: false,
            static_neighbors: Vec::new(),
            router_id,
            dr: Ipv4Addr::UNSPECIFIED,
            bdr: Ipv4Addr::UNSPECIFIED,
            options: OspfOptions::standard(),
            neighbors: HashMap::new(),
            next_hello: Instant::now(),
            wait_timer_expiry: None,
            auth_key: crate::packet::auth::AuthKey::None,
            crypto_seq: 0,
            dd_mtu: 1500,
        }
    }

    /// Apply a state machine event and return the new state if changed.
    pub fn handle_event(&mut self, event: &InterfaceEvent) -> Option<InterfaceState> {
        let old_state = self.state;

        let new_state = match (&self.state, event) {
            (InterfaceState::Down, InterfaceEvent::InterfaceUp) => {
                match self.network_type {
                    // P2P and P2MP both skip DR election entirely
                    // and jump straight into the operational state.
                    // P2MP reuses the PointToPoint state — the
                    // distinction lives in network_type, not state.
                    NetworkType::PointToPoint | NetworkType::PointToMultipoint => {
                        Some(InterfaceState::PointToPoint)
                    }
                    // NBMA uses the same DR-election FSM as Broadcast
                    // — only the Hello transport differs (unicast to
                    // static_neighbors instead of 224.0.0.5).
                    NetworkType::Broadcast | NetworkType::NonBroadcast => {
                        if self.priority == 0 {
                            // Can't be DR/BDR — skip election, go to DROther
                            Some(InterfaceState::DROther)
                        } else {
                            // Start the Wait timer for DR election
                            self.wait_timer_expiry =
                                Some(Instant::now() + Duration::from_secs(self.dead_interval as u64));
                            Some(InterfaceState::Waiting)
                        }
                    }
                }
            }

            (InterfaceState::Waiting, InterfaceEvent::WaitTimer) => {
                // Wait timer expired — run DR election
                self.wait_timer_expiry = None;
                Some(self.run_dr_election())
            }

            (InterfaceState::Waiting, InterfaceEvent::BackupSeen) => {
                // A neighbor declared itself BDR — run election immediately
                self.wait_timer_expiry = None;
                Some(self.run_dr_election())
            }

            // DR/BDR/DROther -> re-run election on NeighborChange
            (
                InterfaceState::DROther | InterfaceState::Backup | InterfaceState::DR,
                InterfaceEvent::NeighborChange,
            ) => Some(self.run_dr_election()),

            (InterfaceState::Down, InterfaceEvent::LoopInd) => Some(InterfaceState::Loopback),
            (InterfaceState::Loopback, InterfaceEvent::UnloopInd) => Some(InterfaceState::Down),

            // InterfaceDown from any state
            (_, InterfaceEvent::InterfaceDown) => {
                self.neighbors.clear();
                self.dr = Ipv4Addr::UNSPECIFIED;
                self.bdr = Ipv4Addr::UNSPECIFIED;
                self.wait_timer_expiry = None;
                Some(InterfaceState::Down)
            }

            _ => None,
        };

        if let Some(new) = new_state {
            if new != old_state {
                tracing::info!(
                    interface = %self.name,
                    from = %old_state,
                    to = %new,
                    "interface state change"
                );
                self.state = new;

                // RFC 2328 Section 10.3: after an interface state change that
                // affects DR/BDR (i.e. any of Waiting/DROther/Backup/DR), we
                // must re-evaluate every neighbor's adjacency eligibility by
                // firing the AdjOk? event. For broadcast networks, a neighbor
                // forms an adjacency if either end is DR or BDR.
                match new {
                    InterfaceState::DR
                    | InterfaceState::Backup
                    | InterfaceState::DROther => {
                        self.reevaluate_adjacencies();
                    }
                    _ => {}
                }

                return Some(new);
            }
        }
        None
    }

    /// Re-fire `AdjOk?` on every neighbor in 2-Way or higher state.
    ///
    /// Called after our interface state changes (e.g., after DR election).
    /// This is what transitions 2-Way neighbors to ExStart when we or they
    /// become DR/BDR.
    fn reevaluate_adjacencies(&mut self) {
        use crate::proto::neighbor::NeighborEvent;

        let self_state = self.state;
        let self_addr = self.address;
        let network_type = self.network_type;

        let neighbor_ids: Vec<Ipv4Addr> = self
            .neighbors
            .iter()
            .filter(|(_, n)| n.state >= crate::proto::neighbor::NeighborState::TwoWay)
            .map(|(id, _)| *id)
            .collect();

        for id in neighbor_ids {
            let Some(neighbor) = self.neighbors.get_mut(&id) else {
                continue;
            };
            // Determine if an adjacency should form with this neighbor now.
            let should_adj = match network_type {
                NetworkType::PointToPoint | NetworkType::PointToMultipoint => true,
                NetworkType::Broadcast | NetworkType::NonBroadcast => {
                    matches!(self_state, InterfaceState::DR | InterfaceState::Backup)
                        || neighbor.dr == neighbor.address
                        || neighbor.bdr == neighbor.address
                        || neighbor.dr == self_addr
                        || neighbor.bdr == self_addr
                }
            };
            neighbor.handle_event(&NeighborEvent::AdjOk, should_adj);
        }
    }

    /// DR/BDR election algorithm (RFC 2328 Section 9.4).
    ///
    /// Three passes:
    ///   2. BDR among non-DR-declarers, prefer self-BDR-declarers
    ///   3. DR among DR-declarers, fallback to BDR if nobody claims
    ///      DR. Re-elect BDR if the BDR candidate just got promoted.
    ///   4. Rerun-on-self-change: if our own role changed (in or
    ///      out of DR/BDR), re-run once with our updated declarations
    ///      folded in. This is the incumbent-preference step that
    ///      prevents transient flap when our state flips.
    ///
    /// Returns the new interface state (DR, Backup, or DROther).
    fn run_dr_election(&mut self) -> InterfaceState {
        let my_router_id = self.router_id;

        struct Candidate {
            router_id: Ipv4Addr,
            ip_address: Ipv4Addr,
            priority: u8,
            declared_dr: Ipv4Addr,
            declared_bdr: Ipv4Addr,
        }

        // Up to two iterations. Self-declarations get refreshed
        // between iterations to fold in the result of the first
        // pass — this is the rerun step.
        let mut self_dr = self.dr;
        let mut self_bdr = self.bdr;
        let mut new_dr;
        let mut new_bdr;
        let mut iteration = 0;
        loop {
            iteration += 1;
            let mut candidates: Vec<Candidate> = self
                .neighbors
                .values()
                .filter(|n| n.state.is_two_way_or_better())
                .map(|n| Candidate {
                    router_id: n.router_id,
                    ip_address: n.address,
                    priority: n.priority,
                    declared_dr: n.dr,
                    declared_bdr: n.bdr,
                })
                .collect();
            candidates.push(Candidate {
                router_id: my_router_id,
                ip_address: self.address,
                priority: self.priority,
                declared_dr: self_dr,
                declared_bdr: self_bdr,
            });

            // Step 2: BDR — among priority>0 candidates not declaring
            // themselves DR, prefer those declaring themselves BDR,
            // then highest priority, then highest router-id.
            let bdr = candidates
                .iter()
                .filter(|c| c.priority > 0)
                .filter(|c| c.declared_dr != c.ip_address)
                .max_by(|a, b| {
                    let a_claims_bdr = a.declared_bdr == a.ip_address;
                    let b_claims_bdr = b.declared_bdr == b.ip_address;
                    a_claims_bdr
                        .cmp(&b_claims_bdr)
                        .then(a.priority.cmp(&b.priority))
                        .then(a.router_id.cmp(&b.router_id))
                })
                .map(|c| c.ip_address);

            // Step 3: DR — among candidates declaring themselves DR,
            // pick highest priority then highest router-id. If
            // nobody declares DR, the BDR becomes DR.
            let dr_declarer = candidates
                .iter()
                .filter(|c| c.priority > 0)
                .filter(|c| c.declared_dr == c.ip_address)
                .max_by(|a, b| {
                    a.priority
                        .cmp(&b.priority)
                        .then(a.router_id.cmp(&b.router_id))
                })
                .map(|c| c.ip_address);

            new_dr = dr_declarer.or(bdr).unwrap_or(Ipv4Addr::UNSPECIFIED);
            new_bdr = if Some(new_dr) == bdr {
                candidates
                    .iter()
                    .filter(|c| c.priority > 0 && c.ip_address != new_dr)
                    .max_by(|a, b| {
                        a.priority
                            .cmp(&b.priority)
                            .then(a.router_id.cmp(&b.router_id))
                    })
                    .map(|c| c.ip_address)
                    .unwrap_or(Ipv4Addr::UNSPECIFIED)
            } else {
                bdr.unwrap_or(Ipv4Addr::UNSPECIFIED)
            };

            // Step 4 (rerun): only meaningful if we had a prior
            // role. See the v3 dr_election in instance_v3.rs for
            // the full reasoning — fresh-boot segments (no
            // incumbent) skip the rerun to avoid oscillating.
            let had_prior_role = self_dr == self.address || self_bdr == self.address;
            let was_dr = self_dr == self.address;
            let was_bdr = self_bdr == self.address;
            let is_dr = new_dr == self.address;
            let is_bdr = new_bdr == self.address;
            if iteration < 2
                && had_prior_role
                && (was_dr != is_dr || was_bdr != is_bdr)
            {
                self_dr = new_dr;
                self_bdr = new_bdr;
                continue;
            }
            break;
        }

        self.dr = new_dr;
        self.bdr = new_bdr;

        tracing::debug!(
            interface = %self.name,
            dr = %self.dr,
            bdr = %self.bdr,
            "DR election complete"
        );

        if self.dr == self.address {
            InterfaceState::DR
        } else if self.bdr == self.address {
            InterfaceState::Backup
        } else {
            InterfaceState::DROther
        }
    }

    /// Should a full adjacency be formed with this neighbor?
    ///
    /// On point-to-point: always yes.
    /// On broadcast: only if we or the neighbor are DR/BDR.
    pub fn should_form_adjacency(&self, neighbor: &Neighbor) -> bool {
        match self.network_type {
            NetworkType::PointToPoint | NetworkType::PointToMultipoint => true,
            NetworkType::Broadcast | NetworkType::NonBroadcast => {
                // Form adjacency if either end is DR or BDR
                self.state == InterfaceState::DR
                    || self.state == InterfaceState::Backup
                    || neighbor.dr == neighbor.address
                    || neighbor.bdr == neighbor.address
            }
        }
    }

    /// Get the destination address for Hello packets on this interface.
    pub fn hello_destination(&self) -> Ipv4Addr {
        crate::packet::ALL_SPF_ROUTERS
    }

    /// Duration until next Hello should be sent.
    pub fn hello_duration(&self) -> Duration {
        Duration::from_secs(self.hello_interval as u64)
    }

    /// Duration for the dead interval timer.
    pub fn dead_duration(&self) -> Duration {
        Duration::from_secs(self.dead_interval as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_interface() -> OspfInterface {
        OspfInterface::new(
            "wan".to_string(),
            1,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::UNSPECIFIED, // area 0
            NetworkType::Broadcast,
            Ipv4Addr::new(10, 0, 0, 1), // router_id = iface address
        )
    }

    #[test]
    fn test_down_to_waiting_on_broadcast() {
        let mut iface = make_interface();
        assert_eq!(iface.state, InterfaceState::Down);

        iface.handle_event(&InterfaceEvent::InterfaceUp);
        assert_eq!(iface.state, InterfaceState::Waiting);
        assert!(iface.wait_timer_expiry.is_some());
    }

    #[test]
    fn test_down_to_p2p() {
        let mut iface = make_interface();
        iface.network_type = NetworkType::PointToPoint;

        iface.handle_event(&InterfaceEvent::InterfaceUp);
        assert_eq!(iface.state, InterfaceState::PointToPoint);
    }

    #[test]
    fn test_p2mp_skips_dr_election_and_jumps_to_p2p_state() {
        // Point-to-Multipoint reuses the PointToPoint interface
        // state — the distinction lives in network_type. ISM
        // shouldn't run a Wait timer or DR election for P2MP.
        let mut iface = make_interface();
        iface.network_type = NetworkType::PointToMultipoint;

        iface.handle_event(&InterfaceEvent::InterfaceUp);
        assert_eq!(iface.state, InterfaceState::PointToPoint);
        assert!(
            iface.wait_timer_expiry.is_none(),
            "P2MP must not start the Wait timer"
        );
    }

    #[test]
    fn test_p2mp_always_forms_adjacency() {
        // P2MP should_form_adjacency() returns true for every
        // 2-Way neighbor, just like PointToPoint.
        let mut iface = make_interface();
        iface.network_type = NetworkType::PointToMultipoint;
        let n = Neighbor::new(Ipv4Addr::new(2, 2, 2, 2), Ipv4Addr::new(10, 0, 0, 2));
        assert!(iface.should_form_adjacency(&n));
    }

    #[test]
    fn test_waiting_to_dr_on_timer() {
        let mut iface = make_interface();
        iface.priority = 1;
        iface.handle_event(&InterfaceEvent::InterfaceUp);
        assert_eq!(iface.state, InterfaceState::Waiting);

        // Wait timer fires — we're the only router, should become DR
        iface.handle_event(&InterfaceEvent::WaitTimer);
        assert_eq!(iface.state, InterfaceState::DR);
        assert_eq!(iface.dr, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_zero_priority_becomes_drother() {
        let mut iface = make_interface();
        iface.priority = 0;
        iface.handle_event(&InterfaceEvent::InterfaceUp);
        assert_eq!(iface.state, InterfaceState::DROther);
    }

    #[test]
    fn test_interface_down_clears_state() {
        let mut iface = make_interface();
        iface.handle_event(&InterfaceEvent::InterfaceUp);
        iface.handle_event(&InterfaceEvent::WaitTimer);

        // Add a neighbor
        iface.neighbors.insert(
            Ipv4Addr::new(2, 2, 2, 2),
            Neighbor::new(Ipv4Addr::new(2, 2, 2, 2), Ipv4Addr::new(10, 0, 0, 2)),
        );

        iface.handle_event(&InterfaceEvent::InterfaceDown);
        assert_eq!(iface.state, InterfaceState::Down);
        assert!(iface.neighbors.is_empty());
        assert_eq!(iface.dr, Ipv4Addr::UNSPECIFIED);
    }
}
