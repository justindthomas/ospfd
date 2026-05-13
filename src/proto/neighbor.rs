//! OSPF Neighbor state machine (RFC 2328 Section 10).
//!
//! Each neighbor goes through states from Down to Full as adjacency
//! forms. The state machine is event-driven — events come from received
//! packets and timers.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::packet::dd::DbDescPacket;
use crate::packet::lsa::{LsaHeader, LsaKey};

/// Neighbor states (RFC 2328 Section 10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NeighborState {
    Down,
    Attempt,
    Init,
    TwoWay,
    ExStart,
    Exchange,
    Loading,
    Full,
}

impl NeighborState {
    /// Returns true if this state means we have at least 2-way communication.
    pub fn is_two_way_or_better(&self) -> bool {
        *self >= NeighborState::TwoWay
    }

    /// Returns true if this state means we're fully adjacent.
    pub fn is_full(&self) -> bool {
        *self == NeighborState::Full
    }
}

impl std::fmt::Display for NeighborState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Down => write!(f, "Down"),
            Self::Attempt => write!(f, "Attempt"),
            Self::Init => write!(f, "Init"),
            Self::TwoWay => write!(f, "2-Way"),
            Self::ExStart => write!(f, "ExStart"),
            Self::Exchange => write!(f, "Exchange"),
            Self::Loading => write!(f, "Loading"),
            Self::Full => write!(f, "Full"),
        }
    }
}

/// Events that drive the neighbor state machine (RFC 2328 Section 10.2).
#[derive(Debug, Clone)]
pub enum NeighborEvent {
    /// A Hello was received from this neighbor.
    HelloReceived,
    /// This router appeared in the neighbor's Hello (2-way).
    TwoWayReceived,
    /// Negotiation is done — DD exchange can begin.
    NegotiationDone,
    /// DD exchange is complete.
    ExchangeDone,
    /// A BadLSReq was received.
    BadLsReq,
    /// Loading is done — all requested LSAs received.
    LoadingDone,
    /// Adjacency should form (DR/BDR election result).
    AdjOk,
    /// Sequence number mismatch in DD exchange.
    SeqNumberMismatch,
    /// The inactivity timer expired.
    InactivityTimer,
    /// The 1-way state detected (our router not in neighbor's Hello).
    OneWay,
    /// A Link Down event occurred.
    LinkDown,
}

/// An OSPF neighbor.
#[derive(Debug)]
pub struct Neighbor {
    /// Neighbor's router ID.
    pub router_id: Ipv4Addr,
    /// Neighbor's IP address (source of Hello packets).
    pub address: Ipv4Addr,
    /// Current state.
    pub state: NeighborState,
    /// Neighbor's priority (from Hello).
    pub priority: u8,
    /// Neighbor's declared DR (from Hello).
    pub dr: Ipv4Addr,
    /// Neighbor's declared BDR (from Hello).
    pub bdr: Ipv4Addr,
    /// Neighbor's options (from Hello/DD).
    pub options: u8,

    // --- DD exchange state ---
    /// DD sequence number.
    pub dd_seq_number: u32,
    /// Are we the master in DD exchange?
    pub is_master: bool,
    /// Have we sent at least one DD to this neighbor with M=0? Master must
    /// finish describing its LSDB before it can accept ExchangeDone (RFC
    /// 2328 §10.8): "The master completes the Database Exchange process
    /// when it has sent and received DD Packets with the M-bit clear."
    pub sent_m_clear: bool,
    /// Last received DD packet (for duplicate detection).
    pub last_dd: Option<DbDescPacket>,

    // --- Request/retransmit lists ---
    /// LSAs we need to request from this neighbor.
    pub ls_request_list: Vec<LsaKey>,
    /// LSAs we need to retransmit to this neighbor.
    pub ls_retransmit_list: Vec<LsaHeader>,
    /// LSA headers from the neighbor's DB Description.
    pub db_summary_list: Vec<LsaHeader>,

    // --- Timers ---
    /// When the neighbor was last heard from (for inactivity detection).
    pub last_heard: Instant,
    /// When we last sent a DD packet to this neighbor (for retransmit pacing).
    pub last_dd_sent: Instant,
    /// When we last sent a Link State Request packet to this neighbor.
    /// RFC 2328 §10.9: LSRs are retransmitted every RxmtInterval while
    /// the neighbor is in Loading state (or in Exchange with a non-empty
    /// request list) until the list drains or the neighbor leaves Loading.
    /// Without this, if the peer's LSU response is dropped or incomplete,
    /// the adjacency wedges in Loading forever.
    pub last_lsr_sent: Instant,
}

impl Neighbor {
    pub fn new(router_id: Ipv4Addr, address: Ipv4Addr) -> Self {
        Neighbor {
            router_id,
            address,
            state: NeighborState::Down,
            priority: 0,
            dr: Ipv4Addr::UNSPECIFIED,
            bdr: Ipv4Addr::UNSPECIFIED,
            options: 0,
            dd_seq_number: 0,
            is_master: false,
            sent_m_clear: false,
            last_dd: None,
            ls_request_list: Vec::new(),
            ls_retransmit_list: Vec::new(),
            db_summary_list: Vec::new(),
            last_heard: Instant::now(),
            last_dd_sent: Instant::now() - Duration::from_secs(10),
            // Seed in the past so the first LSR can fire immediately
            // — once we add a request to ls_request_list and enter
            // Exchange/Loading, the next timer tick should emit it
            // without waiting a full RxmtInterval.
            last_lsr_sent: Instant::now() - Duration::from_secs(60),
        }
    }

    /// Apply a state machine event and return the new state.
    ///
    /// Returns `Some(new_state)` if a transition occurred, `None` if the
    /// event was ignored in the current state.
    ///
    /// The caller is responsible for:
    /// - Resetting the inactivity timer on HelloReceived
    /// - Running DR election when transitioning to/from 2-Way
    /// - Starting DD exchange on ExStart entry
    /// - Clearing lists on state regression
    pub fn handle_event(
        &mut self,
        event: &NeighborEvent,
        should_form_adjacency: bool,
    ) -> Option<NeighborState> {
        let old_state = self.state;
        let new_state = match (&self.state, event) {
            // Down -> Init on HelloReceived
            (NeighborState::Down, NeighborEvent::HelloReceived) => {
                self.last_heard = Instant::now();
                Some(NeighborState::Init)
            }

            // Attempt -> Init on HelloReceived
            (NeighborState::Attempt, NeighborEvent::HelloReceived) => {
                self.last_heard = Instant::now();
                Some(NeighborState::Init)
            }

            // Init -> TwoWay or ExStart on TwoWayReceived
            (NeighborState::Init, NeighborEvent::TwoWayReceived) => {
                if should_form_adjacency {
                    Some(NeighborState::ExStart)
                } else {
                    Some(NeighborState::TwoWay)
                }
            }

            // TwoWay -> ExStart on AdjOk (when adjacency should form)
            (NeighborState::TwoWay, NeighborEvent::AdjOk) => {
                if should_form_adjacency {
                    Some(NeighborState::ExStart)
                } else {
                    None // Stay in TwoWay
                }
            }

            // ExStart -> Exchange on NegotiationDone
            (NeighborState::ExStart, NeighborEvent::NegotiationDone) => {
                Some(NeighborState::Exchange)
            }

            // Exchange -> Loading or Full on ExchangeDone
            (NeighborState::Exchange, NeighborEvent::ExchangeDone) => {
                if self.ls_request_list.is_empty() {
                    Some(NeighborState::Full)
                } else {
                    Some(NeighborState::Loading)
                }
            }

            // Loading -> Full on LoadingDone
            (NeighborState::Loading, NeighborEvent::LoadingDone) => {
                Some(NeighborState::Full)
            }

            // Any >= ExStart -> ExStart on SeqNumberMismatch
            (s, NeighborEvent::SeqNumberMismatch) if *s >= NeighborState::ExStart => {
                self.clear_lists();
                Some(NeighborState::ExStart)
            }

            // Any >= ExStart -> ExStart on BadLsReq
            (s, NeighborEvent::BadLsReq) if *s >= NeighborState::ExStart => {
                self.clear_lists();
                Some(NeighborState::ExStart)
            }

            // Any >= TwoWay -> TwoWay on AdjOk when adjacency should NOT form
            (s, NeighborEvent::AdjOk) if *s >= NeighborState::ExStart => {
                if !should_form_adjacency {
                    self.clear_lists();
                    Some(NeighborState::TwoWay)
                } else {
                    None
                }
            }

            // TwoWay -> Init on OneWay
            (s, NeighborEvent::OneWay) if *s >= NeighborState::TwoWay => {
                self.clear_lists();
                Some(NeighborState::Init)
            }

            // Any -> Down on InactivityTimer or LinkDown
            (_, NeighborEvent::InactivityTimer) | (_, NeighborEvent::LinkDown) => {
                self.clear_lists();
                Some(NeighborState::Down)
            }

            // HelloReceived in any state >= Init just resets the timer
            (_, NeighborEvent::HelloReceived) => {
                self.last_heard = Instant::now();
                None
            }

            _ => None,
        };

        if let Some(new) = new_state {
            if new != old_state {
                tracing::info!(
                    neighbor = %self.router_id,
                    from = %old_state,
                    to = %new,
                    "neighbor state change"
                );
                self.state = new;
                return Some(new);
            }
        }

        None
    }

    /// Clear all exchange/request/retransmit lists.
    fn clear_lists(&mut self) {
        self.ls_request_list.clear();
        self.ls_retransmit_list.clear();
        self.db_summary_list.clear();
        self.last_dd = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_neighbor() -> Neighbor {
        Neighbor::new(Ipv4Addr::new(2, 2, 2, 2), Ipv4Addr::new(10, 0, 0, 2))
    }

    #[test]
    fn test_down_to_init_on_hello() {
        let mut n = make_neighbor();
        assert_eq!(n.state, NeighborState::Down);
        let result = n.handle_event(&NeighborEvent::HelloReceived, false);
        assert_eq!(result, Some(NeighborState::Init));
        assert_eq!(n.state, NeighborState::Init);
    }

    #[test]
    fn test_init_to_twoway_no_adjacency() {
        let mut n = make_neighbor();
        n.handle_event(&NeighborEvent::HelloReceived, false);
        let result = n.handle_event(&NeighborEvent::TwoWayReceived, false);
        assert_eq!(result, Some(NeighborState::TwoWay));
    }

    #[test]
    fn test_init_to_exstart_with_adjacency() {
        let mut n = make_neighbor();
        n.handle_event(&NeighborEvent::HelloReceived, false);
        let result = n.handle_event(&NeighborEvent::TwoWayReceived, true);
        assert_eq!(result, Some(NeighborState::ExStart));
    }

    #[test]
    fn test_full_adjacency_formation() {
        let mut n = make_neighbor();
        n.handle_event(&NeighborEvent::HelloReceived, false);
        n.handle_event(&NeighborEvent::TwoWayReceived, true);
        assert_eq!(n.state, NeighborState::ExStart);

        n.handle_event(&NeighborEvent::NegotiationDone, true);
        assert_eq!(n.state, NeighborState::Exchange);

        // No LSAs to request — go straight to Full
        n.handle_event(&NeighborEvent::ExchangeDone, true);
        assert_eq!(n.state, NeighborState::Full);
    }

    #[test]
    fn test_exchange_to_loading() {
        let mut n = make_neighbor();
        n.handle_event(&NeighborEvent::HelloReceived, false);
        n.handle_event(&NeighborEvent::TwoWayReceived, true);
        n.handle_event(&NeighborEvent::NegotiationDone, true);

        // Add something to the request list
        n.ls_request_list.push(crate::packet::lsa::LsaKey {
            ls_type: crate::packet::lsa::LsaType::Router,
            link_state_id: Ipv4Addr::new(3, 3, 3, 3),
            advertising_router: Ipv4Addr::new(3, 3, 3, 3),
        });

        n.handle_event(&NeighborEvent::ExchangeDone, true);
        assert_eq!(n.state, NeighborState::Loading);

        n.ls_request_list.clear();
        n.handle_event(&NeighborEvent::LoadingDone, true);
        assert_eq!(n.state, NeighborState::Full);
    }

    #[test]
    fn test_seq_mismatch_resets_to_exstart() {
        let mut n = make_neighbor();
        n.handle_event(&NeighborEvent::HelloReceived, false);
        n.handle_event(&NeighborEvent::TwoWayReceived, true);
        n.handle_event(&NeighborEvent::NegotiationDone, true);
        assert_eq!(n.state, NeighborState::Exchange);

        n.handle_event(&NeighborEvent::SeqNumberMismatch, true);
        assert_eq!(n.state, NeighborState::ExStart);
    }

    #[test]
    fn test_inactivity_timer_kills_neighbor() {
        let mut n = make_neighbor();
        n.handle_event(&NeighborEvent::HelloReceived, false);
        n.handle_event(&NeighborEvent::TwoWayReceived, true);
        assert_eq!(n.state, NeighborState::ExStart);

        n.handle_event(&NeighborEvent::InactivityTimer, false);
        assert_eq!(n.state, NeighborState::Down);
    }

    #[test]
    fn test_adj_ok_demotes_from_exstart() {
        let mut n = make_neighbor();
        n.handle_event(&NeighborEvent::HelloReceived, false);
        n.handle_event(&NeighborEvent::TwoWayReceived, true);
        assert_eq!(n.state, NeighborState::ExStart);

        // Adjacency no longer needed (DR changed)
        n.handle_event(&NeighborEvent::AdjOk, false);
        assert_eq!(n.state, NeighborState::TwoWay);
    }
}
