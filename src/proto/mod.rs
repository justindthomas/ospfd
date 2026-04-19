//! OSPF protocol engine.
//!
//! Implements the state machines and algorithms from RFC 2328:
//! - Neighbor state machine (Section 10)
//! - Interface state machine (Section 9)
//! - DR/BDR election (Section 9.4)
//! - SPF calculation (Section 16)
//! - Flooding procedure (Section 13)

pub mod neighbor;
pub mod interface;
pub mod spf;
