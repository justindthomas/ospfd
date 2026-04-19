//! ospfd — OSPFv2 + OSPFv3 routing daemon.
//!
//! Exposed as a library so examples and integration tests can use the
//! packet parsing, state machines, and protocol engine.

pub mod area;
pub mod config;
pub mod control;
pub mod daemon_v3;
pub mod instance;
pub mod instance_v3;
pub mod io;
pub mod io_punt;
pub mod io_punt_v3;
pub mod io_v3;
pub mod lsdb;
pub mod lsdb_v3;
pub mod packet;
pub mod packet_v3;
pub mod proto;
pub mod rib;
pub mod rib_client;
pub mod rib_v3;
pub mod spf_v3;
