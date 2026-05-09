#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the OSPFv2 Link State Update packet body (RFC 2328 §A.3.5).
// LSU is the most complex v2 parser — carries multiple LSAs each with
// header + type-specific body (Router-LSA, Network-LSA, Summary-LSA,
// AS-External-LSA). Targeting LSU directly gives libFuzzer a deeper
// mutation budget on the LSA header `length` field and per-LSA-type
// link-list parsing where most OSPF parser bugs historically live.
//
// LSU is reached only after Full adjacency, so practical reach
// requires a peer that's negotiated through the OSPF FSM — but a
// compromised peer or any rogue speaker on a shared segment can flood
// arbitrary LSU bytes.
fuzz_target!(|data: &[u8]| {
    let _ = ospfd::packet::lsu::LsUpdatePacket::parse(data);
});
