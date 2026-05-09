#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the OSPFv3 Link State Update body (RFC 5340 §A.3.5). v3's LSA
// types differ from v2 — Router-LSA no longer carries prefixes (those
// moved to Intra-Area-Prefix-LSA Type 9), and the Link-LSA (Type 8) is
// new — so the v3 parser exercises a different decoder set than the v2
// LSU harness. Direct targeting gives libFuzzer maximum mutation
// budget on the LSA framing inside LSU rather than burning it on the
// fixed v3 header.
fuzz_target!(|data: &[u8]| {
    let _ = ospfd::packet_v3::lsu::LsUpdateV3Packet::parse(data);
});
