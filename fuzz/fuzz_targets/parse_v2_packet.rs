#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the OSPFv2 top-level packet parser (RFC 2328 §A.3). Covers all
// five v2 message types in one harness: Hello, DBDescription,
// LinkStateRequest, LinkStateUpdate, LinkStateAck. The dispatcher in
// `OspfPacket::parse` invokes the right body decoder by type.
//
// Reachable by anything that can send an IP packet with proto 89 to
// the all-OSPF-routers multicast (224.0.0.5) on a configured OSPFv2
// interface — i.e. any device on a directly-attached link with the
// daemon listening. Pre-authentication: header parsing happens before
// MD5 verification.
fuzz_target!(|data: &[u8]| {
    let _ = ospfd::packet::OspfPacket::parse(data);
});
