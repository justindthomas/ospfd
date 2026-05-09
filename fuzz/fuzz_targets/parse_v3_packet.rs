#![no_main]

use libfuzzer_sys::fuzz_target;

use ospfd::packet_v3::{Ospfv3Header, Ospfv3PacketType, OSPFV3_HEADER_LEN};
use ospfd::packet_v3::{dd, hello, lsack, lsr, lsu};

// Fuzz the OSPFv3 wire-format dispatch (RFC 5340 §A.3). Unlike v2,
// the v3 packet module does not expose a single top-level enum-dispatch
// fn — the daemon's loop parses the header itself and switches on
// packet_type. We mirror that here so libFuzzer exercises every v3
// body parser through a single harness.
//
// Reachable on any link with a configured OSPFv3 interface: dst is the
// all-OSPF-routers multicast (ff02::5), proto is 89. v3 has no
// embedded auth — the spec offloads to IPsec AH/ESP at the IP layer —
// so the parser sees raw attacker bytes pre-authentication.
fuzz_target!(|data: &[u8]| {
    let header = match Ospfv3Header::parse(data) {
        Ok(h) => h,
        Err(_) => return,
    };
    if data.len() < OSPFV3_HEADER_LEN {
        return;
    }
    let body = &data[OSPFV3_HEADER_LEN..];
    match header.packet_type {
        Ospfv3PacketType::Hello => {
            let _ = hello::HelloV3Packet::parse(body);
        }
        Ospfv3PacketType::DatabaseDescription => {
            let _ = dd::DbDescV3Packet::parse(body);
        }
        Ospfv3PacketType::LinkStateRequest => {
            let _ = lsr::LsRequestV3Packet::parse(body);
        }
        Ospfv3PacketType::LinkStateUpdate => {
            let _ = lsu::LsUpdateV3Packet::parse(body);
        }
        Ospfv3PacketType::LinkStateAck => {
            let _ = lsack::LsAckV3Packet::parse(body);
        }
    }
});
