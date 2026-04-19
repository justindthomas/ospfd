//! Validate ospfd parser against a real FRR Hello packet captured on the wire.
//!
//! This is a UNH-style conformance test: take a real packet from a production
//! OSPF implementation and verify our parser handles it correctly.

use std::net::Ipv4Addr;

use ospfd::packet::{verify_ospf_checksum, OspfPacket};

fn main() {
    // Captured FRR Hello from 172.30.0.1 -> 224.0.0.5
    // IP header: 20 bytes starting at offset 0
    // OSPF header + body: starts at IP+20
    let ip_packet: [u8; 68] = [
        // IP header (20 bytes)
        0x45, 0xc0, 0x00, 0x44, 0x6a, 0xed, 0x00, 0x00,
        0x01, 0x59, 0xc1, 0x8f, 0xac, 0x1e, 0x00, 0x01,
        0xe0, 0x00, 0x00, 0x05,
        // OSPF header (24 bytes) + Hello body (24 bytes) = 48 bytes
        0x02, 0x01, 0x00, 0x30, 0xac, 0x1e, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x4c, 0x1a, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Hello body
        0xff, 0xff, 0xff, 0x00, // network mask 255.255.255.0
        0x00, 0x0a,             // hello interval 10
        0x02,                    // options (E bit)
        0x01,                    // priority
        0x00, 0x00, 0x00, 0x28, // dead interval 40
        0xac, 0x1e, 0x00, 0x01, // DR 172.30.0.1
        0xac, 0x1e, 0x00, 0x02, // BDR 172.30.0.2
        0xac, 0x1e, 0x00, 0x02, // neighbor 172.30.0.2
    ];

    // Skip the IP header (20 bytes)
    let ospf_data = &ip_packet[20..];

    println!("=== Parsing real FRR Hello packet ===\n");
    println!("OSPF packet length: {} bytes", ospf_data.len());

    // Verify the OSPF checksum first
    if verify_ospf_checksum(ospf_data) {
        println!("✓ OSPF checksum valid");
    } else {
        println!("✗ OSPF checksum INVALID — parser may have a bug");
    }

    // Parse the packet
    match OspfPacket::parse(ospf_data) {
        Ok(OspfPacket::Hello(header, hello)) => {
            println!("✓ Parsed as Hello packet");
            println!();
            println!("OSPF Header:");
            println!("  Version:        {}", header.version);
            println!("  Type:           Hello");
            println!("  Length:         {}", header.packet_length);
            println!("  Router ID:      {}", header.router_id);
            println!("  Area ID:        {}", header.area_id);
            println!("  Checksum:       0x{:04x}", header.checksum);
            println!("  Auth Type:      {}", header.au_type);
            println!();
            println!("Hello Body:");
            println!("  Network Mask:   {}", hello.network_mask);
            println!("  Hello Interval: {}", hello.hello_interval);
            println!("  Options:        0x{:02x} (E={})",
                     hello.options.0, hello.options.has_e_bit());
            println!("  Router Prio:    {}", hello.router_priority);
            println!("  Dead Interval:  {}", hello.router_dead_interval);
            println!("  DR:             {}", hello.designated_router);
            println!("  BDR:            {}", hello.backup_designated_router);
            println!("  Neighbors:      {} entries", hello.neighbors.len());
            for (i, n) in hello.neighbors.iter().enumerate() {
                println!("    [{}] {}", i, n);
            }

            // Validate expected values from the captured packet
            assert_eq!(header.version, 2);
            assert_eq!(header.packet_length, 48);
            assert_eq!(header.router_id, Ipv4Addr::new(172, 30, 0, 1));
            assert_eq!(header.area_id, Ipv4Addr::UNSPECIFIED);
            assert_eq!(hello.network_mask, Ipv4Addr::new(255, 255, 255, 0));
            assert_eq!(hello.hello_interval, 10);
            assert_eq!(hello.router_dead_interval, 40);
            assert_eq!(hello.router_priority, 1);
            assert_eq!(hello.designated_router, Ipv4Addr::new(172, 30, 0, 1));
            assert_eq!(hello.backup_designated_router, Ipv4Addr::new(172, 30, 0, 2));
            assert_eq!(hello.neighbors.len(), 1);
            assert_eq!(hello.neighbors[0], Ipv4Addr::new(172, 30, 0, 2));

            println!();
            println!("✓ All field assertions passed");

            // Now re-encode and verify we produce identical bytes
            let reencoded = OspfPacket::Hello(header.clone(), hello.clone()).encode();
            if reencoded == ospf_data {
                println!("✓ Re-encoded packet matches original byte-for-byte");
            } else {
                println!("✗ Re-encoded packet differs:");
                println!("  Original: {:?}", ospf_data);
                println!("  Encoded:  {:?}", reencoded);
                if reencoded.len() == ospf_data.len() {
                    for i in 0..reencoded.len() {
                        if reencoded[i] != ospf_data[i] {
                            println!("  Diff at byte {}: orig=0x{:02x}, encoded=0x{:02x}",
                                     i, ospf_data[i], reencoded[i]);
                        }
                    }
                }
            }
        }
        Ok(other) => {
            println!("✗ Expected Hello, got {:?}", other.header().packet_type);
        }
        Err(e) => {
            println!("✗ Parse error: {}", e);
        }
    }
}
