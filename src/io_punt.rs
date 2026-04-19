//! OSPFv2 I/O backend via VPP active punt sockets (IP proto 89).
//!
//! Replaces the legacy `RawSocketIo` with a path that doesn't
//! require a Linux TAP. Packets flow `phy → ip4-input → ip4-local
//! → ip4-proto-punt-socket → unix datagram socket → PuntSocketIo
//! reader task`. Outbound packets go `PuntSocketIo::send → unix
//! datagram → VPP punt_socket_rx_node → { ip4-lookup | <iface>-output
//! }` depending on whether the destination is unicast or multicast.
//!
//! See `vpp-api/examples/punt_probe.rs` for the Phase 0 investigation
//! that nailed down the wire format and dispatch semantics. Key
//! findings, reproduced here for when the probe gets deleted:
//!
//! ## RX datagram framing
//!
//! ```text
//! [u32 sw_if_index][u32 action][ethernet header][ip header][payload]
//! ```
//!
//! Both integers are native-endian (little-endian on x86). `action`
//! is always 0 (PUNT_L2) on RX — the value carries no semantics in
//! this direction. The ethernet header is real for phy ingress; for
//! GRE-decapsulated ingress VPP synthesizes a fake header whose
//! "source MAC" encodes the tunnel's local IP. We skip the L2 header
//! and use `sw_if_index` + the IP-header source address as the
//! authoritative identifiers.
//!
//! ## TX datagram framing
//!
//! ```text
//! [u32 sw_if_index][u32 action][... payload depending on action]
//! ```
//!
//! - `action = 0 (PUNT_L2)`: payload is a full L2 frame (ethernet +
//!   IP + data). VPP enqueues directly at `<iface>-output`, bypassing
//!   the unicast FIB lookup. Required for multicast destinations
//!   because ip4-lookup has no multicast FIB entries.
//! - `action = 1 (PUNT_IP4_ROUTED)`: payload is an IP packet (no
//!   ethernet header). VPP enqueues at ip4-lookup, which walks the
//!   unicast FIB, uses the ARP cache to build the L2 header via
//!   ip4-rewrite, and transmits. Simpler but only works for unicast.
//!
//! ## Why two modes
//!
//! OSPF Hellos go to 224.0.0.5 (AllSPFRouters) — multicast. Our own
//! NBMA Hellos, DD packets, LS Requests, LS Updates and LS Acks
//! between fully-adjacent neighbors go to the peer's unicast address.
//! So we need both paths: PUNT_L2 for multicast, PUNT_IP4_ROUTED for
//! unicast. The `send` implementation below picks based on dst_addr.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::unix::net::UnixDatagram as StdUnixDatagram;
use std::sync::Arc;

use tokio::net::UnixDatagram;
use tokio::sync::mpsc;

use crate::io::{IoInterface, RxPacket, TxPacket};

/// VPP punt_packetdesc_t.action constants. See `punt.h`:
///   PUNT_L2 = 0         (interface-output, expects L2 frame)
///   PUNT_IP4_ROUTED = 1 (ip4-lookup, expects IP packet)
///   PUNT_IP6_ROUTED = 2 (ip6-lookup, expects IP packet)
const PUNT_ACTION_L2: u32 = 0;
const PUNT_ACTION_IP4_ROUTED: u32 = 1;

/// Size of VPP's punt_packetdesc_t prefix on each datagram.
const PUNT_DESC_LEN: usize = 8;

/// Size of the ethernet header VPP prepends to RX datagrams.
const ETHERNET_HEADER_LEN: usize = 14;

/// Punt-socket OSPFv2 I/O backend.
///
/// Owns one client-side Unix datagram socket bound at our pathname
/// (VPP writes to it), holds the VPP server path as a string (we
/// write to it for TX), and dispatches RX packets to the shared mpsc
/// channel that the daemon's select loop consumes.
pub struct PuntSocketIo {
    /// Map sw_if_index -> interface info (name, address, MAC, etc.).
    /// Populated from the `interfaces` vec passed to `new`.
    interfaces: HashMap<u32, IoInterface>,
    /// TX socket (unbound unix-datagram). VPP's listening socket is
    /// at `vpp_server_path` — we `send_to` that for each outbound
    /// packet.
    tx: StdUnixDatagram,
    /// Path to VPP's server socket. Returned to us in the
    /// `punt_socket_register_reply.pathname` field.
    vpp_server_path: String,
    /// Incoming packet channel — filled by the reader task.
    rx: mpsc::Receiver<RxPacket>,
    /// Reader task handle (kept alive for the life of the struct).
    _reader_task: tokio::task::JoinHandle<()>,
}

impl PuntSocketIo {
    /// Create a new punt-backed I/O handler.
    ///
    /// `client_socket_path` is where VPP will write packets for us to
    /// read. `vpp_server_path` is where we write packets for VPP to
    /// inject. Typically the caller (main.rs) sets up both by issuing
    /// a `punt_socket_register` via the binary API and reading the
    /// returned VPP server path from the reply.
    pub fn new(
        interfaces: Vec<IoInterface>,
        client_socket_path: &str,
        vpp_server_path: String,
    ) -> std::io::Result<Self> {
        // Remove any stale socket file — if a previous ospfd
        // crashed it may still be sitting there.
        let _ = std::fs::remove_file(client_socket_path);

        // Bind our client socket. VPP will sendmsg packets to us
        // via this path.
        let rx_sock = StdUnixDatagram::bind(client_socket_path)?;
        rx_sock.set_nonblocking(true)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            client_socket_path,
            std::fs::Permissions::from_mode(0o777),
        )?;

        // Hand the socket to tokio so the reader task can await on it.
        let async_rx = UnixDatagram::from_std(rx_sock)?;

        // Separate (unbound) TX socket. Keeping TX and RX on different
        // sockets avoids any surprise with partially-blocking writes
        // while we're also waiting for reads.
        let tx = StdUnixDatagram::unbound()?;

        let iface_map: HashMap<u32, IoInterface> =
            interfaces.into_iter().map(|i| (i.sw_if_index, i)).collect();

        let (chan_tx, chan_rx) = mpsc::channel::<RxPacket>(256);
        let iface_map_for_reader = Arc::new(iface_map.clone());
        let reader = tokio::spawn(reader_task(async_rx, chan_tx, iface_map_for_reader));

        tracing::info!(
            client = client_socket_path,
            vpp_server = vpp_server_path.as_str(),
            interfaces = iface_map.len(),
            "PuntSocketIo ready"
        );

        Ok(PuntSocketIo {
            interfaces: iface_map,
            tx,
            vpp_server_path,
            rx: chan_rx,
            _reader_task: reader,
        })
    }

    pub async fn recv(&mut self) -> Option<RxPacket> {
        self.rx.recv().await
    }

    pub fn send(&self, packet: &TxPacket) -> std::io::Result<()> {
        let iface = self.interfaces.get(&packet.sw_if_index).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("unknown sw_if_index {}", packet.sw_if_index),
            )
        })?;

        // Build the IP header. The raw-socket backend lets the kernel
        // do this; for punt we have to construct it ourselves because
        // VPP expects a full IP packet in the punt datagram, not just
        // OSPF payload.
        let ip_pkt = build_ip_packet(
            &packet.src_addr,
            &packet.dst_addr,
            &packet.data,
        );

        // Pick the injection mode based on destination class. See the
        // module-level doc for why.
        if is_multicast_v4(&packet.dst_addr) {
            // PUNT_L2: enqueue directly at <iface>-output. Need a full
            // L2 frame (ethernet header + IP packet).
            let dst_mac = multicast_mac_v4(&packet.dst_addr);
            let mut frame = Vec::with_capacity(14 + ip_pkt.len());
            frame.extend_from_slice(&dst_mac);
            frame.extend_from_slice(&iface.mac_address);
            frame.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
            frame.extend_from_slice(&ip_pkt);

            let mut dgram = Vec::with_capacity(PUNT_DESC_LEN + frame.len());
            dgram.extend_from_slice(&packet.sw_if_index.to_le_bytes());
            dgram.extend_from_slice(&PUNT_ACTION_L2.to_le_bytes());
            dgram.extend_from_slice(&frame);
            self.tx.send_to(&dgram, &self.vpp_server_path)?;
        } else {
            // PUNT_IP4_ROUTED: let VPP's ip4-lookup + ip4-rewrite
            // handle FIB lookup and L2 construction.
            let mut dgram = Vec::with_capacity(PUNT_DESC_LEN + ip_pkt.len());
            dgram.extend_from_slice(&packet.sw_if_index.to_le_bytes());
            dgram.extend_from_slice(&PUNT_ACTION_IP4_ROUTED.to_le_bytes());
            dgram.extend_from_slice(&ip_pkt);
            self.tx.send_to(&dgram, &self.vpp_server_path)?;
        }
        Ok(())
    }

    pub fn interface(&self, sw_if_index: u32) -> Option<&IoInterface> {
        self.interfaces.get(&sw_if_index)
    }
}

/// Returns true if `addr` is in 224.0.0.0/4 (IPv4 multicast).
fn is_multicast_v4(addr: &Ipv4Addr) -> bool {
    (addr.octets()[0] & 0xf0) == 0xe0
}

/// Map an IPv4 multicast destination to its canonical ethernet MAC
/// (RFC 1112 §6.4): `01:00:5e:<low-23-bits-of-group>`. The high 5
/// bits of the group's last 3 octets are discarded; high bit of the
/// second octet is forced to 0.
fn multicast_mac_v4(addr: &Ipv4Addr) -> [u8; 6] {
    let o = addr.octets();
    [0x01, 0x00, 0x5e, o[1] & 0x7f, o[2], o[3]]
}

/// Build a full IPv4 packet with a valid header checksum. The `data`
/// argument is the OSPF payload (already auth-applied by the caller).
/// TTL is hardcoded to 1 — OSPF Hellos, DDs, LSU and friends are
/// always link-local so TTL=1 is correct.
fn build_ip_packet(src: &Ipv4Addr, dst: &Ipv4Addr, data: &[u8]) -> Vec<u8> {
    let total_length: u16 = 20 + data.len() as u16;
    let mut hdr = Vec::with_capacity(total_length as usize);
    hdr.push(0x45); // version=4, ihl=5
    hdr.push(0xc0); // tos: IP Precedence "Internetwork Control" per RFC 2328 §A.1
    hdr.extend_from_slice(&total_length.to_be_bytes());
    hdr.extend_from_slice(&[0, 0]); // id (VPP will overwrite if it cares; we don't)
    hdr.extend_from_slice(&[0, 0]); // flags + fragment offset
    hdr.push(1); // ttl
    hdr.push(89); // proto OSPF
    hdr.extend_from_slice(&[0, 0]); // checksum placeholder
    hdr.extend_from_slice(&src.octets());
    hdr.extend_from_slice(&dst.octets());
    let ck = ip_header_checksum(&hdr);
    hdr[10..12].copy_from_slice(&ck.to_be_bytes());
    hdr.extend_from_slice(data);
    hdr
}

/// Compute the 16-bit IP header checksum over `header_bytes`.
/// One's-complement sum of 16-bit words, then one's-complement.
fn ip_header_checksum(header_bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header_bytes.len() {
        sum += ((header_bytes[i] as u32) << 8) | header_bytes[i + 1] as u32;
        i += 2;
    }
    if i < header_bytes.len() {
        sum += (header_bytes[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Reader task: loops on recv(), parses the punt framing, and forwards
/// RxPackets through the channel. Exits silently if the receiver end
/// is dropped.
async fn reader_task(
    sock: UnixDatagram,
    chan: mpsc::Sender<RxPacket>,
    interfaces: Arc<HashMap<u32, IoInterface>>,
) {
    let mut buf = vec![0u8; 65536];
    loop {
        let n = match sock.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("punt recv error: {}", e);
                continue;
            }
        };
        // Minimum datagram = 8 (desc) + 14 (eth) + 20 (ip) + 24 (ospf header)
        if n < PUNT_DESC_LEN + ETHERNET_HEADER_LEN + 20 + 24 {
            tracing::debug!(len = n, "punt datagram too short; skipping");
            continue;
        }

        let sw_if_index = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        // buf[4..8] is the "action" byte — we don't care on RX.

        // Skip punt descriptor + ethernet header.
        let l3_off = PUNT_DESC_LEN + ETHERNET_HEADER_LEN;
        // Parse minimal IPv4 fields to extract src/dst + ihl.
        let ver_ihl = buf[l3_off];
        let ihl = (ver_ihl & 0x0f) as usize * 4;
        if ihl < 20 {
            tracing::debug!("bad IPv4 header length");
            continue;
        }
        let proto = buf[l3_off + 9];
        if proto != 89 {
            // Shouldn't happen since we registered for proto 89 only,
            // but if VPP ever delivers something else drop it quietly.
            tracing::debug!(proto, "non-OSPF proto punted; skipping");
            continue;
        }
        let src_addr = Ipv4Addr::new(
            buf[l3_off + 12],
            buf[l3_off + 13],
            buf[l3_off + 14],
            buf[l3_off + 15],
        );
        let dst_addr = Ipv4Addr::new(
            buf[l3_off + 16],
            buf[l3_off + 17],
            buf[l3_off + 18],
            buf[l3_off + 19],
        );
        // Payload = everything after the IP header, up to the total_length
        // the IP header advertises (datagram may be padded).
        let total_len = u16::from_be_bytes([buf[l3_off + 2], buf[l3_off + 3]]) as usize;
        let payload_end = l3_off + total_len;
        if payload_end > n {
            tracing::debug!(
                total_len,
                recv = n,
                "IP total_length exceeds datagram; truncated"
            );
            continue;
        }
        let data = buf[l3_off + ihl..payload_end].to_vec();

        // Sanity check: we know this sw_if_index?
        if !interfaces.contains_key(&sw_if_index) {
            tracing::debug!(
                sw_if_index,
                "punt packet on unknown interface; dropping"
            );
            continue;
        }

        let pkt = RxPacket {
            sw_if_index,
            src_addr,
            dst_addr,
            data,
        };
        if chan.send(pkt).await.is_err() {
            // Receiver dropped — daemon is shutting down.
            break;
        }
    }
}
