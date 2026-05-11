//! OSPFv3 I/O backend via VPP active punt sockets (IPv6 proto 89).
//!
//! Parallels `io_punt.rs` for the v3 side. Same architecture, same
//! wire format, same injection-mode split (PUNT_L2 for multicast
//! ff02::5 / ff02::6, PUNT_IP6_ROUTED for unicast).
//!
//! Key v6 differences:
//!
//!   - Register against VPP with `af = 1` (AF_IP6) instead of 0.
//!   - IPv6 header is 40 bytes fixed, no checksum field. Simpler to
//!     build than the v4 header.
//!   - Multicast MAC = `33:33:<low-32-bits-of-group>` per RFC 2464 §7.
//!     ff02::5 -> 33:33:00:00:00:05
//!     ff02::6 -> 33:33:00:00:00:06
//!   - Source address must be the interface's link-local (VPP won't
//!     let us spoof off-link sources for local TX).
//!   - OSPFv3's own checksum is computed over the v3 pseudo-header
//!     plus the OSPFv3 packet, which means the caller (daemon_v3)
//!     already filled it in before handing us the packet — we don't
//!     touch it here.

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::os::unix::net::UnixDatagram as StdUnixDatagram;
use std::sync::Arc;

use tokio::net::UnixDatagram;
use tokio::sync::mpsc;

use crate::io_v3::{IoInterfaceV3, RxPacketV3, TxPacketV3};

const PUNT_ACTION_L2: u32 = 0;
const PUNT_ACTION_IP6_ROUTED: u32 = 2;

const PUNT_DESC_LEN: usize = 8;
const ETHERNET_HEADER_LEN: usize = 14;
const IPV6_HEADER_LEN: usize = 40;

pub struct PuntSocketIoV3 {
    interfaces: HashMap<u32, IoInterfaceV3>,
    tx: StdUnixDatagram,
    vpp_server_path: String,
    rx: mpsc::Receiver<RxPacketV3>,
    _reader_task: tokio::task::JoinHandle<()>,
}

impl PuntSocketIoV3 {
    pub fn new(
        interfaces: Vec<IoInterfaceV3>,
        client_socket_path: &str,
        vpp_server_path: String,
    ) -> std::io::Result<Self> {
        let _ = std::fs::remove_file(client_socket_path);
        let rx_sock = StdUnixDatagram::bind(client_socket_path)?;
        rx_sock.set_nonblocking(true)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            client_socket_path,
            std::fs::Permissions::from_mode(0o777),
        )?;
        let async_rx = UnixDatagram::from_std(rx_sock)?;

        let tx = StdUnixDatagram::unbound()?;

        let iface_map: HashMap<u32, IoInterfaceV3> =
            interfaces.into_iter().map(|i| (i.sw_if_index, i)).collect();

        let (chan_tx, chan_rx) = mpsc::channel::<RxPacketV3>(256);
        let iface_map_for_reader = Arc::new(iface_map.clone());
        let reader = tokio::spawn(reader_task(async_rx, chan_tx, iface_map_for_reader));

        tracing::info!(
            client = client_socket_path,
            vpp_server = vpp_server_path.as_str(),
            interfaces = iface_map.len(),
            "PuntSocketIoV3 ready"
        );

        Ok(PuntSocketIoV3 {
            interfaces: iface_map,
            tx,
            vpp_server_path,
            rx: chan_rx,
            _reader_task: reader,
        })
    }

    pub async fn recv(&mut self) -> Option<RxPacketV3> {
        self.rx.recv().await
    }

    pub fn send(&self, packet: &TxPacketV3) -> std::io::Result<()> {
        let iface = self.interfaces.get(&packet.sw_if_index).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("unknown sw_if_index {}", packet.sw_if_index),
            )
        })?;

        // Compute the OSPFv3 checksum over the IPv6 pseudo-header +
        // the OSPFv3 packet (with the checksum field zeroed during
        // computation). The daemon's encode_* path emits a fresh
        // header with checksum=0 and never patches it — putting
        // the compute here means TX paths share one implementation
        // and the daemon stays unaware of src/dst plumbing.
        //
        // RFC 5340 §2.4 says invalid checksums MUST be dropped. An
        // OS10 trunk between imp and a VyOS/FRR peer was eating
        // every multicast frame with checksum=0 — the L2 hop never
        // reached the receiver. With this fix the frame matches
        // FRR's expectation and the adjacency forms.
        let data = ospfv3_compute_checksum_in_place(
            &packet.src_addr,
            &packet.dst_addr,
            &packet.data,
        );

        let ip_pkt = build_ipv6_packet(&packet.src_addr, &packet.dst_addr, &data);

        if is_multicast_v6(&packet.dst_addr) {
            // PUNT_L2: build a full ethernet frame with the multicast
            // MAC derived from the group address per RFC 2464 §7.
            //
            // VLAN-tagged sub-interfaces need the 802.1Q (and inner
            // 802.1Q for QinQ) tag pushed BY US — VPP does not
            // rewrite a PUNT_L2 frame on egress (it trusts the
            // caller). The PUNT_IP6_ROUTED path does get vlan-push
            // via ip6-rewrite, which is why unicast (and v2 NBMA)
            // worked but multicast on a sub-iface did not: hellos
            // egressed untagged and trunk peers dropped them onto
            // the native vlan.
            let dst_mac = multicast_mac_v6(&packet.dst_addr);
            let tag_bytes = match (iface.outer_vlan_id, iface.inner_vlan_id) {
                (Some(_), Some(_)) => 8,
                (Some(_), None) => 4,
                _ => 0,
            };
            let mut frame = Vec::with_capacity(14 + tag_bytes + ip_pkt.len());
            frame.extend_from_slice(&dst_mac);
            frame.extend_from_slice(&iface.mac_address);
            if let Some(outer) = iface.outer_vlan_id {
                // Outer 802.1Q: TPID 0x8100, TCI = PCP=0, DEI=0, VID
                // = outer (12 bits, masked).
                frame.extend_from_slice(&[0x81, 0x00]);
                frame.extend_from_slice(&(outer & 0x0fff).to_be_bytes());
                if let Some(inner) = iface.inner_vlan_id {
                    // Inner 802.1Q (same TPID for an OS-side
                    // "dot1q outer X inner Y" sub-iface; switch to
                    // 0x88a8 if/when we surface dot1ad sub-ifs).
                    frame.extend_from_slice(&[0x81, 0x00]);
                    frame.extend_from_slice(&(inner & 0x0fff).to_be_bytes());
                }
            }
            frame.extend_from_slice(&[0x86, 0xdd]); // ethertype IPv6
            frame.extend_from_slice(&ip_pkt);

            let mut dgram = Vec::with_capacity(PUNT_DESC_LEN + frame.len());
            dgram.extend_from_slice(&packet.sw_if_index.to_le_bytes());
            dgram.extend_from_slice(&PUNT_ACTION_L2.to_le_bytes());
            dgram.extend_from_slice(&frame);
            self.tx.send_to(&dgram, &self.vpp_server_path)?;
        } else {
            // PUNT_IP6_ROUTED: VPP walks ip6-lookup + ip6-rewrite for us.
            let mut dgram = Vec::with_capacity(PUNT_DESC_LEN + ip_pkt.len());
            dgram.extend_from_slice(&packet.sw_if_index.to_le_bytes());
            dgram.extend_from_slice(&PUNT_ACTION_IP6_ROUTED.to_le_bytes());
            dgram.extend_from_slice(&ip_pkt);
            self.tx.send_to(&dgram, &self.vpp_server_path)?;
        }
        Ok(())
    }

    pub fn interface(&self, sw_if_index: u32) -> Option<&IoInterfaceV3> {
        self.interfaces.get(&sw_if_index)
    }
}

/// Byte offset of the `checksum` field in the OSPFv3 header.
/// Layout (RFC 5340 §A.3.1): version(1) type(1) packet_length(2)
/// router_id(4) area_id(4) checksum(2) instance_id(1) reserved(1).
pub(crate) const OSPF_V3_CHECKSUM_OFFSET: usize = 12;

/// Compute the OSPFv3 packet checksum. Per RFC 5340 §2.4 this is the
/// standard Internet (one's-complement) checksum over the IPv6
/// pseudo-header followed by the OSPF packet (with the checksum
/// field set to zero during computation).
///
/// IPv6 pseudo-header (RFC 8200 §8.1): 16 src + 16 dst + 4 upper-
/// layer-length + 3 zeros + 1 next-header (= 40 bytes).
/// Patch the OSPFv3 checksum field of `packet` over the IPv6
/// pseudo-header derived from `src`/`dst` and return the resulting
/// bytes. Used by both the raw-socket and punt TX paths so neither
/// has to know the daemon's checksum encoding.
pub(crate) fn ospfv3_compute_checksum_in_place(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    packet: &[u8],
) -> Vec<u8> {
    let mut data = packet.to_vec();
    if data.len() >= OSPF_V3_CHECKSUM_OFFSET + 2 {
        data[OSPF_V3_CHECKSUM_OFFSET] = 0;
        data[OSPF_V3_CHECKSUM_OFFSET + 1] = 0;
        let csum = ospfv3_checksum(src, dst, &data);
        data[OSPF_V3_CHECKSUM_OFFSET..OSPF_V3_CHECKSUM_OFFSET + 2]
            .copy_from_slice(&csum.to_be_bytes());
    }
    data
}

pub(crate) fn ospfv3_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, ospf: &[u8]) -> u16 {
    let mut buf: Vec<u8> = Vec::with_capacity(40 + ospf.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.extend_from_slice(&(ospf.len() as u32).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 89]); // 3 zeros + next-header OSPF
    buf.extend_from_slice(ospf);

    // Standard Internet checksum: one's-complement sum of 16-bit
    // words, then one's-complement.
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < buf.len() {
        sum += ((buf[i] as u32) << 8) | buf[i + 1] as u32;
        i += 2;
    }
    if i < buf.len() {
        sum += (buf[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// True if `addr` is an IPv6 multicast address (ff00::/8).
fn is_multicast_v6(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] & 0xff00 == 0xff00
}

/// Map an IPv6 multicast destination to its ethernet MAC per RFC 2464
/// §7: prefix is `33:33`, then the low 32 bits of the group address.
fn multicast_mac_v6(addr: &Ipv6Addr) -> [u8; 6] {
    let o = addr.octets();
    [0x33, 0x33, o[12], o[13], o[14], o[15]]
}

/// Build an IPv6 header + payload. Hop Limit is hardcoded to 1 —
/// OSPFv3 packets are always link-local per RFC 5340 §4.3.
fn build_ipv6_packet(src: &Ipv6Addr, dst: &Ipv6Addr, data: &[u8]) -> Vec<u8> {
    let payload_length: u16 = data.len() as u16;
    let mut hdr = Vec::with_capacity(IPV6_HEADER_LEN + data.len());
    // IPv6 first 32-bit word (RFC 8200 §3):
    //   bits 0..3   = Version
    //   bits 4..11  = Traffic Class (8 bits)
    //   bits 12..31 = Flow Label (20 bits)
    //
    // Version=6, Traffic Class=0xc0 (CS6 = Internetwork Control, same
    // as OSPFv2), Flow Label=0. Packed: 0x6c000000.
    //   0x6c = 0110 1100   → version=0110=6, TC high nibble=1100
    //   0x00 = 0000 0000   → TC low nibble=0000, flow label high=0
    //
    // Earlier code used 0x60c00000 which encoded TC=0x0c instead of
    // 0xc0. The traffic class doesn't gate L2 forwarding, but it's
    // worth getting right so packet captures match peer
    // implementations and any DSCP-aware policers on the path
    // (e.g., switch CoS queues) classify the traffic correctly.
    hdr.extend_from_slice(&0x6c00_0000u32.to_be_bytes());
    hdr.extend_from_slice(&payload_length.to_be_bytes());
    hdr.push(89); // next header = OSPF
    hdr.push(1); // hop limit = 1 (link-local only)
    hdr.extend_from_slice(&src.octets());
    hdr.extend_from_slice(&dst.octets());
    hdr.extend_from_slice(data);
    hdr
}

async fn reader_task(
    sock: UnixDatagram,
    chan: mpsc::Sender<RxPacketV3>,
    interfaces: Arc<HashMap<u32, IoInterfaceV3>>,
) {
    let mut buf = vec![0u8; 65536];
    loop {
        let n = match sock.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("v3 punt recv error: {}", e);
                continue;
            }
        };
        // Min: 8 desc + 14 untagged eth + 40 v6 header + 16
        // OSPFv3 header. Tagged sub-interfaces add 4+ bytes that
        // crate::io_punt::eth_l3_offset walks past after this
        // floor.
        if n < PUNT_DESC_LEN + ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + 16 {
            tracing::debug!(len = n, "v3 punt datagram too short");
            continue;
        }

        let sw_if_index = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        // buf[4..8] is action — ignore on RX.

        // Walk eth header + any VLAN tags to the start of the IP6
        // header. Hardcoding 14 broke sub-interfaces — see the v2
        // path's eth_l3_offset for the rationale.
        let eth_start = PUNT_DESC_LEN;
        let eth_off = match crate::io_punt::eth_l3_offset(&buf[eth_start..n]) {
            Some(o) => o,
            None => {
                tracing::debug!(len = n, "v3 punt datagram has truncated ethernet header");
                continue;
            }
        };
        let l3_off = eth_start + eth_off;
        if l3_off + IPV6_HEADER_LEN > n {
            tracing::debug!(
                l3_off,
                recv = n,
                "v3 punt datagram truncated before IP6 header"
            );
            continue;
        }
        // Parse IPv6 header.
        let ver_tc = buf[l3_off] >> 4;
        if ver_tc != 6 {
            tracing::debug!("v3 punt: not an IPv6 packet (version {})", ver_tc);
            continue;
        }
        let next_hdr = buf[l3_off + 6];
        if next_hdr != 89 {
            // We could also see Hop-By-Hop (0) or Routing (43) extension
            // headers — but OSPFv3 doesn't use either in practice, so
            // drop quietly.
            tracing::debug!(next_hdr, "v3 punt: non-OSPF next header; skipping");
            continue;
        }
        let payload_len = u16::from_be_bytes([buf[l3_off + 4], buf[l3_off + 5]]) as usize;
        let mut src_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&buf[l3_off + 8..l3_off + 24]);
        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&buf[l3_off + 24..l3_off + 40]);
        let src_addr = Ipv6Addr::from(src_bytes);
        let dst_addr = Ipv6Addr::from(dst_bytes);

        let payload_start = l3_off + IPV6_HEADER_LEN;
        let payload_end = payload_start + payload_len;
        if payload_end > n {
            tracing::debug!(
                payload_len,
                recv = n,
                "v3 punt: payload_length exceeds datagram"
            );
            continue;
        }
        let data = buf[payload_start..payload_end].to_vec();

        if !interfaces.contains_key(&sw_if_index) {
            tracing::debug!(sw_if_index, "v3 punt: unknown interface");
            continue;
        }

        let pkt = RxPacketV3 {
            sw_if_index,
            src_addr,
            dst_addr,
            data,
        };
        if chan.send(pkt).await.is_err() {
            break;
        }
    }
}
