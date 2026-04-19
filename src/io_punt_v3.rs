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

        // Build the IPv6 header. The daemon_v3 layer already computed
        // OSPFv3's own checksum over the pseudo-header + body, so the
        // `data` field is ready to ship as-is.
        let ip_pkt = build_ipv6_packet(&packet.src_addr, &packet.dst_addr, &packet.data);

        if is_multicast_v6(&packet.dst_addr) {
            // PUNT_L2: build a full ethernet frame with the multicast
            // MAC derived from the group address per RFC 2464 §7.
            let dst_mac = multicast_mac_v6(&packet.dst_addr);
            let mut frame = Vec::with_capacity(14 + ip_pkt.len());
            frame.extend_from_slice(&dst_mac);
            frame.extend_from_slice(&iface.mac_address);
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
    // Version=6 (4b) | Traffic Class (8b) | Flow Label (20b)
    //   version=6, TC=0xc0 (Internetwork Control, same as v2), flow=0
    // Byte 0: 0x60 (version 6 high nibble, TC high nibble = 0)
    // Byte 1: 0x0c (TC low 4 bits = 0xc, flow high 4 bits = 0)
    //
    // Actually: the full 32-bit word is 0x60c00000:
    //   bits 0..3  = 6  (version)
    //   bits 4..11 = 0xc0 (traffic class = IP Precedence Internet Control)
    //   bits 12..31 = 0 (flow label)
    hdr.extend_from_slice(&0x60c0_0000u32.to_be_bytes());
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
        // Min: 8 desc + 14 eth + 40 v6 header + 16 OSPFv3 header
        if n < PUNT_DESC_LEN + ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + 16 {
            tracing::debug!(len = n, "v3 punt datagram too short");
            continue;
        }

        let sw_if_index = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        // buf[4..8] is action — ignore on RX.

        let l3_off = PUNT_DESC_LEN + ETHERNET_HEADER_LEN;
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
