//! OSPF packet I/O abstraction.
//!
//! Phase 1 implementation: raw sockets on the dataplane namespace's linux-cp
//! TAP interfaces. This uses the same mechanism FRR uses today.
//!
//! Architecture:
//! - One AF_INET/SOCK_RAW/IPPROTO_OSPF socket per OSPF interface
//! - SO_BINDTODEVICE binds each to its TAP
//! - Multicast groups 224.0.0.5 and 224.0.0.6 joined on each interface
//! - One tokio task per socket reads packets and sends them to a shared mpsc
//! - send() is synchronous (raw sockets are always writable for our packet sizes)

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use crate::packet::{ALL_DR_ROUTERS, ALL_SPF_ROUTERS};

/// A received OSPF packet with metadata.
#[derive(Debug)]
pub struct RxPacket {
    pub sw_if_index: u32,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    /// OSPF packet data (starting from the OSPF header — IP header stripped).
    pub data: Vec<u8>,
}

/// Parameters for sending an OSPF packet.
#[derive(Debug)]
pub struct TxPacket {
    pub sw_if_index: u32,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    /// OSPF packet data (starting from the OSPF header — no IP header).
    pub data: Vec<u8>,
}

/// An OSPF-enabled interface (name + addresses + indices).
#[derive(Debug, Clone)]
pub struct IoInterface {
    pub name: String,
    pub sw_if_index: u32,
    pub kernel_ifindex: u32,
    pub address: Ipv4Addr,
    /// L2 MAC address, fetched from VPP's sw_interface_dump. Used only
    /// by the punt-socket backend when synthesizing ethernet headers
    /// for multicast TX via PUNT_L2. The raw-socket backend ignores
    /// this field since the kernel handles L2 via its own ARP table.
    pub mac_address: [u8; 6],
}

/// Raw-socket I/O for OSPF packets.
pub struct RawSocketIo {
    /// Mapping sw_if_index -> interface info.
    interfaces: HashMap<u32, IoInterface>,
    /// TX sockets (one per interface).
    tx_fds: HashMap<u32, Arc<OwnedFd>>,
    /// Incoming packet channel.
    rx: mpsc::Receiver<RxPacket>,
    /// Reader task handles (kept alive for the life of the struct).
    _reader_tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl RawSocketIo {
    /// Create an I/O handler for the given interfaces.
    pub fn new(interfaces: Vec<IoInterface>) -> std::io::Result<Self> {
        let mut iface_map = HashMap::new();
        let mut tx_fds = HashMap::new();
        let (tx, rx) = mpsc::channel(256);
        let mut reader_tasks = Vec::new();

        for iface in interfaces {
            tracing::info!(
                name = %iface.name,
                kernel_ifindex = iface.kernel_ifindex,
                address = %iface.address,
                "opening raw socket"
            );

            let sock_fd = open_ospf_socket(&iface)?;
            let sock_arc = Arc::new(sock_fd);

            // Dup for the reader task
            let reader_raw = unsafe { libc::dup(sock_arc.as_raw_fd()) };
            if reader_raw < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let reader_fd = unsafe { OwnedFd::from_raw_fd(reader_raw) };

            // Set reader non-blocking
            unsafe {
                let flags = libc::fcntl(reader_fd.as_raw_fd(), libc::F_GETFL, 0);
                libc::fcntl(reader_fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
            }

            let async_fd = AsyncFd::new(reader_fd)?;
            let tx_clone = tx.clone();
            let sw_if_index = iface.sw_if_index;
            let iface_name = iface.name.clone();

            let task = tokio::spawn(async move {
                reader_task(sw_if_index, iface_name, async_fd, tx_clone).await;
            });
            reader_tasks.push(task);

            tx_fds.insert(iface.sw_if_index, sock_arc);
            iface_map.insert(iface.sw_if_index, iface);
        }

        Ok(RawSocketIo {
            interfaces: iface_map,
            tx_fds,
            rx,
            _reader_tasks: reader_tasks,
        })
    }

    /// Receive the next OSPF packet from any interface.
    pub async fn recv(&mut self) -> Option<RxPacket> {
        self.rx.recv().await
    }

    /// Send an OSPF packet on the specified interface.
    pub fn send(&self, packet: &TxPacket) -> std::io::Result<()> {
        let fd = self.tx_fds.get(&packet.sw_if_index).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("unknown sw_if_index {}", packet.sw_if_index),
            )
        })?;

        // Use zeroed() to stay portable — BSD sockaddr_in has a leading sin_len
        // byte that Linux doesn't expose. Zeroing is fine since the kernel fills
        // in sin_len from the socklen_t we pass to sendto().
        let mut dest: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        dest.sin_family = libc::AF_INET as libc::sa_family_t;
        dest.sin_addr.s_addr = u32::from_be_bytes(packet.dst_addr.octets()).to_be();

        let ret = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                packet.data.as_ptr() as *const libc::c_void,
                packet.data.len(),
                0,
                &dest as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn interface(&self, sw_if_index: u32) -> Option<&IoInterface> {
        self.interfaces.get(&sw_if_index)
    }
}

/// Per-socket reader task: reads packets from one socket and pushes them to the channel.
async fn reader_task(
    sw_if_index: u32,
    iface_name: String,
    async_fd: AsyncFd<OwnedFd>,
    tx: mpsc::Sender<RxPacket>,
) {
    loop {
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(e) => {
                tracing::error!(iface = %iface_name, "readable() error: {}", e);
                break;
            }
        };

        let mut buf = vec![0u8; 2048];
        let raw_fd = async_fd.get_ref().as_raw_fd();

        let nread = unsafe {
            let mut src_addr: libc::sockaddr_in = std::mem::zeroed();
            let mut src_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            libc::recvfrom(
                raw_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut src_addr as *mut _ as *mut libc::sockaddr,
                &mut src_len,
            )
        };

        if nread < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            tracing::error!(iface = %iface_name, "recvfrom error: {}", err);
            break;
        }

        let nread = nread as usize;
        if nread < 20 {
            continue;
        }

        // Parse IP header
        let ip_hdr_len = ((buf[0] & 0x0F) as usize) * 4;
        if nread < ip_hdr_len {
            continue;
        }

        let src_addr = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
        let dst_addr = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
        let ospf_data = buf[ip_hdr_len..nread].to_vec();

        let rx_pkt = RxPacket {
            sw_if_index,
            src_addr,
            dst_addr,
            data: ospf_data,
        };

        if tx.send(rx_pkt).await.is_err() {
            break;
        }
    }
}

/// Open an OSPF raw socket bound to a specific interface.
fn open_ospf_socket(iface: &IoInterface) -> std::io::Result<OwnedFd> {
    // socket(AF_INET, SOCK_RAW, IPPROTO_OSPF)
    let raw_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, 89) };
    if raw_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    // SO_BINDTODEVICE (Linux-only). On FreeBSD/BSD we skip it; inbound packet
    // filtering is per-multicast-group + IP_MULTICAST_IF, and outbound
    // interface selection is handled by IP_MULTICAST_IF below. The RX path
    // may need an IP_RECVIF-based sw_if_index dispatch later if we want
    // per-socket-per-interface isolation; for the experiment, per-socket is
    // enough because each socket joins groups on one interface only.
    #[cfg(target_os = "linux")]
    {
        let ifname_bytes = iface.name.as_bytes();
        if ifname_bytes.len() >= libc::IFNAMSIZ {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }
        unsafe {
            let ret = libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                ifname_bytes.as_ptr() as *const libc::c_void,
                ifname_bytes.len() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }

    // Join multicast groups
    join_multicast(fd.as_raw_fd(), ALL_SPF_ROUTERS, iface.kernel_ifindex)?;
    join_multicast(fd.as_raw_fd(), ALL_DR_ROUTERS, iface.kernel_ifindex)?;

    // Set multicast output interface
    set_multicast_if(fd.as_raw_fd(), iface.kernel_ifindex)?;

    // Disable multicast loopback
    unsafe {
        let off: libc::c_int = 0;
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_LOOP,
            &off as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        // Multicast TTL = 1 (OSPF packets don't cross routers)
        let ttl: libc::c_int = 1;
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_TTL,
            &ttl as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    Ok(fd)
}

/// Join a multicast group on a specific interface.
fn join_multicast(fd: RawFd, group: Ipv4Addr, ifindex: u32) -> std::io::Result<()> {
    let mreqn = libc::ip_mreqn {
        imr_multiaddr: libc::in_addr {
            s_addr: u32::from_be_bytes(group.octets()).to_be(),
        },
        imr_address: libc::in_addr { s_addr: 0 },
        imr_ifindex: ifindex as libc::c_int,
    };
    unsafe {
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_ADD_MEMBERSHIP,
            &mreqn as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
        );
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Set the outgoing multicast interface.
fn set_multicast_if(fd: RawFd, ifindex: u32) -> std::io::Result<()> {
    let mreqn = libc::ip_mreqn {
        imr_multiaddr: libc::in_addr { s_addr: 0 },
        imr_address: libc::in_addr { s_addr: 0 },
        imr_ifindex: ifindex as libc::c_int,
    };
    unsafe {
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            &mreqn as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
        );
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// OSPFv2 I/O backend — dispatches to the selected transport
/// implementation. Introduced to let the daemon choose between the
/// legacy raw-socket-on-LCP-TAP path and a VPP punt-socket path at
/// runtime via a CLI flag. Both variants share the same RxPacket /
/// TxPacket data shapes, so the protocol code above doesn't care
/// which backend is in play.
///
/// Variants:
///   Raw  — AF_INET/SOCK_RAW bound to each LCP TAP. Linux-only.
///          Reuses the long-standing implementation in this file.
///   Punt — VPP active-punt socket for IP proto 89. Requires
///          `punt { socket /run/vpp/punt-server.sock }` in VPP's
///          startup.conf. See io_punt.rs for the implementation.
pub enum Ospfv2Io {
    Raw(RawSocketIo),
    Punt(crate::io_punt::PuntSocketIo),
}

impl Ospfv2Io {
    pub async fn recv(&mut self) -> Option<RxPacket> {
        match self {
            Ospfv2Io::Raw(io) => io.recv().await,
            Ospfv2Io::Punt(io) => io.recv().await,
        }
    }

    pub fn send(&self, packet: &TxPacket) -> std::io::Result<()> {
        match self {
            Ospfv2Io::Raw(io) => io.send(packet),
            Ospfv2Io::Punt(io) => io.send(packet),
        }
    }

    pub fn interface(&self, sw_if_index: u32) -> Option<&IoInterface> {
        match self {
            Ospfv2Io::Raw(io) => io.interface(sw_if_index),
            Ospfv2Io::Punt(io) => io.interface(sw_if_index),
        }
    }
}
