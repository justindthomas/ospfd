//! OSPFv3 packet I/O over IPv6 raw sockets.
//!
//! Mirrors `io.rs` but for IPv6:
//! - AF_INET6 / SOCK_RAW / IPPROTO_OSPFIGP (89)
//! - Joins ff02::5 (AllSPFRouters) and ff02::6 (AllDRRouters) per interface
//! - Uses IPV6_MULTICAST_IF / HOPS / LOOP
//! - Binds to link-local source via IPV6_PKTINFO on TX
//!
//! Unlike the IPv4 raw socket path, IPv6 raw sockets deliver payload
//! without the IP header, so the reader doesn't need to strip one.

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use crate::io_punt_v3::ospfv3_compute_checksum_in_place;
use crate::packet_v3::{ALL_DR_ROUTERS_V6, ALL_SPF_ROUTERS_V6, OSPFV3_IP_PROTO};

#[derive(Debug)]
pub struct RxPacketV3 {
    pub sw_if_index: u32,
    pub src_addr: Ipv6Addr,
    pub dst_addr: Ipv6Addr,
    /// OSPFv3 packet (starting at the v3 header).
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct TxPacketV3 {
    pub sw_if_index: u32,
    pub src_addr: Ipv6Addr,
    pub dst_addr: Ipv6Addr,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct IoInterfaceV3 {
    pub name: String,
    pub sw_if_index: u32,
    pub kernel_ifindex: u32,
    /// Link-local address used as source for OSPFv3 packets.
    pub link_local: Ipv6Addr,
    /// L2 MAC address. Used only by the punt backend for
    /// synthesizing ethernet headers on PUNT_L2 multicast TX.
    pub mac_address: [u8; 6],
    /// 802.1Q outer VLAN tag, or `None` for untagged parent
    /// interfaces. PUNT_L2 hands VPP a fully-formed L2 frame and
    /// VPP does NOT push the vlan tag on egress (unlike the
    /// PUNT_IP6_ROUTED / unicast path, which runs through
    /// ip6-rewrite and gets the tag). Without this field, ff02::5
    /// hellos egressed lan.110 untagged and trunk peers dropped
    /// them.
    pub outer_vlan_id: Option<u16>,
    /// 802.1Q inner VLAN tag for QinQ sub-interfaces. `None` when
    /// `sub_number_of_tags < 2`.
    pub inner_vlan_id: Option<u16>,
}

pub struct RawSocketIoV3 {
    interfaces: HashMap<u32, IoInterfaceV3>,
    tx_fds: HashMap<u32, Arc<OwnedFd>>,
    rx: mpsc::Receiver<RxPacketV3>,
    _reader_tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl RawSocketIoV3 {
    pub fn new(interfaces: Vec<IoInterfaceV3>) -> std::io::Result<Self> {
        let mut iface_map = HashMap::new();
        let mut tx_fds = HashMap::new();
        let (tx, rx) = mpsc::channel(256);
        let mut reader_tasks = Vec::new();

        for iface in interfaces {
            tracing::info!(
                name = %iface.name,
                kernel_ifindex = iface.kernel_ifindex,
                link_local = %iface.link_local,
                "opening IPv6 raw socket for OSPFv3"
            );

            let sock_fd = open_ospfv3_socket(&iface)?;
            let sock_arc = Arc::new(sock_fd);

            let reader_raw = unsafe { libc::dup(sock_arc.as_raw_fd()) };
            if reader_raw < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let reader_fd = unsafe { OwnedFd::from_raw_fd(reader_raw) };
            unsafe {
                let flags = libc::fcntl(reader_fd.as_raw_fd(), libc::F_GETFL, 0);
                if flags < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(reader_fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
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

        Ok(RawSocketIoV3 {
            interfaces: iface_map,
            tx_fds,
            rx,
            _reader_tasks: reader_tasks,
        })
    }

    pub async fn recv(&mut self) -> Option<RxPacketV3> {
        self.rx.recv().await
    }

    pub fn send(&self, packet: &TxPacketV3) -> std::io::Result<()> {
        let fd = self.tx_fds.get(&packet.sw_if_index).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("unknown sw_if_index {}", packet.sw_if_index),
            )
        })?;

        let iface = self.interfaces.get(&packet.sw_if_index).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "unknown interface")
        })?;

        // Compute the OSPFv3 checksum over the IPv6 pseudo-header
        // and the OSPF packet (see io_punt_v3 for the rationale).
        // SOCK_RAW with IPPROTO_OSPF leaves the checksum to us;
        // without this, peers running RFC-compliant OSPFv3 reject
        // the packet and the adjacency never forms.
        let data = ospfv3_compute_checksum_in_place(
            &packet.src_addr,
            &packet.dst_addr,
            &packet.data,
        );

        // zeroed() for portability — BSD sockaddr_in6 has a leading sin6_len byte.
        let mut dest: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        dest.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        dest.sin6_addr.s6_addr = packet.dst_addr.octets();
        dest.sin6_scope_id = iface.kernel_ifindex;

        let ret = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &dest as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn interface(&self, sw_if_index: u32) -> Option<&IoInterfaceV3> {
        self.interfaces.get(&sw_if_index)
    }
}

async fn reader_task(
    sw_if_index: u32,
    iface_name: String,
    async_fd: AsyncFd<OwnedFd>,
    tx: mpsc::Sender<RxPacketV3>,
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

        let (nread, src_addr) = unsafe {
            let mut src: libc::sockaddr_in6 = std::mem::zeroed();
            let mut src_len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            let n = libc::recvfrom(
                raw_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut src as *mut _ as *mut libc::sockaddr,
                &mut src_len,
            );
            (n, Ipv6Addr::from(src.sin6_addr.s6_addr))
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
        if nread < 16 {
            continue;
        }

        // IPv6 raw sockets deliver the payload without the IPv6 header.
        // Destination address isn't directly available without IPV6_RECVPKTINFO
        // and recvmsg; leave it unspecified for now (callers generally just
        // need to know if it was multicast vs unicast, which they can infer
        // from packet semantics).
        let data = buf[..nread].to_vec();

        let rx_pkt = RxPacketV3 {
            sw_if_index,
            src_addr,
            dst_addr: Ipv6Addr::UNSPECIFIED,
            data,
        };

        if tx.send(rx_pkt).await.is_err() {
            break;
        }
    }
}

fn open_ospfv3_socket(iface: &IoInterfaceV3) -> std::io::Result<OwnedFd> {
    let raw_fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, OSPFV3_IP_PROTO as i32) };
    if raw_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    // SO_BINDTODEVICE (Linux-only); see rationale in io.rs.
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

    // Checksum offload: kernel computes OSPFv3 checksum (with IPv6 pseudo-header).
    // Offset 12 is the "Checksum" field in the OSPFv3 header.
    unsafe {
        let offset: libc::c_int = 12;
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_CHECKSUM,
            &offset as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    join_multicast6(fd.as_raw_fd(), ALL_SPF_ROUTERS_V6, iface.kernel_ifindex)?;
    join_multicast6(fd.as_raw_fd(), ALL_DR_ROUTERS_V6, iface.kernel_ifindex)?;
    set_multicast_if6(fd.as_raw_fd(), iface.kernel_ifindex)?;

    unsafe {
        let off: libc::c_int = 0;
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_LOOP,
            &off as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let hops: libc::c_int = 1;
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_HOPS,
            &hops as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let hops_uni: libc::c_int = 1;
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS,
            &hops_uni as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    Ok(fd)
}

fn join_multicast6(fd: RawFd, group: Ipv6Addr, ifindex: u32) -> std::io::Result<()> {
    let mreq = libc::ipv6_mreq {
        ipv6mr_multiaddr: libc::in6_addr {
            s6_addr: group.octets(),
        },
        ipv6mr_interface: ifindex,
    };
    // IPV6_ADD_MEMBERSHIP on Linux; IPV6_JOIN_GROUP on BSD (same numeric value,
    // different name exposed by libc).
    #[cfg(target_os = "linux")]
    let join_opt = libc::IPV6_ADD_MEMBERSHIP;
    #[cfg(not(target_os = "linux"))]
    let join_opt = libc::IPV6_JOIN_GROUP;
    unsafe {
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            join_opt,
            &mreq as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::ipv6_mreq>() as libc::socklen_t,
        );
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn set_multicast_if6(fd: RawFd, ifindex: u32) -> std::io::Result<()> {
    unsafe {
        let idx: libc::c_uint = ifindex;
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_IF,
            &idx as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        );
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// OSPFv3 I/O backend wrapper — same shape as v2's `Ospfv2Io`. See
/// `io.rs` for the rationale. The `Raw` variant talks to the Linux
/// kernel via an IPv6 raw socket bound to an LCP TAP; the `Punt`
/// variant talks to VPP's active-punt socket for IPv6 proto 89.
pub enum Ospfv3Io {
    Raw(RawSocketIoV3),
    Punt(crate::io_punt_v3::PuntSocketIoV3),
}

impl Ospfv3Io {
    pub async fn recv(&mut self) -> Option<RxPacketV3> {
        match self {
            Ospfv3Io::Raw(io) => io.recv().await,
            Ospfv3Io::Punt(io) => io.recv().await,
        }
    }

    pub fn send(&self, packet: &TxPacketV3) -> std::io::Result<()> {
        match self {
            Ospfv3Io::Raw(io) => io.send(packet),
            Ospfv3Io::Punt(io) => io.send(packet),
        }
    }

    #[allow(dead_code)]
    pub fn interface(&self, sw_if_index: u32) -> Option<&IoInterfaceV3> {
        match self {
            Ospfv3Io::Raw(io) => io.interface(sw_if_index),
            Ospfv3Io::Punt(io) => io.interface(sw_if_index),
        }
    }
}
