//! OSPFv3 daemon task — self-contained runtime.
//!
//! Spawned as an independent tokio task from main.rs. Owns the v3
//! instance, the v3 raw-socket I/O layer, the v3 RIB, and the
//! hello / dead / SPF / refresh timers.
//!
//! Runtime loop select arms:
//!  - io.recv() → handle_rx (hello / dd / lsr / lsu / lsack)
//!  - hello_tick → encode_hello, emit_pending_dds, emit_pending_lsdb_packets
//!  - expire_tick → expire_neighbors, refresh_router_lsa_if_needed
//!  - spf_tick → calculate_spf_v3 + rib.apply_routes when LSDB or
//!    neighbor count changes
//!  - iface_refresh → periodic VPP poll for address / link state
//!    changes, fire refresh_interface_state
//!
//! Interface addresses are discovered from VPP (not Linux) via the
//! ip_address_dump + sw_interface_ip6_get_link_local_address calls.

use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::instance_v3::{InstanceV3, NetworkTypeV3};
use crate::io_v3::{IoInterfaceV3, RawSocketIoV3, TxPacketV3};
use crate::rib_client::RibClient;
use crate::rib_v3::OspfRibV3;
use crate::spf_v3::calculate_spf_v3;

#[derive(Debug, Clone)]
pub struct V3InterfaceConfig {
    pub name: String,
    pub sw_if_index: u32,
    pub kernel_ifindex: u32,
    pub link_local: Ipv6Addr,
    /// Global/site-local IPv6 prefixes on this interface, used for
    /// Intra-Area-Prefix-LSA origination. (address, prefix_length)
    pub global_prefixes: Vec<(Ipv6Addr, u8)>,
    pub area_id: std::net::Ipv4Addr,
    pub network_type: NetworkTypeV3,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub retransmit_interval: u16,
    pub transmit_delay: u16,
    pub priority: u8,
    /// Static NBMA neighbors (peer link-local IPv6 + priority).
    /// Only populated and only meaningful when `network_type ==
    /// NonBroadcast`.
    pub static_neighbors: Vec<(Ipv6Addr, u8)>,
    /// L2 MAC address (from sw_interface_dump). Only used by the
    /// punt backend when synthesizing ethernet headers for
    /// multicast TX via PUNT_L2.
    pub mac_address: [u8; 6],
}

#[derive(Debug, Clone)]
pub struct V3DaemonConfig {
    pub router_id: std::net::Ipv4Addr,
    pub interfaces: Vec<V3InterfaceConfig>,
    /// Per-area type (Normal / Stub / NSSA). Used to gate Type 5
    /// AS-External LSA flooding and Type 7 NSSA-LSA scope.
    pub areas: Vec<(std::net::Ipv4Addr, crate::area::AreaType)>,
    /// Redistribute sources (source, metric, metric_type). A non-empty
    /// list makes us an ASBR: the E flag is set in our Router-LSA and
    /// Type 5 AS-External-LSAs are originated for matching prefixes.
    pub redistribute: Vec<(crate::config::RedistributeSource, u32, u8)>,
    /// Admin-distance override applied to all v3 route sub-types.
    /// `None` keeps the ribd default (110).
    pub distance: Option<u8>,
    /// When true, originate a Type 5 default route (::/0).
    pub default_originate: bool,
    pub default_originate_metric: u32,
    pub default_originate_metric_type: u8,
    /// Parsed summary-address entries (ASBR external aggregation).
    pub summary_addresses: Vec<crate::config::ParsedSummaryAddress6>,
    /// Which I/O backend to use: raw sockets on the LCP TAP, or a
    /// VPP active-punt socket registered for IPv6 proto 89.
    /// Mirrors the v2 IoBackend in main.rs.
    pub io_backend: V3IoBackend,
}

/// OSPFv3 I/O backend selector. Duplicated from main.rs's v2
/// IoBackend to keep the v3 subtree independent, but carrying the
/// same semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V3IoBackend {
    Raw,
    Punt,
}

/// Run the OSPFv3 daemon loop. Returns on fatal error or cancellation.
///
/// `instance` is a shared handle created by main.rs before the task
/// is spawned, so the control server can read v3 state without
/// needing to wait for setup to complete.
pub async fn run(
    mut cfg: V3DaemonConfig,
    vpp: vpp_api::VppClient,
    instance: Arc<Mutex<InstanceV3>>,
) -> anyhow::Result<()> {
    if cfg.interfaces.is_empty() {
        tracing::info!("OSPFv3: no interfaces configured, not starting");
        return Ok(());
    }

    tracing::info!(
        router_id = %cfg.router_id,
        interfaces = cfg.interfaces.len(),
        "starting OSPFv3 daemon task"
    );

    // Discover IPv6 addresses for each interface from VPP (the source
    // of truth — the v3 daemon programs VPP directly, not Linux).
    // Retry for up to 8s: VPP enables IPv6 on an interface lazily
    // (when the first v6 address is added or `ip6 enable` runs from
    // commands-core.txt), and the link-local auto-assignment finishes
    // a beat after that. The supervisor spawns imp-ospfd the moment
    // VPP binds its API socket, which can pre-date the v6 init.
    let mut usable = Vec::new();
    for mut ic in cfg.interfaces.drain(..) {
        let mut addrs = discover_addrs_vpp(&vpp, ic.sw_if_index).await;
        if addrs.link_local.is_none() {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
            while std::time::Instant::now() < deadline {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                addrs = discover_addrs_vpp(&vpp, ic.sw_if_index).await;
                if addrs.link_local.is_some() {
                    break;
                }
            }
        }
        let Some(ll) = addrs.link_local else {
            tracing::info!(
                name = %ic.name,
                "OSPFv3: no IPv6 link-local address in VPP after retries, skipping interface"
            );
            continue;
        };
        ic.link_local = ll;
        ic.global_prefixes = addrs.global_prefixes;
        tracing::info!(
            name = %ic.name,
            sw_if_index = ic.sw_if_index,
            link_local = %ll,
            prefixes = ic.global_prefixes.len(),
            "OSPFv3: discovered interface addresses from VPP"
        );
        usable.push(ic);
    }
    cfg.interfaces = usable;
    if cfg.interfaces.is_empty() {
        tracing::info!("OSPFv3: no interfaces with link-local addresses, exiting");
        return Ok(());
    }

    // Populate the shared instance with area types and interfaces.
    {
        let mut inst = instance.lock().await;
        inst.redistribute = cfg.redistribute.clone();
        inst.set_asbr(!cfg.redistribute.is_empty());
        for (area_id, area_type) in &cfg.areas {
            inst.set_area_type(*area_id, *area_type);
        }
        for ic in &cfg.interfaces {
            let io = IoInterfaceV3 {
                name: ic.name.clone(),
                sw_if_index: ic.sw_if_index,
                kernel_ifindex: ic.kernel_ifindex,
                link_local: ic.link_local,
                mac_address: ic.mac_address,
            };
            let sw_if_index = ic.sw_if_index;
            inst.add_interface_full(
                io,
                ic.area_id,
                ic.network_type,
                ic.hello_interval,
                ic.dead_interval,
                ic.priority,
                ic.global_prefixes.clone(),
                ic.retransmit_interval,
                ic.transmit_delay,
            );
            if !ic.static_neighbors.is_empty() {
                let neighbors = ic
                    .static_neighbors
                    .iter()
                    .map(|(addr, prio)| crate::instance_v3::StaticNeighborV3 {
                        link_local: *addr,
                        priority: *prio,
                    })
                    .collect();
                inst.set_static_neighbors_v3(sw_if_index, neighbors);
            }
        }
        // Originate our initial self-LSAs so the LSDB is populated
        // before any peer DD exchange begins.
        inst.originate_router_lsa();
        inst.originate_intra_area_prefix_lsas();
        inst.originate_inter_area_prefix_lsas();
    }

    // If we're an ASBR, discover the set of externally-redistributable
    // prefixes from VPP (all non-OSPF-enrolled interfaces' globals)
    // and originate Type 5 AS-External-LSAs.
    if !cfg.redistribute.is_empty() {
        let enrolled: std::collections::HashSet<u32> = {
            let inst = instance.lock().await;
            inst.interfaces.keys().copied().collect()
        };
        let externals = discover_externals(&vpp, &enrolled).await;
        let mut inst = instance.lock().await;
        inst.originate_external_lsas(externals, &cfg.summary_addresses);
    }

    // Default-route origination (::/0): independent of redistribute.
    // Makes this router the gateway of last resort for the OSPFv3
    // domain.
    if cfg.default_originate {
        let mut inst = instance.lock().await;
        // set_asbr so the E flag is set and flooding treats Type 5
        // as valid — default_originate implies ASBR-hood even if
        // no other redistribute sources are configured.
        inst.set_asbr(true);
        inst.originate_default_route_lsa(
            cfg.default_originate_metric,
            cfg.default_originate_metric_type,
        );
    }

    // Summary-address aggregates. Same ASBR implication as
    // default_originate — emitting a Type 5 only makes sense with
    // the E flag set.
    if !cfg.summary_addresses.is_empty() {
        let mut inst = instance.lock().await;
        inst.set_asbr(true);
        inst.originate_summary_address_lsas(&cfg.summary_addresses);
    }

    let io_ifaces: Vec<IoInterfaceV3> = cfg
        .interfaces
        .iter()
        .map(|ic| IoInterfaceV3 {
            name: ic.name.clone(),
            sw_if_index: ic.sw_if_index,
            kernel_ifindex: ic.kernel_ifindex,
            link_local: ic.link_local,
            mac_address: ic.mac_address,
        })
        .collect();
    let mut io = match cfg.io_backend {
        V3IoBackend::Raw => crate::io_v3::Ospfv3Io::Raw(RawSocketIoV3::new(io_ifaces)?),
        V3IoBackend::Punt => {
            let client_path = "/run/ospfd/punt-v6.sock";
            let _ = std::fs::create_dir_all("/run/ospfd");
            let vpp_server_path = register_punt_v6(&vpp, client_path).await?;
            crate::io_v3::Ospfv3Io::Punt(crate::io_punt_v3::PuntSocketIoV3::new(
                io_ifaces,
                client_path,
                vpp_server_path,
            )?)
        }
    };

    let mut rib = OspfRibV3::new();
    let mut last_lsdb_size = 0usize;
    let mut last_neighbor_count = 0usize;

    // Connect to ribd. v3 uses its own RibClient so its
    // connection lifecycle is independent from v2.
    let mut rib_client = RibClient::new("/run/ribd.sock", "ospfd-v3");
    if let Err(e) = rib_client.connect(Duration::from_secs(10)).await {
        tracing::warn!(
            "ribd connect (v3) failed at startup: {} — will retry on next push",
            e
        );
    }
    let ad_override_v6: Option<u8> = cfg.distance;

    let mut hello_tick = tokio::time::interval(Duration::from_secs(1));
    hello_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut expire_tick = tokio::time::interval(Duration::from_secs(1));
    let mut spf_tick = tokio::time::interval(Duration::from_secs(2));
    spf_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Same startup-race avoidance as v2 (see main.rs::iface_refresh):
    // skip the immediate first tick so we don't transiently see an
    // empty IpAddressDump and demote the interface back to Down.
    let mut iface_refresh = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(30),
        Duration::from_secs(30),
    );
    iface_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            Some(rx) = io.recv() => {
                let mut inst = instance.lock().await;
                if let Err(e) = inst.handle_rx(rx) {
                    tracing::debug!("OSPFv3 rx error: {}", e);
                }
            }

            _ = hello_tick.tick() => {
                let now = Instant::now();
                let mut inst = instance.lock().await;
                let packets = inst.hello_tick(now);
                for pkt in packets {
                    send(&io, pkt);
                }
                let dds = inst.emit_pending_dds(now);
                for pkt in dds {
                    send(&io, pkt);
                }
                let lsdb_pkts = inst.emit_pending_lsdb_packets();
                for pkt in lsdb_pkts {
                    send(&io, pkt);
                }
            }

            _ = expire_tick.tick() => {
                let mut inst = instance.lock().await;
                inst.expire_neighbors(Instant::now());
                inst.refresh_router_lsa_if_needed();
            }

            _ = iface_refresh.tick() => {
                use vpp_api::generated::interface::{SwInterfaceDetails, SwInterfaceDump};
                // Snapshot sw_if_indices without holding the lock during
                // the VPP dumps (those are async).
                let sw_if_indices: Vec<u32> = {
                    let inst = instance.lock().await;
                    inst.interfaces.keys().copied().collect()
                };
                let vpp_ifaces: Vec<SwInterfaceDetails> = vpp
                    .dump::<SwInterfaceDump, SwInterfaceDetails>(SwInterfaceDump::default())
                    .await
                    .unwrap_or_default();
                let mut snapshots = Vec::new();
                for sw_if_index in sw_if_indices {
                    let oper_up = vpp_ifaces
                        .iter()
                        .find(|vi| vi.sw_if_index == sw_if_index)
                        .map(|vi| vi.flags.is_admin_up() && vi.flags.is_link_up())
                        .unwrap_or(false);
                    let addrs = discover_addrs_vpp(&vpp, sw_if_index).await;
                    snapshots.push((sw_if_index, addrs.link_local, addrs.global_prefixes, oper_up));
                }
                let mut inst = instance.lock().await;
                let mut any_change = false;
                for (sw_if_index, ll, prefixes, oper_up) in snapshots {
                    if inst.refresh_interface_state(sw_if_index, ll, prefixes, oper_up) {
                        any_change = true;
                    }
                }
                if any_change {
                    inst.refresh_router_lsa_if_needed();
                    // Force SPF on next tick
                    last_lsdb_size = 0;
                    last_neighbor_count = 0;
                }
                drop(inst);
                // Refresh Type 5 LSAs too (prefix set may have changed
                // on non-OSPF interfaces).
                if !cfg.redistribute.is_empty() {
                    let enrolled: std::collections::HashSet<u32> = {
                        let inst = instance.lock().await;
                        inst.interfaces.keys().copied().collect()
                    };
                    let externals = discover_externals(&vpp, &enrolled).await;
                    let mut inst = instance.lock().await;
                    inst.originate_external_lsas(externals, &cfg.summary_addresses);
                }
            }

            _ = spf_tick.tick() => {
                // Compute routes under the lock, then release before
                // the async VPP apply.
                let (lsdb_size, neighbor_count, routes) = {
                    let mut inst = instance.lock().await;
                    let lsdb_size = inst.lsdb.len();
                    let neighbors = inst.spf_neighbors();
                    if lsdb_size == last_lsdb_size
                        && neighbors.len() == last_neighbor_count
                    {
                        continue;
                    }
                    // Re-originate Type 3 Inter-Area-Prefix-LSAs if
                    // we're an ABR. Must happen before SPF so the
                    // computed routes include newly-summarized inter-
                    // area prefixes.
                    inst.originate_inter_area_prefix_lsas();
                    let routes = calculate_spf_v3(cfg.router_id, &inst.lsdb, &neighbors);
                    (lsdb_size, neighbors.len(), routes)
                };
                last_lsdb_size = lsdb_size;
                last_neighbor_count = neighbor_count;
                tracing::debug!(
                    lsdb = lsdb_size,
                    neighbors = neighbor_count,
                    routes = routes.len(),
                    "OSPFv3 SPF run"
                );
                let (added, deleted) = rib.apply_routes(&routes);
                if added > 0 || deleted > 0 {
                    tracing::info!(
                        added,
                        deleted,
                        total = rib.route_count(),
                        "OSPFv3 SPF cache updated"
                    );
                }
                // Push to ribd. push_v6 splits by sub-type
                // (intra / inter / ext1 / ext2) into four separate
                // Bulks for ribd admin-distance arbitration.
                if let Err(e) = rib_client
                    .push_v6(&routes, |_kind| ad_override_v6)
                    .await
                {
                    tracing::warn!("OSPFv3 ribd push failed: {}", e);
                }
            }
        }
    }
}

fn send(io: &crate::io_v3::Ospfv3Io, pkt: TxPacketV3) {
    if let Err(e) = io.send(&pkt) {
        tracing::warn!(sw_if_index = pkt.sw_if_index, "OSPFv3 send error: {}", e);
    }
}

/// Register a punt socket against VPP for IPv6 proto 89 (OSPFv3).
/// Mirrors `register_punt_v4` in main.rs; kept local to daemon_v3
/// because v3 has its own dedicated VPP client.
async fn register_punt_v6(
    vpp: &vpp_api::VppClient,
    client_pathname: &str,
) -> anyhow::Result<String> {
    use vpp_api::generated::punt::{
        PuntSocketRegister, PuntSocketRegisterReply, PuntType,
    };
    let req = PuntSocketRegister {
        header_version: 1,
        punt_type: PuntType::IpProto,
        af: 1, // AF_IP6
        protocol: 89,
        port: 0,
        pathname: client_pathname.to_string(),
    };
    let reply: PuntSocketRegisterReply = vpp
        .request::<PuntSocketRegister, PuntSocketRegisterReply>(req)
        .await
        .map_err(|e| anyhow::anyhow!("punt_socket_register (v6): {}", e))?;
    if reply.retval != 0 {
        anyhow::bail!(
            "punt_socket_register for IPv6 proto 89 failed: retval={}",
            reply.retval,
        );
    }
    let server = reply.pathname.trim_end_matches('\0').to_string();
    tracing::info!(
        client = client_pathname,
        server = server.as_str(),
        "registered punt socket for IPv6 proto 89"
    );
    Ok(server)
}

/// Discovered IPv6 addresses on a single interface (from VPP).
#[derive(Debug, Clone, Default)]
pub struct DiscoveredAddrs {
    pub link_local: Option<Ipv6Addr>,
    /// (address, prefix_length) pairs for non-link-local addresses.
    pub global_prefixes: Vec<(Ipv6Addr, u8)>,
}

/// Query VPP for IPv6 addresses on the given sw_if_index. Returns the
/// link-local plus all configured global/site-local prefixes.
///
/// VPP exposes link-local addresses through a dedicated request
/// (sw_interface_ip6_get_link_local_address) — they are NOT included
/// in the ip_address_dump output even though they exist on the
/// interface. Both calls are needed.
/// Enumerate all IPv6 prefixes on VPP interfaces that are NOT
/// enrolled in OSPFv3. Used for `redistribute connected` — these are
/// the prefixes emitted as Type 5 AS-External-LSAs.
pub async fn discover_externals(
    vpp: &vpp_api::VppClient,
    enrolled: &std::collections::HashSet<u32>,
) -> Vec<(Ipv6Addr, u8)> {
    use vpp_api::generated::interface::{SwInterfaceDetails, SwInterfaceDump};
    let vpp_ifaces: Vec<SwInterfaceDetails> = vpp
        .dump::<SwInterfaceDump, SwInterfaceDetails>(SwInterfaceDump::default())
        .await
        .unwrap_or_default();
    let mut out = Vec::new();
    for vi in vpp_ifaces {
        if enrolled.contains(&vi.sw_if_index) {
            continue;
        }
        if !vi.flags.is_admin_up() {
            continue;
        }
        let addrs = discover_addrs_vpp(vpp, vi.sw_if_index).await;
        for p in addrs.global_prefixes {
            out.push(p);
        }
    }
    out
}

pub async fn discover_addrs_vpp(
    vpp: &vpp_api::VppClient,
    sw_if_index: u32,
) -> DiscoveredAddrs {
    use vpp_api::generated::ip::{
        IpAddressDetails, IpAddressDump, SwInterfaceIp6GetLinkLocalAddress,
        SwInterfaceIp6GetLinkLocalAddressReply,
    };
    let mut out = DiscoveredAddrs::default();

    // 1. Link-local
    match vpp
        .request::<SwInterfaceIp6GetLinkLocalAddress, SwInterfaceIp6GetLinkLocalAddressReply>(
            SwInterfaceIp6GetLinkLocalAddress { sw_if_index },
        )
        .await
    {
        Ok(reply) if reply.retval == 0 => {
            let addr = Ipv6Addr::from(reply.ip);
            if !addr.is_unspecified() {
                out.link_local = Some(addr);
            }
        }
        Ok(reply) => {
            tracing::warn!(
                sw_if_index,
                retval = reply.retval,
                "sw_interface_ip6_get_link_local_address returned error"
            );
        }
        Err(e) => {
            tracing::warn!(sw_if_index, "link-local lookup failed: {}", e);
        }
    }

    // 2. Global / site-local prefixes
    let dump = IpAddressDump {
        sw_if_index,
        is_ipv6: true,
    };
    match vpp.dump::<IpAddressDump, IpAddressDetails>(dump).await {
        Ok(details) => {
            for d in details {
                let addr = Ipv6Addr::from(d.prefix.address);
                // Skip link-local just in case VPP includes it.
                if d.prefix.address[0] == 0xfe && (d.prefix.address[1] & 0xc0) == 0x80 {
                    continue;
                }
                out.global_prefixes.push((addr, d.prefix.len));
            }
        }
        Err(e) => {
            tracing::warn!(sw_if_index, "ip_address_dump failed: {}", e);
        }
    }

    out
}
