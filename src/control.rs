//! Control socket for operational queries.
//!
//! Listens on a Unix domain socket (default `/run/ospfd.sock`) and
//! accepts line-delimited JSON requests. Each request is a JSON object
//! with a `command` field; each response is also a single JSON line.
//!
//! This is the IPC endpoint the `ospfd query` CLI (and any external
//! management plane) use to fetch OSPF state without touching the
//! daemon's event loop.
//!
//! Protocol:
//!   - Each connection is request/response
//!   - Request: one JSON line like `{"command": "neighbors"}`
//!   - Response: one JSON line with the query result or `{"error": "..."}`
//!
//! Supported commands:
//!   - `status` — router ID, areas, ABR/ASBR flags, LSA counts
//!   - `neighbors` — all neighbors with state, DR/BDR, dead timer
//!   - `interfaces` — all OSPF interfaces with state, DR/BDR, timers
//!   - `database` — LSDB dump (router/network/summary/external)
//!   - `routes` — currently installed OSPF routes

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::instance::OspfInstance;
use crate::instance_v3::{InstanceV3, NeighborStateV3};
use crate::packet::lsa::LsaType;
use crate::packet_v3::lsa::LsaV3Type;
use crate::proto::neighbor::NeighborState;

pub const DEFAULT_CONTROL_SOCKET: &str = "/run/ospfd.sock";

/// A control request from a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ControlRequest {
    Status,
    Neighbors,
    Interfaces,
    Database {
        #[serde(default)]
        area: Option<String>,
        #[serde(default)]
        ls_type: Option<String>,
    },
    Routes,
    // ---- OSPFv3 ----
    Status6,
    Neighbors6,
    Interfaces6,
    Database6 {
        #[serde(default)]
        area: Option<String>,
        #[serde(default)]
        ls_type: Option<String>,
    },
    Routes6,
}

/// A control response sent back to a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResponse {
    Status(StatusReply),
    Neighbors(NeighborsReply),
    Interfaces(InterfacesReply),
    Database(DatabaseReply),
    Routes(RoutesReply),
    // ---- OSPFv3 ----
    // v3 replies reuse the v2 reply shapes where the semantics match,
    // and use a dedicated type for routes (which carry IPv6 addresses
    // and support multipath via next_hops).
    Status6(StatusReply),
    Neighbors6(NeighborsReply),
    Interfaces6(InterfacesReply),
    Database6(DatabaseReply),
    Routes6(Routes6Reply),
    Error {
        error: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Routes6Reply {
    pub routes: Vec<Route6Status>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route6Status {
    pub prefix: String,
    pub prefix_len: u8,
    pub cost: u32,
    /// One entry per ECMP path.
    pub next_hops: Vec<Route6NextHop>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route6NextHop {
    pub address: String,
    pub sw_if_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReply {
    /// VRF this instance serves; None for the default VRF. Multi-
    /// instance ospfd can run several v2 instances at once, so the
    /// query CLI prints this as the first line of `query status`
    /// to identify which control socket the operator is talking
    /// to.
    #[serde(default)]
    pub vrf_name: Option<String>,
    pub router_id: String,
    pub areas: Vec<AreaStatus>,
    pub is_abr: bool,
    pub as_external_lsa_count: usize,
    pub installed_route_count: usize,
    #[serde(default)]
    pub summary_addresses: Vec<SummaryAddressStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryAddressStatus {
    pub prefix: String,
    pub no_advertise: bool,
    pub tag: u32,
    pub metric: u32,
    pub metric_type: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AreaStatus {
    pub area_id: String,
    pub lsa_count: usize,
    pub interface_count: usize,
    pub fully_adjacent_neighbors: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborsReply {
    pub neighbors: Vec<NeighborStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborStatus {
    pub router_id: String,
    pub address: String,
    pub interface: String,
    pub area_id: String,
    pub state: String,
    pub priority: u8,
    pub dr: String,
    pub bdr: String,
    pub dead_seconds_remaining: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfacesReply {
    pub interfaces: Vec<InterfaceStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStatus {
    pub name: String,
    pub sw_if_index: u32,
    pub address: String,
    pub mask: String,
    pub area_id: String,
    pub state: String,
    pub network_type: String,
    pub cost: u16,
    pub priority: u8,
    pub hello_interval: u16,
    pub dead_interval: u32,
    pub dr: String,
    pub bdr: String,
    pub neighbor_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseReply {
    pub lsas: Vec<LsaSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsaSummary {
    pub area_id: String,
    pub ls_type: String,
    pub link_state_id: String,
    pub advertising_router: String,
    pub ls_age: u16,
    pub ls_sequence_number: i32,
    pub length: u16,
    pub self_originated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutesReply {
    pub routes: Vec<RouteStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteStatus {
    pub prefix: String,
    pub prefix_len: u8,
    pub next_hop: String,
    pub sw_if_index: u32,
    pub cost: u32,
}

/// Run the control server. Listens on `socket_path` and handles
/// requests using shared references to the v2 and (optional) v3
/// OSPF instances.
///
/// This function runs forever; spawn it in a tokio task.
pub async fn run_control_server(
    socket_path: String,
    instance: Arc<Mutex<OspfInstance>>,
    instance_v3: Option<Arc<Mutex<InstanceV3>>>,
) -> std::io::Result<()> {
    // Remove any stale socket
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)?;

    // Allow the vpp group to read/write (like vpp does for its sockets).
    // Best-effort: ignore permission errors.
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660));

    tracing::info!(socket = %socket_path, "control server listening");

    loop {
        let (stream, _addr) = listener.accept().await?;
        let instance = instance.clone();
        let instance_v3 = instance_v3.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, instance, instance_v3).await {
                tracing::debug!("control client error: {}", e);
            }
        });
    }
}

/// Handle one control connection: read one request, write one response.
async fn handle_connection(
    stream: UnixStream,
    instance: Arc<Mutex<OspfInstance>>,
    instance_v3: Option<Arc<Mutex<InstanceV3>>>,
) -> std::io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<ControlRequest>(&line) {
            Ok(req) => {
                // v3 requests are dispatched separately so we don't
                // lock the v2 instance unnecessarily.
                if is_v3_request(&req) {
                    match &instance_v3 {
                        Some(v3) => {
                            let v3 = v3.lock().await;
                            handle_request_v3(&req, &v3)
                        }
                        None => ControlResponse::Error {
                            error: "OSPFv3 not enabled".to_string(),
                        },
                    }
                } else {
                    let inst = instance.lock().await;
                    handle_request(&req, &inst)
                }
            }
            Err(e) => ControlResponse::Error {
                error: format!("invalid request: {}", e),
            },
        };

        let json = serde_json::to_string(&response).unwrap_or_else(|e| {
            format!(r#"{{"type":"error","error":"encode failed: {}"}}"#, e)
        });
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }

    Ok(())
}

/// True if the request is a v3 query.
fn is_v3_request(req: &ControlRequest) -> bool {
    matches!(
        req,
        ControlRequest::Status6
            | ControlRequest::Neighbors6
            | ControlRequest::Interfaces6
            | ControlRequest::Database6 { .. }
            | ControlRequest::Routes6
    )
}

/// Dispatch a v2 request to the appropriate query handler.
pub fn handle_request(req: &ControlRequest, inst: &OspfInstance) -> ControlResponse {
    match req {
        ControlRequest::Status => ControlResponse::Status(collect_status(inst)),
        ControlRequest::Neighbors => ControlResponse::Neighbors(collect_neighbors(inst)),
        ControlRequest::Interfaces => ControlResponse::Interfaces(collect_interfaces(inst)),
        ControlRequest::Database { area, ls_type } => {
            ControlResponse::Database(collect_database(inst, area.as_deref(), ls_type.as_deref()))
        }
        ControlRequest::Routes => ControlResponse::Routes(collect_routes(inst)),
        // v3 requests are dispatched by the caller via is_v3_request.
        _ => ControlResponse::Error {
            error: "not a v2 request".to_string(),
        },
    }
}

/// Dispatch a v3 request to the v3 query handlers.
pub fn handle_request_v3(req: &ControlRequest, inst: &InstanceV3) -> ControlResponse {
    match req {
        ControlRequest::Status6 => ControlResponse::Status6(collect_status_v3(inst)),
        ControlRequest::Neighbors6 => ControlResponse::Neighbors6(collect_neighbors_v3(inst)),
        ControlRequest::Interfaces6 => {
            ControlResponse::Interfaces6(collect_interfaces_v3(inst))
        }
        ControlRequest::Database6 { area, ls_type } => ControlResponse::Database6(
            collect_database_v3(inst, area.as_deref(), ls_type.as_deref()),
        ),
        ControlRequest::Routes6 => ControlResponse::Routes6(collect_routes_v3(inst)),
        _ => ControlResponse::Error {
            error: "not a v3 request".to_string(),
        },
    }
}

fn collect_status(inst: &OspfInstance) -> StatusReply {
    let mut areas = Vec::new();
    for (area_id, area) in &inst.areas {
        let interface_count = inst
            .interfaces
            .iter()
            .filter(|i| i.area_id == *area_id)
            .count();
        let fully_adjacent = inst
            .interfaces
            .iter()
            .filter(|i| i.area_id == *area_id)
            .flat_map(|i| i.neighbors.values())
            .filter(|n| n.state == NeighborState::Full)
            .count();
        areas.push(AreaStatus {
            area_id: area_id.to_string(),
            lsa_count: area.lsdb.entries_count(),
            interface_count,
            fully_adjacent_neighbors: fully_adjacent,
        });
    }
    // Sort for stable output
    areas.sort_by(|a, b| a.area_id.cmp(&b.area_id));

    let summary_addresses = inst
        .summary_addresses
        .iter()
        .map(|s| SummaryAddressStatus {
            prefix: format!("{}/{}", s.prefix, s.prefix_len),
            no_advertise: s.no_advertise,
            tag: s.tag,
            metric: s.metric,
            metric_type: s.metric_type,
        })
        .collect();

    StatusReply {
        vrf_name: inst.vrf_name.clone(),
        router_id: inst.router_id.to_string(),
        areas,
        is_abr: inst.is_abr(),
        as_external_lsa_count: inst.as_external_lsdb.entries_count(),
        installed_route_count: inst.rib.route_count(),
        summary_addresses,
    }
}

fn collect_neighbors(inst: &OspfInstance) -> NeighborsReply {
    let now = std::time::Instant::now();
    let mut neighbors = Vec::new();

    for iface in &inst.interfaces {
        let dead = iface.dead_duration();
        for n in iface.neighbors.values() {
            let elapsed = now.saturating_duration_since(n.last_heard);
            let remaining = dead.saturating_sub(elapsed).as_secs();
            neighbors.push(NeighborStatus {
                router_id: n.router_id.to_string(),
                address: n.address.to_string(),
                interface: iface.name.clone(),
                area_id: iface.area_id.to_string(),
                state: n.state.to_string(),
                priority: n.priority,
                dr: n.dr.to_string(),
                bdr: n.bdr.to_string(),
                dead_seconds_remaining: remaining,
            });
        }
    }

    neighbors.sort_by(|a, b| a.router_id.cmp(&b.router_id));
    NeighborsReply { neighbors }
}

fn collect_interfaces(inst: &OspfInstance) -> InterfacesReply {
    let interfaces = inst
        .interfaces
        .iter()
        .map(|i| InterfaceStatus {
            name: i.name.clone(),
            sw_if_index: i.sw_if_index,
            address: i.address.to_string(),
            mask: i.mask.to_string(),
            area_id: i.area_id.to_string(),
            state: i.state.to_string(),
            network_type: format!("{:?}", i.network_type),
            cost: i.cost,
            priority: i.priority,
            hello_interval: i.hello_interval,
            dead_interval: i.dead_interval,
            dr: i.dr.to_string(),
            bdr: i.bdr.to_string(),
            neighbor_count: i.neighbors.len(),
        })
        .collect();
    InterfacesReply { interfaces }
}

fn collect_database(
    inst: &OspfInstance,
    area_filter: Option<&str>,
    type_filter: Option<&str>,
) -> DatabaseReply {
    let mut lsas = Vec::new();

    // Area LSDBs
    for (area_id, area) in &inst.areas {
        let area_str = area_id.to_string();
        if let Some(f) = area_filter {
            if f != area_str {
                continue;
            }
        }
        for (_, entry) in area.lsdb.all_entries() {
            if let Some(tf) = type_filter {
                if !matches_ls_type(&entry.lsa.header.ls_type, tf) {
                    continue;
                }
            }
            lsas.push(LsaSummary {
                area_id: area_str.clone(),
                ls_type: format!("{:?}", entry.lsa.header.ls_type),
                link_state_id: entry.lsa.header.link_state_id.to_string(),
                advertising_router: entry.lsa.header.advertising_router.to_string(),
                ls_age: entry.current_age(),
                ls_sequence_number: entry.lsa.header.ls_sequence_number,
                length: entry.lsa.header.length,
                self_originated: entry.self_originated,
            });
        }
    }

    // AS-wide LSDB (Type 5)
    if area_filter.is_none() || area_filter == Some("external") {
        for (_, entry) in inst.as_external_lsdb.all_entries() {
            if let Some(tf) = type_filter {
                if !matches_ls_type(&entry.lsa.header.ls_type, tf) {
                    continue;
                }
            }
            lsas.push(LsaSummary {
                area_id: "external".to_string(),
                ls_type: format!("{:?}", entry.lsa.header.ls_type),
                link_state_id: entry.lsa.header.link_state_id.to_string(),
                advertising_router: entry.lsa.header.advertising_router.to_string(),
                ls_age: entry.current_age(),
                ls_sequence_number: entry.lsa.header.ls_sequence_number,
                length: entry.lsa.header.length,
                self_originated: entry.self_originated,
            });
        }
    }

    // Stable ordering
    lsas.sort_by(|a, b| {
        a.area_id
            .cmp(&b.area_id)
            .then_with(|| a.ls_type.cmp(&b.ls_type))
            .then_with(|| a.link_state_id.cmp(&b.link_state_id))
            .then_with(|| a.advertising_router.cmp(&b.advertising_router))
    });

    DatabaseReply { lsas }
}

fn matches_ls_type(ls_type: &LsaType, filter: &str) -> bool {
    let want = match filter.to_lowercase().as_str() {
        "router" | "1" => LsaType::Router,
        "network" | "2" => LsaType::Network,
        "summary" | "summary-network" | "3" => LsaType::SummaryNetwork,
        "summary-asbr" | "4" => LsaType::SummaryAsbr,
        "external" | "as-external" | "5" => LsaType::AsExternal,
        _ => return false,
    };
    *ls_type == want
}

fn collect_routes(inst: &OspfInstance) -> RoutesReply {
    let routes = inst
        .rib
        .installed_routes()
        .into_iter()
        .map(|r| RouteStatus {
            prefix: r.prefix.to_string(),
            prefix_len: r.prefix_len,
            next_hop: r.next_hop.to_string(),
            sw_if_index: r.sw_if_index,
            cost: r.cost,
        })
        .collect();
    RoutesReply { routes }
}

// ------------------------------------------------------------------
// OSPFv3 query collectors. These run with the instance lock held, so
// they should be cheap and allocate-free where possible.
// ------------------------------------------------------------------

fn collect_status_v3(inst: &InstanceV3) -> StatusReply {
    // v3 keeps a single LSDB (not partitioned per area in our
    // implementation). For the StatusReply we bucket interfaces and
    // full-adjacent neighbors by area; the lsa_count is the total
    // LSDB size reported against every area seen.
    use std::collections::HashMap as Map;
    #[derive(Default)]
    struct Bucket {
        interfaces: usize,
        full_neighbors: usize,
    }
    let mut areas_map: Map<std::net::Ipv4Addr, Bucket> = Map::new();
    for iface in inst.interfaces.values() {
        let b = areas_map.entry(iface.area_id).or_default();
        b.interfaces += 1;
        b.full_neighbors += iface
            .neighbors
            .values()
            .filter(|n| n.state == NeighborStateV3::Full)
            .count();
    }
    let total_lsas = inst.lsdb.len();
    let mut areas: Vec<AreaStatus> = areas_map
        .into_iter()
        .map(|(area_id, b)| AreaStatus {
            area_id: area_id.to_string(),
            lsa_count: total_lsas,
            interface_count: b.interfaces,
            fully_adjacent_neighbors: b.full_neighbors,
        })
        .collect();
    areas.sort_by(|a, b| a.area_id.cmp(&b.area_id));

    let summary_addresses = inst
        .summary_addresses
        .iter()
        .map(|s| SummaryAddressStatus {
            prefix: format!("{}/{}", s.prefix, s.prefix_len),
            no_advertise: s.no_advertise,
            tag: s.tag,
            metric: s.metric,
            metric_type: s.metric_type,
        })
        .collect();

    StatusReply {
        vrf_name: inst.vrf_name.clone(),
        router_id: inst.router_id.to_string(),
        areas,
        is_abr: false, // v3 ABR not tracked today
        as_external_lsa_count: inst
            .lsdb
            .iter()
            .filter(|e| e.header.ls_type == LsaV3Type::AsExternal)
            .count(),
        // v3 RIB lives inside daemon_v3 and isn't visible via the
        // shared instance handle yet.
        installed_route_count: 0,
        summary_addresses,
    }
}

fn collect_neighbors_v3(inst: &InstanceV3) -> NeighborsReply {
    let now = std::time::Instant::now();
    let mut neighbors = Vec::new();
    for iface in inst.interfaces.values() {
        let dead = std::time::Duration::from_secs(iface.dead_interval as u64);
        for n in iface.neighbors.values() {
            let elapsed = now.saturating_duration_since(n.last_hello);
            let remaining = dead.saturating_sub(elapsed).as_secs();
            neighbors.push(NeighborStatus {
                router_id: n.router_id.to_string(),
                address: n.link_local.to_string(),
                interface: iface.io.name.clone(),
                area_id: iface.area_id.to_string(),
                state: format!("{:?}", n.state),
                priority: n.priority,
                dr: n.dr.to_string(),
                bdr: n.bdr.to_string(),
                dead_seconds_remaining: remaining,
            });
        }
    }
    neighbors.sort_by(|a, b| a.router_id.cmp(&b.router_id));
    NeighborsReply { neighbors }
}

fn collect_interfaces_v3(inst: &InstanceV3) -> InterfacesReply {
    let interfaces = inst
        .interfaces
        .values()
        .map(|i| InterfaceStatus {
            name: i.io.name.clone(),
            sw_if_index: i.io.sw_if_index,
            address: i.io.link_local.to_string(),
            mask: String::new(), // not meaningful for v3
            area_id: i.area_id.to_string(),
            state: format!("{:?}", i.state),
            network_type: format!("{:?}", i.network_type),
            cost: 10, // v3 interfaces don't carry per-iface cost yet
            priority: i.priority,
            hello_interval: i.hello_interval,
            dead_interval: i.dead_interval as u32,
            dr: i.dr.to_string(),
            bdr: i.bdr.to_string(),
            neighbor_count: i.neighbors.len(),
        })
        .collect();
    InterfacesReply { interfaces }
}

fn collect_database_v3(
    inst: &InstanceV3,
    area_filter: Option<&str>,
    type_filter: Option<&str>,
) -> DatabaseReply {
    let mut lsas = Vec::new();
    for entry in inst.lsdb.iter() {
        if let Some(tf) = type_filter {
            if !matches_ls_type_v3(&entry.header.ls_type, tf) {
                continue;
            }
        }
        // v3 doesn't partition the LSDB by area in this implementation,
        // so the area filter is only meaningful for the "external"
        // magic value which selects Type 5 LSAs.
        if let Some(af) = area_filter {
            match af {
                "external" => {
                    if entry.header.ls_type != LsaV3Type::AsExternal {
                        continue;
                    }
                }
                _ => {}
            }
        }
        lsas.push(LsaSummary {
            area_id: if entry.header.ls_type == LsaV3Type::AsExternal {
                "external".to_string()
            } else if entry.header.ls_type == LsaV3Type::Link {
                format!("link:{}", entry.header.link_state_id)
            } else {
                // v3 doesn't track per-LSA area membership, so we
                // report "0.0.0.0" as a placeholder unless we can
                // infer otherwise.
                "0.0.0.0".to_string()
            },
            ls_type: format!("{:?}", entry.header.ls_type),
            link_state_id: entry.header.link_state_id.to_string(),
            advertising_router: entry.header.advertising_router.to_string(),
            ls_age: entry.header.ls_age,
            ls_sequence_number: entry.header.ls_sequence_number,
            length: entry.header.length,
            self_originated: entry.header.advertising_router == inst.router_id,
        });
    }
    lsas.sort_by(|a, b| {
        a.ls_type
            .cmp(&b.ls_type)
            .then_with(|| a.link_state_id.cmp(&b.link_state_id))
            .then_with(|| a.advertising_router.cmp(&b.advertising_router))
    });
    DatabaseReply { lsas }
}

fn matches_ls_type_v3(ls_type: &LsaV3Type, filter: &str) -> bool {
    let want = match filter.to_lowercase().as_str() {
        "router" | "1" => LsaV3Type::Router,
        "network" | "2" => LsaV3Type::Network,
        "inter-area-prefix" | "inter-area" | "3" => LsaV3Type::InterAreaPrefix,
        "inter-area-router" | "4" => LsaV3Type::InterAreaRouter,
        "external" | "as-external" | "5" => LsaV3Type::AsExternal,
        "nssa" | "7" => LsaV3Type::Nssa,
        "link" | "8" => LsaV3Type::Link,
        "intra-area-prefix" | "9" => LsaV3Type::IntraAreaPrefix,
        _ => return false,
    };
    *ls_type == want
}

fn collect_routes_v3(inst: &InstanceV3) -> Routes6Reply {
    // Re-run v3 SPF on-demand against the current LSDB + neighbors.
    // The daemon caches the installed-set inside daemon_v3::run; we
    // don't share that, so this recomputes on every query. Cheap
    // enough for an operator-driven diagnostic.
    let neighbors = inst.spf_neighbors();
    let routes = crate::spf_v3::calculate_spf_v3(inst.router_id, &inst.lsdb, &neighbors);
    let out = routes
        .into_iter()
        .map(|r| Route6Status {
            prefix: r.prefix.to_string(),
            prefix_len: r.prefix_len,
            cost: r.cost,
            next_hops: r
                .next_hops
                .into_iter()
                .map(|(nh, swi)| Route6NextHop {
                    address: nh.to_string(),
                    sw_if_index: swi,
                })
                .collect(),
        })
        .collect();
    Routes6Reply { routes: out }
}

/// Connect to the control socket and send a single request, returning the
/// response. Used by `ospfd query ...` and by external clients.
pub async fn client_request(
    socket_path: &str,
    req: &ControlRequest,
) -> std::io::Result<ControlResponse> {
    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    let json = serde_json::to_string(req)
        .map_err(|e| std::io::Error::other(format!("encode: {}", e)))?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.shutdown().await?;

    if let Some(line) = lines.next_line().await? {
        serde_json::from_str::<ControlResponse>(&line)
            .map_err(|e| std::io::Error::other(format!("decode: {}", e)))
    } else {
        Err(std::io::Error::other("empty response"))
    }
}

