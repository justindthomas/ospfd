//! ospfd — OSPFv2 + OSPFv3 with direct VPP FIB programming.
//!
//! This daemon implements OSPFv2 (RFC 2328) + OSPFv3 (RFC 5340) and
//! programs routes via imp-ribd into VPP's FIB and the Linux kernel.
//!
//! As of the multi-instance refactor, ONE ospfd process owns every
//! VRF declared in the YAML — the default VRF plus each `ospf.vrfs[]`
//! / `ospf6.vrfs[]` entry. VPP's `punt_socket_register` is keyed
//! globally on (af, proto, port) with register-last-wins semantics, so
//! a per-VRF process model would silently lose punt RX for whichever
//! ospfd registered last. Single-process owns the punt registration
//! once and dispatches incoming packets by sw_if_index → owning
//! instance.
//!
//! Usage:
//!   ospfd --config /etc/ospfd/config.yaml
//!   ospfd query neighbors                    # query a running daemon
//!   ospfd query database --area 0.0.0.0
//!   ospfd query neighbors \
//!         --control-socket /run/ospfd@customer_vrf.sock

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, mpsc, Mutex};
use tracing_subscriber::EnvFilter;

use ospfd::config::{Ospf6DaemonConfig, OspfDaemonConfig};
use ospfd::control::{self, ControlRequest, ControlResponse, DEFAULT_CONTROL_SOCKET};
use ospfd::daemon_v3;
use ospfd::instance::OspfInstance;
use ospfd::instance_v3::{InstanceV3, NetworkTypeV3};
use ospfd::io::{InstanceIo, IoInterface, PuntInstanceIo, RawSocketIo, RxPacket, TxPacket};
use ospfd::io_punt::PuntSocketIo;
use ospfd::packet::auth::{apply_auth, verify_auth};
use ospfd::packet::{OspfPacket, ALL_SPF_ROUTERS};
use ospfd::proto::interface::{InterfaceEvent, InterfaceState};
use ospfd::rib_client::RibClient;

/// Top-level command: either run the daemon or issue a one-shot query.
enum Command {
    Run(RunArgs),
    Query(QueryArgs),
}

struct RunArgs {
    config_path: PathBuf,
    vpp_api_socket: String,
    /// Path of the lock-file sentinel and the default-VRF control
    /// socket. Per-VRF control sockets are derived from each
    /// instance's `cfg.vrf_name`.
    control_socket: String,
    io_backend: IoBackend,
    /// Deprecated. Pre-multi-instance ospfd accepted `--vrf X` to
    /// scope the daemon to a single VRF. The supervisor used to
    /// spawn one process per VRF; that's gone now — a single
    /// process owns every VRF. The flag is logged-and-ignored for
    /// one release so old systemd unit files don't fail to start
    /// during a rolling deploy.
    vrf_deprecated: Option<String>,
}

/// Which OSPF I/O backend to use. `Raw` opens AF_INET/SOCK_RAW sockets
/// bound to LCP TAP interfaces in the dataplane netns; `Punt` talks
/// directly to VPP via the punt-socket API. See `io.rs::Ospfv2Io` and
/// `io_punt.rs::PuntSocketIo` for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IoBackend {
    Raw,
    Punt,
}

struct QueryArgs {
    control_socket: String,
    request: ControlRequest,
    output: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

fn print_usage_and_exit(code: i32) -> ! {
    eprintln!("Usage:");
    eprintln!("  ospfd [--config PATH] [--vpp-api SOCKET] [--control-socket PATH] [--io raw|punt]");
    eprintln!("  ospfd query <status|neighbors|interfaces|database|routes> [options]");
    eprintln!();
    eprintln!("Query options:");
    eprintln!("  -o, --output <text|json>  output format (default: text)");
    eprintln!("  --area <ID>               filter by area ID (e.g., 0.0.0.0)");
    eprintln!("  --type <TYPE>             filter by LSA type");
    eprintln!("                              (router/network/summary/external)");
    eprintln!();
    eprintln!("  --vrf <NAME>              DEPRECATED — ignored. A single ospfd");
    eprintln!("                            process now owns every VRF declared");
    eprintln!("                            in the config.");
    std::process::exit(code);
}

fn parse_args() -> Command {
    let raw: Vec<String> = std::env::args().skip(1).collect();

    // Zero-arg invocation prints usage and exits. This used to silently
    // start a full daemon with default paths, which is a foot-gun — if
    // another ospfd is already running under systemd, the second
    // instance's remove_file/bind dance on the control and punt sockets
    // replaces the live paths with orphaned inodes, breaking both
    // query and punt RX until the live daemon is restarted.
    // systemd always passes explicit args, so this only affects
    // interactive invocations.
    if raw.is_empty() {
        print_usage_and_exit(1);
    }

    let mut args = raw.into_iter().peekable();

    // If the first positional argument is "query", parse as query command.
    if let Some(first) = args.peek() {
        if first == "query" {
            args.next();
            return Command::Query(parse_query_args(args));
        }
    }

    // Otherwise parse as run mode.
    let mut run = RunArgs {
        config_path: PathBuf::from("/etc/ospfd/config.yaml"),
        vpp_api_socket: vpp_api::client::DEFAULT_API_SOCKET.to_string(),
        control_socket: DEFAULT_CONTROL_SOCKET.to_string(),
        io_backend: IoBackend::Raw,
        vrf_deprecated: None,
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                run.config_path = PathBuf::from(args.next().expect("--config requires a path"));
            }
            "--vpp-api" => {
                run.vpp_api_socket = args.next().expect("--vpp-api requires a socket path");
            }
            "--control-socket" => {
                run.control_socket = args.next().expect("--control-socket requires a path");
            }
            "--vrf" => {
                run.vrf_deprecated = Some(args.next().expect("--vrf requires a name"));
            }
            "--io" => {
                let v = args.next().expect("--io requires 'raw' or 'punt'");
                run.io_backend = match v.as_str() {
                    "raw" => IoBackend::Raw,
                    "punt" => IoBackend::Punt,
                    other => {
                        eprintln!("Unknown --io value: {} (expected raw|punt)", other);
                        print_usage_and_exit(1);
                    }
                };
            }
            "--help" | "-h" => print_usage_and_exit(0),
            other => {
                eprintln!("Unknown argument: {}", other);
                print_usage_and_exit(1);
            }
        }
    }
    Command::Run(run)
}

fn parse_query_args<I: Iterator<Item = String>>(mut args: I) -> QueryArgs {
    let mut control_socket = DEFAULT_CONTROL_SOCKET.to_string();
    let subject = args.next().unwrap_or_else(|| {
        eprintln!("query requires a subject (status, neighbors, ...)");
        print_usage_and_exit(1);
    });

    let mut area: Option<String> = None;
    let mut ls_type: Option<String> = None;
    let mut output = OutputFormat::Text;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--control-socket" => {
                control_socket = args.next().expect("--control-socket requires a path");
            }
            "--area" => {
                area = Some(args.next().expect("--area requires a value"));
            }
            "--type" => {
                ls_type = Some(args.next().expect("--type requires a value"));
            }
            "-o" | "--output" => {
                let v = args.next().expect("-o/--output requires 'text' or 'json'");
                output = match v.as_str() {
                    "text" => OutputFormat::Text,
                    "json" => OutputFormat::Json,
                    other => {
                        eprintln!("Unknown output format: {} (expected text|json)", other);
                        print_usage_and_exit(1);
                    }
                };
            }
            other => {
                eprintln!("Unknown query argument: {}", other);
                print_usage_and_exit(1);
            }
        }
    }

    let request = match subject.as_str() {
        "status" => ControlRequest::Status,
        "neighbors" => ControlRequest::Neighbors,
        "interfaces" => ControlRequest::Interfaces,
        "database" => ControlRequest::Database { area, ls_type },
        "routes" => ControlRequest::Routes,
        "status6" => ControlRequest::Status6,
        "neighbors6" => ControlRequest::Neighbors6,
        "interfaces6" => ControlRequest::Interfaces6,
        "database6" => ControlRequest::Database6 { area, ls_type },
        "routes6" => ControlRequest::Routes6,
        other => {
            eprintln!("Unknown query subject: {}", other);
            print_usage_and_exit(1);
        }
    };

    QueryArgs {
        control_socket,
        request,
        output,
    }
}

/// Send a list of (sw_if_index, dst_addr, packet) responses via the I/O layer.
///
/// Needs a mutable instance reference to bump per-interface crypto sequence
/// numbers for MD5-authenticated packets.
fn send_responses(
    io: &InstanceIo,
    instance: &mut OspfInstance,
    responses: Vec<(u32, std::net::Ipv4Addr, OspfPacket)>,
) {
    for (sw_if_index, dst_addr, pkt) in responses {
        let raw = pkt.encode();
        let (src_addr, data) = {
            let Some(iface) = instance
                .interfaces
                .iter_mut()
                .find(|i| i.sw_if_index == sw_if_index)
            else {
                continue;
            };
            iface.crypto_seq = iface.crypto_seq.wrapping_add(1);
            let authed = apply_auth(raw, &iface.auth_key, iface.crypto_seq);
            (iface.address, authed)
        };
        let tx = TxPacket {
            sw_if_index,
            src_addr,
            dst_addr,
            data,
        };
        if let Err(e) = io.send(&tx) {
            tracing::warn!("send error: {}", e);
        }
    }
}

/// Acquire a single-instance advisory lock so a stray second
/// ospfd process can't clobber a running daemon's unix sockets.
///
/// The lock file lives at `<control_socket>.lock` and is held via
/// `flock(LOCK_EX | LOCK_NB)` — the kernel releases the lock when
/// the process exits, no cleanup needed. If another process holds
/// the lock we exit with a clear error instead of proceeding to
/// remove_file + bind the shared socket paths.
///
/// History: before this guard existed, running `ospfd` with no
/// args (e.g., to inspect the CLI interactively) would silently
/// launch a second daemon, whose `remove_file`/`bind` dance on
/// `/run/ospfd.sock` and `/run/ospfd/punt-v{4,6}.sock` would
/// unlink the live daemon's sockets and replace them with new
/// inodes. When the ad-hoc process died (Ctrl-C), the stale inodes
/// remained on disk, the live daemon was listening on orphaned fds,
/// and VPP was sending punted packets to a dead path. Reproduced
/// on jt-router 2026-04-15 and fixed by restarting ospfd.
/// This guard prevents the reoccurrence.
fn acquire_instance_lock(control_socket: &str) -> anyhow::Result<std::fs::File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let lock_path = format!("{}.lock", control_socket);
    // Best-effort parent dir create — matches what we do elsewhere.
    if let Some(parent) = std::path::Path::new(&lock_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o644)
        .open(&lock_path)
        .map_err(|e| anyhow::anyhow!("failed to open lock file {}: {}", lock_path, e))?;

    let fd = lock_file.as_raw_fd();
    // LOCK_EX | LOCK_NB: exclusive, fail immediately if held.
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            anyhow::bail!(
                "another ospfd instance is already running \
                 (lock file {} held). If you're trying to query state, \
                 use `ospfd query ...` instead.",
                lock_path,
            );
        }
        anyhow::bail!("flock({}): {}", lock_path, err);
    }

    // Write our pid into the lock file purely as a hint for humans.
    // The lock itself is the flock, not the file contents.
    use std::io::{Seek, SeekFrom, Write};
    let mut f = lock_file;
    f.seek(SeekFrom::Start(0)).ok();
    let _ = f.set_len(0);
    writeln!(&mut f, "{}", std::process::id()).ok();
    f.flush().ok();
    Ok(f)
}

/// Register an active-punt socket against VPP for IPv4 proto 89
/// (OSPF). Called by the `run_daemon` setup when `--io punt` is
/// selected. Returns the VPP-side server pathname, which is the
/// Unix socket we send TX packets to.
///
/// Requires that VPP was started with `punt { socket <path> }` in
/// startup.conf, otherwise register fails with retval = -1
/// ("socket is not configured").
async fn register_punt_v4(
    vpp: &vpp_api::VppClient,
    client_pathname: &str,
) -> anyhow::Result<String> {
    use vpp_api::generated::punt::{
        PuntSocketRegister, PuntSocketRegisterReply, PuntType,
    };
    let req = PuntSocketRegister {
        header_version: 1,
        punt_type: PuntType::IpProto,
        af: 0, // AF_IP4
        protocol: 89,
        port: 0, // unused for IP_PROTO
        pathname: client_pathname.to_string(),
    };
    let reply: PuntSocketRegisterReply = vpp
        .request::<PuntSocketRegister, PuntSocketRegisterReply>(req)
        .await
        .map_err(|e| anyhow::anyhow!("punt_socket_register: {}", e))?;
    if reply.retval != 0 {
        anyhow::bail!(
            "punt_socket_register for IPv4 proto 89 failed: retval={} \
             (is `punt {{ socket ... }}` set in startup.conf?)",
            reply.retval,
        );
    }
    let server = reply.pathname.trim_end_matches('\0').to_string();
    tracing::info!(
        client = client_pathname,
        server = server.as_str(),
        "registered punt socket for IPv4 proto 89"
    );
    Ok(server)
}

fn get_kernel_ifindex(name: &str) -> anyhow::Result<u32> {
    let path = format!("/sys/class/net/{}/ifindex", name);
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path, e))?;
    contents
        .trim()
        .parse::<u32>()
        .map_err(|e| anyhow::anyhow!("invalid ifindex in {}: {}", path, e))
}

/// Resolve the kernel ifindex for `name`, retrying for up to
/// `total_ms` milliseconds. LCP can take a second or two to
/// materialize the TAP for a freshly-created VPP interface — impd's
/// supervisor starts imp-ospfd right after VPP binds its API socket,
/// which often pre-dates that materialization.
fn resolve_kernel_ifindex(name: &str, total_ms: u64) -> anyhow::Result<u32> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(total_ms);
    let mut last_err: Option<anyhow::Error> = None;
    loop {
        match get_kernel_ifindex(name) {
            Ok(idx) => return Ok(idx),
            Err(e) => {
                last_err = Some(e);
                if std::time::Instant::now() >= deadline {
                    return Err(last_err.unwrap());
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
    }
}

/// Enumerate all IPv4 prefixes on VPP interfaces that are NOT
/// enrolled in OSPFv2. Used for `redistribute connected` — these are
/// the prefixes emitted as Type 5 AS-External-LSAs. The OSPF-enrolled
/// interfaces are advertised intra-area via Router-LSA stub links,
/// so they MUST be excluded here to avoid double-advertisement.
///
/// `table_id_v4` is the FIB table-id this ospfd instance owns
/// (0 for default-VRF, the VRF's `table_id_v4` for per-VRF
/// instances). Interfaces in OTHER tables are skipped — a
/// per-VRF ospfd must not redistribute connected routes that
/// live in someone else's VRF, otherwise the per-VRF FIB ends
/// up flooded with foreign prefixes. VPP exposes the per-iface
/// table via `sw_interface_get_table(sw_if_index, is_ipv6=false)`.
async fn discover_externals_v4(
    vpp: &vpp_api::VppClient,
    enrolled: &std::collections::HashSet<u32>,
    table_id_v4: u32,
) -> Vec<(std::net::Ipv4Addr, std::net::Ipv4Addr)> {
    use vpp_api::generated::interface::{
        SwInterfaceDetails, SwInterfaceDump, SwInterfaceGetTable, SwInterfaceGetTableReply,
    };
    use vpp_api::generated::ip::{IpAddressDetails, IpAddressDump};

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
        // VRF gate. Treat lookup failure as "stay out" — better
        // to omit a prefix than to leak a foreign one across
        // VRF boundaries.
        match vpp
            .request::<SwInterfaceGetTable, SwInterfaceGetTableReply>(SwInterfaceGetTable {
                sw_if_index: vi.sw_if_index,
                is_ipv6: false,
            })
            .await
        {
            Ok(reply) if reply.retval == 0 && reply.vrf_id == table_id_v4 => {}
            _ => continue,
        }
        let v4_addrs = vpp
            .dump::<IpAddressDump, IpAddressDetails>(IpAddressDump {
                sw_if_index: vi.sw_if_index,
                is_ipv6: false,
            })
            .await
            .unwrap_or_default();
        for d in v4_addrs {
            let prefix_len = d.prefix.len;
            let octets = [
                d.prefix.address[0],
                d.prefix.address[1],
                d.prefix.address[2],
                d.prefix.address[3],
            ];
            let addr = std::net::Ipv4Addr::from(octets);
            // Convert prefix length to a netmask, then derive the
            // network prefix (mask out host bits).
            let mask_bits: u32 = if prefix_len == 0 {
                0
            } else {
                (!0u32) << (32 - prefix_len)
            };
            let mask = std::net::Ipv4Addr::from(mask_bits.to_be_bytes());
            let net_octets = [
                addr.octets()[0] & mask.octets()[0],
                addr.octets()[1] & mask.octets()[1],
                addr.octets()[2] & mask.octets()[2],
                addr.octets()[3] & mask.octets()[3],
            ];
            out.push((std::net::Ipv4Addr::from(net_octets), mask));
        }
    }
    out
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    match parse_args() {
        Command::Run(args) => run_daemon(args).await,
        Command::Query(args) => run_query(args).await,
    }
}

/// Run a one-shot query against a live daemon.
async fn run_query(args: QueryArgs) -> anyhow::Result<()> {
    // No tracing subscriber for query mode — plain output only.
    let response = control::client_request(&args.control_socket, &args.request)
        .await
        .map_err(|e| anyhow::anyhow!("control request failed: {}", e))?;
    match args.output {
        OutputFormat::Text => print_response(&response),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
    }
    Ok(())
}

fn print_response(resp: &ControlResponse) {
    match resp {
        ControlResponse::Status(s) => {
            println!("Router ID:             {}", s.router_id);
            println!("ABR:                   {}", s.is_abr);
            println!("AS-External LSAs:      {}", s.as_external_lsa_count);
            println!("Installed routes:      {}", s.installed_route_count);
            println!();
            println!("Areas:");
            for area in &s.areas {
                println!(
                    "  {}  LSAs={:<4} ifaces={:<2} full_neighbors={}",
                    area.area_id,
                    area.lsa_count,
                    area.interface_count,
                    area.fully_adjacent_neighbors
                );
            }
            if !s.summary_addresses.is_empty() {
                println!();
                println!("Summary addresses:");
                for sa in &s.summary_addresses {
                    let na = if sa.no_advertise { " no-advertise" } else { "" };
                    println!(
                        "  {}  metric={} type={} tag={}{}",
                        sa.prefix, sa.metric, sa.metric_type, sa.tag, na
                    );
                }
            }
        }
        ControlResponse::Neighbors(n) => {
            if n.neighbors.is_empty() {
                println!("No neighbors.");
                return;
            }
            println!(
                "{:<16} {:<16} {:<10} {:<10} {:<4} {:<16} {:<16} {}",
                "Router ID", "Address", "Interface", "State", "Pri", "DR", "BDR", "Dead"
            );
            for n in &n.neighbors {
                println!(
                    "{:<16} {:<16} {:<10} {:<10} {:<4} {:<16} {:<16} {}s",
                    n.router_id,
                    n.address,
                    n.interface,
                    n.state,
                    n.priority,
                    n.dr,
                    n.bdr,
                    n.dead_seconds_remaining
                );
            }
        }
        ControlResponse::Interfaces(r) => {
            if r.interfaces.is_empty() {
                println!("No interfaces.");
                return;
            }
            println!(
                "{:<12} {:<16} {:<12} {:<14} {:<4} {:<3} {:<5} {}",
                "Name", "Address", "Area", "State", "Cost", "Pri", "Hello", "Neighbors"
            );
            for i in &r.interfaces {
                println!(
                    "{:<12} {:<16} {:<12} {:<14} {:<4} {:<3} {:<5} {}",
                    i.name,
                    format!("{}/{}", i.address, prefix_from_mask(&i.mask)),
                    i.area_id,
                    i.state,
                    i.cost,
                    i.priority,
                    i.hello_interval,
                    i.neighbor_count
                );
            }
        }
        ControlResponse::Database(d) => {
            if d.lsas.is_empty() {
                println!("LSDB is empty.");
                return;
            }
            println!(
                "{:<12} {:<16} {:<16} {:<16} {:<6} {:<12} {}",
                "Area", "Type", "Link State ID", "Adv Router", "Age", "Seq", "Len"
            );
            for l in &d.lsas {
                println!(
                    "{:<12} {:<16} {:<16} {:<16} {:<6} {:<#12x} {}{}",
                    l.area_id,
                    l.ls_type,
                    l.link_state_id,
                    l.advertising_router,
                    l.ls_age,
                    l.ls_sequence_number as u32,
                    l.length,
                    if l.self_originated { " (self)" } else { "" }
                );
            }
        }
        ControlResponse::Routes(r) => {
            if r.routes.is_empty() {
                println!("No OSPF routes installed.");
                return;
            }
            println!(
                "{:<20} {:<16} {:<6} {}",
                "Prefix", "Next Hop", "Cost", "sw_if_index"
            );
            for r in &r.routes {
                println!(
                    "{:<20} {:<16} {:<6} {}",
                    format!("{}/{}", r.prefix, r.prefix_len),
                    r.next_hop,
                    r.cost,
                    r.sw_if_index
                );
            }
        }
        // v3 responses reuse the v2 pretty-printers where the shape
        // matches; routes need their own (multipath, v6 addresses).
        ControlResponse::Status6(s) => print_response(&ControlResponse::Status(s.clone())),
        ControlResponse::Neighbors6(n) => {
            print_response(&ControlResponse::Neighbors(n.clone()))
        }
        ControlResponse::Interfaces6(i) => {
            print_response(&ControlResponse::Interfaces(i.clone()))
        }
        ControlResponse::Database6(d) => {
            print_response(&ControlResponse::Database(d.clone()))
        }
        ControlResponse::Routes6(r) => {
            if r.routes.is_empty() {
                println!("No OSPFv3 routes installed.");
                return;
            }
            println!("{:<40} {:<6} {}", "Prefix", "Cost", "Next Hops");
            for rt in &r.routes {
                let hops: Vec<String> = rt
                    .next_hops
                    .iter()
                    .map(|h| format!("{}%{}", h.address, h.sw_if_index))
                    .collect();
                println!(
                    "{:<40} {:<6} {}",
                    format!("{}/{}", rt.prefix, rt.prefix_len),
                    rt.cost,
                    hops.join(", ")
                );
            }
        }
        ControlResponse::Error { error } => {
            eprintln!("Error: {}", error);
            std::process::exit(1);
        }
    }
}

fn prefix_from_mask(mask: &str) -> u8 {
    if let Ok(addr) = mask.parse::<std::net::Ipv4Addr>() {
        u32::from(addr).count_ones() as u8
    } else {
        0
    }
}

/// Derive the per-instance control-socket path from its VRF name.
/// `None → /run/ospfd.sock`, `Some("customer_vrf") →
/// /run/ospfd@customer_vrf.sock`. Stable across releases — the
/// `imp-ospfd query` CLI and external tooling key on these paths.
fn control_socket_path(vrf_name: &Option<String>) -> String {
    match vrf_name {
        None => DEFAULT_CONTROL_SOCKET.to_string(),
        Some(v) => format!("/run/ospfd@{v}.sock"),
    }
}

/// Per-v2-instance setup carrying everything its event loop needs.
/// Built up-front during orchestration so the per-instance task can
/// just take ownership and run.
struct V2Setup {
    cfg: OspfDaemonConfig,
    instance: Arc<Mutex<OspfInstance>>,
    /// Interfaces this instance owns, after VPP-side resolution of
    /// sw_if_index / kernel_ifindex / address. The dispatcher uses
    /// the sw_if_index here to demux incoming packets to this
    /// instance.
    io_interfaces: Vec<IoInterface>,
}

/// Per-v2-instance event loop, lifted from the pre-multi-instance
/// monolithic `run_daemon`. Body is unchanged from the single-instance
/// shape — the only refactor is that I/O now flows through
/// `InstanceIo` (per-instance mpsc + shared punt-Tx clone, or a
/// per-instance `RawSocketIo`) rather than the single-process
/// `Ospfv2Io`.
async fn run_v2_instance(
    setup: V2Setup,
    mut io: InstanceIo,
    vpp: Arc<vpp_api::VppClient>,
    config_path: PathBuf,
    mut sighup_rx: broadcast::Receiver<()>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let V2Setup {
        cfg: config,
        instance,
        io_interfaces: _,
    } = setup;

    // Connect to ribd. Per-instance — each connection stamps its own
    // (table_id_v4, client_name=ospfd[@vrf]) so ribd can attribute
    // and replace per-instance route sets independently.
    let client_name = match &config.vrf_name {
        None => "ospfd".to_string(),
        Some(v) => format!("ospfd@{v}"),
    };
    let mut rib_client = RibClient::new("/run/ribd.sock", client_name)
        .with_table_ids(config.table_id_v4, 0);
    if let Err(e) = rib_client.connect(Duration::from_secs(10)).await {
        tracing::warn!(
            vrf = ?config.vrf_name,
            "ribd connect failed at startup: {} — will retry on next SPF",
            e,
        );
    }

    // Snapshot per-sub-type admin-distance overrides. Static for the
    // life of the daemon — reload_config doesn't currently change
    // these.
    let ad_intra = config.distance_intra.or(config.distance);
    let ad_inter = config.distance_inter.or(config.distance);
    let ad_ext = config.distance_external.or(config.distance);

    tracing::info!(
        vrf = ?config.vrf_name,
        table_id_v4 = config.table_id_v4,
        "OSPFv2 instance running",
    );

    let mut hello_tick = tokio::time::interval(Duration::from_secs(1));
    hello_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut neighbor_check = tokio::time::interval(Duration::from_secs(1));
    let mut lsdb_tick = tokio::time::interval(Duration::from_secs(30));
    lsdb_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Periodic VPP interface refresh — pick up address changes and
    // admin/link state transitions for OSPF interfaces. Polling cadence
    // chosen to be slow enough to be cheap and fast enough that adjacency
    // recovery after a flap is bounded by ~refresh + dead_interval.
    //
    // Start the first tick one period from now (interval_at), not
    // immediately. The default `interval()` ticks straight away, which
    // races VPP at startup: the initial resolution above just primed
    // every interface from VPP's IpAddressDump, but firing the refresh
    // microseconds later sometimes sees a transient empty dump (VPP
    // mid-operation) and demotes the interface back to Down — which
    // tears down everything the daemon just initialised, including the
    // InterfaceUp transition.
    let mut iface_refresh = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(30),
        Duration::from_secs(30),
    );
    iface_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Rate-limit for the "authentication failed" log: one warn per
    // (sw_if_index, src_addr) per minute so a misconfigured peer
    // sending Hellos every 10s doesn't flood the log.
    let mut last_auth_warn: HashMap<(u32, std::net::Ipv4Addr), Instant> = HashMap::new();

    loop {
        tokio::select! {
            Some(rx) = io.recv() => {
                let mut inst = instance.lock().await;

                // Verify authentication on the packet before processing.
                let auth_ok = inst
                    .interfaces
                    .iter()
                    .find(|i| i.sw_if_index == rx.sw_if_index)
                    .map(|i| verify_auth(&rx.data, &i.auth_key))
                    .unwrap_or(false);
                if !auth_ok {
                    let key = (rx.sw_if_index, rx.src_addr);
                    let now = Instant::now();
                    let should_warn = match last_auth_warn.get(&key) {
                        None => true,
                        Some(last) => {
                            now.duration_since(*last) >= Duration::from_secs(60)
                        }
                    };
                    if should_warn {
                        last_auth_warn.insert(key, now);
                        tracing::warn!(
                            sw_if_index = rx.sw_if_index,
                            src = %rx.src_addr,
                            "authentication failed, dropping packet (subsequent \
                             failures from this peer suppressed for 60s)"
                        );
                    } else {
                        tracing::debug!(
                            sw_if_index = rx.sw_if_index,
                            src = %rx.src_addr,
                            "authentication failed (suppressed)"
                        );
                    }
                    continue;
                }

                match OspfPacket::parse(&rx.data) {
                    Ok(packet) => {
                        tracing::debug!(
                            sw_if_index = rx.sw_if_index,
                            src = %rx.src_addr,
                            packet_type = ?packet.header().packet_type,
                            "received OSPF packet"
                        );
                        let responses = inst.process_packet(
                            rx.sw_if_index,
                            rx.src_addr,
                            &packet,
                        );
                        send_responses(&io, &mut inst, responses);
                    }
                    Err(e) => {
                        tracing::debug!("invalid OSPF packet from {}: {}", rx.src_addr, e);
                    }
                }
            }

            _ = hello_tick.tick() => {
                let mut inst = instance.lock().await;
                let now = Instant::now();
                let mut hellos_to_send = Vec::new();

                for (idx, iface) in inst.interfaces.iter().enumerate() {
                    if iface.state == InterfaceState::Down {
                        continue;
                    }
                    if now >= iface.next_hello {
                        let pkt = inst.build_hello(iface);
                        let data = pkt.encode();
                        // NBMA: unicast a copy to each statically-
                        // configured neighbor. Broadcast / P2P:
                        // single multicast send.
                        let destinations: Vec<Ipv4Addr> = if matches!(
                            iface.network_type,
                            ospfd::proto::interface::NetworkType::NonBroadcast
                        ) {
                            iface.static_neighbors.iter().map(|n| n.address).collect()
                        } else {
                            vec![ALL_SPF_ROUTERS]
                        };
                        hellos_to_send.push((
                            idx,
                            iface.sw_if_index,
                            iface.address,
                            data,
                            destinations,
                        ));
                    }
                }

                for (idx, sw_if_index, src_addr, raw, destinations) in hellos_to_send {
                    let iface_mut = &mut inst.interfaces[idx];
                    iface_mut.crypto_seq = iface_mut.crypto_seq.wrapping_add(1);
                    let data = apply_auth(raw, &iface_mut.auth_key, iface_mut.crypto_seq);

                    for dst in destinations {
                        let tx = TxPacket {
                            sw_if_index,
                            src_addr,
                            dst_addr: dst,
                            data: data.clone(),
                        };
                        if let Err(e) = io.send(&tx) {
                            tracing::warn!(
                                iface = %inst.interfaces[idx].name,
                                dst = %dst,
                                "hello send error: {}", e
                            );
                        }
                    }
                    let dur = inst.interfaces[idx].hello_duration();
                    inst.interfaces[idx].next_hello = now + dur;
                }

                let wait_due: Vec<usize> = inst.interfaces
                    .iter()
                    .enumerate()
                    .filter(|(_, iface)| {
                        matches!(iface.wait_timer_expiry, Some(expiry) if now >= expiry)
                    })
                    .map(|(i, _)| i)
                    .collect();

                for idx in wait_due {
                    inst.interfaces[idx].handle_event(&InterfaceEvent::WaitTimer);
                }

                let pending_dds = inst.emit_pending_dds();
                send_responses(&io, &mut inst, pending_dds);
            }

            _ = neighbor_check.tick() => {
                let mut inst = instance.lock().await;
                if inst.check_neighbor_timers() {
                    inst.originate_router_lsa();
                    inst.schedule_spf();
                }
            }

            _ = lsdb_tick.tick() => {
                let mut inst = instance.lock().await;
                let mut responses = Vec::new();
                if inst.periodic_maintenance(&mut responses) {
                    inst.schedule_spf();
                }
                send_responses(&io, &mut inst, responses);
            }

            _ = iface_refresh.tick() => {
                let sw_if_indices: Vec<u32> = {
                    let inst = instance.lock().await;
                    inst.interfaces
                        .iter()
                        .filter(|i| i.sw_if_index != 0)
                        .map(|i| i.sw_if_index)
                        .collect()
                };
                let vpp_ifaces = vpp
                    .dump::<
                        vpp_api::generated::interface::SwInterfaceDump,
                        vpp_api::generated::interface::SwInterfaceDetails,
                    >(vpp_api::generated::interface::SwInterfaceDump::default())
                    .await
                    .unwrap_or_default();
                let mut snapshots = Vec::new();
                for sw_if_index in sw_if_indices {
                    let oper_up = vpp_ifaces
                        .iter()
                        .find(|vi| vi.sw_if_index == sw_if_index)
                        .map(|vi| vi.flags.is_admin_up() && vi.flags.is_link_up())
                        .unwrap_or(false);
                    let v4 = vpp
                        .dump::<
                            vpp_api::generated::ip::IpAddressDump,
                            vpp_api::generated::ip::IpAddressDetails,
                        >(vpp_api::generated::ip::IpAddressDump {
                            sw_if_index,
                            is_ipv6: false,
                        })
                        .await
                        .unwrap_or_default();
                    if let Some(d) = v4.first() {
                        let octets = [
                            d.prefix.address[0],
                            d.prefix.address[1],
                            d.prefix.address[2],
                            d.prefix.address[3],
                        ];
                        let addr = std::net::Ipv4Addr::from(octets);
                        let mask_bits: u32 = if d.prefix.len == 0 {
                            0
                        } else {
                            u32::MAX << (32 - d.prefix.len as u32)
                        };
                        let mask = std::net::Ipv4Addr::from(mask_bits);
                        snapshots.push((sw_if_index, addr, mask, oper_up));
                    } else {
                        snapshots.push((
                            sw_if_index,
                            std::net::Ipv4Addr::UNSPECIFIED,
                            std::net::Ipv4Addr::UNSPECIFIED,
                            false,
                        ));
                    }
                }
                let mut inst = instance.lock().await;
                let mut any_change = false;
                for (sw_if_index, addr, mask, oper_up) in snapshots {
                    if inst.refresh_interface_state(sw_if_index, addr, mask, oper_up) {
                        any_change = true;
                    }
                }
                if any_change {
                    inst.originate_router_lsa();
                    inst.schedule_spf();
                }
            }

            _ = async {
                let due = instance.lock().await.spf_due();
                if let Some(due) = due {
                    tokio::time::sleep_until(due.into()).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                let routes = {
                    let mut inst = instance.lock().await;
                    let routes = inst.run_spf();
                    let (added, deleted) = inst.rib.apply_routes(&routes);
                    if added > 0 || deleted > 0 {
                        tracing::info!(
                            vrf = ?config.vrf_name,
                            added,
                            deleted,
                            total = inst.rib.route_count(),
                            "SPF cache updated"
                        );
                    }
                    routes
                };
                if let Err(e) = rib_client
                    .push_v4(&routes, |kind| {
                        use ospfd::proto::spf::OspfRouteKind;
                        match kind {
                            OspfRouteKind::Intra => ad_intra,
                            OspfRouteKind::Inter => ad_inter,
                            OspfRouteKind::External1 | OspfRouteKind::External2 => ad_ext,
                        }
                    })
                    .await
                {
                    tracing::warn!(vrf = ?config.vrf_name, "ribd push_v4 failed: {}", e);
                }
            }

            r = sighup_rx.recv() => {
                if r.is_err() {
                    // Sender dropped — process is shutting down. Treat
                    // identically to a Ctrl-C arm: withdraw and exit.
                    break;
                }
                tracing::info!(
                    path = %config_path.display(),
                    vrf = ?config.vrf_name,
                    "SIGHUP: reloading config",
                );
                // Per-instance reload: re-read the VRF's slice of the
                // config and apply via reload_config. New VRFs added to
                // YAML on SIGHUP are NOT picked up by an existing
                // process (Q2 in MULTI_INSTANCE.md) — that requires a
                // daemon restart, which impd's supervisor will do on
                // the apply path.
                let reloaded = match &config.vrf_name {
                    None => OspfDaemonConfig::load(&config_path),
                    Some(name) => OspfDaemonConfig::load_for_vrf(&config_path, name),
                };
                match reloaded {
                    Ok(new_config) => {
                        let mut inst = instance.lock().await;
                        let changed = inst.reload_config(&new_config);
                        if changed {
                            tracing::info!(vrf = ?config.vrf_name, "reload applied");
                        } else {
                            tracing::info!(
                                vrf = ?config.vrf_name,
                                "reload: no effective changes",
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            vrf = ?config.vrf_name,
                            error = %e,
                            "reload failed; keeping prior config live",
                        );
                    }
                }
            }

            _ = shutdown_rx.recv() => {
                tracing::info!(vrf = ?config.vrf_name, "instance shutting down");
                break;
            }
        }
    }

    // Withdraw our routes from ribd before exiting so the FIB
    // doesn't carry stale OSPF entries from this instance.
    if let Err(e) = rib_client.withdraw_v4().await {
        tracing::warn!(
            vrf = ?config.vrf_name,
            "ribd shutdown withdraw failed: {}", e,
        );
    }
    let mut inst = instance.lock().await;
    inst.rib.clear();
    tracing::info!(vrf = ?config.vrf_name, "OSPF routes withdrawn from ribd");
    Ok(())
}

/// Build a V2Setup for one instance: resolve every enrolled interface
/// against the live VPP, override addresses from VPP's view, originate
/// initial LSAs, and schedule SPF. Returns the populated setup ready
/// for run_v2_instance.
async fn build_v2_setup(
    vpp: &vpp_api::VppClient,
    vpp_interfaces: &[vpp_api::generated::interface::SwInterfaceDetails],
    config: OspfDaemonConfig,
    io_backend: IoBackend,
) -> anyhow::Result<V2Setup> {
    tracing::info!(
        vrf = ?config.vrf_name,
        table_id_v4 = config.table_id_v4,
        router_id = %config.router_id,
        interfaces = config.interfaces.len(),
        "OSPFv2 configuration loaded",
    );

    let mut instance = OspfInstance::new(&config);

    let mut io_interfaces = Vec::new();
    for iface in &mut instance.interfaces {
        let vpp_iface = vpp_interfaces
            .iter()
            .find(|vi| vi.interface_name == iface.name);
        let Some(vpp_iface) = vpp_iface else {
            tracing::warn!(name = %iface.name, vrf = ?config.vrf_name, "interface not found in VPP, skipping");
            continue;
        };
        iface.sw_if_index = vpp_iface.sw_if_index;

        // VPP is authoritative for interface addresses.
        let v4_addrs = vpp
            .dump::<
                vpp_api::generated::ip::IpAddressDump,
                vpp_api::generated::ip::IpAddressDetails,
            >(vpp_api::generated::ip::IpAddressDump {
                sw_if_index: vpp_iface.sw_if_index,
                is_ipv6: false,
            })
            .await
            .unwrap_or_default();
        if let Some(d) = v4_addrs.first() {
            let octets = [
                d.prefix.address[0],
                d.prefix.address[1],
                d.prefix.address[2],
                d.prefix.address[3],
            ];
            let vpp_addr = std::net::Ipv4Addr::from(octets);
            let vpp_prefix = d.prefix.len;
            let mask_bits: u32 = if vpp_prefix == 0 {
                0
            } else {
                u32::MAX << (32 - vpp_prefix as u32)
            };
            let vpp_mask = std::net::Ipv4Addr::from(mask_bits);
            if vpp_addr != iface.address || vpp_mask != iface.mask {
                tracing::info!(
                    name = %iface.name,
                    vrf = ?config.vrf_name,
                    yaml_addr = %iface.address,
                    yaml_mask = %iface.mask,
                    vpp_addr = %vpp_addr,
                    vpp_prefix = vpp_prefix,
                    "OSPFv2: overriding YAML address with VPP-configured address"
                );
            }
            iface.address = vpp_addr;
            iface.mask = vpp_mask;
        } else {
            tracing::warn!(
                name = %iface.name,
                vrf = ?config.vrf_name,
                yaml_addr = %iface.address,
                "OSPFv2: VPP has no IPv4 address on this interface, using YAML value",
            );
        }

        let kernel_ifindex = match io_backend {
            IoBackend::Raw => match resolve_kernel_ifindex(&iface.name, 6000) {
                Ok(idx) => idx,
                Err(e) => {
                    tracing::warn!(
                        name = %iface.name,
                        vrf = ?config.vrf_name,
                        "raw backend: no LCP TAP after retries, skipping: {}", e,
                    );
                    continue;
                }
            },
            IoBackend::Punt => {
                get_kernel_ifindex(&iface.name).unwrap_or(0)
            }
        };

        tracing::info!(
            name = %iface.name,
            vrf = ?config.vrf_name,
            sw_if_index = iface.sw_if_index,
            kernel_ifindex,
            address = %iface.address,
            "resolved interface",
        );

        io_interfaces.push(IoInterface {
            name: iface.name.clone(),
            sw_if_index: iface.sw_if_index,
            kernel_ifindex,
            address: iface.address,
            mac_address: vpp_iface.l2_address,
        });
    }

    for iface in &mut instance.interfaces {
        if iface.sw_if_index != 0 {
            iface.handle_event(&InterfaceEvent::InterfaceUp);
        }
    }

    instance.originate_router_lsas();

    let redistribute = instance.redistribute.clone();
    let externals = if redistribute.is_empty() {
        Vec::new()
    } else {
        let enrolled: std::collections::HashSet<u32> = instance
            .interfaces
            .iter()
            .map(|i| i.sw_if_index)
            .filter(|s| *s != 0)
            .collect();
        discover_externals_v4(vpp, &enrolled, config.table_id_v4).await
    };
    let ext_lsas = instance.originate_external_lsas(
        &redistribute,
        &externals,
        &config.summary_addresses,
    );
    if !ext_lsas.is_empty() {
        tracing::info!(
            vrf = ?config.vrf_name,
            count = ext_lsas.len(),
            "originated AS-external LSAs from redistribution",
        );
    }

    if !config.summary_addresses.is_empty() {
        let summary_lsas = instance.originate_summary_address_lsas(&config.summary_addresses.clone());
        if !summary_lsas.is_empty() {
            tracing::info!(
                vrf = ?config.vrf_name,
                count = summary_lsas.len(),
                "originated summary-address Type 5 LSAs",
            );
        }
    }

    if config.default_originate {
        if instance
            .originate_default_route_lsa(
                config.default_originate_metric,
                config.default_originate_metric_type,
            )
            .is_some()
        {
            tracing::info!(
                vrf = ?config.vrf_name,
                metric = config.default_originate_metric,
                metric_type = config.default_originate_metric_type,
                "originated default-route Type 5 LSA",
            );
        }
    }

    instance.schedule_spf();

    Ok(V2Setup {
        cfg: config,
        instance: Arc::new(Mutex::new(instance)),
        io_interfaces,
    })
}

/// Demux incoming v4 punt packets to the owning instance's mpsc by
/// sw_if_index. Spawned as a single tokio task per process when the
/// punt backend is in use; raw mode runs without it (each instance
/// owns its own per-iface raw sockets).
///
/// Packets whose sw_if_index is unknown — typically a transient race
/// where VPP delivers a frame milliseconds before the daemon's
/// interface map covers it — are dropped silently. The previous
/// per-instance code logged them at debug; preserving that here
/// would amplify the noise across N instances, so the demux drops
/// quietly.
async fn v4_dispatcher(
    mut rx: ospfd::io_punt::PuntSocketRx,
    iface_to_idx: HashMap<u32, usize>,
    senders: Vec<mpsc::Sender<RxPacket>>,
) {
    while let Some(pkt) = rx.recv().await {
        dispatch_one(&iface_to_idx, &senders, pkt).await;
    }
}

/// One-packet step of the v4 dispatcher; factored out for unit
/// testing. Returns the index the packet was forwarded to (if any),
/// for diagnostics.
async fn dispatch_one(
    iface_to_idx: &HashMap<u32, usize>,
    senders: &[mpsc::Sender<RxPacket>],
    pkt: RxPacket,
) -> Option<usize> {
    let idx = *iface_to_idx.get(&pkt.sw_if_index)?;
    if senders[idx].send(pkt).await.is_err() {
        // Receiver dropped (instance task exited). Leave the
        // mapping in place — keeping it here means the dispatcher
        // continues serving the other instances; only this VRF's
        // packets get black-holed, which matches what would happen
        // if its rx channel filled up.
        return None;
    }
    Some(idx)
}

async fn run_daemon(args: RunArgs) -> anyhow::Result<()> {
    // Filter precedence:
    //   1. RUST_LOG (if set) — operator override.
    //   2. Fallback: `ospfd=info` so the journal shows hello /
    //      neighbor / SPF lifecycle without drowning in tokio.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("ospfd=info"));
    tracing_subscriber::fmt()
        .with_ansi(std::env::var_os("NO_COLOR").is_none())
        .with_env_filter(filter)
        .init();

    if let Some(name) = &args.vrf_deprecated {
        tracing::warn!(
            arg = %name,
            "--vrf is deprecated and ignored — a single ospfd process now \
             owns every VRF declared in the config",
        );
    }

    // Process-wide lock so a stray second ospfd process can't
    // clobber our control / punt socket bindings. Anchored on
    // args.control_socket (default /run/ospfd.sock) — that's the
    // global "this ospfd process" sentinel even when N per-VRF
    // control sockets coexist beneath it.
    let _instance_lock = acquire_instance_lock(&args.control_socket)?;

    tracing::info!(
        config = %args.config_path.display(),
        "loading configuration",
    );
    let v2_configs = OspfDaemonConfig::load_all(&args.config_path)?;
    let mut v3_configs_all = Ospf6DaemonConfig::load_all(&args.config_path)?;
    if v2_configs.is_empty() && v3_configs_all.is_empty() {
        anyhow::bail!(
            "no OSPF instances configured (neither ospf nor ospf6 enabled)"
        );
    }
    if v3_configs_all.len() > 1 {
        let dropped: Vec<Option<String>> = v3_configs_all[1..]
            .iter()
            .map(|c| c.vrf_name.clone())
            .collect();
        tracing::warn!(
            kept = ?v3_configs_all[0].vrf_name,
            dropped = ?dropped,
            "OSPFv3 multi-instance not yet implemented — running first \
             ospf6 config only; other v3 VRFs are skipped until the v3 \
             dispatcher lands",
        );
        v3_configs_all.truncate(1);
    }
    let v3_config_first = v3_configs_all.into_iter().next();

    tracing::info!(
        socket = %args.vpp_api_socket,
        v2_instances = v2_configs.len(),
        v3_instances = if v3_config_first.is_some() { 1 } else { 0 },
        "connecting to VPP",
    );
    let vpp_supervisor = vpp_api::VppSupervisor::spawn(args.vpp_api_socket.clone());
    let vpp = vpp_supervisor.wait_ready().await;
    tracing::info!(client_index = vpp.client_index(), "connected to VPP");

    {
        let mut lifecycle = vpp_supervisor.subscribe();
        tokio::spawn(async move {
            while let Ok(ev) = lifecycle.recv().await {
                if matches!(ev, vpp_api::VppLifecycle::Disconnected) {
                    tracing::error!("VPP connection lost — exiting so systemd restarts ospfd");
                    std::process::exit(1);
                }
            }
        });
    }

    // One shared interface dump for every instance to read against.
    let vpp_interfaces = vpp
        .dump::<
            vpp_api::generated::interface::SwInterfaceDump,
            vpp_api::generated::interface::SwInterfaceDetails,
        >(vpp_api::generated::interface::SwInterfaceDump::default())
        .await?;

    // Build a V2Setup for every v2 cfg. Failed setups (interface
    // resolution dies, VPP returns garbage, etc.) get logged but
    // don't kill the process — the other VRFs should still come
    // up. Empty-result is allowed; the v2 instance just sits idle.
    let mut v2_setups: Vec<V2Setup> = Vec::new();
    for cfg in v2_configs {
        let vrf = cfg.vrf_name.clone();
        match build_v2_setup(&vpp, &vpp_interfaces, cfg, args.io_backend).await {
            Ok(s) => v2_setups.push(s),
            Err(e) => {
                tracing::warn!(vrf = ?vrf, "v2 setup failed: {}", e);
            }
        }
    }

    if v2_setups.is_empty() && v3_config_first.is_none() {
        anyhow::bail!(
            "no OSPF instances came up — every v2 config failed validation \
             and v3 is not configured",
        );
    }

    // Allocate I/O for every v2 instance:
    //  * Raw mode: per-instance RawSocketIo (raw sockets are
    //    per-iface, so per-instance is the natural boundary).
    //  * Punt mode: a SHARED punt registration covering every
    //    instance's interfaces, fed by a dispatcher task that
    //    demuxes by sw_if_index → owning instance.
    let mut v2_ios: Vec<InstanceIo> = match args.io_backend {
        IoBackend::Raw => {
            let mut ios = Vec::with_capacity(v2_setups.len());
            for s in &v2_setups {
                ios.push(InstanceIo::Raw(RawSocketIo::new(s.io_interfaces.clone())?));
            }
            ios
        }
        IoBackend::Punt => {
            // Union the io_interfaces across every v2 setup.
            // sw_if_indices are globally unique within VPP so a
            // simple linear de-dup is fine.
            let mut all_ifaces: Vec<IoInterface> = Vec::new();
            for s in &v2_setups {
                for io in &s.io_interfaces {
                    if !all_ifaces.iter().any(|x| x.sw_if_index == io.sw_if_index) {
                        all_ifaces.push(io.clone());
                    }
                }
            }

            // Allocate per-instance mpsc pairs and the dispatcher
            // map up front, regardless of whether any interfaces
            // are actually enrolled — empty-iface instances still
            // need an InstanceIo to feed their event loop.
            let mut senders: Vec<mpsc::Sender<RxPacket>> = Vec::with_capacity(v2_setups.len());
            let mut receivers: Vec<mpsc::Receiver<RxPacket>> = Vec::with_capacity(v2_setups.len());
            for _ in &v2_setups {
                let (tx, rx) = mpsc::channel::<RxPacket>(256);
                senders.push(tx);
                receivers.push(rx);
            }
            let mut iface_to_idx: HashMap<u32, usize> = HashMap::new();
            for (idx, s) in v2_setups.iter().enumerate() {
                for io in &s.io_interfaces {
                    iface_to_idx.insert(io.sw_if_index, idx);
                }
            }

            if all_ifaces.is_empty() {
                // No instance enrolls any interface — skip the VPP
                // punt registration entirely (otherwise we'd
                // clobber a peer process's registration; VPP's
                // punt-socket map is keyed on (af, proto, port)
                // globally). All per-instance receivers will just
                // never receive anything; the daemon is idle but
                // running so its control sockets and ribd
                // bookkeeping still work.
                tracing::info!(
                    "no enrolled interfaces across any v2 VRF; \
                     skipping punt_socket_register",
                );
                let punt = PuntSocketIo::new_unregistered(Vec::new())?;
                let (_rx, tx) = punt.into_split();
                receivers
                    .into_iter()
                    .map(|rx_chan| InstanceIo::Punt(PuntInstanceIo {
                        rx: rx_chan,
                        tx: tx.clone(),
                    }))
                    .collect()
            } else {
                let _ = std::fs::create_dir_all("/run/ospfd");
                let client_path = "/run/ospfd/punt-v4.sock";
                let vpp_server_path = register_punt_v4(&vpp, client_path).await?;
                let punt = PuntSocketIo::new(all_ifaces, client_path, vpp_server_path)?;
                let (rx, tx) = punt.into_split();

                tokio::spawn(v4_dispatcher(rx, iface_to_idx, senders));

                receivers
                    .into_iter()
                    .map(|rx_chan| InstanceIo::Punt(PuntInstanceIo {
                        rx: rx_chan,
                        tx: tx.clone(),
                    }))
                    .collect()
            }
        }
    };

    // SIGHUP → broadcast to every per-instance task. broadcast::Sender
    // resends from the time of subscribe, so we subscribe BEFORE
    // spawning instance tasks below so no signal is missed.
    let (sighup_tx, _) = broadcast::channel::<()>(8);
    let (shutdown_tx, _) = broadcast::channel::<()>(8);

    {
        let tx = sighup_tx.clone();
        let mut sighup_signal = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::hangup(),
        )?;
        tokio::spawn(async move {
            while sighup_signal.recv().await.is_some() {
                let _ = tx.send(());
            }
        });
    }
    {
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = tx.send(());
        });
    }

    // Build the v3 instance handle, if a v3 config block exists. v3
    // remains single-instance for this refactor (multi-instance v3
    // is a follow-up — see MULTI_INSTANCE.md §6); whichever VRF
    // appears first in v3_configs is the one we run.
    let v3_handle: Option<(Option<String>, Arc<Mutex<InstanceV3>>)> =
        if let Some(v3_config) = v3_config_first {
            spawn_v3_instance(
                v3_config,
                &vpp_interfaces,
                args.io_backend,
                &args.vpp_api_socket,
                &mut sighup_tx.subscribe(),
            )
            .await
        } else {
            tracing::info!("OSPFv3: not enabled in config, skipping v3 daemon");
            None
        };

    // Spawn one control-server task per VRF, pairing v2 + v3
    // handles by VRF name. Unique paths per VRF preserve the
    // existing query CLI:
    //   imp-ospfd query --control-socket /run/ospfd.sock
    //   imp-ospfd query --control-socket /run/ospfd@<vrf>.sock
    {
        let mut by_vrf: BTreeMap<
            Option<String>,
            (Option<Arc<Mutex<OspfInstance>>>, Option<Arc<Mutex<InstanceV3>>>),
        > = BTreeMap::new();
        for s in &v2_setups {
            by_vrf.entry(s.cfg.vrf_name.clone()).or_default().0 = Some(s.instance.clone());
        }
        if let Some((vrf, h)) = &v3_handle {
            by_vrf.entry(vrf.clone()).or_default().1 = Some(h.clone());
        }
        for (vrf, (v2h, v3h)) in by_vrf {
            let path = control_socket_path(&vrf);
            // control::run_control_server requires a v2 handle. If a
            // VRF has only v3 (currently impossible — the v3 spawn
            // pairs to a v2 by VRF name — but defensive for the
            // future), skip the bind and warn.
            let Some(v2_inst) = v2h else {
                tracing::warn!(vrf = ?vrf, "v3-only VRF has no control socket");
                continue;
            };
            let v3_inst = v3h;
            tokio::spawn(async move {
                if let Err(e) = control::run_control_server(path.clone(), v2_inst, v3_inst).await {
                    tracing::error!(socket = %path, "control server error: {}", e);
                }
            });
        }
    }

    // Spawn one tokio task per v2 instance. Each task owns its slice
    // of state — instance, ribd connection, control loop — and
    // tickets back through the broadcast channels for SIGHUP / Ctrl-C.
    let mut tasks = Vec::with_capacity(v2_setups.len());
    let mut ios_iter = v2_ios.drain(..);
    for setup in v2_setups {
        let io = ios_iter.next().expect("io count must match setup count");
        let vpp_for_task = vpp.clone();
        let config_path = args.config_path.clone();
        let sighup_rx = sighup_tx.subscribe();
        let shutdown_rx = shutdown_tx.subscribe();
        let vrf = setup.cfg.vrf_name.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) =
                run_v2_instance(setup, io, vpp_for_task, config_path, sighup_rx, shutdown_rx)
                    .await
            {
                tracing::error!(vrf = ?vrf, "v2 instance task exited with error: {}", e);
            }
        }));
    }

    tracing::info!(
        instances = tasks.len(),
        "ospfd: all instance tasks spawned, entering supervision",
    );

    // Wait for all v2 tasks to complete. Ctrl-C broadcast triggers
    // each instance's shutdown branch, so this returns when every
    // instance has finished its withdraw.
    for t in tasks {
        let _ = t.await;
    }

    Ok(())
}

/// Build and spawn the OSPFv3 daemon for a single config block.
/// Returns `Some((vrf_name, Arc<Mutex<InstanceV3>>))` for control-
/// server pairing, or `None` if v3 has no enrolled interfaces.
async fn spawn_v3_instance(
    v3_config: Ospf6DaemonConfig,
    vpp_interfaces: &[vpp_api::generated::interface::SwInterfaceDetails],
    io_backend: IoBackend,
    vpp_api_socket: &str,
    _sighup_rx: &mut broadcast::Receiver<()>,
) -> Option<(Option<String>, Arc<Mutex<InstanceV3>>)> {
    let mut v3_ifaces = Vec::new();
    for ic in &v3_config.interfaces {
        let Some(vpp_iface) = vpp_interfaces
            .iter()
            .find(|vi| vi.interface_name == ic.name)
        else {
            tracing::warn!(name = %ic.name, "OSPFv3: interface not in VPP, skipping");
            continue;
        };
        let kernel_ifindex = match io_backend {
            IoBackend::Raw => match resolve_kernel_ifindex(&ic.name, 6000) {
                Ok(i) => i,
                Err(e) => {
                    tracing::warn!(
                        name = %ic.name,
                        "OSPFv3 raw: no kernel TAP after retries, skipping: {}", e,
                    );
                    continue;
                }
            },
            IoBackend::Punt => get_kernel_ifindex(&ic.name).unwrap_or(0),
        };
        let network_type = match ic.network_type.as_str() {
            "point-to-point" => NetworkTypeV3::PointToPoint,
            "non-broadcast" => NetworkTypeV3::NonBroadcast,
            "point-to-multipoint" => NetworkTypeV3::PointToMultipoint,
            _ => NetworkTypeV3::Broadcast,
        };
        v3_ifaces.push(daemon_v3::V3InterfaceConfig {
            name: ic.name.clone(),
            sw_if_index: vpp_iface.sw_if_index,
            kernel_ifindex,
            link_local: std::net::Ipv6Addr::UNSPECIFIED,
            global_prefixes: Vec::new(),
            area_id: ic.area_id,
            network_type,
            hello_interval: ic.hello_interval,
            dead_interval: ic.dead_interval as u16,
            retransmit_interval: ic.retransmit_interval,
            transmit_delay: ic.transmit_delay,
            priority: ic.priority,
            static_neighbors: ic.static_neighbors.clone(),
            mac_address: vpp_iface.l2_address,
        });
    }

    if v3_ifaces.is_empty() {
        tracing::info!("OSPFv3: no enrolled interfaces, not starting daemon");
        return None;
    }

    let areas = v3_config
        .areas
        .iter()
        .map(|a| {
            let at = match a.area_type {
                ospfd::config::AreaType::Normal => ospfd::area::AreaType::Normal,
                ospfd::config::AreaType::Stub => ospfd::area::AreaType::Stub,
                ospfd::config::AreaType::Nssa => ospfd::area::AreaType::Nssa,
            };
            (a.area_id, at)
        })
        .collect();
    let v3_cfg = daemon_v3::V3DaemonConfig {
        vrf_name: v3_config.vrf_name.clone(),
        table_id_v6: v3_config.table_id_v6,
        router_id: v3_config.router_id,
        interfaces: v3_ifaces,
        areas,
        redistribute: v3_config.redistribute.clone(),
        route_maps: v3_config.route_maps.clone(),
        distance: v3_config.distance,
        default_originate: v3_config.default_originate,
        default_originate_metric: v3_config.default_originate_metric,
        default_originate_metric_type: v3_config.default_originate_metric_type,
        summary_addresses: v3_config.summary_addresses.clone(),
        io_backend: match io_backend {
            IoBackend::Raw => daemon_v3::V3IoBackend::Raw,
            IoBackend::Punt => daemon_v3::V3IoBackend::Punt,
        },
    };
    let v3_inst = Arc::new(Mutex::new({
        let mut i = InstanceV3::new(v3_config.router_id);
        i.summary_addresses = v3_config.summary_addresses.clone();
        i
    }));
    let v3_inst_clone = v3_inst.clone();
    let v3_vpp_socket = vpp_api_socket.to_string();
    tokio::spawn(async move {
        let v3_super = vpp_api::VppSupervisor::spawn(v3_vpp_socket);
        let v3_vpp = v3_super.wait_ready().await;
        let owned = match Arc::try_unwrap(v3_vpp) {
            Ok(c) => c,
            Err(arc) => {
                tracing::warn!("v3: VppClient still shared, falling back to direct connect");
                drop(arc);
                match vpp_api::VppClient::connect(v3_super.socket_path()).await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("OSPFv3 VPP connect failed: {}", e);
                        return;
                    }
                }
            }
        };
        if let Err(e) = daemon_v3::run(v3_cfg, owned, v3_inst_clone).await {
            tracing::error!("OSPFv3 daemon exited: {}", e);
        }
    });

    Some((v3_config.vrf_name, v3_inst))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rx_pkt(sw_if_index: u32) -> RxPacket {
        RxPacket {
            sw_if_index,
            src_addr: Ipv4Addr::new(10, 0, 0, 1),
            dst_addr: Ipv4Addr::new(224, 0, 0, 5),
            data: vec![],
        }
    }

    #[tokio::test]
    async fn dispatch_routes_by_sw_if_index() {
        // Two instances: idx 0 owns sw_if_index 7, idx 1 owns 9.
        let (tx0, mut rx0) = mpsc::channel::<RxPacket>(8);
        let (tx1, mut rx1) = mpsc::channel::<RxPacket>(8);
        let senders = vec![tx0, tx1];
        let mut iface_to_idx = HashMap::new();
        iface_to_idx.insert(7u32, 0usize);
        iface_to_idx.insert(9u32, 1usize);

        // Packet for idx 0
        assert_eq!(
            dispatch_one(&iface_to_idx, &senders, rx_pkt(7)).await,
            Some(0),
        );
        // Packet for idx 1
        assert_eq!(
            dispatch_one(&iface_to_idx, &senders, rx_pkt(9)).await,
            Some(1),
        );
        // Packet on an unknown sw_if_index → dropped silently
        assert_eq!(
            dispatch_one(&iface_to_idx, &senders, rx_pkt(42)).await,
            None,
        );

        // Both instance receivers should have seen exactly the
        // packet meant for them.
        let p0 = rx0.try_recv().expect("idx 0 should have received its pkt");
        assert_eq!(p0.sw_if_index, 7);
        assert!(rx0.try_recv().is_err());

        let p1 = rx1.try_recv().expect("idx 1 should have received its pkt");
        assert_eq!(p1.sw_if_index, 9);
        assert!(rx1.try_recv().is_err());
    }

    #[tokio::test]
    async fn dispatch_when_receiver_dropped_returns_none() {
        // If the per-instance receiver has been dropped (its task
        // exited), dispatch_one returns None instead of panicking
        // — the dispatcher task keeps serving the other instances.
        let (tx0, rx0) = mpsc::channel::<RxPacket>(1);
        drop(rx0);
        let senders = vec![tx0];
        let mut iface_to_idx = HashMap::new();
        iface_to_idx.insert(7u32, 0usize);

        assert_eq!(
            dispatch_one(&iface_to_idx, &senders, rx_pkt(7)).await,
            None,
        );
    }
}
