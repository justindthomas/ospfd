//! ospfd — OSPFv2 with direct VPP FIB programming.
//!
//! This daemon implements OSPFv2 (RFC 2328) and programs routes directly
//! into VPP's FIB via the binary API, bypassing the Linux kernel entirely.
//!
//! Usage:
//!   ospfd --config /etc/ospfd/config.yaml
//!   ospfd query neighbors                    # query a running daemon
//!   ospfd query database --area 0.0.0.0

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use ospfd::config::OspfDaemonConfig;
use ospfd::control::{self, ControlRequest, ControlResponse, DEFAULT_CONTROL_SOCKET};
use ospfd::daemon_v3;
use ospfd::instance::OspfInstance;
use ospfd::instance_v3::NetworkTypeV3;
use ospfd::io::{IoInterface, RawSocketIo, TxPacket};
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
    control_socket: String,
    io_backend: IoBackend,
    /// VRF name passed by the supervisor as `--vrf <name>`. None
    /// for the default-VRF instance (table 0); per-VRF instances
    /// (`imp-ospfd@<vrf>`) set Some so the daemon picks its slice
    /// and stamps its table-id on every Route push to ribd.
    vrf: Option<String>,
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
    eprintln!("  ospfd [--config PATH] [--vpp-api SOCKET] [--control-socket PATH] [--io raw|punt] [--vrf NAME]");
    eprintln!("  ospfd query <status|neighbors|interfaces|database|routes> [options]");
    eprintln!();
    eprintln!("Query options:");
    eprintln!("  -o, --output <text|json>  output format (default: text)");
    eprintln!("  --area <ID>               filter by area ID (e.g., 0.0.0.0)");
    eprintln!("  --type <TYPE>             filter by LSA type");
    eprintln!("                              (router/network/summary/external)");
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
        vrf: None,
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
                run.vrf = Some(args.next().expect("--vrf requires a name"));
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
    io: &ospfd::io::Ospfv2Io,
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

async fn run_daemon(args: RunArgs) -> anyhow::Result<()> {
    // Honour NO_COLOR — keeps ANSI escapes out of impd-captured
    // stderr → journald.
    // Filter precedence:
    //   1. RUST_LOG (if set) — operator override.
    //   2. Fallback: `ospfd=info` so the journal shows hello /
    //      neighbor / SPF lifecycle without drowning in tokio.
    // Earlier code chained `add_directive("ospfd=info")` *after*
    // `from_default_env()`, which made the hardcoded directive
    // win against any env override (later directives have higher
    // precedence in EnvFilter). That meant `RUST_LOG=ospfd=debug`
    // was silently downgraded to info — exactly the wrong shape
    // when impd's supervisor wants to bump verbosity for a
    // diagnostic run.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("ospfd=info"));
    tracing_subscriber::fmt()
        .with_ansi(std::env::var_os("NO_COLOR").is_none())
        .with_env_filter(filter)
        .init();

    // Acquire the single-instance lock BEFORE doing anything that
    // touches shared state (sockets, punt registration, etc.). If
    // another ospfd is already running against the same control
    // socket path, bail out with a clear error rather than clobber
    // its bound sockets.
    let _instance_lock = acquire_instance_lock(&args.control_socket)?;

    // Load configuration. Default-VRF instance: load(); per-VRF
    // instance (--vrf X): load_for_vrf(X). Either way the resulting
    // OspfDaemonConfig carries its own table_id_v4 + vrf_name which
    // get stamped on every Route push and used to filter interfaces.
    tracing::info!(
        config = %args.config_path.display(),
        vrf = ?args.vrf,
        "loading configuration",
    );
    let config = match &args.vrf {
        None => OspfDaemonConfig::load(&args.config_path)?,
        Some(name) => OspfDaemonConfig::load_for_vrf(&args.config_path, name)?,
    };
    tracing::info!(
        vrf = ?config.vrf_name,
        table_id_v4 = config.table_id_v4,
        router_id = %config.router_id,
        interfaces = config.interfaces.len(),
        "OSPF configuration loaded"
    );

    // Connect to VPP via the supervisor — survives VPP being slow to
    // come up at boot. After we have a live client we hand it off to
    // the rest of init (raw sockets / punt registrations are bound to
    // the current connection's sw_if_index values, so the simplest
    // robust recovery on VPP restart is to exit and let systemd
    // restart us — the lifecycle watcher below does that).
    tracing::info!(socket = %args.vpp_api_socket, "connecting to VPP");
    let vpp_supervisor = vpp_api::VppSupervisor::spawn(args.vpp_api_socket.clone());
    let vpp = vpp_supervisor.wait_ready().await;
    tracing::info!(client_index = vpp.client_index(), "connected to VPP");

    // Watch for VPP disconnects. On disconnect we log a clear
    // warning and exit — every component below this point holds
    // VPP-bound state (raw sockets per sw_if_index, punt
    // registrations, neighbor LSDB references to interfaces) that
    // would all need rebuilding from scratch. systemd's restart will
    // do that with one less moving piece than a hot rebuild.
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

    // Resolve interface sw_if_index values from VPP
    let vpp_interfaces = vpp
        .dump::<
            vpp_api::generated::interface::SwInterfaceDump,
            vpp_api::generated::interface::SwInterfaceDetails,
        >(vpp_api::generated::interface::SwInterfaceDump::default())
        .await?;

    // Create OSPF instance
    let mut instance = OspfInstance::new(&config);

    // Map interface names to VPP sw_if_index and kernel ifindex
    let mut io_interfaces = Vec::new();
    for iface in &mut instance.interfaces {
        let vpp_iface = vpp_interfaces
            .iter()
            .find(|vi| vi.interface_name == iface.name);
        let Some(vpp_iface) = vpp_iface else {
            tracing::warn!(name = %iface.name, "interface not found in VPP, skipping");
            continue;
        };
        iface.sw_if_index = vpp_iface.sw_if_index;

        // VPP is the source of truth for interface addresses. Query
        // ip_address_dump and override the YAML values with whatever
        // VPP has actually configured. The YAML address is treated as
        // a fallback hint (used only if VPP has nothing on this
        // interface, which usually means a misconfiguration).
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
            // Convert prefix length to a netmask.
            let mask_bits: u32 = if vpp_prefix == 0 {
                0
            } else {
                u32::MAX << (32 - vpp_prefix as u32)
            };
            let vpp_mask = std::net::Ipv4Addr::from(mask_bits);
            if vpp_addr != iface.address || vpp_mask != iface.mask {
                tracing::info!(
                    name = %iface.name,
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
                yaml_addr = %iface.address,
                "OSPFv2: VPP has no IPv4 address on this interface, using YAML value"
            );
        }

        // kernel_ifindex is only used by the raw backend (IP_ADD_MEMBERSHIP
        // + IP_MULTICAST_IF on the LCP TAP). The punt backend doesn't
        // need it — it sends via VPP's punt socket directly. FreeBSD
        // has no /sys/class/net at all, so future FreeBSD support must
        // rely on punt/VCL exclusively.
        //
        // For raw, retry the lookup with backoff: impd's supervisor
        // can start imp-ospfd the moment VPP binds its API socket,
        // which is often before LCP has materialized the TAPs in the
        // dataplane netns. Retrying for a few seconds rides out that
        // race cleanly.
        let kernel_ifindex = match args.io_backend {
            IoBackend::Raw => match resolve_kernel_ifindex(&iface.name, 6000) {
                Ok(idx) => idx,
                Err(e) => {
                    tracing::warn!(
                        name = %iface.name,
                        "raw backend: no LCP TAP after retries, skipping: {}", e
                    );
                    continue;
                }
            },
            IoBackend::Punt => {
                // Best-effort — log it if available for diagnostics,
                // but don't skip the interface on failure.
                get_kernel_ifindex(&iface.name).unwrap_or(0)
            }
        };

        tracing::info!(
            name = %iface.name,
            sw_if_index = iface.sw_if_index,
            kernel_ifindex,
            address = %iface.address,
            "resolved interface"
        );

        io_interfaces.push(IoInterface {
            name: iface.name.clone(),
            sw_if_index: iface.sw_if_index,
            kernel_ifindex,
            address: iface.address,
            mac_address: vpp_iface.l2_address,
        });
    }

    // Open the I/O backend. `args.io_backend` is set from the CLI
    // `--io raw|punt` flag, defaulting to `raw` for backwards
    // compatibility. The punt backend additionally issues a
    // `punt_socket_register` against VPP — see io_punt.rs for details.
    let mut io = match args.io_backend {
        IoBackend::Raw => ospfd::io::Ospfv2Io::Raw(RawSocketIo::new(io_interfaces)?),
        IoBackend::Punt => {
            // Per-VRF instances must use distinct socket paths.
            // VPP's `punt_socket_register` is keyed on (af, proto,
            // port) → socket_path; the second register for the same
            // tuple OVERWRITES the first inside VPP, so without
            // per-VRF paths the default-VRF instance silently loses
            // its punt RX the moment a customer_vrf instance starts.
            // The Unix-socket bind side has the same hazard:
            // `remove_file + bind` on a shared path orphans whoever
            // bound first.
            let client_path = match &args.vrf {
                None => "/run/ospfd/punt-v4.sock".to_string(),
                Some(name) => format!("/run/ospfd/punt-v4@{name}.sock"),
            };
            // Skip punt registration entirely when this instance has
            // zero enrolled interfaces. VPP's punt is keyed on
            // (af, proto, port) globally — register-last-wins — so a
            // dormant default-VRF instance with no interfaces would
            // silently clobber the per-VRF instance's registration
            // every time the supervisor respawned it. Stay running
            // (the daemon's other RPCs / control socket / RIB sync
            // are still useful) but don't touch VPP's punt path.
            // Re-register on the first interface that arrives via
            // a future config reload would be the proper followup;
            // for v1 the supervisor restart picks it up.
            if io_interfaces.is_empty() {
                tracing::info!(
                    "no enrolled interfaces; skipping punt_socket_register \
                     to avoid clobbering peer instances' registration"
                );
                ospfd::io::Ospfv2Io::Punt(ospfd::io_punt::PuntSocketIo::new_unregistered(
                    io_interfaces,
                )?)
            } else {
                // Ensure parent dir exists.
                let _ = std::fs::create_dir_all("/run/ospfd");
                let vpp_server_path = register_punt_v4(&vpp, &client_path).await?;
                ospfd::io::Ospfv2Io::Punt(
                    ospfd::io_punt::PuntSocketIo::new(
                        io_interfaces,
                        &client_path,
                        vpp_server_path,
                    )?,
                )
            }
        }
    };

    // Bring interfaces up
    for iface in &mut instance.interfaces {
        if iface.sw_if_index != 0 {
            iface.handle_event(&InterfaceEvent::InterfaceUp);
        }
    }

    // Originate initial Router-LSA(s) — one per area
    instance.originate_router_lsas();

    // Originate AS-External LSAs for redistributed routes. We
    // discover the externals as v4 prefixes on VPP interfaces that
    // are NOT already enrolled in OSPFv2 (those are advertised
    // intra-area via the Router-LSA stub-link path).
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
        discover_externals_v4(&vpp, &enrolled, config.table_id_v4).await
    };
    let ext_lsas =
        instance.originate_external_lsas(&redistribute, &externals, &config.summary_addresses);
    if !ext_lsas.is_empty() {
        tracing::info!(
            count = ext_lsas.len(),
            "originated AS-external LSAs from redistribution"
        );
    }

    // Summary-address aggregates: one Type 5 per configured
    // entry. Component prefixes that fall inside the aggregate are
    // still emitted as their own Type 5s — full exclusion is a
    // follow-up.
    if !config.summary_addresses.is_empty() {
        let summary_lsas =
            instance.originate_summary_address_lsas(&config.summary_addresses.clone());
        if !summary_lsas.is_empty() {
            tracing::info!(
                count = summary_lsas.len(),
                "originated summary-address Type 5 LSAs"
            );
        }
    }

    // Default-route origination: when ospf.default_originate is set,
    // the router advertises 0.0.0.0/0 as a Type 5 external so its
    // area peers see it as their gateway of last resort.
    if config.default_originate {
        if instance
            .originate_default_route_lsa(
                config.default_originate_metric,
                config.default_originate_metric_type,
            )
            .is_some()
        {
            tracing::info!(
                metric = config.default_originate_metric,
                metric_type = config.default_originate_metric_type,
                "originated default-route Type 5 LSA"
            );
        }
    }

    instance.schedule_spf();

    // Wrap in Arc<Mutex<>> for sharing with the control server task
    let instance = Arc::new(Mutex::new(instance));

    // Shared handle for the v3 instance. Populated when the v3
    // daemon is enabled; stays None otherwise so the control
    // server can tell v3 is disabled.
    let v3_handle: Option<Arc<Mutex<ospfd::instance_v3::InstanceV3>>>;

    // Spawn the OSPFv3 daemon task, driven by the dedicated `ospf6:`
    // config section. Only interfaces listed with an ospf6_area are
    // enrolled. If ospf6.enabled is false or missing, the v3 daemon
    // does not start.
    let v6_load = match &args.vrf {
        None => ospfd::config::Ospf6DaemonConfig::load(&args.config_path),
        Some(name) => ospfd::config::Ospf6DaemonConfig::load_for_vrf(&args.config_path, name),
    };
    match v6_load {
        Ok(Some(v3_config)) => {
            // Resolve sw_if_index / kernel_ifindex for each configured v3
            // interface against VPP. We re-use the already-fetched
            // vpp_interfaces dump from the v2 resolution above.
            let mut v3_ifaces = Vec::new();
            for ic in &v3_config.interfaces {
                let Some(vpp_iface) = vpp_interfaces
                    .iter()
                    .find(|vi| vi.interface_name == ic.name)
                else {
                    tracing::warn!(
                        name = %ic.name,
                        "OSPFv3: interface not in VPP, skipping"
                    );
                    continue;
                };
                let kernel_ifindex = match args.io_backend {
                    IoBackend::Raw => match resolve_kernel_ifindex(&ic.name, 6000) {
                        Ok(i) => i,
                        Err(e) => {
                            tracing::warn!(name = %ic.name,
                                "OSPFv3 raw: no kernel TAP after retries, skipping: {}", e);
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
                // link_local + global_prefixes are filled in by
                // daemon_v3::run() from VPP's ip_address_dump.
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
                tracing::info!(
                    "OSPFv3: no enrolled interfaces, not starting daemon"
                );
                v3_handle = None;
            } else {
                // Convert config::AreaType → area::AreaType for the daemon.
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
                    // Use the same backend as v2 — operators flip
                    // both sides with a single flag.
                    io_backend: match args.io_backend {
                        IoBackend::Raw => daemon_v3::V3IoBackend::Raw,
                        IoBackend::Punt => daemon_v3::V3IoBackend::Punt,
                    },
                };
                let v3_inst = Arc::new(Mutex::new({
                    let mut i = ospfd::instance_v3::InstanceV3::new(v3_config.router_id);
                    i.summary_addresses = v3_config.summary_addresses.clone();
                    i
                }));
                v3_handle = Some(v3_inst.clone());
                let v3_vpp_socket = args.vpp_api_socket.clone();
                tokio::spawn(async move {
                    // Dedicated VPP connection so v3 doesn't share
                    // request/reply context with the v2 client.
                    // Same supervisor pattern as v2 — wait for the
                    // first connection, then run. If this connection
                    // dies the v2 lifecycle watcher (which observes
                    // both processes share VPP) will exit() the
                    // daemon as a whole.
                    let v3_super = vpp_api::VppSupervisor::spawn(v3_vpp_socket);
                    let v3_vpp = v3_super.wait_ready().await;
                    // run() needs an owned VppClient; clone-out via
                    // Arc isn't sufficient. Reconnect under the v3
                    // path stays as exit-and-restart for now (the
                    // outer lifecycle watcher handles that).
                    let owned = match std::sync::Arc::try_unwrap(v3_vpp) {
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
                    if let Err(e) = daemon_v3::run(v3_cfg, owned, v3_inst).await {
                        tracing::error!("OSPFv3 daemon exited: {}", e);
                    }
                });
            }
        }
        Ok(None) => {
            tracing::info!("OSPFv3: not enabled in config, skipping v3 daemon");
            v3_handle = None;
        }
        Err(e) => {
            tracing::warn!("OSPFv3 config load failed: {} — not starting v3 daemon", e);
            v3_handle = None;
        }
    }
    // Spawn the control server now that both v2 and (optional) v3
    // handles are ready.
    {
        let ctrl_instance = instance.clone();
        let ctrl_v3 = v3_handle.clone();
        let ctrl_socket = args.control_socket.clone();
        tokio::spawn(async move {
            if let Err(e) =
                control::run_control_server(ctrl_socket, ctrl_instance, ctrl_v3).await
            {
                tracing::error!("control server error: {}", e);
            }
        });
    }

    // Connect to ribd so we can push routes instead of
    // programming VPP directly. We block here with a bounded retry
    // because OSPF routes don't matter if the RIB can't accept
    // them. If connect ultimately fails, continue anyway — SPF
    // still runs, the cache fills, and we'll retry on the next
    // successful push.
    let client_name = match &config.vrf_name {
        None => "ospfd".to_string(),
        Some(v) => format!("ospfd@{v}"),
    };
    let mut rib_client = RibClient::new("/run/ribd.sock", client_name)
        .with_table_ids(config.table_id_v4, 0);
    if let Err(e) = rib_client.connect(Duration::from_secs(10)).await {
        tracing::warn!("ribd connect failed at startup: {} — will retry on next SPF", e);
    }

    // Snapshot the per-sub-type admin-distance overrides. These
    // don't change at runtime without a daemon restart, so plain
    // Copy values keep the push-time closure self-contained.
    let ad_intra = config.distance_intra.or(config.distance);
    let ad_inter = config.distance_inter.or(config.distance);
    let ad_ext = config.distance_external.or(config.distance);

    tracing::info!("OSPF daemon running — entering main loop");

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
    // InterfaceUp transition. With the punt backend that race is
    // perfectly reproducible because PuntSocketIo::new + register_punt
    // adds enough VPP back-and-forth before the loop starts that VPP
    // is still busy when the first tick fires.
    let mut iface_refresh = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(30),
        Duration::from_secs(30),
    );
    iface_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // SIGHUP re-reads the config file and calls OspfInstance::reload_config
    // so external config changes take effect without bouncing
    // adjacencies. Unhandled SIGHUP would otherwise terminate the
    // process (kernel default) and force a cold cycle through systemd
    // Restart=always.
    let mut sighup = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::hangup(),
    )?;
    let config_path = args.config_path.clone();

    // Rate-limit for the "authentication failed" log: one warn per
    // (sw_if_index, src_addr) per minute so a misconfigured peer
    // sending Hellos every 10s doesn't flood the log.
    let mut last_auth_warn: std::collections::HashMap<(u32, std::net::Ipv4Addr), Instant> =
        std::collections::HashMap::new();

    loop {
        tokio::select! {
            Some(rx) = io.recv() => {
                let mut inst = instance.lock().await;

                // Verify authentication on the packet before processing.
                // Look up the receiving interface's auth key.
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
                    // Apply per-interface authentication and bump the crypto
                    // sequence number for MD5 auth.
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

                // Emit initial DDs for any ExStart neighbors that need them
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
                // Snapshot the current OSPF interface set (sw_if_index list)
                // so we can release the instance lock during the VPP queries.
                let sw_if_indices: Vec<u32> = {
                    let inst = instance.lock().await;
                    inst.interfaces
                        .iter()
                        .filter(|i| i.sw_if_index != 0)
                        .map(|i| i.sw_if_index)
                        .collect()
                };
                // Re-dump VPP interface list once for admin/link state.
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
                        // No v4 address — treat as down for OSPF purposes.
                        snapshots.push((
                            sw_if_index,
                            std::net::Ipv4Addr::UNSPECIFIED,
                            std::net::Ipv4Addr::UNSPECIFIED,
                            false,
                        ));
                    }
                }
                // Apply with the lock.
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
                // Compute SPF and update the local cache under
                // the lock, then release BEFORE talking to
                // ribd so the RibClient round-trip doesn't
                // block packet processing.
                let routes = {
                    let mut inst = instance.lock().await;
                    let routes = inst.run_spf();
                    let (added, deleted) = inst.rib.apply_routes(&routes);
                    if added > 0 || deleted > 0 {
                        tracing::info!(
                            added,
                            deleted,
                            total = inst.rib.route_count(),
                            "SPF cache updated"
                        );
                    }
                    routes
                };
                // Push to ribd. Bulk is idempotent — ribd
                // diffs server-side. push_v4 splits routes by
                // sub-type (intra / inter / ext1 / ext2) into
                // four separate Bulks so admin-distance
                // arbitration can treat them independently.
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
                    tracing::warn!("ribd push_v4 failed: {}", e);
                }
            }

            _ = sighup.recv() => {
                tracing::info!(path = %config_path.display(), vrf = ?args.vrf, "SIGHUP: reloading config");
                let reloaded = match &args.vrf {
                    None => OspfDaemonConfig::load(&config_path),
                    Some(name) => OspfDaemonConfig::load_for_vrf(&config_path, name),
                };
                match reloaded {
                    Ok(new_config) => {
                        let mut inst = instance.lock().await;
                        let changed = inst.reload_config(&new_config);
                        if changed {
                            tracing::info!("reload applied");
                        } else {
                            tracing::info!("reload: no effective changes");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "reload failed; keeping prior config live");
                    }
                }
                // v3 reload: same model as v2 — re-parse the v3
                // config block, push the diff in place. If the v3
                // config block is absent or disabled we silently
                // skip; a v3 daemon can't spring into existence
                // from a reload (interfaces + VPP sockets are wired
                // at startup), and a running v3 losing its config
                // isn't something we want to tear down live.
                if let Some(v3) = &v3_handle {
                    let reloaded_v3 = match &args.vrf {
                        None => ospfd::config::Ospf6DaemonConfig::load(&config_path),
                        Some(name) => ospfd::config::Ospf6DaemonConfig::load_for_vrf(&config_path, name),
                    };
                    match reloaded_v3 {
                        Ok(Some(new_v3)) => {
                            let mut inst = v3.lock().await;
                            let changed = inst.reload_config(&new_v3);
                            if changed {
                                tracing::info!("reload (v3) applied");
                            } else {
                                tracing::info!("reload (v3): no effective changes");
                            }
                        }
                        Ok(None) => {
                            tracing::info!(
                                "reload (v3): config block absent; v3 stays on prior config"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "reload (v3) failed; keeping prior v3 config live"
                            );
                        }
                    }
                }
            }

            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                // Push empty Bulks for every sub-type so ribd
                // withdraws everything attributed to us.
                if let Err(e) = rib_client.withdraw_v4().await {
                    tracing::warn!("ribd shutdown withdraw failed: {}", e);
                }
                let mut inst = instance.lock().await;
                inst.rib.clear();
                tracing::info!("OSPF routes withdrawn from ribd");
                break;
            }
        }
    }

    Ok(())
}
