//! OSPF daemon configuration.
//!
//! Reads the OSPF-relevant fields from /etc/ospfd/config.yaml.
//! We define our own serde structs for just the fields we need.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use ribd_routemap::{RouteMap, RouteMapYaml};
use serde::Deserialize;

/// Top-level router configuration (we only deserialize the fields we need).
#[derive(Debug, Deserialize)]
pub struct RouterConfig {
    #[serde(default)]
    pub ospf: OspfConfig,
    #[serde(default)]
    pub ospf6: OspfConfig,
    #[serde(default)]
    pub interfaces: Vec<InterfaceConfig>,
    #[serde(default)]
    pub loopbacks: Vec<LoopbackConfig>,
    /// Top-level route-maps shared across daemons (bgpd, ospfd,
    /// future producers). Each map is referenced by name from
    /// per-protocol redistribute entries. Universal-clause-only
    /// in v1 (`NoExtras`); ospfd-specific match/set extras are a
    /// follow-up if/when needed.
    #[serde(default)]
    pub route_maps: Vec<RouteMapYaml>,
}

/// OSPF configuration block.
#[derive(Debug, Default, Deserialize)]
pub struct OspfConfig {
    #[serde(default)]
    pub enabled: bool,
    pub router_id: Option<String>,
    pub reference_bandwidth: Option<u32>,
    pub spf_delay: Option<u64>,
    pub spf_holdtime: Option<u64>,
    pub spf_max_holdtime: Option<u64>,
    #[serde(default)]
    pub passive_default: bool,
    /// Default admin distance for all OSPF sub-types (1-255).
    /// Overridden per sub-type by the fields below.
    pub distance: Option<u8>,
    pub distance_intra: Option<u8>,
    pub distance_inter: Option<u8>,
    pub distance_external: Option<u8>,
    /// Summary-address entries for ASBR external summarization.
    /// Each entry tells the daemon to originate a single aggregate
    /// Type 5 LSA for the summary prefix. Phase 1 emits the
    /// summary LSA but does not yet suppress the component
    /// (matching-prefix) Type 5s — full exclusion is a follow-up.
    #[serde(default)]
    pub summary_addresses: Vec<SummaryAddressEntry>,
    /// When true, originate a Type 5 default route (0.0.0.0/0 or
    /// ::/0) as if we were an ASBR. Makes this router act as a
    /// default-gateway of last resort for the OSPF domain.
    #[serde(default)]
    pub default_originate: bool,
    /// With default_originate=true, also originate when we don't
    /// ourselves have a default route in the FIB. When false,
    /// we only advertise if we're already resolving the default.
    /// Phase 1: `always` is the only supported mode (we don't
    /// consult the FIB yet). Kept for forward compat.
    #[serde(default)]
    pub default_originate_always: bool,
    /// Metric to use for the default-originate Type 5 LSA.
    pub default_originate_metric: Option<u32>,
    /// 1 (E1) or 2 (E2). Default E2.
    pub default_originate_metric_type: Option<u8>,
    /// Redistribution sources (e.g., "connected", "static", "bgp").
    #[serde(default)]
    pub redistribute: Vec<RedistributeEntry>,
    /// Area-level configuration (type, default_cost, etc.).
    #[serde(default)]
    pub areas: Vec<AreaConfigEntry>,
}

/// A summary-address entry from `ospf.summary_addresses[]` or
/// `ospf6.summary_addresses[]` in the config file. `prefix` carries
/// a CIDR string parsed separately by the daemon (v4 or v6 chosen
/// by which config block it came from).
#[derive(Debug, Default, Clone, Deserialize)]
pub struct SummaryAddressEntry {
    pub prefix: String,
    #[serde(default)]
    pub no_advertise: bool,
    #[serde(default)]
    pub tag: Option<u32>,
    #[serde(default)]
    pub metric: Option<u32>,
    #[serde(default)]
    pub metric_type: Option<u8>,
}

/// Area-level configuration from the config file.
#[derive(Debug, Deserialize)]
pub struct AreaConfigEntry {
    pub area_id: serde_yaml::Value,
    /// Area type: "normal", "stub", or "nssa" (default: normal).
    #[serde(default)]
    pub r#type: Option<String>,
    /// For stub/NSSA: metric of the default Summary-LSA originated by ABRs.
    #[serde(default)]
    pub default_cost: Option<u32>,
}

/// A redistribution entry as it appears in the config file.
///
/// The actual schema uses `protocol: <name>` with optional `metric`,
/// `metric_type`, and `route_map` fields.
#[derive(Debug, Default, Deserialize)]
pub struct RedistributeEntry {
    pub protocol: String,
    #[serde(default)]
    pub metric: Option<u32>,
    #[serde(default)]
    pub metric_type: Option<u8>,
    /// Optional reference (by name) to a top-level `route_maps:`
    /// entry. The named map filters/transforms each candidate
    /// prefix at LSA-origination time.
    #[serde(default)]
    pub route_map: Option<String>,
}

impl RedistributeEntry {
    pub fn source(&self) -> &str {
        &self.protocol
    }
    pub fn metric(&self) -> u32 {
        self.metric.unwrap_or(20)
    }
    pub fn metric_type(&self) -> u8 {
        self.metric_type.unwrap_or(2)
    }
}

/// An IPv4 address assigned to an interface.
#[derive(Debug, Default, Deserialize)]
pub struct Ipv4AddressConfig {
    pub address: String,
    pub prefix: u8,
}

/// An IPv4 address for loopbacks (uses cidr field instead).
#[derive(Debug, Default, Deserialize)]
pub struct Ipv4CidrConfig {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub cidr: Option<String>,
    #[serde(default)]
    pub prefix: Option<u8>,
}

/// Interface configuration (OSPF-relevant fields).
#[derive(Debug, Default, Deserialize)]
pub struct InterfaceConfig {
    pub name: Option<String>,
    #[serde(default)]
    pub ipv4: Vec<Ipv4AddressConfig>,
    pub ospf_area: Option<serde_yaml::Value>,
    pub ospf_cost: Option<u16>,
    pub ospf_passive: Option<bool>,
    pub ospf_network_type: Option<String>,
    pub ospf_hello_interval: Option<u16>,
    pub ospf_dead_interval: Option<u32>,
    pub ospf_retransmit_interval: Option<u16>,
    pub ospf_priority: Option<u8>,
    /// Static NBMA neighbor list. Only honored when
    /// `ospf_network_type` is `non-broadcast`.
    #[serde(default)]
    pub ospf_neighbors: Vec<OspfNeighborConfig>,
    /// Authentication type: "simple", "message-digest", or omitted for none.
    pub ospf_auth_type: Option<String>,
    /// Simple-auth cleartext password.
    pub ospf_auth_key: Option<String>,
    /// MD5 key ID (1-255) for message-digest auth.
    pub ospf_md5_key_id: Option<u8>,
    /// MD5 cryptographic key for message-digest auth.
    pub ospf_md5_key: Option<String>,

    /// ---- OSPFv3 per-interface fields ----
    pub ospf6_area: Option<serde_yaml::Value>,
    pub ospf6_cost: Option<u16>,
    pub ospf6_passive: Option<bool>,
    pub ospf6_network_type: Option<String>,
    pub ospf6_hello_interval: Option<u16>,
    pub ospf6_dead_interval: Option<u32>,
    pub ospf6_retransmit_interval: Option<u16>,
    pub ospf6_transmit_delay: Option<u16>,
    pub ospf6_priority: Option<u8>,
    pub ospf6_instance_id: Option<u8>,
    /// Static NBMA neighbor list for OSPFv3. Only honored when
    /// `ospf6_network_type` is `non-broadcast`. Each entry's address
    /// must be a link-local IPv6 address (fe80::/10) belonging to
    /// the peer's interface on this segment — OSPFv3 keys neighbor
    /// state on link-local addresses, not router-ids.
    #[serde(default)]
    pub ospf6_neighbors: Vec<Ospf6NeighborConfig>,
}

/// Loopback interface (OSPF-relevant fields).
#[derive(Debug, Default, Deserialize)]
pub struct LoopbackConfig {
    pub name: Option<String>,
    #[serde(default)]
    pub ipv4: Vec<Ipv4CidrConfig>,
    pub ospf_area: Option<serde_yaml::Value>,
    pub ospf_cost: Option<u16>,
    pub ospf_passive: Option<bool>,

    /// OSPFv3 loopback fields.
    pub ospf6_area: Option<serde_yaml::Value>,
    pub ospf6_cost: Option<u16>,
    pub ospf6_passive: Option<bool>,
}

/// Parsed, validated OSPF daemon configuration.
#[derive(Debug)]
pub struct OspfDaemonConfig {
    pub router_id: Ipv4Addr,
    pub reference_bandwidth: u32,
    pub spf_delay_ms: u64,
    pub spf_holdtime_ms: u64,
    pub spf_max_holdtime_ms: u64,
    pub interfaces: Vec<OspfInterfaceConfig>,
    /// Redistribution: which external route sources to advertise.
    pub redistribute: Vec<RedistributeConfig>,
    /// Per-area configuration (type, default cost).
    pub areas: Vec<AreaConfig>,
    /// Admin distances by route sub-type. Any `None` falls back to
    /// the ribd default (110). If `distance` is set but the per-sub-
    /// type value is not, the generic value applies to all.
    pub distance: Option<u8>,
    pub distance_intra: Option<u8>,
    pub distance_inter: Option<u8>,
    pub distance_external: Option<u8>,
    /// Originate a Type 5 LSA for 0.0.0.0/0 (default route).
    pub default_originate: bool,
    /// Metric for the default-originate Type 5 LSA (default 1).
    pub default_originate_metric: u32,
    /// 1=E1, 2=E2 (default 2).
    pub default_originate_metric_type: u8,
    /// Parsed summary-address entries (ASBR external aggregation).
    /// Each entry becomes a single Type 5 aggregate LSA. Component
    /// prefixes that fall inside the summary range are suppressed
    /// at origination time (in `originate_external_lsas`), so peers
    /// only see the aggregate. The `no_advertise` flag controls
    /// whether the aggregate itself is emitted; component
    /// suppression happens regardless.
    pub summary_addresses: Vec<ParsedSummaryAddress>,
    /// Compiled route-maps from the top-level `route_maps:` block,
    /// keyed by name. Per-redistribute entries reference these by
    /// name; the origination path looks them up to permit/deny
    /// candidate prefixes.
    pub route_maps: HashMap<String, RouteMap>,
}

/// A fully parsed summary-address entry, ready for origination.
#[derive(Debug, Clone)]
pub struct ParsedSummaryAddress {
    pub prefix: Ipv4Addr,
    pub prefix_len: u8,
    pub no_advertise: bool,
    pub tag: u32,
    pub metric: u32,
    pub metric_type: u8,
}

/// IPv6 counterpart of [`ParsedSummaryAddress`].
#[derive(Debug, Clone)]
pub struct ParsedSummaryAddress6 {
    pub prefix: std::net::Ipv6Addr,
    pub prefix_len: u8,
    pub no_advertise: bool,
    pub tag: u32,
    pub metric: u32,
    pub metric_type: u8,
}

impl OspfDaemonConfig {
    /// Resolve the effective admin-distance override for a given
    /// sub-type. Returns `None` to let ribd use its source default.
    pub fn admin_distance_for(&self, kind: crate::proto::spf::OspfRouteKind) -> Option<u8> {
        use crate::proto::spf::OspfRouteKind;
        let specific = match kind {
            OspfRouteKind::Intra => self.distance_intra,
            OspfRouteKind::Inter => self.distance_inter,
            OspfRouteKind::External1 | OspfRouteKind::External2 => self.distance_external,
        };
        specific.or(self.distance)
    }
}

/// Parsed area configuration.
#[derive(Debug, Clone)]
pub struct AreaConfig {
    pub area_id: Ipv4Addr,
    pub area_type: AreaType,
    /// Default-LSA cost for stub/NSSA areas (metric of the default-route
    /// Type 3 Summary-LSA originated by the ABR).
    pub default_cost: u32,
}

/// Parsed area type (matches crate::area::AreaType).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AreaType {
    Normal,
    Stub,
    Nssa,
}

/// Parsed redistribution configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedistributeConfig {
    pub source: RedistributeSource,
    /// Metric to advertise (default 20).
    pub metric: u32,
    /// E1 (1) or E2 (2). Default E2.
    pub metric_type: u8,
    /// Optional name of a top-level route-map. Resolved at
    /// LSA-origination time against `OspfDaemonConfig.route_maps`
    /// (or `Ospf6DaemonConfig.route_maps`). A `None` here means
    /// "permit every route from this protocol".
    pub route_map: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedistributeSource {
    Connected,
    Static,
    Bgp,
    Kernel,
}

impl RedistributeSource {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "connected" => Some(Self::Connected),
            "static" => Some(Self::Static),
            "bgp" => Some(Self::Bgp),
            "kernel" => Some(Self::Kernel),
            _ => None,
        }
    }
}

/// A statically-configured NBMA neighbor entry from the config file.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct OspfNeighborConfig {
    /// Unicast IPv4 address to which Hellos are sent.
    pub address: String,
    /// Priority for DR election while the peer hasn't responded.
    /// Defaults to 1 (same as the standard default priority).
    #[serde(default)]
    pub priority: Option<u8>,
}

/// A statically-configured NBMA neighbor for OSPFv3. Address must be
/// the peer's link-local IPv6 (fe80::/10), since OSPFv3 keys neighbor
/// state on link-local addresses.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct Ospf6NeighborConfig {
    /// Link-local IPv6 address of the peer's interface on this segment.
    pub address: String,
    /// Priority for DR election while the peer hasn't responded.
    #[serde(default)]
    pub priority: Option<u8>,
}

/// A configured OSPF interface.
#[derive(Debug, Clone)]
pub struct OspfInterfaceConfig {
    pub name: String,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub area_id: Ipv4Addr,
    pub cost: u16,
    pub passive: bool,
    pub network_type: String,
    pub hello_interval: u16,
    pub dead_interval: u32,
    pub priority: u8,
    /// LSA retransmit interval in seconds. Used as the DD
    /// retransmit interval and (when flooding gains a retransmit
    /// queue) the LSU retransmit-on-ack-timeout interval.
    pub retransmit_interval: u16,
    /// Parsed authentication key. AuthKey::None if no auth configured.
    pub auth_key: crate::packet::auth::AuthKey,
    /// Static NBMA neighbors, parsed from the YAML list. Only
    /// populated (and only meaningful) when `network_type` is
    /// `"non-broadcast"`.
    pub static_neighbors: Vec<(Ipv4Addr, u8)>,
}

/// Parsed OSPFv3 daemon configuration, assembled from the `ospf6:` block
/// and per-interface `ospf6_*` fields in the config file.
#[derive(Debug, Clone)]
pub struct Ospf6DaemonConfig {
    pub router_id: Ipv4Addr,
    pub reference_bandwidth: u32,
    pub interfaces: Vec<Ospf6InterfaceConfig>,
    pub redistribute: Vec<RedistributeConfig>,
    pub areas: Vec<AreaConfig>,
    /// Single admin distance applied to every v3 route sub-type
    /// (v3 has no per-sub-type distance; see proto OSPF6Config).
    pub distance: Option<u8>,
    /// Originate a Type 5 default route (::/0).
    pub default_originate: bool,
    pub default_originate_metric: u32,
    pub default_originate_metric_type: u8,
    /// Parsed summary-address entries.
    pub summary_addresses: Vec<ParsedSummaryAddress6>,
    /// Compiled route-maps from the top-level `route_maps:` block,
    /// keyed by name. Mirrors the v2 field.
    pub route_maps: HashMap<String, RouteMap>,
}

impl Ospf6DaemonConfig {
    pub fn admin_distance_for(
        &self,
        _kind: crate::spf_v3::Ospfv3RouteKind,
    ) -> Option<u8> {
        self.distance
    }
}

/// A configured OSPFv3 interface.
#[derive(Debug, Clone)]
pub struct Ospf6InterfaceConfig {
    pub name: String,
    pub area_id: Ipv4Addr,
    pub cost: u16,
    pub passive: bool,
    pub network_type: String,
    pub hello_interval: u16,
    pub dead_interval: u32,
    pub priority: u8,
    pub instance_id: u8,
    /// LSA retransmit interval in seconds. Used when the flooding
    /// layer gains a retransmit queue.
    pub retransmit_interval: u16,
    /// Transmit delay (seconds added to LSA age when flooding out
    /// this interface). Used by the LSA-age math.
    pub transmit_delay: u16,
    /// Static NBMA neighbors (link-local IPv6 + priority). Only
    /// populated and only meaningful when `network_type` is
    /// `"non-broadcast"`.
    pub static_neighbors: Vec<(Ipv6Addr, u8)>,
}

/// Compile every entry in the top-level `route_maps:` block into
/// runtime form, keyed by name. Returns an error on duplicate
/// names or unparseable clauses (bad CIDR, unknown source, etc.).
fn compile_route_maps(
    yaml: &[RouteMapYaml],
) -> anyhow::Result<HashMap<String, RouteMap>> {
    let mut out: HashMap<String, RouteMap> = HashMap::new();
    for m in yaml {
        let name = m.name.clone();
        if out.contains_key(&name) {
            anyhow::bail!("duplicate route-map name: {name}");
        }
        let compiled = m
            .clone()
            .compile()
            .map_err(|e| anyhow::anyhow!("route-map {name}: {e}"))?;
        out.insert(name, compiled);
    }
    Ok(out)
}

impl OspfDaemonConfig {
    /// Load configuration from a YAML file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: RouterConfig = serde_yaml::from_str(&contents)?;

        if !config.ospf.enabled {
            anyhow::bail!("OSPF is not enabled in configuration");
        }

        let router_id: Ipv4Addr = config
            .ospf
            .router_id
            .as_deref()
            .unwrap_or("0.0.0.0")
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid router_id: {}", e))?;

        if router_id.is_unspecified() {
            anyhow::bail!("OSPF router_id must be set");
        }

        let mut interfaces = Vec::new();

        // Physical interfaces
        for iface in &config.interfaces {
            if let Some(area_val) = &iface.ospf_area {
                let area_id = parse_area_id_value(area_val)?;
                let name = iface.name.as_deref().unwrap_or("").to_string();

                // Use the first IPv4 address on the interface
                let (address, prefix_len) = if let Some(first) = iface.ipv4.first() {
                    (
                        first.address.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED),
                        first.prefix,
                    )
                } else {
                    (Ipv4Addr::UNSPECIFIED, 24)
                };

                let passive = iface.ospf_passive.unwrap_or(config.ospf.passive_default);
                let auth_key = parse_auth_key(
                    iface.ospf_auth_type.as_deref(),
                    iface.ospf_auth_key.as_deref(),
                    iface.ospf_md5_key_id,
                    iface.ospf_md5_key.as_deref(),
                );

                let static_neighbors: Vec<(Ipv4Addr, u8)> = iface
                    .ospf_neighbors
                    .iter()
                    .filter_map(|n| {
                        let addr: Ipv4Addr = n.address.parse().ok()?;
                        Some((addr, n.priority.unwrap_or(1)))
                    })
                    .collect();
                interfaces.push(OspfInterfaceConfig {
                    name,
                    address,
                    prefix_len,
                    area_id,
                    cost: iface.ospf_cost.unwrap_or(10),
                    passive,
                    network_type: iface
                        .ospf_network_type
                        .clone()
                        .unwrap_or_else(|| "broadcast".to_string()),
                    hello_interval: iface.ospf_hello_interval.unwrap_or(10),
                    dead_interval: iface.ospf_dead_interval.unwrap_or(40),
                    retransmit_interval: iface.ospf_retransmit_interval.unwrap_or(5),
                    priority: iface.ospf_priority.unwrap_or(1),
                    auth_key,
                    static_neighbors,
                });
            }
        }

        // Loopbacks
        for lb in &config.loopbacks {
            if let Some(area_val) = &lb.ospf_area {
                let area_id = parse_area_id_value(area_val)?;
                let name = lb.name.as_deref().unwrap_or("").to_string();

                // Loopback addresses may use `cidr` or `address` + `prefix`
                let (address, prefix_len) = if let Some(first) = lb.ipv4.first() {
                    if let Some(cidr) = &first.cidr {
                        let (addr_part, prefix_part) = cidr
                            .split_once('/')
                            .unwrap_or((cidr.as_str(), "32"));
                        (
                            addr_part.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED),
                            prefix_part.parse::<u8>().unwrap_or(32),
                        )
                    } else if let Some(addr) = &first.address {
                        (
                            addr.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED),
                            first.prefix.unwrap_or(32),
                        )
                    } else {
                        (Ipv4Addr::UNSPECIFIED, 32)
                    }
                } else {
                    (Ipv4Addr::UNSPECIFIED, 32)
                };

                interfaces.push(OspfInterfaceConfig {
                    name,
                    address,
                    prefix_len,
                    area_id,
                    cost: lb.ospf_cost.unwrap_or(1),
                    passive: lb.ospf_passive.unwrap_or(true),
                    network_type: "point-to-point".to_string(),
                    hello_interval: 10,
                    dead_interval: 40,
                    retransmit_interval: 5,
                    priority: 0,
                    // Loopbacks never receive OSPF packets — no auth needed
                    auth_key: crate::packet::auth::AuthKey::None,
                    static_neighbors: Vec::new(),
                });
            }
        }

        // Compile the top-level route_maps block once so both v4
        // and v6 redistribute paths can resolve names against the
        // same set.
        let route_maps = compile_route_maps(&config.route_maps)?;

        // Parse redistribution entries
        let mut redistribute = Vec::new();
        for entry in &config.ospf.redistribute {
            if let Some(source) = RedistributeSource::parse(entry.source()) {
                if let Some(name) = &entry.route_map {
                    if !route_maps.contains_key(name) {
                        anyhow::bail!(
                            "redistribute references unknown route-map: {name}"
                        );
                    }
                }
                redistribute.push(RedistributeConfig {
                    source,
                    metric: entry.metric(),
                    metric_type: entry.metric_type(),
                    route_map: entry.route_map.clone(),
                });
            } else {
                tracing::warn!(
                    source = entry.source(),
                    "unknown redistribute source, skipping"
                );
            }
        }

        // Parse area configuration
        let mut areas = Vec::new();
        for area in &config.ospf.areas {
            let area_id = parse_area_id_value(&area.area_id)?;
            let area_type = match area.r#type.as_deref() {
                Some("stub") => AreaType::Stub,
                Some("nssa") => AreaType::Nssa,
                _ => AreaType::Normal,
            };
            areas.push(AreaConfig {
                area_id,
                area_type,
                default_cost: area.default_cost.unwrap_or(1),
            });
        }

        Ok(OspfDaemonConfig {
            router_id,
            reference_bandwidth: config.ospf.reference_bandwidth.unwrap_or(100),
            spf_delay_ms: config.ospf.spf_delay.unwrap_or(50),
            spf_holdtime_ms: config.ospf.spf_holdtime.unwrap_or(200),
            spf_max_holdtime_ms: config.ospf.spf_max_holdtime.unwrap_or(5000),
            interfaces,
            redistribute,
            areas,
            distance: config.ospf.distance,
            distance_intra: config.ospf.distance_intra,
            distance_inter: config.ospf.distance_inter,
            distance_external: config.ospf.distance_external,
            default_originate: config.ospf.default_originate,
            default_originate_metric: config.ospf.default_originate_metric.unwrap_or(1),
            default_originate_metric_type: config.ospf.default_originate_metric_type.unwrap_or(2),
            summary_addresses: config
                .ospf
                .summary_addresses
                .iter()
                .filter_map(|e| parse_summary_v4(e))
                .collect(),
            route_maps,
        })
    }
}

impl Ospf6DaemonConfig {
    /// Load the OSPFv3 daemon configuration from a YAML file. Returns
    /// Ok(None) when the `ospf6:` block is absent or `enabled: false`.
    pub fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        let contents = std::fs::read_to_string(path)?;
        let config: RouterConfig = serde_yaml::from_str(&contents)?;

        if !config.ospf6.enabled {
            return Ok(None);
        }

        let router_id: Ipv4Addr = config
            .ospf6
            .router_id
            .as_deref()
            .unwrap_or("0.0.0.0")
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid ospf6 router_id: {}", e))?;
        if router_id.is_unspecified() {
            anyhow::bail!("OSPFv3 router_id must be set");
        }

        let mut interfaces = Vec::new();
        for iface in &config.interfaces {
            let Some(area_val) = &iface.ospf6_area else {
                continue;
            };
            let area_id = parse_area_id_value(area_val)?;
            let name = iface.name.as_deref().unwrap_or("").to_string();
            let passive = iface.ospf6_passive.unwrap_or(config.ospf6.passive_default);
            // Parse the static NBMA neighbor list (link-local IPv6
            // addresses) — only meaningful for non-broadcast network
            // type, but we always parse so misconfigurations show up
            // as warnings rather than silent drops.
            let mut v6_static_neighbors: Vec<(Ipv6Addr, u8)> = Vec::new();
            for n in &iface.ospf6_neighbors {
                match n.address.parse::<Ipv6Addr>() {
                    Ok(addr) => {
                        if !addr.is_unicast_link_local() {
                            tracing::warn!(
                                addr = %addr,
                                "ospf6 static neighbor is not link-local; OSPFv3 expects fe80::/10"
                            );
                        }
                        v6_static_neighbors.push((addr, n.priority.unwrap_or(1)));
                    }
                    Err(e) => {
                        tracing::warn!(
                            addr = %n.address,
                            error = %e,
                            "ignoring invalid ospf6 static neighbor address"
                        );
                    }
                }
            }
            interfaces.push(Ospf6InterfaceConfig {
                name,
                area_id,
                cost: iface.ospf6_cost.unwrap_or(10),
                passive,
                network_type: iface
                    .ospf6_network_type
                    .clone()
                    .unwrap_or_else(|| "broadcast".to_string()),
                hello_interval: iface.ospf6_hello_interval.unwrap_or(10),
                dead_interval: iface.ospf6_dead_interval.unwrap_or(40),
                retransmit_interval: iface.ospf6_retransmit_interval.unwrap_or(5),
                transmit_delay: iface.ospf6_transmit_delay.unwrap_or(1),
                priority: iface.ospf6_priority.unwrap_or(1),
                instance_id: iface.ospf6_instance_id.unwrap_or(0),
                static_neighbors: v6_static_neighbors,
            });
        }

        // Loopbacks are modelled as passive P2P interfaces (no hellos,
        // prefix advertised via Intra-Area-Prefix-LSA).
        for lb in &config.loopbacks {
            let Some(area_val) = &lb.ospf6_area else {
                continue;
            };
            let area_id = parse_area_id_value(area_val)?;
            let name = lb.name.as_deref().unwrap_or("").to_string();
            interfaces.push(Ospf6InterfaceConfig {
                name,
                area_id,
                cost: lb.ospf6_cost.unwrap_or(1),
                passive: lb.ospf6_passive.unwrap_or(true),
                network_type: "point-to-point".to_string(),
                hello_interval: 10,
                dead_interval: 40,
                retransmit_interval: 5,
                transmit_delay: 1,
                priority: 0,
                instance_id: 0,
                static_neighbors: Vec::new(),
            });
        }

        let route_maps = compile_route_maps(&config.route_maps)?;

        let mut redistribute = Vec::new();
        for entry in &config.ospf6.redistribute {
            if let Some(source) = RedistributeSource::parse(entry.source()) {
                if let Some(name) = &entry.route_map {
                    if !route_maps.contains_key(name) {
                        anyhow::bail!(
                            "ospf6 redistribute references unknown route-map: {name}"
                        );
                    }
                }
                redistribute.push(RedistributeConfig {
                    source,
                    metric: entry.metric(),
                    metric_type: entry.metric_type(),
                    route_map: entry.route_map.clone(),
                });
            } else {
                tracing::warn!(
                    source = entry.source(),
                    "unknown ospf6 redistribute source, skipping"
                );
            }
        }

        let mut areas = Vec::new();
        for area in &config.ospf6.areas {
            let area_id = parse_area_id_value(&area.area_id)?;
            let area_type = match area.r#type.as_deref() {
                Some("stub") => AreaType::Stub,
                Some("nssa") => AreaType::Nssa,
                _ => AreaType::Normal,
            };
            areas.push(AreaConfig {
                area_id,
                area_type,
                default_cost: area.default_cost.unwrap_or(1),
            });
        }

        Ok(Some(Ospf6DaemonConfig {
            router_id,
            reference_bandwidth: config.ospf6.reference_bandwidth.unwrap_or(100),
            interfaces,
            redistribute,
            areas,
            distance: config.ospf6.distance,
            default_originate: config.ospf6.default_originate,
            default_originate_metric: config.ospf6.default_originate_metric.unwrap_or(1),
            default_originate_metric_type: config
                .ospf6
                .default_originate_metric_type
                .unwrap_or(2),
            summary_addresses: config
                .ospf6
                .summary_addresses
                .iter()
                .filter_map(|e| parse_summary_v6(e))
                .collect(),
            route_maps,
        }))
    }
}

/// Parse an `ospf.summary_addresses[]` entry into a
/// [`ParsedSummaryAddress`]. Invalid CIDR strings are dropped with
/// a warn.
fn parse_summary_v4(e: &SummaryAddressEntry) -> Option<ParsedSummaryAddress> {
    let (addr_s, len_s) = e.prefix.split_once('/')?;
    let addr: Ipv4Addr = addr_s.parse().ok()?;
    let prefix_len: u8 = len_s.parse().ok()?;
    Some(ParsedSummaryAddress {
        prefix: addr,
        prefix_len,
        no_advertise: e.no_advertise,
        tag: e.tag.unwrap_or(0),
        metric: e.metric.unwrap_or(20),
        metric_type: e.metric_type.unwrap_or(2),
    })
}

/// Parse an `ospf6.summary_addresses[]` entry.
fn parse_summary_v6(e: &SummaryAddressEntry) -> Option<ParsedSummaryAddress6> {
    let (addr_s, len_s) = e.prefix.split_once('/')?;
    let addr: std::net::Ipv6Addr = addr_s.parse().ok()?;
    let prefix_len: u8 = len_s.parse().ok()?;
    Some(ParsedSummaryAddress6 {
        prefix: addr,
        prefix_len,
        no_advertise: e.no_advertise,
        tag: e.tag.unwrap_or(0),
        metric: e.metric.unwrap_or(20),
        metric_type: e.metric_type.unwrap_or(2),
    })
}

/// Parse per-interface authentication config into an AuthKey.
fn parse_auth_key(
    auth_type: Option<&str>,
    simple_key: Option<&str>,
    md5_key_id: Option<u8>,
    md5_key: Option<&str>,
) -> crate::packet::auth::AuthKey {
    match auth_type {
        Some("simple") => match simple_key {
            Some(k) if !k.is_empty() => {
                crate::packet::auth::AuthKey::Simple(k.as_bytes().to_vec())
            }
            _ => crate::packet::auth::AuthKey::None,
        },
        Some("message-digest") | Some("md5") => {
            match (md5_key_id, md5_key) {
                (Some(id), Some(k)) if !k.is_empty() => crate::packet::auth::AuthKey::Md5 {
                    key_id: id,
                    key: k.as_bytes().to_vec(),
                },
                _ => crate::packet::auth::AuthKey::None,
            }
        }
        _ => crate::packet::auth::AuthKey::None,
    }
}

/// Parse an OSPF area ID from YAML. Accepts integers, decimal strings, and dotted IPv4.
fn parse_area_id_value(v: &serde_yaml::Value) -> anyhow::Result<Ipv4Addr> {
    match v {
        serde_yaml::Value::Number(n) => {
            let n = n.as_u64().ok_or_else(|| anyhow::anyhow!("negative area ID"))?;
            Ok(Ipv4Addr::from(n as u32))
        }
        serde_yaml::Value::String(s) => {
            // Try as dotted IPv4 first
            if let Ok(addr) = s.parse::<Ipv4Addr>() {
                return Ok(addr);
            }
            // Try as a decimal number
            if let Ok(n) = s.parse::<u32>() {
                return Ok(Ipv4Addr::from(n));
            }
            anyhow::bail!("invalid OSPF area ID '{}'", s)
        }
        _ => anyhow::bail!("OSPF area ID must be a number or string, got {:?}", v),
    }
}
