//! OSPF daemon configuration.
//!
//! Reads the OSPF-relevant fields from /etc/ospfd/config.yaml.
//! We define our own serde structs for just the fields we need.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use ribd_routemap::{RouteMap, RouteMapYaml};
use serde::Deserialize;

/// One entry in an `ipv4` / `ipv6` address list as written by impd
/// to /persistent/config/router.yaml. The canonical shape is a CIDR
/// string (`"10.0.0.1/24"`); the legacy split shape
/// (`{address, prefix}`) is also accepted for back-compat.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum AddrEntry {
    Cidr(String),
    Split {
        address: String,
        #[serde(default)]
        prefix: Option<u8>,
    },
}

impl AddrEntry {
    /// Split into (address-without-prefix, prefix-length). Returns
    /// `None` for entries that fail to parse a numeric prefix.
    pub fn as_pair(&self) -> Option<(&str, u8)> {
        match self {
            AddrEntry::Cidr(s) => {
                let (a, p) = s.split_once('/')?;
                let plen: u8 = p.parse().ok()?;
                Some((a, plen))
            }
            AddrEntry::Split { address, prefix } => prefix.map(|p| (address.as_str(), p)),
        }
    }
}

/// Top-level router configuration (we only deserialize the fields we need).
#[derive(Debug, Clone, Deserialize)]
pub struct RouterConfig {
    #[serde(default)]
    pub ospf: OspfConfig,
    #[serde(default)]
    pub ospf3: OspfConfig,
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
    /// Top-level VRF declarations (`name`, `table_id_v4`,
    /// `table_id_v6`). ospfd reads this to map `--vrf <name>` to
    /// the v4/v6 FIB ids it stamps onto Routes pushed to ribd.
    /// Mirror of impd's `vrfs:` block — see imp/api/config.proto.
    #[serde(default)]
    pub vrfs: Vec<VrfYaml>,
}

/// On-disk VRF declaration. ospfd only cares about the table-ids;
/// other fields (description) are tolerated but ignored.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct VrfYaml {
    pub name: String,
    #[serde(default)]
    pub table_id_v4: u32,
    #[serde(default)]
    pub table_id_v6: u32,
    #[serde(default)]
    pub description: Option<String>,
}

/// OSPF configuration block. Used both for the top-level `ospf:`
/// block (default-VRF instance) and as the body shape for per-VRF
/// entries via `OspfVrfYaml`. The two share fields by composition:
/// `OspfVrfYaml` flattens an `OspfConfig` and adds `name`.
#[derive(Debug, Default, Deserialize, Clone)]
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
    /// Per-VRF instances. Each entry overrides the top-level fields
    /// for that VRF. impd's supervisor spawns `imp-ospfd@<vrf>`
    /// children that pass `--vrf <name>` to pick their slice.
    #[serde(default)]
    pub vrfs: Vec<OspfVrfYaml>,
}

/// Per-VRF OSPF configuration block. Mirrors `OspfConfig` (minus the
/// recursive `vrfs` field) and adds `name`. Loaded by
/// `OspfDaemonConfig::load_for_vrf` when the daemon is invoked with
/// `--vrf <name>` and `name` matches.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct OspfVrfYaml {
    pub name: String,
    /// Defaults true for per-VRF instances — appearing in the
    /// `vrfs:` list implies enabled. Operators can still set
    /// `enabled: false` to keep the slice config-side without
    /// spawning the daemon.
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub router_id: Option<String>,
    pub reference_bandwidth: Option<u32>,
    pub spf_delay: Option<u64>,
    pub spf_holdtime: Option<u64>,
    pub spf_max_holdtime: Option<u64>,
    #[serde(default)]
    pub passive_default: bool,
    pub distance: Option<u8>,
    pub distance_intra: Option<u8>,
    pub distance_inter: Option<u8>,
    pub distance_external: Option<u8>,
    #[serde(default)]
    pub summary_addresses: Vec<SummaryAddressEntry>,
    #[serde(default)]
    pub default_originate: bool,
    #[serde(default)]
    pub default_originate_always: bool,
    pub default_originate_metric: Option<u32>,
    pub default_originate_metric_type: Option<u8>,
    #[serde(default)]
    pub redistribute: Vec<RedistributeEntry>,
    #[serde(default)]
    pub areas: Vec<AreaConfigEntry>,
}

fn default_true() -> bool {
    true
}

/// Convert a per-VRF YAML slice into an OspfConfig that the existing
/// parser can consume. Drops the `name` field.
impl From<OspfVrfYaml> for OspfConfig {
    fn from(v: OspfVrfYaml) -> Self {
        OspfConfig {
            enabled: v.enabled,
            router_id: v.router_id,
            reference_bandwidth: v.reference_bandwidth,
            spf_delay: v.spf_delay,
            spf_holdtime: v.spf_holdtime,
            spf_max_holdtime: v.spf_max_holdtime,
            passive_default: v.passive_default,
            distance: v.distance,
            distance_intra: v.distance_intra,
            distance_inter: v.distance_inter,
            distance_external: v.distance_external,
            summary_addresses: v.summary_addresses,
            default_originate: v.default_originate,
            default_originate_always: v.default_originate_always,
            default_originate_metric: v.default_originate_metric,
            default_originate_metric_type: v.default_originate_metric_type,
            redistribute: v.redistribute,
            areas: v.areas,
            vrfs: Vec::new(),
        }
    }
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
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Default, Deserialize, Clone)]
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

/// An IPv4 address assigned to an interface. impd writes a CIDR
/// string today; the legacy `{address, prefix}` map is also
/// accepted via the untagged enum so existing yaml round-trips.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Ipv4AddressConfig {
    Cidr(String),
    Split { address: String, prefix: u8 },
}

impl Default for Ipv4AddressConfig {
    fn default() -> Self {
        Ipv4AddressConfig::Cidr(String::new())
    }
}

impl Ipv4AddressConfig {
    /// Parse into (address, prefix). Returns None when the CIDR
    /// string is malformed.
    pub fn as_pair(&self) -> Option<(&str, u8)> {
        match self {
            Ipv4AddressConfig::Cidr(s) => {
                let (a, p) = s.split_once('/')?;
                let plen: u8 = p.parse().ok()?;
                Some((a, plen))
            }
            Ipv4AddressConfig::Split { address, prefix } => Some((address.as_str(), *prefix)),
        }
    }
}

/// Interface configuration (OSPF-relevant fields).
#[derive(Debug, Default, Clone, Deserialize)]
pub struct InterfaceConfig {
    pub name: Option<String>,
    /// VRF the interface lives in. Empty string or "default" means
    /// the default VRF (table 0). Used to scope per-instance
    /// adjacency formation: each ospfd instance only forms
    /// adjacencies on interfaces whose `vrf` matches its
    /// configured VRF name.
    #[serde(default)]
    pub vrf: Option<String>,
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
    /// Authentication type: "simple", "message-digest" (RFC 2328 keyed-MD5),
    /// "hmac-sha-256" / "hmac-sha-384" / "hmac-sha-512" (RFC 5709), or omitted
    /// for none. MD5 is preserved for legacy interop; new deployments should
    /// prefer HMAC-SHA-256 or stronger.
    pub ospf_auth_type: Option<String>,
    /// Simple-auth cleartext password.
    pub ospf_auth_key: Option<String>,
    /// Crypto key ID (1-255) for any keyed crypto auth type.
    pub ospf_md5_key_id: Option<u8>,
    /// Crypto key for any keyed crypto auth type (MD5 or HMAC-SHA).
    pub ospf_md5_key: Option<String>,

    /// ---- OSPFv3 per-interface fields ----
    pub ospf3_area: Option<serde_yaml::Value>,
    pub ospf3_cost: Option<u16>,
    pub ospf3_passive: Option<bool>,
    pub ospf3_network_type: Option<String>,
    pub ospf3_hello_interval: Option<u16>,
    pub ospf3_dead_interval: Option<u32>,
    pub ospf3_retransmit_interval: Option<u16>,
    pub ospf3_transmit_delay: Option<u16>,
    pub ospf3_priority: Option<u8>,
    pub ospf3_instance_id: Option<u8>,
    /// Static NBMA neighbor list for OSPFv3. Only honored when
    /// `ospf6_network_type` is `non-broadcast`. Each entry's address
    /// must be a link-local IPv6 address (fe80::/10) belonging to
    /// the peer's interface on this segment — OSPFv3 keys neighbor
    /// state on link-local addresses, not router-ids.
    #[serde(default)]
    pub ospf3_neighbors: Vec<Ospf6NeighborConfig>,

    /// VLAN sub-interfaces sitting under this parent. Each sub
    /// terminates as `<parent>.<vlan_id>` in Linux (lcp-auto-subint
    /// in VPP creates the TAP), with its own VRF, IP addresses, and
    /// OSPF settings independent of the parent. ospfd treats them as
    /// first-class OSPF interfaces — see the inner loop in
    /// `OspfDaemonConfig::from_router_yaml` (and the v3 equivalent).
    #[serde(default)]
    pub subinterfaces: Vec<SubInterfaceConfig>,
}

/// VLAN sub-interface (OSPF-relevant fields). Mirrors impd's
/// `SubInterface` struct shape: flat `ipv4` + `ipv4_prefix` (not
/// the `Vec<Ipv4AddressConfig>` shape parents use), per-sub VRF
/// independent of the parent, full set of `ospf_*` / `ospf6_*`
/// knobs.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct SubInterfaceConfig {
    pub vlan_id: u16,
    /// VRF the sub-interface lives in. Independent of the parent —
    /// `lan.110` in customer_vrf and `lan.120` in default both work.
    /// Empty string or "default" means the default VRF (table 0).
    #[serde(default)]
    pub vrf: Option<String>,
    /// Sub-interface IPv4 addresses (CIDR strings on the wire).
    /// OSPF picks the first entry for the interface's primary
    /// address; impd is responsible for keeping it stable.
    #[serde(default)]
    pub ipv4: Vec<AddrEntry>,
    /// Sub-interface IPv6 addresses. Used by the v3 path for the
    /// passive/p2p-style address advertisement; OSPFv3 hellos still
    /// run over link-local.
    #[serde(default)]
    pub ipv6: Vec<AddrEntry>,

    pub ospf_area: Option<serde_yaml::Value>,
    pub ospf_cost: Option<u16>,
    pub ospf_passive: Option<bool>,
    pub ospf_network_type: Option<String>,
    pub ospf_hello_interval: Option<u16>,
    pub ospf_dead_interval: Option<u32>,
    pub ospf_retransmit_interval: Option<u16>,
    pub ospf_priority: Option<u8>,
    #[serde(default)]
    pub ospf_neighbors: Vec<OspfNeighborConfig>,
    pub ospf_auth_type: Option<String>,
    pub ospf_auth_key: Option<String>,
    pub ospf_md5_key_id: Option<u8>,
    pub ospf_md5_key: Option<String>,

    pub ospf3_area: Option<serde_yaml::Value>,
    pub ospf3_cost: Option<u16>,
    pub ospf3_passive: Option<bool>,
    pub ospf3_network_type: Option<String>,
    pub ospf3_hello_interval: Option<u16>,
    pub ospf3_dead_interval: Option<u32>,
    pub ospf3_retransmit_interval: Option<u16>,
    pub ospf3_transmit_delay: Option<u16>,
    pub ospf3_priority: Option<u8>,
    pub ospf3_instance_id: Option<u8>,
    #[serde(default)]
    pub ospf3_neighbors: Vec<Ospf6NeighborConfig>,
}

/// Loopback interface (OSPF-relevant fields). Mirrors impd's
/// `LoopbackInterface` shape: flat `ipv4` / `ipv4_prefix` (not a
/// `Vec<…>` of CIDR objects) — single-address per loopback,
/// matching what impd writes to /persistent/config/router.yaml.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct LoopbackConfig {
    pub name: Option<String>,
    /// VRF the loopback lives in. Same semantics as
    /// `InterfaceConfig::vrf` — controls which ospfd instance
    /// will use this loopback.
    #[serde(default)]
    pub vrf: Option<String>,
    #[serde(default)]
    pub ipv4: Vec<AddrEntry>,
    #[serde(default)]
    pub ipv6: Vec<AddrEntry>,
    pub ospf_area: Option<serde_yaml::Value>,
    pub ospf_cost: Option<u16>,
    pub ospf_passive: Option<bool>,

    /// OSPFv3 loopback fields.
    pub ospf3_area: Option<serde_yaml::Value>,
    pub ospf3_cost: Option<u16>,
    pub ospf3_passive: Option<bool>,
}

/// Parsed, validated OSPF daemon configuration.
#[derive(Debug)]
pub struct OspfDaemonConfig {
    /// VRF this instance serves. `None` for the default VRF; the
    /// per-VRF spawn (`imp-ospfd@<vrf>`) sets `Some("customer_vrf")`.
    /// Drives adjacency-formation filtering: only interfaces with
    /// matching `vrf:` field get OSPF on this instance.
    pub vrf_name: Option<String>,
    /// IPv4 FIB table-id this instance writes routes into. 0 for
    /// default VRF; per-VRF instances pick up their VRF's
    /// `table_id_v4` from the top-level `vrfs:` declaration.
    pub table_id_v4: u32,
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
    /// VRF this instance serves; mirrors OspfDaemonConfig::vrf_name.
    pub vrf_name: Option<String>,
    /// IPv6 FIB table-id this instance writes routes into. 0 for
    /// default; per-VRF instances pick up `table_id_v6` from the
    /// top-level `vrfs:` declaration.
    pub table_id_v6: u32,
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
    /// Load configuration from a YAML file (default-VRF instance).
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: RouterConfig = serde_yaml::from_str(&contents)?;
        Self::from_router_yaml(config, None)
    }

    /// Load configuration for a per-VRF instance. Looks up
    /// `ospf.vrfs[name]` for the OSPF block and the top-level
    /// `vrfs[name]` for the table-id; returns an error if either
    /// is missing or `table_id_v4 == 0`.
    pub fn load_for_vrf(path: &Path, vrf_name: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: RouterConfig = serde_yaml::from_str(&contents)?;
        Self::from_router_yaml(config, Some(vrf_name))
    }

    /// Load every OSPFv2 instance the YAML declares: the default
    /// VRF (if `ospf.enabled`) plus one per `ospf.vrfs[]` entry
    /// whose VRF is declared at the top level. Returns an empty
    /// Vec if no v2 instance is configured.
    ///
    /// Used by the multi-instance daemon entry point — one
    /// process owns every VRF's state, so it needs to see all
    /// configs at once. Per-VRF entries that fail validation
    /// (undeclared VRF, table_id_v4=0, …) are skipped with a
    /// warning rather than aborting the whole load: the default
    /// instance and any other valid VRFs should still come up.
    pub fn load_all(path: &Path) -> anyhow::Result<Vec<Self>> {
        let contents = std::fs::read_to_string(path)?;
        let parsed: RouterConfig = serde_yaml::from_str(&contents)?;
        let mut out = Vec::new();

        // Default-VRF — only if ospf.enabled. `from_router_yaml`
        // bails on disabled; treat that as "no default instance"
        // rather than a hard failure (per-VRF config alone is a
        // legitimate deployment shape).
        if parsed.ospf.enabled {
            match Self::from_router_yaml(parsed.clone(), None) {
                Ok(cfg) => out.push(cfg),
                Err(e) => {
                    tracing::warn!("ospfv2 default-VRF config invalid: {}", e);
                }
            }
        }

        // Per-VRF instances. Iterate by name so a malformed entry
        // doesn't cascade across the others.
        let vrf_names: Vec<String> =
            parsed.ospf.vrfs.iter().map(|v| v.name.clone()).collect();
        for name in vrf_names {
            match Self::from_router_yaml(parsed.clone(), Some(&name)) {
                Ok(cfg) => out.push(cfg),
                Err(e) => {
                    tracing::warn!(
                        vrf = %name,
                        "ospfv2 vrf config invalid, skipping: {}", e
                    );
                }
            }
        }

        Ok(out)
    }

    /// Build an OspfDaemonConfig for either default-VRF (vrf_name=None)
    /// or a per-VRF instance (vrf_name=Some). Per-VRF picks
    /// `config.ospf.vrfs[name]` for the OSPF body and
    /// `config.vrfs[name].table_id_v4` for the FIB stamp; default-VRF
    /// uses the flat `config.ospf` block with table_id 0.
    pub fn from_router_yaml(
        mut config: RouterConfig,
        vrf_name: Option<&str>,
    ) -> anyhow::Result<Self> {
        // Per-VRF instances pull their slice from `ospf.vrfs[name]`
        // and resolve table-ids against the top-level `vrfs:` block.
        let table_id_v4: u32 = match vrf_name {
            None => 0,
            Some(name) => {
                let vrf_yaml = config
                    .ospf
                    .vrfs
                    .iter()
                    .find(|v| v.name == name)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!(
                        "--vrf {name}: no matching ospf.vrfs[] block in config"
                    ))?;
                let decl = config
                    .vrfs
                    .iter()
                    .find(|v| v.name == name)
                    .ok_or_else(|| anyhow::anyhow!(
                        "--vrf {name}: VRF not declared in top-level vrfs:"
                    ))?;
                if decl.table_id_v4 == 0 {
                    anyhow::bail!(
                        "--vrf {name}: table_id_v4 is 0 (reserved for default VRF)"
                    );
                }
                // Replace `config.ospf` with the per-VRF slice so the
                // existing parser below sees the right shape.
                let table_id_v4 = decl.table_id_v4;
                config.ospf = vrf_yaml.into();
                table_id_v4
            }
        };

        if !config.ospf.enabled {
            anyhow::bail!(
                "OSPF is not enabled in configuration{}",
                vrf_name.map(|v| format!(" for VRF '{v}'")).unwrap_or_default()
            );
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

        // Filter interfaces / loopbacks to those that live in our VRF.
        // Empty-string / "default" / missing `vrf:` field all map to
        // the default VRF (None below).
        let iface_in_vrf = |iface_vrf: &Option<String>| -> bool {
            let normalized = iface_vrf
                .as_deref()
                .filter(|s| !s.is_empty() && *s != "default")
                .map(|s| s.to_string());
            match (&normalized, vrf_name) {
                (None, None) => true,
                (Some(n), Some(target)) => n == target,
                _ => false,
            }
        };

        let mut interfaces = Vec::new();

        // Physical interfaces. Per-VRF gating is applied per item
        // (parent + each sub) rather than at the top of the loop —
        // a sub-interface in `customer_vrf` can hang off a parent
        // that's in the default VRF, and ospfd-for-customer_vrf
        // must still see lan.110 even though `lan` itself isn't in
        // its VRF.
        for iface in &config.interfaces {
            // Parent-interface OSPF
            if iface_in_vrf(&iface.vrf) {
                if let Some(area_val) = &iface.ospf_area {
                    let area_id = parse_area_id_value(area_val)?;
                    let name = iface.name.as_deref().unwrap_or("").to_string();

                    // Use the first IPv4 address on the interface.
                    let (address, prefix_len) = iface
                        .ipv4
                        .first()
                        .and_then(|a| a.as_pair())
                        .and_then(|(a, p)| a.parse::<Ipv4Addr>().ok().map(|addr| (addr, p)))
                        .unwrap_or((Ipv4Addr::UNSPECIFIED, 24));

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

            // Sub-interface OSPF. Each sub has its own VRF and IP
            // and is wired to Linux as `<parent>.<vlan_id>` by
            // VPP's lcp-auto-subint, so the OspfInterfaceConfig
            // name is built from the parent name + vlan_id. Parent
            // name is required — without it we have nothing to
            // bind raw sockets to, so skip.
            let parent_name = match iface.name.as_deref() {
                Some(n) if !n.is_empty() => n,
                _ => continue,
            };
            for sub in &iface.subinterfaces {
                if !iface_in_vrf(&sub.vrf) {
                    continue;
                }
                let Some(area_val) = &sub.ospf_area else {
                    continue;
                };
                let area_id = parse_area_id_value(area_val)?;
                let name = format!("{parent_name}.{}", sub.vlan_id);

                let (address, prefix_len) = sub
                    .ipv4
                    .iter()
                    .find_map(|a| a.as_pair())
                    .and_then(|(a, p)| a.parse::<Ipv4Addr>().ok().map(|addr| (addr, p)))
                    .unwrap_or((Ipv4Addr::UNSPECIFIED, 24));

                let passive = sub.ospf_passive.unwrap_or(config.ospf.passive_default);
                let auth_key = parse_auth_key(
                    sub.ospf_auth_type.as_deref(),
                    sub.ospf_auth_key.as_deref(),
                    sub.ospf_md5_key_id,
                    sub.ospf_md5_key.as_deref(),
                );
                let static_neighbors: Vec<(Ipv4Addr, u8)> = sub
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
                    cost: sub.ospf_cost.unwrap_or(10),
                    passive,
                    network_type: sub
                        .ospf_network_type
                        .clone()
                        .unwrap_or_else(|| "broadcast".to_string()),
                    hello_interval: sub.ospf_hello_interval.unwrap_or(10),
                    dead_interval: sub.ospf_dead_interval.unwrap_or(40),
                    retransmit_interval: sub.ospf_retransmit_interval.unwrap_or(5),
                    priority: sub.ospf_priority.unwrap_or(1),
                    auth_key,
                    static_neighbors,
                });
            }
        }

        // Loopbacks
        for lb in &config.loopbacks {
            if !iface_in_vrf(&lb.vrf) {
                continue;
            }
            if let Some(area_val) = &lb.ospf_area {
                let area_id = parse_area_id_value(area_val)?;
                let name = lb.name.as_deref().unwrap_or("").to_string();

                let (address, prefix_len) = lb
                    .ipv4
                    .iter()
                    .find_map(|a| a.as_pair())
                    .and_then(|(a, p)| a.parse::<Ipv4Addr>().ok().map(|addr| (addr, p)))
                    .unwrap_or((Ipv4Addr::UNSPECIFIED, 32));

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
            vrf_name: vrf_name.map(|s| s.to_string()),
            table_id_v4,
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
    /// Load the OSPFv3 daemon configuration from a YAML file
    /// (default-VRF instance). Returns Ok(None) when the `ospf6:`
    /// block is absent or `enabled: false`.
    pub fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        let contents = std::fs::read_to_string(path)?;
        let config: RouterConfig = serde_yaml::from_str(&contents)?;
        Self::from_router_yaml(config, None)
    }

    /// Load the OSPFv3 config for a per-VRF instance. Returns
    /// Ok(None) when the per-VRF block has `enabled: false`.
    pub fn load_for_vrf(path: &Path, vrf_name: &str) -> anyhow::Result<Option<Self>> {
        let contents = std::fs::read_to_string(path)?;
        let config: RouterConfig = serde_yaml::from_str(&contents)?;
        Self::from_router_yaml(config, Some(vrf_name))
    }

    /// Load every OSPFv3 instance the YAML declares: the default
    /// VRF (if `ospf6.enabled`) plus one per `ospf6.vrfs[]` entry
    /// whose VRF is declared at the top level. Returns an empty
    /// Vec if no v3 instance is configured. Mirrors
    /// `OspfDaemonConfig::load_all`.
    pub fn load_all(path: &Path) -> anyhow::Result<Vec<Self>> {
        let contents = std::fs::read_to_string(path)?;
        let parsed: RouterConfig = serde_yaml::from_str(&contents)?;
        let mut out = Vec::new();

        // Default-VRF (Ok(None) means "not enabled" — skip silently).
        match Self::from_router_yaml(parsed.clone(), None) {
            Ok(Some(cfg)) => out.push(cfg),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("ospfv3 default-VRF config invalid: {}", e);
            }
        }

        let vrf_names: Vec<String> =
            parsed.ospf3.vrfs.iter().map(|v| v.name.clone()).collect();
        for name in vrf_names {
            match Self::from_router_yaml(parsed.clone(), Some(&name)) {
                Ok(Some(cfg)) => out.push(cfg),
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        vrf = %name,
                        "ospfv3 vrf config invalid, skipping: {}", e
                    );
                }
            }
        }

        Ok(out)
    }

    /// Build an Ospf6DaemonConfig for default-VRF (vrf_name=None) or
    /// a per-VRF instance. Same dispatch shape as
    /// `OspfDaemonConfig::from_router_yaml`.
    pub fn from_router_yaml(
        mut config: RouterConfig,
        vrf_name: Option<&str>,
    ) -> anyhow::Result<Option<Self>> {
        let table_id_v6: u32 = match vrf_name {
            None => 0,
            Some(name) => {
                let vrf_yaml = config
                    .ospf3
                    .vrfs
                    .iter()
                    .find(|v| v.name == name)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!(
                        "--vrf {name}: no matching ospf6.vrfs[] block in config"
                    ))?;
                let decl = config
                    .vrfs
                    .iter()
                    .find(|v| v.name == name)
                    .ok_or_else(|| anyhow::anyhow!(
                        "--vrf {name}: VRF not declared in top-level vrfs:"
                    ))?;
                if decl.table_id_v6 == 0 {
                    anyhow::bail!(
                        "--vrf {name}: table_id_v6 is 0 (reserved for default VRF)"
                    );
                }
                let table_id_v6 = decl.table_id_v6;
                config.ospf3 = vrf_yaml.into();
                table_id_v6
            }
        };

        if !config.ospf3.enabled {
            return Ok(None);
        }

        let router_id: Ipv4Addr = config
            .ospf3
            .router_id
            .as_deref()
            .unwrap_or("0.0.0.0")
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid ospf6 router_id: {}", e))?;
        if router_id.is_unspecified() {
            anyhow::bail!("OSPFv3 router_id must be set");
        }

        // Same VRF filter as OspfDaemonConfig — only adopt
        // interfaces / loopbacks that live in our VRF.
        let iface_in_vrf = |iface_vrf: &Option<String>| -> bool {
            let normalized = iface_vrf
                .as_deref()
                .filter(|s| !s.is_empty() && *s != "default")
                .map(|s| s.to_string());
            match (&normalized, vrf_name) {
                (None, None) => true,
                (Some(n), Some(target)) => n == target,
                _ => false,
            }
        };

        let mut interfaces = Vec::new();
        // Parent-VRF gating is per-item (see the v2 equivalent for
        // rationale): a sub in `customer_vrf` under a default-VRF
        // parent must still surface in the customer_vrf instance.
        for iface in &config.interfaces {
            // Parent-interface OSPFv3
            if iface_in_vrf(&iface.vrf) {
                if let Some(area_val) = &iface.ospf3_area {
                    let area_id = parse_area_id_value(area_val)?;
                    let name = iface.name.as_deref().unwrap_or("").to_string();
                    let passive = iface.ospf3_passive.unwrap_or(config.ospf3.passive_default);
                    // Parse the static NBMA neighbor list (link-local IPv6
                    // addresses) — only meaningful for non-broadcast network
                    // type, but we always parse so misconfigurations show up
                    // as warnings rather than silent drops.
                    let mut v6_static_neighbors: Vec<(Ipv6Addr, u8)> = Vec::new();
                    for n in &iface.ospf3_neighbors {
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
                        cost: iface.ospf3_cost.unwrap_or(10),
                        passive,
                        network_type: iface
                            .ospf3_network_type
                            .clone()
                            .unwrap_or_else(|| "broadcast".to_string()),
                        hello_interval: iface.ospf3_hello_interval.unwrap_or(10),
                        dead_interval: iface.ospf3_dead_interval.unwrap_or(40),
                        retransmit_interval: iface.ospf3_retransmit_interval.unwrap_or(5),
                        transmit_delay: iface.ospf3_transmit_delay.unwrap_or(1),
                        priority: iface.ospf3_priority.unwrap_or(1),
                        instance_id: iface.ospf3_instance_id.unwrap_or(0),
                        static_neighbors: v6_static_neighbors,
                    });
                }
            }

            // Sub-interface OSPFv3. Same name convention as v2
            // (`<parent>.<vlan_id>`), with the sub's own VRF.
            let parent_name = match iface.name.as_deref() {
                Some(n) if !n.is_empty() => n,
                _ => continue,
            };
            for sub in &iface.subinterfaces {
                if !iface_in_vrf(&sub.vrf) {
                    continue;
                }
                let Some(area_val) = &sub.ospf3_area else {
                    continue;
                };
                let area_id = parse_area_id_value(area_val)?;
                let name = format!("{parent_name}.{}", sub.vlan_id);
                let passive = sub.ospf3_passive.unwrap_or(config.ospf3.passive_default);
                let mut v6_static_neighbors: Vec<(Ipv6Addr, u8)> = Vec::new();
                for n in &sub.ospf3_neighbors {
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
                    cost: sub.ospf3_cost.unwrap_or(10),
                    passive,
                    network_type: sub
                        .ospf3_network_type
                        .clone()
                        .unwrap_or_else(|| "broadcast".to_string()),
                    hello_interval: sub.ospf3_hello_interval.unwrap_or(10),
                    dead_interval: sub.ospf3_dead_interval.unwrap_or(40),
                    retransmit_interval: sub.ospf3_retransmit_interval.unwrap_or(5),
                    transmit_delay: sub.ospf3_transmit_delay.unwrap_or(1),
                    priority: sub.ospf3_priority.unwrap_or(1),
                    instance_id: sub.ospf3_instance_id.unwrap_or(0),
                    static_neighbors: v6_static_neighbors,
                });
            }
        }

        // Loopbacks are modelled as passive P2P interfaces (no hellos,
        // prefix advertised via Intra-Area-Prefix-LSA).
        for lb in &config.loopbacks {
            if !iface_in_vrf(&lb.vrf) {
                continue;
            }
            let Some(area_val) = &lb.ospf3_area else {
                continue;
            };
            let area_id = parse_area_id_value(area_val)?;
            let name = lb.name.as_deref().unwrap_or("").to_string();
            interfaces.push(Ospf6InterfaceConfig {
                name,
                area_id,
                cost: lb.ospf3_cost.unwrap_or(1),
                passive: lb.ospf3_passive.unwrap_or(true),
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
        for entry in &config.ospf3.redistribute {
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
        for area in &config.ospf3.areas {
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
            vrf_name: vrf_name.map(|s| s.to_string()),
            table_id_v6,
            router_id,
            reference_bandwidth: config.ospf3.reference_bandwidth.unwrap_or(100),
            interfaces,
            redistribute,
            areas,
            distance: config.ospf3.distance,
            default_originate: config.ospf3.default_originate,
            default_originate_metric: config.ospf3.default_originate_metric.unwrap_or(1),
            default_originate_metric_type: config
                .ospf3
                .default_originate_metric_type
                .unwrap_or(2),
            summary_addresses: config
                .ospf3
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
    use crate::packet::auth::{AuthKey, HmacAlgo};
    let crypto_alg = match auth_type.map(str::to_ascii_lowercase).as_deref() {
        Some("simple") => {
            return match simple_key {
                Some(k) if !k.is_empty() => AuthKey::Simple(k.as_bytes().to_vec()),
                _ => AuthKey::None,
            };
        }
        Some("message-digest" | "md5") => None, // sentinel for MD5
        Some("hmac-sha-256" | "hmac-sha256" | "sha256" | "sha-256") => Some(HmacAlgo::Sha256),
        Some("hmac-sha-384" | "hmac-sha384" | "sha384" | "sha-384") => Some(HmacAlgo::Sha384),
        Some("hmac-sha-512" | "hmac-sha512" | "sha512" | "sha-512") => Some(HmacAlgo::Sha512),
        _ => return AuthKey::None,
    };
    match (md5_key_id, md5_key) {
        (Some(id), Some(k)) if !k.is_empty() => match crypto_alg {
            None => AuthKey::Md5 { key_id: id, key: k.as_bytes().to_vec() },
            Some(algo) => AuthKey::HmacSha { algo, key_id: id, key: k.as_bytes().to_vec() },
        },
        _ => AuthKey::None,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml_with_subinterface_ospf(extra: &str) -> RouterConfig {
        // Minimal router.yaml shape with a single VLAN sub-interface
        // carrying ospf_area. No top-level ospf.areas — exercising
        // the path that would have been silently swallowed before
        // the parent-vrf-gating fix.
        let body = format!(
            r#"
ospf:
  enabled: true
  router_id: "10.0.0.1"
ospf3:
  enabled: true
  router_id: "10.0.0.1"
interfaces:
  - name: lan
    iface: enp4s0f1np1
    pci: "0000:04:00.1"
    subinterfaces:
      - vlan_id: 110
        ipv4:
          - "192.168.37.5/24"
        ipv6:
          - "2001:db8:37::5/64"
        create_lcp: true
        ospf_area: 0
        ospf6_area: 0
        {extra}
"#
        );
        serde_yaml::from_str(&body).expect("parse router.yaml")
    }

    #[test]
    fn subinterface_ospf_v2_lands_with_dotted_name() {
        // Regression: an `ospf_area: 0` on a sub-interface must
        // produce an OspfInterfaceConfig keyed on `<parent>.<vlan_id>`
        // with the sub's own IPv4 (not the parent's, and not
        // UNSPECIFIED) — pre-fix, the sub-interface scan didn't
        // exist and the sub was silently ignored.
        let cfg = yaml_with_subinterface_ospf("");
        let parsed = OspfDaemonConfig::from_router_yaml(cfg, None).unwrap();
        let lan_110 = parsed
            .interfaces
            .iter()
            .find(|i| i.name == "lan.110")
            .expect("lan.110 in OSPFv2 interface list");
        assert_eq!(lan_110.address, "192.168.37.5".parse::<Ipv4Addr>().unwrap());
        assert_eq!(lan_110.prefix_len, 24);
        assert_eq!(lan_110.area_id, Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn subinterface_ospf_v3_lands_with_dotted_name() {
        let cfg = yaml_with_subinterface_ospf("");
        let parsed = Ospf6DaemonConfig::from_router_yaml(cfg, None).unwrap().expect("v6 cfg");
        let lan_110 = parsed
            .interfaces
            .iter()
            .find(|i| i.name == "lan.110")
            .expect("lan.110 in OSPFv3 interface list");
        assert_eq!(lan_110.area_id, Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn loopback_ipv4_list_shape_parses() {
        // impd writes `ipv4:` as a list of CIDR strings on loopbacks
        // (matching its `LoopbackInterface { ipv4: Vec<IpAddress> }`
        // serde, which renders each entry as `"addr/prefix"`). Make
        // sure ospfd accepts that shape and pulls the first address
        // for its interface entry.
        let yaml = r#"
ospf:
  enabled: true
  router_id: "10.0.0.1"
loopbacks:
  - instance: 0
    name: lo0
    ipv4:
      - "10.255.255.100/32"
    create_lcp: true
    ospf_area: 0
"#;
        let cfg: RouterConfig = serde_yaml::from_str(yaml).expect("parse loopback yaml");
        let parsed = OspfDaemonConfig::from_router_yaml(cfg, None).unwrap();
        let lo0 = parsed
            .interfaces
            .iter()
            .find(|i| i.name == "lo0")
            .expect("lo0 in OSPFv2 interface list");
        assert_eq!(lo0.address, "10.255.255.100".parse::<Ipv4Addr>().unwrap());
        assert_eq!(lo0.prefix_len, 32);
    }

    #[test]
    fn subinterface_in_other_vrf_skipped_by_default_instance() {
        // The default-VRF instance must skip subs in customer_vrf,
        // and conversely the customer_vrf instance must pick them
        // up even when the parent is in the default VRF.
        let cfg = yaml_with_subinterface_ospf("vrf: customer_vrf");
        let default_vrf = OspfDaemonConfig::from_router_yaml(cfg, None).unwrap();
        assert!(
            default_vrf.interfaces.iter().all(|i| i.name != "lan.110"),
            "default-VRF instance must not pick up customer_vrf sub"
        );

        // For per-VRF parse we need to declare the VRF and a per-VRF
        // OSPF block with its own router_id — otherwise from_router_yaml
        // bails on the missing per-VRF config.
        let yaml = r#"
vrfs:
  - name: customer_vrf
    table_id_v4: 100
    table_id_v6: 100
ospf:
  enabled: true
  router_id: "10.0.0.1"
  vrfs:
    - name: customer_vrf
      enabled: true
      router_id: "10.0.0.2"
interfaces:
  - name: lan
    iface: enp4s0f1np1
    pci: "0000:04:00.1"
    subinterfaces:
      - vlan_id: 110
        ipv4:
          - "192.168.37.5/24"
        create_lcp: true
        ospf_area: 0
        vrf: customer_vrf
"#;
        let cfg: RouterConfig = serde_yaml::from_str(yaml).unwrap();
        let customer = OspfDaemonConfig::from_router_yaml(cfg, Some("customer_vrf")).unwrap();
        assert!(
            customer.interfaces.iter().any(|i| i.name == "lan.110"),
            "customer_vrf instance must pick up its sub even when parent is default-VRF"
        );
    }

    #[test]
    fn load_all_returns_default_plus_per_vrf_instances() {
        // The multi-instance entry point loads N OspfDaemonConfigs
        // from one router.yaml: the default-VRF block (when
        // `ospf.enabled`) plus one per `ospf.vrfs[]` entry whose
        // VRF is declared at the top level. Instances missing a
        // matching `vrfs:` declaration must be silently skipped so
        // a stale `ospf.vrfs[]` entry doesn't take down the whole
        // daemon.
        let yaml = r#"
vrfs:
  - name: customer_vrf
    table_id_v4: 10
    table_id_v6: 10
  - name: customer2_vrf
    table_id_v4: 20
    table_id_v6: 20
ospf:
  enabled: true
  router_id: "10.0.0.1"
  vrfs:
    - name: customer_vrf
      enabled: true
      router_id: "10.0.0.2"
    - name: customer2_vrf
      enabled: true
      router_id: "10.0.0.3"
    - name: undeclared_vrf
      enabled: true
      router_id: "10.0.0.4"
interfaces: []
"#;
        let path = std::env::temp_dir().join(format!(
            "ospfd_load_all_{}.yaml",
            std::process::id()
        ));
        std::fs::write(&path, yaml).unwrap();
        let configs = OspfDaemonConfig::load_all(&path).unwrap();
        std::fs::remove_file(&path).ok();

        // Expect 3: default + customer_vrf + customer2_vrf.
        // undeclared_vrf gets skipped (no top-level vrfs[] match).
        assert_eq!(
            configs.len(),
            3,
            "expected default + 2 declared VRFs (got {} entries)",
            configs.len(),
        );

        let names: Vec<Option<String>> = configs.iter().map(|c| c.vrf_name.clone()).collect();
        assert!(names.contains(&None), "default-VRF instance missing");
        assert!(names.contains(&Some("customer_vrf".to_string())));
        assert!(names.contains(&Some("customer2_vrf".to_string())));
        assert!(!names.contains(&Some("undeclared_vrf".to_string())));

        // table_id_v4 stamping: default = 0, per-VRF picks up the
        // top-level `vrfs[].table_id_v4`.
        let default = configs
            .iter()
            .find(|c| c.vrf_name.is_none())
            .expect("default cfg");
        assert_eq!(default.table_id_v4, 0);
        let customer = configs
            .iter()
            .find(|c| c.vrf_name.as_deref() == Some("customer_vrf"))
            .expect("customer_vrf cfg");
        assert_eq!(customer.table_id_v4, 10);
        let customer2 = configs
            .iter()
            .find(|c| c.vrf_name.as_deref() == Some("customer2_vrf"))
            .expect("customer2_vrf cfg");
        assert_eq!(customer2.table_id_v4, 20);
    }

    #[test]
    fn load_all_returns_empty_when_ospf_disabled_and_no_vrfs() {
        let yaml = r#"
ospf:
  enabled: false
interfaces: []
"#;
        let path = std::env::temp_dir().join(format!(
            "ospfd_load_all_disabled_{}.yaml",
            std::process::id()
        ));
        std::fs::write(&path, yaml).unwrap();
        let configs = OspfDaemonConfig::load_all(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(configs.is_empty());
    }
}
