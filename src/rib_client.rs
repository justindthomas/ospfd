//! Thin wrapper around [`ribd_client::RibConnection`] with
//! reconnect-on-failure and SpfRoute/Ospfv3Route → proto::Route
//! conversion.
//!
//! Phase 3 cutover: replaces the direct VPP FIB programming that
//! used to live in rib.rs / rib_v3.rs. ospfd no longer knows
//! about VPP route install calls — it computes SPF output, converts
//! to the [`ribd_proto::Route`] shape, and pushes a Bulk per
//! address family per SPF cycle. ribd handles the diff against
//! its in-memory RIB and programs VPP + kernel.
//!
//! Bulk semantics mean push_bulk is idempotent: we don't need to
//! track what's installed locally, and recovery after a ribd
//! restart is "push the current set again".

use std::path::PathBuf;
use std::time::Duration;

use ribd_client::{connect_with_retry, RibConnection};
use ribd_proto::{NextHop, Prefix, Route, Source};

use crate::proto::spf::{OspfRouteKind, SpfRoute};
use crate::spf_v3::{Ospfv3Route, Ospfv3RouteKind};

pub struct RibClient {
    socket_path: PathBuf,
    client_name: String,
    conn: Option<RibConnection>,
}

impl RibClient {
    /// Construct without connecting. Use [`connect`] to establish
    /// the initial session — separating the two lets callers
    /// report startup failures cleanly.
    pub fn new(socket_path: impl Into<PathBuf>, client_name: impl Into<String>) -> Self {
        RibClient {
            socket_path: socket_path.into(),
            client_name: client_name.into(),
            conn: None,
        }
    }

    /// Connect with bounded retry. On success, subsequent push_bulk
    /// calls use the established session.
    pub async fn connect(&mut self, max_wait: Duration) -> anyhow::Result<()> {
        let c = connect_with_retry(&self.socket_path, &self.client_name, max_wait)
            .await
            .map_err(|e| anyhow::anyhow!("ribd connect: {}", e))?;
        self.conn = Some(c);
        tracing::info!(
            socket = %self.socket_path.display(),
            client = %self.client_name,
            "connected to ribd"
        );
        Ok(())
    }

    /// Push all OSPFv2 routes, split by sub-type into four separate
    /// Bulk messages (intra / inter / ext1 / ext2). ribd stores each
    /// sub-type under its own Source so admin-distance arbitration
    /// can treat them independently. Always emits a Bulk for every
    /// sub-type — including empty ones — so that stale routes from
    /// a previous cycle are purged.
    ///
    /// `ad_override`: resolves a per-sub-type admin distance from
    /// OspfDaemonConfig. `None` for any kind keeps the ribd default.
    pub async fn push_v4(
        &mut self,
        routes: &[SpfRoute],
        ad_override: impl Fn(OspfRouteKind) -> Option<u8>,
    ) -> anyhow::Result<()> {
        let mut intra: Vec<Route> = Vec::new();
        let mut inter: Vec<Route> = Vec::new();
        let mut ext1: Vec<Route> = Vec::new();
        let mut ext2: Vec<Route> = Vec::new();
        for r in routes {
            let source = match r.kind {
                OspfRouteKind::Intra => Source::OspfIntra,
                OspfRouteKind::Inter => Source::OspfInter,
                OspfRouteKind::External1 => Source::OspfExt1,
                OspfRouteKind::External2 => Source::OspfExt2,
            };
            let mut proto = spf_route_to_proto(r, source);
            proto.admin_distance = ad_override(r.kind);
            match r.kind {
                OspfRouteKind::Intra => intra.push(proto),
                OspfRouteKind::Inter => inter.push(proto),
                OspfRouteKind::External1 => ext1.push(proto),
                OspfRouteKind::External2 => ext2.push(proto),
            }
        }
        self.push_bulk(Source::OspfIntra, intra).await?;
        self.push_bulk(Source::OspfInter, inter).await?;
        self.push_bulk(Source::OspfExt1, ext1).await?;
        self.push_bulk(Source::OspfExt2, ext2).await?;
        Ok(())
    }

    /// Push all OSPFv3 routes, split by sub-type. Mirrors push_v4.
    pub async fn push_v6(
        &mut self,
        routes: &[Ospfv3Route],
        ad_override: impl Fn(Ospfv3RouteKind) -> Option<u8>,
    ) -> anyhow::Result<()> {
        let mut intra: Vec<Route> = Vec::new();
        let mut inter: Vec<Route> = Vec::new();
        let mut ext1: Vec<Route> = Vec::new();
        let mut ext2: Vec<Route> = Vec::new();
        for r in routes {
            let source = match r.kind {
                Ospfv3RouteKind::Intra => Source::Ospf6Intra,
                Ospfv3RouteKind::Inter => Source::Ospf6Inter,
                Ospfv3RouteKind::External1 => Source::Ospf6Ext1,
                Ospfv3RouteKind::External2 => Source::Ospf6Ext2,
            };
            let mut proto = ospfv3_route_to_proto(r, source);
            proto.admin_distance = ad_override(r.kind);
            match r.kind {
                Ospfv3RouteKind::Intra => intra.push(proto),
                Ospfv3RouteKind::Inter => inter.push(proto),
                Ospfv3RouteKind::External1 => ext1.push(proto),
                Ospfv3RouteKind::External2 => ext2.push(proto),
            }
        }
        self.push_bulk(Source::Ospf6Intra, intra).await?;
        self.push_bulk(Source::Ospf6Inter, inter).await?;
        self.push_bulk(Source::Ospf6Ext1, ext1).await?;
        self.push_bulk(Source::Ospf6Ext2, ext2).await?;
        Ok(())
    }

    /// Push an empty bulk for every OSPFv2 sub-type — used at
    /// shutdown so ribd drops our state.
    pub async fn withdraw_v4(&mut self) -> anyhow::Result<()> {
        self.push_bulk(Source::OspfIntra, Vec::new()).await?;
        self.push_bulk(Source::OspfInter, Vec::new()).await?;
        self.push_bulk(Source::OspfExt1, Vec::new()).await?;
        self.push_bulk(Source::OspfExt2, Vec::new()).await?;
        Ok(())
    }

    /// Push an empty bulk for every OSPFv3 sub-type.
    pub async fn withdraw_v6(&mut self) -> anyhow::Result<()> {
        self.push_bulk(Source::Ospf6Intra, Vec::new()).await?;
        self.push_bulk(Source::Ospf6Inter, Vec::new()).await?;
        self.push_bulk(Source::Ospf6Ext1, Vec::new()).await?;
        self.push_bulk(Source::Ospf6Ext2, Vec::new()).await?;
        Ok(())
    }

    /// Shared push path with single-shot reconnect on failure. If
    /// the connection is dropped, we reconnect once, re-handshake,
    /// and retry the bulk. If that also fails, return the error —
    /// the caller can keep ospfd running and try again next
    /// SPF cycle.
    async fn push_bulk(&mut self, source: Source, routes: Vec<Route>) -> anyhow::Result<()> {
        if self.conn.is_none() {
            self.reconnect().await?;
        }
        let result = {
            let conn = self.conn.as_mut().unwrap();
            conn.push_bulk(source, routes.clone()).await
        };
        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::warn!(
                    "ribd push failed: {} — reconnecting and retrying once", e
                );
                self.conn = None;
                self.reconnect().await?;
                let conn = self.conn.as_mut().unwrap();
                conn.push_bulk(source, routes)
                    .await
                    .map_err(|e| anyhow::anyhow!("ribd retry push: {}", e))
            }
        }
    }

    async fn reconnect(&mut self) -> anyhow::Result<()> {
        let c = connect_with_retry(
            &self.socket_path,
            &self.client_name,
            Duration::from_secs(5),
        )
        .await
        .map_err(|e| anyhow::anyhow!("ribd reconnect: {}", e))?;
        self.conn = Some(c);
        tracing::info!("reconnected to ribd");
        Ok(())
    }
}

fn spf_route_to_proto(r: &SpfRoute, source: Source) -> Route {
    Route {
        prefix: Prefix::v4(r.prefix, r.prefix_len),
        source,
        next_hops: vec![NextHop::v4(r.next_hop, r.sw_if_index)],
        metric: r.cost,
        tag: 0,
        admin_distance: None,
    }
}

fn ospfv3_route_to_proto(r: &Ospfv3Route, source: Source) -> Route {
    let next_hops = r
        .next_hops
        .iter()
        .map(|(addr, swi)| NextHop::v6(*addr, *swi))
        .collect();
    Route {
        prefix: Prefix::v6(r.prefix, r.prefix_len),
        source,
        next_hops,
        metric: r.cost,
        tag: 0,
        admin_distance: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ospfv3_route_to_proto, spf_route_to_proto, Ospfv3Route, Ospfv3RouteKind,
        OspfRouteKind, SpfRoute,
    };
    use ribd_proto::Source;

    #[test]
    fn spf_route_conversion_intra() {
        let r = SpfRoute {
            prefix: std::net::Ipv4Addr::new(10, 1, 0, 0),
            prefix_len: 24,
            next_hop: std::net::Ipv4Addr::new(172, 30, 0, 1),
            cost: 10,
            sw_if_index: 1,
            kind: OspfRouteKind::Intra,
        };
        let p = spf_route_to_proto(&r, Source::OspfIntra);
        assert_eq!(p.source, Source::OspfIntra);
        assert_eq!(p.metric, 10);
        assert_eq!(p.next_hops.len(), 1);
        assert_eq!(p.next_hops[0].sw_if_index, 1);
        assert_eq!(p.prefix.as_v4(), Some(std::net::Ipv4Addr::new(10, 1, 0, 0)));
        assert_eq!(p.prefix.len, 24);
    }

    #[test]
    fn ospfv3_route_conversion_ecmp() {
        let r = Ospfv3Route {
            prefix: "2001:db8::".parse::<std::net::Ipv6Addr>().unwrap(),
            prefix_len: 64,
            next_hops: vec![
                ("fe80::1".parse().unwrap(), 1),
                ("fe80::2".parse().unwrap(), 2),
            ],
            cost: 20,
            kind: Ospfv3RouteKind::Intra,
        };
        let p = ospfv3_route_to_proto(&r, Source::Ospf6Intra);
        assert_eq!(p.source, Source::Ospf6Intra);
        assert_eq!(p.metric, 20);
        assert_eq!(p.next_hops.len(), 2);
    }
}
