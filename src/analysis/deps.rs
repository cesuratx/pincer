//! Application dependency map: client-asset → server-asset:port edges, derived
//! from the completed flow table and resolved against the asset inventory.
//! This is the "application dependency map" a passive sensor builds from flows.

use serde::Serialize;

use super::flows::FlowTable;
use super::{AssetInventory, AssetKey, service_name};
use crate::types::IpProto;

#[derive(Debug, Clone, Serialize)]
pub struct DepEdge {
    pub client: String,
    pub client_label: String,
    pub server: String,
    pub server_label: String,
    pub port: u16,
    pub proto: String,
    pub service: Option<&'static str>,
    pub flows: u64,
    pub bytes_c2s: u64,
    pub bytes_s2c: u64,
    /// At least one flow saw a SYN-ACK from the server.
    pub confirmed: bool,
}

/// Build dependency edges, aggregating multiple flows between the same
/// client/server/port into one edge. Client/server roles come from each
/// flow's initiator heuristic; identities resolve through the inventory so a
/// host keyed by MAC and by IP collapses to one node.
///
/// Known limitation: identity resolution uses the inventory's *final*
/// IP→MAC bindings. If an IP changed hands mid-capture (DHCP churn, VRRP
/// failover), all of its flows — including those from the earlier holder —
/// attribute to the final one. The inventory counts these as
/// `AssetOverflow::rebound_ips` and the CLI surfaces them in the degradation
/// report, so the ambiguity is visible rather than silent.
#[must_use]
pub fn dependency_edges(flows: &FlowTable, inventory: &AssetInventory) -> Vec<DepEdge> {
    use std::collections::BTreeMap;

    // Resolve each asset key to its display label exactly once. Previously
    // label_for re-collected and re-sorted the whole inventory per edge —
    // O(edges · assets·log assets); this is O(assets) up front, O(1) per edge.
    let labels: BTreeMap<AssetKey, String> = inventory
        .assets()
        .into_iter()
        .map(|asset| (asset.key, asset.display_name()))
        .collect();
    let label_for = |key: AssetKey, ip: std::net::IpAddr| {
        labels.get(&key).cloned().unwrap_or_else(|| ip.to_string())
    };

    // Key edges by (client-key, server-key, port, proto). AssetKey is Copy, so
    // keying edges no longer clones a String per flow.
    let mut edges: BTreeMap<(AssetKey, AssetKey, u16, IpProto), DepEdge> = BTreeMap::new();

    for flow in flows.iter() {
        let proto = flow.key.proto();
        // Only connection-oriented or port-bearing flows make sense as deps.
        if !matches!(proto, IpProto::Tcp | IpProto::Udp | IpProto::Sctp) {
            continue;
        }
        let client = flow.client();
        let server = flow.server();
        // A dependency is host-to-host: drop broadcast/multicast/unspecified
        // endpoints (DHCP broadcast, mDNS multicast) — they are discovery
        // chatter, visible in `flows`, but not edges in a dependency graph.
        if is_non_unicast(client.ip) || is_non_unicast(server.ip) {
            continue;
        }
        let client_key = inventory.key_for_ip(client.ip);
        let server_key = inventory.key_for_ip(server.ip);
        if client_key == server_key {
            continue; // ignore self-talk
        }

        let c2s = flow.client_to_server();
        let s2c = flow.server_to_client();
        let entry = edges
            .entry((client_key, server_key, server.port, proto))
            .or_insert_with(|| DepEdge {
                client: client_key.to_string(),
                client_label: label_for(client_key, client.ip),
                server: server_key.to_string(),
                server_label: label_for(server_key, server.ip),
                port: server.port,
                proto: proto.to_string(),
                service: service_name(server.port),
                flows: 0,
                bytes_c2s: 0,
                bytes_s2c: 0,
                confirmed: false,
            });
        entry.flows = entry.flows.saturating_add(1);
        entry.bytes_c2s = entry.bytes_c2s.saturating_add(c2s.bytes);
        entry.bytes_s2c = entry.bytes_s2c.saturating_add(s2c.bytes);
        entry.confirmed |= flow.server_confirmed();
    }

    let mut out: Vec<DepEdge> = edges.into_values().collect();
    out.sort_by(|x, y| {
        let total_x = x.bytes_c2s.saturating_add(x.bytes_s2c);
        let total_y = y.bytes_c2s.saturating_add(y.bytes_s2c);
        total_y.cmp(&total_x).then(x.client.cmp(&y.client))
    });
    out
}

/// Broadcast, multicast, or unspecified — not a unicast peer.
fn is_non_unicast(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast(),
        std::net::IpAddr::V6(v6) => v6.is_unspecified() || v6.is_multicast(),
    }
}
