//! Rendering: human tables and JSON for every report. The `Report` enum is
//! the strategy seam — each subcommand produces one, and the caller picks the
//! `--json` or table renderer.

pub(crate) mod table;

use std::fmt::Write as _;

use serde::Serialize;
use serde_json::json;

use crate::analysis::{Asset, DepEdge, FlowTable, Stats};
use crate::app::{AppEvent, DnsRData};
use table::{Align, Table, human_bytes};

/// A finished analysis ready to render as a table, JSON, or DOT.
///
/// Rendering materializes the whole report in memory before writing. That is
/// bounded — entry counts by [`crate::analysis::Limits`] and name lengths at
/// the parsers — but a deliberately cap-saturating capture can make it large
/// (hundreds of MB at the default caps). Lower the caps before raising them
/// for untrusted input; streaming rendering is deliberately not attempted.
#[derive(Debug)]
pub enum Report<'a> {
    Summary(&'a Stats),
    Flows(&'a FlowTable),
    Assets(&'a [&'a Asset]),
    Services(&'a [&'a Asset]),
    Deps(&'a [DepEdge]),
    Dns(&'a [DnsRecord]),
    Dhcp(&'a [DhcpRecord]),
}

/// A flat DNS observation for the `dns` subcommand.
#[derive(Debug, Serialize)]
pub struct DnsRecord {
    /// `"query"` or `"answer"` — the clean discriminator; `kind` carries the
    /// record type and is shared between both roles.
    pub role: &'static str,
    pub kind: &'static str,
    pub name: String,
    pub value: String,
}

/// A flat DHCP observation for the `dhcp` subcommand.
#[derive(Debug, Serialize)]
pub struct DhcpRecord {
    pub msg_type: String,
    pub client_mac: String,
    pub hostname: Option<String>,
    pub assigned_ip: Option<String>,
    pub fingerprint: Option<String>,
    pub vendor_class: Option<String>,
}

impl DnsRecord {
    /// Flatten one DNS event, appending zero or more records to `out`.
    pub fn push_from(event: &AppEvent, out: &mut Vec<Self>) {
        let AppEvent::Dns(dns) = event else { return };
        for query in &dns.queries {
            out.push(Self {
                role: "query",
                kind: dns_type_name(query.qtype),
                name: query.name.clone(),
                value: dns_type_name(query.qtype).to_string(),
            });
        }
        for answer in &dns.answers {
            let (kind, value) = match &answer.data {
                DnsRData::A(ip) => ("A", ip.to_string()),
                DnsRData::Aaaa(ip) => ("AAAA", ip.to_string()),
                DnsRData::Cname(name) => ("CNAME", name.clone()),
                DnsRData::Ptr(name) => ("PTR", name.clone()),
                DnsRData::Srv { port, target } => ("SRV", format!("{target}:{port}")),
                DnsRData::Other { rtype } => ("?", format!("type-{rtype}")),
            };
            out.push(Self {
                role: "answer",
                kind,
                name: answer.name.clone(),
                value,
            });
        }
    }
}

impl DhcpRecord {
    /// Flatten one DHCP event, appending its record to `out`.
    pub fn push_from(event: &AppEvent, out: &mut Vec<Self>) {
        let AppEvent::Dhcp(dhcp) = event else { return };
        out.push(Self {
            msg_type: dhcp.msg_type.to_string(),
            client_mac: dhcp.client_mac.to_string(),
            hostname: dhcp.hostname.clone(),
            assigned_ip: dhcp.your_ip.map(|ip| ip.to_string()),
            fingerprint: (!dhcp.param_req_list.is_empty()).then(|| dhcp.fingerprint()),
            vendor_class: dhcp.vendor_class.clone(),
        });
    }
}

/// Stable JSON envelope version. Bump on any breaking change to the `data`
/// shapes so consumers can version-lock. v3: flow `first_ts`/`last_ts` and
/// asset `first_seen`/`last_seen` are `null` when every sighting came from
/// timestamp-less records (pcapng SPB) — previously a fabricated 1970 epoch;
/// summary gains `clock_inconsistent` and `anomalies.timestampless`, and the
/// degradation envelope gains `timestampless_records`.
pub const JSON_SCHEMA_VERSION: &str = "3";

/// Machine-readable record of everything that degraded this analysis —
/// damaged input, skipped blocks, caps hit. Mirrors the stderr warnings so a
/// JSON consumer can detect partial results without scraping stderr; always
/// present in the envelope (all zeros means the analysis was complete).
#[derive(Debug, Default, Serialize)]
pub struct Degradation {
    /// The capture ended on a record cut short mid-file.
    pub truncated_tail: bool,
    /// Records whose link layer could not be decoded at all.
    pub undecodable_records: u64,
    /// Well-framed pcapng packet blocks with malformed bodies, skipped.
    pub skipped_blocks: u64,
    pub flows_dropped: u64,
    pub assets_dropped: u64,
    pub bindings_dropped: u64,
    pub subnets_dropped: u64,
    pub hostnames_dropped: u64,
    pub services_dropped: u64,
    /// IPs dropped at the per-asset `max_ips_per_asset` cap.
    pub ips_dropped: u64,
    pub dns_records_dropped: u64,
    pub dhcp_records_dropped: u64,
    /// IPs whose MAC binding changed mid-capture — flow attribution for them
    /// uses the final binding and is therefore ambiguous.
    pub ips_rebound: u64,
    /// Records that carry no capture timestamp (pcapng Simple Packet
    /// Blocks); every first/last time and duration excludes them.
    pub timestampless_records: u64,
}

impl Report<'_> {
    /// The subcommand name, used as the JSON envelope discriminator.
    #[must_use]
    pub const fn command_name(&self) -> &'static str {
        match self {
            Self::Summary(_) => "summary",
            Self::Flows(_) => "flows",
            Self::Assets(_) => "assets",
            Self::Services(_) => "services",
            Self::Deps(_) => "deps",
            Self::Dns(_) => "dns",
            Self::Dhcp(_) => "dhcp",
        }
    }

    /// Render as a pretty JSON document wrapped in a stable, versioned
    /// envelope: `{ tool, version, schema, command, degradation, data }`. The
    /// envelope gives every subcommand one discriminated, machine-parseable
    /// shape and a version a consumer can pin — what the mixed bare
    /// arrays/objects lacked. `degradation` is always present so partial
    /// analysis is machine-detectable, not stderr-only.
    pub fn to_json(&self, degradation: &Degradation) -> Result<String, serde_json::Error> {
        let envelope = json!({
            "tool": "pincer",
            "version": env!("CARGO_PKG_VERSION"),
            "schema": JSON_SCHEMA_VERSION,
            "command": self.command_name(),
            "degradation": degradation,
            "data": self.data_json()?,
        });
        serde_json::to_string_pretty(&envelope)
    }

    fn data_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        let value = match self {
            Self::Summary(stats) => json!({
                "packets": stats.packets,
                "bytes": stats.bytes,
                "duration_secs": stats.duration_secs(),
                "first_ts": stats.first_ts,
                "last_ts": stats.last_ts,
                // The same data-quality signal the table note carries — a
                // machine consumer must not have to re-derive it from the span.
                "clock_inconsistent": stats.clock_inconsistent(),
                "link_protocols": stats.link_protocols,
                "transport_protocols": stats.transport_protocols,
                "app_protocols": stats.app_protocols,
                "anomalies": {
                    "truncated": stats.truncated_packets,
                    "malformed": stats.malformed_packets,
                    "undecodable": stats.undecodable,
                    "skipped_blocks": stats.skipped_blocks,
                    "timestampless": stats.timestampless_records,
                },
            }),
            Self::Flows(flows) => {
                let items: Vec<_> = flows
                    .by_bytes()
                    .iter()
                    .map(|flow| {
                        json!({
                            "client": flow.client().to_string(),
                            "server": flow.server().to_string(),
                            "proto": flow.key.proto().to_string(),
                            // null, not the table's "-" sentinel: JSON has a
                            // way to say "unknown" and consumers expect it.
                            "app": (flow.app_label() != "-").then(|| flow.app_label()),
                            "server_name": flow.server_name(),
                            "packets": flow.total_packets(),
                            "bytes": flow.total_bytes(),
                            "bytes_c2s": flow.client_to_server().bytes,
                            "bytes_s2c": flow.server_to_client().bytes,
                            "flags": flow.tcp_flags.to_string(),
                            "confirmed": flow.server_confirmed(),
                            "first_ts": flow.first_ts,
                            "last_ts": flow.last_ts,
                        })
                    })
                    .collect();
                serde_json::Value::Array(items)
            }
            Self::Assets(assets) => serde_json::to_value(assets)?,
            // Match the table semantics: `services` lists hosts that HAVE
            // services, not the whole inventory under a different name.
            Self::Services(assets) => {
                let servers: Vec<_> = assets
                    .iter()
                    .filter(|asset| !asset.services().is_empty())
                    .collect();
                serde_json::to_value(servers)?
            }
            Self::Deps(edges) => serde_json::to_value(edges)?,
            Self::Dns(records) => serde_json::to_value(records)?,
            Self::Dhcp(records) => serde_json::to_value(records)?,
        };
        Ok(value)
    }

    /// Render as a human-readable table / summary block.
    #[must_use]
    pub fn to_table(&self) -> String {
        match self {
            Self::Summary(stats) => render_summary(stats),
            Self::Flows(flows) => render_flows(flows),
            Self::Assets(assets) => render_assets(assets),
            Self::Services(assets) => render_services(assets),
            Self::Deps(edges) => render_deps(edges),
            Self::Dns(records) => render_dns(records),
            Self::Dhcp(records) => render_dhcp(records),
        }
    }
}

/// Render the dependency edges as a Graphviz DOT graph. Confirmed edges
/// (SYN-ACK seen) are solid; inferred ones are dashed.
///
/// Nodes are identified by the asset's unique key (MAC/IP), with the display
/// name carried in the `label` attribute. In DOT the quoted identifier IS the
/// node identity — identifying by display name would merge two distinct
/// assets that share (or forge) a hostname into one node.
#[must_use]
pub fn deps_dot(edges: &[DepEdge]) -> String {
    let mut dot = String::from("digraph dependencies {\n");
    dot.push_str("  rankdir=LR;\n");
    dot.push_str("  node [shape=box, style=rounded, fontname=\"monospace\"];\n");
    dot.push_str("  edge [fontname=\"monospace\", fontsize=10];\n");

    let mut nodes = std::collections::BTreeMap::new();
    for edge in edges {
        nodes.insert(&edge.client, &edge.client_label);
        nodes.insert(&edge.server, &edge.server_label);
    }
    for (key, label) in nodes {
        let _ = writeln!(dot, "  {key:?} [label={label:?}];");
    }

    for edge in edges {
        let service = edge.service.unwrap_or(edge.proto.as_str());
        let style = if edge.confirmed { "solid" } else { "dashed" };
        let bytes = edge.bytes_c2s.saturating_add(edge.bytes_s2c);
        let _ = writeln!(
            dot,
            "  {:?} -> {:?} [label=\"{}/{} {}\", style={}];",
            edge.client,
            edge.server,
            service,
            edge.port,
            human_bytes(bytes),
            style,
        );
    }
    dot.push_str("}\n");
    dot
}

fn render_summary(stats: &Stats) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "packets   {}", stats.packets);
    let _ = writeln!(out, "bytes     {}", human_bytes(stats.bytes));
    let _ = writeln!(out, "duration  {:.3}s", stats.duration_secs());
    if let (Some(first), Some(last)) = (stats.first_ts, stats.last_ts) {
        let _ = writeln!(out, "from      {first}");
        let _ = writeln!(out, "to        {last}");
        if stats.clock_inconsistent() {
            let _ = writeln!(
                out,
                "note      timestamp span exceeds 5 years — capture clock looks inconsistent"
            );
        }
    }
    if stats.timestampless_records > 0 {
        let _ = writeln!(
            out,
            "note      {} record(s) carry no timestamp (pcapng Simple Packet Block); \
             time span and duration exclude them",
            stats.timestampless_records
        );
    }
    let proto_line = |label: &str, map: &std::collections::BTreeMap<&'static str, u64>| {
        let mut parts: Vec<(&str, u64)> = map.iter().map(|(k, v)| (*k, *v)).collect();
        parts.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        let joined: Vec<String> = parts
            .iter()
            .map(|(name, count)| format!("{name}={count}"))
            .collect();
        format!("{label:<9} {}", joined.join(" "))
    };
    if !stats.link_protocols.is_empty() {
        let _ = writeln!(out, "{}", proto_line("network", &stats.link_protocols));
    }
    if !stats.transport_protocols.is_empty() {
        let _ = writeln!(
            out,
            "{}",
            proto_line("transport", &stats.transport_protocols)
        );
    }
    if !stats.app_protocols.is_empty() {
        let _ = writeln!(out, "{}", proto_line("app", &stats.app_protocols));
    }
    let anomalies = stats
        .truncated_packets
        .saturating_add(stats.malformed_packets)
        .saturating_add(stats.undecodable)
        .saturating_add(stats.skipped_blocks);
    if anomalies > 0 {
        let _ = writeln!(
            out,
            "anomalies truncated={} malformed={} undecodable={} skipped_blocks={}",
            stats.truncated_packets,
            stats.malformed_packets,
            stats.undecodable,
            stats.skipped_blocks
        );
    }
    out
}

fn render_flows(flows: &FlowTable) -> String {
    if flows.is_empty() {
        return "no flows\n".to_string();
    }
    let mut table = Table::new(&[
        ("client", Align::Left),
        ("server", Align::Left),
        ("proto", Align::Left),
        ("app", Align::Left),
        ("name", Align::Left),
        ("pkts", Align::Right),
        ("bytes", Align::Right),
        ("flags", Align::Left),
    ]);
    for flow in flows.by_bytes() {
        table.push(vec![
            flow.client().to_string(),
            flow.server().to_string(),
            flow.key.proto().to_string(),
            flow.app_label().to_string(),
            flow.server_name().unwrap_or("-").to_string(),
            flow.total_packets().to_string(),
            human_bytes(flow.total_bytes()),
            flow.tcp_flags.to_string(),
        ]);
    }
    table.render()
}

fn render_assets(assets: &[&Asset]) -> String {
    if assets.is_empty() {
        return "no assets\n".to_string();
    }
    let mut table = Table::new(&[
        ("asset", Align::Left),
        ("name", Align::Left),
        ("ips", Align::Left),
        ("fingerprint", Align::Left),
        ("vendor", Align::Left),
    ]);
    for asset in assets {
        let ips: Vec<String> = asset.ips.iter().map(ToString::to_string).collect();
        table.push(vec![
            asset.key.to_string(),
            asset.display_name(),
            ips.join(", "),
            asset.dhcp_fingerprint.clone().unwrap_or_else(|| "-".into()),
            asset.vendor_class.clone().unwrap_or_else(|| "-".into()),
        ]);
    }
    table.render()
}

fn render_services(assets: &[&Asset]) -> String {
    let mut table = Table::new(&[
        ("asset", Align::Left),
        ("name", Align::Left),
        ("port", Align::Right),
        ("proto", Align::Left),
        ("service", Align::Left),
        ("evidence", Align::Left),
    ]);
    for asset in assets {
        for svc in &asset.services() {
            table.push(vec![
                asset.key.to_string(),
                asset.display_name(),
                svc.port.to_string(),
                svc.proto.to_string(),
                svc.name.unwrap_or("-").to_string(),
                svc.evidence.to_string(),
            ]);
        }
    }
    if table.is_empty() {
        return "no services observed\n".to_string();
    }
    table.render()
}

fn render_deps(edges: &[DepEdge]) -> String {
    if edges.is_empty() {
        return "no dependencies\n".to_string();
    }
    let mut table = Table::new(&[
        ("client", Align::Left),
        ("server", Align::Left),
        ("port", Align::Right),
        ("service", Align::Left),
        ("flows", Align::Right),
        ("c2s", Align::Right),
        ("s2c", Align::Right),
        ("confirmed", Align::Left),
    ]);
    for edge in edges {
        table.push(vec![
            edge.client_label.clone(),
            edge.server_label.clone(),
            edge.port.to_string(),
            edge.service.unwrap_or(edge.proto.as_str()).to_string(),
            edge.flows.to_string(),
            human_bytes(edge.bytes_c2s),
            human_bytes(edge.bytes_s2c),
            if edge.confirmed { "yes" } else { "no" }.to_string(),
        ]);
    }
    table.render()
}

fn render_dns(records: &[DnsRecord]) -> String {
    if records.is_empty() {
        return "no DNS traffic\n".to_string();
    }
    let mut table = Table::new(&[
        ("role", Align::Left),
        ("kind", Align::Left),
        ("name", Align::Left),
        ("value", Align::Left),
    ]);
    for record in records {
        table.push(vec![
            record.role.to_string(),
            record.kind.to_string(),
            record.name.clone(),
            record.value.clone(),
        ]);
    }
    table.render()
}

fn render_dhcp(records: &[DhcpRecord]) -> String {
    if records.is_empty() {
        return "no DHCP traffic\n".to_string();
    }
    let mut table = Table::new(&[
        ("type", Align::Left),
        ("client-mac", Align::Left),
        ("hostname", Align::Left),
        ("assigned", Align::Left),
        ("fingerprint", Align::Left),
        ("vendor", Align::Left),
    ]);
    for record in records {
        table.push(vec![
            record.msg_type.clone(),
            record.client_mac.clone(),
            record.hostname.clone().unwrap_or_else(|| "-".into()),
            record.assigned_ip.clone().unwrap_or_else(|| "-".into()),
            record.fingerprint.clone().unwrap_or_else(|| "-".into()),
            record.vendor_class.clone().unwrap_or_else(|| "-".into()),
        ]);
    }
    table.render()
}

fn dns_type_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(client: &str, client_label: &str, server: &str, server_label: &str) -> DepEdge {
        DepEdge {
            client: client.to_string(),
            client_label: client_label.to_string(),
            server: server.to_string(),
            server_label: server_label.to_string(),
            port: 443,
            proto: "tcp".to_string(),
            service: Some("https"),
            flows: 1,
            bytes_c2s: 10,
            bytes_s2c: 20,
            confirmed: true,
        }
    }

    /// Two distinct assets sharing a display name (mundane: two "iPhone"s;
    /// hostile: malware naming itself after the DC) must stay distinct nodes.
    #[test]
    fn dot_nodes_keyed_by_identity_not_label() {
        let edges = [
            edge("aa:aa:aa:aa:aa:01", "iPhone", "10.0.0.1", "server"),
            edge("aa:aa:aa:aa:aa:02", "iPhone", "10.0.0.1", "server"),
        ];
        let dot = deps_dot(&edges);
        assert!(dot.contains("\"aa:aa:aa:aa:aa:01\" [label=\"iPhone\"];"));
        assert!(dot.contains("\"aa:aa:aa:aa:aa:02\" [label=\"iPhone\"];"));
        assert!(dot.contains("\"aa:aa:aa:aa:aa:01\" -> \"10.0.0.1\""));
        assert!(dot.contains("\"aa:aa:aa:aa:aa:02\" -> \"10.0.0.1\""));
        // exactly one declaration for the shared server node
        assert_eq!(dot.matches("[label=\"server\"];").count(), 1);
    }

    /// A forged hostname carrying DOT syntax must arrive escaped, never as
    /// structure.
    #[test]
    fn dot_labels_escape_quotes() {
        let edges = [edge(
            "aa:aa:aa:aa:aa:03",
            "evil\"];x->y[\"",
            "10.0.0.1",
            "server",
        )];
        let dot = deps_dot(&edges);
        assert!(dot.contains(r#"[label="evil\"];x->y[\""];"#));
    }
}
