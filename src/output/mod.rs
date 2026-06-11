//! Rendering: human tables and JSON for every report. The `Report` enum is
//! the strategy seam — each subcommand produces one, and the caller picks the
//! `--json` or table renderer.

pub(crate) mod table;

use std::fmt::Write as _;

use serde::Serialize;

use crate::analysis::{Asset, DepEdge, Flow, FlowTable, Stats};
use crate::app::{AppEvent, DnsRData};
use crate::types::Timestamp;
use table::{Align, Table, human_bytes};

/// A finished analysis ready to render as a table, JSON, or DOT.
///
/// JSON rendering streams: [`Report::write_json`] serializes the envelope
/// straight into the output writer, so its peak memory is the analysis state
/// plus a serializer buffer — never an intermediate `serde_json::Value` tree
/// or a second full `String` (those measured in the GBs on a cap-saturating
/// capture). Table and DOT rendering still materialize the whole string
/// before writing; that is bounded — entry counts by
/// [`crate::analysis::Limits`] and name lengths at the parsers — but a
/// deliberately cap-saturating capture can push it to hundreds of MB. Lower
/// the caps before raising them for untrusted input.
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
    /// How many records [`Self::push_from`] would append for this event,
    /// counted without building them — keeps the post-cap drop accounting
    /// record-exact (a multi-answer event is not "one drop") at zero
    /// allocation.
    #[must_use]
    pub fn count_from(event: &AppEvent) -> usize {
        let AppEvent::Dns(dns) = event else { return 0 };
        dns.queries.len().saturating_add(dns.answers.len())
    }

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
    /// The DHCP twin of [`DnsRecord::count_from`]: one record per event.
    #[must_use]
    pub fn count_from(event: &AppEvent) -> usize {
        usize::from(matches!(event, AppEvent::Dhcp(_)))
    }

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
/// degradation envelope gains `timestampless_records`. v4: a corrupt
/// mid-stream section header (concatenated pcapng) yields a flagged partial
/// result — the degradation envelope gains `damaged_section` — where it
/// previously discarded the whole run with an error. v5: the envelope
/// serializes in a fixed byte order with `degradation` before `data` (a
/// truncated document's salvaged prefix can never contain data without its
/// degradation record), and objects emit keys in declaration order instead
/// of alphabetically — field names, types, and values are unchanged.
pub const JSON_SCHEMA_VERSION: &str = "5";

/// Machine-readable record of everything that degraded this analysis —
/// damaged input, skipped blocks, caps hit. Mirrors the stderr warnings so a
/// JSON consumer can detect partial results without scraping stderr; always
/// present in the envelope (all zeros means the analysis was complete).
#[derive(Debug, Default, Serialize)]
pub struct Degradation {
    /// The capture ended on a record cut short mid-file.
    pub truncated_tail: bool,
    /// A mid-stream section header (concatenated pcapng) was corrupt; the
    /// analysis covers only the sections before it.
    pub damaged_section: bool,
    /// Records whose link layer could not be decoded at all.
    pub undecodable_records: u64,
    /// Well-framed pcapng packet blocks with malformed bodies, skipped.
    pub skipped_blocks: u64,
    /// Packets belonging to flows beyond the `max_flows` cap — refused
    /// packets plus the accumulated packets of evicted flows; exactly the
    /// packets of flows missing from the report, in any packet order.
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

impl Degradation {
    /// True when anything degraded the analysis — the single switch behind
    /// the table/DOT `PARTIAL` markers and `--strict`'s exit code.
    #[must_use]
    pub fn any(&self) -> bool {
        !self.reasons().is_empty()
    }

    /// The nonzero fields, named exactly as the JSON envelope names them, for
    /// the in-band `PARTIAL` markers. Field order is fixed so marker lines
    /// stay snapshot-testable.
    fn reasons(&self) -> Vec<String> {
        let mut parts = Vec::new();
        if self.truncated_tail {
            parts.push("truncated_tail".to_string());
        }
        if self.damaged_section {
            parts.push("damaged_section".to_string());
        }
        for (name, count) in [
            ("undecodable_records", self.undecodable_records),
            ("skipped_blocks", self.skipped_blocks),
            ("flows_dropped", self.flows_dropped),
            ("assets_dropped", self.assets_dropped),
            ("bindings_dropped", self.bindings_dropped),
            ("subnets_dropped", self.subnets_dropped),
            ("hostnames_dropped", self.hostnames_dropped),
            ("services_dropped", self.services_dropped),
            ("ips_dropped", self.ips_dropped),
            ("dns_records_dropped", self.dns_records_dropped),
            ("dhcp_records_dropped", self.dhcp_records_dropped),
            ("ips_rebound", self.ips_rebound),
            ("timestampless_records", self.timestampless_records),
        ] {
            if count > 0 {
                parts.push(format!("{name}={count}"));
            }
        }
        parts
    }
}

/// One-line status shared by the table footer and the DOT header:
/// `complete`, or `PARTIAL — <nonzero degradation fields>`.
fn status_marker(degradation: &Degradation) -> String {
    let reasons = degradation.reasons();
    if reasons.is_empty() {
        "complete".to_string()
    } else {
        format!("PARTIAL — {}", reasons.join(", "))
    }
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

    /// Write the report as a pretty JSON document wrapped in a stable,
    /// versioned envelope: `{ tool, version, schema, command, degradation,
    /// data }`, in exactly that byte order — `degradation` before `data`, so
    /// a truncated document's salvaged prefix can never contain data without
    /// its degradation record. The envelope gives every subcommand one
    /// discriminated, machine-parseable shape and a version a consumer can
    /// pin. `data` streams straight from the analysis structures into the
    /// writer; nothing is materialized.
    pub fn write_json<W: std::io::Write>(
        &self,
        degradation: &Degradation,
        writer: W,
    ) -> Result<(), serde_json::Error> {
        serde_json::to_writer_pretty(
            writer,
            &Envelope {
                tool: "pincer",
                version: env!("CARGO_PKG_VERSION"),
                schema: JSON_SCHEMA_VERSION,
                command: self.command_name(),
                degradation,
                data: DataView(self),
            },
        )
    }

    /// Render as a human-readable table / summary block. The final line is
    /// always a `# pincer: …` footer — the in-band completion marker that
    /// makes a pipe-truncated table distinguishable from a complete smaller
    /// one — carrying the row count and `complete` or `PARTIAL — <reasons>`.
    #[must_use]
    pub fn to_table(&self, degradation: &Degradation) -> String {
        let (mut out, rows) = match self {
            Self::Summary(stats) => (render_summary(stats), None),
            Self::Flows(flows) => (render_flows(flows), Some(flows.len())),
            Self::Assets(assets) => (render_assets(assets), Some(assets.len())),
            Self::Services(assets) => {
                let (out, rows) = render_services(assets);
                (out, Some(rows))
            }
            Self::Deps(edges) => (render_deps(edges), Some(edges.len())),
            Self::Dns(records) => (render_dns(records), Some(records.len())),
            Self::Dhcp(records) => (render_dhcp(records), Some(records.len())),
        };
        let marker = status_marker(degradation);
        match rows {
            Some(rows) => {
                let _ = writeln!(out, "# pincer: {rows} row(s), {marker}");
            }
            None => {
                let _ = writeln!(out, "# pincer: {marker}");
            }
        }
        out
    }
}

/// The JSON envelope. Field declaration order IS the byte order on the wire
/// (serde structs serialize in declaration order): `degradation` must come
/// before `data` — see [`Report::write_json`].
#[derive(Serialize)]
struct Envelope<'a> {
    tool: &'static str,
    version: &'static str,
    schema: &'static str,
    command: &'static str,
    degradation: &'a Degradation,
    data: DataView<'a>,
}

/// Lazily serializes the report's `data` field straight into the writer — no
/// intermediate `serde_json::Value` tree, no second full `String`. At cap
/// scale the tree alone measured in the GBs; streaming keeps rendering at the
/// cost of a serializer buffer.
struct DataView<'a>(&'a Report<'a>);

impl Serialize for DataView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Report::Summary(stats) => SummaryData {
                packets: stats.packets,
                bytes: stats.bytes,
                duration_secs: stats.duration_secs(),
                first_ts: stats.first_ts,
                last_ts: stats.last_ts,
                clock_inconsistent: stats.clock_inconsistent(),
                link_protocols: &stats.link_protocols,
                transport_protocols: &stats.transport_protocols,
                app_protocols: &stats.app_protocols,
                anomalies: Anomalies {
                    truncated: stats.truncated_packets,
                    malformed: stats.malformed_packets,
                    undecodable: stats.undecodable,
                    skipped_blocks: stats.skipped_blocks,
                    timestampless: stats.timestampless_records,
                },
            }
            .serialize(serializer),
            Report::Flows(flows) => {
                serializer.collect_seq(flows.by_bytes().into_iter().map(FlowRow))
            }
            Report::Assets(assets) => serializer.collect_seq(assets.iter()),
            // Match the table semantics: `services` lists hosts that HAVE
            // services, not the whole inventory under a different name.
            Report::Services(assets) => {
                serializer.collect_seq(assets.iter().filter(|asset| !asset.services().is_empty()))
            }
            Report::Deps(edges) => serializer.collect_seq(edges.iter()),
            Report::Dns(records) => serializer.collect_seq(records.iter()),
            Report::Dhcp(records) => serializer.collect_seq(records.iter()),
        }
    }
}

/// The summary `data` object — small and fixed-size, so a plain derive.
#[derive(Serialize)]
struct SummaryData<'a> {
    packets: u64,
    bytes: u64,
    duration_secs: f64,
    first_ts: Option<Timestamp>,
    last_ts: Option<Timestamp>,
    /// The same data-quality signal the table note carries — a machine
    /// consumer must not have to re-derive it from the span.
    clock_inconsistent: bool,
    link_protocols: &'a std::collections::BTreeMap<&'static str, u64>,
    transport_protocols: &'a std::collections::BTreeMap<&'static str, u64>,
    app_protocols: &'a std::collections::BTreeMap<&'static str, u64>,
    anomalies: Anomalies,
}

#[derive(Serialize)]
struct Anomalies {
    truncated: u64,
    malformed: u64,
    undecodable: u64,
    skipped_blocks: u64,
    timestampless: u64,
}

/// One flow as the locked JSON row shape. Manual impl so the hot path
/// allocates nothing per flow — `Display` types format straight into the
/// serializer via [`AsStr`].
struct FlowRow<'a>(&'a Flow);

impl Serialize for FlowRow<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let flow = self.0;
        let mut row = serializer.serialize_struct("Flow", 13)?;
        row.serialize_field("client", &AsStr(flow.client()))?;
        row.serialize_field("server", &AsStr(flow.server()))?;
        row.serialize_field("proto", &flow.key.proto())?;
        // null, not the table's "-" sentinel: JSON has a way to say
        // "unknown" and consumers expect it.
        row.serialize_field("app", &(flow.app_label() != "-").then(|| flow.app_label()))?;
        row.serialize_field("server_name", &flow.server_name())?;
        row.serialize_field("packets", &flow.total_packets())?;
        row.serialize_field("bytes", &flow.total_bytes())?;
        row.serialize_field("bytes_c2s", &flow.client_to_server().bytes)?;
        row.serialize_field("bytes_s2c", &flow.server_to_client().bytes)?;
        row.serialize_field("flags", &AsStr(flow.tcp_flags))?;
        row.serialize_field("confirmed", &flow.server_confirmed())?;
        row.serialize_field("first_ts", &flow.first_ts)?;
        row.serialize_field("last_ts", &flow.last_ts)?;
        row.end()
    }
}

/// Serialize any `Display` as a JSON string with no intermediate `String`.
struct AsStr<T>(T);

impl<T: std::fmt::Display> Serialize for AsStr<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

/// Render the dependency edges as a Graphviz DOT graph. Confirmed edges
/// (SYN-ACK seen) are solid; inferred ones are dashed.
///
/// Nodes are identified by the asset's unique key (MAC/IP), with the display
/// name carried in the `label` attribute. In DOT the quoted identifier IS the
/// node identity — identifying by display name would merge two distinct
/// assets that share (or forge) a hostname into one node.
///
/// A degraded analysis prepends a `// pincer: PARTIAL — <reasons>` comment:
/// a saved or piped graph must not need stderr or the exit code to say the
/// map is incomplete.
#[must_use]
pub fn deps_dot(edges: &[DepEdge], degradation: &Degradation) -> String {
    let mut dot = String::new();
    if degradation.any() {
        let _ = writeln!(dot, "// pincer: {}", status_marker(degradation));
    }
    dot.push_str("digraph dependencies {\n");
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

/// Returns the rendered table and its row count (rows are per service, not
/// per asset, so the caller cannot derive the count from the slice).
fn render_services(assets: &[&Asset]) -> (String, usize) {
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
        return ("no services observed\n".to_string(), 0);
    }
    let rows = table.len();
    (table.render(), rows)
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
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

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
        let dot = deps_dot(&edges, &Degradation::default());
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
        let dot = deps_dot(&edges, &Degradation::default());
        assert!(dot.contains(r#"[label="evil\"];x->y[\""];"#));
    }

    /// A clean run renders an unmarked graph; a degraded one leads with the
    /// `PARTIAL` comment naming the envelope fields that fired.
    #[test]
    fn dot_partial_header_appears_exactly_when_degraded() {
        let edges = [edge("aa:aa:aa:aa:aa:01", "client", "10.0.0.1", "server")];
        let clean = deps_dot(&edges, &Degradation::default());
        assert!(clean.starts_with("digraph dependencies {"));
        assert!(!clean.contains("PARTIAL"));

        let degradation = Degradation {
            truncated_tail: true,
            flows_dropped: 5,
            ..Degradation::default()
        };
        let partial = deps_dot(&edges, &degradation);
        let first = partial.lines().next().unwrap();
        assert_eq!(
            first,
            "// pincer: PARTIAL — truncated_tail, flows_dropped=5"
        );
        assert!(partial.contains("digraph dependencies {"));
        assert!(partial.trim_end().ends_with('}'));
    }

    /// Every table ends with the completion footer — row count plus
    /// `complete` or the `PARTIAL` reasons — even when the report is empty.
    #[test]
    fn table_footer_marks_completion_and_degradation() {
        let records: Vec<DnsRecord> = Vec::new();
        let report = Report::Dns(&records);
        let clean = report.to_table(&Degradation::default());
        assert!(clean.starts_with("no DNS traffic\n"));
        assert!(clean.ends_with("# pincer: 0 row(s), complete\n"));

        let degradation = Degradation {
            dns_records_dropped: 3,
            ..Degradation::default()
        };
        let partial = report.to_table(&degradation);
        assert!(partial.ends_with("# pincer: 0 row(s), PARTIAL — dns_records_dropped=3\n"));
    }

    /// The streamed envelope is valid JSON whose `degradation` bytes precede
    /// `data` — a salvaged prefix can never carry data without its
    /// degradation record.
    #[test]
    fn json_envelope_streams_degradation_before_data() {
        let records = vec![DnsRecord {
            role: "query",
            kind: "A",
            name: "example.com".to_string(),
            value: "A".to_string(),
        }];
        let report = Report::Dns(&records);
        let mut out = Vec::new();
        report
            .write_json(&Degradation::default(), &mut out)
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        let degradation_at = text.find("\"degradation\"").unwrap();
        let data_at = text.find("\"data\"").unwrap();
        assert!(degradation_at < data_at, "salvage-safe field order: {text}");

        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["schema"], JSON_SCHEMA_VERSION);
        assert_eq!(json["data"][0]["name"], "example.com");
    }
}
