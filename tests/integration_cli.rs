//! End-to-end pipeline tests: build the office capture in memory, write it as
//! pcap, read it back through the full reader → decode → analysis pipeline,
//! and assert the conclusions a passive-discovery report must reach.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::net::IpAddr;

use pincer::analysis::{AssetInventory, AssetKey, FlowTable, Observe, Stats, dependency_edges};
use pincer::app::sniff;
use pincer::decode::decode_packet;
use pincer::fixtures::scenarios;
use pincer::pcap::CaptureReader;

/// Run the office scenario through the whole pipeline.
fn analyze_office() -> (Stats, FlowTable, AssetInventory) {
    let frames = scenarios::office();
    let mut bytes = Vec::new();
    scenarios::write_pcap(&frames, &mut bytes).unwrap();

    let mut reader = CaptureReader::new(bytes.as_slice()).unwrap();
    let mut stats = Stats::new();
    let mut flows = FlowTable::new();
    let mut assets = AssetInventory::new();

    while let Some(record) = reader.next_record().unwrap() {
        let pkt = decode_packet(&record).unwrap();
        let app = sniff(&pkt);
        stats.observe(&pkt, app.as_ref());
        flows.observe(&pkt, app.as_ref());
        assets.observe(&pkt, app.as_ref());
    }
    // The CLI always finalizes before reporting (provisional bindings resolve
    // there); test the state that actually ships.
    assets.finalize();
    (stats, flows, assets)
}

#[test]
fn summary_counts_every_packet_with_no_anomalies() {
    let (stats, _, _) = analyze_office();
    assert_eq!(stats.packets, scenarios::office().len() as u64);
    assert_eq!(
        stats.malformed_packets, 0,
        "office capture must decode cleanly"
    );
    assert_eq!(stats.undecodable, 0);
    assert_eq!(stats.truncated_packets, 0);
    assert_eq!(stats.link_protocols.get("arp"), Some(&2));
    assert!(stats.app_protocols.contains_key("dhcp"));
    assert!(stats.app_protocols.contains_key("tls"));
}

#[test]
fn dhcp_hostname_lands_on_the_laptop_asset() {
    let (_, _, assets) = analyze_office();
    let laptop = assets
        .assets()
        .into_iter()
        .find(|a| a.key == AssetKey::Mac(scenarios::MAC_LAPTOP))
        .expect("laptop asset keyed by its MAC");

    assert!(laptop.ips.contains(&IpAddr::V4(scenarios::IP_LAPTOP)));
    assert!(laptop.hostnames.keys().any(|h| h == "carols-laptop"));
    assert_eq!(laptop.dhcp_fingerprint.as_deref(), Some("1,3,6,15,119,252"));
    assert_eq!(laptop.vendor_class.as_deref(), Some("MSFT 5.0"));
}

#[test]
fn off_link_host_is_ip_keyed_not_merged_into_the_gateway() {
    let (_, _, assets) = analyze_office();
    let keys: Vec<AssetKey> = assets.assets().into_iter().map(|a| a.key).collect();

    // example.com is remote: it must be its own IP-keyed asset...
    assert!(
        keys.iter()
            .any(|k| k == &AssetKey::Ip(std::net::IpAddr::V4(scenarios::IP_EXAMPLE)))
    );
    // ...and the gateway MAC must NOT have absorbed it.
    let gateway = assets
        .assets()
        .into_iter()
        .find(|a| a.key == AssetKey::Mac(scenarios::MAC_GATEWAY))
        .expect("gateway asset");
    assert!(
        !gateway.ips.contains(&IpAddr::V4(scenarios::IP_EXAMPLE)),
        "router MAC must not be bound to off-link IPs"
    );
    assert_eq!(gateway.ips.len(), 1, "gateway holds only its own IP");
}

#[test]
fn tls_sni_names_the_https_service() {
    let (_, _, assets) = analyze_office();
    let example = assets
        .assets()
        .into_iter()
        .find(|a| a.key == AssetKey::Ip(std::net::IpAddr::V4(scenarios::IP_EXAMPLE)))
        .expect("example.com asset");
    assert!(example.hostnames.keys().any(|h| h == "example.com"));
}

#[test]
fn dependency_map_has_the_laptop_to_https_edge_with_sni() {
    let (_, flows, assets) = analyze_office();
    let edges = dependency_edges(&flows, &assets);

    let https = edges
        .iter()
        .find(|e| e.server_label == "example.com" && e.port == 443)
        .expect("laptop -> example.com:443 edge");
    assert_eq!(https.client_label, "carols-laptop");
    assert!(
        https.confirmed,
        "SYN-ACK was observed, so the service is confirmed"
    );
    assert_eq!(https.service, Some("https"));

    // SSH and HTTP edges to the intranet server must also be present.
    assert!(
        edges
            .iter()
            .any(|e| e.server_label == "intranet.local" && e.port == 22)
    );
    assert!(
        edges
            .iter()
            .any(|e| e.server_label == "intranet.local" && e.port == 80)
    );

    // DHCP broadcast / mDNS multicast must NOT appear as dependency edges.
    assert!(
        !edges.iter().any(|e| e.port == 67 || e.port == 5353),
        "broadcast/multicast discovery chatter is not a dependency"
    );
}

#[test]
fn ssh_flow_is_detected_by_port_without_a_decoder() {
    let (_, flows, _) = analyze_office();
    let ssh = flows
        .iter()
        .find(|f| f.server().port == 22)
        .expect("ssh flow");
    assert_eq!(ssh.app_label(), "ssh");
    assert!(ssh.server_confirmed());
    assert_eq!(ssh.client().ip, IpAddr::V4(scenarios::IP_LAPTOP));
}

#[test]
fn committed_samples_match_the_generator() {
    // The committed testdata/*.pcap must be byte-identical to what the fixture
    // builder produces now — so the samples can never silently drift from the
    // code that documents them. Regenerate with `cargo run -- gen testdata`.
    for (name, frames) in [
        ("office.pcap", scenarios::office()),
        ("incident.pcap", scenarios::incident()),
    ] {
        let mut expected = Vec::new();
        scenarios::write_pcap(&frames, &mut expected).unwrap();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/");
        let committed = std::fs::read(format!("{path}{name}"))
            .unwrap_or_else(|_| panic!("missing testdata/{name}; run `cargo run -- gen testdata`"));
        assert_eq!(
            committed, expected,
            "testdata/{name} is stale; regenerate with `cargo run -- gen testdata`"
        );
    }
}

#[test]
fn incident_capture_surfaces_the_scanner() {
    let frames = scenarios::incident();
    let mut bytes = Vec::new();
    scenarios::write_pcap(&frames, &mut bytes).unwrap();
    let mut reader = CaptureReader::new(bytes.as_slice()).unwrap();
    let mut flows = FlowTable::new();
    while let Some(record) = reader.next_record().unwrap() {
        let pkt = decode_packet(&record).unwrap();
        let app = sniff(&pkt);
        flows.observe(&pkt, app.as_ref());
    }
    // The scanner touches many distinct ports on the server: count flows whose
    // client is the scanner IP.
    let scanner_flows = flows
        .iter()
        .filter(|f| f.client().ip == IpAddr::V4(scenarios::IP_SCANNER))
        .count();
    assert!(
        scanner_flows >= 12,
        "SYN scan should create many flows, got {scanner_flows}"
    );
}
