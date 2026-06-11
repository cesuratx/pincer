//! Determinism under caps: the report must be a function of the packet SET,
//! not the arrival order, even when `analysis::Limits` caps engage (the
//! hostile case — exactly when reproducible, diffable output matters most).
//! Caps admit by key order: at a cap, a new key replaces the largest admitted
//! one only if it sorts before it, so the survivors are always the N smallest
//! keys the capture offered. These tests permute cap-exceeding captures and
//! assert byte-identical *rendered* output — tables with their footers, full
//! JSON envelopes, and the degradation object — not just equal counts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr};

use pincer::analysis::{AssetInventory, AssetKey, FlowTable, Limits, Observe, dependency_edges};
use pincer::app::sniff;
use pincer::decode::decode_packet;
use pincer::fixtures::{self, Packet};
use pincer::output::{Degradation, Report};
use pincer::pcap::{LinkType, Record};
use pincer::types::{MacAddr, Timestamp};
use proptest::prelude::*;

type Frames = Vec<(Timestamp, Vec<u8>)>;

fn ts(i: u64) -> Timestamp {
    Timestamp::new(1_700_000_000 + i, 0)
}

/// Stream every frame through both analysis sinks under `Limits::tiny`, the
/// way the CLI pipeline does, including the finalize step.
fn run_sinks(frames: &[(Timestamp, Vec<u8>)]) -> (FlowTable, AssetInventory) {
    let mut flows = FlowTable::with_limits(Limits::tiny());
    let mut assets = AssetInventory::with_limits(Limits::tiny());
    for (ts, frame) in frames {
        let record = Record {
            ts: Some(*ts),
            orig_len: u32::try_from(frame.len()).unwrap(),
            link_type: LinkType::Ethernet,
            data: frame,
        };
        let Ok(pkt) = decode_packet(&record) else {
            continue;
        };
        let app = sniff(&pkt);
        flows.observe(&pkt, app.as_ref());
        assets.observe(&pkt, app.as_ref());
    }
    assets.finalize();
    (flows, assets)
}

/// Every artifact the CLI can emit for these sinks — flows, assets, services,
/// deps — rendered as both the table (footer included) and the full JSON
/// envelope (degradation object included). Byte equality of this string IS
/// report equality.
fn render_everything(frames: &[(Timestamp, Vec<u8>)]) -> String {
    let (flows, assets) = run_sinks(frames);
    let asset_refs = assets.assets();
    let edges = dependency_edges(&flows, &assets);
    let of = assets.overflow();
    let degradation = Degradation {
        flows_dropped: flows.dropped(),
        assets_dropped: of.assets,
        bindings_dropped: of.bindings,
        subnets_dropped: of.subnets,
        hostnames_dropped: of.hostnames,
        services_dropped: of.services,
        ips_dropped: of.ips,
        ips_rebound: of.rebound_ips,
        ..Degradation::default()
    };
    let mut out = String::new();
    for report in [
        Report::Flows(&flows),
        Report::Assets(&asset_refs),
        Report::Services(&asset_refs),
        Report::Deps(&edges),
    ] {
        out.push_str(&report.to_table(&degradation));
        let mut json = Vec::new();
        report
            .write_json(&degradation, &mut json)
            .expect("json renders");
        out.push_str(&String::from_utf8(json).expect("utf8 json"));
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// Cap-exceeding captures. Each frame carries its own fixed timestamp, so a
// permutation changes only the processing order, never the packet facts; the
// timestamps double as the canonical sort key. One evidence event per capped
// identity keeps the overflow counters order-exact, so even the degradation
// JSON must match byte-for-byte.
// ---------------------------------------------------------------------------

/// 20 distinct TCP flows (cap 8) from one client to one server:443 — a SYN
/// plus one data segment each, so direction is evidence-determined and every
/// dropped flow is worth exactly two packets.
fn flow_flood() -> Frames {
    let client = MacAddr([2, 0, 0, 0, 0, 1]);
    let server = MacAddr([2, 0, 0, 0, 0, 2]);
    let (cip, sip) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
    let mut frames = Frames::new();
    for i in 0..20u16 {
        let port = 49100 + i;
        frames.push((
            ts(u64::from(i) * 2),
            Packet::ethernet(client, server)
                .ipv4(cip, sip)
                .tcp(port, 443)
                .syn()
                .build(),
        ));
        frames.push((
            ts(u64::from(i) * 2 + 1),
            Packet::ethernet(client, server)
                .ipv4(cip, sip)
                .tcp(port, 443)
                .payload(b"hello"),
        ));
    }
    frames
}

/// 20 distinct off-link servers (asset cap 8), each proving one service with
/// a single SYN-ACK. The client IP sorts below every server so its repeated
/// provisional sightings never churn the candidate cap.
fn asset_flood() -> Frames {
    let client = MacAddr([2, 0, 0, 0, 0, 9]);
    let cip = Ipv4Addr::new(10, 0, 0, 9);
    (0..20u8)
        .map(|i| {
            let smac = MacAddr([2, 0, 0, 0, 1, i]);
            let sip = Ipv4Addr::new(203, 0, 113, i);
            (
                ts(u64::from(i)),
                Packet::ethernet(smac, client)
                    .ipv4(sip, cip)
                    .tcp(443, 51000 + u16::from(i))
                    .syn_ack()
                    .build(),
            )
        })
        .collect()
}

/// 20 ARP announces from 20 hosts on 20 distinct /24s: the asset (8),
/// binding (8), and subnet (4) caps all engage at once, one offer per
/// identity.
fn arp_storm() -> Frames {
    (0..20u8)
        .map(|i| {
            let mac = MacAddr([2, 0, 0, 0, 2, i]);
            (
                ts(u64::from(i)),
                Packet::ethernet(mac, MacAddr::BROADCAST)
                    .arp_request(Ipv4Addr::new(10, 0, i, 5), Ipv4Addr::new(10, 0, i, 1)),
            )
        })
        .collect()
}

/// The audit's evidence shape: 20 local hosts seen only as data frames, on a
/// /16 taught by a single DHCP ACK that can land anywhere in the shuffle.
/// Engages the provisional-candidate and flow caps; finalize must key the
/// same hosts by MAC whether the subnet lesson arrived first or last.
fn local_host_flood() -> Frames {
    let server_mac = MacAddr([2, 0, 0, 0, 0, 1]);
    let client_mac = MacAddr([2, 0, 0, 0, 0, 0xC8]);
    let router_mac = MacAddr([2, 0, 0, 0, 0, 0xFE]);
    let mut frames = Frames::new();
    let opts = fixtures::DhcpOptions {
        your_ip: Some(Ipv4Addr::new(10, 0, 0, 200)),
        subnet_mask: Some(Ipv4Addr::new(255, 255, 0, 0)),
        ..fixtures::DhcpOptions::default()
    };
    frames.push((
        ts(100),
        Packet::ethernet(server_mac, MacAddr::BROADCAST)
            .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::BROADCAST)
            .udp(67, 68)
            .payload(&fixtures::dhcp(5, client_mac, 0x42, &opts)),
    ));
    for i in 0..20u8 {
        let mac = MacAddr([2, 0, 0, 0, 1, i]);
        frames.push((
            ts(200 + u64::from(i)),
            Packet::ethernet(mac, router_mac)
                .ipv4(
                    Ipv4Addr::new(10, 0, 0, 10 + i),
                    // Off-link, and smaller than every local IP, so the
                    // shared destination always survives the candidate cap
                    // instead of churning it order-dependently.
                    Ipv4Addr::new(8, 8, 8, 8),
                )
                .udp(40000 + u16::from(i), 40001)
                .payload(b"x"),
        ));
    }
    frames
}

/// One local IP whose data frames carry two different source MACs (DHCP
/// lease churn mid-capture, or spoofing), on a /16 taught by a DHCP ACK that
/// can land anywhere in the shuffle. The winning identity (the smaller MAC)
/// and the counted rebind ambiguity must not depend on arrival order — the
/// contest is resolved per IP at finalize, so even the counter is exact.
fn mac_conflict_churn() -> Frames {
    let server_mac = MacAddr([2, 0, 0, 0, 0, 1]);
    let client_mac = MacAddr([2, 0, 0, 0, 0, 0xC8]);
    let router_mac = MacAddr([2, 0, 0, 0, 0, 0xFE]);
    let mut frames = Frames::new();
    let opts = fixtures::DhcpOptions {
        your_ip: Some(Ipv4Addr::new(10, 0, 0, 200)),
        subnet_mask: Some(Ipv4Addr::new(255, 255, 0, 0)),
        ..fixtures::DhcpOptions::default()
    };
    frames.push((
        ts(100),
        Packet::ethernet(server_mac, MacAddr::BROADCAST)
            .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::BROADCAST)
            .udp(67, 68)
            .payload(&fixtures::dhcp(5, client_mac, 0x42, &opts)),
    ));
    for (i, mac) in [
        MacAddr([2, 0, 0, 0, 0xAA, 1]),
        MacAddr([2, 0, 0, 0, 0xBB, 2]),
    ]
    .into_iter()
    .enumerate()
    {
        frames.push((
            ts(200 + i as u64),
            Packet::ethernet(mac, router_mac)
                .ipv4(Ipv4Addr::new(10, 0, 5, 5), Ipv4Addr::new(8, 8, 8, 8))
                .udp(40000, 40001)
                .payload(b"x"),
        ));
    }
    frames
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// THE determinism contract: any permutation of the same packet multiset
    /// renders byte-identical reports, caps engaged and all.
    #[test]
    fn shuffled_hostile_captures_render_identical_reports(
        shuffled in prop_oneof![
            Just(flow_flood()).prop_shuffle(),
            Just(asset_flood()).prop_shuffle(),
            Just(arp_storm()).prop_shuffle(),
            Just(local_host_flood()).prop_shuffle(),
            Just(mac_conflict_churn()).prop_shuffle(),
        ]
    ) {
        let mut canonical = shuffled.clone();
        canonical.sort_by_key(|(ts, _)| *ts);
        prop_assert_eq!(
            render_everything(&canonical),
            render_everything(&shuffled),
            "a permutation must not change any rendered artifact"
        );
    }
}

/// The permutation generators must actually ENGAGE the caps they claim to —
/// otherwise the identity assertions above prove nothing about capped runs.
#[test]
fn permutation_generators_engage_their_caps() {
    let (flows, _) = run_sinks(&flow_flood());
    assert!(flows.dropped() > 0, "flow_flood must exceed max_flows");
    let (_, assets) = run_sinks(&asset_flood());
    assert!(
        assets.overflow().assets > 0,
        "asset_flood must exceed max_assets"
    );
    let (_, assets) = run_sinks(&arp_storm());
    let of = assets.overflow();
    assert!(
        of.assets > 0 && of.bindings > 0 && of.subnets > 0,
        "arp_storm must exceed the asset, binding, and subnet caps"
    );
    let (_, assets) = run_sinks(&local_host_flood());
    assert!(
        assets.overflow().bindings > 0,
        "local_host_flood must exceed the candidate cap"
    );
}

/// At the cap the table keeps the smallest flow keys of the SET — reversed
/// arrival (largest keys first, forcing eviction on every later packet) must
/// end identical to forward arrival, and `dropped` must be exactly the
/// non-survivors' packets.
#[test]
fn flow_cap_keeps_the_smallest_keys_with_exact_drop_accounting() {
    let frames = flow_flood();
    let mut reversed = frames.clone();
    reversed.reverse();
    for order in [&frames, &reversed] {
        let (flows, _) = run_sinks(order);
        let ports: Vec<u16> = flows.iter().map(|f| f.client().port).collect();
        assert_eq!(
            ports,
            (49100..49108).collect::<Vec<_>>(),
            "survivors are the 8 smallest keys, not the 8 first-seen"
        );
        assert_eq!(flows.dropped(), 24, "12 dropped flows x 2 packets each");
        assert_eq!(flows.len(), 8);
    }
}

/// One IP under two MACs on data frames: in either arrival order the host
/// must key to the SAME MAC (the smaller — first-writer-wins flipped the
/// inventory, bindings, and every dependency edge with packet order) and the
/// conflict must surface in `rebound_ips`, never as an all-zero envelope.
#[test]
fn conflicting_mac_claims_key_order_independently_and_are_counted() {
    let frames = mac_conflict_churn();
    let mut reversed = frames.clone();
    reversed.reverse();
    for order in [&frames, &reversed] {
        let (_, assets) = run_sinks(order);
        assert_eq!(
            assets.key_for_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 5, 5))),
            AssetKey::Mac(MacAddr([2, 0, 0, 0, 0xAA, 1])),
            "the smaller MAC wins in any arrival order"
        );
        assert_eq!(
            assets.overflow().rebound_ips,
            1,
            "the contested claim must be counted, not silent"
        );
    }
}

/// Subnet survivors decide keying identically in any order: 6 ARP-taught
/// /24s against a cap of 4 — a host in a surviving subnet ends MAC-keyed, a
/// host in an evicted subnet stays IP-keyed, forward or reversed.
#[test]
fn subnet_eviction_keys_hosts_order_independently() {
    let mut frames = Frames::new();
    for k in 0..6u8 {
        let router = MacAddr([2, 0, 0, 0, 3, k]);
        frames.push((
            ts(u64::from(k)),
            Packet::ethernet(router, MacAddr::BROADCAST)
                .arp_request(Ipv4Addr::new(10, 0, k, 1), Ipv4Addr::new(10, 0, k, 254)),
        ));
    }
    let host_in = MacAddr([2, 0, 0, 0, 4, 1]);
    let host_out = MacAddr([2, 0, 0, 0, 4, 2]);
    let dst = MacAddr([2, 0, 0, 0, 4, 3]);
    frames.push((
        ts(10),
        Packet::ethernet(host_in, dst)
            .ipv4(Ipv4Addr::new(10, 0, 0, 77), Ipv4Addr::new(198, 51, 100, 1))
            .udp(40000, 40001)
            .payload(b"x"),
    ));
    frames.push((
        ts(11),
        Packet::ethernet(host_out, dst)
            .ipv4(Ipv4Addr::new(10, 0, 5, 77), Ipv4Addr::new(198, 51, 100, 1))
            .udp(40000, 40001)
            .payload(b"x"),
    ));

    let mut reversed = frames.clone();
    reversed.reverse();
    for order in [frames, reversed] {
        let (_, assets) = run_sinks(&order);
        assert_eq!(
            assets.key_for_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 77))),
            AssetKey::Mac(host_in),
            "a host in a surviving /24 is MAC-keyed"
        );
        assert_eq!(
            assets.key_for_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 5, 77))),
            AssetKey::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 5, 77))),
            "a host in an evicted /24 stays IP-keyed"
        );
        assert!(assets.overflow().subnets > 0, "the cap drop is counted");
    }
}
