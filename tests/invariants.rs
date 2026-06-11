//! Semantic-invariant tests. Where `never_panic.rs` proves the code does not
//! crash, this proves it produces *correct* aggregates: bytes are conserved,
//! flow direction is order-independent when evidence allows, evidence grading
//! is insertion-order-independent, and the round-trip encoders/decoders agree.
//!
//! These are written as properties the code *should* satisfy; a failure here
//! is a real bug, not a flaky test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::{IpAddr, Ipv4Addr};

use pincer::analysis::{AssetInventory, FlowTable, Observe, Stats};
use pincer::app::{dhcp, dns, sniff};
use pincer::decode::decode_packet;
use pincer::fixtures::{self, Packet, scenarios};
use pincer::pcap::{LinkType, Record};
use pincer::types::{MacAddr, Timestamp};
use proptest::prelude::*;

fn observe_frame<O: Observe>(sink: &mut O, ts: Timestamp, frame: &[u8]) {
    let record = Record {
        ts: Some(ts),
        orig_len: u32::try_from(frame.len()).unwrap(),
        link_type: LinkType::Ethernet,
        data: frame,
    };
    if let Ok(pkt) = decode_packet(&record) {
        let app = sniff(&pkt);
        sink.observe(&pkt, app.as_ref());
    }
}

// ---------------------------------------------------------------------------
// Flow aggregation invariants
// ---------------------------------------------------------------------------

/// Per-direction byte totals must sum to the whole: c2s + s2c == total, for
/// every flow, regardless of which side we call client.
#[test]
fn flow_direction_bytes_are_conserved() {
    let mut flows = FlowTable::new();
    for (ts, frame) in scenarios::office() {
        observe_frame(&mut flows, ts, &frame);
    }
    assert!(!flows.is_empty());
    for flow in flows.iter() {
        let c2s = flow.client_to_server().bytes;
        let s2c = flow.server_to_client().bytes;
        assert_eq!(
            c2s.saturating_add(s2c),
            flow.total_bytes(),
            "client/server byte split must reconstruct the total"
        );
        assert_eq!(
            flow.client_to_server().packets + flow.server_to_client().packets,
            flow.total_packets()
        );
        assert!(flow.first_ts <= flow.last_ts, "time order within a flow");
        assert_ne!(flow.client(), flow.server(), "a flow has two distinct ends");
    }
}

/// Total bytes across all flows must equal the bytes the stats sink counted
/// for the *same* packets (IP packets carrying a transport header). We compare
/// against an independently-accumulated total. (The oracle re-applies the
/// same eligibility rule as the flow table — this checks the *accounting*,
/// not the eligibility predicate itself.)
#[test]
fn flow_bytes_match_packet_bytes() {
    // Build a capture of only TCP/UDP packets so every packet yields a flow.
    let frames = scenarios::office();
    let mut flows = FlowTable::new();
    let mut expected: u64 = 0;
    for (ts, frame) in &frames {
        let record = Record {
            ts: Some(*ts),
            orig_len: u32::try_from(frame.len()).unwrap(),
            link_type: LinkType::Ethernet,
            data: frame,
        };
        let Ok(pkt) = decode_packet(&record) else {
            continue;
        };
        // Only packets the flow table actually counts.
        let counts = matches!(
            pkt.transport,
            Some(
                pincer::decode::TransportView::Tcp(_)
                    | pincer::decode::TransportView::Udp(_)
                    | pincer::decode::TransportView::Icmp(_)
            )
        ) && pkt.ip_pair().is_some();
        if counts {
            expected = expected.saturating_add(u64::from(pkt.orig_len));
        }
        let app = sniff(&pkt);
        flows.observe(&pkt, app.as_ref());
    }
    let got: u64 = flows.iter().map(pincer::analysis::Flow::total_bytes).sum();
    assert_eq!(
        got, expected,
        "no packet's bytes may be lost or double-counted"
    );
}

/// A flow whose handshake includes a SYN must identify the same client and
/// server no matter the packet order — the SYN is order-independent evidence.
#[test]
fn syn_flow_direction_is_order_independent() {
    let client = MacAddr([0x02, 0, 0, 0, 0, 1]);
    let server = MacAddr([0x02, 0, 0, 0, 0, 2]);
    let cip = Ipv4Addr::new(10, 0, 0, 1);
    let sip = Ipv4Addr::new(10, 0, 0, 2);
    let (cport, sport) = (51000u16, 443u16);

    let syn = Packet::ethernet(client, server)
        .ipv4(cip, sip)
        .tcp(cport, sport)
        .syn()
        .build();
    let synack = Packet::ethernet(server, client)
        .ipv4(sip, cip)
        .tcp(sport, cport)
        .syn_ack()
        .build();
    let data = Packet::ethernet(client, server)
        .ipv4(cip, sip)
        .tcp(cport, sport)
        .payload(b"hello");

    let forward = [syn.clone(), synack.clone(), data.clone()];
    let reversed = [data, synack, syn];

    let run = |frames: &[Vec<u8>]| {
        let mut flows = FlowTable::new();
        for (i, f) in frames.iter().enumerate() {
            observe_frame(&mut flows, Timestamp::new(100 + i as u64, 0), f);
        }
        let flow = flows.iter().next().expect("one flow");
        (flow.client(), flow.server())
    };
    assert_eq!(
        run(&forward),
        run(&reversed),
        "SYN direction is order-independent"
    );
    let (c, s) = run(&forward);
    assert_eq!(c.ip, IpAddr::V4(cip));
    assert_eq!(s.ip, IpAddr::V4(sip));
}

// ---------------------------------------------------------------------------
// Asset / service invariants
// ---------------------------------------------------------------------------

/// Stronger service evidence must win regardless of the order evidence
/// arrives in (`SynAck` beats `AppLayer` beats `PortHeuristic`).
#[test]
fn service_evidence_is_insertion_order_independent() {
    use pincer::analysis::ServiceEvidence;

    // Two orderings of the same three evidences for one host:port.
    let server = MacAddr([0xDC, 0xA6, 0x32, 0, 0, 1]);
    let client = MacAddr([0x02, 0, 0, 0, 0, 9]);
    let sip = Ipv4Addr::new(192, 168, 1, 50);
    let cip = Ipv4Addr::new(192, 168, 1, 9);

    // Establish locality so the server is one MAC-keyed asset.
    let arp = Packet::ethernet(server, MacAddr::BROADCAST).arp_reply(sip, client, cip);

    // PortHeuristic: client SYN to :80; SynAck: server SYN-ACK from :80.
    let syn = Packet::ethernet(client, server)
        .ipv4(cip, sip)
        .tcp(50000, 80)
        .syn()
        .build();
    let synack = Packet::ethernet(server, client)
        .ipv4(sip, cip)
        .tcp(80, 50000)
        .syn_ack()
        .build();

    let evidence_for = |order: &[&Vec<u8>]| {
        let mut inv = AssetInventory::new();
        for (i, f) in order.iter().enumerate() {
            observe_frame(&mut inv, Timestamp::new(1 + i as u64, 0), f);
        }
        let asset = inv
            .assets()
            .into_iter()
            .find(|a| a.ips.contains(&IpAddr::V4(sip)))
            .expect("server asset");
        asset
            .services()
            .into_iter()
            .find(|s| s.port == 80)
            .expect("port 80 service")
            .evidence
    };

    let a = evidence_for(&[&arp, &syn, &synack]);
    let b = evidence_for(&[&arp, &synack, &syn]);
    assert_eq!(a, b, "evidence must not depend on arrival order");
    assert_eq!(a, ServiceEvidence::SynAck, "strongest evidence must win");
}

/// Resolving an IP to its asset key is deterministic and idempotent.
#[test]
fn asset_key_resolution_is_stable() {
    let mut inv = AssetInventory::new();
    for (ts, frame) in scenarios::office() {
        observe_frame(&mut inv, ts, &frame);
    }
    let ip = IpAddr::V4(scenarios::IP_LAPTOP);
    let k1 = inv.key_for_ip(ip);
    let k2 = inv.key_for_ip(ip);
    assert_eq!(k1, k2);
    // The laptop is a local DHCP host → MAC-keyed, and that MAC is the one
    // from the capture.
    assert_eq!(k1, pincer::analysis::AssetKey::Mac(scenarios::MAC_LAPTOP));
}

// ---------------------------------------------------------------------------
// Round-trip encoder/decoder agreement
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// A hostname encoded by the fixture builder and parsed back by the DNS
    /// decoder must survive intact (labels 1..=63, total under the cap).
    #[test]
    fn dns_name_round_trips(
        // Labels up to the 63-byte boundary; at most three so the assembled
        // name stays under the 253-byte total cap the parser enforces.
        labels in proptest::collection::vec("[a-z0-9]{1,63}", 1..4)
    ) {
        let name = labels.join(".");
        // Wrap the encoded name in a minimal A-record query and parse it.
        let msg = fixtures::dns_query(0x1234, &name);
        let summary = dns::parse(&msg, false).expect("valid DNS query parses");
        prop_assert_eq!(&summary.queries[0].name, &name);
    }

    /// A DHCP option-55 fingerprint round-trips through encode → parse →
    /// `fingerprint()` string.
    #[test]
    fn dhcp_fingerprint_round_trips(
        codes in proptest::collection::vec(any::<u8>(), 1..20)
    ) {
        let opts = fixtures::DhcpOptions {
            param_req_list: &codes,
            ..fixtures::DhcpOptions::default()
        };
        let payload = fixtures::dhcp(1, MacAddr([1, 2, 3, 4, 5, 6]), 0xABCD, &opts);
        let summary = dhcp::parse(&payload).expect("valid DHCP parses");
        let expected = codes.iter().map(u8::to_string).collect::<Vec<_>>().join(",");
        prop_assert_eq!(summary.fingerprint(), expected);
    }
}

// `FlowKey::new` is canonical: the same key for either endpoint order.
proptest! {
    #[test]
    fn flow_key_is_canonical(
        a1 in any::<u8>(), a2 in any::<u8>(), pa in any::<u16>(),
        b1 in any::<u8>(), b2 in any::<u8>(), pb in any::<u16>(),
    ) {
        use pincer::analysis::{Endpoint, FlowKey};
        use pincer::types::IpProto;
        let ea = Endpoint { ip: IpAddr::V4(Ipv4Addr::new(10, 0, a1, a2)), port: pa };
        let eb = Endpoint { ip: IpAddr::V4(Ipv4Addr::new(10, 0, b1, b2)), port: pb };
        let k1 = FlowKey::new(ea, eb, IpProto::Tcp);
        let k2 = FlowKey::new(eb, ea, IpProto::Tcp);
        prop_assert_eq!(k1, k2, "flow key must be direction-independent");
    }
}

// ---------------------------------------------------------------------------
// Stats invariants
// ---------------------------------------------------------------------------

/// Every decoded packet is counted exactly once, and the protocol tallies sum
/// to no more than the packet count.
#[test]
fn stats_counts_are_consistent() {
    let mut stats = Stats::new();
    let mut decoded = 0u64;
    for (ts, frame) in scenarios::incident() {
        let record = Record {
            ts: Some(ts),
            orig_len: u32::try_from(frame.len()).unwrap(),
            link_type: LinkType::Ethernet,
            data: &frame,
        };
        if let Ok(pkt) = decode_packet(&record) {
            decoded += 1;
            let app = sniff(&pkt);
            stats.observe(&pkt, app.as_ref());
        }
    }
    assert_eq!(stats.packets, decoded);
    let link_total: u64 = stats.link_protocols.values().sum();
    assert_eq!(
        link_total, stats.packets,
        "every packet has exactly one network class"
    );
    let transport_total: u64 = stats.transport_protocols.values().sum();
    assert!(
        transport_total <= stats.packets,
        "transport count cannot exceed packets"
    );
    if let (Some(first), Some(last)) = (stats.first_ts, stats.last_ts) {
        assert!(first <= last);
    }
}
