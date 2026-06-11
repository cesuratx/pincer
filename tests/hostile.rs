//! Adversarial *content* tests: a capture whose packets are individually
//! valid but collectively a flood (random 5-tuples, full port scan, ARP-spoof
//! storm, mDNS name flood). The analyses must degrade into bounded memory with
//! honest drop counters — never OOM, never hang. This is the dimension that
//! separates a demo from a sensor you can point at a live network.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{Ipv4Addr, Ipv6Addr};

use pincer::analysis::{AssetInventory, FlowTable, Limits, Observe};
use pincer::app::sniff;
use pincer::decode::decode_packet;
use pincer::fixtures::{Packet, mdns_announce_a};
use pincer::pcap::{LinkType, Record};
use pincer::types::{MacAddr, Timestamp};

fn decode_observe<O: Observe>(sink: &mut O, frame: &[u8]) {
    let record = Record {
        ts: Timestamp::ZERO,
        orig_len: u32::try_from(frame.len()).unwrap(),
        link_type: LinkType::Ethernet,
        data: frame,
    };
    if let Ok(pkt) = decode_packet(&record) {
        let app = sniff(&pkt);
        sink.observe(&pkt, app.as_ref());
    }
}

#[test]
fn random_five_tuple_flood_respects_flow_cap() {
    let mut flows = FlowTable::with_limits(Limits::tiny()); // max_flows = 8
    let attacker = MacAddr([2, 0, 0, 0, 0, 1]);
    let victim = MacAddr([2, 0, 0, 0, 0, 2]);
    // 5000 distinct source ports → 5000 distinct flows attempted.
    for port in 0u16..5000 {
        let frame = Packet::ethernet(attacker, victim)
            .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
            .tcp(40000u16.wrapping_add(port), 80)
            .syn()
            .build();
        decode_observe(&mut flows, &frame);
    }
    assert_eq!(flows.len(), 8, "flow table must not exceed its cap");
    assert!(flows.dropped() >= 4900, "drops must be counted, not hidden");
}

#[test]
fn full_port_scan_is_bounded_and_fast() {
    // Every TCP port to one host. The old Vec-scan made this O(n^2); the cap
    // plus map keeps it bounded. (If this test ever hangs, the regression is
    // back.)
    let mut assets = AssetInventory::with_limits(Limits::tiny()); // max_services = 4
    let scanner = MacAddr([2, 0, 0, 0, 0, 9]);
    let target = MacAddr([0xDC, 0xA6, 0x32, 0, 0, 1]);
    // Teach locality so the target is MAC-keyed (one asset).
    let arp = Packet::ethernet(target, MacAddr::BROADCAST).arp_reply(
        Ipv4Addr::new(10, 0, 0, 50),
        scanner,
        Ipv4Addr::new(10, 0, 0, 9),
    );
    decode_observe(&mut assets, &arp);
    for port in 1u16..=2000 {
        let frame = Packet::ethernet(scanner, target)
            .ipv4(Ipv4Addr::new(10, 0, 0, 9), Ipv4Addr::new(10, 0, 0, 50))
            .tcp(55000, port)
            .syn()
            .build();
        decode_observe(&mut assets, &frame);
    }
    let target_asset = assets
        .assets()
        .into_iter()
        .find(|a| {
            a.ips
                .contains(&std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)))
        })
        .expect("target asset exists");
    assert!(
        target_asset.services().len() <= 4,
        "services per asset must respect the cap"
    );
}

#[test]
fn arp_spoof_storm_bounds_bindings_and_assets() {
    let mut assets = AssetInventory::with_limits(Limits::tiny());
    // 3000 ARP replies, each claiming a fresh (IP, MAC) pair.
    for i in 0u32..3000 {
        let octets = i.to_be_bytes();
        let mac = MacAddr([0x02, octets[0], octets[1], octets[2], octets[3], 0xAA]);
        let ip = Ipv4Addr::from(0x0A00_0000 + i); // 10.x.x.x
        let frame = Packet::ethernet(mac, MacAddr::BROADCAST).arp_reply(
            ip,
            MacAddr([0xFF; 6]),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        decode_observe(&mut assets, &frame);
    }
    // Assets and bindings both capped; overflow recorded.
    assert!(assets.len() <= 8, "asset inventory must respect its cap");
    let of = assets.overflow();
    assert!(of.assets > 0 || of.bindings > 0, "overflow must be counted");
}

#[test]
fn dhcp_mask_flood_is_capped_and_counted() {
    // An attacker sprays DHCP ACKs with distinct (garbage-but-contiguous)
    // netmasks. Each previously leaked an empty per-mask BTreeSet *before* the
    // cap check; now the subnet cap holds and the drop is counted.
    let mut assets = AssetInventory::with_limits(Limits::tiny()); // max_subnets = 4
    let server = MacAddr([0xAA, 0, 0xCC, 0, 0, 1]);
    let masks: [u8; 6] = [8, 12, 16, 20, 24, 28]; // distinct /prefix → distinct masks
    for (idx, &prefix) in masks.iter().enumerate() {
        let i = u8::try_from(idx).unwrap();
        let mask = u32::MAX << (32 - prefix);
        let client = MacAddr([0x02, 0, 0, 0, 0, i]);
        let your_ip = Ipv4Addr::from(0x0A00_0001 + u32::from(i) * 0x0001_0000);
        let opts = pincer::fixtures::DhcpOptions {
            your_ip: Some(your_ip),
            subnet_mask: Some(Ipv4Addr::from(mask)),
            ..pincer::fixtures::DhcpOptions::default()
        };
        let frame = Packet::ethernet(server, MacAddr::BROADCAST)
            .ipv4(Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::BROADCAST)
            .udp(67, 68)
            .payload(&pincer::fixtures::dhcp(
                5,
                client,
                0x1000 + u32::from(i),
                &opts,
            ));
        decode_observe(&mut assets, &frame);
    }
    // Cap held and the overflow was reported — not a silent unbounded leak.
    assert!(assets.overflow().subnets > 0, "mask flood must be counted");
}

#[test]
fn port_scan_service_cap_is_counted() {
    let mut assets = AssetInventory::with_limits(Limits::tiny()); // max_services = 4
    let scanner = MacAddr([2, 0, 0, 0, 0, 9]);
    let target = MacAddr([0xDC, 0xA6, 0x32, 0, 0, 1]);
    let arp = Packet::ethernet(target, MacAddr::BROADCAST).arp_reply(
        Ipv4Addr::new(10, 0, 0, 50),
        scanner,
        Ipv4Addr::new(10, 0, 0, 9),
    );
    decode_observe(&mut assets, &arp);
    for port in 1u16..=200 {
        let frame = Packet::ethernet(scanner, target)
            .ipv4(Ipv4Addr::new(10, 0, 0, 9), Ipv4Addr::new(10, 0, 0, 50))
            .tcp(55000, port)
            .syn()
            .build();
        decode_observe(&mut assets, &frame);
    }
    assert!(
        assets.overflow().services > 0,
        "service-cap drops must be counted, not silent"
    );
}

#[test]
fn mdns_name_flood_bounds_hostnames_per_asset() {
    let mut assets = AssetInventory::with_limits(Limits::tiny()); // max_hostnames = 4
    let host = MacAddr([0xD0, 0x81, 0x7A, 1, 2, 3]);
    // 500 distinct mDNS A-record names all pointing at the same IP.
    for i in 0u32..500 {
        let name = format!("host-{i}.local");
        let frame = Packet::ethernet(host, MacAddr([0x01, 0, 0x5E, 0, 0, 0xFB]))
            .ipv4(
                Ipv4Addr::new(192, 168, 1, 77),
                Ipv4Addr::new(224, 0, 0, 251),
            )
            .udp(5353, 5353)
            .payload(&mdns_announce_a(&name, Ipv4Addr::new(192, 168, 1, 77)));
        decode_observe(&mut assets, &frame);
    }
    let asset = assets
        .assets()
        .into_iter()
        .find(|a| {
            a.ips
                .contains(&std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 77)))
        })
        .expect("asset exists");
    assert!(
        asset.hostnames.len() <= 4,
        "hostnames per asset must respect the cap, got {}",
        asset.hostnames.len()
    );
    assert!(
        assets.overflow().hostnames > 0,
        "name-flood drops must be counted"
    );
}

#[test]
fn normal_traffic_never_triggers_caps() {
    // Sanity: the office capture must analyze fully under DEFAULT limits with
    // zero drops — the caps are a hostile-only backstop, invisible in practice.
    let mut flows = FlowTable::new();
    let mut assets = AssetInventory::new();
    for (_, frame) in pincer::fixtures::scenarios::office() {
        decode_observe(&mut flows, &frame);
        decode_observe(&mut assets, &frame);
    }
    assert_eq!(flows.dropped(), 0);
    assert!(!assets.overflow().any());
}

/// An IPv6 random-flow flood must also stay bounded (the v6 path is separate).
#[test]
fn ipv6_flow_flood_respects_cap() {
    let mut flows = FlowTable::with_limits(Limits::tiny());
    let a = MacAddr([2, 0, 0, 0, 0, 1]);
    let b = MacAddr([2, 0, 0, 0, 0, 2]);
    for port in 0u16..2000 {
        let frame = Packet::ethernet(a, b)
            .ipv6(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            )
            .udp(40000u16.wrapping_add(port), 53)
            .payload(b"x");
        decode_observe(&mut flows, &frame);
    }
    assert_eq!(flows.len(), 8);
}
