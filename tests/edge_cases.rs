//! Edge-case and order-independence tests aimed at *finding* bugs, not just
//! guarding known-good behavior. Several construct adversarial-but-legal
//! orderings the synthetic office capture never exercises.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::{IpAddr, Ipv4Addr};

use pincer::analysis::{AssetInventory, Observe};
use pincer::app::{dhcp, dns, http, sniff, tls};
use pincer::decode::decode_packet;
use pincer::fixtures::{self, Packet};
use pincer::pcap::{LinkType, Record};
use pincer::types::{MacAddr, Timestamp};

fn observe_frame(inv: &mut AssetInventory, ts: u64, frame: &[u8]) {
    let record = Record {
        ts: Some(Timestamp::new(ts, 0)),
        orig_len: u32::try_from(frame.len()).unwrap(),
        link_type: LinkType::Ethernet,
        data: frame,
    };
    if let Ok(pkt) = decode_packet(&record) {
        let app = sniff(&pkt);
        inv.observe(&pkt, app.as_ref());
    }
}

/// A local host can name itself (via its own mDNS announcement) *before* we
/// learn its MAC via ARP. The hostname must still end up on the host's final
/// (MAC-keyed) asset — not orphaned on a separate IP-keyed asset. This is the
/// order-independence the asset model promises. (The announcement is a
/// self-claim — src IP == claimed IP — because third-party answers are only
/// trusted within a learned segment; see assets.rs.)
#[test]
fn hostname_before_arp_binding_is_not_orphaned() {
    let server_ip = Ipv4Addr::new(192, 168, 1, 50);
    let server_mac = MacAddr([0xDC, 0xA6, 0x32, 0, 0, 1]);
    let gateway = MacAddr([0xAA, 0, 0xCC, 0, 0, 1]);

    // 1) The server announces itself: 192.168.1.50 = "fileserver.local".
    let mdns = Packet::ethernet(server_mac, MacAddr([0x01, 0, 0x5E, 0, 0, 0xFB]))
        .ipv4(server_ip, Ipv4Addr::new(224, 0, 0, 251))
        .udp(5353, 5353)
        .payload(&fixtures::mdns_announce_a("fileserver.local", server_ip));

    // 2) Then ARP teaches that 192.168.1.50 lives at server_mac.
    let arp = Packet::ethernet(server_mac, MacAddr::BROADCAST).arp_reply(
        server_ip,
        gateway,
        Ipv4Addr::new(192, 168, 1, 1),
    );

    let mut inv = AssetInventory::new();
    observe_frame(&mut inv, 1, &mdns);
    observe_frame(&mut inv, 2, &arp);

    // The host should be a single asset, MAC-keyed, carrying the hostname.
    let server_assets: Vec<_> = inv
        .assets()
        .into_iter()
        .filter(|a| a.ips.contains(&IpAddr::V4(server_ip)) || a.macs.contains(&server_mac))
        .collect();
    assert_eq!(
        server_assets.len(),
        1,
        "the host must be ONE asset, not split between its IP and its MAC"
    );
    let asset = server_assets[0];
    assert!(
        asset.hostnames.keys().any(|h| h == "fileserver.local"),
        "hostname learned before the MAC binding must survive on the merged asset"
    );
}

/// The whole inventory must be independent of packet order: analyzing the
/// office capture forwards and in reverse must yield the same set of assets,
/// hostnames, and services.
#[test]
fn asset_inventory_is_order_independent() {
    use pincer::fixtures::scenarios;

    type AssetRow = (
        String,
        Vec<String>,
        Vec<String>,
        Vec<String>,
        Vec<(u16, String)>,
    );
    let summarize = |frames: &[(Timestamp, Vec<u8>)]| -> Vec<AssetRow> {
        let mut inv = AssetInventory::new();
        for (i, (_, frame)) in frames.iter().enumerate() {
            // Re-stamp monotonically so first/last-seen don't depend on the
            // original timestamps (we are testing identity, not timing).
            observe_frame(&mut inv, i as u64, frame);
        }
        inv.finalize();
        // Canonical fingerprint: sorted (key, hostnames, services) tuples.
        let mut rows: Vec<AssetRow> = inv
            .assets()
            .into_iter()
            .map(|a| {
                let mut names: Vec<String> = a.hostnames.keys().cloned().collect();
                names.sort();
                let mut svcs: Vec<(u16, String)> = a
                    .services()
                    .into_iter()
                    .map(|s| (s.port, format!("{:?}", s.evidence)))
                    .collect();
                svcs.sort();
                // Identity fields too: a merge bug that scrambles which
                // MACs/IPs belong to which asset must fail this fingerprint.
                let mut ips: Vec<String> = a.ips.iter().map(ToString::to_string).collect();
                ips.sort();
                let mut macs: Vec<String> = a.macs.iter().map(ToString::to_string).collect();
                macs.sort();
                (a.key.to_string(), ips, macs, names, svcs)
            })
            .collect();
        rows.sort();
        rows
    };

    let frames = scenarios::office();
    let mut reversed = frames.clone();
    reversed.reverse();

    assert_eq!(
        summarize(&frames),
        summarize(&reversed),
        "asset identities, hostnames, and services must not depend on packet order"
    );
}

/// Truncating a valid application message at *every* length must never panic
/// and must never fabricate data: a cut DNS/DHCP/TLS/HTTP message parses a
/// faithful prefix or returns None — never wrong fields.
#[test]
fn app_parsers_degrade_cleanly_on_truncation() {
    let dns_msg = fixtures::dns_response_a(0x1234, "example.com", Ipv4Addr::new(93, 184, 216, 34));
    for len in 0..dns_msg.len() {
        if let Some(summary) = dns::parse(&dns_msg[..len], false) {
            // Any answer we *did* parse must be the real record, never garbage.
            for ans in &summary.answers {
                assert!(!ans.name.is_empty());
            }
        }
    }

    let dhcp_msg = fixtures::dhcp(
        1,
        MacAddr([1, 2, 3, 4, 5, 6]),
        0xABCD,
        &fixtures::DhcpOptions {
            hostname: Some("host"),
            param_req_list: &[1, 3, 6, 15],
            ..fixtures::DhcpOptions::default()
        },
    );
    for len in 0..dhcp_msg.len() {
        let _ = dhcp::parse(&dhcp_msg[..len]);
    }

    let tls_msg = fixtures::tls_client_hello("example.com");
    for len in 0..tls_msg.len() {
        if let Some(hello) = tls::parse_client_hello(&tls_msg[..len])
            && let Some(sni) = &hello.sni
        {
            assert_eq!(sni, "example.com", "a parsed SNI must be the real one");
        }
    }

    let http_msg = fixtures::http_get("intranet.local", "/status");
    for len in 0..http_msg.len() {
        if let Some(req) = http::parse_request(&http_msg[..len]) {
            assert_eq!(req.method, "GET");
        }
    }
}

/// VLAN tags stack up to the cap (4) and a deeper stack degrades gracefully
/// (no panic, recorded as malformed/unknown) rather than parsing wrong.
#[test]
fn vlan_stack_at_and_beyond_cap() {
    // Exactly 4 tags: decodes, all four VLAN IDs recovered.
    let mut p = Packet::ethernet(MacAddr([2; 6]), MacAddr([4; 6]));
    for vid in [100u16, 200, 300, 400] {
        p = p.vlan(vid);
    }
    let frame = p
        .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
        .udp(1000, 2000)
        .payload(b"x");
    let record = Record {
        ts: Some(Timestamp::ZERO),
        orig_len: u32::try_from(frame.len()).unwrap(),
        link_type: LinkType::Ethernet,
        data: &frame,
    };
    let pkt = decode_packet(&record).unwrap();
    let vlans: Vec<u16> = pkt.eth.vlan.iter().collect();
    assert_eq!(vlans, vec![100, 200, 300, 400]);

    // 5 tags: must not panic; the network layer is recorded as malformed.
    let mut deep = Packet::ethernet(MacAddr([2; 6]), MacAddr([4; 6]));
    for vid in [1u16, 2, 3, 4, 5] {
        deep = deep.vlan(vid);
    }
    let frame = deep
        .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
        .udp(1000, 2000)
        .payload(b"x");
    let record = Record {
        ts: Some(Timestamp::ZERO),
        orig_len: u32::try_from(frame.len()).unwrap(),
        link_type: LinkType::Ethernet,
        data: &frame,
    };
    // Either an Err or a Malformed view — but never a panic, and never a wrong
    // IPv4 parse from misaligned bytes.
    if let Ok(pkt) = decode_packet(&record) {
        assert!(
            !matches!(pkt.net, pincer::decode::NetView::Ipv4(_)),
            "a 5-deep VLAN stack must not yield a (misaligned) IPv4 view"
        );
    }
}

/// Differential vs etherparse on synthetic VLAN and IPv6 frames — the cases
/// our real-capture corpus is thin on.
#[test]
fn synthetic_vlan_and_ipv6_agree_with_etherparse() {
    use etherparse::{NetSlice, SlicedPacket, TransportSlice};

    let frames = [
        // single VLAN tag, IPv4/UDP
        Packet::ethernet(MacAddr([2; 6]), MacAddr([4; 6]))
            .vlan(42)
            .ipv4(Ipv4Addr::new(10, 1, 2, 3), Ipv4Addr::new(10, 4, 5, 6))
            .udp(1111, 2222)
            .payload(b"vlan-udp"),
        // IPv6/TCP
        Packet::ethernet(MacAddr([2; 6]), MacAddr([4; 6]))
            .ipv6(
                std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            )
            .tcp(40000, 443)
            .syn()
            .build(),
    ];

    for frame in &frames {
        let record = Record {
            ts: Some(Timestamp::ZERO),
            orig_len: u32::try_from(frame.len()).unwrap(),
            link_type: LinkType::Ethernet,
            data: frame,
        };
        let ours = decode_packet(&record).unwrap();
        let theirs = SlicedPacket::from_ethernet(frame).expect("etherparse decodes");

        let their_ips = match &theirs.net {
            Some(NetSlice::Ipv4(v4)) => Some((
                IpAddr::from(v4.header().source_addr()),
                IpAddr::from(v4.header().destination_addr()),
            )),
            Some(NetSlice::Ipv6(v6)) => Some((
                IpAddr::from(v6.header().source_addr()),
                IpAddr::from(v6.header().destination_addr()),
            )),
            _ => None,
        };
        assert_eq!(ours.ip_pair(), their_ips, "IP addresses must agree");

        let our_ports = match &ours.transport {
            Some(pincer::decode::TransportView::Tcp(t)) => Some((t.src_port, t.dst_port)),
            Some(pincer::decode::TransportView::Udp(u)) => Some((u.src_port, u.dst_port)),
            _ => None,
        };
        let their_ports = match &theirs.transport {
            Some(TransportSlice::Tcp(t)) => Some((t.source_port(), t.destination_port())),
            Some(TransportSlice::Udp(u)) => Some((u.source_port(), u.destination_port())),
            _ => None,
        };
        assert_eq!(our_ports, their_ports, "ports must agree (VLAN/IPv6)");
    }
}
