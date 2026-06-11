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

// ---------------------------------------------------------------------------
// Adversarial *container* tests: pcapng framing attacks. The block-length
// field drives buffer sizing and stream advancement, so lies here are how a
// hostile file tries to hang the reader, force a giant allocation, or
// silently truncate the analysis.
// ---------------------------------------------------------------------------

mod pcapng_hostile {
    use pincer::error::PcapError;
    use pincer::pcap::CaptureReader;

    /// Minimal little-endian SHB (28 bytes, no options).
    fn shb_le() -> Vec<u8> {
        let mut b = vec![0x0A, 0x0D, 0x0D, 0x0A];
        b.extend_from_slice(&28u32.to_le_bytes());
        b.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(-1i64).to_le_bytes());
        b.extend_from_slice(&28u32.to_le_bytes());
        b
    }

    /// A block whose header *claims* `total_len`, regardless of the body.
    fn lying_block(block_type: u32, total_len: u32, body: &[u8]) -> Vec<u8> {
        let mut b = block_type.to_le_bytes().to_vec();
        b.extend_from_slice(&total_len.to_le_bytes());
        b.extend_from_slice(body);
        b
    }

    #[test]
    fn block_length_lies_are_rejected_not_hung() {
        // 0 and 4 would make the stream go backwards; 8 and 11 are below the
        // 12-byte framing minimum; 13 and 14 break 4-alignment. Every one
        // must be a BadLength error — not an infinite loop, not a panic, and
        // not a silent EOF.
        for lie in [0u32, 4, 8, 11, 13, 14] {
            let mut file = shb_le();
            file.extend_from_slice(&lying_block(6, lie, &[0u8; 64]));
            let mut reader = CaptureReader::new(file.as_slice()).unwrap();
            let err = reader.next_record().expect_err("length lie must error");
            assert!(
                matches!(err, PcapError::BadLength { len, .. } if len == u64::from(lie)),
                "total_len {lie}: got {err:?}"
            );
        }
    }

    #[test]
    fn giant_block_length_is_rejected_without_allocation() {
        // 4-aligned and well-formed framing, but claims a ~4 GiB body. The
        // 64 MiB record cap must reject it before any buffer is sized by it.
        let mut file = shb_le();
        file.extend_from_slice(&lying_block(6, 0xFFFF_FFF0, &[0u8; 16]));
        let mut reader = CaptureReader::new(file.as_slice()).unwrap();
        let err = reader.next_record().expect_err("giant length must error");
        assert!(matches!(err, PcapError::BadLength { .. }), "got {err:?}");
    }

    #[test]
    fn truncated_mid_block_is_truncation_not_panic() {
        // A block header promising more bytes than the file has: the typical
        // cut-off-mid-write capture. Must surface as TruncatedFile so the
        // caller can flag the tail, never a panic or a hang.
        let mut file = shb_le();
        file.extend_from_slice(&lying_block(6, 64, &[0u8; 10])); // 42 bytes short
        let mut reader = CaptureReader::new(file.as_slice()).unwrap();
        let err = reader.next_record().expect_err("must error");
        assert!(
            matches!(err, PcapError::TruncatedFile { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn big_endian_section_parses() {
        // Endianness comes from the BOM per section; a big-endian file is
        // valid input, not an anomaly.
        let mut file = vec![0x0A, 0x0D, 0x0D, 0x0A];
        file.extend_from_slice(&28u32.to_be_bytes());
        file.extend_from_slice(&0x1A2B_3C4Du32.to_be_bytes());
        file.extend_from_slice(&1u16.to_be_bytes());
        file.extend_from_slice(&0u16.to_be_bytes());
        file.extend_from_slice(&(-1i64).to_be_bytes());
        file.extend_from_slice(&28u32.to_be_bytes());
        // IDB: Ethernet, snaplen 0.
        file.extend_from_slice(&1u32.to_be_bytes());
        file.extend_from_slice(&20u32.to_be_bytes());
        file.extend_from_slice(&1u16.to_be_bytes());
        file.extend_from_slice(&0u16.to_be_bytes());
        file.extend_from_slice(&0u32.to_be_bytes());
        file.extend_from_slice(&20u32.to_be_bytes());
        // EPB with 4 data bytes.
        file.extend_from_slice(&6u32.to_be_bytes());
        file.extend_from_slice(&36u32.to_be_bytes());
        for field in [0u32, 0, 0, 4, 4] {
            file.extend_from_slice(&field.to_be_bytes());
        }
        file.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        file.extend_from_slice(&36u32.to_be_bytes());

        let mut reader = CaptureReader::new(file.as_slice()).unwrap();
        let record = reader.next_record().unwrap().expect("one packet");
        assert_eq!(record.data, &[0xCA, 0xFE, 0xBA, 0xBE]);
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn idb_option_length_lie_does_not_hang_or_poison_the_section() {
        // IDB whose if_tsresol option claims 0xFFFF value bytes that are not
        // there. Option walking must stop; the packet block after it must
        // still decode under the interface's defaults.
        let mut file = shb_le();
        let mut idb_body = Vec::new();
        idb_body.extend_from_slice(&1u16.to_le_bytes()); // Ethernet
        idb_body.extend_from_slice(&0u16.to_le_bytes());
        idb_body.extend_from_slice(&0u32.to_le_bytes()); // snaplen: no limit
        idb_body.extend_from_slice(&9u16.to_le_bytes()); // if_tsresol
        idb_body.extend_from_slice(&0xFFFFu16.to_le_bytes()); // length lie
        let total = u32::try_from(idb_body.len()).unwrap() + 12;
        file.extend_from_slice(&1u32.to_le_bytes());
        file.extend_from_slice(&total.to_le_bytes());
        file.extend_from_slice(&idb_body);
        file.extend_from_slice(&total.to_le_bytes());
        // Valid EPB.
        file.extend_from_slice(&6u32.to_le_bytes());
        file.extend_from_slice(&36u32.to_le_bytes());
        for field in [0u32, 0, 0, 4, 4] {
            file.extend_from_slice(&field.to_le_bytes());
        }
        file.extend_from_slice(&[1, 2, 3, 4]);
        file.extend_from_slice(&36u32.to_le_bytes());

        let mut reader = CaptureReader::new(file.as_slice()).unwrap();
        let record = reader.next_record().unwrap().expect("EPB must survive");
        assert_eq!(record.data, &[1, 2, 3, 4]);
    }
}

mod pcapng_framing {
    use pincer::error::PcapError;
    use pincer::pcap::CaptureReader;

    fn shb_le() -> Vec<u8> {
        let mut b = vec![0x0A, 0x0D, 0x0D, 0x0A];
        b.extend_from_slice(&28u32.to_le_bytes());
        b.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(-1i64).to_le_bytes());
        b.extend_from_slice(&28u32.to_le_bytes());
        b
    }

    fn idb_le() -> Vec<u8> {
        let mut b = 1u32.to_le_bytes().to_vec();
        b.extend_from_slice(&20u32.to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&20u32.to_le_bytes());
        b
    }

    fn epb_le(iface: u32, data: &[u8]) -> Vec<u8> {
        let cap = u32::try_from(data.len()).unwrap();
        let padded = data.len().next_multiple_of(4);
        let total = u32::try_from(32 + padded).unwrap();
        let mut b = 6u32.to_le_bytes().to_vec();
        b.extend_from_slice(&total.to_le_bytes());
        for field in [iface, 0, 0, cap, cap] {
            b.extend_from_slice(&field.to_le_bytes());
        }
        b.extend_from_slice(data);
        b.resize(b.len() + (padded - data.len()), 0);
        b.extend_from_slice(&total.to_le_bytes());
        b
    }

    /// A trailing Block Total Length that disagrees with the leading one means
    /// the framing itself is corrupt — the stream must stop with an error, not
    /// keep walking on a length it now knows is untrustworthy.
    #[test]
    fn trailing_length_mismatch_is_fatal_framing_damage() {
        let mut file = shb_le();
        file.extend_from_slice(&idb_le());
        let mut epb = epb_le(0, &[1, 2, 3, 4]);
        let n = epb.len();
        epb.get_mut(n - 4..)
            .unwrap()
            .copy_from_slice(&999u32.to_le_bytes()); // corrupt trailer
        file.extend_from_slice(&epb);
        let mut reader = CaptureReader::new(file.as_slice()).unwrap();
        let err = reader.next_record().expect_err("mismatch must error");
        assert!(
            matches!(err, PcapError::BadLength { len: 999, .. }),
            "got {err:?}"
        );
    }

    /// An EPB naming an interface the section never declared must be skipped
    /// and counted — not silently decoded under a guessed default interface
    /// (wrong link type, wrong clock).
    #[test]
    fn epb_with_undeclared_interface_is_skipped_and_counted() {
        let mut file = shb_le();
        file.extend_from_slice(&idb_le()); // declares interface 0 only
        file.extend_from_slice(&epb_le(7, &[1, 2, 3, 4])); // references 7
        file.extend_from_slice(&epb_le(0, &[5, 6, 7, 8])); // valid
        let mut reader = CaptureReader::new(file.as_slice()).unwrap();
        let rec = reader.next_record().unwrap().expect("valid EPB survives");
        assert_eq!(rec.data, &[5, 6, 7, 8]);
        assert!(reader.next_record().unwrap().is_none());
        assert_eq!(reader.skipped_blocks(), 1);
    }

    /// An IDB flood must not grow memory without bound: past the cap the
    /// definitions are skipped and counted.
    #[test]
    fn idb_flood_is_capped_not_unbounded() {
        let mut file = shb_le();
        for _ in 0..5000 {
            file.extend_from_slice(&idb_le());
        }
        file.extend_from_slice(&epb_le(0, &[9, 9, 9, 9]));
        let mut reader = CaptureReader::new(file.as_slice()).unwrap();
        let rec = reader.next_record().unwrap().expect("packet still decodes");
        assert_eq!(rec.data, &[9, 9, 9, 9]);
        assert_eq!(reader.skipped_blocks(), 5000 - 4096, "overflow counted");
    }
}
