//! Property tests proving the crate-wide claim: no input — random bytes,
//! truncated captures, or mutated valid frames — can panic, hang, or run the
//! analysis out of memory. Run under debug assertions so arithmetic overflow
//! also counts as a panic.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

mod common;

use pincer::analysis::{AssetInventory, FlowTable, Observe, Stats, dependency_edges};
use pincer::app::sniff;
use pincer::decode::decode_packet;
use pincer::fixtures::scenarios;
use pincer::output::{Degradation, DhcpRecord, DnsRecord, Report, deps_dot};
use pincer::pcap::{CaptureReader, LinkType, Record};
use proptest::prelude::*;

/// Drive arbitrary bytes through the whole pipeline — reader, decoders,
/// sniffers, sinks, and then the CLI tail the shipped binary always runs:
/// `finalize`, dependency derivation, and every renderer (table, JSON
/// envelope, DOT). Attacker-derived strings (hostnames, SNI, HTTP hosts) flow
/// into the renderers, so the no-panic property must not stop at `observe`.
fn run_pipeline(capture: &[u8]) {
    let Ok(mut reader) = CaptureReader::new(capture) else {
        return; // rejecting a bad header is fine
    };
    let mut stats = Stats::new();
    let mut flows = FlowTable::new();
    let mut assets = AssetInventory::new();
    let mut dns = Vec::new();
    let mut dhcp = Vec::new();
    let mut guard = 0u32;
    loop {
        guard += 1;
        assert!(guard <= 1_000_000, "reader failed to terminate");
        match reader.next_record() {
            Ok(Some(record)) => {
                if let Ok(pkt) = decode_packet(&record) {
                    let app = sniff(&pkt);
                    stats.observe(&pkt, app.as_ref());
                    flows.observe(&pkt, app.as_ref());
                    assets.observe(&pkt, app.as_ref());
                    if let Some(event) = app.as_ref() {
                        DnsRecord::push_from(event, &mut dns);
                        DhcpRecord::push_from(event, &mut dhcp);
                    }
                }
            }
            Ok(None) | Err(_) => break,
        }
    }

    assets.finalize();
    let asset_list = assets.assets();
    let edges = dependency_edges(&flows, &assets);
    // The same degradation facts `Pass::degradation` would report, so the
    // PARTIAL footers and markers render under fuzz too.
    let of = assets.overflow();
    let degradation = Degradation {
        skipped_blocks: reader.skipped_blocks(),
        timestampless_records: reader.timestampless_records(),
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
    for report in [
        Report::Summary(&stats),
        Report::Flows(&flows),
        Report::Assets(&asset_list),
        Report::Services(&asset_list),
        Report::Deps(&edges),
        Report::Dns(&dns),
        Report::Dhcp(&dhcp),
    ] {
        let _ = report.to_table(&degradation);
        let mut json = Vec::new();
        let _ = report.write_json(&degradation, &mut json);
    }
    let _ = deps_dot(&edges, &degradation);
}

/// A single Ethernet frame decoded directly; never panic. `ts: None` keeps
/// the timestamp-less (SPB) record shape under fuzz too.
fn decode_frame(frame: &[u8]) {
    let record = Record {
        ts: None,
        orig_len: u32::try_from(frame.len()).unwrap_or(u32::MAX),
        link_type: LinkType::Ethernet,
        data: frame,
    };
    if let Ok(pkt) = decode_packet(&record) {
        let _ = sniff(&pkt);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn arbitrary_capture_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        run_pipeline(&bytes);
    }

    #[test]
    fn arbitrary_frame_bytes_never_panic(frame in proptest::collection::vec(any::<u8>(), 0..2048)) {
        decode_frame(&frame);
    }

    /// A pcapng SHB type prefix, then garbage: this fuzzes the section-header
    /// length/BOM validation itself — random bytes survive the byte-order
    /// magic check with probability ~2⁻³¹, so the block walk is reached by
    /// the two `valid_shb_*` variants below, not here.
    #[test]
    fn arbitrary_pcapng_section_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let mut file = vec![0x0A, 0x0D, 0x0D, 0x0A];
        file.extend_from_slice(&bytes);
        run_pipeline(&file);
    }

    /// A complete valid little-endian SHB, then garbage: the fuzz lands
    /// inside `next_record`'s block loop — framing checks, IDB option
    /// walking, EPB/SPB body checks, and mid-stream SHB resets — instead of
    /// dying at the BOM check.
    #[test]
    fn valid_shb_then_garbage_never_panics(tail in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let mut file = common::shb_le();
        file.extend_from_slice(&tail);
        run_pipeline(&file);
    }

    /// Same, with an Ethernet interface declared: packet blocks that survive
    /// the well-formedness checks now reach the decoders and sinks too.
    #[test]
    fn valid_shb_idb_then_garbage_never_panics(tail in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let mut file = common::shb_le();
        file.extend_from_slice(&common::idb_le());
        file.extend_from_slice(&tail);
        run_pipeline(&file);
    }

    /// Fuzz the application sniffers directly on arbitrary payloads — the
    /// loop-prone parsers (DNS name decompression, TLS/DHCP option walks) get
    /// their most direct adversarial exposure here, below the packet framing.
    #[test]
    fn arbitrary_payload_through_app_parsers_never_panics(
        payload in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        let _ = pincer::app::dns::parse(&payload, false);
        let _ = pincer::app::dns::parse(&payload, true);
        let _ = pincer::app::dns::parse_shallow(&payload, false);
        let _ = pincer::app::dns::parse_shallow(&payload, true);
        let _ = pincer::app::dhcp::parse(&payload);
        let _ = pincer::app::dhcp::parse_shallow(&payload);
        let _ = pincer::app::http::parse_request(&payload);
        let _ = pincer::app::tls::parse_client_hello(&payload);
    }

    /// A valid pcap global header followed by arbitrary record bytes — gets
    /// past the header check and stresses the record/decoder path.
    #[test]
    fn valid_header_then_garbage_never_panics(tail in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let mut capture = vec![
            0xD4, 0xC3, 0xB2, 0xA1, // LE µs magic
            0x02, 0x00, 0x04, 0x00, // version 2.4
            0x00, 0x00, 0x00, 0x00, // thiszone
            0x00, 0x00, 0x00, 0x00, // sigfigs
            0xFF, 0xFF, 0x00, 0x00, // snaplen
            0x01, 0x00, 0x00, 0x00, // DLT_EN10MB
        ];
        capture.extend_from_slice(&tail);
        run_pipeline(&capture);
    }
}

/// Structure-aware fuzzing: take the real office capture and corrupt it at
/// every single byte offset (truncations and bit flips). None may panic.
#[test]
fn mutated_office_capture_never_panics() {
    let frames = scenarios::office();
    let mut capture = Vec::new();
    scenarios::write_pcap(&frames, &mut capture).unwrap();

    // Every truncation length.
    for len in 0..capture.len() {
        run_pipeline(&capture[..len]);
    }
    // A bit flip at every byte (flip the high bit — cheap, deterministic).
    for idx in 0..capture.len() {
        let mut mutated = capture.clone();
        mutated[idx] ^= 0x80;
        run_pipeline(&mutated);
    }
}
