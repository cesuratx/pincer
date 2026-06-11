//! Property tests proving the crate-wide claim: no input — random bytes,
//! truncated captures, or mutated valid frames — can panic, hang, or run the
//! analysis out of memory. Run under debug assertions so arithmetic overflow
//! also counts as a panic.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use pincer::analysis::{AssetInventory, FlowTable, Observe, Stats};
use pincer::app::sniff;
use pincer::decode::decode_packet;
use pincer::fixtures::scenarios;
use pincer::pcap::{CaptureReader, LinkType, Record};
use pincer::types::Timestamp;
use proptest::prelude::*;

/// Drive arbitrary bytes through the whole pipeline; never panic.
fn run_pipeline(capture: &[u8]) {
    let Ok(mut reader) = CaptureReader::new(capture) else {
        return; // rejecting a bad header is fine
    };
    let mut stats = Stats::new();
    let mut flows = FlowTable::new();
    let mut assets = AssetInventory::new();
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
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
}

/// A single Ethernet frame decoded directly; never panic.
fn decode_frame(frame: &[u8]) {
    let record = Record {
        ts: Timestamp::ZERO,
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

    /// Fuzz the application sniffers directly on arbitrary payloads — the
    /// loop-prone parsers (DNS name decompression, TLS/DHCP option walks) get
    /// their most direct adversarial exposure here, below the packet framing.
    #[test]
    fn arbitrary_payload_through_app_parsers_never_panics(
        payload in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        let _ = pincer::app::dns::parse(&payload, false);
        let _ = pincer::app::dns::parse(&payload, true);
        let _ = pincer::app::dhcp::parse(&payload);
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
