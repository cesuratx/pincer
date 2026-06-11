//! Shared scaffolding for the fuzz targets: valid container prefixes, so
//! coverage-guided mutation lands *past* the magic/version gates and inside
//! the record machinery (blind random bytes die at the byte-order magic with
//! probability ~1 − 2⁻³¹ — the blind spot the proptest suite documents in
//! `tests/never_panic.rs`), plus the reader-drain loop the container targets
//! share.
//!
//! The byte builders mirror `tests/common/mod.rs`; they are duplicated here
//! because this crate is its own workspace and cannot reach the root crate's
//! test-support modules. They encode fixed spec layouts, not logic.
#![forbid(unsafe_code)]

use pincer::app::sniff;
use pincer::decode::decode_packet;
use pincer::pcap::CaptureReader;

/// Minimal little-endian pcapng Section Header Block (28 bytes, no options).
#[must_use]
pub fn shb_le() -> Vec<u8> {
    let mut b = vec![0x0A, 0x0D, 0x0D, 0x0A];
    b.extend_from_slice(&28u32.to_le_bytes());
    b.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&(-1i64).to_le_bytes());
    b.extend_from_slice(&28u32.to_le_bytes());
    b
}

/// pcapng Interface Description Block: Ethernet, snaplen 0 ("no limit"),
/// no options.
#[must_use]
pub fn idb_le() -> Vec<u8> {
    let mut b = 1u32.to_le_bytes().to_vec();
    b.extend_from_slice(&20u32.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&20u32.to_le_bytes());
    b
}

/// Legacy pcap global header: little-endian µs magic, v2.4, snaplen 65535,
/// `DLT_EN10MB` (Ethernet).
#[must_use]
pub fn legacy_header_le() -> Vec<u8> {
    let mut b = vec![0xD4, 0xC3, 0xB2, 0xA1];
    b.extend_from_slice(&2u16.to_le_bytes()); // version major
    b.extend_from_slice(&4u16.to_le_bytes()); // version minor
    b.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    b.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    b.extend_from_slice(&65_535u32.to_le_bytes()); // snaplen
    b.extend_from_slice(&1u32.to_le_bytes()); // link type
    b
}

/// Stream every record out of a capture, decoding and sniffing each. The
/// container targets only care that the reader terminates and nothing
/// panics; a mid-stream `Err` is the degrade-don't-discard path the CLI
/// takes too, so it ends the drain rather than failing it.
pub fn drain_capture(file: &[u8]) {
    let Ok(mut reader) = CaptureReader::new(file) else {
        return;
    };
    while let Ok(Some(record)) = reader.next_record() {
        if let Ok(pkt) = decode_packet(&record) {
            std::hint::black_box(pkt.ip_pair());
            std::hint::black_box(sniff(&pkt));
        }
    }
    std::hint::black_box((reader.skipped_blocks(), reader.timestampless_records()));
}
