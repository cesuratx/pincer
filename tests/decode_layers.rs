//! Hand-written hex fixtures with byte-offset comments, plus reader tests for
//! the legacy pcap container variants. (Adversarial pcapng coverage — block
//! length lies, big-endian sections, SPB abuse — lives in `hostile.rs`.)
//! These pin the exact wire layout each decoder must accept — the test you
//! read to understand the format.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

use std::net::Ipv4Addr;

use pincer::decode::{NetView, TransportView, decode_packet};
use pincer::pcap::{CaptureReader, LinkType, Record};
use pincer::types::{MacAddr, Timestamp};

fn record(frame: &[u8]) -> Record<'_> {
    Record {
        ts: Timestamp::ZERO,
        orig_len: u32::try_from(frame.len()).unwrap(),
        link_type: LinkType::Ethernet,
        data: frame,
    }
}

/// A hand-assembled Ethernet/IPv4/UDP frame, annotated byte-by-byte.
#[rustfmt::skip]
const UDP_FRAME: &[u8] = &[
    // --- Ethernet (14 bytes) ---
    0xDC, 0xA6, 0x32, 0x00, 0x00, 0x01, // dst MAC
    0x3C, 0x22, 0xFB, 0x00, 0x00, 0x02, // src MAC
    0x08, 0x00,                         // ethertype = IPv4
    // --- IPv4 (20 bytes) ---
    0x45,             // version 4, IHL 5
    0x00,             // DSCP/ECN
    0x00, 0x26,       // total length = 38
    0x12, 0x34,       // identification
    0x40, 0x00,       // flags=DF, fragment offset 0
    0x40,             // TTL 64
    0x11,             // protocol = UDP (17)
    0x00, 0x00,       // header checksum (unchecked)
    0xC0, 0xA8, 0x01, 0x0A, // src 192.168.1.10
    0xC0, 0xA8, 0x01, 0x01, // dst 192.168.1.1
    // --- UDP (8 bytes) ---
    0xD4, 0x31,       // src port 54321
    0x00, 0x35,       // dst port 53
    0x00, 0x12,       // length = 18
    0x00, 0x00,       // checksum
    // --- payload (10 bytes) ---
    b'p', b'i', b'n', b'c', b'e', b'r', b'-', b'u', b'd', b'p',
];

#[test]
fn decodes_annotated_udp_frame() {
    let pkt = decode_packet(&record(UDP_FRAME)).unwrap();
    assert_eq!(pkt.eth.src, MacAddr([0x3C, 0x22, 0xFB, 0, 0, 2]));
    assert_eq!(pkt.eth.dst, MacAddr([0xDC, 0xA6, 0x32, 0, 0, 1]));

    let NetView::Ipv4(ip) = &pkt.net else {
        panic!("expected ipv4")
    };
    assert_eq!(ip.src, Ipv4Addr::new(192, 168, 1, 10));
    assert_eq!(ip.dst, Ipv4Addr::new(192, 168, 1, 1));
    assert!(ip.dont_fragment);
    assert!(!ip.is_fragmented());

    let Some(TransportView::Udp(udp)) = &pkt.transport else {
        panic!("expected udp")
    };
    assert_eq!(udp.src_port, 54321);
    assert_eq!(udp.dst_port, 53);
    assert_eq!(udp.payload, b"pincer-udp");
}

#[test]
fn truncation_at_every_boundary_never_panics_and_degrades() {
    // Cutting the frame at any length must yield a decode result or a clean
    // error — never a panic — and deeper layers simply disappear.
    for len in 0..UDP_FRAME.len() {
        let frame = &UDP_FRAME[..len];
        if let Ok(pkt) = decode_packet(&record(frame)) {
            // If we got a transport layer, the network layer must exist too.
            if pkt.transport.is_some() {
                assert!(matches!(pkt.net, NetView::Ipv4(_)));
            }
        }
    }
}

#[test]
fn non_first_fragment_has_no_transport() {
    // Same frame but fragment offset = 1 (flags/frag field = 0x0001): the
    // transport header must NOT be parsed (it isn't there in a real fragment).
    let mut frame = UDP_FRAME.to_vec();
    frame[20] = 0x00; // clear DF
    frame[21] = 0x01; // fragment offset = 1
    let pkt = decode_packet(&record(&frame)).unwrap();
    let NetView::Ipv4(ip) = &pkt.net else {
        panic!("ipv4")
    };
    assert!(ip.is_fragment_continuation());
    assert!(
        pkt.transport.is_none(),
        "must not parse transport in a fragment tail"
    );
}

#[test]
fn malformed_ipv4_is_recorded_not_fatal() {
    let mut frame = UDP_FRAME.to_vec();
    frame[14] = 0x40; // version 4, IHL 0 — illegal (< 5 words)
    let pkt = decode_packet(&record(&frame)).unwrap();
    assert!(matches!(pkt.net, NetView::Malformed { layer: "ipv4", .. }));
}

// ---------------------------------------------------------------------------
// Container variants — all four legacy magics and a pcapng file decode the
// same single packet identically.
// ---------------------------------------------------------------------------

/// One captured packet (the UDP frame), as a legacy record body.
fn legacy_capture(magic: [u8; 4], big_endian: bool, ns: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&magic);
    let pack16 = |v: u16| {
        if big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    let pack32 = |v: u32| {
        if big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    out.extend_from_slice(&pack16(2)); // major
    out.extend_from_slice(&pack16(4)); // minor
    out.extend_from_slice(&pack32(0)); // thiszone
    out.extend_from_slice(&pack32(0)); // sigfigs
    out.extend_from_slice(&pack32(65535)); // snaplen
    out.extend_from_slice(&pack32(1)); // DLT_EN10MB
    // record header
    out.extend_from_slice(&pack32(0x6543_2100)); // ts_sec
    let frac = if ns { 123_456_000 } else { 123_456 };
    out.extend_from_slice(&pack32(frac));
    out.extend_from_slice(&pack32(UDP_FRAME.len() as u32)); // incl_len
    out.extend_from_slice(&pack32(UDP_FRAME.len() as u32)); // orig_len
    out.extend_from_slice(UDP_FRAME);
    out
}

#[test]
fn all_four_legacy_magics_decode_identically() {
    let variants = [
        ([0xA1, 0xB2, 0xC3, 0xD4], true, false),  // BE, µs
        ([0xD4, 0xC3, 0xB2, 0xA1], false, false), // LE, µs
        ([0xA1, 0xB2, 0x3C, 0x4D], true, true),   // BE, ns
        ([0x4D, 0x3C, 0xB2, 0xA1], false, true),  // LE, ns
    ];
    for (magic, big_endian, ns) in variants {
        let capture = legacy_capture(magic, big_endian, ns);
        let mut reader = CaptureReader::new(capture.as_slice()).unwrap();
        let rec = reader.next_record().unwrap().expect("one record");
        assert_eq!(rec.data, UDP_FRAME, "magic {magic:02x?}");
        assert_eq!(rec.ts.secs, 0x6543_2100);
        assert_eq!(
            rec.ts.nanos, 123_456_000,
            "ns normalization for {magic:02x?}"
        );
        assert!(reader.next_record().unwrap().is_none());
    }
}

#[test]
fn pcapng_with_epb_decodes_the_same_packet() {
    // SHB + IDB + EPB, little-endian, default µs resolution.
    let frame = UDP_FRAME;
    let frame_len = frame.len();
    let padded = (frame_len + 3) & !3;
    let mut cap = Vec::new();

    // --- SHB ---
    cap.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes()); // block type
    cap.extend_from_slice(&28u32.to_le_bytes()); // total length
    cap.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes()); // byte-order magic
    cap.extend_from_slice(&1u16.to_le_bytes()); // major
    cap.extend_from_slice(&0u16.to_le_bytes()); // minor
    cap.extend_from_slice(&(-1i64).to_le_bytes()); // section length unknown
    cap.extend_from_slice(&28u32.to_le_bytes()); // trailing total length

    // --- IDB ---
    cap.extend_from_slice(&1u32.to_le_bytes()); // block type
    cap.extend_from_slice(&20u32.to_le_bytes()); // total length
    cap.extend_from_slice(&1u16.to_le_bytes()); // link type = Ethernet
    cap.extend_from_slice(&0u16.to_le_bytes()); // reserved
    cap.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    cap.extend_from_slice(&20u32.to_le_bytes()); // trailing total length

    // --- EPB ---
    let epb_total = 32 + padded; // 8 framing + 20 fixed + padded data + 4 trailing
    cap.extend_from_slice(&6u32.to_le_bytes()); // block type
    cap.extend_from_slice(&(epb_total as u32).to_le_bytes());
    cap.extend_from_slice(&0u32.to_le_bytes()); // interface id
    cap.extend_from_slice(&0u32.to_le_bytes()); // ts high
    cap.extend_from_slice(&1_000_000u32.to_le_bytes()); // ts low = 1s in µs
    cap.extend_from_slice(&(frame_len as u32).to_le_bytes()); // captured len
    cap.extend_from_slice(&(frame_len as u32).to_le_bytes()); // original len
    cap.extend_from_slice(frame);
    cap.extend_from_slice(&vec![0u8; padded - frame_len]); // padding
    cap.extend_from_slice(&(epb_total as u32).to_le_bytes()); // trailing length

    let mut reader = CaptureReader::new(cap.as_slice()).unwrap();
    let rec = reader.next_record().unwrap().expect("one EPB record");
    assert_eq!(rec.data, frame);
    assert_eq!(rec.link_type, LinkType::Ethernet);
    assert_eq!((rec.ts.secs, rec.ts.nanos), (1, 0));
    assert!(reader.next_record().unwrap().is_none());
}

/// A concatenated pcapng with TWO sections (a mid-stream SHB). The reader must
/// stay aligned across the second SHB and decode the packet in section 2 —
/// previously the mid-stream SHB was mis-read by 4 bytes and aborted the stream.
#[test]
fn pcapng_two_sections_mid_stream_shb() {
    let frame = UDP_FRAME;
    let frame_len = frame.len();
    let padded = (frame_len + 3) & !3;

    let section = |ts_low: u32| {
        let mut s = Vec::new();
        // SHB
        s.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
        s.extend_from_slice(&28u32.to_le_bytes());
        s.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        s.extend_from_slice(&1u16.to_le_bytes());
        s.extend_from_slice(&0u16.to_le_bytes());
        s.extend_from_slice(&(-1i64).to_le_bytes());
        s.extend_from_slice(&28u32.to_le_bytes());
        // IDB
        s.extend_from_slice(&1u32.to_le_bytes());
        s.extend_from_slice(&20u32.to_le_bytes());
        s.extend_from_slice(&1u16.to_le_bytes());
        s.extend_from_slice(&0u16.to_le_bytes());
        s.extend_from_slice(&65535u32.to_le_bytes());
        s.extend_from_slice(&20u32.to_le_bytes());
        // EPB
        let epb_total = 32 + padded;
        s.extend_from_slice(&6u32.to_le_bytes());
        s.extend_from_slice(&(epb_total as u32).to_le_bytes());
        s.extend_from_slice(&0u32.to_le_bytes());
        s.extend_from_slice(&0u32.to_le_bytes());
        s.extend_from_slice(&ts_low.to_le_bytes());
        s.extend_from_slice(&(frame_len as u32).to_le_bytes());
        s.extend_from_slice(&(frame_len as u32).to_le_bytes());
        s.extend_from_slice(frame);
        s.extend_from_slice(&vec![0u8; padded - frame_len]);
        s.extend_from_slice(&(epb_total as u32).to_le_bytes());
        s
    };

    let mut cap = section(1_000_000); // section 1: ts 1s
    cap.extend_from_slice(&section(2_000_000)); // section 2: ts 2s

    let mut reader = CaptureReader::new(cap.as_slice()).unwrap();
    let r1 = reader.next_record().unwrap().expect("section 1 packet");
    assert_eq!(r1.ts.secs, 1);
    assert_eq!(r1.data, frame);
    let r2 = reader
        .next_record()
        .unwrap()
        .expect("section 2 packet after mid-stream SHB");
    assert_eq!(r2.ts.secs, 2);
    assert_eq!(r2.data, frame);
    assert!(reader.next_record().unwrap().is_none());
}

#[test]
fn rejects_unknown_magic() {
    assert!(CaptureReader::new(&[0xDE, 0xAD, 0xBE, 0xEF][..]).is_err());
    assert!(CaptureReader::new(&[][..]).is_err());
}

#[test]
fn ipv6_fragment_continuation_has_no_transport() {
    // IPv6 packet whose payload starts with a Fragment extension header at
    // offset 1 (a *non-first* fragment): the bytes after it are the middle of
    // a datagram, so no transport header may be parsed from them.
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xDC, 0xA6, 0x32, 0, 0, 1]); // dst MAC
    frame.extend_from_slice(&[0x3C, 0x22, 0xFB, 0, 0, 2]); // src MAC
    frame.extend_from_slice(&[0x86, 0xDD]); // ethertype IPv6
    frame.extend_from_slice(&0x6000_0000u32.to_be_bytes()); // version 6
    frame.extend_from_slice(&16u16.to_be_bytes()); // payload length
    frame.push(44); // next header = Fragment
    frame.push(64); // hop limit
    frame.extend_from_slice(&[0x20, 1, 0xD, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // src
    frame.extend_from_slice(&[0x20, 1, 0xD, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]); // dst
    // Fragment header: next=TCP(6), reserved, offset 1 (<<3), ident
    frame.push(6);
    frame.push(0);
    frame.extend_from_slice(&(1u16 << 3).to_be_bytes());
    frame.extend_from_slice(&0xABCD_1234u32.to_be_bytes());
    // 8 bytes of mid-datagram payload that would mis-parse as a TCP header.
    frame.extend_from_slice(&[0x00, 0x16, 0xC0, 0x00, 0, 0, 0, 1]);

    let pkt = decode_packet(&record(&frame)).unwrap();
    let NetView::Ipv6(ip) = &pkt.net else {
        panic!("expected ipv6")
    };
    assert!(ip.is_fragment_continuation());
    assert!(
        pkt.transport.is_none(),
        "non-first IPv6 fragment must not be transport-parsed"
    );
}

#[test]
fn tso_zero_total_length_still_yields_transport() {
    // Segmentation-offload captures: tcpdump on the sending host records
    // large packets with IPv4 total_length == 0 (the NIC fills it in later).
    // The packet must still decode to its transport layer instead of being
    // discarded as malformed — otherwise every large local flow disappears.
    let mut frame = UDP_FRAME.to_vec();
    frame[16] = 0x00; // total_length = 0 (offload artifact)
    frame[17] = 0x00;
    let pkt = decode_packet(&record(&frame)).unwrap();
    assert!(
        matches!(pkt.net, NetView::Ipv4(_)),
        "TSO frame must not be malformed"
    );
    let Some(TransportView::Udp(udp)) = &pkt.transport else {
        panic!("transport must survive a TSO zero-length header")
    };
    assert_eq!((udp.src_port, udp.dst_port), (54321, 53));
}

#[test]
fn udp_length_beyond_capture_marks_packet_truncated() {
    // Same UDP frame, but the UDP length field claims far more payload than was
    // captured. The packet must be flagged truncated so the summary's anomaly
    // count is honest about a cut-short DNS/DHCP/NTP payload.
    let mut frame = UDP_FRAME.to_vec();
    // UDP length field sits at Ethernet(14) + IPv4(20) + 4 = offset 38. Inflate
    // it without touching the IPv4 total-length, so *only* the UDP layer sees a
    // shortfall — isolating the UDP truncation path from the IP one.
    frame[38] = 0x00;
    frame[39] = 0x40; // claim 64 bytes (56 payload) vs the 10 actually present
    let pkt = decode_packet(&record(&frame)).unwrap();
    assert!(
        pkt.truncated,
        "UDP payload truncation must propagate to PacketView.truncated"
    );
}

/// Real SYN/data segments virtually always carry TCP options. The data-offset
/// arithmetic decides where the payload begins — and therefore what the
/// HTTP/TLS sniffers read. Until this test, no committed fixture exercised an
/// offset above 5.
#[test]
fn tcp_options_shift_the_payload_not_the_sniffers() {
    use pincer::app::{AppEvent, sniff};
    use pincer::fixtures::Packet;
    use pincer::pcap::{LinkType, Record};
    use pincer::types::{MacAddr, Timestamp};

    // MSS(4) + NOP + NOP + SACK-permitted(2) = 8 option bytes → offset 7.
    let options = [2, 4, 0x05, 0xB4, 1, 1, 4, 2];
    let http = b"GET /probe HTTP/1.1\r\nHost: options.test\r\n\r\n";
    let frame = Packet::ethernet(MacAddr([2, 0, 0, 0, 0, 1]), MacAddr([2, 0, 0, 0, 0, 2]))
        .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
        .tcp(40000, 80)
        .tcp_options(&options)
        .payload(http);

    let record = Record {
        ts: Timestamp::ZERO,
        orig_len: u32::try_from(frame.len()).unwrap(),
        link_type: LinkType::Ethernet,
        data: &frame,
    };
    let pkt = decode_packet(&record).unwrap();
    let Some(TransportView::Tcp(tcp)) = &pkt.transport else {
        panic!("expected TCP, got {:?}", pkt.transport);
    };
    assert_eq!(
        tcp.payload, http,
        "payload must start after the options, not inside them"
    );

    let Some(AppEvent::Http(req)) = sniff(&pkt) else {
        panic!("HTTP must be sniffed through a data offset > 5");
    };
    assert_eq!(req.host.as_deref(), Some("options.test"));
}

/// The first fragment of a fragmented UDP datagram carries a UDP length that
/// describes the WHOLE datagram. The missing bytes are in later fragments,
/// not lost to snaplen — an intact capture must not count it as truncated.
#[test]
fn udp_first_fragment_is_not_truncation() {
    let mut frame = UDP_FRAME.to_vec();
    frame[20] = 0x20; // flags = MF, offset 0: first fragment of many
    frame[21] = 0x00;
    // UDP length claims the full (larger) datagram.
    frame[38] = 0x04;
    frame[39] = 0x00; // length = 1024
    let pkt = decode_packet(&record(&frame)).unwrap();
    let NetView::Ipv4(ip) = &pkt.net else {
        panic!("ipv4")
    };
    assert!(ip.is_fragmented() && !ip.is_fragment_continuation());
    assert!(
        !pkt.truncated,
        "fragmentation is not truncation on an intact capture"
    );
}

/// A legacy record whose `incl_len` exceeds its `orig_len` is a writer lie; the
/// reader must normalize `orig_len` up so the truncation flag cannot misfire.
#[test]
fn legacy_incl_len_above_orig_len_is_normalized() {
    let mut file = Vec::new();
    // Global header: LE µs magic, v2.4, zone/sigfigs 0, snaplen, DLT 1.
    file.extend_from_slice(&[0xD4, 0xC3, 0xB2, 0xA1]);
    file.extend_from_slice(&2u16.to_le_bytes());
    file.extend_from_slice(&4u16.to_le_bytes());
    file.extend_from_slice(&0u32.to_le_bytes());
    file.extend_from_slice(&0u32.to_le_bytes());
    file.extend_from_slice(&65535u32.to_le_bytes());
    file.extend_from_slice(&1u32.to_le_bytes());
    // Record header: ts 0.0, incl_len = frame len, orig_len lies smaller.
    let frame_len = u32::try_from(UDP_FRAME.len()).unwrap();
    file.extend_from_slice(&0u32.to_le_bytes());
    file.extend_from_slice(&0u32.to_le_bytes());
    file.extend_from_slice(&frame_len.to_le_bytes());
    file.extend_from_slice(&(frame_len - 10).to_le_bytes()); // the lie
    file.extend_from_slice(UDP_FRAME);

    let mut reader = CaptureReader::new(file.as_slice()).unwrap();
    let rec = reader.next_record().unwrap().expect("one record");
    assert_eq!(
        rec.orig_len, frame_len,
        "orig_len normalized to >= incl_len"
    );
    let pkt = decode_packet(&rec).unwrap();
    assert!(!pkt.truncated, "normalized record is not truncated");
}
