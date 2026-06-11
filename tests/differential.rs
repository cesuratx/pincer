//! Differential testing: decode the same frames with pincer and with the
//! independent `etherparse` crate (a dev-dependency only) and assert they
//! agree on the layer fields. This is the "did I misread the RFC" detector —
//! crate-grade correctness without shipping the crate.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::net::Ipv4Addr;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pincer::decode::{NetView, TransportView, decode_packet};
use pincer::fixtures::{Packet, dns_query, http_get, tls_client_hello};
use pincer::pcap::{LinkType, Record};
use pincer::types::{MacAddr, Timestamp};

fn record(frame: &[u8]) -> Record<'_> {
    Record {
        ts: Some(Timestamp::ZERO),
        orig_len: u32::try_from(frame.len()).unwrap(),
        link_type: LinkType::Ethernet,
        data: frame,
    }
}

/// Assert pincer and etherparse agree on the IPv4 5-tuple of a frame.
fn assert_agrees(frame: &[u8]) {
    let ours = decode_packet(&record(frame)).unwrap();
    let theirs = SlicedPacket::from_ethernet(frame).unwrap();

    let NetView::Ipv4(our_ip) = &ours.net else {
        panic!("pincer did not decode IPv4")
    };
    let Some(NetSlice::Ipv4(their_ip)) = theirs.net else {
        panic!("etherparse did not decode IPv4")
    };
    assert_eq!(
        our_ip.src.octets(),
        their_ip.header().source(),
        "source IP mismatch"
    );
    assert_eq!(our_ip.dst.octets(), their_ip.header().destination());
    assert_eq!(our_ip.proto, their_ip.header().protocol().0);

    match (&ours.transport, theirs.transport) {
        (Some(TransportView::Tcp(our_tcp)), Some(TransportSlice::Tcp(their_tcp))) => {
            assert_eq!(our_tcp.src_port, their_tcp.source_port());
            assert_eq!(our_tcp.dst_port, their_tcp.destination_port());
            assert_eq!(our_tcp.seq, their_tcp.sequence_number());
            assert_eq!(
                our_tcp.flags.contains(pincer::decode::TcpFlags::SYN),
                their_tcp.syn()
            );
            assert_eq!(
                our_tcp.flags.contains(pincer::decode::TcpFlags::ACK),
                their_tcp.ack()
            );
            assert_eq!(
                our_tcp.flags.contains(pincer::decode::TcpFlags::FIN),
                their_tcp.fin()
            );
            assert_eq!(our_tcp.window, their_tcp.window_size());
            // Payload boundary is what HTTP/TLS sniffing reads from — any
            // disagreement on where options end would poison everything above.
            assert_eq!(our_tcp.payload, their_tcp.payload(), "TCP payload boundary");
        }
        (Some(TransportView::Udp(our_udp)), Some(TransportSlice::Udp(their_udp))) => {
            assert_eq!(our_udp.src_port, their_udp.source_port());
            assert_eq!(our_udp.dst_port, their_udp.destination_port());
            assert_eq!(our_udp.payload, their_udp.payload(), "UDP payload boundary");
        }
        (ours, theirs) => panic!("transport layer disagreement: {ours:?} vs {theirs:?}"),
    }
}

fn laptop() -> MacAddr {
    MacAddr([0x3C, 0x22, 0xFB, 1, 2, 3])
}
fn server() -> MacAddr {
    MacAddr([0xDC, 0xA6, 0x32, 4, 5, 6])
}
fn ip(a: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, a)
}

#[test]
fn tcp_syn_agrees() {
    let frame = Packet::ethernet(laptop(), server())
        .ipv4(ip(1), ip(2))
        .tcp(50000, 443)
        .syn()
        .seq(12345)
        .build();
    assert_agrees(&frame);
}

#[test]
fn tcp_with_tls_payload_agrees() {
    let frame = Packet::ethernet(laptop(), server())
        .ipv4(ip(1), ip(2))
        .tcp(50000, 443)
        .payload(&tls_client_hello("differential.example"));
    assert_agrees(&frame);
}

#[test]
fn tcp_with_http_payload_agrees() {
    let frame = Packet::ethernet(laptop(), server())
        .ipv4(ip(1), ip(2))
        .tcp(50000, 80)
        .payload(&http_get("intranet.local", "/"));
    assert_agrees(&frame);
}

#[test]
fn udp_dns_agrees() {
    let frame = Packet::ethernet(laptop(), server())
        .ipv4(ip(1), ip(2))
        .udp(40000, 53)
        .payload(&dns_query(0x4242, "differential.example"));
    assert_agrees(&frame);
}

#[test]
fn vlan_tagged_frame_agrees() {
    let frame = Packet::ethernet(laptop(), server())
        .vlan(100)
        .ipv4(ip(1), ip(2))
        .tcp(50000, 22)
        .syn()
        .build();
    assert_agrees(&frame);
}

#[test]
fn ipv4_checksums_are_valid_per_etherparse() {
    // etherparse can verify the header checksum; our fixture builder must emit
    // correct ones, which also validates the builder used everywhere else.
    let frame = Packet::ethernet(laptop(), server())
        .ipv4(ip(1), ip(2))
        .udp(40000, 53)
        .payload(&dns_query(1, "checksum.test"));
    let theirs = SlicedPacket::from_ethernet(&frame).unwrap();
    let Some(NetSlice::Ipv4(ipv4)) = theirs.net else {
        panic!("no ipv4")
    };
    assert!(
        ipv4.header().to_header().calc_header_checksum() == ipv4.header().header_checksum(),
        "fixture builder emitted a wrong IPv4 checksum"
    );
}
