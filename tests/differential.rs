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

use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};
use pincer::decode::{NetView, TransportView, decode_packet};
use pincer::fixtures::{Packet, dns_query, http_get, tls_client_hello};
use pincer::pcap::{LinkType, Record};
use pincer::types::{MacAddr, Timestamp};
use proptest::prelude::*;

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
fn ip6(a: u16) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, a)
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

/// IPv4 options (IHL=6, one NOP-padded option word): the options skip at
/// decode decides where the transport header begins — the same boundary bug
/// class the TCP-options coverage exists for, one layer down.
#[test]
fn ipv4_with_options_agrees() {
    let udp = Packet::ethernet(laptop(), server())
        .ipv4(ip(1), ip(2))
        .ip_options(&[1, 1, 1, 1]) // four NOPs → IHL 6
        .udp(40000, 53)
        .payload(&dns_query(7, "ihl.example"));
    let theirs = SlicedPacket::from_ethernet(&udp).unwrap();
    let Some(NetSlice::Ipv4(v4)) = &theirs.net else {
        panic!("etherparse did not decode IPv4")
    };
    assert_eq!(v4.header().ihl(), 6, "fixture must actually raise the IHL");
    assert_agrees(&udp);

    let tcp = Packet::ethernet(laptop(), server())
        .ipv4(ip(1), ip(2))
        .ip_options(&[1, 1, 1, 1])
        .tcp(50000, 80)
        .payload(&http_get("ihl.example", "/"));
    assert_agrees(&tcp);
}

/// 802.1ad `QinQ`: outer service tag (TPID 0x88A8) wrapping a customer tag
/// (0x8100). Both parsers must walk through to the same IPv4/TCP view, and
/// pincer must surface both VIDs, outer first.
#[test]
fn qinq_88a8_stacked_vlan_agrees() {
    let frame = Packet::ethernet(laptop(), server())
        .vlan_tpid(0x88A8, 100)
        .vlan(200)
        .ipv4(ip(1), ip(2))
        .tcp(50000, 443)
        .syn()
        .build();
    assert_agrees(&frame);

    let ours = decode_packet(&record(&frame)).unwrap();
    let vlans: Vec<u16> = ours.eth.vlan.iter().collect();
    assert_eq!(vlans, vec![100, 200], "both tags survive, outer first");
}

/// IPv6 hop-by-hop extension header before TCP: the extension walk decides
/// the final next-header and therefore the transport boundary.
#[test]
fn ipv6_hop_by_hop_before_tcp_agrees() {
    let frame = Packet::ethernet(laptop(), server())
        .ipv6(ip6(1), ip6(2))
        .hop_by_hop()
        .tcp(50000, 443)
        .payload(&http_get("v6.example", "/"));

    let ours = decode_packet(&record(&frame)).unwrap();
    let theirs = SlicedPacket::from_ethernet(&frame).unwrap();

    let NetView::Ipv6(our_ip) = &ours.net else {
        panic!("pincer did not decode IPv6")
    };
    assert_eq!(our_ip.next_header, 6, "extension walk must land on TCP");
    let Some(NetSlice::Ipv6(their_ip)) = &theirs.net else {
        panic!("etherparse did not decode IPv6")
    };
    assert_eq!(our_ip.src.octets(), their_ip.header().source());
    assert_eq!(our_ip.dst.octets(), their_ip.header().destination());

    match (&ours.transport, &theirs.transport) {
        (Some(TransportView::Tcp(our_tcp)), Some(TransportSlice::Tcp(their_tcp))) => {
            assert_eq!(our_tcp.src_port, their_tcp.source_port());
            assert_eq!(our_tcp.dst_port, their_tcp.destination_port());
            assert_eq!(
                our_tcp.payload,
                their_tcp.payload(),
                "TCP payload boundary past the extension header"
            );
        }
        (ours, theirs) => panic!("transport layer disagreement: {ours:?} vs {theirs:?}"),
    }
}

/// ICMP echo: type and code, request and reply, cross-checked.
#[test]
fn icmp_echo_type_and_code_agree() {
    for request in [true, false] {
        let frame = Packet::ethernet(laptop(), server())
            .ipv4(ip(1), ip(2))
            .icmp_echo(request);
        let ours = decode_packet(&record(&frame)).unwrap();
        let theirs = SlicedPacket::from_ethernet(&frame).unwrap();
        let Some(TransportView::Icmp(our_icmp)) = &ours.transport else {
            panic!("pincer did not decode ICMP")
        };
        let Some(TransportSlice::Icmpv4(their_icmp)) = &theirs.transport else {
            panic!("etherparse did not decode ICMPv4")
        };
        assert!(!our_icmp.v6);
        assert_eq!(our_icmp.icmp_type, their_icmp.type_u8());
        assert_eq!(our_icmp.code, their_icmp.code_u8());
        assert_eq!(our_icmp.icmp_type, if request { 8 } else { 0 });
    }
}

/// The `ICMPv6` twin: IPv6 next-header 58 must yield the v6-flavored view
/// with echo types 128/129, agreeing with etherparse.
#[test]
fn icmpv6_echo_type_and_code_agree() {
    for request in [true, false] {
        let frame = Packet::ethernet(laptop(), server())
            .ipv6(ip6(1), ip6(2))
            .icmpv6_echo(request);
        let ours = decode_packet(&record(&frame)).unwrap();
        let theirs = SlicedPacket::from_ethernet(&frame).unwrap();
        let Some(TransportView::Icmp(our_icmp)) = &ours.transport else {
            panic!("pincer did not decode ICMPv6")
        };
        let Some(TransportSlice::Icmpv6(their_icmp)) = &theirs.transport else {
            panic!("etherparse did not decode ICMPv6")
        };
        assert!(our_icmp.v6, "next-header 58 is the v6 flavor");
        assert_eq!(our_icmp.icmp_type, their_icmp.type_u8());
        assert_eq!(our_icmp.code, their_icmp.code_u8());
        assert_eq!(our_icmp.icmp_type, if request { 128 } else { 129 });
    }
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

/// The 5-tuple-and-payload-boundary agreement the fixed frames above assert,
/// for frames *built by etherparse* — both parsers must read back what the
/// independent builder wrote, for either IP version and either transport.
fn assert_round_trip_agrees(frame: &[u8], ports: (u16, u16), payload: &[u8]) {
    let ours = decode_packet(&record(frame)).unwrap();
    let theirs = SlicedPacket::from_ethernet(frame).unwrap();

    match (&ours.net, &theirs.net) {
        (NetView::Ipv4(o), Some(NetSlice::Ipv4(t))) => {
            assert_eq!(o.src.octets(), t.header().source());
            assert_eq!(o.dst.octets(), t.header().destination());
        }
        (NetView::Ipv6(o), Some(NetSlice::Ipv6(t))) => {
            assert_eq!(o.src.octets(), t.header().source());
            assert_eq!(o.dst.octets(), t.header().destination());
        }
        (o, t) => panic!("net layer disagreement: {o:?} vs {t:?}"),
    }
    match (&ours.transport, &theirs.transport) {
        (Some(TransportView::Tcp(o)), Some(TransportSlice::Tcp(t))) => {
            assert_eq!((o.src_port, o.dst_port), ports);
            assert_eq!((t.source_port(), t.destination_port()), ports);
            assert_eq!(o.payload, payload, "TCP payload boundary");
            assert_eq!(t.payload(), payload);
        }
        (Some(TransportView::Udp(o)), Some(TransportSlice::Udp(t))) => {
            assert_eq!((o.src_port, o.dst_port), ports);
            assert_eq!((t.source_port(), t.destination_port()), ports);
            assert_eq!(o.payload, payload, "UDP payload boundary");
            assert_eq!(t.payload(), payload);
        }
        (o, t) => panic!("transport layer disagreement: {o:?} vs {t:?}"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Generative oracle: etherparse *builds* random valid packets — IPv4 and
    /// IPv6 crossed with TCP and UDP, arbitrary addresses, ports, and payload
    /// — and pincer must agree on the 5-tuple and payload boundary. Turns the
    /// fixed-frame spot checks above into a property over the valid space.
    #[test]
    fn random_valid_packets_agree(
        v6 in any::<bool>(),
        tcp in any::<bool>(),
        src in any::<[u8; 16]>(),
        dst in any::<[u8; 16]>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
        seq in any::<u32>(),
        window in any::<u16>(),
        payload in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let eth = PacketBuilder::ethernet2(laptop().0, server().0);
        let mut frame = Vec::new();
        match (v6, tcp) {
            (false, false) => eth
                .ipv4(src[..4].try_into().unwrap(), dst[..4].try_into().unwrap(), 64)
                .udp(src_port, dst_port)
                .write(&mut frame, &payload)
                .unwrap(),
            (false, true) => eth
                .ipv4(src[..4].try_into().unwrap(), dst[..4].try_into().unwrap(), 64)
                .tcp(src_port, dst_port, seq, window)
                .write(&mut frame, &payload)
                .unwrap(),
            (true, false) => eth
                .ipv6(src, dst, 64)
                .udp(src_port, dst_port)
                .write(&mut frame, &payload)
                .unwrap(),
            (true, true) => eth
                .ipv6(src, dst, 64)
                .tcp(src_port, dst_port, seq, window)
                .write(&mut frame, &payload)
                .unwrap(),
        }
        assert_round_trip_agrees(&frame, (src_port, dst_port), &payload);
    }
}
