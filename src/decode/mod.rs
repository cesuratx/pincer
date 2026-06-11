//! Zero-copy packet layer decoders. A [`PacketView`] borrows the reader's
//! buffer; decoding allocates nothing. Failures below Ethernet are recorded
//! *in* the view (`Malformed` variants) so one hostile packet costs an anomaly
//! counter, never the analysis.
#![deny(clippy::arithmetic_side_effects)]

pub mod arp;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod ipv6;
pub mod rawip;
pub mod sctp;
pub mod sll;
pub mod tcp;
pub mod udp;

use std::net::IpAddr;

pub use arp::ArpView;
pub use ethernet::{EthView, VlanStack};
pub use icmp::IcmpView;
pub use ipv4::Ipv4View;
pub use ipv6::Ipv6View;
pub use sctp::SctpView;
pub use tcp::{TcpFlags, TcpView};
pub use udp::UdpView;

use crate::bytes::Cursor;
use crate::error::DecodeError;
use crate::pcap::{LinkType, Record};
use crate::types::Timestamp;

/// Network layer, or why it could not be decoded.
#[derive(Debug)]
pub enum NetView<'a> {
    Arp(ArpView),
    Ipv4(Ipv4View<'a>),
    Ipv6(Ipv6View<'a>),
    /// `EtherType` we do not decode (LLDP, MPLS, …).
    Unknown {
        ethertype: u16,
    },
    Malformed {
        layer: &'static str,
        err: DecodeError,
    },
}

/// Transport layer, or why it could not be decoded.
#[derive(Debug)]
pub enum TransportView<'a> {
    Tcp(TcpView<'a>),
    Udp(UdpView<'a>),
    Sctp(SctpView),
    Icmp(IcmpView),
    /// IP protocol we do not decode (GRE, ESP, …).
    Other {
        proto: u8,
    },
    Malformed {
        layer: &'static str,
        err: DecodeError,
    },
}

/// One decoded packet. All slices borrow the capture buffer.
#[derive(Debug)]
pub struct PacketView<'a> {
    /// Capture time; `None` when the container carried no per-record
    /// timestamp (pcapng Simple Packet Blocks). Sinks must skip, not invent.
    pub ts: Option<Timestamp>,
    /// Length on the wire (used for byte accounting).
    pub orig_len: u32,
    /// Bytes actually captured.
    pub cap_len: u32,
    pub eth: EthView,
    pub net: NetView<'a>,
    pub transport: Option<TransportView<'a>>,
    /// Snaplen cut this packet short somewhere.
    pub truncated: bool,
}

impl PacketView<'_> {
    /// Source/destination IPs if the packet has an IP layer.
    #[must_use]
    pub fn ip_pair(&self) -> Option<(IpAddr, IpAddr)> {
        match &self.net {
            NetView::Ipv4(ip) => Some((IpAddr::V4(ip.src), IpAddr::V4(ip.dst))),
            NetView::Ipv6(ip) => Some((IpAddr::V6(ip.src), IpAddr::V6(ip.dst))),
            _ => None,
        }
    }
}

/// Decode one captured record. `Err` only when even the link header is
/// unreadable (or the link type is unsupported); deeper failures land in the
/// view's `Malformed` variants.
pub fn decode_packet<'a>(record: &Record<'a>) -> Result<PacketView<'a>, DecodeError> {
    let mut cur = Cursor::new(record.data);
    let eth = match record.link_type {
        LinkType::Ethernet => ethernet::parse(&mut cur)?,
        // Linux "cooked" captures (`tcpdump -i any`): synthetic link header,
        // sender MAC only — see decode::sll.
        LinkType::LinuxSll => sll::parse_v1(&mut cur)?,
        LinkType::LinuxSll2 => sll::parse_v2(&mut cur)?,
        // Bare-IP links: VPN/tun (RAW) and BSD/macOS loopback (NULL/LOOP).
        LinkType::Raw => rawip::parse_raw(&mut cur)?,
        LinkType::NullLoop => rawip::parse_null(&mut cur)?,
        LinkType::Other(_) => {
            return Err(DecodeError::malformed("link", "unsupported link type"));
        }
    };
    // Lossless: both readers cap record bodies at MAX_RECORD_LEN (64 MiB),
    // far below u32::MAX.
    #[allow(clippy::cast_possible_truncation)]
    let cap_len = record.data.len() as u32;
    let mut truncated = cap_len < record.orig_len;

    let net = match eth.ethertype {
        ethernet::ETHERTYPE_ARP => match arp::parse(&mut cur) {
            Ok(view) => NetView::Arp(view),
            // Spec-valid ARP we simply do not decode must not inflate the
            // malformed (lying-packet) anomaly counter.
            Err(DecodeError::Malformed {
                reason: "unsupported hardware/protocol",
                ..
            }) => NetView::Unknown {
                ethertype: ethernet::ETHERTYPE_ARP,
            },
            Err(err) => NetView::Malformed { layer: "arp", err },
        },
        ethernet::ETHERTYPE_IPV4 => match ipv4::parse(&mut cur) {
            Ok(view) => NetView::Ipv4(view),
            Err(err) => NetView::Malformed { layer: "ipv4", err },
        },
        ethernet::ETHERTYPE_IPV6 => match ipv6::parse(&mut cur) {
            Ok(view) => NetView::Ipv6(view),
            Err(err) => NetView::Malformed { layer: "ipv6", err },
        },
        ethertype => NetView::Unknown { ethertype },
    };

    let transport = match &net {
        NetView::Ipv4(ip) => {
            truncated |= ip.payload_truncated;
            if ip.is_fragment_continuation() {
                // Non-first fragments carry no transport header; trying to
                // parse TCP at fragment offset N is the classic trap.
                None
            } else {
                Some(parse_transport(ip.proto, ip.payload))
            }
        }
        NetView::Ipv6(ip) => {
            truncated |= ip.payload_truncated;
            if ip.is_fragment_continuation() {
                // Same rule as IPv4: a non-first fragment's payload is the
                // middle of a datagram, not a transport header.
                None
            } else {
                Some(parse_transport(ip.next_header, ip.payload))
            }
        }
        _ => None,
    };

    // A transport whose length field promised more than was captured is also a
    // truncation — propagate it the same way the IP layers do, so snaplen-cut
    // UDP payloads (DNS/DHCP/NTP) are counted as anomalies, not clean packets.
    // EXCEPT the first fragment of a fragmented datagram: there the UDP length
    // describes the whole datagram by design, and the missing bytes live in
    // the other fragments, not on the cutting-room floor.
    let first_fragment = match &net {
        NetView::Ipv4(ip) => ip.is_fragmented() && !ip.is_fragment_continuation(),
        NetView::Ipv6(ip) => ip.fragmented && !ip.is_fragment_continuation(),
        _ => false,
    };
    if !first_fragment && let Some(TransportView::Udp(udp)) = &transport {
        truncated |= udp.payload_truncated;
    }

    Ok(PacketView {
        ts: record.ts,
        // The on-wire length as recorded; byte accounting uses this. The
        // readers normalize orig_len to at least the captured length (a
        // record claiming orig_len < incl_len is a writer lie), so a captured
        // length below orig_len is a genuine truncation, not a value to paper
        // over.
        orig_len: record.orig_len,
        cap_len,
        eth,
        net,
        transport,
        truncated,
    })
}

fn parse_transport(proto: u8, payload: &[u8]) -> TransportView<'_> {
    let mut cur = Cursor::new(payload);
    match proto {
        6 => match tcp::parse(&mut cur) {
            Ok(view) => TransportView::Tcp(view),
            Err(err) => TransportView::Malformed { layer: "tcp", err },
        },
        17 => match udp::parse(&mut cur) {
            Ok(view) => TransportView::Udp(view),
            Err(err) => TransportView::Malformed { layer: "udp", err },
        },
        132 => match sctp::parse(&mut cur) {
            Ok(view) => TransportView::Sctp(view),
            Err(err) => TransportView::Malformed { layer: "sctp", err },
        },
        // ICMP flavor follows the IP *protocol number*, not the outer IP
        // version — ICMPv4 tunneled in IPv6 keeps v4 type/code semantics.
        1 | 58 => match icmp::parse(&mut cur, proto == 58) {
            Ok(view) => TransportView::Icmp(view),
            Err(err) => TransportView::Malformed { layer: "icmp", err },
        },
        proto => TransportView::Other { proto },
    }
}
