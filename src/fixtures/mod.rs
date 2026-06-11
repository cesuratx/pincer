//! Packet factory for tests, committed samples, and `pincer gen`.
//!
//! Typestate builder: each layer method returns a *different* stage type, so
//! an invalid stack (TCP before IP) is a compile error, not a runtime bug.
//! All length fields and checksums (IPv4 header, TCP/UDP pseudo-header) are
//! computed for you — the writer/reader pair forms a closed test loop with
//! `etherparse` as the independent referee.

pub mod scenarios;

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::types::MacAddr;

/// Entry point: `Packet::ethernet(src, dst).ipv4(..).udp(..).payload(..)`.
#[derive(Debug)]
pub struct Packet;

impl Packet {
    #[must_use]
    pub fn ethernet(src: MacAddr, dst: MacAddr) -> EthStage {
        EthStage {
            src,
            dst,
            vlans: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct EthStage {
    src: MacAddr,
    dst: MacAddr,
    /// `(TPID, VID)` per tag, outermost first.
    vlans: Vec<(u16, u16)>,
}

impl EthStage {
    /// 802.1Q customer tag (TPID 0x8100).
    #[must_use]
    pub fn vlan(self, vid: u16) -> Self {
        self.vlan_tpid(0x8100, vid)
    }

    /// VLAN tag with an explicit tag protocol ID — 0x88A8 (802.1ad service
    /// tag) or a pre-standard 0x9100/0x9200/0x9300 for `QinQ` outer tags.
    #[must_use]
    pub fn vlan_tpid(mut self, tpid: u16, vid: u16) -> Self {
        self.vlans.push((tpid, vid & 0x0FFF));
        self
    }

    fn frame(&self, ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(14 + 4 * self.vlans.len() + payload.len());
        out.extend_from_slice(&self.dst.0);
        out.extend_from_slice(&self.src.0);
        for (tpid, vid) in &self.vlans {
            out.extend_from_slice(&tpid.to_be_bytes());
            out.extend_from_slice(&vid.to_be_bytes());
        }
        out.extend_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(payload);
        // Real NICs pad runt frames to 60 bytes; emulate for realism.
        while out.len() < 60 {
            out.push(0);
        }
        out
    }

    #[must_use]
    pub fn ipv4(self, src: Ipv4Addr, dst: Ipv4Addr) -> Ipv4Stage {
        Ipv4Stage {
            eth: self,
            src,
            dst,
            ttl: 64,
            ident: 0x4000,
            options: Vec::new(),
        }
    }

    #[must_use]
    pub fn ipv6(self, src: Ipv6Addr, dst: Ipv6Addr) -> Ipv6Stage {
        Ipv6Stage {
            eth: self,
            src,
            dst,
            hop_limit: 64,
            hop_by_hop: false,
        }
    }

    #[must_use]
    pub fn arp_request(self, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
        let body = arp_body(1, self.src, sender_ip, MacAddr::ZERO, target_ip);
        self.frame(0x0806, &body)
    }

    #[must_use]
    pub fn arp_reply(
        self,
        sender_ip: Ipv4Addr,
        target_mac: MacAddr,
        target_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let body = arp_body(2, self.src, sender_ip, target_mac, target_ip);
        self.frame(0x0806, &body)
    }
}

fn arp_body(
    op: u16,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(28);
    body.extend_from_slice(&1u16.to_be_bytes()); // Ethernet
    body.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    body.push(6);
    body.push(4);
    body.extend_from_slice(&op.to_be_bytes());
    body.extend_from_slice(&sender_mac.0);
    body.extend_from_slice(&sender_ip.octets());
    body.extend_from_slice(&target_mac.0);
    body.extend_from_slice(&target_ip.octets());
    body
}

#[derive(Debug)]
pub struct Ipv4Stage {
    eth: EthStage,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ttl: u8,
    ident: u16,
    options: Vec<u8>,
}

impl Ipv4Stage {
    #[must_use]
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    #[must_use]
    pub fn ident(mut self, ident: u16) -> Self {
        self.ident = ident;
        self
    }

    /// IPv4 options bytes, padded here to a 4-byte boundary (zero
    /// End-of-Options padding) and capped at the protocol maximum of 40.
    /// Raises the IHL above 5 — the decoder's options skip decides where the
    /// transport header (and everything sniffed above it) begins.
    #[must_use]
    pub fn ip_options(mut self, options: &[u8]) -> Self {
        let mut padded = options.get(..options.len().min(40)).unwrap_or(&[]).to_vec();
        padded.resize(padded.len().next_multiple_of(4).min(40), 0);
        self.options = padded;
        self
    }

    #[must_use]
    pub fn udp(self, src_port: u16, dst_port: u16) -> UdpStage {
        UdpStage {
            ip: IpStage::V4(self),
            src_port,
            dst_port,
        }
    }

    #[must_use]
    pub fn tcp(self, src_port: u16, dst_port: u16) -> TcpStage {
        TcpStage {
            ip: IpStage::V4(self),
            src_port,
            dst_port,
            seq: 1000,
            ack: 0,
            flags: 0x18, // PSH+ACK default for data segments
            options: Vec::new(),
        }
    }

    /// ICMP echo (request if `request`, else reply).
    #[must_use]
    pub fn icmp_echo(self, request: bool) -> Vec<u8> {
        let mut icmp = vec![if request { 8 } else { 0 }, 0, 0, 0, 0, 1, 0, 1];
        icmp.extend_from_slice(b"pincer-ping");
        let checksum = internet_checksum(&[&icmp]);
        splice_u16(&mut icmp, 2, checksum);
        self.build(1, &icmp)
    }

    fn build(self, proto: u8, payload: &[u8]) -> Vec<u8> {
        // `ip_options` pre-pads to a 4-byte multiple and caps at 40, so the
        // header length is always expressible as an IHL of 5..=15 words.
        let header_len = 20 + self.options.len();
        let total_len = len_u16(header_len + payload.len());
        let mut header = Vec::with_capacity(header_len);
        header.push(0x40 | u8::try_from(header_len / 4).unwrap_or(5)); // version 4, IHL
        header.push(0);
        header.extend_from_slice(&total_len.to_be_bytes());
        header.extend_from_slice(&self.ident.to_be_bytes());
        header.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
        header.push(self.ttl);
        header.push(proto);
        header.extend_from_slice(&[0, 0]); // checksum placeholder
        header.extend_from_slice(&self.src.octets());
        header.extend_from_slice(&self.dst.octets());
        header.extend_from_slice(&self.options);
        let checksum = internet_checksum(&[&header]);
        splice_u16(&mut header, 10, checksum);

        let mut packet = header;
        packet.extend_from_slice(payload);
        self.eth.frame(0x0800, &packet)
    }

    fn pseudo_header(&self, proto: u8, len: u16) -> Vec<u8> {
        let mut pseudo = Vec::with_capacity(12);
        pseudo.extend_from_slice(&self.src.octets());
        pseudo.extend_from_slice(&self.dst.octets());
        pseudo.push(0);
        pseudo.push(proto);
        pseudo.extend_from_slice(&len.to_be_bytes());
        pseudo
    }
}

#[derive(Debug)]
pub struct Ipv6Stage {
    eth: EthStage,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    hop_limit: u8,
    hop_by_hop: bool,
}

impl Ipv6Stage {
    /// Insert a minimal hop-by-hop extension header (8 octets, PadN-filled)
    /// between the fixed header and the transport: the decoder must walk the
    /// next-header chain instead of trusting the fixed header's value.
    #[must_use]
    pub fn hop_by_hop(mut self) -> Self {
        self.hop_by_hop = true;
        self
    }

    #[must_use]
    pub fn udp(self, src_port: u16, dst_port: u16) -> UdpStage {
        UdpStage {
            ip: IpStage::V6(self),
            src_port,
            dst_port,
        }
    }

    #[must_use]
    pub fn tcp(self, src_port: u16, dst_port: u16) -> TcpStage {
        TcpStage {
            ip: IpStage::V6(self),
            src_port,
            dst_port,
            seq: 1000,
            ack: 0,
            flags: 0x18,
            options: Vec::new(),
        }
    }

    /// `ICMPv6` echo (type 128 request / 129 reply), checksummed over the v6
    /// pseudo-header.
    #[must_use]
    pub fn icmpv6_echo(self, request: bool) -> Vec<u8> {
        let mut icmp = vec![if request { 128 } else { 129 }, 0, 0, 0, 0, 1, 0, 1];
        icmp.extend_from_slice(b"pincer-ping");
        let pseudo = self.pseudo_header(58, len_u16(icmp.len()));
        let checksum = internet_checksum(&[&pseudo, &icmp]);
        splice_u16(&mut icmp, 2, checksum);
        self.build(58, &icmp)
    }

    fn build(self, next_header: u8, payload: &[u8]) -> Vec<u8> {
        // Hop-by-hop: next-header, length 0 (= 8 octets total), PadN(4).
        let ext_block = [next_header, 0, 1, 4, 0, 0, 0, 0];
        let ext: &[u8] = if self.hop_by_hop { &ext_block } else { &[] };
        let first_header = if self.hop_by_hop { 0 } else { next_header };
        let mut header = Vec::with_capacity(40);
        header.extend_from_slice(&0x6000_0000u32.to_be_bytes());
        header.extend_from_slice(&len_u16(ext.len() + payload.len()).to_be_bytes());
        header.push(first_header);
        header.push(self.hop_limit);
        header.extend_from_slice(&self.src.octets());
        header.extend_from_slice(&self.dst.octets());
        let mut packet = header;
        packet.extend_from_slice(ext);
        packet.extend_from_slice(payload);
        self.eth.frame(0x86DD, &packet)
    }

    fn pseudo_header(&self, proto: u8, len: u16) -> Vec<u8> {
        let mut pseudo = Vec::with_capacity(40);
        pseudo.extend_from_slice(&self.src.octets());
        pseudo.extend_from_slice(&self.dst.octets());
        pseudo.extend_from_slice(&u32::from(len).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, proto]);
        pseudo
    }
}

#[derive(Debug)]
enum IpStage {
    V4(Ipv4Stage),
    V6(Ipv6Stage),
}

#[derive(Debug)]
pub struct UdpStage {
    ip: IpStage,
    src_port: u16,
    dst_port: u16,
}

impl UdpStage {
    /// Finish the packet with this UDP payload.
    #[must_use]
    pub fn payload(self, data: &[u8]) -> Vec<u8> {
        let udp_len = len_u16(8 + data.len());
        let mut udp = Vec::with_capacity(8 + data.len());
        udp.extend_from_slice(&self.src_port.to_be_bytes());
        udp.extend_from_slice(&self.dst_port.to_be_bytes());
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // checksum placeholder
        udp.extend_from_slice(data);

        match self.ip {
            IpStage::V4(ip) => {
                let pseudo = ip.pseudo_header(17, udp_len);
                let mut checksum = internet_checksum(&[&pseudo, &udp]);
                if checksum == 0 {
                    checksum = 0xFFFF; // 0 means "no checksum" in UDP
                }
                splice_u16(&mut udp, 6, checksum);
                ip.build(17, &udp)
            }
            IpStage::V6(ip) => {
                let pseudo = ip.pseudo_header(17, udp_len);
                let mut checksum = internet_checksum(&[&pseudo, &udp]);
                if checksum == 0 {
                    checksum = 0xFFFF;
                }
                splice_u16(&mut udp, 6, checksum);
                ip.build(17, &udp)
            }
        }
    }
}

#[derive(Debug)]
pub struct TcpStage {
    ip: IpStage,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    options: Vec<u8>,
}

impl TcpStage {
    #[must_use]
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    #[must_use]
    pub fn syn(self) -> Self {
        self.flags(0x02)
    }

    #[must_use]
    pub fn syn_ack(self) -> Self {
        self.flags(0x12)
    }

    #[must_use]
    pub fn ack_only(self) -> Self {
        self.flags(0x10)
    }

    #[must_use]
    pub fn fin_ack(self) -> Self {
        self.flags(0x11)
    }

    #[must_use]
    pub fn rst(self) -> Self {
        self.flags(0x04)
    }

    #[must_use]
    pub fn seq(mut self, seq: u32) -> Self {
        self.seq = seq;
        self
    }

    #[must_use]
    pub fn ack(mut self, ack: u32) -> Self {
        self.ack = ack;
        self
    }

    /// TCP options bytes, padded here to a 4-byte boundary (end-of-list
    /// padding) and capped at the protocol maximum of 40. Raises the data
    /// offset above 5 — real SYNs virtually always carry options, and the
    /// decoder's offset arithmetic decides where the payload (and therefore
    /// HTTP/TLS sniffing) begins.
    #[must_use]
    pub fn tcp_options(mut self, options: &[u8]) -> Self {
        let mut padded = options.get(..options.len().min(40)).unwrap_or(&[]).to_vec();
        padded.resize(padded.len().next_multiple_of(4).min(40), 0);
        self.options = padded;
        self
    }

    /// Finish with no payload (handshake segments).
    #[must_use]
    pub fn build(self) -> Vec<u8> {
        self.payload(&[])
    }

    /// Finish the packet with this TCP payload.
    #[must_use]
    pub fn payload(self, data: &[u8]) -> Vec<u8> {
        let header_len = 20 + self.options.len();
        let tcp_len = len_u16(header_len + data.len());
        let mut tcp = Vec::with_capacity(header_len + data.len());
        tcp.extend_from_slice(&self.src_port.to_be_bytes());
        tcp.extend_from_slice(&self.dst_port.to_be_bytes());
        tcp.extend_from_slice(&self.seq.to_be_bytes());
        tcp.extend_from_slice(&self.ack.to_be_bytes());
        let offset_words = u8::try_from(header_len / 4).unwrap_or(5);
        tcp.push(offset_words << 4);
        tcp.push(self.flags);
        tcp.extend_from_slice(&0xFFFFu16.to_be_bytes()); // window
        tcp.extend_from_slice(&[0, 0]); // checksum placeholder
        tcp.extend_from_slice(&[0, 0]); // urgent pointer
        tcp.extend_from_slice(&self.options);
        tcp.extend_from_slice(data);

        match self.ip {
            IpStage::V4(ip) => {
                let pseudo = ip.pseudo_header(6, tcp_len);
                let checksum = internet_checksum(&[&pseudo, &tcp]);
                splice_u16(&mut tcp, 16, checksum);
                ip.build(6, &tcp)
            }
            IpStage::V6(ip) => {
                let pseudo = ip.pseudo_header(6, tcp_len);
                let checksum = internet_checksum(&[&pseudo, &tcp]);
                splice_u16(&mut tcp, 16, checksum);
                ip.build(6, &tcp)
            }
        }
    }
}

/// RFC 1071 one's-complement checksum over the given byte slices.
fn internet_checksum(parts: &[&[u8]]) -> u16 {
    // u64 accumulator: a u32 one overflows — and panics under
    // overflow-checks — after ~128 KiB of 0xFF bytes, reachable through a
    // large fixture payload. Overflowing u64 would take 2^48 16-bit words
    // (half a petabyte), which cannot exist in memory.
    let mut sum = 0u64;
    let mut leftover: Option<u8> = None;
    for part in parts {
        for &byte in *part {
            if let Some(high) = leftover.take() {
                sum += u64::from(u16::from_be_bytes([high, byte]));
            } else {
                leftover = Some(byte);
            }
        }
    }
    if let Some(high) = leftover {
        sum += u64::from(u16::from_be_bytes([high, 0]));
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(0xFFFF)
}

fn splice_u16(buf: &mut [u8], offset: usize, value: u16) {
    let bytes = value.to_be_bytes();
    if let Some(slot) = buf.get_mut(offset..offset + 2) {
        slot.copy_from_slice(&bytes);
    }
}

fn len_u16(len: usize) -> u16 {
    u16::try_from(len).unwrap_or(u16::MAX)
}

fn len_u8(len: usize) -> u8 {
    u8::try_from(len).unwrap_or(u8::MAX)
}

// ---------------------------------------------------------------------------
// Application payload builders
// ---------------------------------------------------------------------------

/// Encode `example.com` as `\x07example\x03com\x00`.
#[must_use]
pub fn dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        let bytes = label.as_bytes();
        let take = bytes.len().min(63);
        out.push(u8::try_from(take).unwrap_or(63));
        out.extend(bytes.iter().take(take));
    }
    out.push(0);
    out
}

/// A query for one A record.
#[must_use]
pub fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&[0x01, 0x00]); // RD
    msg.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    msg.extend_from_slice(&dns_name(name));
    msg.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    msg
}

/// A response with one A answer that uses a compression pointer back to the
/// question name — exercises the decompression path on every fixture run.
#[must_use]
pub fn dns_response_a(id: u16, name: &str, addr: Ipv4Addr) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&[0x81, 0x80]); // QR, RD, RA
    msg.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
    msg.extend_from_slice(&dns_name(name));
    msg.extend_from_slice(&[0, 1, 0, 1]);
    msg.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12
    msg.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    msg.extend_from_slice(&60u32.to_be_bytes()); // ttl
    msg.extend_from_slice(&[0, 4]);
    msg.extend_from_slice(&addr.octets());
    msg
}

/// An mDNS announcement: one A record (no question section).
#[must_use]
pub fn mdns_announce_a(name: &str, addr: Ipv4Addr) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0, 0]); // id 0 for mDNS
    msg.extend_from_slice(&[0x84, 0x00]); // QR, AA
    msg.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
    msg.extend_from_slice(&dns_name(name));
    msg.extend_from_slice(&[0, 1, 0x80, 1]); // A, cache-flush + IN
    msg.extend_from_slice(&120u32.to_be_bytes());
    msg.extend_from_slice(&[0, 4]);
    msg.extend_from_slice(&addr.octets());
    msg
}

/// An mDNS SRV announcement (service instance → host:port).
#[must_use]
pub fn mdns_announce_srv(instance: &str, port: u16, target: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0, 0]);
    msg.extend_from_slice(&[0x84, 0x00]);
    msg.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
    msg.extend_from_slice(&dns_name(instance));
    msg.extend_from_slice(&[0, 33, 0x80, 1]); // SRV
    msg.extend_from_slice(&120u32.to_be_bytes());
    let target_encoded = dns_name(target);
    msg.extend_from_slice(&len_u16(6 + target_encoded.len()).to_be_bytes());
    msg.extend_from_slice(&[0, 0, 0, 0]); // priority, weight
    msg.extend_from_slice(&port.to_be_bytes());
    msg.extend_from_slice(&target_encoded);
    msg
}

/// Options for building DHCP fixture payloads.
#[derive(Debug, Default)]
pub struct DhcpOptions<'a> {
    pub hostname: Option<&'a str>,
    pub vendor_class: Option<&'a str>,
    pub param_req_list: &'a [u8],
    pub your_ip: Option<Ipv4Addr>,
    pub requested_ip: Option<Ipv4Addr>,
    pub server_id: Option<Ipv4Addr>,
    /// DHCP option 1 — the real subnet mask, when set.
    pub subnet_mask: Option<Ipv4Addr>,
    /// `giaddr` — marks the exchange as relayed from another segment.
    pub relay_ip: Option<Ipv4Addr>,
}

/// BOOTP/DHCP payload with the given message type and options.
#[must_use]
pub fn dhcp(msg_type: u8, client_mac: MacAddr, xid: u32, opts: &DhcpOptions<'_>) -> Vec<u8> {
    let mut msg = vec![
        if matches!(msg_type, 2 | 5 | 6) { 2 } else { 1 }, // op: reply for OFFER/ACK/NAK
        1,
        6,
        0,
    ];
    msg.extend_from_slice(&xid.to_be_bytes());
    msg.extend_from_slice(&[0u8; 8]); // secs, flags, ciaddr
    msg.extend_from_slice(&opts.your_ip.unwrap_or(Ipv4Addr::UNSPECIFIED).octets());
    msg.extend_from_slice(&[0u8; 4]); // siaddr
    msg.extend_from_slice(&opts.relay_ip.unwrap_or(Ipv4Addr::UNSPECIFIED).octets()); // giaddr
    msg.extend_from_slice(&client_mac.0);
    msg.extend_from_slice(&[0u8; 10]);
    msg.extend_from_slice(&[0u8; 192]); // sname + file
    msg.extend_from_slice(&0x6382_5363u32.to_be_bytes());
    msg.extend_from_slice(&[53, 1, msg_type]);
    if let Some(mask) = opts.subnet_mask {
        msg.push(1);
        msg.push(4);
        msg.extend_from_slice(&mask.octets());
    }
    if let Some(hostname) = opts.hostname {
        msg.push(12);
        msg.push(len_u8(hostname.len()));
        msg.extend_from_slice(hostname.as_bytes());
    }
    if let Some(vendor) = opts.vendor_class {
        msg.push(60);
        msg.push(len_u8(vendor.len()));
        msg.extend_from_slice(vendor.as_bytes());
    }
    if !opts.param_req_list.is_empty() {
        msg.push(55);
        msg.push(len_u8(opts.param_req_list.len()));
        msg.extend_from_slice(opts.param_req_list);
    }
    if let Some(ip) = opts.requested_ip {
        msg.push(50);
        msg.push(4);
        msg.extend_from_slice(&ip.octets());
    }
    if let Some(ip) = opts.server_id {
        msg.push(54);
        msg.push(4);
        msg.extend_from_slice(&ip.octets());
    }
    msg.push(255);
    msg
}

/// A minimal but structurally valid TLS `ClientHello` with an SNI extension.
#[must_use]
pub fn tls_client_hello(sni: &str) -> Vec<u8> {
    // SNI extension body
    let host = sni.as_bytes();
    let mut sni_body = Vec::new();
    sni_body.extend_from_slice(&len_u16(host.len() + 3).to_be_bytes()); // list len
    sni_body.push(0); // name_type host
    sni_body.extend_from_slice(&len_u16(host.len()).to_be_bytes());
    sni_body.extend_from_slice(host);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0, 0]); // server_name
    extensions.extend_from_slice(&len_u16(sni_body.len()).to_be_bytes());
    extensions.extend_from_slice(&sni_body);
    // supported_versions extension for realism
    extensions.extend_from_slice(&[0, 43, 0, 3, 2, 3, 4]);

    let mut hello = Vec::new();
    hello.extend_from_slice(&[3, 3]); // client version TLS 1.2
    hello.extend_from_slice(&[0x42; 32]); // random
    hello.push(0); // session id len
    hello.extend_from_slice(&[0, 4, 0x13, 0x01, 0x13, 0x02]); // two suites
    hello.extend_from_slice(&[1, 0]); // null compression
    hello.extend_from_slice(&len_u16(extensions.len()).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut handshake = vec![1]; // ClientHello
    let hs_len = u32::try_from(hello.len()).unwrap_or(0).to_be_bytes();
    handshake.extend_from_slice(&[hs_len[1], hs_len[2], hs_len[3]]); // u24 length
    handshake.extend_from_slice(&hello);

    let mut record = vec![22, 3, 1]; // handshake, TLS 1.0 record version
    record.extend_from_slice(&len_u16(handshake.len()).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// `GET <path> HTTP/1.1` with a Host header.
#[must_use]
pub fn http_get(host: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: pincer-fixture/1.0\r\nAccept: */*\r\n\r\n")
        .into_bytes()
}

/// Client-mode NTP packet (48 bytes) — deliberately has no decoder, so the
/// service shows up by port heuristic only. Great "add a decoder" drill.
#[must_use]
pub fn ntp_client() -> Vec<u8> {
    let mut msg = vec![0x23]; // LI=0, VN=4, mode=3 (client)
    msg.resize(48, 0);
    msg
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;
    use crate::decode::{NetView, TransportView, decode_packet};
    use crate::pcap::{LinkType, Record};
    use crate::types::Timestamp;

    fn decode(frame: &[u8]) -> crate::decode::PacketView<'_> {
        decode_packet(&Record {
            ts: Some(Timestamp::ZERO),
            orig_len: u32::try_from(frame.len()).unwrap(),
            link_type: LinkType::Ethernet,
            data: frame,
        })
        .unwrap()
    }

    #[test]
    fn typestate_builds_decodable_udp() {
        let frame = Packet::ethernet(MacAddr([2; 6]), MacAddr([4; 6]))
            .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
            .udp(40000, 53)
            .payload(&dns_query(7, "example.com"));
        let pkt = decode(&frame);
        let NetView::Ipv4(ip) = &pkt.net else {
            panic!("expected ipv4")
        };
        assert_eq!(ip.src, Ipv4Addr::new(10, 0, 0, 1));
        let Some(TransportView::Udp(udp)) = &pkt.transport else {
            panic!("expected udp")
        };
        assert_eq!((udp.src_port, udp.dst_port), (40000, 53));
        assert!(crate::app::dns::parse(udp.payload, false).is_some());
    }

    #[test]
    fn vlan_tags_survive_decode() {
        let frame = Packet::ethernet(MacAddr([2; 6]), MacAddr([4; 6]))
            .vlan(100)
            .vlan(200)
            .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
            .tcp(1234, 80)
            .syn()
            .build();
        let pkt = decode(&frame);
        let vlans: Vec<u16> = pkt.eth.vlan.iter().collect();
        assert_eq!(vlans, vec![100, 200]);
        let Some(TransportView::Tcp(tcp)) = &pkt.transport else {
            panic!("expected tcp")
        };
        assert!(tcp.flags.is_initial_syn());
    }
}
