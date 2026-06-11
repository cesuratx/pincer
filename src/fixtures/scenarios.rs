//! Synthetic capture scenarios. `office()` is a small office network with
//! every protocol the analyzer understands; `incident()` plants a port
//! scanner and an exfiltration-shaped flow for analysis drills.

use std::io::Write;
use std::net::Ipv4Addr;

use super::{
    DhcpOptions, Packet, dhcp, dns_query, dns_response_a, http_get, mdns_announce_a,
    mdns_announce_srv, ntp_client, tls_client_hello,
};
use crate::pcap::writer::PcapWriter;
use crate::types::{MacAddr, Timestamp};

/// Base capture time: 2026-06-10 09:00:00 UTC.
const BASE_SECS: u64 = 1_781_082_000;

pub const MAC_GATEWAY: MacAddr = MacAddr([0xAA, 0x00, 0xCC, 0x00, 0x00, 0x01]);
pub const MAC_LAPTOP: MacAddr = MacAddr([0x3C, 0x22, 0xFB, 0x10, 0x20, 0x30]);
pub const MAC_PHONE: MacAddr = MacAddr([0xD0, 0x81, 0x7A, 0x40, 0x50, 0x60]);
pub const MAC_PRINTER: MacAddr = MacAddr([0x00, 0x80, 0x77, 0x70, 0x80, 0x90]);
pub const MAC_SERVER: MacAddr = MacAddr([0xDC, 0xA6, 0x32, 0xA0, 0xB0, 0xC0]);
pub const MAC_SCANNER: MacAddr = MacAddr([0x02, 0x66, 0x66, 0x01, 0x02, 0x03]);
const MAC_MCAST: MacAddr = MacAddr([0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB]);

pub const IP_GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
pub const IP_LAPTOP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
pub const IP_PHONE: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);
pub const IP_PRINTER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 30);
pub const IP_SERVER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
pub const IP_SCANNER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 66);
pub const IP_EXAMPLE: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
pub const IP_NTP: Ipv4Addr = Ipv4Addr::new(216, 239, 35, 0);
pub const IP_EXFIL: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 99);
const IP_MCAST_MDNS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const IP_BROADCAST: Ipv4Addr = Ipv4Addr::BROADCAST;

type TimedFrame = (Timestamp, Vec<u8>);

fn at(millis: u64) -> Timestamp {
    Timestamp::new(
        BASE_SECS + millis / 1000,
        u32::try_from(millis % 1000).unwrap_or(0) * 1_000_000,
    )
}

/// A laptop joins the network (ARP + DHCP), resolves and browses
/// `example.com` over TLS, talks HTTP and SSH to the intranet server, a phone
/// and a printer announce themselves over mDNS, plus NTP and a ping.
#[must_use]
#[allow(clippy::too_many_lines, clippy::vec_init_then_push)]
pub fn office() -> Vec<TimedFrame> {
    let mut frames: Vec<TimedFrame> = Vec::new();
    let mut push = |millis: u64, frame: Vec<u8>| frames.push((at(millis), frame));

    // --- ARP: laptop resolves the gateway -------------------------------
    push(
        0,
        Packet::ethernet(MAC_LAPTOP, MacAddr::BROADCAST).arp_request(IP_LAPTOP, IP_GATEWAY),
    );
    push(
        2,
        Packet::ethernet(MAC_GATEWAY, MAC_LAPTOP).arp_reply(IP_GATEWAY, MAC_LAPTOP, IP_LAPTOP),
    );

    // --- DHCP DORA: laptop gets 192.168.1.10, hostname carols-laptop ----
    let xid = 0x0BAD_CAFE;
    let fingerprint: &[u8] = &[1, 3, 6, 15, 119, 252];
    push(
        100,
        Packet::ethernet(MAC_LAPTOP, MacAddr::BROADCAST)
            .ipv4(Ipv4Addr::UNSPECIFIED, IP_BROADCAST)
            .udp(68, 67)
            .payload(&dhcp(
                1,
                MAC_LAPTOP,
                xid,
                &DhcpOptions {
                    hostname: Some("carols-laptop"),
                    vendor_class: Some("MSFT 5.0"),
                    param_req_list: fingerprint,
                    ..DhcpOptions::default()
                },
            )),
    );
    push(
        110,
        Packet::ethernet(MAC_GATEWAY, MAC_LAPTOP)
            .ipv4(IP_GATEWAY, IP_BROADCAST)
            .udp(67, 68)
            .payload(&dhcp(
                2,
                MAC_LAPTOP,
                xid,
                &DhcpOptions {
                    your_ip: Some(IP_LAPTOP),
                    server_id: Some(IP_GATEWAY),
                    ..DhcpOptions::default()
                },
            )),
    );
    push(
        120,
        Packet::ethernet(MAC_LAPTOP, MacAddr::BROADCAST)
            .ipv4(Ipv4Addr::UNSPECIFIED, IP_BROADCAST)
            .udp(68, 67)
            .payload(&dhcp(
                3,
                MAC_LAPTOP,
                xid,
                &DhcpOptions {
                    hostname: Some("carols-laptop"),
                    param_req_list: fingerprint,
                    requested_ip: Some(IP_LAPTOP),
                    server_id: Some(IP_GATEWAY),
                    ..DhcpOptions::default()
                },
            )),
    );
    push(
        130,
        Packet::ethernet(MAC_GATEWAY, MAC_LAPTOP)
            .ipv4(IP_GATEWAY, IP_BROADCAST)
            .udp(67, 68)
            .payload(&dhcp(
                5,
                MAC_LAPTOP,
                xid,
                &DhcpOptions {
                    your_ip: Some(IP_LAPTOP),
                    server_id: Some(IP_GATEWAY),
                    ..DhcpOptions::default()
                },
            )),
    );

    // --- DNS: laptop resolves example.com via the gateway ---------------
    push(
        500,
        Packet::ethernet(MAC_LAPTOP, MAC_GATEWAY)
            .ipv4(IP_LAPTOP, IP_GATEWAY)
            .udp(54321, 53)
            .payload(&dns_query(0x1234, "example.com")),
    );
    push(
        512,
        Packet::ethernet(MAC_GATEWAY, MAC_LAPTOP)
            .ipv4(IP_GATEWAY, IP_LAPTOP)
            .udp(53, 54321)
            .payload(&dns_response_a(0x1234, "example.com", IP_EXAMPLE)),
    );

    // --- HTTPS to example.com (via gateway MAC), with SNI ---------------
    let (cport, sport) = (51514, 443);
    push(
        600,
        Packet::ethernet(MAC_LAPTOP, MAC_GATEWAY)
            .ipv4(IP_LAPTOP, IP_EXAMPLE)
            .tcp(cport, sport)
            .syn()
            .seq(3_000_000)
            .build(),
    );
    push(
        640,
        Packet::ethernet(MAC_GATEWAY, MAC_LAPTOP)
            .ipv4(IP_EXAMPLE, IP_LAPTOP)
            .ttl(52)
            .tcp(sport, cport)
            .syn_ack()
            .seq(9_000_000)
            .ack(3_000_001)
            .build(),
    );
    push(
        641,
        Packet::ethernet(MAC_LAPTOP, MAC_GATEWAY)
            .ipv4(IP_LAPTOP, IP_EXAMPLE)
            .tcp(cport, sport)
            .ack_only()
            .seq(3_000_001)
            .ack(9_000_001)
            .build(),
    );
    push(
        650,
        Packet::ethernet(MAC_LAPTOP, MAC_GATEWAY)
            .ipv4(IP_LAPTOP, IP_EXAMPLE)
            .tcp(cport, sport)
            .seq(3_000_001)
            .ack(9_000_001)
            .payload(&tls_client_hello("example.com")),
    );
    push(
        720,
        Packet::ethernet(MAC_GATEWAY, MAC_LAPTOP)
            .ipv4(IP_EXAMPLE, IP_LAPTOP)
            .ttl(52)
            .tcp(sport, cport)
            .seq(9_000_001)
            .ack(3_000_200)
            .payload(&[0x16, 0x03, 0x03, 0x00, 0x40].repeat(40)), // server hello-ish bytes
    );
    push(
        900,
        Packet::ethernet(MAC_LAPTOP, MAC_GATEWAY)
            .ipv4(IP_LAPTOP, IP_EXAMPLE)
            .tcp(cport, sport)
            .fin_ack()
            .seq(3_000_200)
            .ack(9_000_201)
            .build(),
    );

    // --- HTTP to the intranet server -------------------------------------
    let hport = 51620;
    push(
        1000,
        Packet::ethernet(MAC_LAPTOP, MAC_SERVER)
            .ipv4(IP_LAPTOP, IP_SERVER)
            .tcp(hport, 80)
            .syn()
            .seq(4_000_000)
            .build(),
    );
    push(
        1004,
        Packet::ethernet(MAC_SERVER, MAC_LAPTOP)
            .ipv4(IP_SERVER, IP_LAPTOP)
            .tcp(80, hport)
            .syn_ack()
            .seq(7_000_000)
            .ack(4_000_001)
            .build(),
    );
    push(
        1005,
        Packet::ethernet(MAC_LAPTOP, MAC_SERVER)
            .ipv4(IP_LAPTOP, IP_SERVER)
            .tcp(hport, 80)
            .ack_only()
            .seq(4_000_001)
            .ack(7_000_001)
            .build(),
    );
    push(
        1010,
        Packet::ethernet(MAC_LAPTOP, MAC_SERVER)
            .ipv4(IP_LAPTOP, IP_SERVER)
            .tcp(hport, 80)
            .seq(4_000_001)
            .ack(7_000_001)
            .payload(&http_get("intranet.local", "/status")),
    );
    push(
        1030,
        Packet::ethernet(MAC_SERVER, MAC_LAPTOP)
            .ipv4(IP_SERVER, IP_LAPTOP)
            .tcp(80, hport)
            .seq(7_000_001)
            .ack(4_000_120)
            .payload(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 64\r\n\r\n<html><body>printer online, backups green, coffee low</body></html>"),
    );

    // --- mDNS announcements ----------------------------------------------
    push(
        1500,
        Packet::ethernet(MAC_PHONE, MAC_MCAST)
            .ipv4(IP_PHONE, IP_MCAST_MDNS)
            .ttl(255)
            .udp(5353, 5353)
            .payload(&mdns_announce_a("franks-iphone.local", IP_PHONE)),
    );
    push(
        1600,
        Packet::ethernet(MAC_PRINTER, MAC_MCAST)
            .ipv4(IP_PRINTER, IP_MCAST_MDNS)
            .ttl(255)
            .udp(5353, 5353)
            .payload(&mdns_announce_a("printer.local", IP_PRINTER)),
    );
    push(
        1601,
        Packet::ethernet(MAC_PRINTER, MAC_MCAST)
            .ipv4(IP_PRINTER, IP_MCAST_MDNS)
            .ttl(255)
            .udp(5353, 5353)
            .payload(&mdns_announce_srv(
                "LaserJet._ipp._tcp.local",
                631,
                "printer.local",
            )),
    );

    // --- SSH session: laptop → server ------------------------------------
    let ssh_port = 51800;
    push(
        2000,
        Packet::ethernet(MAC_LAPTOP, MAC_SERVER)
            .ipv4(IP_LAPTOP, IP_SERVER)
            .tcp(ssh_port, 22)
            .syn()
            .seq(5_000_000)
            .build(),
    );
    push(
        2003,
        Packet::ethernet(MAC_SERVER, MAC_LAPTOP)
            .ipv4(IP_SERVER, IP_LAPTOP)
            .tcp(22, ssh_port)
            .syn_ack()
            .seq(8_000_000)
            .ack(5_000_001)
            .build(),
    );
    push(
        2004,
        Packet::ethernet(MAC_LAPTOP, MAC_SERVER)
            .ipv4(IP_LAPTOP, IP_SERVER)
            .tcp(ssh_port, 22)
            .ack_only()
            .seq(5_000_001)
            .ack(8_000_001)
            .build(),
    );
    push(
        2010,
        Packet::ethernet(MAC_SERVER, MAC_LAPTOP)
            .ipv4(IP_SERVER, IP_LAPTOP)
            .tcp(22, ssh_port)
            .seq(8_000_001)
            .ack(5_000_001)
            .payload(b"SSH-2.0-OpenSSH_9.6\r\n"),
    );
    push(
        2020,
        Packet::ethernet(MAC_LAPTOP, MAC_SERVER)
            .ipv4(IP_LAPTOP, IP_SERVER)
            .tcp(ssh_port, 22)
            .seq(5_000_001)
            .ack(8_000_022)
            .payload(b"SSH-2.0-OpenSSH_9.8\r\n"),
    );

    // --- NTP + ping --------------------------------------------------------
    push(
        2500,
        Packet::ethernet(MAC_LAPTOP, MAC_GATEWAY)
            .ipv4(IP_LAPTOP, IP_NTP)
            .udp(35000, 123)
            .payload(&ntp_client()),
    );
    push(
        2548,
        Packet::ethernet(MAC_GATEWAY, MAC_LAPTOP)
            .ipv4(IP_NTP, IP_LAPTOP)
            .ttl(54)
            .udp(123, 35000)
            .payload(&ntp_client()), // shape is fine for a response fixture
    );
    push(
        3000,
        Packet::ethernet(MAC_LAPTOP, MAC_GATEWAY)
            .ipv4(IP_LAPTOP, IP_GATEWAY)
            .icmp_echo(true),
    );
    push(
        3002,
        Packet::ethernet(MAC_GATEWAY, MAC_LAPTOP)
            .ipv4(IP_GATEWAY, IP_LAPTOP)
            .icmp_echo(false),
    );

    frames
}

/// The office capture plus a planted incident: a SYN scan against the server
/// and a high-volume upload to an unknown external host on port 4444.
#[must_use]
pub fn incident() -> Vec<TimedFrame> {
    let mut frames = office();
    let base = 10_000u64;
    let mut push = |millis: u64, frame: Vec<u8>| frames.push((at(millis), frame));

    // SYN scan: scanner probes the server's ports; only 22 and 80 answer.
    let scan_ports = [21u16, 22, 23, 25, 80, 110, 143, 443, 445, 3389, 5900, 8080];
    for (idx, &port) in scan_ports.iter().enumerate() {
        let idx_u64 = idx as u64;
        let idx_u32 = u32::try_from(idx).unwrap_or(0);
        let sport = 60000u16.saturating_add(u16::try_from(idx).unwrap_or(0));
        push(
            base + idx_u64 * 5,
            Packet::ethernet(MAC_SCANNER, MAC_SERVER)
                .ipv4(IP_SCANNER, IP_SERVER)
                .tcp(sport, port)
                .syn()
                .seq(1_000_000 + idx_u32)
                .build(),
        );
        let reply_at = base + idx_u64 * 5 + 2;
        if port == 22 || port == 80 {
            push(
                reply_at,
                Packet::ethernet(MAC_SERVER, MAC_SCANNER)
                    .ipv4(IP_SERVER, IP_SCANNER)
                    .tcp(port, sport)
                    .syn_ack()
                    .seq(2_000_000)
                    .ack(1_000_001 + idx_u32)
                    .build(),
            );
            // Scanner immediately resets — classic half-open scan signature.
            push(
                reply_at + 1,
                Packet::ethernet(MAC_SCANNER, MAC_SERVER)
                    .ipv4(IP_SCANNER, IP_SERVER)
                    .tcp(sport, port)
                    .rst()
                    .seq(1_000_001 + idx_u32)
                    .build(),
            );
        } else {
            push(
                reply_at,
                Packet::ethernet(MAC_SERVER, MAC_SCANNER)
                    .ipv4(IP_SERVER, IP_SCANNER)
                    .tcp(port, sport)
                    .rst()
                    .seq(0)
                    .ack(1_000_001 + idx_u32)
                    .build(),
            );
        }
    }

    // Exfiltration-shaped: sustained upload to an external host, port 4444.
    push(
        base + 200,
        Packet::ethernet(MAC_SCANNER, MAC_GATEWAY)
            .ipv4(IP_SCANNER, IP_EXFIL)
            .tcp(61000, 4444)
            .syn()
            .seq(42)
            .build(),
    );
    push(
        base + 230,
        Packet::ethernet(MAC_GATEWAY, MAC_SCANNER)
            .ipv4(IP_EXFIL, IP_SCANNER)
            .ttl(48)
            .tcp(4444, 61000)
            .syn_ack()
            .seq(7)
            .ack(43)
            .build(),
    );
    let chunk = vec![0xA5u8; 1200];
    for burst in 0u64..20 {
        let burst_u32 = u32::try_from(burst).unwrap_or(0);
        push(
            base + 240 + burst * 10,
            Packet::ethernet(MAC_SCANNER, MAC_GATEWAY)
                .ipv4(IP_SCANNER, IP_EXFIL)
                .tcp(61000, 4444)
                .seq(43 + burst_u32 * 1200)
                .ack(8)
                .payload(&chunk),
        );
    }

    frames.sort_by_key(|(ts, _)| *ts);
    frames
}

/// Write a scenario to any sink as a legacy pcap.
pub fn write_pcap(frames: &[TimedFrame], sink: impl Write) -> std::io::Result<()> {
    let mut writer = PcapWriter::new(sink)?;
    for (ts, frame) in frames {
        writer.write_packet(*ts, frame)?;
    }
    writer.finish()?;
    Ok(())
}
