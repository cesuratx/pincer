# Protocol headers

Field-by-field layouts for every protocol `pincer` decodes. Offsets are within
that layer (the previous layer is already consumed). All fields network byte
order (big-endian).

## Ethernet II (14 bytes, + 4 per VLAN tag)

| offset | size | field |
|-------:|-----:|-------|
| 0  | 6 | destination MAC |
| 6  | 6 | source MAC |
| 12 | 2 | EtherType |

EtherTypes: `0x0800` IPv4, `0x0806` ARP, `0x86DD` IPv6, `0x8100` 802.1Q VLAN,
`0x88A8`/`0x9100` QinQ. A VLAN tag is 4 bytes: 2-byte TPID (the `0x8100`-class
value, already read as EtherType) + 2-byte TCI; the low 12 bits of the TCI are
the VLAN ID. Tags stack (QinQ); loop until the EtherType is non-VLAN (pincer caps the stack at four tags and degrades — MACs survive — beyond that). The first
octet's low bit (`& 0x01`) marks a multicast/broadcast destination.

## ARP (28 bytes for IPv4-over-Ethernet)

| offset | size | field | value we require |
|-------:|-----:|-------|------------------|
| 0  | 2 | hardware type | 1 (Ethernet) |
| 2  | 2 | protocol type | 0x0800 (IPv4) |
| 4  | 1 | hardware len  | 6 |
| 5  | 1 | protocol len  | 4 |
| 6  | 2 | opcode        | 1 request, 2 reply |
| 8  | 6 | sender MAC    | |
| 14 | 4 | sender IP     | authoritative MAC↔IP binding |
| 18 | 6 | target MAC    | |
| 24 | 4 | target IP     | |

ARP is gold for asset discovery: it gives same-segment MAC↔IP bindings directly.

## IPv4 (20 bytes + options)

| offset | size | field | notes |
|-------:|-----:|-------|-------|
| 0  | 1 | version + IHL | high nibble = 4; low nibble × 4 = header length (≥ 20) |
| 1  | 1 | DSCP/ECN | |
| 2  | 2 | total length | header + payload |
| 4  | 2 | identification | groups fragments |
| 6  | 2 | flags + frag offset | bit 14 = DF, bit 13 = MF, low 13 bits = offset ÷ 8 |
| 8  | 1 | TTL | |
| 9  | 1 | protocol | 1 ICMP, 6 TCP, 17 UDP |
| 10 | 2 | header checksum | not verified (we analyze, not route) |
| 12 | 4 | source IP | |
| 16 | 4 | destination IP | |
| 20 | … | options | (IHL − 5) × 4 bytes |

Fragmentation: a packet with **fragment offset > 0** carries no transport
header — parsing TCP at offset 1480 is the trap (guarded for IPv4 *and* the
IPv6 fragment extension header). `pincer` records frag flags but does not
reassemble; non-first fragments skip transport parsing. Trust `total length`
as the payload bound (Ethernet pads runt frames to 60 bytes; without this the
padding leaks into the payload) — with one exception: `total length == 0`
means a segmentation-offload (TSO/GSO) capture wrote the packet before the
NIC filled the field in; use the captured bytes, don't reject the packet.

## IPv6 (40-byte fixed header + extension chain)

| offset | size | field |
|-------:|-----:|-------|
| 0  | 4  | version (4 bits) + traffic class + flow label |
| 4  | 2  | payload length |
| 6  | 1  | next header |
| 7  | 1  | hop limit |
| 8  | 16 | source address |
| 24 | 16 | destination address |

`next header` may be an extension header (0 hop-by-hop, 43 routing, 44 fragment,
60 dest-opts) rather than a transport protocol; walk the chain (each: next
header byte + length byte + data) to the real transport. Cap the walk — hostile
chains can loop.

## TCP (20 bytes + options)

| offset | size | field | notes |
|-------:|-----:|-------|-------|
| 0  | 2 | source port | |
| 2  | 2 | destination port | |
| 4  | 4 | sequence number | |
| 8  | 4 | acknowledgment number | |
| 12 | 1 | data offset (high nibble × 4 = header len, ≥ 20) + reserved | |
| 13 | 1 | flags | see below |
| 14 | 2 | window size | |
| 16 | 2 | checksum | not verified |
| 18 | 2 | urgent pointer | |
| 20 | … | options | (data offset − 5) × 4 bytes |

Flag bits: `FIN 0x01`, `SYN 0x02`, `RST 0x04`, `PSH 0x08`, `ACK 0x10`,
`URG 0x20`. Connection logic that drives flow direction:
- **SYN without ACK** (`& 0x12 == 0x02`) = the client's opening segment.
- **SYN+ACK** (`& 0x12 == 0x12`) = the server accepting; proves the destination
  port is a listening service (strongest passive service evidence).

## UDP (8 bytes)

| offset | size | field |
|-------:|-----:|-------|
| 0 | 2 | source port |
| 2 | 2 | destination port |
| 4 | 2 | length (header + data, ≥ 8) |
| 6 | 2 | checksum |

## ICMP / ICMPv6 (type + code)

Byte 0 = type, byte 1 = code. ICMPv4 echo: type 8 request / 0 reply. ICMPv6
echo: 128 request / 129 reply. `pincer` keeps type+code only.

## DNS / mDNS

Header (12 bytes): id, flags, then four 16-bit counts — questions, answers,
authority RRs, additional RRs. Flags: bit 15 QR (1 = response), bits 11–14
opcode (0 = query). Each question: name, 2-byte type, 2-byte class. Each RR:
name, type, class, 4-byte TTL, 2-byte rdlength, rdata.

Record types pincer extracts: A (1), CNAME (5), PTR (12), AAAA (28), SRV (33).

**Name compression**: a length byte whose top two bits are `11` is a pointer;
its low 14 bits are an offset from the message start to continue the name.
Decompression must be hardened: pointers must point **strictly backwards**, a
jump budget bounds the loop, and the assembled name is capped (253). These three
rules defeat both pointer loops and decompression bombs. mDNS is DNS on UDP 5353
to multicast 224.0.0.251 / ff02::fb, often with answers in the additional
section.

## DHCP / BOOTP

Fixed BOOTP header then options. Key offsets: op (0; 1 request / 2 reply),
htype (1), hlen (2), xid (4–7), yiaddr — "your" assigned IP (16–19),
chaddr — client MAC (28–33). At offset 236 the 4-byte **magic cookie**
`63 82 53 63` marks the start of options (`code, len, value…`, terminated by
255).

Options that identify devices:
- **53** message type: 1 DISCOVER, 2 OFFER, 3 REQUEST, 5 ACK, …
- **12** hostname — direct device name.
- **55** parameter request list — the ordered option codes the client asks for;
  this sequence is a stable **device/OS fingerprint** (the Fing technique).
- **60** vendor class identifier (e.g. "MSFT 5.0", "android-dhcp-14").

## TLS ClientHello (SNI)

The one unencrypted hostname in an HTTPS connection. Record header: type 22
(handshake), 2-byte version, 2-byte length. Handshake: type 1 (ClientHello),
3-byte length, 2-byte client version, 32-byte random, then variable session id,
cipher suites, compression methods, and finally extensions. The **server_name**
extension (type 0) contains a server-name list whose first entry (name_type 0,
host_name) is the SNI string. First-segment only — a ClientHello split across
TCP segments needs stream reassembly, which pincer does not do.
