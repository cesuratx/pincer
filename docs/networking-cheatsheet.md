# Networking cheatsheet

Quick reference for packet analysis.

## Well-known ports

| port | service | port | service |
|-----:|---------|-----:|---------|
| 20/21 | FTP    | 443  | HTTPS |
| 22   | SSH     | 445  | SMB |
| 23   | Telnet  | 514  | syslog |
| 25   | SMTP    | 587  | SMTP submission |
| 53   | DNS     | 631  | IPP (printing) |
| 67/68| DHCP    | 993  | IMAPS |
| 69   | TFTP    | 1433 | MS-SQL |
| 80   | HTTP    | 3306 | MySQL |
| 110  | POP3    | 3389 | RDP |
| 123  | NTP     | 5060 | SIP |
| 137–139 | NetBIOS | 5353 | mDNS |
| 143  | IMAP    | 5432 | PostgreSQL |
| 161/162 | SNMP | 5900 | VNC |
| 389  | LDAP    | 6379 | Redis |
| 636  | LDAPS   | 8080 | HTTP-alt |
| 1900 | SSDP/UPnP | 9100 | JetDirect (raw printing) |

Ports < 1024 are "well-known"; a connection's server side is almost always the
lower / well-known port.

## TCP three-way handshake & teardown

```
client            server
  | --- SYN -------> |   client opens (SYN, no ACK)
  | <-- SYN,ACK ---- |   server accepts → port is LISTENING (key signal)
  | --- ACK -------> |   established
  ...   data    ...
  | --- FIN,ACK ---> |   graceful close (both sides FIN)
  | <-- FIN,ACK ---- |
```

- **SYN with no reply** → host down, port filtered, or a scan.
- **SYN then RST** (instead of SYN-ACK) → port closed / actively refused.
- **Many SYNs from one host to many ports** → port scan.
- **SYN-ACK seen** → definitive proof the destination is a service. Passive
  discovery leans hard on this; everything else is weaker inference.

## Passive device-recognition signals

Identify a device without touching it, by correlating these from traffic:

1. **MAC OUI** — first 3 bytes of the MAC map to a vendor (the manufacturer
   that bought that address block). Gives hardware vendor for free.
2. **DHCP option 55** (parameter request list) — the ordered set of options a
   client asks for is remarkably OS/stack-specific: a stable fingerprint.
3. **DHCP option 60** (vendor class) — often literally names the OS family.
4. **DHCP option 12** / mDNS / NetBIOS — the host's self-declared name.
5. **mDNS/Bonjour & SSDP/UPnP** — service announcements reveal device class
   (printer `_ipp._tcp`, Chromecast, NAS, smart-TV…).
6. **User-Agent / TLS fingerprint (JA3)** — application and TLS-stack identity.
7. **Open/visible services** — a host serving 9100 is a printer; 3389 a Windows
   box; 22 a server or network device.

Correlating several weak signals into one confident identity — ideally against
a large device-signature database — is how commercial device-recognition
products turn passive traffic into an accurate inventory.

## DNS record types

| type | meaning |
|-----:|---------|
| A (1)     | IPv4 address |
| NS (2)    | authoritative name server |
| CNAME (5) | alias to another name |
| PTR (12)  | reverse (IP → name); also mDNS service enumeration |
| MX (15)   | mail exchanger |
| TXT (16)  | arbitrary text (SPF, verification) |
| AAAA (28) | IPv6 address |
| SRV (33)  | service location: priority, weight, port, target host |

## DHCP DORA

**D**iscover (client broadcast) → **O**ffer (server) → **R**equest (client
broadcast, confirming choice) → **A**ck (server, lease confirmed). Discover and
Request carry the client's hostname and fingerprint; Offer and Ack carry the
assigned IP (`yiaddr`) — together an authoritative MAC↔IP↔hostname binding.

## Address ranges worth recognizing

- **RFC 1918 private**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
- **Link-local**: `169.254.0.0/16` (IPv4 APIPA), `fe80::/10` (IPv6).
- **Multicast**: `224.0.0.0/4` (e.g. `224.0.0.251` mDNS), `ff00::/8`.
- **Broadcast**: `255.255.255.255` (and per-subnet broadcast).
- An IP outside the local subnet reached via the **router's MAC** is off-link;
  its MAC in the frame is the router's, not the host's — never bind them.
