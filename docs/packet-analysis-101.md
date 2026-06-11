# Packet analysis 101 — what we're doing and why

This is the "from zero" primer. No prior networking knowledge assumed. By the
end you'll understand what a packet is, what a capture file holds, what every
layer in `pincer` decodes, and _why_ a tool like this exists. Read this first,
then [DESIGN.md](../DESIGN.md) for how we built it.

---

## 1. The one idea: computers talk by sending labelled envelopes

When your laptop loads a web page, it does **not** send "the web page request"
as one thing. It sends a stream of small chunks called **packets**. A packet is
just a block of bytes with two parts:

- **Headers** — labels on the outside of the envelope: who it's from, who it's
  going to, what's inside, how big it is.
- **Payload** — the actual contents.

Every packet is wrapped in _several_ envelopes, one inside the other, because
different parts of the network care about different labels. This nesting is
called the **protocol stack**, and peeling it apart is the whole job of a packet
analyzer. Picture a physical envelope inside an envelope inside an envelope:

```
┌─────────────────────────────────────────────────────────┐
│ Ethernet header  (which machine on this local wire?)    │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ IP header   (which machine on the whole internet?)  │ │
│ │ ┌─────────────────────────────────────────────────┐ │ │
│ │ │ TCP header  (which program/conversation?)       │ │ │
│ │ │ ┌─────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload: "GET /index.html HTTP/1.1 ..."     │ │ │ │
│ │ │ └─────────────────────────────────────────────┘ │ │ │
│ │ └─────────────────────────────────────────────────┘ │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

Each layer wraps the one above. The sender wraps from the inside out; the
receiver (and our analyzer) unwraps from the outside in. That unwrapping is
exactly what `src/decode/` does, one module per layer.

### Why so many layers? (the "OSI / TCP-IP model")

Each layer solves one problem and trusts the layer below to solve its own:

| Layer                             | Question it answers                                                   | In `pincer`                           |
| --------------------------------- | --------------------------------------------------------------------- | ------------------------------------- |
| **Link** (Ethernet)               | Which device on _this local wire_? Uses **MAC addresses**.            | `decode/ethernet.rs`, `decode/arp.rs` |
| **Network** (IP)                  | Which device anywhere on the _internet_? Uses **IP addresses**.       | `decode/ipv4.rs`, `decode/ipv6.rs`    |
| **Transport** (TCP/UDP)           | Which _program / conversation_ on that device? Uses **port numbers**. | `decode/tcp.rs`, `decode/udp.rs`      |
| **Application** (HTTP, DNS, TLS…) | What is the data actually _saying_?                                   | `app/*.rs`                            |

The mental model: **MAC = which machine on my street, IP = which building in the
world, port = which apartment in the building, application = the conversation
happening inside.**

---

## 2. The addresses you'll see everywhere

**MAC address** (link layer): six bytes, burned into a network card, written
`3c:22:fb:10:20:30`. Only meaningful on the _local_ network segment. The first
three bytes (`3c:22:fb`) are the **OUI** — a code assigned to the manufacturer,
so a MAC tells you the hardware vendor for free. Crucial point for later: when
your laptop talks to a server across the internet, the destination MAC on the
packet is your **router's** MAC, not the server's — because on your local wire,
the router is the next hop. The router strips the Ethernet envelope, looks at
the IP envelope, and forwards. This is _why_ a MAC only identifies same-wire
devices, and why `pincer` is careful never to bind a far-away IP to your
router's MAC (see [DESIGN.md](../DESIGN.md) "locality").

**IP address** (network layer): `192.168.1.10` (IPv4) or
`fe80::1` (IPv6). Routable across the whole internet. Some ranges are special:
`192.168.x.x`, `10.x.x.x`, `172.16–31.x.x` are **private** (only valid inside
your local network); everything else is public.

**Port number** (transport layer): a 16-bit number (0–65535) identifying which
program is talking. **Well-known ports** are conventions: 80 = HTTP, 443 =
HTTPS, 22 = SSH, 53 = DNS. The side of a connection using the low/well-known
port is almost always the **server**; the side using a high random port (like 51514) is the **client**. `pincer` uses this to guess who initiated a
conversation when it can't see the start.

---

## 3. What is a "capture"?

A **capture** is a recording of packets as they flew past a point on the
network — like a security camera for traffic. A tool (Wireshark, tcpdump, or a
sensor appliance) copies each packet and writes it to a file. That file is what
`pincer` reads.

The file format is simple: a small **global header** (what kind of file, what
byte order, what link type) followed by one **record** per packet (a timestamp,
the length, then the raw packet bytes exactly as they appeared on the wire).
Two formats exist — classic **pcap** and the newer **pcapng** — and `pincer`
reads both. The byte-level details are in [pcap-format.md](pcap-format.md).

Two subtleties that matter:

- **Snaplen / truncation:** captures often save only the first N bytes of each
  packet (headers are interesting, the 1 MB file download body usually isn't).
  So a packet's recorded length can be _smaller_ than its real length. Our
  parser must handle "the bytes ran out" gracefully at every layer.
- **Timestamps aren't perfectly ordered.** When captures from two network cards
  are merged, or a clock is adjusted, timestamps can jump backwards. So we never
  assume "first packet seen = earliest"; we take min/max explicitly.

---

## 3½. Streaming: reading a file you never download

A network transfer is not "a file arriving" — it is **bytes flowing in order,
chunk by chunk**. "Downloading" just means writing those chunks to disk before
looking at them. That step is optional. The alternative is **streaming**:
process each chunk the moment it arrives, then throw it away. The whole file
never exists on your machine — only a small moving window of it.

What makes a tool able to stream? **Never needing to look backwards.** A GUI
like Wireshark must jump around the file (scroll to packet 80,000, back to
packet 3), so it needs the whole file on disk. `pincer` reads each record
exactly once, front to back, folding everything into small running state —
so any byte source works. In Rust terms: `CaptureReader<R: Read>` accepts any
"byte faucet" (`File`, stdin, a TCP socket, a decompressor), and `pincer
<cmd> -` plugs stdin in.

Step by step, `curl -s URL | pincer summary -`:

```
S3 ──TCP──▶ curl ──pipe (~64 KB, kernel memory)──▶ pincer
```

curl writes chunks into the pipe; pincer drains it record by record; if either
side is faster, the pipe and TCP automatically pace them (back-pressure). At
any instant the footprint is one pipe buffer + one packet + the analysis
state — ~1 MB, for a file of any size.

The cookbook (no local disk in any of these):

```bash
aws s3 cp s3://bucket/capture.pcap - | pincer flows -     # S3 ('-' = to stdout)
curl -s "$PRESIGNED_URL"            | pincer summary -    # any URL
ssh host 'cat /captures/big.pcap'   | pincer deps -       # remote server
gzcat big.pcap.gz                   | pincer flows -      # compressed
sudo tcpdump -i eth0 -c 100000 -w - | pincer assets -     # LIVE traffic
```

Caveat: reports print at end-of-stream, so for live capture bound it
(`-c 100000`) or Ctrl-C tcpdump. And streaming only ever moves forward — a
task that genuinely needs random access still needs the file.

---

## 4. Passive vs active discovery — the heart of _why_

There are two ways to learn what's on a network:

- **Active:** you send probes — ping every address, knock on every port, log in
  and ask "what are you?". Accurate, but intrusive: it generates traffic, and it
  can crash fragile devices (medical equipment, industrial controllers, IoT) or
  trip security alarms. You also need credentials and permission.

- **Passive:** you just **listen**. You never send anything; you watch the
  traffic that's already flowing and _infer_ what's there. Safe for fragile
  networks, invisible, needs no credentials. The cost: you only know what the
  traffic reveals, so you must squeeze every drop of signal from it and be
  honest about confidence.

**`pincer` is a passive analyzer.** This is how commercial passive-discovery
sensors work: lightweight collectors watch the traffic that is already flowing
and build asset intelligence without ever touching the assets. So everything `pincer` produces is shaped around the passive-discovery
questions:

1. **Flows** — who is talking to whom, how much? (`flows`)
2. **Assets** — what devices exist, and what are they? (`assets`)
3. **Services** — what is each device offering? (`services`)
4. **Dependencies** — which systems rely on which? (`deps`)

---

## 5. The four things we build, explained

### Flows — "conversations"

A single TCP conversation is hundreds of packets. Staring at packets is
useless; you want the **conversation**. A **flow** aggregates all packets
between the same two endpoints into one summary row: who, total bytes each
direction, how long, which flags were seen.

The key insight is the **5-tuple**: a conversation is identified by (source IP,
source port, destination IP, destination port, protocol). Packets in _both_
directions belong to the same flow, so we sort the two endpoints into a
canonical order — that's why `FlowKey` always stores the smaller endpoint first.
(Detail in `analysis/flows.rs`.)

We also figure out **who started it** (the "client"), because in passive
discovery the initiator vs responder distinction is everything — it tells you
who depends on whom. Best evidence: a lone **SYN** packet (TCP's "let's start a
conversation" signal) points at the client. If we didn't capture the start, we
fall back to "whoever used the well-known port is the server."

### Assets — "devices"

An **asset** is a real device on the network. The challenge: one device shows up
under many identities — a MAC address, one or more IP addresses, a hostname. We
have to _merge_ these into one record. `pincer` keys a local device by its **MAC**
(stable even when its IP changes via DHCP) and an off-network host by its **IP**.

Then we attach every identity signal we can passively observe, **each tagged with
how we learned it** (its evidence):

- hostname from DHCP, mDNS, or DNS answers
- the **DHCP fingerprint** (option 55) — the ordered list of settings a device
  asks for, which is remarkably specific to its OS, the classic DHCP-fingerprinting trick
- vendor from the MAC OUI
- services it offers

Attribution — _why_ we believe each fact — is the discipline that separates real
passive discovery from guessing.

### Services — "what each device offers"

A device is a **server** for a service if it's _listening_ on a port. The
strongest passive proof is a **SYN-ACK**: when a client SYNs and the server
answers SYN-ACK, that handshake proves the port is open and serving. Weaker
evidence: we saw an application banner (a TLS hostname, an HTTP request). Weakest:
we only saw traffic _to_ that port and are guessing from the port number.
`pincer` records services with exactly these three evidence levels so you never
overstate confidence.

### Dependencies — "the map"

Once you have flows + assets, you can draw the **application dependency map**:
arrows from each client device to each server it uses, labelled with the service
and traffic volume. "The laptop depends on the intranet server's HTTP and SSH;
it depends on example.com's HTTPS." This is the deliverable security and
continuity teams care about most — if you're going to patch or move a server,
you need to know who breaks. `pincer` exports it as a table or a Graphviz graph.

---

## 6. The application layer — reading the conversation

Below transport, the payload is the actual protocol. `pincer` does **best-effort**
decoding of a few high-value ones (it doesn't try to be Wireshark):

- **DNS / mDNS** — the phone-book lookups: "what IP is `example.com`?" These are
  pure gold for naming assets, because the _answers_ tell you which hostname goes
  with which IP. mDNS is the local-network variant devices use to announce
  themselves ("I'm `franks-iphone.local`").
- **DHCP** — how a device gets its IP when it joins. The exchange (DISCOVER,
  OFFER, REQUEST, ACK — "DORA") carries the device's hostname _and_ its
  fingerprint _and_ the IP it's assigned. One DHCP exchange can fully identify a
  device.
- **HTTP** — unencrypted web requests reveal the `Host:` header (which site) and
  the path.
- **TLS** — encrypted, but the very first message (the **ClientHello**) sends the
  destination hostname _in the clear_ in a field called **SNI**. So even for
  HTTPS we can see _which_ site, just not the contents.

A crucial honesty point: we do **not** reassemble TCP streams (stitching the
payload back together across packets). So we can read these protocols only when
the interesting part fits in the first data packet — which, for handshakes and
requests, it almost always does. When it doesn't, we degrade gracefully to
"there's a TLS service on 443" without the hostname, and we _say so_.

---

## 7. Putting it together: the office capture

Run `cargo run -- gen testdata` then `cargo run -- assets testdata/office.pcap`.
The sample capture is a tiny office: a laptop joins (ARP + DHCP, so we learn its
MAC, IP, hostname `carols-laptop`, and OS fingerprint), looks up and visits
`example.com` over HTTPS (so we get the SNI), talks HTTP and SSH to an intranet
server, while a phone and printer announce themselves over mDNS. From that raw
traffic alone, `pincer` reconstructs the device inventory, the services, and the
dependency map — without sending a single packet. That's passive discovery, and
that's the job.

The `incident.pcap` sample adds a planted attack — a port scan and a data-exfil
flow — so you can practice spotting the anomalies (`flows` and `deps` make both
obvious) — see the `pcap-analysis` workflow under `.claude/skills/`.
