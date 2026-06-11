# pincer

[![CI](https://github.com/cesuratx/pincer/actions/workflows/ci.yml/badge.svg)](https://github.com/cesuratx/pincer/actions/workflows/ci.yml)
[![Security audit](https://github.com/cesuratx/pincer/actions/workflows/audit.yml/badge.svg)](https://github.com/cesuratx/pincer/actions/workflows/audit.yml)

A hand-rolled pcap/pcapng analyzer in Rust for **passive asset discovery**: it
turns a network capture into communication **flows**, an **asset inventory**,
and an **application dependency map** — no libpcap, no packet-parsing crates.
Every byte is parsed in-house through one bounds-checked cursor, and the crate
is `#![forbid(unsafe_code)]` with `unwrap`/`panic`/indexing/unchecked-arithmetic
denied by lint.

## Quick start

```bash
cargo run -- gen testdata                  # write sample captures
cargo run -- summary testdata/office.pcap  # capture overview
cargo run -- flows   testdata/office.pcap  # bidirectional flows
cargo run -- assets  testdata/office.pcap  # device inventory with evidence
cargo run -- deps --dot testdata/office.pcap | dot -Tpng -o deps.png
```

Subcommands: `summary`, `flows`, `assets`, `services`, `deps`, `dns`, `dhcp`,
`gen`. All analysis commands take `--json`.

## What it understands

- **Containers:** legacy pcap (all four magic variants) and pcapng (SHB/IDB/EPB/SPB), streamed in constant memory.
- **Link types:** Ethernet (+stacked VLAN), Linux SLL/SLL2 (`tcpdump -i any`), raw IP (VPN/tun), NULL/LOOP (BSD/macOS loopback); anything else is counted and reported, never fatal.
- **Layers:** Ethernet + stacked VLAN, ARP, IPv4 (frag-aware), IPv6 (ext-header walk), TCP, UDP, ICMP.
- **Application:** DNS/mDNS (loop-safe name decompression), DHCP (hostname + option-55 fingerprint), HTTP (Host), TLS (SNI).
- **Analysis:** bidirectional flows with initiator detection, asset inventory with attributed evidence, client→server dependency edges (JSON or Graphviz DOT).

## Layout

`src/bytes.rs` (the cursor), `src/pcap/` (readers + writer), `src/decode/`
(layers), `src/app/` (sniffers), `src/analysis/` (flows/assets/deps/stats),
`src/output/` (table/JSON/DOT), `src/fixtures/` (packet builder + scenarios).

## Learning the project

New to packet analysis or Rust? Read in this order:
1. [docs/packet-analysis-101.md](docs/packet-analysis-101.md) — the domain from zero.
2. [DESIGN.md](DESIGN.md) — architecture and every design decision, with rationale.
3. [docs/rust-concepts.md](docs/rust-concepts.md) — every Rust concept used, tied to real code.

Reference sheets: [docs/pcap-format.md](docs/pcap-format.md),
[docs/protocol-headers.md](docs/protocol-headers.md),
[docs/networking-cheatsheet.md](docs/networking-cheatsheet.md).
`CLAUDE.md` is the project guide for working in this repo.

## Development

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

Built to explore how passive network sensors turn raw traffic into asset
intelligence — communication flows, an asset inventory, and a dependency map.

## Streaming, limits, and degradation

Pass `-` as the capture argument to stream from stdin — no local disk needed:
`ssh host 'cat big.pcap' | pincer flows -` or `gzcat big.pcap.gz | pincer deps -`.
Memory stays constant either way.

Analysis collections are hard-capped (`analysis::Limits`) so a hostile capture
degrades instead of exhausting memory. Anything that degrades a run — a
truncated tail, malformed blocks skipped, caps hit, records without timestamps
(pcapng Simple Packet Blocks) — is reported as warnings on stderr and
machine-readably in the `degradation` object of every `--json` envelope.
Timestamp-less records are excluded from every first/last time and duration —
time fields stay `null`/absent rather than reading as the 1970 epoch — and a
capture whose timestamps span more than five years sets a `clock_inconsistent`
flag in the summary JSON alongside the table note.
