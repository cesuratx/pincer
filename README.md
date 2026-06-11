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
`gen`. All analysis commands take `--json`, and `--strict` makes a degraded
analysis exit 3 instead of 0.

## What it understands

- **Containers:** legacy pcap (all four magic variants) and pcapng (SHB/IDB/EPB/SPB), streamed in constant memory.
- **Link types:** Ethernet (+stacked VLAN), Linux SLL/SLL2 (`tcpdump -i any`), raw IP (VPN/tun), NULL/LOOP (BSD/macOS loopback); anything else is counted and reported, never fatal.
- **Layers:** Ethernet + stacked VLAN, ARP, IPv4 (frag-aware), IPv6 (ext-header walk), TCP, UDP, ICMP.
- **Application:** DNS/mDNS (loop-safe name decompression), DHCP (hostname + option-55 fingerprint), HTTP (Host), TLS (SNI).
- **Analysis:** bidirectional flows with initiator detection, asset inventory with attributed evidence, client→server dependency edges (JSON or Graphviz DOT).

## Layout

`src/bytes.rs` (the cursor), `src/pcap/` (readers + writer), `src/decode/`
(layers), `src/app/` (sniffers), `src/analysis/` (flows/assets/deps/stats),
`src/output/` (table/JSON/DOT), `src/fixtures/` (packet builder + scenarios),
`fuzz/` (cargo-fuzz targets, a separate crate — see Fuzzing below).

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

### Fuzzing

Coverage-guided fuzzing lives in [`fuzz/`](fuzz/) — its own crate and
workspace, excluded from the root build (libFuzzer needs nightly; the root
gates stay on stable):

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz list               # the five targets
cargo +nightly fuzz run fuzz_pipeline  # add e.g. -- -max_total_time=600
```

The targets, narrowest reach last:

- `fuzz_pipeline` — raw bytes through the full shipped path: reader →
  decode → sniff → every sink → finalize → dependency edges → JSON + DOT
  render.
- `fuzz_pcapng` / `fuzz_legacy` — a valid container prefix (SHB+IDB / global
  header) followed by the fuzzed record stream, so mutation lands inside the
  block-walking machinery instead of dying at the magic check.
- `fuzz_dns` — straight into the DNS message parser (name decompression is
  the loop- and amplification-prone hot spot), asserting that the deep and
  shallow parse modes agree on accept/reject.
- `fuzz_decode` — `decode_packet` across every supported link type, no
  container framing in the way.

Seed the corpora from the committed samples; `fuzz_legacy` takes the record
stream *after* the 24-byte global header:

```bash
mkdir -p fuzz/corpus/{fuzz_pipeline,fuzz_decode,fuzz_legacy}
cp testdata/*.pcap fuzz/corpus/fuzz_pipeline/
cp testdata/*.pcap fuzz/corpus/fuzz_decode/
for f in testdata/*.pcap; do tail -c +25 "$f" > "fuzz/corpus/fuzz_legacy/$(basename "$f")"; done
```

(`fuzz_pcapng` and `fuzz_dns` take a bare block stream / DNS message, which
no committed fixture is, so they start from an empty corpus.) Captures
fetched into `testdata-real/` make good extra seeds for `fuzz_pipeline`.

There is deliberately no CI fuzz job — nightly toolchain churn makes one
flaky. A scheduled job (~10 min per target, corpus cached between runs) is
reasonable follow-up work.

## Streaming, limits, and degradation

Pass `-` as the capture argument to stream from stdin — no local disk needed:
`ssh host 'cat big.pcap' | pincer flows -` or `gzcat big.pcap.gz | pincer deps -`.
Memory stays constant either way.

Analysis collections are hard-capped (`analysis::Limits`) so a hostile capture
degrades instead of exhausting memory. The keyed collections (flows, assets,
bindings, candidate sightings, subnets, and the per-asset
hostname/service/IP sets) evict deterministically — at a cap a new key is
admitted only by evicting the largest admitted one, so survivors are the N
smallest keys of the capture in any arrival order. The `dns`/`dhcp` detail
logs are chronological instead: at their cap the first N records are kept
and the rest counted as dropped. Once any cap engages, the overflow-counter
values tally capped events and may vary with packet order (`flows_dropped`
is exact; zero vs nonzero is always stable), so byte-diffing capped reports
should exclude or normalize those counters — see DESIGN.md for the
residuals. Anything that
degrades a run — a truncated tail, a corrupt mid-stream section header
(concatenated pcapng), malformed blocks skipped, caps hit, records without
timestamps (pcapng Simple Packet Blocks) — is reported as warnings on stderr
and machine-readably in the `degradation` object of every `--json` envelope.
Only a capture whose initial header is unreadable fails outright.

The degradation signal is also in-band in every output format, so a consumer
that only sees stdout can still detect partial results:

- **Tables** always end with a `# pincer: <n> row(s), complete` footer — or
  `PARTIAL — <reasons>` when degraded. A piped table cut off mid-stream is
  detectable by the missing footer; without that check, only `--json` output
  is self-validating against truncation.
- **`deps --dot`** prepends `// pincer: PARTIAL — <reasons>` to a degraded
  graph.
- **JSON** streams with `degradation` serialized *before* `data` (schema 5),
  so even the salvaged prefix of a truncated document names its damage.

Exit codes: 0 success (degraded runs included, so existing pipelines keep
working), 1 error, 2 usage. Pass `--strict` to make any degradation exit 3
instead — for pipelines that must branch on partial analysis.
Timestamp-less records are excluded from every first/last time and duration —
time fields stay `null`/absent rather than reading as the 1970 epoch — and a
capture whose timestamps span more than five years sets a `clock_inconsistent`
flag in the summary JSON alongside the table note.
