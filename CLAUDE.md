# pincer — project guide for Claude

`pincer` is a hand-rolled pcap/pcapng analyzer in Rust. It turns raw network
captures into the three artifacts of passive asset discovery: **communication
flows**, an **asset inventory**, and an **application dependency map**. No
libpcap, no packet-parsing crates — every byte is parsed in-house through one
bounds-checked cursor.

## Commands

```bash
cargo build                                   # debug build
cargo test                                    # all unit + integration + proptest
cargo clippy --all-targets -- -D warnings     # lint gate (must be clean)
cargo fmt                                      # format
cargo run -- gen testdata                     # (re)generate sample captures
cargo run -- summary testdata/office.pcap     # try a subcommand
cargo +nightly fuzz run fuzz_pipeline         # coverage-guided fuzzing (fuzz/ is its own crate; see README § Fuzzing)
```

Subcommands: `summary`, `flows`, `assets`, `services`, `deps` (`--dot` for
Graphviz), `dns`, `dhcp`, `gen`. Every analysis subcommand accepts `--json`,
and `-` as the file argument streams from stdin (`gzcat big.pcap.gz | pincer
flows -`). Hostile-flood caps live in `analysis::Limits`; they evict by key
order (the N smallest keys survive), so even a cap-saturated report is
order-independent and diffable. Cap drops and other degradation are reported
on stderr, in the JSON envelope (whose `degradation` field always precedes
`data` in the byte stream), in the `# pincer: … complete|PARTIAL` table
footer, and as a `// pincer: PARTIAL` header on degraded DOT. The global `--strict` flag turns any degradation into exit 3
(default stays exit 0). JSON renders by streaming (`Report::write_json`);
tables/DOT still materialize their string.

## Definition of done

A change is done only when **all three** are green:
1. `cargo fmt --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test`

Run `/check` (project skill) to do all three at once. If you touch the fixture
builder, also run `cargo run -- gen testdata` so the committed samples stay in
sync (a test enforces byte-identity).

## Architecture (one line each)

- `bytes.rs` — `Cursor`, the **only** place raw packet bytes are read. Bounds-checked, returns `Result`, never panics. Everything rests on this.
- `error.rs` — three error tiers: `PcapError` (container, aborts the stream), `DecodeError` (one packet, never aborts), and `Option::None` from app sniffers ("not this protocol", not an error).
- `pcap/` — streaming `CaptureReader` (legacy + pcapng) and a legacy `writer`. Lending iterator: one reusable buffer, constant memory on any file size.
- `decode/` — zero-copy layer views: Ethernet/VLAN, SLL/SLL2 (Linux cooked), raw-IP/null/loop link types, ARP, IPv4, IPv6, TCP, UDP, SCTP (ports), ICMP. Borrow the buffer; allocate nothing.
- `app/` — best-effort sniffers returning **owned** `AppEvent`: DNS/mDNS/LLMNR, DHCP, HTTP, TLS SNI. This owned/borrowed boundary is deliberate.
- `analysis/` — `Observe` sinks run in a single pass: `flows`, `assets`, `stats`; `deps` is *derived* from flows + assets after the pass.
- `output/` — table / JSON renderers behind one `Report` type, plus the standalone DOT renderer (`deps_dot`).
- `fixtures/` — typestate packet builder + `scenarios` (office, incident). Powers tests and `gen`.

## House rules (enforced by lints — do not work around them)

- `#![forbid(unsafe_code)]` crate-wide. No `unsafe`, ever.
- No raw indexing/slicing of packet bytes outside `bytes.rs`. Use `Cursor`. (`clippy::indexing_slicing` is denied.)
- No `unwrap`/`expect`/`panic` in library code (denied). Propagate `Result`/`Option`. Tests may opt out with a module-level `#![allow(...)]`.
- Checked arithmetic on any value derived from packet bytes (`clippy::arithmetic_side_effects` is denied in parsing modules). Use `checked_*`/`saturating_*`.
- Deterministic output: prefer `BTreeMap`/`BTreeSet` so reports are stable and snapshot-testable.
- A malformed packet increments an anomaly counter (see `summary`) — it must never abort the analysis.

## Known limitations (intentional — state them, don't "fix" silently)

- No IP fragment reassembly. Non-first fragments are excluded from transport parsing.
- No TCP stream reassembly. HTTP/TLS detection works on the **first** data segment of a connection; otherwise the flow degrades to port + SYN-ACK evidence.
- MAC↔IP binding is gated on L2 locality (a router's MAC fronts many off-link IPs); off-link hosts are keyed by IP. Local segments come from DHCP option 1 (real mask) or ARP (/24 guess); no RFC-1918 fallback (it made keying order-dependent). Data frames bind and enter the inventory only at `finalize()`, against the complete segment set. ARP-only wide subnets and global IPv6 are documented limitations. See `analysis/assets.rs`.
- Cap survivors are order-independent (smallest-N keys; permutation proptests in `tests/determinism.rs`), but under an engaged cap the overflow-counter *values* tally capped events (order may vary), and evidence already merged through a later-evicted binding/asset cannot be unmerged. Degradation signals always fire when a cap engages.
- DNS/mDNS hostname evidence is trust-gated: answer records count only in responses (qr=1), and only when the record names the speaker itself or a host on the same learned local segment. A resolver's answers for off-segment IPs are not attributed — off-link assets get names from TLS SNI / HTTP Host instead.

## Where to learn the formats

Learning / reference docs (read in this order if you're new to the project):
- `docs/packet-analysis-101.md` — the domain from zero: packets, layers, why passive discovery.
- `DESIGN.md` — architecture, data flow, every design decision and pattern with rationale.
- `docs/rust-concepts.md` — every Rust concept the code uses, tied to real lines.
- `docs/pcap-format.md`, `docs/protocol-headers.md`, `docs/networking-cheatsheet.md` — byte layouts and networking background; read before adding a decoder.
