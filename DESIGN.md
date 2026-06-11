# pincer — design document

How `pincer` is built and **why each decision was made**. Read
[docs/packet-analysis-101.md](docs/packet-analysis-101.md) first for the domain;
read [docs/rust-concepts.md](docs/rust-concepts.md) alongside this for the Rust
language details. This document is the bridge between the two: the engineering.

---

## 1. Goal and constraints

**Goal.** Read a pcap/pcapng capture and produce passive-discovery output:
communication flows, an asset inventory, a service list, and an application
dependency map.

**Constraints** (set deliberately, each with a reason):

| Constraint | Why |
|-----------|-----|
| No libpcap / no packet-parsing crates | The job *is* understanding the bytes; a crate hides exactly that. Also keeps the crate pure safe Rust with zero system dependencies. |
| Hand-rolled parsers, verified against `etherparse` in tests only | Crate-grade correctness as a *test oracle* without shipping the dependency. |
| Never panic on any input | Every byte comes from an untrusted network. A parser that crashes on a malformed packet is useless for real or hostile captures. This is the domain's core requirement, not gold-plating. |
| Constant memory regardless of file size | Captures can be many gigabytes; loading one into RAM is a non-starter. |
| Deterministic output | Reports must be diff-able and snapshot-testable. |

These constraints *drive the architecture* — most design choices below trace
back to one of them.

---

## 2. The pipeline at a glance

Data flows in one direction, transformed at each stage. Read top to bottom:

```
 capture file (bytes on disk)
        │
        ▼
 ┌──────────────────┐   pcap/  — streaming container reader
 │  CaptureReader   │   one packet at a time, ONE reusable buffer
 └──────────────────┘   → Record { ts, bytes, link_type }
        │  &[u8]  (borrowed — no copy)
        ▼
 ┌──────────────────┐   decode/ — peel the protocol layers
 │  decode_packet   │   Ethernet → IP → TCP/UDP, zero-copy views
 └──────────────────┘   → PacketView<'a>  (borrows the buffer)
        │
        ├───────────────► app/ — sniff the payload (DNS/DHCP/HTTP/TLS)
        │                      → Option<AppEvent>  (OWNED summary)
        ▼
 ┌──────────────────┐   analysis/ — fold packets into state
 │  Observe sinks   │   FlowTable, AssetInventory, Stats  (single pass!)
 └──────────────────┘
        │
        ▼
 ┌──────────────────┐   output/ — render
 │  Report          │   table | JSON | Graphviz DOT
 └──────────────────┘
        │
        ▼
   stdout
```

Two things to notice, because they're the soul of the design:

1. **Everything from the reader down to the analysis sinks is *borrowed*, not
   copied.** A packet's bytes live in the reader's one buffer; the decoded views
   are just offsets and small parsed values pointing into it. We allocate
   memory only when a fact crosses into the long-lived analysis state.

2. **The capture is traversed exactly once.** No matter how many analyses a
   subcommand needs, packets stream past once and each analysis "observes" them.
   That's the [observer pattern](#52-observer--single-pass-pipeline), and it's
   what keeps a multi-gigabyte file affordable.

---

## 3. Module map and responsibilities

```
src/
├── bytes.rs          THE safety chokepoint: Cursor, the only code that reads raw packet bytes
├── error.rs          Three error tiers (see §4)
├── types.rs          Shared value types: MacAddr, Timestamp, IpProto (newtypes)
│
├── pcap/             Container layer — file format
│   ├── mod.rs        CaptureReader: format auto-detect, the lending reader
│   ├── legacy.rs     Classic pcap (4 magic variants)
│   ├── pcapng.rs     pcapng blocks (SHB/IDB/EPB/SPB)
│   └── writer.rs     Legacy writer (powers fixtures + `gen`)
│
├── decode/           Packet layers — zero-copy borrowed views
│   ├── mod.rs        PacketView + the layer-dispatch chain
│   ├── ethernet.rs   Ethernet II + stacked VLAN
│   ├── arp.rs ipv4.rs ipv6.rs tcp.rs udp.rs icmp.rs
│
├── app/              Application sniffers — owned summaries, best-effort
│   ├── mod.rs        AppEvent enum + sniff() dispatch (chain of responsibility)
│   ├── dns.rs dhcp.rs http.rs tls.rs
│
├── analysis/         The intelligence — Observe sinks, single pass
│   ├── mod.rs        Observe trait + service_name()
│   ├── flows.rs      FlowTable: bidirectional 5-tuple aggregation
│   ├── assets.rs     AssetInventory: identity resolution with evidence
│   ├── deps.rs       Dependency edges + Graphviz export
│   └── stats.rs      Capture-wide counters + anomalies
│
├── output/           Rendering — strategy over one Report type
│   ├── mod.rs        Report enum → to_table() / to_json()
│   └── table.rs      Aligned-table renderer (no crate)
│
├── fixtures/         Test data — typestate packet builder
│   ├── mod.rs        Packet builder (compile-safe layer stacking)
│   └── scenarios.rs  office() and incident() captures
│
├── cli.rs            clap commands + the single-pass Pass runner
├── lib.rs            Library root, module declarations, run()
└── main.rs           Thin binary: call run(), map errors to exit codes
```

The dependency direction is strictly downward: `analysis` uses `decode` and
`app`; `decode` uses `bytes`; nothing reaches back up. `bytes.rs` depends on
nothing but `error` and `types`. This layering is what makes each piece testable
in isolation.

---

## 4. The error model — three tiers, on purpose

Most parsers have one error type and treat every failure the same. That's wrong
for packet analysis, where failures mean genuinely different things. `pincer`
has **three tiers** ([error.rs](src/error.rs)):

1. **`PcapError` — the container is broken.** Bad magic number, an impossible
   block length, the file ends mid-header. This is fatal *to the stream*: we
   can't trust the file's framing past that point, so we stop reading.
   Returned by the reader. Fatal to the stream is not fatal to the *run*: the
   CLI turns mid-stream damage — a truncated tail, a framing mismatch, a
   corrupt later section header in a concatenated pcapng — into a flagged
   partial report (`truncated_tail` / `damaged_section` in the degradation
   envelope, plus a stderr warning) and keeps everything already analyzed.
   Only an unreadable *initial* header, where nothing trustworthy has been
   parsed yet, aborts with an error.

2. **`DecodeError` — one packet is bad.** Truncated (ran out of bytes — normal,
   from snaplen) or malformed (claims to be IPv4 but isn't). This is **not**
   fatal: we increment an anomaly counter, skip that packet, and keep going. One
   hostile packet costs one counter, never the analysis. Returned by decoders.

3. **`Option::None` — "not this protocol."** When a DNS sniffer looks at a
   payload that isn't DNS, that's not an *error* — it's the normal, expected
   answer. So application sniffers return `Option`, not `Result`. `None` means
   "doesn't apply," which happens for the vast majority of packets.

Why this matters: it makes the code's intent legible. A reviewer
can see that `parse_dns -> Option` means "best-effort detection" while
`parse_ipv4 -> Result<_, DecodeError>` means "this *should* be IPv4 and if it
isn't that's a finding." The type signatures document the semantics.

```rust
// container: aborts the stream
fn next_record(&mut self) -> Result<Option<Record<'_>>, PcapError>;
// packet layer: recorded as an anomaly, never aborts
fn parse(cur: &mut Cursor) -> Result<Ipv4View, DecodeError>;
// app sniffer: "not this protocol" is normal, not an error
fn parse(payload: &[u8]) -> Option<DnsSummary>;
```

---

## 5. The design patterns, and why each earns its place

A pattern is only worth using if it removes a real risk or expresses a real
constraint. Here's each one in `pincer` with the specific problem it solves.

### 5.1 The single byte-reading chokepoint (`Cursor`)

**Problem:** any code that does `packet_bytes[12]` can panic if the packet is
shorter than 13 bytes — and we have hundreds of such reads. With raw indexing
spread across the codebase, "never panics" is unprovable.

**Solution:** one type, [`bytes::Cursor`](src/bytes.rs), is the only code
that *indexes or slices* raw packet bytes. Every accessor is bounds-checked and
returns `Result`. Everywhere else, the lint `clippy::indexing_slicing` is
**denied**, so the compiler rejects any `bytes[i]` outside `Cursor`. (A few
consumers — the HTTP sniffer's header scan, for example — then read those bytes
through safe std APIs like `str::from_utf8`, which cannot panic either.) Now "never panics" reduces
to "audit one small file," and we did — then proved it empirically with a fuzz
test. This is the keystone: most other safety properties rest on it.

### 5.2 Observer / single-pass pipeline

**Problem:** `summary`, `flows`, `assets`, and `deps` each need to look at every
packet. The naive design reads the file four times. On a 10 GB capture that's
catastrophic.

**Solution:** the [`Observe` trait](src/analysis/mod.rs):

```rust
pub trait Observe {
    fn observe(&mut self, pkt: &PacketView<'_>, app: Option<&AppEvent>);
}
```

`FlowTable`, `AssetInventory`, and `Stats` all implement it. The CLI builds the
sinks it needs, then streams the file **once**, handing each packet to every
sink ([cli.rs](src/cli.rs) `Pass::run`). Adding a new analysis is "implement one
method"; the traversal cost never grows.

### 5.3 Lending iterator (the reader)

**Problem:** we want `for packet in capture { ... }` ergonomics, but a real
`Iterator` must hand out values the caller can keep — which forces either a
fresh `Vec` allocation per packet (slow) or `Rc`/copies (slower). We want each
packet to *borrow* one reusable buffer so memory stays flat.

**Solution:** instead of `impl Iterator`, the reader exposes

```rust
fn next_record(&mut self) -> Result<Option<Record<'_>>, PcapError>;
```

The returned `Record` borrows the reader (the `'_` lifetime). You must finish
with one packet before asking for the next — which is *exactly* the streaming
discipline we want, and the borrow checker enforces it for free. This is the
known "lending iterator" shape (a true lending `Iterator` needs unstable GATs;
the inherent-method form is the idiomatic workaround). See
[pcap/mod.rs](src/pcap/mod.rs).

### 5.4 Newtype + smart constructor

**Problem:** a MAC address is "six bytes," a flow key is "two endpoints" — but
raw tuples carry no guarantees and invite mixing up arguments.

**Solution:** wrap them in dedicated types ([types.rs](src/types.rs),
[flows.rs](src/analysis/flows.rs)):
- `MacAddr([u8; 6])` — formats itself, knows `is_multicast()`, can't be confused
  with any other `[u8; 6]`.
- `FlowKey` — its **only** constructor sorts the two endpoints, so "packets in
  either direction share one key" is true *by construction*, not by every caller
  remembering to sort. The invariant lives in one place.

### 5.5 Typestate builder (the fixture factory)

**Problem:** test packets must be built layer by layer, but "UDP before IP" or
"two IP headers" are nonsense — and a runtime check is a test that can itself be
buggy.

**Solution:** each builder step returns a **different type**
([fixtures/mod.rs](src/fixtures/mod.rs)):
`Packet::ethernet(..) -> EthStage`, `.ipv4(..) -> Ipv4Stage`,
`.udp(..) -> UdpStage`, `.payload(..) -> Vec<u8>`. You *cannot* call `.udp()`
before `.ipv4()` because `EthStage` has no `.udp()` method — it's a **compile
error**, not a runtime failure. The valid sequences are encoded in the type
graph. (It also computes all lengths and checksums for you.)

### 5.6 Chain of responsibility (app sniffing)

**Problem:** a TCP payload might be TLS, or HTTP, or neither. We want to try
candidates in order, cheapest discriminator first, stopping at the first match.

**Solution:** [`app::sniff`](src/app/mod.rs) tries sniffers in sequence; each
does a cheap structural pre-check and returns `Option`, so `None` falls through
to the next. UDP dispatches by port; TCP by content (`tls.or_else(|| http)`).

### 5.7 Strategy (output rendering)

**Problem:** every report needs table, JSON, and (for deps) DOT renderings, and
we don't want a rendering `if/else` smeared through the analysis code.

**Solution:** one [`Report`](src/output/mod.rs) enum wraps any analysis result;
`to_table()` / `to_json()` are the interchangeable strategies. The CLI picks one
based on `--json`. Analysis code knows nothing about formatting.

---

## 6. The load-bearing decisions (the ones with real subtlety)

### Zero-copy, and where the copy *does* happen

Decoding allocates nothing: `PacketView<'a>` and its layers are offsets plus
small scalars plus `&'a [u8]` slices into the reader's buffer. At a million
packets, per-packet `Vec`s would dominate runtime. The lifetimes also *prevent a
bug*: a `PacketView` cannot outlive the buffer it borrows, so you physically
cannot accumulate raw packets and blow memory — the borrow checker enforces the
streaming model.

The single deliberate seam where we copy is **`AppEvent`** (app sniffers return
*owned* `String`s and numbers). Why there? Because an asset's hostname must
outlive the packet it came from — it lives in the inventory for the whole run.
So the rule is: *borrow while decoding, own when a fact graduates into long-lived
state.* That boundary is the `AppEvent` type, and naming it is itself a design
statement.

### Locality: never bind a MAC to an off-link IP

This is the subtlest correctness rule, and a real bug fixed during development.
When your laptop talks to `example.com`, the packet's source MAC is your
**router's** (it forwarded the packet); the source IP is example.com's. A naive
"bind source MAC ↔ source IP" would attach example.com — and every other site —
to the router's MAC, collapsing the whole internet into one "asset."

The fix ([assets.rs](src/analysis/assets.rs)): only bind a MAC to an IP we
believe is on the **same local segment** (Layer 2). We learn local segments
authoritatively — from DHCP option 1 we get the *real* subnet mask, and from
ARP (which carries no mask) a conservative /24. An IP is local only if it is
already bound or falls in a learned segment; there is **no** RFC-1918 fallback,
because one that switched on only "before any segment is learned" made a host's
keying depend on packet order. Off-link hosts stay keyed by IP. Assets are keyed
by an `AssetKey` enum (`Mac | Ip`, both `Copy`), so resolving an IP to its asset
in the per-packet hot path allocates nothing. This is exactly the kind of domain
subtlety a passive-discovery product lives and dies on.

Residual limitations, stated honestly in the code: an ARP-only network wider
than /24 may IP-key a same-segment host in another /24; IPv6 locality covers
link-local/ULA only (global SLAAC needs NDP parsing we don't do). The deeper
fix — a two-phase resolve that collects candidate bindings during the pass and
keys them once at the end, against the complete segment set — is implemented:
`record_provisional` collects, `finalize()` resolves, which is what makes the
inventory order-independent.

### Honest limitations, stated not hidden

- **No IP fragment reassembly** — a non-first fragment carries no transport
  header, so we exclude it from transport parsing rather than mis-parse it.
- **No TCP stream reassembly** — HTTP/TLS detection works on the first data
  segment; otherwise the service is still found (by port + SYN-ACK) but without
  the hostname. We *report* the degradation rather than pretending.
- **Service evidence is graded** (`SynAck` > `AppLayer` > `PortHeuristic`) so a
  guess is never presented as a fact.
- **DNS/mDNS naming evidence is trust-gated** — answer records count only in
  responses (qr=1; answers riding on queries are a poisoning shape or mDNS
  known-answer suppression, neither a claim), and only when the record names
  the speaker itself or a neighbor on the same learned local segment
  (resolver-style). A spoofed record claiming an off-segment victim IP cannot
  rewrite that asset's identity; off-link hosts are named by TLS SNI / HTTP
  Host instead. The residual exposure — an on-segment attacker naming an
  on-segment neighbor — is indistinguishable from a legitimate local resolver
  by passive evidence alone.
- **Timestamp absence is typed, not faked** — a pcapng Simple Packet Block
  carries no timestamp, so `Record.ts` (and `PacketView.ts`) is
  `Option<Timestamp>`. SPB records are excluded from every first/last fold and
  from `duration_secs` (no fabricated 1970 epoch in flows, assets, or the
  summary), and counted as `timestampless_records` in the degradation
  envelope, a summary note, and a stderr warning. A >5-year timestamp span —
  now only producible by genuinely inconsistent capture clocks — surfaces as
  `clock_inconsistent` in summary JSON, not just the table note.
- **Offload-capture quirks are handled, not punted**: IPv4 `total_length == 0`
  and IPv6 `payload_length == 0` (TSO/GSO captures taken on the sending host,
  plus v6 jumbograms) decode using the captured bytes instead of being dropped
  as malformed — the same accommodation Wireshark makes.
- **Smaller declared non-goals**: DHCP option overload (52) and RFC 3396 long
  options aren't reassembled; the IPv6 extension walk stops at AH/ESP
  (encrypted/authenticated — counted, not guessed at); 802.3/LLC frames are
  labeled `802.3` but not parsed; the pcapng Name Resolution Block is skipped
  (a free hostname source — good future work).

Stating limitations precisely is a senior signal. A tool that hides them is one
you can't trust.

---

## 7. The strict Rust rules — each as a decision

These are configured in [`Cargo.toml`](Cargo.toml) `[lints]` and enforced by
`cargo clippy --all-targets -- -D warnings`. Each one is here because it converts
a class of runtime bug into a compile error — they make the code *simpler to
reason about*, not more ceremonious.

| Rule | What it prevents | Why it's right *here* |
|------|------------------|------------------------|
| `#![forbid(unsafe_code)]` | memory-corruption bugs | We parse untrusted input; `unsafe` is where parsers get CVEs. Forbidding it means memory safety is the compiler's guarantee, not ours. |
| `deny(clippy::indexing_slicing)` | out-of-bounds panics | Forces all byte access through `Cursor` (§5.1) — makes "never panics" provable. |
| `deny(clippy::unwrap_used / expect_used / panic)` | panics on bad data | A library that `unwrap`s on a malformed packet crashes the caller. Forces honest `Result`/`Option` propagation. |
| `deny(clippy::arithmetic_side_effects)` in parsers | integer overflow panics / wraps | Packet lengths are attacker-controlled; `a + b` on them can overflow. Forces `checked_*` / `saturating_*`. |
| `warn(clippy::pedantic)` | a hundred small non-idioms | Keeps the code idiomatic by default; we opt out of a handful that don't fit. |
| `overflow-checks = true` in release | silent wrong math in production | Overflow panics in release too, so a bug surfaces loudly instead of corrupting a result. |

Tests opt out where appropriate (a test *should* `unwrap` and `panic!` on a
failed assertion) via a module-level `#![allow(...)]` — the strictness is for
the *library*, where untrusted input lands.

The payoff is concrete: because of these rules, the claim "no input can panic
this program" is first made *provable* (audit one file, trust the compiler for
the rest) and then *proven* by `tests/never_panic.rs`, which throws random
bytes, valid-header-plus-garbage, and every truncation and bit-flip of the
office capture at the whole pipeline.

---

## 8. Testing strategy (how we trust it)

Four layers, each catching a different failure class:

1. **Hex-fixture unit tests** ([tests/decode_layers.rs](tests/decode_layers.rs))
   — hand-assembled packets with byte-offset comments; the test you read to
   *learn* the format. Plus truncation at every boundary.
2. **Integration tests** ([tests/integration_cli.rs](tests/integration_cli.rs))
   — build the office capture, run the whole pipeline, assert the *conclusions*
   (the DHCP hostname lands on the right asset; the dependency map has the
   `laptop → example.com:443` edge with SNI; the gateway didn't absorb off-link
   IPs).
3. **Differential tests** ([tests/differential.rs](tests/differential.rs)) — our
   decoders vs `etherparse` on the same frames. Catches "I misread the spec."
4. **Property tests** ([tests/never_panic.rs](tests/never_panic.rs)) — the
   never-panic proof, via fuzzing.

Plus a **round-trip guarantee**: the committed sample captures are byte-identical
to what the fixture builder generates (a test enforces it), so the samples can
never silently drift from the code.

The reader and writer testing each other, with `etherparse` as an independent
referee, forms a closed loop you can trust without any external tool.

---

## 9. If we kept going (honest future work)

- **TCP stream reassembly** would unlock full HTTP/TLS parsing across segments —
  the biggest single capability jump.
- **More fingerprint signals** (SSDP/UPnP, NetBIOS, SNMP, JA3 TLS fingerprints)
  would sharpen device recognition toward what the Fing database does.
- **Performance, *if measured to need it*:** profile first; then cheap
  single-threaded wins (run only the needed sinks, a faster hot-path map);
  then — only then — **flow-key sharding** across cores (hash the 5-tuple to a
  per-core worker owning its shard), which is how line-rate sensors parallelize.
  Naive file-splitting is wrong because the format is sequential and flow
  analysis is order-sensitive. (Benchmarked single-threaded: ~340K packets/sec
  through the whole pipeline — so this is hypothetical, not needed.)
