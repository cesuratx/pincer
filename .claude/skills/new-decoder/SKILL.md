---
name: new-decoder
description: Add a new protocol decoder to pincer (a packet layer or an application-layer sniffer), test-first, wired into the pipeline. Use when extending pincer to recognize a protocol it doesn't yet parse — e.g. NTP, SNMP, SSDP, NetBIOS, an L2 protocol — the common way the tool gets extended.
---

# new-decoder — extend pincer to a new protocol

The recipe for adding a decoder cleanly, the way the existing ones are built.
Work **test-first**: a hex fixture with byte-offset comments comes before the
parser.

## 1. Decide the layer

- **Application-layer sniffer** (most common: NTP, SNMP, SSDP, NetBIOS-NS, …)
  → add a module under `src/app/`, return an owned summary, wire into the
  chain in `src/app/mod.rs::sniff`.
- **Transport/network layer** (rare: SCTP, GRE) → add under `src/decode/`,
  add a `*View` variant and a dispatch arm in `src/decode/mod.rs`.

This skill assumes an app-layer sniffer; adjust for a packet layer.

## 2. Read the format first

Check `docs/protocol-headers.md` and `docs/networking-cheatsheet.md`. If the
protocol isn't there, look it up and **add it to the docs** as part of the
change. Know the well-known port(s) and the first few discriminating bytes.

## 3. Write the hex fixture and a failing test

In the new module's `#[cfg(test)]` block (or `tests/decode_layers.rs` for a
packet layer), hand-assemble a known-good payload as a byte array with one
comment per field. Add a `fn parse(...)` test asserting the extracted values,
plus a `rejects_garbage` test (`parse(&[]).is_none()`, random bytes → `None`).

## 4. Implement the parser — the house rules

- **All byte access through `crate::bytes::Cursor`.** No indexing/slicing of
  the payload (the lint forbids it). `Cursor` makes "never panics" free.
- Signature: `pub fn parse(payload: &[u8]) -> Option<Summary>`. `None` means
  "not this protocol" — the normal case. Internally use a
  `fn parse_inner(...) -> Result<Summary, DecodeError>` and `.ok()` it, so a
  malformed-but-plausible payload yields `None` (no noise), matching `dns.rs`.
- **Cheap structural pre-check first** (port already filtered by the caller;
  check a version byte / magic before doing work).
- Checked arithmetic on every length derived from bytes (`saturating_*`,
  `checked_*`). Cap any count/loop bound that comes from the packet.
- Return **owned** data (`String`, numbers) — never borrow the payload past
  the function. This is the owned/borrowed seam.

## 5. Wire it into dispatch

In `src/app/mod.rs`:
- add a `PORT_<PROTO>` const and a variant to the `AppEvent` enum,
- give it a `label()` arm,
- add the port/content branch to `sniff()` (UDP by port, TCP by content).

If the new event should surface in reports, thread it through
`src/output/mod.rs` (a `DnsRecord`-style flattener or a new `Report` arm) and
`analysis/assets.rs` if it carries identity/service evidence.

## 6. Add it to the office fixture (optional but strong)

Add a builder helper in `src/fixtures/mod.rs` and a packet in
`scenarios::office()` so the new protocol has end-to-end coverage and shows up
in the demo capture. Then `cargo run -- gen testdata` to refresh samples.

## 7. Gate

Run `/check`. Differential tests (`tests/differential.rs`) can cross-check a
packet-layer decoder against `etherparse`; app-layer protocols etherparse
doesn't model are covered by your hex fixtures and the proptest never-panic
harness (which will exercise the new code automatically).
