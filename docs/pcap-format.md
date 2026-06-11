# Capture file formats

How `pincer`'s `pcap/` module reads files. Two formats: classic (legacy) pcap
and the newer pcapng. All multi-byte fields' endianness is set by the file
header; **packet contents are always network (big-endian) byte order**
regardless — two independent endianness domains, and mixing them is the
classic bug.

## Legacy pcap

### Global header (24 bytes)

| offset | size | field          | notes |
|-------:|-----:|----------------|-------|
| 0      | 4    | magic          | sets byte order AND timestamp resolution |
| 4      | 2    | version major  | always 2 |
| 6      | 2    | version minor  | always 4 |
| 8      | 4    | thiszone       | GMT offset; effectively always 0 |
| 12     | 4    | sigfigs        | timestamp accuracy; always 0 |
| 16     | 4    | snaplen        | max captured bytes per packet |
| 20     | 4    | network (DLT)  | link type; 1 = Ethernet (`DLT_EN10MB`) |

The four magic values:

| bytes (on disk)        | byte order | timestamp fraction |
|------------------------|------------|--------------------|
| `A1 B2 C3 D4`          | big-endian | microseconds       |
| `D4 C3 B2 A1`          | little     | microseconds       |
| `A1 B2 3C 4D`          | big-endian | nanoseconds        |
| `4D 3C B2 A1`          | little     | nanoseconds        |

### Per-record header (16 bytes), then `incl_len` bytes of packet

| offset | size | field    | notes |
|-------:|-----:|----------|-------|
| 0      | 4    | ts_sec   | Unix seconds |
| 4      | 4    | ts_frac  | µs or ns per the magic |
| 8      | 4    | incl_len | bytes captured (≤ snaplen) |
| 12     | 4    | orig_len | bytes on the wire (may exceed incl_len) |

`incl_len < orig_len` ⇒ the packet was snaplen-truncated. Normal; decode as
far as the bytes allow.

## pcapng (block-structured)

A sequence of typed, length-prefixed blocks. Every block:

```
 0      4   block type
 4      4   block total length (includes these 12 framing bytes; 4-byte aligned)
 8    ...   block body
 ...    4   block total length again (redundant, for backward parsing)
```

`pincer` reads four block types and skips the rest by length:

- **SHB — Section Header Block** (`0x0A0D0D0A`): body starts with a byte-order
  magic `0x1A2B3C4D` that defines endianness for the whole section, then
  version and section length. **Endianness resets at every SHB** (files can be
  concatenated). The block type bytes also serve as the file's magic.
- **IDB — Interface Description Block** (`0x00000001`): link type + snaplen +
  options. Option code 9 = `if_tsresol`, the timestamp resolution for packets
  on this interface. Default 10⁻⁶ (µs); if the high bit is set the low 7 bits
  are a base-2 exponent. Interfaces are referenced by index from packet blocks.
- **EPB — Enhanced Packet Block** (`0x00000006`): interface id, a 64-bit
  timestamp (high32 << 32 | low32) **in that interface's `if_tsresol` units**,
  captured length, original length, then the packet bytes (padded to 4).
  Assuming microseconds globally is the classic pcapng bug.
- **SPB — Simple Packet Block** (`0x00000003`): original length then packet
  bytes; no timestamp, no per-interface data. The reader surfaces that absence
  (`Record.ts = None`, counted as `timestampless_records` degradation) rather
  than fabricating an epoch time.

## Edge cases the reader handles

- All four legacy magics; ns fractions normalized to a common `Timestamp`.
- pcapng endianness per-section; per-interface timestamp resolution.
- Implausible record/block lengths rejected (`> 64 MiB`, not 4-aligned, `< 12`).
- The reader reports a final record cut off mid-file as `TruncatedFile`; the
  analysis driver tolerates that case and reports what it has, so a partial
  capture still yields results.
- A corrupt *second* SHB in a concatenated file (bad byte-order magic or an
  unknown major version) likewise stops the stream without discarding it: the
  driver keeps the sections already read and flags `damaged_section`. The
  first SHB getting the same damage is a hard error — nothing was readable.
- Constant memory: one reusable buffer, so multi-GB files stream fine.
