//! Minimal pcapng reader: Section Header, Interface Description, Enhanced
//! Packet, and Simple Packet blocks; everything else is skipped by length.
//!
//! The classic pcapng traps handled here:
//! - endianness comes from the SHB byte-order magic and **resets at every
//!   SHB** (concatenated captures);
//! - EPB timestamps are counts of *per-interface* units (`if_tsresol`,
//!   default 10⁻⁶, MSB set ⇒ base 2) — never globally microseconds;
//! - block total length includes the 12 bytes of framing and is 4-aligned.
#![deny(clippy::arithmetic_side_effects)]

use std::io::Read;

use super::{LinkType, MAX_RECORD_LEN, Record, read_exact, read_exact_or_eof};
use crate::bytes::Cursor;
use crate::error::{DecodeError, PcapError};
use crate::types::Timestamp;

pub(crate) const BLOCK_SHB_BYTES: [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];

const BLOCK_SHB: u32 = 0x0A0D_0D0A;
const BLOCK_IDB: u32 = 0x0000_0001;
const BLOCK_SPB: u32 = 0x0000_0003;
const BLOCK_EPB: u32 = 0x0000_0006;
const BOM: u32 = 0x1A2B_3C4D;
/// Interface descriptions a section may declare; real captures have a
/// handful, and the cap keeps an IDB flood from breaking constant memory.
const MAX_INTERFACES: usize = 4_096;

#[derive(Debug, Clone, Copy)]
struct Interface {
    link_type: LinkType,
    /// Timestamp units per second.
    ticks_per_sec: u64,
    /// Max captured bytes per packet on this interface (IDB snaplen). Bounds
    /// SPB captured length, which the block itself does not carry.
    snaplen: usize,
}

impl Default for Interface {
    fn default() -> Self {
        Self {
            link_type: LinkType::Ethernet,
            ticks_per_sec: 1_000_000, // if_tsresol default: microseconds
            snaplen: MAX_RECORD_LEN,  // 0 in an IDB means "no limit"
        }
    }
}

#[derive(Debug)]
pub struct State {
    big_endian: bool,
    interfaces: Vec<Interface>,
}

impl State {
    fn u16(&self, cur: &mut Cursor<'_>) -> Result<u16, DecodeError> {
        if self.big_endian {
            cur.u16_be()
        } else {
            cur.u16_le()
        }
    }

    fn u32(&self, cur: &mut Cursor<'_>) -> Result<u32, DecodeError> {
        if self.big_endian {
            cur.u32_be()
        } else {
            cur.u32_le()
        }
    }

    /// Called from [`CaptureReader::new`] with **only the 4-byte block type**
    /// consumed — reads `total_length(4) + BOM(4)` next. Returns the state and
    /// the SHB's total length (= file bytes consumed including the magic).
    pub(crate) fn read_section_header(reader: &mut impl Read) -> Result<(Self, u64), PcapError> {
        let mut len_bytes = [0u8; 4];
        read_exact(reader, &mut len_bytes, "pcapng section header length")?;
        Self::read_section_header_after_len(reader, len_bytes)
    }

    /// Called mid-stream from `next_record`, where the block header read already
    /// consumed `block_type(4) + total_length(4)`. We pass the length bytes in
    /// so we do NOT re-read them — re-reading mis-aligned the parser by 4 bytes
    /// and made a concatenated multi-section file abort on the second SHB.
    fn read_section_header_after_len(
        reader: &mut impl Read,
        len_bytes: [u8; 4],
    ) -> Result<(Self, u64), PcapError> {
        // BOM comes after the length; its byte order also interprets the length.
        let mut bom_bytes = [0u8; 4];
        read_exact(reader, &mut bom_bytes, "pcapng section header magic")?;
        let big_endian = match u32::from_be_bytes(bom_bytes) {
            BOM => true,
            _ if u32::from_le_bytes(bom_bytes) == BOM => false,
            _ => return Err(PcapError::BadMagic(bom_bytes)),
        };
        let total_len = if big_endian {
            u32::from_be_bytes(len_bytes)
        } else {
            u32::from_le_bytes(len_bytes)
        } as usize;

        // type(4) + len(4) + BOM(4) + trailing len(4) = 16 framing bytes; the
        // body must hold at least version(4) + section length(8), so the spec
        // minimum SHB is 28 bytes — and like every block, 4-aligned.
        let shb_ok = total_len >= 28 && total_len.is_multiple_of(4) && total_len <= MAX_RECORD_LEN;
        let body_len = total_len.checked_sub(16).filter(|_| shb_ok);
        let Some(body_len) = body_len else {
            return Err(PcapError::BadLength {
                len: total_len as u64,
                context: "pcapng section header block",
                offset: 0,
            });
        };
        let mut body = vec![0u8; body_len];
        read_exact(reader, &mut body, "pcapng section header body")?;
        // The spec requires rejecting sections whose MAJOR version we do not
        // know — their block layouts may differ; guessing would misparse the
        // whole file. (Minor bumps are compatible by definition.)
        let mut ver = Cursor::new(&body);
        let (major, minor) = if big_endian {
            (
                ver.u16_be().unwrap_or_default(),
                ver.u16_be().unwrap_or_default(),
            )
        } else {
            (
                ver.u16_le().unwrap_or_default(),
                ver.u16_le().unwrap_or_default(),
            )
        };
        if major != 1 {
            return Err(PcapError::BadVersion { major, minor });
        }
        // rest of body: section length, options — all skippable.
        let mut trailer = [0u8; 4];
        read_exact(reader, &mut trailer, "pcapng section header trailer")?;
        let trailer_len = if big_endian {
            u32::from_be_bytes(trailer)
        } else {
            u32::from_le_bytes(trailer)
        };
        if trailer_len as usize != total_len {
            return Err(PcapError::BadLength {
                len: u64::from(trailer_len),
                context: "pcapng section header trailer",
                offset: 0,
            });
        }

        Ok((
            Self {
                big_endian,
                interfaces: Vec::new(),
            },
            total_len as u64,
        ))
    }

    pub(crate) fn next_record<'b>(
        &mut self,
        reader: &mut impl Read,
        buf: &'b mut Vec<u8>,
        offset: &mut u64,
        skipped_blocks: &mut u64,
    ) -> Result<Option<Record<'b>>, PcapError> {
        // Find the next packet block. The borrow-returning parse happens
        // *after* the loop: returning a `Record` borrowed from `buf` from
        // inside a loop that also mutates `buf` trips the borrow checker
        // (the classic lending-iterator shape), so we break first.
        let (packet_block, packet_body_len) = loop {
            let mut head = [0u8; 8];
            if !read_exact_or_eof(reader, &mut head, "pcapng block header")? {
                return Ok(None);
            }

            let mut cur = Cursor::new(&head);
            let block_type = self.u32(&mut cur).map_err(|_| PcapError::TruncatedFile {
                context: "pcapng block header",
            })?;

            if block_type == BLOCK_SHB {
                // New section: endianness may change, interfaces reset. The
                // total_length (head[4..8]) is already read; pass it through so
                // the parser stays aligned, and account for the SHB's bytes in
                // the offset before reading on.
                let len_bytes: [u8; 4] = head
                    .get(4..8)
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or_default();
                let (state, total_len) = Self::read_section_header_after_len(reader, len_bytes)?;
                *self = state;
                *offset = offset.saturating_add(total_len);
                continue;
            }

            let total_len = self.u32(&mut cur).map_err(|_| PcapError::TruncatedFile {
                context: "pcapng block header",
            })? as usize;

            // Framing: type(4) + len(4) + trailing len(4); blocks are 4-aligned.
            let body_ok =
                total_len >= 12 && total_len.is_multiple_of(4) && total_len <= MAX_RECORD_LEN;
            let Some(body_len) = total_len.checked_sub(12).filter(|_| body_ok) else {
                return Err(PcapError::BadLength {
                    len: total_len as u64,
                    context: "pcapng block",
                    offset: *offset,
                });
            };

            // High-water buffer: avoid re-zeroing bytes read_exact overwrites.
            if buf.len() < body_len {
                buf.resize(body_len, 0);
            }
            let slot = buf.get_mut(..body_len).unwrap_or_default();
            read_exact(reader, slot, "pcapng block body")?;
            let mut trailer = [0u8; 4];
            read_exact(reader, &mut trailer, "pcapng block trailer")?;
            // The trailing Block Total Length exists so framing damage is
            // detectable; a mismatch means the leading length we just trusted
            // to advance the stream cannot be trusted either.
            let trailer_len = if self.big_endian {
                u32::from_be_bytes(trailer)
            } else {
                u32::from_le_bytes(trailer)
            };
            if trailer_len as usize != total_len {
                return Err(PcapError::BadLength {
                    len: u64::from(trailer_len),
                    context: "pcapng block trailer",
                    offset: *offset,
                });
            }
            *offset = offset.saturating_add(total_len as u64);

            let body = buf.get(..body_len).unwrap_or(&[]);
            match block_type {
                // Interface definitions are tiny but a hostile file can spray
                // millions; the cap preserves the constant-memory guarantee.
                BLOCK_IDB if self.interfaces.len() < MAX_INTERFACES => {
                    self.parse_interface(body, *offset)?;
                }
                BLOCK_IDB => *skipped_blocks = skipped_blocks.saturating_add(1),
                BLOCK_EPB | BLOCK_SPB => {
                    if self.packet_block_well_formed(block_type, body) {
                        break (block_type, body_len);
                    }
                    // The framing was intact (the block was consumed by its
                    // declared length) but the body lies about its structure.
                    // That is per-packet damage: skip the block and keep
                    // reading — returning Ok(None) here would fake a clean
                    // EOF and silently drop the rest of the capture.
                    *skipped_blocks = skipped_blocks.saturating_add(1);
                }
                _ => {} // unknown block: skipped by length
            }
        };

        let body = buf.get(..packet_body_len).unwrap_or(&[]);
        if packet_block == BLOCK_EPB {
            self.parse_epb(body, *offset)
        } else {
            Ok(self.parse_spb(body))
        }
    }

    /// Whether a packet block's body is long enough for its own fixed fields,
    /// its declared `cap_len` fits, and (for EPB) its `interface_id` names an
    /// interface this section actually declared. Checked *before* the
    /// borrow-returning parse so a malformed body can be skipped as an
    /// anomaly instead of faking EOF (SPB) or aborting the stream (EPB).
    fn packet_block_well_formed(&self, block_type: u32, body: &[u8]) -> bool {
        if block_type == BLOCK_SPB {
            // An SPB needs its orig_len field AND a declared interface: the
            // spec ties SPB semantics (snaplen, link type) to the first IDB.
            // Decoding one under a fabricated default interface would invent
            // link-type and clock facts; skip + count instead.
            return body.len() >= 4 && !self.interfaces.is_empty();
        }
        // EPB: iface(4) + ts(8) + cap_len(4) + orig_len(4), then cap_len data.
        let mut cur = Cursor::new(body);
        let Ok(iface_id) = self.u32(&mut cur) else {
            return false;
        };
        // An EPB referencing an undeclared interface would otherwise decode
        // under guessed defaults (wrong link type, wrong clock).
        if iface_id as usize >= self.interfaces.len() {
            return false;
        }
        if cur.skip(8).is_err() {
            return false;
        }
        let Ok(cap_len) = self.u32(&mut cur) else {
            return false;
        };
        cur.skip(4).is_ok() && cap_len as usize <= cur.remaining()
    }

    fn parse_interface(&mut self, body: &[u8], offset: u64) -> Result<(), PcapError> {
        let mut cur = Cursor::new(body);
        let bad = |_| PcapError::BadLength {
            len: body.len() as u64,
            context: "pcapng interface description block",
            offset,
        };
        let dlt = self.u16(&mut cur).map_err(bad)?;
        self.u16(&mut cur).map_err(bad)?; // reserved
        let snaplen = self.u32(&mut cur).map_err(bad)?;

        let mut iface = Interface {
            link_type: LinkType::from_dlt(u32::from(dlt)),
            // 0 means "no limit"; otherwise the per-interface cap.
            snaplen: if snaplen == 0 {
                MAX_RECORD_LEN
            } else {
                usize::try_from(snaplen).unwrap_or(MAX_RECORD_LEN)
            },
            ..Interface::default()
        };

        // Options: u16 code, u16 len, value padded to 4 bytes. Code 9 = if_tsresol.
        while cur.remaining() >= 4 {
            let (Ok(code), Ok(len)) = (self.u16(&mut cur), self.u16(&mut cur)) else {
                break;
            };
            if code == 0 {
                break; // opt_endofopt
            }
            let padded = (len as usize).next_multiple_of(4);
            let Ok(value) = cur.take(padded) else { break };
            if code == 9
                && let Some(&resol) = value.first()
            {
                iface.ticks_per_sec = tsresol_ticks(resol);
            }
        }

        self.interfaces.push(iface);
        Ok(())
    }

    fn parse_epb<'b>(&self, body: &'b [u8], offset: u64) -> Result<Option<Record<'b>>, PcapError> {
        let mut cur = Cursor::new(body);
        let bad = |_| PcapError::BadLength {
            len: body.len() as u64,
            context: "pcapng enhanced packet block",
            offset,
        };
        let iface_id = self.u32(&mut cur).map_err(bad)?;
        let ts_high = self.u32(&mut cur).map_err(bad)?;
        let ts_low = self.u32(&mut cur).map_err(bad)?;
        let cap_len_u32 = self.u32(&mut cur).map_err(bad)?;
        let cap_len = cap_len_u32 as usize;
        // Same normalization as the legacy reader: captured bytes are real,
        // so orig_len is at least cap_len — keeps decode's truncation honest.
        let orig_len = self.u32(&mut cur).map_err(bad)?.max(cap_len_u32);
        let data = cur.take(cap_len).map_err(bad)?;

        let iface = self
            .interfaces
            .get(iface_id as usize)
            .copied()
            .unwrap_or_default();

        let ticks = (u64::from(ts_high) << 32) | u64::from(ts_low);
        Ok(Some(Record {
            ts: Some(ticks_to_timestamp(ticks, iface.ticks_per_sec)),
            orig_len,
            link_type: iface.link_type,
            data,
        }))
    }

    fn parse_spb<'b>(&self, body: &'b [u8]) -> Option<Record<'b>> {
        // SPB: u32 original length, then packet data padded to a 32-bit
        // boundary. The captured length is min(orig_len, snaplen) — the block
        // carries no captured-length field, so we must derive it and NOT hand
        // the padding bytes (up to 3) to the decoders as if they were packet.
        let mut cur = Cursor::new(body);
        let orig_len = self.u32(&mut cur).ok()?;
        let iface = self.interfaces.first().copied().unwrap_or_default();
        let want = usize::try_from(orig_len)
            .unwrap_or(usize::MAX)
            .min(iface.snaplen)
            .min(cur.remaining());
        let data = cur.take(want).unwrap_or(&[]);
        Some(Record {
            // The block has no timestamp field; inventing one (the epoch) would
            // falsify every downstream timeline. Absence stays absent.
            ts: None,
            orig_len,
            link_type: iface.link_type,
            data,
        })
    }
}

/// `if_tsresol`: MSB clear ⇒ 10^-v seconds per tick; MSB set ⇒ 2^-v.
fn tsresol_ticks(resol: u8) -> u64 {
    if resol & 0x80 == 0 {
        // Exponent too large to represent is garbage; fall back to the spec
        // DEFAULT resolution (microseconds), not nanoseconds.
        10u64.checked_pow(u32::from(resol)).unwrap_or(1_000_000)
    } else {
        1u64.checked_shl(u32::from(resol & 0x7F))
            .unwrap_or(u64::MAX)
    }
}

fn ticks_to_timestamp(ticks: u64, ticks_per_sec: u64) -> Timestamp {
    if ticks_per_sec == 0 {
        return Timestamp::ZERO;
    }
    let secs = ticks.checked_div(ticks_per_sec).unwrap_or(0);
    let frac = ticks.checked_rem(ticks_per_sec).unwrap_or(0);
    // nanos = frac * 1e9 / ticks_per_sec, in u128 to avoid overflow.
    let nanos = u128::from(frac)
        .saturating_mul(1_000_000_000)
        .checked_div(u128::from(ticks_per_sec))
        .unwrap_or(0);
    #[allow(clippy::cast_possible_truncation)]
    Timestamp::new(secs, nanos.min(999_999_999) as u32)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// A well-framed SPB whose body is too short for its own `orig_len` field
    /// must be skipped and counted — not treated as clean EOF (which silently
    /// dropped every later packet) and not abort the stream.
    #[test]
    fn malformed_spb_is_skipped_not_eof() {
        let mut file = Vec::new();
        // SHB: type, total_len 28, BOM, version 1.0, section length -1, trailer.
        file.extend_from_slice(&BLOCK_SHB.to_be_bytes());
        file.extend_from_slice(&28u32.to_le_bytes());
        file.extend_from_slice(&BOM.to_le_bytes());
        file.extend_from_slice(&1u16.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&(-1i64).to_le_bytes());
        file.extend_from_slice(&28u32.to_le_bytes());
        // IDB: dlt 1 (Ethernet), reserved, snaplen 0.
        file.extend_from_slice(&BLOCK_IDB.to_le_bytes());
        file.extend_from_slice(&20u32.to_le_bytes());
        file.extend_from_slice(&1u16.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&20u32.to_le_bytes());
        // Malformed SPB: total_len 12 → zero-byte body, no room for orig_len.
        file.extend_from_slice(&BLOCK_SPB.to_le_bytes());
        file.extend_from_slice(&12u32.to_le_bytes());
        file.extend_from_slice(&12u32.to_le_bytes());
        // Valid EPB carrying 4 bytes of packet data.
        file.extend_from_slice(&BLOCK_EPB.to_le_bytes());
        file.extend_from_slice(&36u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes()); // interface_id
        file.extend_from_slice(&0u32.to_le_bytes()); // ts_high
        file.extend_from_slice(&0u32.to_le_bytes()); // ts_low
        file.extend_from_slice(&4u32.to_le_bytes()); // cap_len
        file.extend_from_slice(&4u32.to_le_bytes()); // orig_len
        file.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        file.extend_from_slice(&36u32.to_le_bytes());

        let mut reader = crate::pcap::CaptureReader::new(file.as_slice()).unwrap();
        let record = reader.next_record().unwrap().unwrap();
        assert_eq!(record.data, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(reader.next_record().unwrap().is_none());
        assert_eq!(reader.skipped_blocks(), 1);
    }

    /// An EPB whose declared `cap_len` exceeds its body is per-packet damage:
    /// skipped and counted, never a stream abort.
    #[test]
    fn epb_caplen_overrun_is_skipped_not_fatal() {
        let mut file = Vec::new();
        file.extend_from_slice(&BLOCK_SHB.to_be_bytes());
        file.extend_from_slice(&28u32.to_le_bytes());
        file.extend_from_slice(&BOM.to_le_bytes());
        file.extend_from_slice(&1u16.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&(-1i64).to_le_bytes());
        file.extend_from_slice(&28u32.to_le_bytes());
        // EPB claiming 4096 captured bytes but carrying none.
        file.extend_from_slice(&BLOCK_EPB.to_le_bytes());
        file.extend_from_slice(&32u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&4096u32.to_le_bytes()); // cap_len lie
        file.extend_from_slice(&4096u32.to_le_bytes());
        file.extend_from_slice(&32u32.to_le_bytes());

        let mut reader = crate::pcap::CaptureReader::new(file.as_slice()).unwrap();
        assert!(reader.next_record().unwrap().is_none());
        assert_eq!(reader.skipped_blocks(), 1);
    }

    #[test]
    fn tsresol_decodes_both_bases() {
        assert_eq!(tsresol_ticks(6), 1_000_000); // default µs
        assert_eq!(tsresol_ticks(9), 1_000_000_000); // ns
        assert_eq!(tsresol_ticks(0x80 | 0x0A), 1024); // MSB set, exponent 10 → 2^10
    }

    #[test]
    fn ticks_normalize_to_nanos() {
        let ts = ticks_to_timestamp(1_500_000, 1_000_000);
        assert_eq!((ts.secs, ts.nanos), (1, 500_000_000));
        let ts = ticks_to_timestamp(3, 1_000_000_000);
        assert_eq!((ts.secs, ts.nanos), (0, 3));
        assert_eq!(ticks_to_timestamp(5, 0), Timestamp::ZERO);
    }
}
