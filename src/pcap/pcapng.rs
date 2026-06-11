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
    /// consumed — reads `total_length(4) + BOM(4)` next.
    pub(crate) fn read_section_header(reader: &mut impl Read) -> Result<Self, PcapError> {
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
    ) -> Result<Self, PcapError> {
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

        // type(4) + len(4) + BOM(4) + trailing len(4) = 16 framing bytes
        let body_len = total_len
            .checked_sub(16)
            .filter(|len| *len <= MAX_RECORD_LEN);
        let Some(body_len) = body_len else {
            return Err(PcapError::BadLength {
                len: total_len as u64,
                context: "pcapng section header block",
                offset: 0,
            });
        };
        let mut body = vec![0u8; body_len];
        read_exact(reader, &mut body, "pcapng section header body")?;
        // body: version_major, version_minor, section length, options — all skippable.
        let mut trailer = [0u8; 4];
        read_exact(reader, &mut trailer, "pcapng section header trailer")?;

        Ok(Self {
            big_endian,
            interfaces: Vec::new(),
        })
    }

    pub(crate) fn next_record<'b>(
        &mut self,
        reader: &mut impl Read,
        buf: &'b mut Vec<u8>,
        offset: &mut u64,
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
                let len_bytes = [head[4], head[5], head[6], head[7]];
                *self = Self::read_section_header_after_len(reader, len_bytes)?;
                let total_len = if self.big_endian {
                    u32::from_be_bytes(len_bytes)
                } else {
                    u32::from_le_bytes(len_bytes)
                };
                *offset = offset.saturating_add(u64::from(total_len));
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
            *offset = offset.saturating_add(total_len as u64);

            let body = buf.get(..body_len).unwrap_or(&[]);
            match block_type {
                BLOCK_IDB => self.parse_interface(body, *offset)?,
                BLOCK_EPB | BLOCK_SPB => break (block_type, body_len),
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
        let cap_len = self.u32(&mut cur).map_err(bad)? as usize;
        let orig_len = self.u32(&mut cur).map_err(bad)?;
        let data = cur.take(cap_len).map_err(bad)?;

        let iface = self
            .interfaces
            .get(iface_id as usize)
            .copied()
            .unwrap_or_default();

        let ticks = (u64::from(ts_high) << 32) | u64::from(ts_low);
        Ok(Some(Record {
            ts: ticks_to_timestamp(ticks, iface.ticks_per_sec),
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
            ts: Timestamp::ZERO,
            orig_len,
            link_type: iface.link_type,
            data,
        })
    }
}

/// `if_tsresol`: MSB clear ⇒ 10^-v seconds per tick; MSB set ⇒ 2^-v.
fn tsresol_ticks(resol: u8) -> u64 {
    if resol & 0x80 == 0 {
        10u64.checked_pow(u32::from(resol)).unwrap_or(1_000_000_000)
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
    use super::*;

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
