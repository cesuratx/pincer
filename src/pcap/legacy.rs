//! Legacy pcap format: 24-byte global header, then 16-byte record headers.
//!
//! The magic number encodes **two** properties: the file's byte order and the
//! timestamp resolution (µs or ns). Packet *contents* are always network byte
//! order regardless — two independent endianness domains.
#![deny(clippy::arithmetic_side_effects)]

use std::io::Read;

use super::{LinkType, MAX_RECORD_LEN, Record, read_exact, read_exact_or_eof};
use crate::bytes::Cursor;
use crate::error::PcapError;
use crate::types::Timestamp;

/// 0xA1B2C3D4 written by a big-endian system, microsecond resolution.
pub(crate) const MAGIC_BE_US: [u8; 4] = [0xA1, 0xB2, 0xC3, 0xD4];
/// Same magic as stored by a little-endian system.
pub(crate) const MAGIC_LE_US: [u8; 4] = [0xD4, 0xC3, 0xB2, 0xA1];
/// 0xA1B23C4D — nanosecond-resolution variant.
pub(crate) const MAGIC_BE_NS: [u8; 4] = [0xA1, 0xB2, 0x3C, 0x4D];
pub(crate) const MAGIC_LE_NS: [u8; 4] = [0x4D, 0x3C, 0xB2, 0xA1];

#[derive(Debug)]
pub struct State {
    big_endian: bool,
    nanos: bool,
    link_type: LinkType,
}

impl State {
    fn u16(&self, cur: &mut Cursor<'_>) -> Result<u16, PcapError> {
        let v = if self.big_endian {
            cur.u16_be()
        } else {
            cur.u16_le()
        };
        v.map_err(|_| PcapError::TruncatedFile {
            context: "pcap header",
        })
    }

    fn u32(&self, cur: &mut Cursor<'_>) -> Result<u32, PcapError> {
        let v = if self.big_endian {
            cur.u32_be()
        } else {
            cur.u32_le()
        };
        v.map_err(|_| PcapError::TruncatedFile {
            context: "pcap header",
        })
    }

    /// Parse the remaining 20 bytes of the global header (magic consumed).
    pub(crate) fn read_header(reader: &mut impl Read, magic: [u8; 4]) -> Result<Self, PcapError> {
        let mut state = Self {
            big_endian: magic == MAGIC_BE_US || magic == MAGIC_BE_NS,
            nanos: magic == MAGIC_BE_NS || magic == MAGIC_LE_NS,
            link_type: LinkType::Other(0),
        };

        let mut rest = [0u8; 20];
        read_exact(reader, &mut rest, "pcap global header")?;
        let mut cur = Cursor::new(&rest);

        let major = state.u16(&mut cur)?;
        let minor = state.u16(&mut cur)?;
        if major != 2 {
            return Err(PcapError::BadVersion { major, minor });
        }
        state.u32(&mut cur)?; // thiszone (ignored; effectively always 0)
        state.u32(&mut cur)?; // sigfigs (ignored)
        state.u32(&mut cur)?; // snaplen (informational; we trust per-record lengths)
        let dlt = state.u32(&mut cur)?;
        state.link_type = LinkType::from_dlt(dlt);
        Ok(state)
    }

    pub(crate) fn next_record<'b>(
        &mut self,
        reader: &mut impl Read,
        buf: &'b mut Vec<u8>,
        offset: &mut u64,
    ) -> Result<Option<Record<'b>>, PcapError> {
        let mut header = [0u8; 16];
        if !read_exact_or_eof(reader, &mut header, "pcap record header")? {
            return Ok(None);
        }

        let mut cur = Cursor::new(&header);
        let ts_sec = self.u32(&mut cur)?;
        let ts_frac = self.u32(&mut cur)?;
        let incl_len_u32 = self.u32(&mut cur)?;
        let incl_len = incl_len_u32 as usize;
        // incl_len > orig_len is a writer lie: the captured bytes are real, so
        // the wire length is at least the captured length. Normalizing here is
        // what makes decode's truncation test (cap_len < orig_len) trustworthy.
        let orig_len = self.u32(&mut cur)?.max(incl_len_u32);

        if incl_len > MAX_RECORD_LEN {
            return Err(PcapError::BadLength {
                len: incl_len as u64,
                context: "pcap record",
                offset: *offset,
            });
        }

        // Keep the buffer at its high-water mark and fill a slice: resizing
        // down-then-up re-zeroes bytes that read_exact immediately overwrites
        // (a hidden ~1 KB memset per packet on alternating sizes).
        if buf.len() < incl_len {
            buf.resize(incl_len, 0);
        }
        let slot = buf.get_mut(..incl_len).unwrap_or_default();
        read_exact(reader, slot, "pcap record data")?;
        *offset = offset.saturating_add(16).saturating_add(incl_len as u64);

        // Lenient on out-of-range fractions: normalize rather than abort.
        // Deliberately uncounted — the value is recoverable noise, unlike a
        // malformed block, and the reader's only anomaly channel (skipped
        // blocks) would overstate it as data loss.
        let nanos = if self.nanos {
            ts_frac.checked_rem(1_000_000_000).unwrap_or(0)
        } else {
            ts_frac
                .checked_rem(1_000_000)
                .unwrap_or(0)
                .saturating_mul(1000)
        };

        Ok(Some(Record {
            ts: Timestamp::new(u64::from(ts_sec), nanos),
            orig_len,
            link_type: self.link_type,
            data: buf.get(..incl_len).unwrap_or(&[]),
        }))
    }
}
