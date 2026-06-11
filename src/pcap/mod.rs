//! Capture-file container readers and a legacy writer.
//!
//! [`CaptureReader`] auto-detects legacy pcap (all four magic variants:
//! two endiannesses × µs/ns resolution) and pcapng (SHB/IDB/EPB/SPB).
//! It is a *lending* reader: each [`Record`] borrows the reader's single
//! reusable buffer, so memory stays constant no matter the file size — a true
//! `Iterator` can't express that borrow, which is why `next_record(&mut self)`
//! exists instead.
#![deny(clippy::arithmetic_side_effects)]

pub mod legacy;
pub mod pcapng;
pub mod writer;

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::error::PcapError;
use crate::types::Timestamp;

/// Largest packet record we accept (64 MiB) — anything bigger is a corrupt or
/// hostile length field, not a packet.
pub(crate) const MAX_RECORD_LEN: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// `DLT_EN10MB` — classic Ethernet.
    Ethernet,
    /// `LINKTYPE_LINUX_SLL` (113) — `tcpdump -i any` on older libpcap.
    LinuxSll,
    /// `LINKTYPE_LINUX_SLL2` (276) — `tcpdump -i any` since tcpdump 4.99.
    LinuxSll2,
    /// `LINKTYPE_RAW` (101) and `LINKTYPE_IPV4`/`IPV6` (228/229) — bare IP
    /// datagrams (VPN/tun interfaces, some test tooling).
    Raw,
    /// `LINKTYPE_NULL` (0) / `LINKTYPE_LOOP` (108) — BSD/macOS loopback:
    /// 4-byte address family, then bare IP.
    NullLoop,
    Other(u32),
}

impl LinkType {
    pub(crate) const fn from_dlt(dlt: u32) -> Self {
        match dlt {
            0 | 108 => Self::NullLoop,
            1 => Self::Ethernet,
            101 | 228 | 229 => Self::Raw,
            113 => Self::LinuxSll,
            276 => Self::LinuxSll2,
            other => Self::Other(other),
        }
    }
}

/// One captured packet, borrowing the reader's buffer.
#[derive(Debug)]
pub struct Record<'a> {
    pub ts: Timestamp,
    /// Original length on the wire; `data.len()` may be smaller (snaplen).
    pub orig_len: u32,
    pub link_type: LinkType,
    pub data: &'a [u8],
}

#[derive(Debug)]
enum Format {
    Legacy(legacy::State),
    Ng(pcapng::State),
}

#[derive(Debug)]
pub struct CaptureReader<R> {
    reader: R,
    format: Format,
    /// Single reusable packet buffer — the constant-memory guarantee.
    buf: Vec<u8>,
    /// Byte offset into the file, for error reporting.
    offset: u64,
    /// Well-framed packet blocks skipped because their body was malformed
    /// (pcapng only). Surfaced so damaged input is never silently dropped.
    skipped_blocks: u64,
}

impl<R: Read> CaptureReader<R> {
    /// Sniffs the magic number and parses the file header / section header.
    pub fn new(mut reader: R) -> Result<Self, PcapError> {
        let mut magic = [0u8; 4];
        reader
            .read_exact(&mut magic)
            .map_err(|err| match err.kind() {
                // Only a genuinely short file is "truncated"; a permission or
                // device error must say what it actually was.
                std::io::ErrorKind::UnexpectedEof => PcapError::TruncatedFile {
                    context: "file magic",
                },
                _ => PcapError::Io(err),
            })?;

        let (format, header_len) = match magic {
            legacy::MAGIC_BE_US
            | legacy::MAGIC_LE_US
            | legacy::MAGIC_BE_NS
            | legacy::MAGIC_LE_NS => (
                Format::Legacy(legacy::State::read_header(&mut reader, magic)?),
                24, // 4 magic + 20 global header
            ),
            pcapng::BLOCK_SHB_BYTES => {
                let (state, shb_len) = pcapng::State::read_section_header(&mut reader)?;
                (Format::Ng(state), shb_len)
            }
            other => return Err(PcapError::BadMagic(other)),
        };

        Ok(Self {
            reader,
            format,
            buf: Vec::new(),
            // Exact bytes consumed so far, so error offsets are accurate for
            // both formats (a pcapng SHB is 28+ bytes, not 24).
            offset: header_len,
            skipped_blocks: 0,
        })
    }

    /// Packet blocks whose framing was valid but whose body was malformed;
    /// each was skipped (counted, never aborting the stream).
    #[must_use]
    pub fn skipped_blocks(&self) -> u64 {
        self.skipped_blocks
    }

    /// Next packet, or `Ok(None)` at clean end-of-file.
    pub fn next_record(&mut self) -> Result<Option<Record<'_>>, PcapError> {
        match &mut self.format {
            Format::Legacy(state) => {
                state.next_record(&mut self.reader, &mut self.buf, &mut self.offset)
            }
            Format::Ng(state) => state.next_record(
                &mut self.reader,
                &mut self.buf,
                &mut self.offset,
                &mut self.skipped_blocks,
            ),
        }
    }
}

/// Open a capture file with buffered I/O.
pub fn open(path: &Path) -> Result<CaptureReader<BufReader<File>>, PcapError> {
    let file = File::open(path)?;
    // 64 KiB: fewer syscalls than the 8 KiB default on multi-GB captures.
    CaptureReader::new(BufReader::with_capacity(64 * 1024, file))
}

/// Open a capture from a path, or from **stdin** when the path is `-`.
///
/// Streaming from stdin means a capture never needs local disk space:
/// `ssh host 'cat big.pcap' | pincer flows -`, `gzcat big.pcap.gz | pincer
/// deps -`. Memory stays constant either way — the reader never holds more
/// than one packet.
pub fn open_input(path: &Path) -> Result<CaptureReader<Box<dyn Read>>, PcapError> {
    if path == Path::new("-") {
        CaptureReader::new(Box::new(std::io::stdin().lock()))
    } else {
        let file = File::open(path)?;
        CaptureReader::new(Box::new(BufReader::with_capacity(64 * 1024, file)))
    }
}

/// Read exactly `buf.len()` bytes, or report which structure was cut short.
pub(crate) fn read_exact(
    reader: &mut impl Read,
    buf: &mut [u8],
    context: &'static str,
) -> Result<(), PcapError> {
    reader.read_exact(buf).map_err(|err| match err.kind() {
        std::io::ErrorKind::UnexpectedEof => PcapError::TruncatedFile { context },
        _ => PcapError::Io(err),
    })
}

/// Like [`read_exact`] but a clean EOF *before any byte* returns `Ok(false)` —
/// used at record boundaries, where end-of-file is the normal way out.
pub(crate) fn read_exact_or_eof(
    reader: &mut impl Read,
    buf: &mut [u8],
    context: &'static str,
) -> Result<bool, PcapError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let slice = buf.get_mut(filled..).unwrap_or(&mut []);
        match reader.read(slice) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(PcapError::TruncatedFile { context });
            }
            Ok(n) => filled = filled.saturating_add(n),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(PcapError::Io(err)),
        }
    }
    Ok(true)
}
