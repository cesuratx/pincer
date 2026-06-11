//! Error tiers with distinct semantics:
//!
//! - [`PcapError`]: the capture file container is unreadable — ends the stream.
//! - [`DecodeError`]: one packet's bytes are truncated or lie about their
//!   structure — recorded as an anomaly counter, never aborts the analysis.
//! - "Not this protocol" is **not** an error: best-effort application sniffers
//!   return `Option` instead.

use std::path::PathBuf;

use thiserror::Error;

/// Container-level failure: the pcap/pcapng file itself cannot be read.
#[derive(Debug, Error)]
pub enum PcapError {
    #[error("not a pcap or pcapng file (first bytes {0:02x?})")]
    BadMagic([u8; 4]),

    #[error("unsupported pcap version {major}.{minor}")]
    BadVersion { major: u16, minor: u16 },

    #[error("file ends inside {context}")]
    TruncatedFile { context: &'static str },

    #[error("implausible length {len} in {context} at byte offset {offset}")]
    BadLength {
        len: u64,
        context: &'static str,
        offset: u64,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Packet-level failure: this packet's bytes ran out or contradict themselves.
///
/// `Truncated` is expected in real captures (snaplen); `Malformed` means the
/// bytes claim a structure they do not have. Neither aborts the stream.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    #[error("truncated: needed {needed} bytes, had {have}")]
    Truncated { needed: usize, have: usize },

    #[error("malformed {layer}: {reason}")]
    Malformed {
        layer: &'static str,
        reason: &'static str,
    },
}

impl DecodeError {
    pub(crate) const fn truncated(needed: usize, have: usize) -> Self {
        Self::Truncated { needed, have }
    }

    pub(crate) const fn malformed(layer: &'static str, reason: &'static str) -> Self {
        Self::Malformed { layer, reason }
    }
}

/// Top-level error for the CLI.
#[derive(Debug, Error)]
pub enum Error {
    #[error("{}: {source}", path.display())]
    Capture {
        path: PathBuf,
        #[source]
        source: PcapError,
    },

    /// A filesystem error with the path that caused it (e.g. `gen` output).
    #[error("{}: {source}", path.display())]
    Output {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("failed to serialize report: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    /// Attach a path to a bare I/O error for a user-facing message.
    #[must_use]
    pub fn output(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Output {
            path: path.into(),
            source,
        }
    }
}
