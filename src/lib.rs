//! pincer — hand-rolled pcap analyzer: communication flows, asset inventory,
//! and dependency maps from network captures. No libpcap, no parsing crates;
//! every byte is read through the bounds-checked [`bytes::Cursor`].
#![forbid(unsafe_code)]

pub mod analysis;
pub mod app;
pub mod bytes;
pub mod cli;
pub mod decode;
pub mod error;
pub mod fixtures;
pub mod output;
pub mod pcap;
pub mod types;

pub use error::{DecodeError, Error, PcapError};

/// CLI entry point. `Ok` carries the exit status: success, or
/// [`cli::EXIT_DEGRADED`] when `--strict` is set and the analysis degraded.
pub fn run() -> Result<std::process::ExitCode, Error> {
    cli::run()
}
