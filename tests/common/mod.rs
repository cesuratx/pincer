//! pcapng block builders shared across the integration-test crates
//! (`hostile`, `never_panic`, `cli_binary`). Each test file compiles as its
//! own crate, so the shared code lives in this non-target subdirectory and is
//! pulled in with `mod common;`. Different crates use different subsets —
//! hence the file-level `dead_code` allow.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::net::Ipv4Addr;
use std::process::{Command, Output};

use pincer::types::MacAddr;

/// Minimal little-endian SHB (28 bytes, no options).
pub fn shb_le() -> Vec<u8> {
    let mut b = vec![0x0A, 0x0D, 0x0D, 0x0A];
    b.extend_from_slice(&28u32.to_le_bytes());
    b.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&(-1i64).to_le_bytes());
    b.extend_from_slice(&28u32.to_le_bytes());
    b
}

/// IDB: Ethernet, snaplen 0 ("no limit"), no options.
pub fn idb_le() -> Vec<u8> {
    let mut b = 1u32.to_le_bytes().to_vec();
    b.extend_from_slice(&20u32.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&20u32.to_le_bytes());
    b
}

/// EPB for interface `iface`, stamped at `ticks` µs since the epoch (the IDB
/// default resolution), carrying `data`.
pub fn epb_le(iface: u32, ticks: u64, data: &[u8]) -> Vec<u8> {
    let cap = u32::try_from(data.len()).unwrap();
    let padded = data.len().next_multiple_of(4);
    let total = u32::try_from(32 + padded).unwrap();
    let mut b = 6u32.to_le_bytes().to_vec();
    b.extend_from_slice(&total.to_le_bytes());
    b.extend_from_slice(&iface.to_le_bytes());
    b.extend_from_slice(&u32::try_from(ticks >> 32).unwrap().to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    b.extend_from_slice(&(ticks as u32).to_le_bytes());
    b.extend_from_slice(&cap.to_le_bytes());
    b.extend_from_slice(&cap.to_le_bytes());
    b.extend_from_slice(data);
    b.resize(b.len() + (padded - data.len()), 0);
    b.extend_from_slice(&total.to_le_bytes());
    b
}

/// SPB: original length, then data padded to 4 bytes — no timestamp field.
pub fn spb_le(data: &[u8]) -> Vec<u8> {
    let padded = data.len().next_multiple_of(4);
    let total = u32::try_from(16 + padded).unwrap();
    let mut b = 3u32.to_le_bytes().to_vec();
    b.extend_from_slice(&total.to_le_bytes());
    b.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
    b.extend_from_slice(data);
    b.resize(b.len() + (padded - data.len()), 0);
    b.extend_from_slice(&total.to_le_bytes());
    b
}

/// A decodable UDP frame so the analysis sinks actually fold the record.
pub fn udp_frame(src_port: u16) -> Vec<u8> {
    pincer::fixtures::Packet::ethernet(MacAddr([2, 0, 0, 0, 0, 1]), MacAddr([2, 0, 0, 0, 0, 2]))
        .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
        .udp(src_port, 53)
        .payload(b"x")
}

/// Write a capture to a temp file and run the real binary on it.
pub fn run_on(tag: &str, capture: &[u8], args: &[&str]) -> Output {
    let path = std::env::temp_dir().join(format!("pincer-{tag}-{}.pcapng", std::process::id()));
    std::fs::write(&path, capture).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_pincer"))
        .args(args)
        .arg(&path)
        .output()
        .expect("binary must run");
    std::fs::remove_file(&path).ok();
    out
}
