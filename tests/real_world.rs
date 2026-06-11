//! Real-capture sweep: every file in `testdata-real/` (not committed; rebuild
//! it with `scripts/fetch-real-captures.sh`) runs through the full pipeline,
//! and every Ethernet frame is additionally cross-checked against `etherparse`.
//!
//! This closes the gap that synthetic fixtures leave: real traffic carries
//! TSO artifacts, fragments, padding, retransmissions, and protocol dialects
//! our generator would never think to produce. The differential oracle is
//! only as good as the diversity of inputs fed to it — so feed it reality.
//!
//! Skips silently when the directory is absent (CI without downloads).
#![allow(
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::indexing_slicing
)]

use std::net::IpAddr;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pincer::analysis::{AssetInventory, FlowTable, Observe, Stats, dependency_edges};
use pincer::app::sniff;
use pincer::decode::{TransportView, decode_packet};
use pincer::pcap::{CaptureReader, LinkType};

fn real_captures() -> Vec<std::path::PathBuf> {
    let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata-real"));
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("pcap" | "cap" | "pcapng")
            )
        })
        .collect();
    files.sort();
    if files.is_empty() {
        // Make the skip visible in test output: a missing corpus must not
        // masquerade as a passing suite.
        eprintln!("real_world: no captures in testdata-real/ — suite is a no-op");
    }
    files
}

/// Run a capture's bytes through the whole pipeline; used by the mutation
/// fuzz, where we only care that nothing panics, hangs, or balloons.
fn drain_pipeline(bytes: &[u8]) {
    let Ok(mut reader) = CaptureReader::new(bytes) else {
        return;
    };
    let mut stats = Stats::new();
    let mut flows = FlowTable::new();
    let mut assets = AssetInventory::new();
    let mut guard = 0u64;
    while let Ok(Some(record)) = reader.next_record() {
        guard += 1;
        assert!(guard < 50_000_000, "reader failed to terminate");
        if let Ok(pkt) = decode_packet(&record) {
            let app = sniff(&pkt);
            stats.observe(&pkt, app.as_ref());
            flows.observe(&pkt, app.as_ref());
            assets.observe(&pkt, app.as_ref());
        }
    }
    assets.finalize();
    let _ = dependency_edges(&flows, &assets);
}

/// Every real capture, mutated at structural offsets (truncations + byte
/// flips), must drive the full pipeline without panicking — the never-panic
/// guarantee proven on bytes we did not craft. Deterministic (no RNG) so a
/// failure is reproducible. Complements the coverage-guided cargo-fuzz
/// targets in `fuzz/`, which run ad hoc on nightly.
#[test]
fn real_captures_survive_mutation() {
    for path in real_captures() {
        let data = std::fs::read(&path).unwrap();
        if data.len() < 32 {
            continue;
        }
        // Truncations at several fractions — exercises mid-record EOF on real
        // record boundaries.
        for frac in [1usize, 4, 16, 64, 256, 1024] {
            let cut = (data.len() / frac).max(4).min(data.len());
            drain_pipeline(&data[..cut]);
        }
        // Byte flips spread across the file (clones, so skip huge captures —
        // truncations above already exercise their record boundaries).
        if data.len() <= 8 * 1024 * 1024 {
            for step in [7usize, 101, 1009, 50_021] {
                let mut m = data.clone();
                let mut i = 24; // skip the global header so the format still sniffs
                while i < m.len() {
                    m[i] ^= 0x80;
                    i = i.saturating_add(step);
                }
                drain_pipeline(&m);
            }
        }
    }
}

#[test]
fn real_captures_run_the_full_pipeline_cleanly() {
    for path in real_captures() {
        let file = std::fs::File::open(&path).unwrap();
        let mut reader = CaptureReader::new(std::io::BufReader::new(file))
            .unwrap_or_else(|e| panic!("{}: unreadable header: {e}", path.display()));

        let mut stats = Stats::new();
        let mut flows = FlowTable::new();
        let mut assets = AssetInventory::new();
        let mut packets = 0u64;
        let mut decoded = 0u64;

        loop {
            match reader.next_record() {
                Ok(Some(record)) => {
                    packets += 1;
                    if let Ok(pkt) = decode_packet(&record) {
                        decoded += 1;
                        let app = sniff(&pkt);
                        stats.observe(&pkt, app.as_ref());
                        flows.observe(&pkt, app.as_ref());
                        assets.observe(&pkt, app.as_ref());
                    }
                }
                // Clean EOF — or, same tolerance as the CLI, a damaged tail:
                // partial analysis, not an erased one.
                Ok(None)
                | Err(
                    pincer::error::PcapError::TruncatedFile { .. }
                    | pincer::error::PcapError::BadLength { .. },
                ) => break,
                Err(e) => panic!("{}: container error mid-stream: {e}", path.display()),
            }
        }

        assert!(packets > 0, "{}: no packets read", path.display());
        // Every decoded packet must be observed; undecodable records (exotic
        // link types) are legitimate in real captures and excluded.
        assert!(
            stats.packets == decoded,
            "{}: stats missed packets",
            path.display()
        );
        let _ = dependency_edges(&flows, &assets);
        println!(
            "{}: {} packets, {} flows, {} assets — ok",
            path.display(),
            packets,
            flows.len(),
            assets.len()
        );
    }
}

/// Differential vs etherparse over every real Ethernet frame: when both
/// parsers produce an IPv4/IPv6 + TCP/UDP view, the 5-tuple must agree.
#[test]
fn real_frames_agree_with_etherparse() {
    let mut compared = 0u64;
    for path in real_captures() {
        let file = std::fs::File::open(&path).unwrap();
        let mut reader = CaptureReader::new(std::io::BufReader::new(file)).unwrap();

        while let Ok(Some(record)) = reader.next_record() {
            if record.link_type != LinkType::Ethernet {
                continue; // etherparse's from_ethernet applies to Ethernet only
            }
            let Ok(ours) = decode_packet(&record) else {
                continue;
            };
            let Ok(theirs) = SlicedPacket::from_ethernet(record.data) else {
                continue; // strict-mode etherparse rejects (e.g. TSO frames); ours is lenient
            };

            let our_ips: Option<(IpAddr, IpAddr)> = ours.ip_pair();
            let their_ips: Option<(IpAddr, IpAddr)> = match &theirs.net {
                Some(NetSlice::Ipv4(v4)) => Some((
                    IpAddr::from(v4.header().source_addr()),
                    IpAddr::from(v4.header().destination_addr()),
                )),
                Some(NetSlice::Ipv6(v6)) => Some((
                    IpAddr::from(v6.header().source_addr()),
                    IpAddr::from(v6.header().destination_addr()),
                )),
                _ => None,
            };
            if let (Some(ours_ip), Some(theirs_ip)) = (our_ips, their_ips) {
                assert_eq!(ours_ip, theirs_ip, "{}: IP mismatch", path.display());
            }

            let our_ports = match &ours.transport {
                Some(TransportView::Tcp(t)) => Some((t.src_port, t.dst_port)),
                Some(TransportView::Udp(u)) => Some((u.src_port, u.dst_port)),
                _ => None,
            };
            let their_ports = match &theirs.transport {
                Some(TransportSlice::Tcp(t)) => Some((t.source_port(), t.destination_port())),
                Some(TransportSlice::Udp(u)) => Some((u.source_port(), u.destination_port())),
                _ => None,
            };
            if let (Some(ours_p), Some(theirs_p)) = (our_ports, their_ports) {
                assert_eq!(ours_p, theirs_p, "{}: port mismatch", path.display());
                compared += 1;
            }
        }
    }
    println!("differential against etherparse: {compared} real frames compared");
}
