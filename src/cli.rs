//! Command-line surface and the single-pass analysis pipeline.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use crate::analysis::{AssetInventory, FlowTable, Limits, Observe, Stats, dependency_edges};
use crate::app::{SniffDepth, sniff_with};
use crate::decode::decode_packet;
use crate::error::{Error, PcapError};
use crate::output::{Degradation, DhcpRecord, DnsRecord, Report, deps_dot};
use crate::pcap;

#[derive(Debug, Parser)]
#[command(
    name = "pincer",
    version,
    about = "Hand-rolled pcap analyzer: flows, assets, and dependency maps",
    long_about = "pincer reads pcap/pcapng captures and surfaces passive-discovery \
                  signal: communication flows, an asset inventory, and an application \
                  dependency map. No libpcap, no parsing crates — every byte is parsed \
                  in-house.\n\nLimitations (by design): no IP reassembly and no TCP \
                  stream reassembly, so HTTP/TLS detection works on the first data \
                  segment of a connection."
)]
pub struct Cli {
    /// Exit 3 instead of 0 when the analysis is degraded (truncated tail,
    /// damaged section, undecodable records, any cap hit) — for pipelines
    /// that must branch on partial results. The output is still emitted in
    /// full either way.
    #[arg(long, global = true)]
    pub strict: bool,
    #[command(subcommand)]
    pub command: Command,
}

/// Exit code under `--strict` for a degraded analysis. Distinct from 1
/// (error: nothing useful emitted) and 2 (usage): the report WAS emitted, in
/// full, but covers a damaged or capped input.
pub const EXIT_DEGRADED: u8 = 3;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Packet/byte totals, protocol breakdown, and parse anomalies.
    Summary(Common),
    /// Bidirectional flows, sorted by bytes.
    Flows(Common),
    /// Discovered hosts with identity evidence.
    Assets(Common),
    /// Services inferred per host, with the evidence for each.
    Services(Common),
    /// Application dependency map (client → server:port).
    Deps(DepsArgs),
    /// DNS / mDNS queries and answers.
    Dns(Common),
    /// DHCP messages, hostnames, and device fingerprints.
    Dhcp(Common),
    /// Generate the built-in sample captures into a directory.
    ///
    /// Each capture is written to a `<name>.pcap.tmp` file in the destination
    /// directory, fsynced, then atomically renamed into place — the final
    /// filename only ever holds a complete capture. An existing regular file
    /// at the destination is replaced; anything else there (symlink,
    /// directory, device) is refused.
    Gen(GenArgs),
}

#[derive(Debug, clap::Args)]
pub struct Common {
    /// Capture file to analyze (pcap or pcapng), or `-` to stream from stdin
    /// (e.g. `gzcat big.pcap.gz | pincer <cmd> -`).
    pub file: PathBuf,
    /// Emit JSON instead of a table.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct DepsArgs {
    #[command(flatten)]
    pub common: Common,
    /// Emit Graphviz DOT instead of a table (ignored with --json).
    #[arg(long)]
    pub dot: bool,
}

#[derive(Debug, clap::Args)]
pub struct GenArgs {
    /// Directory to write sample captures into.
    #[arg(default_value = "testdata")]
    pub out_dir: PathBuf,
    /// Which scenario(s) to write.
    #[arg(long, value_enum, default_value_t = Scenario::All)]
    pub scenario: Scenario,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Scenario {
    Office,
    Incident,
    All,
}

/// Parse args and dispatch. `Ok` carries the exit status (0, or
/// [`EXIT_DEGRADED`] under `--strict`); errors map to 1 via [`Error`].
pub fn run() -> Result<ExitCode, Error> {
    let cli = Cli::parse();
    match cli.command {
        Command::Gen(args) => run_gen(&args).map(|()| ExitCode::SUCCESS),
        Command::Summary(common) => run_analysis(&common, Which::Summary, cli.strict),
        Command::Flows(common) => run_analysis(&common, Which::Flows, cli.strict),
        Command::Assets(common) => run_analysis(&common, Which::Assets, cli.strict),
        Command::Services(common) => run_analysis(&common, Which::Services, cli.strict),
        Command::Dns(common) => run_analysis(&common, Which::Dns, cli.strict),
        Command::Dhcp(common) => run_analysis(&common, Which::Dhcp, cli.strict),
        Command::Deps(args) => run_deps(&args, cli.strict),
    }
}

/// Exit status for a finished, fully emitted analysis.
fn exit_status(strict: bool, degradation: &Degradation) -> ExitCode {
    if strict && degradation.any() {
        ExitCode::from(EXIT_DEGRADED)
    } else {
        ExitCode::SUCCESS
    }
}

#[derive(Debug, Clone, Copy)]
enum Which {
    Summary,
    Flows,
    Assets,
    Services,
    Dns,
    Dhcp,
}

/// Which sinks a subcommand needs. Gating this keeps each command from paying
/// for analyses it will not render — `summary` does not build an asset
/// inventory, and only `dns`/`dhcp` accumulate per-record vectors (the only
/// state that grows with packet count rather than with flows/assets).
// A named flag per sink reads far clearer at the call sites than a bitset.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default)]
struct Needs {
    stats: bool,
    flows: bool,
    assets: bool,
    dns: bool,
    dhcp: bool,
}

impl Which {
    fn needs(self) -> Needs {
        match self {
            Self::Summary => Needs {
                stats: true,
                ..Needs::default()
            },
            // Flows label servers via app evidence carried on the flow itself,
            // so the asset inventory is not required here.
            Self::Flows => Needs {
                flows: true,
                ..Needs::default()
            },
            // Assets/services need L2/L3 + app evidence; deps additionally
            // needs flows (added in `run_deps`).
            Self::Assets | Self::Services => Needs {
                assets: true,
                ..Needs::default()
            },
            Self::Dns => Needs {
                dns: true,
                ..Needs::default()
            },
            Self::Dhcp => Needs {
                dhcp: true,
                ..Needs::default()
            },
        }
    }
}

/// Everything a single streaming pass can collect — only the sinks named in
/// `Needs` are actually run. The capture is traversed exactly once.
#[derive(Default)]
struct Pass {
    stats: Stats,
    flows: FlowTable,
    assets: AssetInventory,
    dns: Vec<DnsRecord>,
    dhcp: Vec<DhcpRecord>,
    /// Records the link layer could not decode at all (any subcommand, not
    /// just `summary`).
    undecodable: u64,
    /// The capture ended on a record cut short mid-file.
    truncated_tail: bool,
    /// A later section header (concatenated pcapng) was unreadable; the
    /// analysis covers only the sections before it.
    damaged_section: bool,
    /// Well-framed pcapng packet blocks with malformed bodies, skipped by
    /// the reader.
    skipped_blocks: u64,
    /// Records delivered without a timestamp (pcapng Simple Packet Blocks);
    /// excluded from every first/last time and duration.
    timestampless_records: u64,
    /// dns/dhcp detail rows dropped once their per-run cap was hit.
    dns_dropped: u64,
    dhcp_dropped: u64,
}

impl Pass {
    fn run(file: &std::path::Path, needs: Needs, limits: Limits) -> Result<Self, Error> {
        let mut reader = pcap::open_input(file).map_err(|source| Error::Capture {
            path: file.to_path_buf(),
            source,
        })?;

        let mut pass = Self {
            flows: FlowTable::with_limits(limits),
            assets: AssetInventory::with_limits(limits),
            ..Self::default()
        };

        // Sniffing itself is unconditional — every subcommand consumes app
        // events (stats/flows label with them; assets/dns/dhcp are built from
        // them) — but the *depth* is not: label-only consumers get the
        // validation-only DNS/DHCP mode, which accepts and rejects the exact
        // same payloads while skipping the per-record allocations.
        let depth = SniffDepth {
            dns_detail: needs.assets || needs.dns,
            dhcp_detail: needs.assets || needs.dhcp,
        };

        loop {
            let record = match reader.next_record() {
                Ok(Some(record)) => record,
                Ok(None) => break,
                // Mid-stream damage — a record cut short (snaplen/truncated
                // file) or framing whose lengths no longer add up: stop and
                // report what we have, flagged, instead of discarding every
                // packet already analyzed. A sensor that throws away an
                // hour of evidence over a bad tail is worse than one that
                // says "partial".
                Err(PcapError::TruncatedFile { .. } | PcapError::BadLength { .. }) => {
                    pass.truncated_tail = true;
                    break;
                }
                // A later SHB with a corrupt byte-order magic or an unknown
                // major version. `next_record` can only surface these from a
                // *second or later* section header — the initial one was
                // validated by `open_input` above — so this is the same
                // mid-stream damage shape: everything before the bad section
                // parsed clean and is kept.
                Err(PcapError::BadMagic(_) | PcapError::BadVersion { .. }) => {
                    pass.damaged_section = true;
                    break;
                }
                Err(source) => {
                    return Err(Error::Capture {
                        path: file.to_path_buf(),
                        source,
                    });
                }
            };

            let Ok(pkt) = decode_packet(&record) else {
                pass.undecodable = pass.undecodable.saturating_add(1);
                if needs.stats {
                    pass.stats.note_undecodable();
                }
                continue;
            };
            let app = sniff_with(&pkt, depth);
            let app_ref = app.as_ref();

            if needs.stats {
                pass.stats.observe(&pkt, app_ref);
            }
            if needs.flows {
                pass.flows.observe(&pkt, app_ref);
            }
            if needs.assets {
                pass.assets.observe(&pkt, app_ref);
            }
            if let Some(event) = app_ref {
                // One event can append many records; trim back to the cap so
                // it is exact, not "cap plus up to one event's worth". Past
                // the cap, count the records the event *would* have appended
                // (`count_from`, allocation-free) — the dropped counter is in
                // record units throughout, never "one per event".
                if needs.dns {
                    if pass.dns.len() < limits.max_dns_records {
                        DnsRecord::push_from(event, &mut pass.dns);
                        let over = pass.dns.len().saturating_sub(limits.max_dns_records);
                        if over > 0 {
                            pass.dns.truncate(limits.max_dns_records);
                            pass.dns_dropped = pass.dns_dropped.saturating_add(over as u64);
                        }
                    } else {
                        pass.dns_dropped = pass
                            .dns_dropped
                            .saturating_add(DnsRecord::count_from(event) as u64);
                    }
                }
                if needs.dhcp {
                    if pass.dhcp.len() < limits.max_dhcp_records {
                        DhcpRecord::push_from(event, &mut pass.dhcp);
                        let over = pass.dhcp.len().saturating_sub(limits.max_dhcp_records);
                        if over > 0 {
                            pass.dhcp.truncate(limits.max_dhcp_records);
                            pass.dhcp_dropped = pass.dhcp_dropped.saturating_add(over as u64);
                        }
                    } else {
                        pass.dhcp_dropped = pass
                            .dhcp_dropped
                            .saturating_add(DhcpRecord::count_from(event) as u64);
                    }
                }
            }
        }

        pass.skipped_blocks = reader.skipped_blocks();
        pass.timestampless_records = reader.timestampless_records();
        if needs.stats {
            pass.stats.note_skipped_blocks(pass.skipped_blocks);
            pass.stats.note_timestampless(pass.timestampless_records);
        }

        // Resolve provisional bindings so asset keying is order-independent.
        if needs.assets {
            pass.assets.finalize();
        }
        pass.warn_degradation(file);
        Ok(pass)
    }

    /// Tell the user — on stderr, best-effort, never panicking — when the
    /// analysis was degraded by damaged input or a hostile-flood cap. Silent
    /// degradation is the failure mode a NASA-grade tool must not have.
    fn warn_degradation(&self, file: &std::path::Path) {
        let warn = |msg: String| {
            let _ = writeln!(
                std::io::stderr(),
                "pincer: warning: {}: {msg}",
                file.display()
            );
        };
        if self.truncated_tail {
            warn("capture ends in a truncated record; reporting packets read so far".into());
        }
        if self.damaged_section {
            warn("a mid-stream section header is corrupt; reporting packets read before it".into());
        }
        if self.undecodable > 0 {
            warn(format!(
                "{} record(s) had an undecodable link layer and were excluded",
                self.undecodable
            ));
        }
        if self.skipped_blocks > 0 {
            warn(format!(
                "{} malformed packet block(s) were skipped",
                self.skipped_blocks
            ));
        }
        if self.timestampless_records > 0 {
            warn(format!(
                "{} record(s) carry no timestamp (pcapng Simple Packet Block); \
                 time spans and durations exclude them",
                self.timestampless_records
            ));
        }
        if self.flows.dropped() > 0 {
            warn(format!(
                "flow table hit its cap; {} packet(s) of untracked flows dropped \
                 (results are partial)",
                self.flows.dropped()
            ));
        }
        let of = self.assets.overflow();
        if of.any() {
            warn(format!(
                "asset caps reached (dropped: {} assets, {} bindings, {} subnets, \
                 {} hostnames, {} services, {} ips)",
                of.assets, of.bindings, of.subnets, of.hostnames, of.services, of.ips
            ));
        }
        if self.dns_dropped > 0 || self.dhcp_dropped > 0 {
            warn(format!(
                "detail-record caps reached (dropped {} dns, {} dhcp records)",
                self.dns_dropped, self.dhcp_dropped
            ));
        }
        if of.rebound_ips > 0 {
            warn(format!(
                "{} IP(s) changed MAC binding during the capture (DHCP churn, \
                 failover, or spoofing); flows for those IPs are attributed to \
                 the final binding",
                of.rebound_ips
            ));
        }
    }

    /// The same facts as [`Pass::warn_degradation`], but for the JSON
    /// envelope — machine consumers must not have to scrape stderr.
    fn degradation(&self) -> Degradation {
        let of = self.assets.overflow();
        Degradation {
            truncated_tail: self.truncated_tail,
            damaged_section: self.damaged_section,
            undecodable_records: self.undecodable,
            skipped_blocks: self.skipped_blocks,
            flows_dropped: self.flows.dropped(),
            assets_dropped: of.assets,
            bindings_dropped: of.bindings,
            subnets_dropped: of.subnets,
            hostnames_dropped: of.hostnames,
            services_dropped: of.services,
            ips_dropped: of.ips,
            dns_records_dropped: self.dns_dropped,
            dhcp_records_dropped: self.dhcp_dropped,
            ips_rebound: of.rebound_ips,
            timestampless_records: self.timestampless_records,
        }
    }
}

fn run_analysis(common: &Common, which: Which, strict: bool) -> Result<ExitCode, Error> {
    let pass = Pass::run(&common.file, which.needs(), Limits::default())?;
    let assets = pass.assets.assets();
    let report = match which {
        Which::Summary => Report::Summary(&pass.stats),
        Which::Flows => Report::Flows(&pass.flows),
        Which::Assets => Report::Assets(&assets),
        Which::Services => Report::Services(&assets),
        Which::Dns => Report::Dns(&pass.dns),
        Which::Dhcp => Report::Dhcp(&pass.dhcp),
    };
    let degradation = pass.degradation();
    emit(&report, common.json, &degradation)?;
    Ok(exit_status(strict, &degradation))
}

fn run_deps(args: &DepsArgs, strict: bool) -> Result<ExitCode, Error> {
    // Dependencies need both the flow table and the asset inventory.
    let needs = Needs {
        flows: true,
        assets: true,
        ..Needs::default()
    };
    let pass = Pass::run(&args.common.file, needs, Limits::default())?;
    let edges = dependency_edges(&pass.flows, &pass.assets);
    let degradation = pass.degradation();
    if args.dot && !args.common.json {
        write_stdout(&deps_dot(&edges, &degradation))?;
    } else {
        emit(&Report::Deps(&edges), args.common.json, &degradation)?;
    }
    Ok(exit_status(strict, &degradation))
}

fn emit(report: &Report<'_>, json: bool, degradation: &Degradation) -> Result<(), Error> {
    let stdout = std::io::stdout();
    // BufWriter: the JSON serializer streams field by field, and stdout's
    // LineWriter would otherwise flush at every newline of pretty output.
    let mut lock = std::io::BufWriter::new(stdout.lock());
    if json {
        // serde_json wraps writer failures in its own error type; unwrap
        // them back to `Error::Io` so a consumer closing the pipe early
        // (`| head`) stays the quiet exit-0 path in `main`.
        report
            .write_json(degradation, &mut lock)
            .map_err(|err| match err.io_error_kind() {
                Some(kind) => Error::Io(std::io::Error::new(kind, err)),
                None => Error::Json(err),
            })?;
        lock.write_all(b"\n")?;
    } else {
        lock.write_all(report.to_table(degradation).as_bytes())?;
    }
    lock.flush()?;
    Ok(())
}

fn run_gen(args: &GenArgs) -> Result<(), Error> {
    use crate::fixtures::scenarios;

    std::fs::create_dir_all(&args.out_dir).map_err(|e| Error::output(&args.out_dir, e))?;
    let mut wrote = Vec::new();

    let mut write_one =
        |name: &str, frames: &[(crate::types::Timestamp, Vec<u8>)]| -> Result<(), Error> {
            let path = args.out_dir.join(name);
            // The destination names are predictable, so a planted symlink (or
            // directory/device) must be refused, never written through. Only
            // a regular file may be replaced; `symlink_metadata` does not
            // follow links, and the rename below replaces the name itself
            // rather than its target.
            if let Ok(meta) = std::fs::symlink_metadata(&path)
                && !meta.is_file()
            {
                return Err(Error::output(
                    &path,
                    std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "destination exists and is not a regular file; refusing to overwrite",
                    ),
                ));
            }
            // Temp-then-rename within the same directory (atomic on POSIX;
            // on Windows the `rename` result is the arbiter): the final name
            // only ever holds a complete, fsynced capture, and a failed or
            // interrupted run cannot destroy the previous good file.
            // `create_new` (O_EXCL) refuses to follow a symlink planted at
            // the temp name.
            let tmp = args.out_dir.join(format!("{name}.tmp"));
            let _ = std::fs::remove_file(&tmp); // stale debris from a crashed run
            let result = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .and_then(|file| {
                    scenarios::write_pcap(frames, std::io::BufWriter::new(&file))?;
                    file.sync_all()?;
                    std::fs::rename(&tmp, &path)
                });
            if let Err(e) = result {
                let _ = std::fs::remove_file(&tmp);
                return Err(Error::output(&path, e));
            }
            wrote.push(path.display().to_string());
            Ok(())
        };

    if matches!(args.scenario, Scenario::Office | Scenario::All) {
        write_one("office.pcap", &scenarios::office())?;
    }
    if matches!(args.scenario, Scenario::Incident | Scenario::All) {
        write_one("incident.pcap", &scenarios::incident())?;
    }

    write_stdout(&format!("wrote {}\n", wrote.join(", ")))
}

/// All stdout goes through a fallible write: `print!`-family macros panic on
/// write failure (e.g. `| head` closing the pipe), which would defeat the
/// crate's no-panic guarantee at the very last step. The `BrokenPipe` case is
/// then handled quietly in `main`.
fn write_stdout(text: &str) -> Result<(), Error> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(text.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::net::Ipv4Addr;

    use super::*;
    use crate::fixtures::{self, Packet};
    use crate::types::{MacAddr, Timestamp};

    /// mDNS response carrying `count` A answers and no questions — one packet
    /// appending many records, so the cap can be crossed mid-event.
    fn mdns_multi_answer(count: u8) -> Vec<u8> {
        let mut msg = vec![0, 0, 0x84, 0x00, 0, 0]; // id 0, QR+AA, qd 0
        msg.extend_from_slice(&u16::from(count).to_be_bytes()); // an
        msg.extend_from_slice(&[0, 0, 0, 0]); // ns, ar
        for i in 0..count {
            msg.extend_from_slice(&fixtures::dns_name(&format!("host-{i}.local")));
            msg.extend_from_slice(&[0, 1, 0x80, 1]); // A, cache-flush + IN
            msg.extend_from_slice(&120u32.to_be_bytes());
            msg.extend_from_slice(&[0, 4]);
            msg.extend_from_slice(&[192, 168, 1, i]);
        }
        msg
    }

    fn write_capture(tag: &str, frames: &[(Timestamp, Vec<u8>)]) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("pincer-cli-{tag}-{}.pcap", std::process::id()));
        let file = std::fs::File::create(&path).expect("temp capture");
        fixtures::scenarios::write_pcap(frames, file).expect("write capture");
        path
    }

    /// A flood of multi-answer mDNS responses against `Limits::tiny`
    /// (`max_dns_records = 8`): the event that crosses the cap is trimmed
    /// back so kept == cap exactly, and the dropped counter is record-exact —
    /// including the records of events arriving wholly past the cap.
    #[test]
    fn dns_record_cap_trims_mid_event_and_counts_every_drop() {
        let host = MacAddr([0xD0, 0x81, 0x7A, 1, 2, 3]);
        let frames: Vec<(Timestamp, Vec<u8>)> = (0..4)
            .map(|_| {
                let frame = Packet::ethernet(host, MacAddr([0x01, 0, 0x5E, 0, 0, 0xFB]))
                    .ipv4(
                        Ipv4Addr::new(192, 168, 1, 77),
                        Ipv4Addr::new(224, 0, 0, 251),
                    )
                    .udp(5353, 5353)
                    .payload(&mdns_multi_answer(3));
                (Timestamp::ZERO, frame)
            })
            .collect();
        let path = write_capture("dns-cap", &frames);
        let needs = Needs {
            dns: true,
            ..Needs::default()
        };
        let pass = Pass::run(&path, needs, Limits::tiny()).expect("analysis runs");
        std::fs::remove_file(&path).ok();

        // 12 answer records against a cap of 8: packet 3 lands mid-event
        // (6 → 9, trimmed back to 8, 1 dropped) and packet 4 is wholly past
        // the cap (3 dropped) — kept == cap, dropped == total − cap.
        assert_eq!(pass.dns.len(), 8, "kept records must equal the cap");
        assert_eq!(pass.dns_dropped, 4, "every dropped record counted");
        assert!(pass.dns.iter().all(|r| r.role == "answer"));
        assert_eq!(pass.degradation().dns_records_dropped, 4);
    }

    /// The DHCP mirror (`max_dhcp_records = 8`): one record per message, so
    /// the cap engages between events — kept == cap and every post-cap
    /// message is counted.
    #[test]
    fn dhcp_record_cap_holds_and_counts_every_drop() {
        let frames: Vec<(Timestamp, Vec<u8>)> = (0..12u8)
            .map(|i| {
                let mac = MacAddr([0x02, 0, 0, 0, 0, i]);
                let opts = fixtures::DhcpOptions {
                    hostname: Some("flood-host"),
                    ..fixtures::DhcpOptions::default()
                };
                let frame = Packet::ethernet(mac, MacAddr::BROADCAST)
                    .ipv4(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST)
                    .udp(68, 67)
                    .payload(&fixtures::dhcp(1, mac, 0x1000 + u32::from(i), &opts));
                (Timestamp::ZERO, frame)
            })
            .collect();
        let path = write_capture("dhcp-cap", &frames);
        let needs = Needs {
            dhcp: true,
            ..Needs::default()
        };
        let pass = Pass::run(&path, needs, Limits::tiny()).expect("analysis runs");
        std::fs::remove_file(&path).ok();

        assert_eq!(pass.dhcp.len(), 8, "kept records must equal the cap");
        assert_eq!(pass.dhcp_dropped, 4, "every dropped record counted");
        assert_eq!(pass.degradation().dhcp_records_dropped, 4);
    }
}
