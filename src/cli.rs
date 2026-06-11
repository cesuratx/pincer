//! Command-line surface and the single-pass analysis pipeline.

use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::analysis::{AssetInventory, FlowTable, Limits, Observe, Stats, dependency_edges};
use crate::app::sniff;
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
    #[command(subcommand)]
    pub command: Command,
}

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

/// Parse args and dispatch. Returns a process exit code worth of error via
/// [`Error`].
pub fn run() -> Result<(), Error> {
    let cli = Cli::parse();
    match cli.command {
        Command::Gen(args) => run_gen(&args),
        Command::Summary(common) => run_analysis(&common, Which::Summary),
        Command::Flows(common) => run_analysis(&common, Which::Flows),
        Command::Assets(common) => run_analysis(&common, Which::Assets),
        Command::Services(common) => run_analysis(&common, Which::Services),
        Command::Dns(common) => run_analysis(&common, Which::Dns),
        Command::Dhcp(common) => run_analysis(&common, Which::Dhcp),
        Command::Deps(args) => run_deps(&args),
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
    /// Well-framed pcapng packet blocks with malformed bodies, skipped by
    /// the reader.
    skipped_blocks: u64,
    /// dns/dhcp detail rows dropped once their per-run cap was hit.
    dns_dropped: u64,
    dhcp_dropped: u64,
}

impl Pass {
    fn run(file: &std::path::Path, needs: Needs) -> Result<Self, Error> {
        let limits = Limits::default();
        let mut reader = pcap::open_input(file).map_err(|source| Error::Capture {
            path: file.to_path_buf(),
            source,
        })?;

        let mut pass = Self {
            flows: FlowTable::with_limits(limits),
            assets: AssetInventory::with_limits(limits),
            ..Self::default()
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
            // Every subcommand consumes app events (stats/flows/assets label
            // with them; dns/dhcp are built from them), so sniffing is
            // unconditional — a "skip when unused" branch here was dead code.
            let app = sniff(&pkt);
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
                // it is exact, not "cap plus up to one event's worth".
                if needs.dns {
                    if pass.dns.len() < limits.max_dns_records {
                        DnsRecord::push_from(event, &mut pass.dns);
                        let over = pass.dns.len().saturating_sub(limits.max_dns_records);
                        if over > 0 {
                            pass.dns.truncate(limits.max_dns_records);
                            pass.dns_dropped = pass.dns_dropped.saturating_add(over as u64);
                        }
                    } else {
                        pass.dns_dropped = pass.dns_dropped.saturating_add(1);
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
                        pass.dhcp_dropped = pass.dhcp_dropped.saturating_add(1);
                    }
                }
            }
        }

        pass.skipped_blocks = reader.skipped_blocks();
        if needs.stats {
            pass.stats.note_skipped_blocks(pass.skipped_blocks);
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
        if self.flows.dropped() > 0 {
            warn(format!(
                "flow table hit its cap; {} flow(s) dropped (results are partial)",
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
                "detail-record caps reached (dropped {} dns, {} dhcp events)",
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
        }
    }
}

fn run_analysis(common: &Common, which: Which) -> Result<(), Error> {
    let pass = Pass::run(&common.file, which.needs())?;
    let assets = pass.assets.assets();
    let report = match which {
        Which::Summary => Report::Summary(&pass.stats),
        Which::Flows => Report::Flows(&pass.flows),
        Which::Assets => Report::Assets(&assets),
        Which::Services => Report::Services(&assets),
        Which::Dns => Report::Dns(&pass.dns),
        Which::Dhcp => Report::Dhcp(&pass.dhcp),
    };
    emit(&report, common.json, &pass.degradation())
}

fn run_deps(args: &DepsArgs) -> Result<(), Error> {
    // Dependencies need both the flow table and the asset inventory.
    let needs = Needs {
        flows: true,
        assets: true,
        ..Needs::default()
    };
    let pass = Pass::run(&args.common.file, needs)?;
    let edges = dependency_edges(&pass.flows, &pass.assets);
    if args.dot && !args.common.json {
        return write_stdout(&deps_dot(&edges));
    }
    emit(&Report::Deps(&edges), args.common.json, &pass.degradation())
}

fn emit(report: &Report<'_>, json: bool, degradation: &Degradation) -> Result<(), Error> {
    let rendered = if json {
        report.to_json(degradation)?
    } else {
        report.to_table()
    };
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(rendered.as_bytes())?;
    if json {
        lock.write_all(b"\n")?;
    }
    Ok(())
}

fn run_gen(args: &GenArgs) -> Result<(), Error> {
    use crate::fixtures::scenarios;

    std::fs::create_dir_all(&args.out_dir).map_err(|e| Error::output(&args.out_dir, e))?;
    let mut wrote = Vec::new();

    let mut write_one =
        |name: &str, frames: &[(crate::types::Timestamp, Vec<u8>)]| -> Result<(), Error> {
            let path = args.out_dir.join(name);
            let file = std::fs::File::create(&path).map_err(|e| Error::output(&path, e))?;
            scenarios::write_pcap(frames, std::io::BufWriter::new(file))
                .map_err(|e| Error::output(&path, e))?;
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
