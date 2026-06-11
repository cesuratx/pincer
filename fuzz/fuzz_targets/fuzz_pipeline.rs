//! The full shipped path on arbitrary bytes: container reader → layer decode
//! → app sniff → every sink → finalize → derived dependency edges → JSON and
//! DOT render. Everything `pincer <cmd>` can reach on a hostile capture,
//! this reaches in one exec.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pincer::analysis::{AssetInventory, FlowTable, Limits, Observe, Stats, dependency_edges};
use pincer::app::{SniffDepth, sniff_with};
use pincer::decode::decode_packet;
use pincer::output::{Degradation, DhcpRecord, DnsRecord, Report, deps_dot};
use pincer::pcap::CaptureReader;

fuzz_target!(|data: &[u8]| {
    let Ok(mut reader) = CaptureReader::new(data) else {
        return;
    };
    // Tiny caps: a handful of fuzzed packets cross every overflow/eviction
    // branch (the hostile-flood defenses), and per-exec memory stays far
    // below libFuzzer's RSS limit.
    let limits = Limits::tiny();
    let mut stats = Stats::new();
    let mut flows = FlowTable::with_limits(limits);
    let mut assets = AssetInventory::with_limits(limits);
    let mut dns: Vec<DnsRecord> = Vec::new();
    let mut dhcp: Vec<DhcpRecord> = Vec::new();
    while let Ok(Some(record)) = reader.next_record() {
        let Ok(pkt) = decode_packet(&record) else {
            continue;
        };
        let app = sniff_with(&pkt, SniffDepth::FULL);
        let app_ref = app.as_ref();
        stats.observe(&pkt, app_ref);
        flows.observe(&pkt, app_ref);
        assets.observe(&pkt, app_ref);
        if let Some(event) = app_ref {
            // Entry-capped like the CLI's detail vectors; the CLI's exact
            // drop accounting is covered by unit tests — bounded memory is
            // what matters here.
            if dns.len() < limits.max_dns_records {
                DnsRecord::push_from(event, &mut dns);
                dns.truncate(limits.max_dns_records);
            }
            if dhcp.len() < limits.max_dhcp_records {
                DhcpRecord::push_from(event, &mut dhcp);
            }
        }
    }
    assets.finalize();
    let edges = dependency_edges(&flows, &assets);
    let asset_refs = assets.assets();

    let degradation = Degradation::default();
    let mut sink = std::io::sink();
    for report in [
        Report::Summary(&stats),
        Report::Flows(&flows),
        Report::Assets(&asset_refs),
        Report::Services(&asset_refs),
        Report::Deps(&edges),
        Report::Dns(&dns),
        Report::Dhcp(&dhcp),
    ] {
        let _ = report.write_json(&degradation, &mut sink);
    }
    std::hint::black_box(deps_dot(&edges, &degradation));
});
