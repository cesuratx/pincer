//! Analysis sinks. Every analysis implements [`Observe`]; the CLI composes
//! whichever sinks a subcommand needs and the capture is streamed **once**,
//! no matter how many analyses run — observer pattern as a single-pass
//! pipeline.

pub mod assets;
pub mod deps;
pub mod flows;
pub mod stats;

pub use assets::{
    Asset, AssetInventory, AssetKey, AssetOverflow, NameSource, Service, ServiceEvidence,
};
pub use deps::{DepEdge, dependency_edges};
pub use flows::{Endpoint, Flow, FlowKey, FlowTable};
pub use stats::Stats;

use crate::app::AppEvent;
use crate::decode::PacketView;

/// One analysis pass over the packet stream.
pub trait Observe {
    fn observe(&mut self, pkt: &PacketView<'_>, app: Option<&AppEvent>);
}

/// Hard caps on every collection that grows with attacker-controlled content.
///
/// A hostile capture (random 5-tuple flood, ARP-spoof storm, mDNS name flood)
/// must degrade into bounded memory with an honest "dropped N" counter, never
/// an OOM. Two layers enforce that: every stored name is length-capped at
/// parse time (≤ 253 bytes, the DNS maximum — longer SNI/Host values are
/// discarded as bogus), and every collection is entry-capped below. Defaults
/// are generous for real networks (a /16 enterprise segment fits).
///
/// Retained bytes are **not** bounded by wire bytes everywhere: DNS name
/// decompression lets a 2-byte compression pointer expand into a ≤ 253-byte
/// name, so one kept `dns` detail record can retain ~600 heap bytes from
/// ~20 wire bytes — ~30x amplification. The flow/asset/binding collections
/// don't have that vector (their keys and names really must arrive on the
/// wire), so for them a cap-saturating capture must itself be large. The
/// `max_dns_records` / `max_dhcp_records` defaults are therefore sized by
/// worst-case retained memory, with the arithmetic documented on each; lower
/// them further when analyzing untrusted multi-GB captures. All caps are
/// configurable, which also lets tests drive overflow with tiny inputs.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_flows: usize,
    pub max_assets: usize,
    pub max_bindings: usize,
    pub max_subnets: usize,
    pub max_hostnames_per_asset: usize,
    pub max_services_per_asset: usize,
    pub max_ips_per_asset: usize,
    pub max_dns_records: usize,
    pub max_dhcp_records: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_flows: 2_000_000,
            max_assets: 500_000,
            max_bindings: 1_000_000,
            max_subnets: 4_096,
            max_hostnames_per_asset: 256,
            max_services_per_asset: 1_024,
            // Generous for real multi-homed hosts and routers; small enough
            // that one MAC spraying fresh IPv6 link-local sources (which are
            // local by definition, no subnet learning needed) cannot grow a
            // single asset's IP set with the streamed file.
            max_ips_per_asset: 4_096,
            // Sized by retained bytes, not entry-count generosity, because
            // decompression amplifies: a minimal hostile answer is ~16-20
            // wire bytes (2-byte pointer name + 10 fixed + rdata) yet
            // retains up to ~600 — an 80-byte record struct plus two
            // ≤ 253/259-byte strings. Worst case here: 200k × ~600 B
            // ≈ 120 MB, reachable from a ~4 MB crafted mDNS capture. (The
            // old 2M default allowed ~1.2 GB; 698 MB was measured.)
            max_dns_records: 200_000,
            // One record per DHCP message and every option value is ≤ 255
            // wire bytes, so retention is ≤ ~2x wire (option 55 formats to
            // at most 4 chars per code) with no decompression vector.
            // Worst case here: 100k × ~1.7 KB ≈ 170 MB, and maxing a
            // record needs an ~1 KB message — the input must be comparably
            // large (≥ ~100 MB) to get there.
            max_dhcp_records: 100_000,
        }
    }
}

impl Limits {
    /// Tiny caps for tests that need to provoke overflow deterministically.
    #[must_use]
    pub fn tiny() -> Self {
        Self {
            max_flows: 8,
            max_assets: 8,
            max_bindings: 8,
            max_subnets: 4,
            max_hostnames_per_asset: 4,
            max_services_per_asset: 4,
            max_ips_per_asset: 4,
            max_dns_records: 8,
            max_dhcp_records: 8,
        }
    }
}

/// Well-known service-port names for labeling inferred services.
#[must_use]
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        20 | 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        67 | 68 => "dhcp",
        80 => "http",
        110 => "pop3",
        123 => "ntp",
        137 => "netbios-ns",
        143 => "imap",
        161 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        631 => "ipp",
        993 => "imaps",
        1433 => "mssql",
        3306 => "mysql",
        3389 => "rdp",
        5353 => "mdns",
        5432 => "postgres",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        9100 => "jetdirect",
        _ => return None,
    })
}

/// Does this port identify a *server* side of a connection? True for any
/// well-known port (< 1024) or one we have a service name for. Used both to
/// infer flow direction and to record services, so the rule lives in one place.
#[must_use]
pub fn is_service_port(port: u16) -> bool {
    // Port 0 is reserved, never a listening service — without this bound a
    // crafted zero-port packet acts as a well-known port in direction
    // inference and creates phantom port-0 "services".
    (1..1024).contains(&port) || service_name(port).is_some()
}
