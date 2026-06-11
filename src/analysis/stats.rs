//! Capture-wide counters: packet/byte totals, protocol breakdown, time span,
//! and parse-anomaly tallies (the honest "what we couldn't decode" view).
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use serde::Serialize;

use super::Observe;
use crate::app::AppEvent;
use crate::decode::{NetView, PacketView, TransportView};
use crate::types::Timestamp;

#[derive(Debug, Default, Serialize)]
pub struct Stats {
    pub packets: u64,
    pub bytes: u64,
    pub first_ts: Option<Timestamp>,
    pub last_ts: Option<Timestamp>,
    /// Counts keyed by a short layer label (`ipv4`, `tcp`, `arp`, …). The keys
    /// are `&'static str` literals, so counting allocates nothing per packet.
    pub link_protocols: BTreeMap<&'static str, u64>,
    pub transport_protocols: BTreeMap<&'static str, u64>,
    pub app_protocols: BTreeMap<&'static str, u64>,
    pub truncated_packets: u64,
    pub malformed_packets: u64,
    /// Records that never became a packet view: non-Ethernet link
    /// type, or an Ethernet header too broken to read.
    pub undecodable: u64,
    /// Well-framed pcapng packet blocks whose bodies were malformed; each
    /// was skipped by the reader instead of aborting the stream.
    pub skipped_blocks: u64,
    /// Records that carry no capture timestamp (pcapng Simple Packet
    /// Blocks); excluded from the first/last span and the duration.
    pub timestampless_records: u64,
}

/// Some capture tools mix uptime-relative and absolute clocks; a span
/// measured in years is a data-quality problem worth saying out loud.
const FIVE_YEARS_SECS: f64 = 5.0 * 365.25 * 86_400.0;

impl Stats {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Capture duration in seconds (0 if fewer than two timestamps).
    #[must_use]
    pub fn duration_secs(&self) -> f64 {
        match (self.first_ts, self.last_ts) {
            (Some(first), Some(last)) => last.secs_since(first),
            _ => 0.0,
        }
    }

    /// The observed span is too long (> 5 years) to be one consistent capture
    /// clock. A heuristic data-quality flag, surfaced in the table note and
    /// the summary JSON alike.
    #[must_use]
    pub fn clock_inconsistent(&self) -> bool {
        self.duration_secs() > FIVE_YEARS_SECS
    }

    fn bump(map: &mut BTreeMap<&'static str, u64>, key: &'static str) {
        let count = map.entry(key).or_insert(0);
        *count = count.saturating_add(1);
    }

    /// A layer that failed to decode is an anomaly — but a header cut short by
    /// snaplen is a *truncation*, not a lying packet. Classify by the error
    /// the decoder actually reported (skipping the truncated count when the
    /// packet-level flag already recorded it).
    fn note_undecoded_layer(&mut self, err: crate::error::DecodeError, already_truncated: bool) {
        match err {
            crate::error::DecodeError::Truncated { .. } => {
                if !already_truncated {
                    self.truncated_packets = self.truncated_packets.saturating_add(1);
                }
            }
            crate::error::DecodeError::Malformed { .. } => {
                self.malformed_packets = self.malformed_packets.saturating_add(1);
            }
        }
    }
}

impl Observe for Stats {
    fn observe(&mut self, pkt: &PacketView<'_>, app: Option<&AppEvent>) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(u64::from(pkt.orig_len));
        // A record without a timestamp contributes nothing to the span —
        // folding a sentinel in would fabricate a 1970 capture start.
        if let Some(ts) = pkt.ts {
            self.first_ts = Some(self.first_ts.map_or(ts, |t| t.min(ts)));
            self.last_ts = Some(self.last_ts.map_or(ts, |t| t.max(ts)));
        }

        if pkt.truncated {
            self.truncated_packets = self.truncated_packets.saturating_add(1);
        }

        match &pkt.net {
            NetView::Arp(_) => Self::bump(&mut self.link_protocols, "arp"),
            NetView::Ipv4(_) => Self::bump(&mut self.link_protocols, "ipv4"),
            NetView::Ipv6(_) => Self::bump(&mut self.link_protocols, "ipv6"),
            // EtherType values <= 0x05DC are 802.3 length fields (LLC/STP/CDP),
            // not protocol numbers — label them honestly instead of "other".
            NetView::Unknown { ethertype } if *ethertype <= 0x05DC => {
                Self::bump(&mut self.link_protocols, "802.3");
            }
            NetView::Unknown { .. } => Self::bump(&mut self.link_protocols, "other"),
            NetView::Malformed { err, .. } => {
                self.note_undecoded_layer(*err, pkt.truncated);
                Self::bump(&mut self.link_protocols, "malformed");
            }
        }

        match &pkt.transport {
            Some(TransportView::Tcp(_)) => Self::bump(&mut self.transport_protocols, "tcp"),
            Some(TransportView::Udp(_)) => Self::bump(&mut self.transport_protocols, "udp"),
            Some(TransportView::Sctp(_)) => Self::bump(&mut self.transport_protocols, "sctp"),
            Some(TransportView::Icmp(icmp)) => {
                Self::bump(
                    &mut self.transport_protocols,
                    if icmp.v6 { "icmpv6" } else { "icmp" },
                );
            }
            Some(TransportView::Other { proto }) => {
                // Name infrastructure protocols (gre/esp/ospf/vrrp/igmp/…)
                // instead of lumping them as "other".
                let label = crate::types::ip_proto_name(*proto).unwrap_or("other");
                Self::bump(&mut self.transport_protocols, label);
            }
            Some(TransportView::Malformed { err, .. }) => {
                self.note_undecoded_layer(*err, pkt.truncated);
                Self::bump(&mut self.transport_protocols, "malformed");
            }
            None => {}
        }

        if let Some(event) = app {
            Self::bump(&mut self.app_protocols, event.label());
        }
    }
}

/// Counts records that could not be decoded into a packet view at all —
/// wrong link type or an unreadable Ethernet header. Tracked separately
/// because [`Stats::observe`] only ever sees decoded packets.
impl Stats {
    pub fn note_undecodable(&mut self) {
        self.undecodable = self.undecodable.saturating_add(1);
    }

    pub fn note_skipped_blocks(&mut self, n: u64) {
        self.skipped_blocks = self.skipped_blocks.saturating_add(n);
    }

    pub fn note_timestampless(&mut self, n: u64) {
        self.timestampless_records = self.timestampless_records.saturating_add(n);
    }
}
