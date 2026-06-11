//! Bidirectional flow aggregation — the core of passive discovery: raw
//! packets become "who talks to whom, on which service, how much".

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt;
use std::net::IpAddr;

use serde::Serialize;

use super::{Limits, Observe, is_service_port, service_name};
use crate::app::AppEvent;
use crate::decode::{PacketView, TcpFlags, TransportView};
use crate::types::{IpProto, Timestamp};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

/// Canonical bidirectional flow key. The constructor is the only way to build
/// one, and it always sorts the endpoints — packets in either direction land
/// on the same key *by construction*, not by convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FlowKey {
    a: Endpoint,
    b: Endpoint,
    proto: IpProto,
}

impl FlowKey {
    #[must_use]
    pub fn new(x: Endpoint, y: Endpoint, proto: IpProto) -> Self {
        let (a, b) = if x <= y { (x, y) } else { (y, x) };
        Self { a, b, proto }
    }

    #[must_use]
    pub const fn a(&self) -> Endpoint {
        self.a
    }

    #[must_use]
    pub const fn b(&self) -> Endpoint {
        self.b
    }

    #[must_use]
    pub const fn proto(&self) -> IpProto {
        self.proto
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    AToB,
    BToA,
}

impl Direction {
    #[must_use]
    pub const fn flip(self) -> Self {
        match self {
            Self::AToB => Self::BToA,
            Self::BToA => Self::AToB,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct DirStats {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug)]
pub struct Flow {
    pub key: FlowKey,
    first_dir: Direction,
    syn_dir: Option<Direction>,
    syn_ack_dir: Option<Direction>,
    a_to_b: DirStats,
    b_to_a: DirStats,
    pub tcp_flags: TcpFlags,
    pub first_ts: Timestamp,
    pub last_ts: Timestamp,
    /// First application protocol identified on this flow.
    app_label: Option<&'static str>,
    /// First server-name evidence seen (TLS SNI / HTTP Host). One small owned
    /// string per flow at most — flows never retain whole app events.
    server_name: Option<String>,
}

impl Flow {
    fn new(key: FlowKey, dir: Direction, ts: Timestamp) -> Self {
        Self {
            key,
            first_dir: dir,
            syn_dir: None,
            syn_ack_dir: None,
            a_to_b: DirStats::default(),
            b_to_a: DirStats::default(),
            tcp_flags: TcpFlags::default(),
            first_ts: ts,
            last_ts: ts,
            app_label: None,
            server_name: None,
        }
    }

    /// Which side initiated, best evidence first: a pure SYN beats a SYN-ACK
    /// beats the well-known-port heuristic beats first-packet-seen.
    #[must_use]
    pub fn client_dir(&self) -> Direction {
        if let Some(dir) = self.syn_dir {
            return dir;
        }
        if let Some(dir) = self.syn_ack_dir {
            return dir.flip();
        }
        let a_is_service = is_service_port(self.key.a.port);
        let b_is_service = is_service_port(self.key.b.port);
        match (a_is_service, b_is_service) {
            (true, false) => Direction::BToA,
            (false, true) => Direction::AToB,
            _ => self.first_dir,
        }
    }

    #[must_use]
    pub fn client(&self) -> Endpoint {
        match self.client_dir() {
            Direction::AToB => self.key.a,
            Direction::BToA => self.key.b,
        }
    }

    #[must_use]
    pub fn server(&self) -> Endpoint {
        match self.client_dir() {
            Direction::AToB => self.key.b,
            Direction::BToA => self.key.a,
        }
    }

    /// Stats in client→server orientation.
    #[must_use]
    pub fn client_to_server(&self) -> DirStats {
        match self.client_dir() {
            Direction::AToB => self.a_to_b,
            Direction::BToA => self.b_to_a,
        }
    }

    #[must_use]
    pub fn server_to_client(&self) -> DirStats {
        match self.client_dir() {
            Direction::AToB => self.b_to_a,
            Direction::BToA => self.a_to_b,
        }
    }

    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.a_to_b.bytes.saturating_add(self.b_to_a.bytes)
    }

    #[must_use]
    pub fn total_packets(&self) -> u64 {
        self.a_to_b.packets.saturating_add(self.b_to_a.packets)
    }

    /// The destination service was confirmed listening (SYN-ACK observed).
    #[must_use]
    pub const fn server_confirmed(&self) -> bool {
        self.syn_ack_dir.is_some()
    }

    /// Best service-name evidence carried by this flow (TLS SNI, HTTP Host).
    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Protocol label, preferring application evidence over port numbers.
    #[must_use]
    pub fn app_label(&self) -> &'static str {
        self.app_label
            .or_else(|| service_name(self.server().port))
            .unwrap_or("-")
    }

    fn stats_mut(&mut self, dir: Direction) -> &mut DirStats {
        match dir {
            Direction::AToB => &mut self.a_to_b,
            Direction::BToA => &mut self.b_to_a,
        }
    }
}

#[derive(Debug)]
pub struct FlowTable {
    flows: BTreeMap<FlowKey, Flow>,
    limits: Limits,
    /// Flows dropped because the table was at `max_flows` — reported, not hidden.
    dropped: u64,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::with_limits(Limits::default())
    }
}

impl FlowTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_limits(limits: Limits) -> Self {
        Self {
            flows: BTreeMap::new(),
            limits,
            dropped: 0,
        }
    }

    /// Flows discarded due to the `max_flows` cap (flow-flood backstop).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Flow> {
        self.flows.values()
    }

    /// Flows sorted by total bytes, descending — the "top conversations" view.
    #[must_use]
    pub fn by_bytes(&self) -> Vec<&Flow> {
        let mut flows: Vec<&Flow> = self.flows.values().collect();
        flows.sort_by_key(|flow| std::cmp::Reverse(flow.total_bytes()));
        flows
    }
}

impl Observe for FlowTable {
    fn observe(&mut self, pkt: &PacketView<'_>, app: Option<&AppEvent>) {
        let Some((src_ip, dst_ip)) = pkt.ip_pair() else {
            return;
        };
        let (src_port, dst_port, proto, tcp_flags) = match pkt.transport.as_ref() {
            Some(TransportView::Tcp(tcp)) => {
                (tcp.src_port, tcp.dst_port, IpProto::Tcp, Some(tcp.flags))
            }
            Some(TransportView::Udp(udp)) => (udp.src_port, udp.dst_port, IpProto::Udp, None),
            Some(TransportView::Sctp(sctp)) => (sctp.src_port, sctp.dst_port, IpProto::Sctp, None),
            Some(TransportView::Icmp(icmp)) => {
                let proto = if icmp.v6 {
                    IpProto::IcmpV6
                } else {
                    IpProto::Icmp
                };
                (0, 0, proto, None)
            }
            Some(TransportView::Other { proto }) => (0, 0, IpProto::Other(*proto), None),
            Some(TransportView::Malformed { .. }) | None => return,
        };

        let src = Endpoint {
            ip: src_ip,
            port: src_port,
        };
        let dst = Endpoint {
            ip: dst_ip,
            port: dst_port,
        };
        let key = FlowKey::new(src, dst, proto);
        let dir = if key.a == src {
            Direction::AToB
        } else {
            Direction::BToA
        };

        // Flow-flood backstop: once the table is full, keep updating flows we
        // already track but stop minting new ones (counting the drop). A
        // random-5-tuple SYN flood therefore costs a bounded table plus a
        // counter, not unbounded memory. One map descent via Entry rather than
        // a separate contains_key + entry.
        let len = self.flows.len();
        let flow = match self.flows.entry(key) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                if len >= self.limits.max_flows {
                    self.dropped = self.dropped.saturating_add(1);
                    return;
                }
                e.insert(Flow::new(key, dir, pkt.ts))
            }
        };

        let stats = flow.stats_mut(dir);
        stats.packets = stats.packets.saturating_add(1);
        stats.bytes = stats.bytes.saturating_add(u64::from(pkt.orig_len));
        flow.first_ts = flow.first_ts.min(pkt.ts);
        flow.last_ts = flow.last_ts.max(pkt.ts);

        if let Some(flags) = tcp_flags {
            flow.tcp_flags = flow.tcp_flags.union(flags);
            if flags.is_initial_syn() && flow.syn_dir.is_none() {
                flow.syn_dir = Some(dir);
            }
            if flags.is_syn_ack() && flow.syn_ack_dir.is_none() {
                flow.syn_ack_dir = Some(dir);
            }
        }

        if let Some(event) = app {
            if flow.app_label.is_none() {
                flow.app_label = Some(event.label());
            }
            if flow.server_name.is_none()
                && let Some(name) = event.server_name_hint()
            {
                flow.server_name = Some(name.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ep(a: u8, port: u16) -> Endpoint {
        Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, a)),
            port,
        }
    }

    #[test]
    fn flow_key_is_direction_independent() {
        let client = ep(10, 51514);
        let server = ep(50, 443);
        let forward = FlowKey::new(client, server, IpProto::Tcp);
        let reverse = FlowKey::new(server, client, IpProto::Tcp);
        assert_eq!(forward, reverse, "canonical key must ignore direction");
    }

    #[test]
    fn syn_decides_client_over_port_heuristic() {
        // Server on a high (non-well-known) port: only the SYN reveals who
        // initiated. We send the SYN from the high-port side.
        let key = FlowKey::new(ep(10, 40000), ep(50, 40001), IpProto::Tcp);
        let mut flow = Flow::new(key, Direction::AToB, Timestamp::ZERO);
        flow.syn_dir = Some(if key.a() == ep(10, 40000) {
            Direction::AToB
        } else {
            Direction::BToA
        });
        assert_eq!(flow.client(), ep(10, 40000));
        assert_eq!(flow.server(), ep(50, 40001));
    }

    #[test]
    fn well_known_port_breaks_tie_without_syn() {
        let key = FlowKey::new(ep(10, 51000), ep(50, 22), IpProto::Tcp);
        let flow = Flow::new(key, Direction::BToA, Timestamp::ZERO);
        // No SYN seen; port 22 marks the server side regardless of first packet.
        assert_eq!(flow.server().port, 22);
        assert_eq!(flow.client().port, 51000);
    }
}
