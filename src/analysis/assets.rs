//! Asset inventory: fold packets into per-host records with identity evidence.
//!
//! A host on the local segment is keyed by its MAC (stable across DHCP
//! leases); a host we only see by IP (behind the router, off-link) is keyed by
//! IP. Hostnames and services carry their *evidence source* so the report can
//! show why we believe each fact — the discipline of attributing every
//! inference, which is what makes passive findings trustworthy.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use serde::Serialize;

use super::{Limits, Observe, is_service_port, service_name};
use crate::app::{AppEvent, DhcpMsgType, DnsRData};
use crate::decode::arp::ArpOp;
use crate::decode::{ArpView, NetView, PacketView, TransportView};
use crate::types::{MacAddr, Timestamp};

/// How we learned a hostname, most authoritative first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum NameSource {
    Dhcp,
    Mdns,
    DnsAnswer,
    Tls,
    Http,
}

/// How we learned a service is present on a host.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ServiceEvidence {
    // NOTE: variant order IS evidence strength (Ord) — strongest first.
    /// SYN-ACK observed from this host:port — it is definitely listening.
    SynAck,
    /// Application banner seen (TLS SNI, HTTP Host) — strong evidence.
    AppLayer,
    /// A UDP datagram from this host:port answered an ephemeral port — a
    /// listener responded (UDP's closest analogue to a SYN-ACK).
    UdpResponse,
    /// Inferred from a well-known destination port only.
    PortHeuristic,
}

impl std::fmt::Display for ServiceEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Human names for report cells — Debug is for developers.
        f.write_str(match self {
            Self::SynAck => "syn-ack",
            Self::AppLayer => "app-layer",
            Self::UdpResponse => "udp-response",
            Self::PortHeuristic => "port",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Service {
    pub port: u16,
    pub proto: &'static str,
    pub name: Option<&'static str>,
    pub evidence: ServiceEvidence,
}

/// Stable identity for an asset: its MAC when it is a local-segment host
/// (survives DHCP lease changes), otherwise its IP. `Copy`, so resolving an IP
/// to its asset key in the hot path allocates nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssetKey {
    Mac(MacAddr),
    Ip(IpAddr),
}

impl std::fmt::Display for AssetKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mac(mac) => write!(f, "{mac}"),
            Self::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

impl Serialize for AssetKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Asset {
    pub key: AssetKey,
    pub macs: BTreeSet<MacAddr>,
    pub ips: BTreeSet<IpAddr>,
    /// hostname -> best (lowest) evidence source.
    pub hostnames: BTreeMap<String, NameSource>,
    /// (port, proto) -> strongest evidence. Serialized as a `services` array
    /// of objects so the JSON contract is unchanged.
    #[serde(serialize_with = "serialize_services", rename = "services")]
    services: BTreeMap<(u16, &'static str), ServiceEvidence>,
    pub dhcp_fingerprint: Option<String>,
    pub vendor_class: Option<String>,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
}

/// Render the service map as the historical `Vec<Service>` JSON shape.
fn serialize_services<S: serde::Serializer>(
    map: &BTreeMap<(u16, &'static str), ServiceEvidence>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(map.len()))?;
    for ((port, proto), evidence) in map {
        seq.serialize_element(&Service {
            port: *port,
            proto,
            name: service_name(*port),
            evidence: evidence.clone(),
        })?;
    }
    seq.end()
}

impl Asset {
    fn new(key: AssetKey, ts: Timestamp) -> Self {
        Self {
            key,
            macs: BTreeSet::new(),
            ips: BTreeSet::new(),
            hostnames: BTreeMap::new(),
            services: BTreeMap::new(),
            dhcp_fingerprint: None,
            vendor_class: None,
            first_seen: ts,
            last_seen: ts,
        }
    }

    /// Fold another asset's evidence into this one — used when a host first
    /// seen by IP is later bound to a MAC, so the two records become one.
    /// Identity-preserving: keeps this asset's `key`, takes the union of
    /// addresses, the strongest hostname source, and the strongest service
    /// evidence; widens the first/last-seen window. Returns how many
    /// (hostnames, services) the per-asset caps dropped, so promotion-time
    /// overflow is counted like any other.
    fn merge_from(&mut self, other: Self, cap_hostnames: usize, cap_services: usize) -> (u64, u64) {
        let (mut dropped_names, mut dropped_services) = (0u64, 0u64);
        self.macs.extend(other.macs);
        self.ips.extend(other.ips);
        for (name, source) in other.hostnames {
            if self.add_hostname(name, source, cap_hostnames) {
                dropped_names = dropped_names.saturating_add(1);
            }
        }
        for ((port, proto), evidence) in other.services {
            if self.add_service(port, proto, evidence, cap_services) {
                dropped_services = dropped_services.saturating_add(1);
            }
        }
        self.dhcp_fingerprint = self.dhcp_fingerprint.take().or(other.dhcp_fingerprint);
        self.vendor_class = self.vendor_class.take().or(other.vendor_class);
        self.first_seen = self.first_seen.min(other.first_seen);
        self.last_seen = self.last_seen.max(other.last_seen);
        (dropped_names, dropped_services)
    }

    /// Services as the public `Service` view, sorted by port then proto.
    #[must_use]
    pub fn services(&self) -> Vec<Service> {
        self.services
            .iter()
            .map(|((port, proto), evidence)| Service {
                port: *port,
                proto,
                name: service_name(*port),
                evidence: evidence.clone(),
            })
            .collect()
    }

    /// Best-known display name: a hostname if we have one, else the key.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.hostnames
            .iter()
            .min_by_key(|(_, src)| **src)
            .map_or_else(|| self.key.to_string(), |(name, _)| name.clone())
    }

    /// Returns `true` if the name was *dropped* at the per-asset cap (so the
    /// inventory can count it) — degradation is never silent.
    fn add_hostname(&mut self, name: String, source: NameSource, cap: usize) -> bool {
        if name.is_empty() {
            return false;
        }
        if let Some(existing) = self.hostnames.get_mut(&name) {
            if source < *existing {
                *existing = source;
            }
            return false;
        }
        // mDNS/DNS name-flood backstop: bound distinct names per asset.
        if self.hostnames.len() >= cap {
            return true;
        }
        self.hostnames.insert(name, source);
        false
    }

    /// Returns `true` if a *new* service was dropped at the cap.
    fn add_service(
        &mut self,
        port: u16,
        proto: &'static str,
        evidence: ServiceEvidence,
        cap: usize,
    ) -> bool {
        // Keyed by (port, proto) so a full 65 K-port scan is O(log n) per
        // packet, not the O(n) linear Vec scan it used to be (which a scan
        // turned quadratic). The cap bounds memory; once reached we still
        // upgrade evidence on known services but add no new ones.
        if let Some(existing) = self.services.get_mut(&(port, proto)) {
            if evidence < *existing {
                *existing = evidence;
            }
            return false;
        }
        if self.services.len() >= cap {
            return true;
        }
        self.services.insert((port, proto), evidence);
        false
    }
}

/// Tallies of what hostile floods forced us to drop — surfaced in reports so
/// degradation is visible, never silent.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct AssetOverflow {
    pub assets: u64,
    pub bindings: u64,
    pub subnets: u64,
    pub hostnames: u64,
    pub services: u64,
    /// IPs whose MAC binding changed mid-capture (DHCP churn, VRRP failover,
    /// spoofing) — flow attribution for these resolves through the *final*
    /// binding and is therefore ambiguous.
    pub rebound_ips: u64,
}

impl AssetOverflow {
    #[must_use]
    pub fn any(&self) -> bool {
        self.assets | self.bindings | self.subnets | self.hostnames | self.services != 0
    }
}

/// `MAC|IP` identity resolver: maps every IP we associate with a MAC to that
/// MAC, so the same host is one asset even across its addresses.
///
/// The load-bearing rule is *locality*: a MAC may only be bound to an IP that
/// sits on the same L2 segment. A router's MAC fronts every off-link IP, so
/// binding it to those would collapse the whole internet into one "asset". We
/// treat an IPv4 as local if it is already authoritatively bound, or falls in a
/// segment we learned: from DHCP option 1 we get the *real* subnet mask; ARP
/// carries no mask, so an ARP binding contributes a conservative /24 guess.
///
/// Known limitations (single-pass, passive): on an ARP-only network with a
/// prefix wider than /24, same-segment hosts in a different /24 may be
/// IP-keyed; classification can shift if a subnet is first learned partway
/// through the capture; IPv6 locality covers link-local/ULA only (global SLAAC
/// addresses on the segment are not recognized without NDP parsing).
///
/// Every collection here is capped (see [`Limits`]); a hostile capture hits
/// the cap and increments an [`AssetOverflow`] counter rather than exhausting
/// memory.
#[derive(Debug)]
pub struct AssetInventory {
    /// asset key -> asset.
    assets: BTreeMap<AssetKey, Asset>,
    /// IP -> owning MAC (authoritative: ARP, DHCP, and same-segment frames).
    ip_to_mac: BTreeMap<IpAddr, MacAddr>,
    /// Local IPv4 segments grouped by mask: `mask -> {network}`. Grouping by
    /// mask makes `is_local` `O(distinct_masks · log n)` — distinct masks are
    /// a tiny handful — instead of `O(total_subnets)` per packet.
    local_v4_subnets: BTreeMap<u32, BTreeSet<u32>>,
    subnet_count: usize,
    /// Candidate IP→MAC pairs seen on data frames, to be confirmed against the
    /// *final* subnet knowledge in [`AssetInventory::finalize`]. This is what
    /// makes keying order-independent: a host whose frames arrive before the
    /// ARP/DHCP that establishes its subnet is still MAC-keyed at the end.
    provisional: BTreeMap<IpAddr, (MacAddr, Timestamp)>,
    finalized: bool,
    limits: Limits,
    overflow: AssetOverflow,
}

impl Default for AssetInventory {
    fn default() -> Self {
        Self::with_limits(Limits::default())
    }
}

/// Mask assumed for a segment learned from ARP, which carries no netmask.
const ARP_SUBNET_GUESS: u32 = 0xFFFF_FF00; // /24

/// A plausible IPv4 netmask: a contiguous run of 1 bits followed by 0 bits
/// (e.g. `255.255.255.0`), no shorter than /8 and no longer than /31. `0` and
/// `0xFFFF_FFFF` define no useful segment, and no real L2 broadcast domain is
/// wider than a /8 — without the floor, one hostile DHCP ACK claiming mask
/// `128.0.0.0` would mark half the IPv4 internet "local" and collapse every
/// routed host behind the gateway into the router's MAC.
fn is_plausible_netmask(mask: u32) -> bool {
    mask != u32::MAX && {
        let ones = mask.leading_ones();
        let zeros = mask.trailing_zeros();
        ones + zeros == 32 && ones >= 8
    }
}

impl AssetInventory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_limits(limits: Limits) -> Self {
        Self {
            assets: BTreeMap::new(),
            ip_to_mac: BTreeMap::new(),
            local_v4_subnets: BTreeMap::new(),
            subnet_count: 0,
            provisional: BTreeMap::new(),
            finalized: false,
            limits,
            overflow: AssetOverflow::default(),
        }
    }

    /// Resolve provisional data-frame bindings against the *complete* subnet
    /// knowledge, making the inventory order-independent. Idempotent. Call once
    /// after the streaming pass and before reading [`AssetInventory::assets`]
    /// — a host whose frames were seen before its subnet was learned is
    /// MAC-keyed here, at the end.
    pub fn finalize(&mut self) {
        if self.finalized {
            return;
        }
        self.finalized = true;
        // Snapshot to satisfy the borrow checker; provisional is bounded by
        // max_bindings, so this is a small, one-time pass.
        let pending: Vec<(IpAddr, MacAddr, Timestamp)> = self
            .provisional
            .iter()
            .filter(|(ip, _)| !self.ip_to_mac.contains_key(ip) && self.is_local(**ip))
            .map(|(ip, (mac, ts))| (*ip, *mac, *ts))
            .collect();
        for (ip, mac, ts) in pending {
            self.bind(mac, ip);
            // A data-frames-only host has no IP-keyed asset for bind() to
            // promote; record it here, with the first-seen time the
            // provisional actually observed, so the inventory lists it.
            self.record_local_host(mac, Some(ip), ts);
        }
    }

    /// What hostile-flood backstops dropped (all zero on normal captures).
    #[must_use]
    pub fn overflow(&self) -> AssetOverflow {
        self.overflow
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.assets.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }

    /// Assets sorted by first-seen, then key — stable, readable order.
    ///
    /// Call [`AssetInventory::finalize`] first (the CLI always does): a
    /// caller that skips it gets order-dependent keying for hosts whose
    /// segment was learned after their first frames.
    #[must_use]
    pub fn assets(&self) -> Vec<&Asset> {
        let mut out: Vec<&Asset> = self.assets.values().collect();
        out.sort_by(|x, y| x.first_seen.cmp(&y.first_seen).then(x.key.cmp(&y.key)));
        out
    }

    /// Resolve an IP to the asset key that owns it: its MAC if we have an
    /// authoritative same-segment binding, else the IP itself. Allocation-free.
    #[must_use]
    pub fn key_for_ip(&self, ip: IpAddr) -> AssetKey {
        self.ip_to_mac
            .get(&ip)
            .map_or(AssetKey::Ip(ip), |mac| AssetKey::Mac(*mac))
    }

    /// Authoritative MAC↔IP binding (from ARP / DHCP). Also seeds a local
    /// segment for the IP, using a /24 guess (ARP has no mask).
    fn bind_authoritative(&mut self, mac: MacAddr, ip: IpAddr) {
        if let IpAddr::V4(v4) = ip {
            self.learn_subnet(v4, ARP_SUBNET_GUESS);
        }
        self.bind(mac, ip);
    }

    /// Record that `ip`'s subnet (under `mask`) is a local segment. Used with
    /// the real mask from DHCP option 1, or the /24 guess from ARP.
    fn learn_subnet(&mut self, ip: Ipv4Addr, mask: u32) {
        // A real netmask is a run of 1s then 0s, at least /8 wide. A garbage
        // or hostile option-1 value (0x0F0F0F0F, 128.0.0.0) would otherwise
        // define a nonsense "segment" that is_local then uses to misclassify
        // off-link hosts as local.
        if !is_plausible_netmask(mask) {
            return;
        }
        if !is_unicast(IpAddr::V4(ip)) {
            return;
        }
        let network = u32::from(ip) & mask;
        if let Some(nets) = self.local_v4_subnets.get(&mask)
            && nets.contains(&network)
        {
            return; // already known — free, no cap interaction
        }
        // Flood backstop checked BEFORE inserting: an attacker spraying fresh
        // masks/subnets must hit the cap and be counted, never grow the map
        // unbounded (the empty-BTreeSet-per-mask leak the audit caught).
        if self.subnet_count >= self.limits.max_subnets {
            self.overflow.subnets = self.overflow.subnets.saturating_add(1);
            return;
        }
        self.local_v4_subnets
            .entry(mask)
            .or_default()
            .insert(network);
        self.subnet_count = self.subnet_count.saturating_add(1);
    }

    fn bind(&mut self, mac: MacAddr, ip: IpAddr) {
        if mac == MacAddr::BROADCAST || mac.is_multicast() || mac == MacAddr::ZERO {
            return;
        }
        // One predicate for every binding path: a multicast/broadcast IP is
        // not a host and must never acquire a MAC binding (a hostile ARP can
        // claim one; honoring it would key group traffic to a device).
        if !is_unicast(ip) {
            return;
        }
        // Rebinding a known IP (ARP refresh, or a spoofer reclaiming it) is
        // free; only a brand-new IP counts against the cap. An ARP-spoof storm
        // claiming millions of fresh IPs therefore stops growing the map.
        let known = self.ip_to_mac.get(&ip).copied();
        if known.is_none() && self.ip_to_mac.len() >= self.limits.max_bindings {
            self.overflow.bindings = self.overflow.bindings.saturating_add(1);
            return;
        }
        // An IP moving to a *different* MAC mid-capture (DHCP churn, VRRP
        // failover, or spoofing) means flow attribution for that IP — which
        // resolves through the final binding — is ambiguous. Count it so the
        // degradation report can say so instead of silently misattributing.
        if let Some(prev) = known
            && prev != mac
        {
            self.overflow.rebound_ips = self.overflow.rebound_ips.saturating_add(1);
        }
        self.ip_to_mac.insert(ip, mac);
        // First time this IP is bound to a MAC, fold any record we built while
        // it was only known by IP into the MAC-keyed asset. Without this, a
        // host named (DNS/mDNS) before its ARP/DHCP binding splits into two
        // assets and the inventory becomes order-dependent.
        if known != Some(mac) {
            self.promote_ip_asset(ip, mac);
        }
    }

    /// Note a candidate IP→MAC pair seen on a data frame. Unlike [`bind`],
    /// this makes no locality claim yet — [`finalize`] decides, once all
    /// subnets are known. Bounded by `max_bindings`.
    fn record_provisional(&mut self, mac: MacAddr, ip: IpAddr, ts: Timestamp) {
        if mac == MacAddr::BROADCAST || mac.is_multicast() || mac == MacAddr::ZERO {
            return;
        }
        if !is_unicast(ip) {
            return;
        }
        if !self.provisional.contains_key(&ip) && self.provisional.len() >= self.limits.max_bindings
        {
            // Same flood backstop as bind(); count it under bindings so the
            // drop is reported, not silent.
            self.overflow.bindings = self.overflow.bindings.saturating_add(1);
            return;
        }
        self.provisional
            .entry(ip)
            .and_modify(|(_, seen)| *seen = (*seen).min(ts))
            .or_insert((mac, ts));
    }

    /// Merge an `Ip(ip)`-keyed asset into the `Mac(mac)`-keyed asset, then drop
    /// the IP-keyed one. No-op if there is nothing to merge.
    fn promote_ip_asset(&mut self, ip: IpAddr, mac: MacAddr) {
        let Some(orphan) = self.assets.remove(&AssetKey::Ip(ip)) else {
            return;
        };
        let ts = orphan.first_seen;
        let (ch, cs) = (
            self.limits.max_hostnames_per_asset,
            self.limits.max_services_per_asset,
        );
        // `asset_mut` may return None only at the asset cap; since we just
        // removed one, there is room for the MAC-keyed target.
        let mut dropped = (0u64, 0u64);
        if let Some(target) = self.asset_mut(AssetKey::Mac(mac), ts) {
            dropped = target.merge_from(orphan, ch, cs);
            target.macs.insert(mac);
            target.ips.insert(ip);
        }
        self.overflow.hostnames = self.overflow.hostnames.saturating_add(dropped.0);
        self.overflow.services = self.overflow.services.saturating_add(dropped.1);
    }

    /// Is this IP plausibly on the local L2 segment? See the type docs. The
    /// answer depends only on learned segments and bindings — there is no
    /// RFC-1918 fallback that would flip a host's classification mid-capture.
    fn is_local(&self, ip: IpAddr) -> bool {
        if self.ip_to_mac.contains_key(&ip) {
            return true;
        }
        match ip {
            IpAddr::V4(v4) if !v4.is_unspecified() && !v4.is_broadcast() => {
                let addr = u32::from(v4);
                // Iterate distinct masks (a handful) with an O(log n) set
                // lookup each — not the whole subnet list.
                self.local_v4_subnets
                    .iter()
                    .any(|(&mask, nets)| nets.contains(&(addr & mask)))
            }
            // IPv6 link-local / unique-local are on-segment by definition.
            IpAddr::V6(v6) => {
                let seg = v6.segments();
                (seg[0] & 0xFFC0) == 0xFE80 || (seg[0] & 0xFE00) == 0xFC00
            }
            IpAddr::V4(_) => false,
        }
    }

    /// Get or create an asset. Returns `None` when the inventory is at
    /// `max_assets` and this is a new identity — a random-source-IP flood then
    /// stops creating assets (counted) instead of exhausting memory.
    fn asset_mut(&mut self, key: AssetKey, ts: Timestamp) -> Option<&mut Asset> {
        if !self.assets.contains_key(&key) && self.assets.len() >= self.limits.max_assets {
            self.overflow.assets = self.overflow.assets.saturating_add(1);
            return None;
        }
        Some(
            self.assets
                .entry(key)
                .or_insert_with(|| Asset::new(key, ts)),
        )
    }

    fn record_local_host(&mut self, mac: MacAddr, ip: Option<IpAddr>, ts: Timestamp) {
        if mac == MacAddr::BROADCAST || mac.is_multicast() || mac == MacAddr::ZERO {
            return;
        }
        let Some(asset) = self.asset_mut(AssetKey::Mac(mac), ts) else {
            return;
        };
        asset.macs.insert(mac);
        asset.last_seen = asset.last_seen.max(ts);
        asset.first_seen = asset.first_seen.min(ts);
        if let Some(ip) = ip.filter(|ip| !ip.is_unspecified() && !ip.is_multicast()) {
            asset.ips.insert(ip);
        }
    }

    fn observe_arp(&mut self, arp: &ArpView, ts: Timestamp) {
        // Unknown opcodes carry the right field layout but unknowable
        // semantics — no trust.
        if !matches!(arp.op, ArpOp::Request | ArpOp::Reply) {
            return;
        }
        // Sender fields are authoritative in requests and replies alike: both
        // place the speaker's own MAC/IP there, on this segment.
        self.bind_authoritative(arp.sender_mac, IpAddr::V4(arp.sender_ip));
        self.record_local_host(arp.sender_mac, Some(IpAddr::V4(arp.sender_ip)), ts);
        // Target fields are only assertions in a REPLY; in a request they are
        // the *question* (zero or stale), not evidence.
        if matches!(arp.op, ArpOp::Reply)
            && !arp.target_ip.is_unspecified()
            && arp.target_mac != MacAddr::ZERO
        {
            self.bind_authoritative(arp.target_mac, IpAddr::V4(arp.target_ip));
            self.record_local_host(arp.target_mac, Some(IpAddr::V4(arp.target_ip)), ts);
        }
    }

    fn observe_app(&mut self, pkt: &PacketView<'_>, app: &AppEvent, ts: Timestamp) {
        match app {
            AppEvent::Dhcp(dhcp) => {
                // A relayed exchange (giaddr set) describes a client on a
                // *different* segment: chaddr is an off-link MAC and option 1
                // names the remote subnet. Recording it as local evidence
                // would mark remote segments local and merge their routed
                // hosts into the router's MAC-keyed asset.
                if dhcp.relay_ip.is_some() {
                    return;
                }
                // Only a server-confirmed assignment binds: the ACK's yiaddr.
                // An OFFER may go unaccepted, and option 50 (requested IP) is
                // an unverified client claim — typically a roaming device's
                // stale lease from a different network.
                let confirmed_ip = (dhcp.msg_type == DhcpMsgType::Ack)
                    .then_some(dhcp.your_ip)
                    .flatten();
                if let Some(ip) = confirmed_ip {
                    self.bind_authoritative(dhcp.client_mac, IpAddr::V4(ip));
                    // Option 1 gives the real subnet mask — learn the actual
                    // segment size, overriding the ARP /24 guess.
                    if let Some(mask) = dhcp.subnet_mask {
                        self.learn_subnet(ip, u32::from(mask));
                    }
                }
                self.record_local_host(dhcp.client_mac, confirmed_ip.map(IpAddr::V4), ts);
                if let Some(host) = dhcp.hostname.clone() {
                    self.attribute_hostname(
                        AssetKey::Mac(dhcp.client_mac),
                        host,
                        NameSource::Dhcp,
                        ts,
                    );
                }
                if let Some(asset) = self.asset_mut(AssetKey::Mac(dhcp.client_mac), ts) {
                    if !dhcp.param_req_list.is_empty() {
                        asset.dhcp_fingerprint = Some(dhcp.fingerprint());
                    }
                    if let Some(vendor) = &dhcp.vendor_class {
                        asset.vendor_class = Some(vendor.clone());
                    }
                }
            }
            AppEvent::Dns(dns) => {
                // A/AAAA answers name the *server* IP; attribute to its asset.
                for answer in &dns.answers {
                    let (ip, source) = match &answer.data {
                        DnsRData::A(ip) => (IpAddr::V4(*ip), source_for(dns.is_mdns)),
                        DnsRData::Aaaa(ip) => (IpAddr::V6(*ip), source_for(dns.is_mdns)),
                        _ => continue,
                    };
                    let key = self.key_for_ip(ip);
                    if let Some(asset) = self.asset_mut(key, ts) {
                        asset.ips.insert(ip);
                    }
                    self.attribute_hostname(key, answer.name.clone(), source, ts);
                }
            }
            AppEvent::Tls(hello) => {
                if let (Some(sni), Some((_, dst))) = (&hello.sni, pkt.ip_pair()) {
                    let key = self.key_for_ip(dst);
                    self.attribute_hostname(key, sni.clone(), NameSource::Tls, ts);
                }
            }
            AppEvent::Http(req) => {
                if let (Some(host), Some((_, dst))) = (&req.host, pkt.ip_pair()) {
                    let key = self.key_for_ip(dst);
                    self.attribute_hostname(key, host.clone(), NameSource::Http, ts);
                }
            }
        }
    }

    /// Add a hostname to an asset and count it if the per-asset cap dropped it
    /// — so a name flood from *any* source (DNS, mDNS, DHCP, TLS, HTTP) shows
    /// in `overflow.hostnames`, never silently. One home for all four sources.
    fn attribute_hostname(
        &mut self,
        key: AssetKey,
        name: String,
        source: NameSource,
        ts: Timestamp,
    ) {
        let cap = self.limits.max_hostnames_per_asset;
        let dropped = match self.asset_mut(key, ts) {
            Some(asset) => asset.add_hostname(name, source, cap),
            None => return, // asset-cap drop already counted by asset_mut
        };
        if dropped {
            self.overflow.hostnames = self.overflow.hostnames.saturating_add(1);
        }
    }

    /// Add a service to an asset and count it if the per-asset cap dropped it —
    /// a port scan against one host then shows in `overflow.services`, never a
    /// silently-truncated service list.
    fn attribute_service(
        &mut self,
        key: AssetKey,
        port: u16,
        proto: &'static str,
        evidence: ServiceEvidence,
        ts: Timestamp,
    ) {
        let cap = self.limits.max_services_per_asset;
        let dropped = match self.asset_mut(key, ts) {
            Some(asset) => asset.add_service(port, proto, evidence, cap),
            None => return,
        };
        if dropped {
            self.overflow.services = self.overflow.services.saturating_add(1);
        }
    }
}

const fn source_for(is_mdns: bool) -> NameSource {
    if is_mdns {
        NameSource::Mdns
    } else {
        NameSource::DnsAnswer
    }
}

/// Neither broadcast, multicast, nor unspecified — an attributable host.
fn is_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_broadcast() && !v4.is_multicast(),
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast(),
    }
}

impl Observe for AssetInventory {
    fn observe(&mut self, pkt: &PacketView<'_>, app: Option<&AppEvent>) {
        let ts = pkt.ts;

        // Layer 2/3 identity: bind the source MAC to its source IP, and record
        // both endpoints as local hosts.
        if let NetView::Arp(arp) = &pkt.net {
            self.observe_arp(arp, ts);
        }
        if let Some((src_ip, dst_ip)) = pkt.ip_pair() {
            // Only bind a MAC to an IP we believe shares its L2 segment.
            // Off-link IPs share the *router's* MAC, so binding them would
            // merge unrelated hosts; they stay IP-keyed instead.
            if self.is_local(src_ip) {
                self.bind(pkt.eth.src, src_ip);
                self.record_local_host(pkt.eth.src, Some(src_ip), ts);
            }
            if self.is_local(dst_ip) {
                self.bind(pkt.eth.dst, dst_ip);
                self.record_local_host(pkt.eth.dst, Some(dst_ip), ts);
            }
            // Record both as candidates regardless of *current* locality:
            // finalize() re-checks them against the final subnet set, so a
            // host seen before its subnet was learned is still MAC-keyed. The
            // router-MAC trap is avoided because finalize() also gates on
            // locality — an off-link IP's candidate is simply never applied.
            self.record_provisional(pkt.eth.src, src_ip, ts);
            self.record_provisional(pkt.eth.dst, dst_ip, ts);
        }

        // Service evidence from TCP: SYN-ACK proves a listener; otherwise a
        // SYN names the destination as an intended service.
        if let Some(TransportView::Tcp(tcp)) = &pkt.transport
            && let Some((src_ip, dst_ip)) = pkt.ip_pair()
        {
            if tcp.flags.is_syn_ack() {
                let key = self.key_for_ip(src_ip);
                self.attribute_service(key, tcp.src_port, "tcp", ServiceEvidence::SynAck, ts);
            } else if tcp.flags.is_initial_syn() && is_service_port(tcp.dst_port) {
                let key = self.key_for_ip(dst_ip);
                self.attribute_service(
                    key,
                    tcp.dst_port,
                    "tcp",
                    ServiceEvidence::PortHeuristic,
                    ts,
                );
            }
        }

        // Service evidence from UDP: there is no handshake, so direction
        // relative to a well-known port is the signal — a datagram FROM a
        // service port answering an ephemeral one is a listener responding.
        // Multicast/broadcast chatter (mDNS, SSDP, DHCP) is not attributed:
        // a multicast group is not a host running a service.
        if let Some(TransportView::Udp(udp)) = &pkt.transport
            && let Some((src_ip, dst_ip)) = pkt.ip_pair()
        {
            let src_svc = is_service_port(udp.src_port);
            let dst_svc = is_service_port(udp.dst_port);
            if src_svc && !dst_svc && is_unicast(src_ip) && is_unicast(dst_ip) {
                let key = self.key_for_ip(src_ip);
                self.attribute_service(key, udp.src_port, "udp", ServiceEvidence::UdpResponse, ts);
            } else if dst_svc && !src_svc && is_unicast(dst_ip) {
                let key = self.key_for_ip(dst_ip);
                self.attribute_service(
                    key,
                    udp.dst_port,
                    "udp",
                    ServiceEvidence::PortHeuristic,
                    ts,
                );
            }
        }

        if let Some(event) = app {
            self.observe_app(pkt, event, ts);
            // Application banners are strong service evidence on the server.
            if let (AppEvent::Tls(_) | AppEvent::Http(_), Some((_, dst))) = (event, pkt.ip_pair())
                && let Some(TransportView::Tcp(tcp)) = &pkt.transport
            {
                let key = self.key_for_ip(dst);
                self.attribute_service(key, tcp.dst_port, "tcp", ServiceEvidence::AppLayer, ts);
            }
            // A unicast DNS answer from port 53 is application-layer proof of
            // a DNS service on the responder.
            if let (AppEvent::Dns(dns), Some((src, _))) = (event, pkt.ip_pair())
                && let Some(TransportView::Udp(udp)) = &pkt.transport
                && !dns.is_mdns
                && udp.src_port == 53
                && is_unicast(src)
            {
                let key = self.key_for_ip(src);
                self.attribute_service(key, 53, "udp", ServiceEvidence::AppLayer, ts);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn dhcp_subnet_mask_widens_beyond_a_slash_24() {
        // A /22 segment learned from DHCP option 1 must make a host in a
        // *different* /24 of that /22 count as local — the /24 guess would miss it.
        let mut inv = AssetInventory::new();
        inv.learn_subnet(Ipv4Addr::new(10, 0, 0, 5), 0xFFFF_FC00); // 10.0.0.0/22
        assert!(inv.is_local(v4(10, 0, 1, 7)), "10.0.1.7 is in 10.0.0.0/22");
        assert!(
            inv.is_local(v4(10, 0, 3, 200)),
            "10.0.3.200 is in 10.0.0.0/22"
        );
        assert!(
            !inv.is_local(v4(10, 0, 4, 1)),
            "10.0.4.1 is outside the /22"
        );
    }

    #[test]
    fn no_rfc1918_flip_flop() {
        // A private IP is NOT automatically local; classification depends only on
        // learned segments, so it cannot change as packets arrive in a different
        // order. (Previously an empty subnet set made all private IPs local.)
        let mut inv = AssetInventory::new();
        assert!(
            !inv.is_local(v4(192, 168, 1, 5)),
            "private != local without evidence"
        );

        // After an ARP-equivalent authoritative binding, only that /24 is local.
        inv.bind_authoritative(MacAddr([2, 0, 0, 0, 0, 1]), v4(192, 168, 1, 1));
        assert!(inv.is_local(v4(192, 168, 1, 5)), "now in a learned /24");
        assert!(
            !inv.is_local(v4(10, 0, 0, 5)),
            "a different private net stays off-link"
        );
    }

    #[test]
    fn off_link_public_ip_is_never_local() {
        let mut inv = AssetInventory::new();
        inv.bind_authoritative(MacAddr([2, 0, 0, 0, 0, 1]), v4(192, 168, 1, 1));
        assert!(
            !inv.is_local(v4(93, 184, 216, 34)),
            "public IP behind the router"
        );
    }

    /// Build a DHCP frame and run it through decode + sniff + observe, the
    /// same path the real pipeline takes.
    fn observe_dhcp(
        inv: &mut AssetInventory,
        msg_type: u8,
        mac: MacAddr,
        opts: &crate::fixtures::DhcpOptions<'_>,
    ) {
        let frame = crate::fixtures::Packet::ethernet(mac, MacAddr::BROADCAST)
            .ipv4(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST)
            .udp(68, 67)
            .payload(&crate::fixtures::dhcp(msg_type, mac, 0x42, opts));
        let record = crate::pcap::Record {
            ts: Timestamp::ZERO,
            orig_len: u32::try_from(frame.len()).unwrap_or(0),
            link_type: crate::pcap::LinkType::Ethernet,
            data: &frame,
        };
        let Ok(pkt) = crate::decode::decode_packet(&record) else {
            unreachable!("fixture frame must decode");
        };
        let app = crate::app::sniff(&pkt);
        inv.observe(&pkt, app.as_ref());
    }

    #[test]
    fn dhcp_client_claims_do_not_bind() {
        // Option 50 in a DISCOVER is an unverified client claim — a roaming
        // laptop's stale lease from another network must not bind nor seed a
        // local segment.
        let mut inv = AssetInventory::new();
        let mac = MacAddr([0x3C, 0, 0, 0, 0, 1]);
        let opts = crate::fixtures::DhcpOptions {
            requested_ip: Some(Ipv4Addr::new(172, 16, 9, 7)),
            ..crate::fixtures::DhcpOptions::default()
        };
        observe_dhcp(&mut inv, 1, mac, &opts); // DISCOVER
        assert!(
            !inv.is_local(v4(172, 16, 9, 200)),
            "client-claimed IP must not seed a local segment"
        );

        // An OFFER is a proposal, not a confirmed lease: still no binding.
        let offer = crate::fixtures::DhcpOptions {
            your_ip: Some(Ipv4Addr::new(192, 168, 5, 10)),
            ..crate::fixtures::DhcpOptions::default()
        };
        observe_dhcp(&mut inv, 2, mac, &offer);
        assert!(!inv.is_local(v4(192, 168, 5, 20)), "OFFER must not bind");

        // The ACK's yiaddr is server-confirmed: now it binds and seeds.
        observe_dhcp(&mut inv, 5, mac, &offer);
        assert!(inv.is_local(v4(192, 168, 5, 20)), "ACK binds");
    }

    #[test]
    fn implausible_masks_define_no_segment() {
        let mut inv = AssetInventory::new();
        // /1: one hostile ACK would otherwise mark half of IPv4 "local".
        inv.learn_subnet(Ipv4Addr::new(10, 0, 0, 1), 0x8000_0000);
        assert!(!inv.is_local(v4(10, 200, 0, 1)), "/1 must be rejected");
        // /7 still under the floor; /8 is the widest believable segment.
        inv.learn_subnet(Ipv4Addr::new(10, 0, 0, 1), 0xFE00_0000);
        assert!(!inv.is_local(v4(10, 200, 0, 1)), "/7 must be rejected");
        inv.learn_subnet(Ipv4Addr::new(10, 0, 0, 1), 0xFF00_0000);
        assert!(inv.is_local(v4(10, 200, 0, 1)), "/8 is accepted");
    }

    #[test]
    fn finalize_records_data_frames_only_hosts() {
        // A host seen only as data frames, whose segment is learned later:
        // finalize must both bind it AND create its inventory record, with
        // the first-seen time the provisional observed.
        let mut inv = AssetInventory::new();
        let mac = MacAddr([0x3C, 0, 0, 0, 0, 9]);
        let ip = v4(192, 168, 7, 42);
        inv.record_provisional(mac, ip, Timestamp::new(100, 0));
        inv.learn_subnet(Ipv4Addr::new(192, 168, 7, 1), 0xFFFF_FF00);
        inv.finalize();
        let assets = inv.assets();
        let asset = assets
            .iter()
            .find(|a| a.key == AssetKey::Mac(mac))
            .unwrap_or_else(|| unreachable!("host must appear in the inventory"));
        assert!(asset.ips.contains(&ip));
        assert_eq!(asset.first_seen, Timestamp::new(100, 0));
    }

    #[test]
    fn udp_response_is_service_evidence_but_multicast_is_not() {
        let mut inv = AssetInventory::new();
        let server = MacAddr([0xAA, 0, 0, 0, 0, 1]);
        let client = MacAddr([0xBB, 0, 0, 0, 0, 2]);
        // DNS server answers an ephemeral port: udp/53 service on the server.
        let frame = crate::fixtures::Packet::ethernet(server, client)
            .ipv4(Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 9))
            .udp(53, 51000)
            .payload(&[0u8; 16]);
        observe_frame(&mut inv, &frame);
        let assets = inv.assets();
        let dns_server = assets
            .iter()
            .find(|a| a.key == AssetKey::Ip(v4(10, 0, 0, 53)))
            .unwrap_or_else(|| unreachable!("server asset exists"));
        assert!(
            dns_server
                .services()
                .iter()
                .any(|s| s.port == 53 && s.proto == "udp"),
            "udp/53 must be inventoried"
        );

        // mDNS chatter to a multicast group must NOT become a "service".
        let mut inv = AssetInventory::new();
        let frame = crate::fixtures::Packet::ethernet(client, MacAddr([0x01, 0, 0x5E, 0, 0, 0xFB]))
            .ipv4(Ipv4Addr::new(10, 0, 0, 9), Ipv4Addr::new(224, 0, 0, 251))
            .udp(5353, 5353)
            .payload(&[0u8; 16]);
        observe_frame(&mut inv, &frame);
        assert!(
            inv.assets()
                .iter()
                .all(|a| a.key != AssetKey::Ip(v4(224, 0, 0, 251))),
            "multicast groups are not assets"
        );
    }

    #[test]
    fn ip_rebinding_is_counted_not_silent() {
        let mut inv = AssetInventory::new();
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        inv.bind_authoritative(MacAddr([2, 0, 0, 0, 0, 1]), IpAddr::V4(ip));
        assert_eq!(inv.overflow().rebound_ips, 0);
        // Same IP claimed by a different MAC: churn/failover/spoof — counted.
        inv.bind_authoritative(MacAddr([2, 0, 0, 0, 0, 2]), IpAddr::V4(ip));
        assert_eq!(inv.overflow().rebound_ips, 1);
    }

    /// Decode + sniff + observe an arbitrary fixture frame — the same path
    /// the real pipeline takes.
    fn observe_frame(inv: &mut AssetInventory, frame: &[u8]) {
        let record = crate::pcap::Record {
            ts: Timestamp::ZERO,
            orig_len: u32::try_from(frame.len()).unwrap_or(0),
            link_type: crate::pcap::LinkType::Ethernet,
            data: frame,
        };
        let Ok(pkt) = crate::decode::decode_packet(&record) else {
            unreachable!("fixture frame must decode");
        };
        let app = crate::app::sniff(&pkt);
        inv.observe(&pkt, app.as_ref());
    }

    #[test]
    fn relayed_dhcp_does_not_learn_remote_segment() {
        // An ACK relayed from another segment (giaddr set) carries a remote
        // yiaddr and the remote subnet's real mask. Learning it as local
        // would merge every routed host of that segment into the router MAC.
        let mut inv = AssetInventory::new();
        let opts = crate::fixtures::DhcpOptions {
            your_ip: Some(Ipv4Addr::new(10, 9, 0, 50)),
            subnet_mask: Some(Ipv4Addr::new(255, 255, 0, 0)),
            relay_ip: Some(Ipv4Addr::new(10, 9, 0, 1)),
            ..crate::fixtures::DhcpOptions::default()
        };
        observe_dhcp(&mut inv, 5, MacAddr([0x3C, 0, 0, 0, 0, 2]), &opts);
        assert!(
            !inv.is_local(v4(10, 9, 3, 3)),
            "relayed exchange must not mark a remote segment local"
        );
    }
}
