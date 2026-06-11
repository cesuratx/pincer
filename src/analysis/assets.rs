//! Asset inventory: fold packets into per-host records with identity evidence.
//!
//! A host on the local segment is keyed by its MAC (stable across DHCP
//! leases); a host we only see by IP (behind the router, off-link) is keyed by
//! IP. Hostnames and services carry their *evidence source* so the report can
//! show why we believe each fact — the discipline of attributing every
//! inference, which is what makes passive findings trustworthy.

use std::collections::btree_map::Entry;
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
    /// `None` when every sighting came from timestamp-less records (pcapng
    /// SPB) — absent, not the epoch.
    pub first_seen: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
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
    fn new(key: AssetKey, ts: Option<Timestamp>) -> Self {
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
    /// (hostnames, services, ips) the per-asset caps dropped, so
    /// promotion-time overflow is counted like any other.
    fn merge_from(
        &mut self,
        other: Self,
        cap_hostnames: usize,
        cap_services: usize,
        cap_ips: usize,
    ) -> (u64, u64, u64) {
        let (mut dropped_names, mut dropped_services, mut dropped_ips) = (0u64, 0u64, 0u64);
        self.macs.extend(other.macs);
        for ip in other.ips {
            if self.add_ip(ip, cap_ips) {
                dropped_ips = dropped_ips.saturating_add(1);
            }
        }
        for (name, source) in other.hostnames {
            if self.add_hostname(&name, source, cap_hostnames) {
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
        self.first_seen = Timestamp::min_opt(self.first_seen, other.first_seen);
        self.last_seen = self.last_seen.max(other.last_seen);
        (dropped_names, dropped_services, dropped_ips)
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

    /// Returns `true` if a name was *dropped* at the per-asset cap (so the
    /// inventory can count it) — degradation is never silent. Borrowed `name`:
    /// the steady state (the same mDNS name re-announced every packet) is a
    /// pure map probe; the String is allocated only on the insert path.
    fn add_hostname(&mut self, name: &str, source: NameSource, cap: usize) -> bool {
        if name.is_empty() {
            return false;
        }
        if let Some(existing) = self.hostnames.get_mut(name) {
            if source < *existing {
                *existing = source;
            }
            return false;
        }
        // mDNS/DNS name-flood backstop: bound distinct names per asset. At
        // the cap, keep the lexicographically-smallest `cap` names — a new
        // name is admitted only by evicting a larger one — so WHICH names
        // survive a flood is a function of the name set, not arrival order.
        // (Key order, not evidence grade: any deterministic choice beats
        // first-come under a flood.) Either way the cap dropped a name.
        if self.hostnames.len() >= cap {
            if self
                .hostnames
                .last_key_value()
                .is_none_or(|(largest, _)| name >= largest.as_str())
            {
                return true;
            }
            self.hostnames.pop_last();
            self.hostnames.insert(name.to_owned(), source);
            return true;
        }
        self.hostnames.insert(name.to_owned(), source);
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
        // upgrade evidence on known services, and a new service is admitted
        // only by evicting the largest (port, proto) key — the kept set is
        // the smallest `cap` keys offered, independent of arrival order.
        if let Some(existing) = self.services.get_mut(&(port, proto)) {
            if evidence < *existing {
                *existing = evidence;
            }
            return false;
        }
        if self.services.len() >= cap {
            if self
                .services
                .last_key_value()
                .is_none_or(|(largest, _)| (port, proto) >= *largest)
            {
                return true;
            }
            self.services.pop_last();
            self.services.insert((port, proto), evidence);
            return true;
        }
        self.services.insert((port, proto), evidence);
        false
    }

    /// Returns `true` if the per-asset cap dropped an IP. One MAC spraying
    /// fresh addresses — ARP claims run `record_local_host` per packet even
    /// when `bind()` dropped at its cap — would otherwise grow this one set
    /// with the streamed file. At the cap, the smallest `cap` IPs are kept
    /// (a new IP evicts a larger one), order-independently.
    fn add_ip(&mut self, ip: IpAddr, cap: usize) -> bool {
        if self.ips.contains(&ip) {
            return false;
        }
        if self.ips.len() >= cap {
            if self.ips.last().is_none_or(|largest| ip >= *largest) {
                return true;
            }
            self.ips.pop_last();
            self.ips.insert(ip);
            return true;
        }
        self.ips.insert(ip);
        false
    }
}

/// Tallies of what hostile floods forced us to drop — surfaced in reports so
/// degradation is visible, never silent. Each counter tallies capped *events*
/// (admissions refused plus evictions made for a smaller key), so a nonzero
/// value always means its cap engaged; the exact value can vary with packet
/// order even though the surviving sets do not.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct AssetOverflow {
    pub assets: u64,
    pub bindings: u64,
    pub subnets: u64,
    pub hostnames: u64,
    pub services: u64,
    /// IPs dropped at the per-asset `max_ips_per_asset` cap.
    pub ips: u64,
    /// IPs whose MAC binding changed mid-capture (DHCP churn, VRRP failover,
    /// spoofing) — flow attribution for these resolves through the *final*
    /// binding and is therefore ambiguous.
    pub rebound_ips: u64,
}

impl AssetOverflow {
    #[must_use]
    pub fn any(&self) -> bool {
        self.assets | self.bindings | self.subnets | self.hostnames | self.services | self.ips != 0
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
/// IP-keyed; resolver-style DNS naming is accepted only once the shared
/// segment has been learned, so it can depend on where in the capture that
/// happens; IPv6 locality covers link-local/ULA only (global SLAAC addresses
/// on the segment are not recognized without NDP parsing).
///
/// Every collection here is capped (see [`Limits`]); a hostile capture hits
/// the cap and increments an [`AssetOverflow`] counter rather than exhausting
/// memory. Caps admit by *key order*, not arrival order: at a cap, a new key
/// replaces the largest admitted one only if it sorts before it, so the
/// surviving assets/bindings/subnets are the smallest N keys the capture
/// offered, identical across packet reorderings. Residual order dependence
/// under an engaged cap is confined to evidence already routed *through* a
/// binding or asset that a smaller key later evicted (merged evidence cannot
/// be unmerged, so such a host may split into MAC- and IP-keyed records) —
/// and it always comes with nonzero overflow counters, so capped output is
/// never mistaken for canonical.
#[derive(Debug)]
pub struct AssetInventory {
    /// asset key -> asset.
    assets: BTreeMap<AssetKey, Asset>,
    /// IP -> owning MAC (authoritative ARP/DHCP claims, plus data-frame
    /// candidates confirmed by [`AssetInventory::finalize`]).
    ip_to_mac: BTreeMap<IpAddr, MacAddr>,
    /// Local IPv4 segments grouped by mask: `mask -> {network}`. Grouping by
    /// mask makes `is_local` `O(distinct_masks · log n)` — distinct masks are
    /// a tiny handful — instead of `O(total_subnets)` per packet.
    local_v4_subnets: BTreeMap<u32, BTreeSet<u32>>,
    subnet_count: usize,
    /// Candidate `IP → (MAC, first ts, last ts)` sightings from data frames,
    /// to be confirmed against the *final* subnet knowledge in
    /// [`AssetInventory::finalize`]. Data frames make no mid-stream binding
    /// or inventory claim at all — deciding per-packet made membership and
    /// keying depend on whether a host's frames preceded the ARP/DHCP that
    /// taught its segment. The sighting window (first/last) carries the
    /// host's honest seen times to the deferred record.
    provisional: BTreeMap<IpAddr, (MacAddr, Option<Timestamp>, Option<Timestamp>)>,
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

    /// Resolve provisional data-frame sightings against the *complete* subnet
    /// knowledge, making the inventory order-independent — this is the only
    /// place data frames bind or enter the inventory. Idempotent. Call once
    /// after the streaming pass and before reading [`AssetInventory::assets`].
    /// Deterministic for a given packet set: the provisional/subnet/binding
    /// survivor sets are order-independent (smallest-N eviction) and the loop
    /// walks `provisional` in key order.
    pub fn finalize(&mut self) {
        if self.finalized {
            return;
        }
        self.finalized = true;
        // Snapshot to satisfy the borrow checker; provisional is bounded by
        // max_bindings, so this is a small, one-time pass.
        let pending: Vec<(IpAddr, MacAddr, Option<Timestamp>, Option<Timestamp>)> = self
            .provisional
            .iter()
            .filter(|(ip, _)| self.is_local(**ip))
            .map(|(ip, (mac, first, last))| (*ip, *mac, *first, *last))
            .collect();
        for (ip, mac, first, last) in pending {
            // An already-authoritative binding is a free refresh; a conflict
            // is the counted rebind ambiguity, same as a late ARP would be.
            self.bind(mac, ip);
            // Record the host with the window its data frames actually
            // spanned — two folds: min via `first`, max via `last`.
            self.record_local_host(mac, Some(ip), first);
            self.record_local_host(mac, None, last);
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
    /// Call [`AssetInventory::finalize`] first (the CLI always does): data
    /// frames enter the inventory only there, so a caller that skips it sees
    /// no hosts that were observed solely as data-frame endpoints.
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
        // unbounded (the empty-BTreeSet-per-mask leak the audit caught — a
        // drained mask bucket is removed for the same reason). At the cap a
        // new (mask, network) pair is admitted only by evicting the largest
        // admitted pair, so the learned segments are the smallest
        // `max_subnets` pairs the capture offered, in any packet order.
        if self.subnet_count >= self.limits.max_subnets {
            self.overflow.subnets = self.overflow.subnets.saturating_add(1);
            let largest = self
                .local_v4_subnets
                .last_key_value()
                .and_then(|(m, nets)| nets.last().map(|n| (*m, *n)));
            let Some((lmask, lnet)) = largest.filter(|l| (mask, network) < *l) else {
                return;
            };
            if let Some(nets) = self.local_v4_subnets.get_mut(&lmask) {
                nets.remove(&lnet);
                if nets.is_empty() {
                    self.local_v4_subnets.remove(&lmask);
                }
            }
            self.subnet_count = self.subnet_count.saturating_sub(1);
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
        // free; only a brand-new IP touches the cap. At the cap a new IP is
        // admitted only by evicting the largest bound IP, so the surviving
        // bindings are the smallest `max_bindings` IPs offered, in any packet
        // order. (An evicted IP's already-merged evidence stays on its MAC
        // asset while later evidence keys by IP — the residual split the
        // type-level docs call out.) An ARP-spoof storm claiming millions of
        // fresh IPs still costs a bounded map plus a counter.
        let len = self.ip_to_mac.len();
        if len >= self.limits.max_bindings && !self.ip_to_mac.contains_key(&ip) {
            self.overflow.bindings = self.overflow.bindings.saturating_add(1);
            if self
                .ip_to_mac
                .last_key_value()
                .is_none_or(|(largest, _)| ip >= *largest)
            {
                return;
            }
            self.ip_to_mac.pop_last();
        }
        match self.ip_to_mac.entry(ip) {
            Entry::Occupied(mut entry) => {
                if *entry.get() == mac {
                    return; // unchanged refresh — the per-packet steady state
                }
                // An IP moving to a *different* MAC mid-capture (DHCP churn,
                // VRRP failover, or spoofing) means flow attribution for that
                // IP — which resolves through the final binding — is
                // ambiguous. Count it so the degradation report can say so
                // instead of silently misattributing.
                self.overflow.rebound_ips = self.overflow.rebound_ips.saturating_add(1);
                entry.insert(mac);
            }
            Entry::Vacant(entry) => {
                entry.insert(mac);
            }
        }
        // First binding (or a MAC change): fold any record we built while the
        // host was only known by IP into the MAC-keyed asset. Without this, a
        // host named (DNS/mDNS) before its ARP/DHCP binding splits into two
        // assets and the inventory becomes order-dependent.
        self.promote_ip_asset(ip, mac);
    }

    /// Note a candidate IP→MAC sighting on a data frame. Unlike [`bind`],
    /// this makes no locality claim — [`AssetInventory::finalize`] decides,
    /// once all subnets are known. Bounded by `max_bindings` with the same
    /// smallest-N eviction (and the same comparator) as [`bind`], so the
    /// candidates finalize sees — and therefore the bindings it confirms —
    /// are order-independent; drops are counted under bindings, not silent.
    fn record_provisional(&mut self, mac: MacAddr, ip: IpAddr, ts: Option<Timestamp>) {
        if mac == MacAddr::BROADCAST || mac.is_multicast() || mac == MacAddr::ZERO {
            return;
        }
        if !is_unicast(ip) {
            return;
        }
        let len = self.provisional.len();
        if len >= self.limits.max_bindings && !self.provisional.contains_key(&ip) {
            self.overflow.bindings = self.overflow.bindings.saturating_add(1);
            if self
                .provisional
                .last_key_value()
                .is_none_or(|(largest, _)| ip >= *largest)
            {
                return;
            }
            self.provisional.pop_last();
        }
        match self.provisional.entry(ip) {
            Entry::Occupied(mut entry) => {
                let (_, first, last) = entry.get_mut();
                *first = Timestamp::min_opt(*first, ts);
                *last = (*last).max(ts);
            }
            Entry::Vacant(entry) => {
                entry.insert((mac, ts, ts));
            }
        }
    }

    /// Merge an `Ip(ip)`-keyed asset into the `Mac(mac)`-keyed asset, then drop
    /// the IP-keyed one. No-op if there is nothing to merge.
    fn promote_ip_asset(&mut self, ip: IpAddr, mac: MacAddr) {
        let Some(orphan) = self.assets.remove(&AssetKey::Ip(ip)) else {
            return;
        };
        let ts = orphan.first_seen;
        let (ch, cs, ci) = (
            self.limits.max_hostnames_per_asset,
            self.limits.max_services_per_asset,
            self.limits.max_ips_per_asset,
        );
        // `asset_mut` may return None only at the asset cap; since we just
        // removed one, there is room for the MAC-keyed target.
        let mut dropped = (0u64, 0u64, 0u64);
        if let Some(target) = self.asset_mut(AssetKey::Mac(mac), ts) {
            dropped = target.merge_from(orphan, ch, cs, ci);
            target.macs.insert(mac);
            if target.add_ip(ip, ci) {
                dropped.2 = dropped.2.saturating_add(1);
            }
        }
        self.overflow.hostnames = self.overflow.hostnames.saturating_add(dropped.0);
        self.overflow.services = self.overflow.services.saturating_add(dropped.1);
        self.overflow.ips = self.overflow.ips.saturating_add(dropped.2);
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

    /// Do these two IPs sit on one *learned* local segment? This is the trust
    /// bound for resolver-style DNS answers: a local DNS server may name its
    /// same-segment neighbors, but never an off-link IP. IPv4 requires a
    /// shared learned subnet (DHCP option 1 or the ARP /24 guess); IPv6 reuses
    /// the [`AssetInventory::is_local`] rule — link-local/ULA addresses seen
    /// in one single-link capture share that link.
    fn same_local_segment(&self, a: IpAddr, b: IpAddr) -> bool {
        match (a, b) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let (a, b) = (u32::from(a), u32::from(b));
                self.local_v4_subnets
                    .iter()
                    .any(|(&mask, nets)| a & mask == b & mask && nets.contains(&(a & mask)))
            }
            (IpAddr::V6(_), IpAddr::V6(_)) => self.is_local(a) && self.is_local(b),
            _ => false,
        }
    }

    /// Get or create an asset, folding `ts` into the seen window either way —
    /// first/last-seen are the min/max over every evidence event, never
    /// first-event-wins, so they cannot depend on arrival order. Returns
    /// `None` when the inventory is at `max_assets` and this new identity
    /// sorts after every admitted one; at the cap a new identity is otherwise
    /// admitted by evicting the largest admitted key (with its evidence), so
    /// a random-source-IP flood costs bounded memory and WHICH assets survive
    /// is a function of the identity set, not arrival order. `Mac` sorts
    /// before `Ip`, so MAC-identified hosts are preferentially retained.
    /// Refusals and evictions both count under `overflow.assets`.
    fn asset_mut(&mut self, key: AssetKey, ts: Option<Timestamp>) -> Option<&mut Asset> {
        let len = self.assets.len();
        if len >= self.limits.max_assets && !self.assets.contains_key(&key) {
            self.overflow.assets = self.overflow.assets.saturating_add(1);
            if self
                .assets
                .last_key_value()
                .is_none_or(|(largest, _)| key >= *largest)
            {
                return None;
            }
            self.assets.pop_last();
        }
        let asset = match self.assets.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(Asset::new(key, ts)),
        };
        asset.first_seen = Timestamp::min_opt(asset.first_seen, ts);
        asset.last_seen = asset.last_seen.max(ts);
        Some(asset)
    }

    fn record_local_host(&mut self, mac: MacAddr, ip: Option<IpAddr>, ts: Option<Timestamp>) {
        if mac == MacAddr::BROADCAST || mac.is_multicast() || mac == MacAddr::ZERO {
            return;
        }
        let cap = self.limits.max_ips_per_asset;
        // `asset_mut` folds `ts` into the first/last-seen window.
        let Some(asset) = self.asset_mut(AssetKey::Mac(mac), ts) else {
            return;
        };
        asset.macs.insert(mac);
        let dropped = ip
            .filter(|ip| !ip.is_unspecified() && !ip.is_multicast())
            .is_some_and(|ip| asset.add_ip(ip, cap));
        if dropped {
            self.overflow.ips = self.overflow.ips.saturating_add(1);
        }
    }

    fn observe_arp(&mut self, arp: &ArpView, ts: Option<Timestamp>) {
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

    fn observe_app(&mut self, pkt: &PacketView<'_>, app: &AppEvent, ts: Option<Timestamp>) {
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
                if let Some(host) = dhcp.hostname.as_deref() {
                    self.attribute_hostname(
                        AssetKey::Mac(dhcp.client_mac),
                        host,
                        NameSource::Dhcp,
                        ts,
                    );
                }
                if let Some(asset) = self.asset_mut(AssetKey::Mac(dhcp.client_mac), ts) {
                    // Compare before replacing: the steady state (the same
                    // device re-DHCPing with an unchanged option 55 / vendor
                    // class) must not re-allocate per packet; a changed value
                    // still updates — last wins, as before.
                    if !dhcp.param_req_list.is_empty()
                        && !fingerprint_unchanged(
                            asset.dhcp_fingerprint.as_deref(),
                            &dhcp.param_req_list,
                        )
                    {
                        asset.dhcp_fingerprint = Some(dhcp.fingerprint());
                    }
                    if let Some(vendor) = dhcp.vendor_class.as_deref()
                        && asset.vendor_class.as_deref() != Some(vendor)
                    {
                        asset.vendor_class = Some(vendor.to_owned());
                    }
                }
            }
            AppEvent::Dns(dns) => {
                // A/AAAA answers are unauthenticated bytes naming a *claimed*
                // IP. Two gates before any inventory write. First: only
                // responses carry naming evidence — answer records riding on
                // a query (qr=0) are either a poisoning attempt or mDNS
                // known-answer suppression (the querier's cache, not a
                // claim). Second: trust a host to name *itself* (mDNS
                // announces, the normal case), or — resolver-style — a
                // neighbor on the same learned local segment; a record
                // claiming an off-segment IP would let any spoofed datagram
                // rewrite an arbitrary victim's reported identity.
                if !dns.is_response {
                    return;
                }
                let Some((src, _)) = pkt.ip_pair() else {
                    return;
                };
                for answer in &dns.answers {
                    let (ip, source) = match &answer.data {
                        DnsRData::A(ip) => (IpAddr::V4(*ip), source_for(dns.is_mdns)),
                        DnsRData::Aaaa(ip) => (IpAddr::V6(*ip), source_for(dns.is_mdns)),
                        _ => continue,
                    };
                    // is_unicast on both sides: a claimed broadcast address
                    // falls inside its segment's learned subnet, and a
                    // multicast "host" is not an asset.
                    if !is_unicast(ip) || !is_unicast(src) {
                        continue;
                    }
                    if ip != src && !self.same_local_segment(src, ip) {
                        continue;
                    }
                    let cap = self.limits.max_ips_per_asset;
                    let key = self.key_for_ip(ip);
                    let dropped = match self.asset_mut(key, ts) {
                        Some(asset) => asset.add_ip(ip, cap),
                        None => false, // asset-cap drop already counted
                    };
                    if dropped {
                        self.overflow.ips = self.overflow.ips.saturating_add(1);
                    }
                    self.attribute_hostname(key, &answer.name, source, ts);
                }
            }
            AppEvent::Tls(hello) => {
                if let (Some(sni), Some((_, dst))) = (hello.sni.as_deref(), pkt.ip_pair()) {
                    let key = self.key_for_ip(dst);
                    self.attribute_hostname(key, sni, NameSource::Tls, ts);
                }
            }
            AppEvent::Http(req) => {
                if let (Some(host), Some((_, dst))) = (req.host.as_deref(), pkt.ip_pair()) {
                    let key = self.key_for_ip(dst);
                    self.attribute_hostname(key, host, NameSource::Http, ts);
                }
            }
        }
    }

    /// Add a hostname to an asset and count it if the per-asset cap dropped it
    /// — so a name flood from *any* source (DNS, mDNS, DHCP, TLS, HTTP) shows
    /// in `overflow.hostnames`, never silently. One home for all four sources.
    /// Borrowed `name`: only [`Asset::add_hostname`]'s insert path allocates.
    fn attribute_hostname(
        &mut self,
        key: AssetKey,
        name: &str,
        source: NameSource,
        ts: Option<Timestamp>,
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
        ts: Option<Timestamp>,
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

/// Is `stored` exactly [`crate::app::DhcpSummary::fingerprint`] of `list`,
/// decided without building the string? `fingerprint()` output is canonical
/// decimal (no signs, no leading zeros), so the numeric per-part comparison
/// is exact — and the steady state (unchanged option 55) costs no allocation.
fn fingerprint_unchanged(stored: Option<&str>, list: &[u8]) -> bool {
    let Some(stored) = stored else {
        return false;
    };
    let mut parts = stored.split(',');
    list.iter()
        .all(|code| parts.next().and_then(|part| part.parse::<u8>().ok()) == Some(*code))
        && parts.next().is_none()
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

        // Layer 2/3 identity. ARP speaks authoritatively about its own
        // segment, so it binds and records immediately.
        if let NetView::Arp(arp) = &pkt.net {
            self.observe_arp(arp, ts);
        }
        if let Some((src_ip, dst_ip)) = pkt.ip_pair() {
            // Data frames only nominate candidates: whether an IP shares its
            // frame's L2 segment can be judged only against the COMPLETE
            // subnet knowledge, so finalize() binds and records the local
            // ones at the end. Deciding per-packet made membership and keying
            // depend on whether a host's frames preceded the ARP/DHCP that
            // taught its segment. The router-MAC trap is avoided because
            // finalize() gates on locality — an off-link IP's candidate is
            // simply never applied.
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
            ts: Some(Timestamp::ZERO),
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
    fn dhcp_fingerprint_and_vendor_class_track_the_latest_packet() {
        // Compare-before-replace must stay last-wins, not become first-wins:
        // an unchanged repeat is a no-op, a changed option 55 list / vendor
        // class still updates the asset.
        let mut inv = AssetInventory::new();
        let mac = MacAddr([0x3C, 0, 0, 0, 0, 7]);
        let first = crate::fixtures::DhcpOptions {
            vendor_class: Some("MSFT 5.0"),
            param_req_list: &[1, 3, 6],
            ..crate::fixtures::DhcpOptions::default()
        };
        observe_dhcp(&mut inv, 1, mac, &first);
        observe_dhcp(&mut inv, 1, mac, &first); // unchanged repeat
        let second = crate::fixtures::DhcpOptions {
            vendor_class: Some("android-dhcp-13"),
            param_req_list: &[1, 121, 3],
            ..crate::fixtures::DhcpOptions::default()
        };
        observe_dhcp(&mut inv, 1, mac, &second);
        let assets = inv.assets();
        let asset = assets
            .iter()
            .find(|a| a.key == AssetKey::Mac(mac))
            .unwrap_or_else(|| unreachable!("dhcp client must be inventoried"));
        assert_eq!(asset.dhcp_fingerprint.as_deref(), Some("1,121,3"));
        assert_eq!(asset.vendor_class.as_deref(), Some("android-dhcp-13"));
    }

    #[test]
    fn fingerprint_comparison_is_exact() {
        assert!(fingerprint_unchanged(Some("1,3,6"), &[1, 3, 6]));
        assert!(!fingerprint_unchanged(Some("1,3,6"), &[1, 3]));
        assert!(!fingerprint_unchanged(Some("1,3"), &[1, 3, 6]));
        assert!(!fingerprint_unchanged(Some("1,3,6"), &[1, 3, 7]));
        assert!(!fingerprint_unchanged(None, &[1]));
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
        inv.record_provisional(mac, ip, Some(Timestamp::new(100, 0)));
        inv.learn_subnet(Ipv4Addr::new(192, 168, 7, 1), 0xFFFF_FF00);
        inv.finalize();
        let assets = inv.assets();
        let asset = assets
            .iter()
            .find(|a| a.key == AssetKey::Mac(mac))
            .unwrap_or_else(|| unreachable!("host must appear in the inventory"));
        assert!(asset.ips.contains(&ip));
        assert_eq!(asset.first_seen, Some(Timestamp::new(100, 0)));
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
            ts: Some(Timestamp::ZERO),
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

    /// A DNS *query* (qr=0) that smuggles an A answer — the wire shape of a
    /// poisoning attempt (or mDNS known-answer suppression, which is the
    /// querier's cache, not a claim).
    fn dns_query_with_answer(name: &str, addr: Ipv4Addr) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&0x4242u16.to_be_bytes()); // id
        msg.extend_from_slice(&[0x00, 0x00]); // qr=0: a query...
        msg.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]); // ...carrying 1 answer
        msg.extend_from_slice(&crate::fixtures::dns_name(name));
        msg.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        msg.extend_from_slice(&60u32.to_be_bytes()); // ttl
        msg.extend_from_slice(&[0, 4]);
        msg.extend_from_slice(&addr.octets());
        msg
    }

    fn any_hostname(inv: &AssetInventory, name: &str) -> bool {
        inv.assets()
            .iter()
            .any(|a| a.hostnames.keys().any(|h| h == name))
    }

    #[test]
    fn dns_answers_riding_on_queries_attribute_nothing() {
        // Attacker and victim share a learned segment, so only the qr gate
        // stands between the smuggled record and the inventory.
        let mut inv = AssetInventory::new();
        inv.bind_authoritative(MacAddr([2, 0, 0, 0, 0, 1]), v4(10, 0, 0, 66));
        let frame = crate::fixtures::Packet::ethernet(
            MacAddr([2, 0, 0, 0, 0, 1]),
            MacAddr([0x01, 0, 0x5E, 0, 0, 0xFB]),
        )
        .ipv4(Ipv4Addr::new(10, 0, 0, 66), Ipv4Addr::new(224, 0, 0, 251))
        .udp(5353, 5353)
        .payload(&dns_query_with_answer(
            "evil.local",
            Ipv4Addr::new(10, 0, 0, 9),
        ));
        observe_frame(&mut inv, &frame);
        assert!(
            !any_hostname(&inv, "evil.local"),
            "a query carrying answer records must attribute nothing"
        );
    }

    #[test]
    fn dns_answer_naming_off_segment_ip_is_not_attributed() {
        // ARP teaches 192.168.1.0/24; the on-segment attacker then "responds"
        // with `evil.example IN A <off-segment victim>`. The claimed IP is
        // neither the speaker nor on a learned segment: no attribution, and
        // the forged record must not even create the victim's asset.
        let mut inv = AssetInventory::new();
        let attacker = MacAddr([2, 0, 0, 0, 0, 0x66]);
        let victim_ip = v4(93, 184, 216, 34);
        let arp = crate::fixtures::Packet::ethernet(attacker, MacAddr::BROADCAST).arp_reply(
            Ipv4Addr::new(192, 168, 1, 66),
            MacAddr([2, 0, 0, 0, 0, 2]),
            Ipv4Addr::new(192, 168, 1, 9),
        );
        observe_frame(&mut inv, &arp);
        let frame = crate::fixtures::Packet::ethernet(attacker, MacAddr([2, 0, 0, 0, 0, 2]))
            .ipv4(
                Ipv4Addr::new(192, 168, 1, 66),
                Ipv4Addr::new(192, 168, 1, 9),
            )
            .udp(53, 51000)
            .payload(&crate::fixtures::dns_response_a(
                7,
                "evil.example",
                Ipv4Addr::new(93, 184, 216, 34),
            ));
        observe_frame(&mut inv, &frame);
        assert!(
            !any_hostname(&inv, "evil.example"),
            "an off-segment claim must not name the victim"
        );
        assert!(
            inv.assets()
                .iter()
                .all(|a| a.key != AssetKey::Ip(victim_ip)),
            "a forged record must not create the victim's asset"
        );
    }

    #[test]
    fn mdns_self_announcement_still_attributes() {
        // The normal mDNS case: a host announces its own A record. Source IP
        // equals the claimed IP, so this passes with no segment learned at
        // all — keeping attribution order-independent for self-claims.
        let mut inv = AssetInventory::new();
        let phone = MacAddr([0xD0, 0x81, 0x7A, 0, 0, 7]);
        let ip = Ipv4Addr::new(192, 168, 1, 77);
        let frame = crate::fixtures::Packet::ethernet(phone, MacAddr([0x01, 0, 0x5E, 0, 0, 0xFB]))
            .ipv4(ip, Ipv4Addr::new(224, 0, 0, 251))
            .udp(5353, 5353)
            .payload(&crate::fixtures::mdns_announce_a("franks-iphone.local", ip));
        observe_frame(&mut inv, &frame);
        let asset = inv
            .assets()
            .into_iter()
            .find(|a| a.ips.contains(&IpAddr::V4(ip)))
            .unwrap_or_else(|| unreachable!("self-announced asset must exist"));
        assert!(
            asset.hostnames.keys().any(|h| h == "franks-iphone.local"),
            "a self-announcement must still attribute"
        );
    }

    #[test]
    fn local_resolver_may_name_same_segment_neighbors() {
        // Resolver-style cross-host naming is kept *within* a learned
        // segment: the gateway's DNS answers `printer.lan IN A 192.168.1.30`
        // and the printer's asset gets the name.
        let mut inv = AssetInventory::new();
        inv.bind_authoritative(MacAddr([0xAA, 0, 0xCC, 0, 0, 1]), v4(192, 168, 1, 1));
        let frame = crate::fixtures::Packet::ethernet(
            MacAddr([0xAA, 0, 0xCC, 0, 0, 1]),
            MacAddr([0x3C, 0, 0, 0, 0, 1]),
        )
        .ipv4(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 10),
        )
        .udp(53, 51000)
        .payload(&crate::fixtures::dns_response_a(
            9,
            "printer.lan",
            Ipv4Addr::new(192, 168, 1, 30),
        ));
        observe_frame(&mut inv, &frame);
        let printer = inv
            .assets()
            .into_iter()
            .find(|a| a.ips.contains(&v4(192, 168, 1, 30)))
            .unwrap_or_else(|| unreachable!("printer asset must exist"));
        assert!(printer.hostnames.keys().any(|h| h == "printer.lan"));
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
