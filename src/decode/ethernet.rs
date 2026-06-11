//! Ethernet II framing, including stacked 802.1Q/802.1ad VLAN tags.
#![deny(clippy::arithmetic_side_effects)]

use crate::bytes::Cursor;
use crate::error::DecodeError;
use crate::types::MacAddr;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

const ETHERTYPE_VLAN_C: u16 = 0x8100; // 802.1Q customer tag
const ETHERTYPE_VLAN_S: u16 = 0x88A8; // 802.1ad service tag (QinQ)
const ETHERTYPE_VLAN_LEGACY_QINQ: u16 = 0x9100;
// Pre-standard QinQ TPIDs still emitted by some metro-Ethernet gear.
const ETHERTYPE_VLAN_LEGACY_QINQ2: u16 = 0x9200;
const ETHERTYPE_VLAN_LEGACY_QINQ3: u16 = 0x9300;

/// Up to four stacked VLAN IDs without heap allocation.
#[derive(Debug, Clone, Copy, Default)]
pub struct VlanStack {
    ids: [u16; 4],
    len: u8,
}

impl VlanStack {
    const fn is_full(&self) -> bool {
        self.len >= 4
    }

    /// No-op when full — the walk checks `is_full` first and degrades.
    fn push(&mut self, vid: u16) {
        if let Some(slot) = self.ids.get_mut(usize::from(self.len)) {
            *slot = vid;
            self.len = self.len.saturating_add(1);
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.ids.iter().copied().take(usize::from(self.len))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EthView {
    pub dst: MacAddr,
    pub src: MacAddr,
    /// `EtherType` after any VLAN tags — the type of the actual payload.
    pub ethertype: u16,
    pub vlan: VlanStack,
}

/// Parse the Ethernet header, leaving `cur` at the network-layer payload.
pub fn parse(cur: &mut Cursor<'_>) -> Result<EthView, DecodeError> {
    let dst = cur.mac()?;
    let src = cur.mac()?;
    let first = cur.u16_be()?;
    let (ethertype, vlan) = walk_vlan_chain(cur, first)?;

    Ok(EthView {
        dst,
        src,
        ethertype,
        vlan,
    })
}

/// Follow stacked 802.1Q/802.1ad tags from `first` to the real `EtherType`.
/// Shared with the Linux SLL/SLL2 link decoders, whose protocol field can
/// also be a VLAN TPID.
pub(crate) fn walk_vlan_chain(
    cur: &mut Cursor<'_>,
    first: u16,
) -> Result<(u16, VlanStack), DecodeError> {
    let mut ethertype = first;
    let mut vlan = VlanStack::default();
    while matches!(
        ethertype,
        ETHERTYPE_VLAN_C
            | ETHERTYPE_VLAN_S
            | ETHERTYPE_VLAN_LEGACY_QINQ
            | ETHERTYPE_VLAN_LEGACY_QINQ2
            | ETHERTYPE_VLAN_LEGACY_QINQ3
    ) {
        if vlan.is_full() {
            // Deeper than anything a real network stacks: stop and surface
            // what we decoded — the TPID becomes the (unknown) ethertype,
            // keeping the MACs and four tags instead of discarding the
            // whole frame as malformed.
            break;
        }
        let tci = cur.u16_be()?;
        vlan.push(tci & 0x0FFF);
        ethertype = cur.u16_be()?;
    }
    Ok((ethertype, vlan))
}
