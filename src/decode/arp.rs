//! ARP for IPv4-over-Ethernet — the protocol that hands us authoritative
//! MAC ↔ IP bindings for the asset inventory.
#![deny(clippy::arithmetic_side_effects)]

use std::net::Ipv4Addr;

use crate::bytes::Cursor;
use crate::error::DecodeError;
use crate::types::MacAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOp {
    Request,
    Reply,
    Other(u16),
}

#[derive(Debug, Clone, Copy)]
pub struct ArpView {
    pub op: ArpOp,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

pub fn parse(cur: &mut Cursor<'_>) -> Result<ArpView, DecodeError> {
    let htype = cur.u16_be()?;
    let ptype = cur.u16_be()?;
    let hlen = cur.u8()?;
    let plen = cur.u8()?;
    if htype != 1 || ptype != super::ethernet::ETHERTYPE_IPV4 || hlen != 6 || plen != 4 {
        // Spec-valid ARP for pairs we do not decode (InfiniBand, IPX, ...).
        // decode::mod matches this exact reason to classify the packet as
        // Unknown rather than Malformed — it is not a lying packet.
        return Err(DecodeError::malformed(
            "arp",
            "unsupported hardware/protocol",
        ));
    }

    let op = match cur.u16_be()? {
        1 => ArpOp::Request,
        2 => ArpOp::Reply,
        other => ArpOp::Other(other),
    };

    Ok(ArpView {
        op,
        sender_mac: cur.mac()?,
        sender_ip: cur.ipv4()?,
        target_mac: cur.mac()?,
        target_ip: cur.ipv4()?,
    })
}
