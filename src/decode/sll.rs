//! Linux "cooked" capture link headers — what `tcpdump -i any` produces.
//!
//! Capturing on the pseudo-interface `any` can't use a real Ethernet header
//! (packets come from many interfaces), so libpcap writes a synthetic one:
//! `LINKTYPE_LINUX_SLL` (113, 16 bytes) or `LINKTYPE_LINUX_SLL2` (276,
//! 20 bytes, default since tcpdump 4.99). Only the *sender's* hardware
//! address is recorded — there is no destination MAC — so we synthesize an
//! [`EthView`] with `dst = MacAddr::ZERO`, and the asset layer keys those
//! hosts by IP exactly as it would for any host whose MAC is unknown.
#![deny(clippy::arithmetic_side_effects)]

use super::ethernet::{EthView, walk_vlan_chain};
use crate::bytes::Cursor;
use crate::error::DecodeError;
use crate::types::MacAddr;

/// `ARPHRD_ETHER` — the sender address is a 6-byte MAC.
const ARPHRD_ETHER: u16 = 1;

/// SLL v1 (16 bytes): packet type, ARPHRD, address length, 8 address bytes,
/// then the protocol (`EtherType` for Ethernet-style interfaces).
pub fn parse_v1(cur: &mut Cursor<'_>) -> Result<EthView, DecodeError> {
    cur.u16_be()?; // packet type (host/broadcast/outgoing/…)
    let arphrd = cur.u16_be()?;
    let addr_len = usize::from(cur.u16_be()?);
    let addr = cur.take(8)?;
    let first = cur.u16_be()?;
    finish(cur, arphrd, addr_len, addr, first)
}

/// SLL v2 (20 bytes): protocol comes *first*, then reserved, interface index,
/// ARPHRD, packet type, address length, 8 address bytes.
pub fn parse_v2(cur: &mut Cursor<'_>) -> Result<EthView, DecodeError> {
    let first = cur.u16_be()?;
    cur.u16_be()?; // reserved
    cur.u32_be()?; // interface index
    let arphrd = cur.u16_be()?;
    cur.u8()?; // packet type
    let addr_len = usize::from(cur.u8()?);
    let addr = cur.take(8)?;
    finish(cur, arphrd, addr_len, addr, first)
}

fn finish(
    cur: &mut Cursor<'_>,
    arphrd: u16,
    addr_len: usize,
    addr: &[u8],
    first: u16,
) -> Result<EthView, DecodeError> {
    // Trust the sender address only when it is a real 6-byte Ethernet MAC.
    let src = if arphrd == ARPHRD_ETHER && addr_len == 6 {
        let mut mac = [0u8; 6];
        if let Some(bytes) = addr.get(..6) {
            mac.copy_from_slice(bytes);
        }
        MacAddr(mac)
    } else {
        MacAddr::ZERO
    };

    let (ethertype, vlan) = walk_vlan_chain(cur, first)?;
    Ok(EthView {
        dst: MacAddr::ZERO, // cooked captures carry no destination address
        src,
        ethertype,
        vlan,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;

    fn sll1_header() -> Vec<u8> {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&0u16.to_be_bytes()); // packet type: to us
        hdr.extend_from_slice(&ARPHRD_ETHER.to_be_bytes());
        hdr.extend_from_slice(&6u16.to_be_bytes()); // address length
        hdr.extend_from_slice(&[0x3C, 0x22, 0xFB, 1, 2, 3, 0, 0]); // MAC + pad
        hdr.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        hdr
    }

    #[test]
    fn v1_extracts_sender_mac_and_ethertype() {
        let hdr = sll1_header();
        let mut cur = Cursor::new(&hdr);
        let eth = parse_v1(&mut cur).unwrap();
        assert_eq!(eth.src, MacAddr([0x3C, 0x22, 0xFB, 1, 2, 3]));
        assert_eq!(eth.dst, MacAddr::ZERO);
        assert_eq!(eth.ethertype, 0x0800);
    }

    #[test]
    fn v2_extracts_sender_mac_and_ethertype() {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&0x86DDu16.to_be_bytes()); // IPv6 — protocol first!
        hdr.extend_from_slice(&0u16.to_be_bytes()); // reserved
        hdr.extend_from_slice(&3u32.to_be_bytes()); // ifindex
        hdr.extend_from_slice(&ARPHRD_ETHER.to_be_bytes());
        hdr.push(0); // packet type
        hdr.push(6); // address length
        hdr.extend_from_slice(&[0xD0, 0x81, 0x7A, 4, 5, 6, 0, 0]);
        let mut cur = Cursor::new(&hdr);
        let eth = parse_v2(&mut cur).unwrap();
        assert_eq!(eth.src, MacAddr([0xD0, 0x81, 0x7A, 4, 5, 6]));
        assert_eq!(eth.ethertype, 0x86DD);
    }

    #[test]
    fn non_ethernet_arphrd_gets_zero_mac() {
        // e.g. ARPHRD_NONE / tunnel interfaces: address bytes are meaningless.
        let mut hdr = sll1_header();
        hdr[2] = 0xFF; // arphrd high byte → not ARPHRD_ETHER
        let mut cur = Cursor::new(&hdr);
        let eth = parse_v1(&mut cur).unwrap();
        assert_eq!(eth.src, MacAddr::ZERO);
        assert_eq!(eth.ethertype, 0x0800);
    }
}
