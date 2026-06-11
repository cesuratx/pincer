//! Link types that carry IP with no real link header.
//!
//! `LINKTYPE_RAW` (101): the packet *is* an IP datagram — produced by
//! VPN/tun interfaces. `LINKTYPE_NULL` (0) / `LINKTYPE_LOOP` (108): a 4-byte
//! address-family word (in the *capturing host's* byte order — both must be
//! tried) then the IP datagram — produced by BSD/macOS loopback captures.
//! Neither has MAC addresses; we synthesize an [`EthView`] with zero MACs and
//! the asset layer keys those hosts by IP.
#![deny(clippy::arithmetic_side_effects)]

use super::ethernet::EthView;
use crate::bytes::Cursor;
use crate::decode::ethernet::{ETHERTYPE_IPV4, ETHERTYPE_IPV6};
use crate::error::DecodeError;
use crate::types::MacAddr;

/// `LINKTYPE_RAW`: classify by the IP version nibble of the first byte.
pub fn parse_raw(cur: &mut Cursor<'_>) -> Result<EthView, DecodeError> {
    let first = cur
        .peek_first()
        .ok_or_else(|| DecodeError::truncated(1, 0))?;
    let ethertype = match first >> 4 {
        4 => ETHERTYPE_IPV4,
        6 => ETHERTYPE_IPV6,
        _ => return Err(DecodeError::malformed("rawip", "not an IP version nibble")),
    };
    Ok(synthetic(ethertype))
}

/// `AF_INET6` values across OSes (10 Linux, 24 FreeBSD/macOS, 28 NetBSD/
/// OpenBSD historic, 30 Darwin). `AF_INET` is 2 everywhere.
const AF_INET6_VALUES: [u32; 4] = [10, 24, 28, 30];

/// `LINKTYPE_NULL` / `LINKTYPE_LOOP`: 4-byte AF family, host byte order.
pub fn parse_null(cur: &mut Cursor<'_>) -> Result<EthView, DecodeError> {
    let family_bytes = cur.take(4)?;
    let mut quad = [0u8; 4];
    quad.copy_from_slice(family_bytes);
    let le = u32::from_le_bytes(quad);
    let be = u32::from_be_bytes(quad);

    // Try both byte orders — the family word is in the capturing host's order.
    let ethertype = if le == 2 || be == 2 {
        ETHERTYPE_IPV4
    } else if AF_INET6_VALUES.contains(&le) || AF_INET6_VALUES.contains(&be) {
        ETHERTYPE_IPV6
    } else {
        return Err(DecodeError::malformed("nullloop", "unknown address family"));
    };
    Ok(synthetic(ethertype))
}

fn synthetic(ethertype: u16) -> EthView {
    EthView {
        dst: MacAddr::ZERO,
        src: MacAddr::ZERO,
        ethertype,
        vlan: super::ethernet::VlanStack::default(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn raw_classifies_by_version_nibble() {
        let v4 = [0x45u8, 0, 0, 20];
        let mut cur = Cursor::new(&v4);
        assert_eq!(parse_raw(&mut cur).unwrap().ethertype, ETHERTYPE_IPV4);
        assert_eq!(cur.pos(), 0, "raw IP starts at offset 0 — nothing consumed");

        let v6 = [0x60u8, 0, 0, 0];
        let mut cur = Cursor::new(&v6);
        assert_eq!(parse_raw(&mut cur).unwrap().ethertype, ETHERTYPE_IPV6);

        let garbage = [0x10u8];
        assert!(parse_raw(&mut Cursor::new(&garbage)).is_err());
        assert!(parse_raw(&mut Cursor::new(&[])).is_err());
    }

    #[test]
    fn null_loop_reads_family_in_either_byte_order() {
        // AF_INET little-endian (macOS loopback writes host order).
        let mut cur = Cursor::new(&[2, 0, 0, 0, 0x45]);
        assert_eq!(parse_null(&mut cur).unwrap().ethertype, ETHERTYPE_IPV4);
        assert_eq!(cur.pos(), 4, "family word consumed");

        // AF_INET big-endian (capture from a BE host).
        let mut cur = Cursor::new(&[0, 0, 0, 2, 0x45]);
        assert_eq!(parse_null(&mut cur).unwrap().ethertype, ETHERTYPE_IPV4);

        // Darwin AF_INET6 = 30, LE.
        let mut cur = Cursor::new(&[30, 0, 0, 0, 0x60]);
        assert_eq!(parse_null(&mut cur).unwrap().ethertype, ETHERTYPE_IPV6);

        assert!(parse_null(&mut Cursor::new(&[9, 9, 9, 9])).is_err());
    }
}
