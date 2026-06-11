//! ICMP / `ICMPv6` — type and code are all the analysis needs.
#![deny(clippy::arithmetic_side_effects)]

use crate::bytes::Cursor;
use crate::error::DecodeError;

#[derive(Debug, Clone, Copy)]
pub struct IcmpView {
    pub v6: bool,
    pub icmp_type: u8,
    pub code: u8,
}

pub fn parse(cur: &mut Cursor<'_>, v6: bool) -> Result<IcmpView, DecodeError> {
    let icmp_type = cur.u8()?;
    let code = cur.u8()?;
    cur.u16_be()?; // checksum — also enforces the 4-byte minimum header
    Ok(IcmpView {
        v6,
        icmp_type,
        code,
    })
}
