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

impl IcmpView {
    /// Echo request/reply — visible host-liveness probing.
    #[must_use]
    pub const fn is_echo(&self) -> bool {
        if self.v6 {
            matches!(self.icmp_type, 128 | 129)
        } else {
            matches!(self.icmp_type, 0 | 8)
        }
    }
}

pub fn parse(cur: &mut Cursor<'_>, v6: bool) -> Result<IcmpView, DecodeError> {
    Ok(IcmpView {
        v6,
        icmp_type: cur.u8()?,
        code: cur.u8()?,
    })
}
