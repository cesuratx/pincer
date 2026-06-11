//! TCP header: ports, sequence numbers, flags, payload slice.
#![deny(clippy::arithmetic_side_effects)]

use std::fmt;

use crate::bytes::Cursor;
use crate::error::DecodeError;

/// The low 8 TCP flag bits, OR-combinable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: Self = Self(0x01);
    pub const SYN: Self = Self(0x02);
    pub const RST: Self = Self(0x04);
    pub const PSH: Self = Self(0x08);
    pub const ACK: Self = Self(0x10);
    pub const URG: Self = Self(0x20);

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// SYN without ACK — the connection-initiating segment.
    #[must_use]
    pub const fn is_initial_syn(self) -> bool {
        self.0 & 0x12 == 0x02
    }

    /// SYN+ACK — proof the destination port is a listening service.
    #[must_use]
    pub const fn is_syn_ack(self) -> bool {
        self.0 & 0x12 == 0x12
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [(u8, &str); 6] = [
            (0x02, "SYN"),
            (0x10, "ACK"),
            (0x01, "FIN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x20, "URG"),
        ];
        let mut first = true;
        for (bit, name) in NAMES {
            if self.0 & bit != 0 {
                if !first {
                    write!(f, ",")?;
                }
                write!(f, "{name}")?;
                first = false;
            }
        }
        if first {
            write!(f, "-")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TcpView<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub payload: &'a [u8],
}

pub fn parse<'a>(cur: &mut Cursor<'a>) -> Result<TcpView<'a>, DecodeError> {
    let src_port = cur.u16_be()?;
    let dst_port = cur.u16_be()?;
    let seq = cur.u32_be()?;
    let ack = cur.u32_be()?;
    let off_flags = cur.u16_be()?;
    let window = cur.u16_be()?;
    cur.u16_be()?; // checksum (not verified)
    cur.u16_be()?; // urgent pointer

    let data_offset = usize::from(off_flags >> 12).saturating_mul(4);
    if data_offset < 20 {
        return Err(DecodeError::malformed("tcp", "data offset below 5 words"));
    }
    cur.skip(data_offset.saturating_sub(20))?; // options

    #[allow(clippy::cast_possible_truncation)]
    Ok(TcpView {
        src_port,
        dst_port,
        seq,
        ack,
        flags: TcpFlags((off_flags & 0xFF) as u8),
        window,
        payload: cur.rest(),
    })
}
