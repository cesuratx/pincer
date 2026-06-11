//! SCTP common header — ports only. The chunked payload (DATA/INIT/SACK…) is
//! beyond passive-discovery needs, but the ports are right at the front with
//! the same layout as UDP, and they are what turns an opaque `proto-132` flow
//! into `host → server:80`.
#![deny(clippy::arithmetic_side_effects)]

use crate::bytes::Cursor;
use crate::error::DecodeError;

#[derive(Debug, Clone, Copy)]
pub struct SctpView {
    pub src_port: u16,
    pub dst_port: u16,
}

pub fn parse(cur: &mut Cursor<'_>) -> Result<SctpView, DecodeError> {
    let src_port = cur.u16_be()?;
    let dst_port = cur.u16_be()?;
    cur.u32_be()?; // verification tag
    cur.u32_be()?; // checksum (CRC32c — not verified)
    Ok(SctpView { src_port, dst_port })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parses_common_header() {
        let hdr = [
            0x80, 0x00, // src 32768
            0x00, 0x50, // dst 80
            0xDE, 0xAD, 0xBE, 0xEF, // vtag
            0x00, 0x00, 0x00, 0x00, // checksum
            0x00, 0x03, // chunk bytes (ignored)
        ];
        let view = parse(&mut Cursor::new(&hdr)).unwrap();
        assert_eq!((view.src_port, view.dst_port), (32768, 80));
        assert!(parse(&mut Cursor::new(&hdr[..8])).is_err());
    }
}
