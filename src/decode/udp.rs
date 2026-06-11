//! UDP header with length-bounded payload.
#![deny(clippy::arithmetic_side_effects)]

use crate::bytes::Cursor;
use crate::error::DecodeError;

#[derive(Debug, Clone, Copy)]
pub struct UdpView<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
    pub payload_truncated: bool,
}

pub fn parse<'a>(cur: &mut Cursor<'a>) -> Result<UdpView<'a>, DecodeError> {
    let src_port = cur.u16_be()?;
    let dst_port = cur.u16_be()?;
    let length = usize::from(cur.u16_be()?);
    cur.u16_be()?; // checksum (not verified)

    // RFC 2675 jumbograms and segmentation-offload captures write 0 here;
    // the real length is filled in below the capture point. Use everything
    // captured — the same leniency the IP layers grant their zero lengths.
    if length == 0 {
        let payload = cur.rest();
        return Ok(UdpView {
            src_port,
            dst_port,
            payload,
            payload_truncated: false,
        });
    }
    if length < 8 {
        return Err(DecodeError::malformed("udp", "length below header size"));
    }
    let declared = length.saturating_sub(8);
    let available = cur.remaining();
    let payload = cur.take(declared.min(available))?;

    Ok(UdpView {
        src_port,
        dst_port,
        payload,
        payload_truncated: available < declared,
    })
}
