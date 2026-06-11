//! IPv6 fixed header plus a bounded walk of the extension-header chain to the
//! final next-header value.
#![deny(clippy::arithmetic_side_effects)]

use std::net::Ipv6Addr;

use crate::bytes::Cursor;
use crate::error::DecodeError;

#[derive(Debug, Clone, Copy)]
pub struct Ipv6View<'a> {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    /// Final next-header after walking extension headers.
    pub next_header: u8,
    pub hop_limit: u8,
    /// A fragment header with offset > 0: the payload is the middle of a
    /// datagram and carries **no** transport header.
    pub fragment_continuation: bool,
    /// Any fragment header was present — also true for the *first* fragment,
    /// whose transport length fields describe the whole datagram.
    pub fragmented: bool,
    pub payload: &'a [u8],
    pub payload_truncated: bool,
}

impl Ipv6View<'_> {
    /// Same trap as IPv4: a non-first fragment must not be transport-parsed.
    #[must_use]
    pub const fn is_fragment_continuation(&self) -> bool {
        self.fragment_continuation
    }
}

const EXT_HOP_BY_HOP: u8 = 0;
const EXT_ROUTING: u8 = 43;
const EXT_FRAGMENT: u8 = 44;
const EXT_DEST_OPTS: u8 = 60;
/// Hostile chains could loop next-header values forever; eight is far beyond
/// anything legitimate.
const MAX_EXT_HEADERS: u8 = 8;

pub fn parse<'a>(cur: &mut Cursor<'a>) -> Result<Ipv6View<'a>, DecodeError> {
    let ver_class_flow = cur.u32_be()?;
    if ver_class_flow >> 28 != 6 {
        return Err(DecodeError::malformed("ipv6", "version is not 6"));
    }
    let payload_len = usize::from(cur.u16_be()?);
    let mut next_header = cur.u8()?;
    let hop_limit = cur.u8()?;
    let src = cur.ipv6()?;
    let dst = cur.ipv6()?;

    // payload_length == 0 is legal for jumbograms (hop-by-hop jumbo option)
    // and also appears in segmentation-offload captures, where the length is
    // filled in below the capture point. Use everything captured in that case.
    let available = cur.remaining();
    let effective_len = if payload_len == 0 {
        available
    } else {
        payload_len
    };
    let bounded = cur.take(effective_len.min(available))?;
    let payload_truncated = available < effective_len;

    // Walk extension headers inside the bounded payload.
    let mut inner = Cursor::new(bounded);
    let mut hops = 0u8;
    let mut fragment_continuation = false;
    let mut fragmented = false;
    loop {
        if hops >= MAX_EXT_HEADERS {
            // Longer than anything legitimate: stop walking and degrade —
            // the un-walked header number lands in `next_header`, transport
            // becomes `Other`, and the already-parsed src/dst survive
            // instead of the whole packet counting as malformed.
            break;
        }
        match next_header {
            EXT_HOP_BY_HOP | EXT_ROUTING | EXT_DEST_OPTS => {
                next_header = inner.u8()?;
                let ext_len = inner.u8()?;
                // Length excludes the first 8 octets; 2 already consumed.
                let skip = usize::from(ext_len).saturating_mul(8).saturating_add(6);
                inner.skip(skip)?;
            }
            EXT_FRAGMENT => {
                next_header = inner.u8()?;
                inner.u8()?; // reserved
                let offset_flags = inner.u16_be()?;
                inner.skip(4)?; // identification
                fragmented = true;
                // High 13 bits are the fragment offset (in 8-byte units). A
                // non-zero offset means this is the *middle* of a datagram:
                // what follows is payload bytes, not headers — the same trap
                // IPv4 guards against, so stop walking here.
                if offset_flags >> 3 != 0 {
                    fragment_continuation = true;
                    break;
                }
            }
            _ => break,
        }
        hops = hops.saturating_add(1);
    }

    Ok(Ipv6View {
        src,
        dst,
        next_header,
        hop_limit,
        fragment_continuation,
        fragmented,
        payload: inner.rest(),
        payload_truncated,
    })
}
