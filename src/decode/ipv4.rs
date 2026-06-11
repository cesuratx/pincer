//! IPv4 header. Fragmentation is *noted* (flags + offset), never reassembled;
//! non-first fragments are excluded from transport parsing upstream.
#![deny(clippy::arithmetic_side_effects)]

use std::net::Ipv4Addr;

use crate::bytes::Cursor;
use crate::error::DecodeError;

#[derive(Debug, Clone, Copy)]
pub struct Ipv4View<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub ttl: u8,
    pub ident: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    /// Fragment offset in 8-byte units.
    pub frag_offset: u16,
    /// Transport bytes, bounded by `total_length` *and* by what was captured.
    pub payload: &'a [u8],
    /// `total_length` promised more payload than the capture holds (snaplen).
    pub payload_truncated: bool,
}

impl Ipv4View<'_> {
    /// A fragment other than the first — carries no transport header.
    #[must_use]
    pub const fn is_fragment_continuation(&self) -> bool {
        self.frag_offset > 0
    }

    #[must_use]
    pub const fn is_fragmented(&self) -> bool {
        self.more_fragments || self.frag_offset > 0
    }
}

pub fn parse<'a>(cur: &mut Cursor<'a>) -> Result<Ipv4View<'a>, DecodeError> {
    let ver_ihl = cur.u8()?;
    if ver_ihl >> 4 != 4 {
        return Err(DecodeError::malformed("ipv4", "version is not 4"));
    }
    let header_len = usize::from(ver_ihl & 0x0F).saturating_mul(4);
    if header_len < 20 {
        return Err(DecodeError::malformed("ipv4", "IHL below 5 words"));
    }

    cur.u8()?; // DSCP/ECN
    let total_len = usize::from(cur.u16_be()?);
    let ident = cur.u16_be()?;
    let flags_frag = cur.u16_be()?;
    let ttl = cur.u8()?;
    let proto = cur.u8()?;
    cur.u16_be()?; // header checksum (not verified: we analyze, not route)
    let src = cur.ipv4()?;
    let dst = cur.ipv4()?;
    cur.skip(header_len.saturating_sub(20))?; // options

    // Segmentation-offload captures (TSO/GSO): when capturing on the sending
    // host, the NIC fills in total_length *after* the capture point, so large
    // outbound packets legitimately carry total_length == 0. Treat the whole
    // captured remainder as payload (Wireshark does the same) instead of
    // discarding every large local flow as malformed.
    let declared_payload = if total_len == 0 {
        cur.remaining()
    } else {
        if total_len < header_len {
            return Err(DecodeError::malformed("ipv4", "total length below IHL"));
        }
        total_len.saturating_sub(header_len)
    };
    let available = cur.remaining();
    // Ethernet pads short frames to 60 bytes: trust total_length as the upper
    // bound so padding never leaks into the transport payload. (The offload
    // total_length == 0 path has no bound to trust — padding could leak
    // there, but offload frames are large and never minimum-frame-padded.)
    let payload = cur.take(declared_payload.min(available))?;

    Ok(Ipv4View {
        src,
        dst,
        proto,
        ttl,
        ident,
        dont_fragment: flags_frag & 0x4000 != 0,
        more_fragments: flags_frag & 0x2000 != 0,
        frag_offset: flags_frag & 0x1FFF,
        payload,
        payload_truncated: available < declared_payload,
    })
}
