//! DNS and mDNS message parsing — the richest source of hostnames for the
//! asset inventory.
//!
//! Name decompression is the classic attack surface here. Three rules make it
//! safe against both loops (`0xC00C → 0xC00C`) and decompression bombs:
//! pointers must point strictly **backwards**, the jump budget is bounded,
//! and the assembled name is capped at 253 bytes.
#![deny(clippy::arithmetic_side_effects)]

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use crate::bytes::Cursor;
use crate::error::DecodeError;

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;

/// Sanity caps for hostile counts/structures.
const MAX_QUESTIONS: u16 = 32;
const MAX_RECORDS: u16 = 128;
const MAX_POINTER_JUMPS: u8 = 16;
const MAX_NAME_LEN: usize = 253;

#[derive(Debug, Clone, Serialize)]
pub struct DnsQuery {
    pub name: String,
    pub qtype: u16,
}

#[derive(Debug, Clone, Serialize)]
pub enum DnsRData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ptr(String),
    Srv { port: u16, target: String },
    Other { rtype: u16 },
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsAnswer {
    pub name: String,
    pub data: DnsRData,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsSummary {
    pub id: u16,
    pub is_response: bool,
    pub is_mdns: bool,
    pub queries: Vec<DnsQuery>,
    /// Answer + additional records (mDNS loves putting A records in
    /// additionals); authority records are walked but not kept.
    pub answers: Vec<DnsAnswer>,
}

/// Parse a DNS/mDNS message. `None` = does not look like DNS.
#[must_use]
pub fn parse(payload: &[u8], is_mdns: bool) -> Option<DnsSummary> {
    parse_inner(payload, is_mdns).ok()
}

fn parse_inner(msg: &[u8], is_mdns: bool) -> Result<DnsSummary, DecodeError> {
    let mut cur = Cursor::new(msg);
    let id = cur.u16_be()?;
    let flags = cur.u16_be()?;
    let qd_count = cur.u16_be()?;
    let an_count = cur.u16_be()?;
    let ns_count = cur.u16_be()?;
    let extra_count = cur.u16_be()?;

    if qd_count > MAX_QUESTIONS {
        return Err(DecodeError::malformed("dns", "implausible question count"));
    }
    let record_total = an_count
        .saturating_add(ns_count)
        .saturating_add(extra_count);
    if record_total > MAX_RECORDS {
        return Err(DecodeError::malformed("dns", "implausible record count"));
    }
    // Opcode must be QUERY(0) for anything we care about.
    if (flags >> 11) & 0x0F != 0 {
        return Err(DecodeError::malformed("dns", "non-query opcode"));
    }

    let mut summary = DnsSummary {
        id,
        is_response: flags & 0x8000 != 0,
        is_mdns,
        queries: Vec::new(),
        answers: Vec::new(),
    };

    for _ in 0..qd_count {
        let (name, next) = parse_name(msg, cur.pos(), msg.len())?;
        cur = Cursor::at(msg, next)?;
        let qtype = cur.u16_be()?;
        cur.u16_be()?; // class (mDNS QU bit lives here; irrelevant to us)
        summary.queries.push(DnsQuery { name, qtype });
    }

    for index in 0..record_total {
        if cur.is_empty() {
            break; // truncated record sets are common in mDNS; keep what we have
        }
        let (name, next) = parse_name(msg, cur.pos(), msg.len())?;
        cur = Cursor::at(msg, next)?;
        let rtype = cur.u16_be()?;
        cur.u16_be()?; // class / cache-flush bit
        cur.u32_be()?; // ttl
        let rd_len = usize::from(cur.u16_be()?);
        let rdata_start = cur.pos();
        let rdata = cur.take(rd_len)?;

        // Answers and additionals carry naming evidence; authority does not.
        let keep = index < an_count || index >= an_count.saturating_add(ns_count);
        if !keep {
            continue;
        }

        let data = match rtype {
            TYPE_A if rd_len == 4 => {
                let mut rd = Cursor::new(rdata);
                DnsRData::A(rd.ipv4()?)
            }
            TYPE_AAAA if rd_len == 16 => {
                let mut rd = Cursor::new(rdata);
                DnsRData::Aaaa(rd.ipv6()?)
            }
            // The name lives inside this RR's RDATA, so literal labels may not
            // run past `rdata_start + rd_len` into the following record.
            TYPE_CNAME => {
                DnsRData::Cname(parse_name(msg, rdata_start, rdata_start.saturating_add(rd_len))?.0)
            }
            TYPE_PTR => {
                DnsRData::Ptr(parse_name(msg, rdata_start, rdata_start.saturating_add(rd_len))?.0)
            }
            TYPE_SRV => {
                let mut rd = Cursor::new(rdata);
                rd.u16_be()?; // priority
                rd.u16_be()?; // weight
                let port = rd.u16_be()?;
                // SRV target starts 6 bytes in and must stay within the RDATA
                // (it may still use a compression pointer into the message).
                let target_offset = rdata_start.saturating_add(6);
                let target = parse_name(msg, target_offset, rdata_start.saturating_add(rd_len))?.0;
                DnsRData::Srv { port, target }
            }
            rtype => DnsRData::Other { rtype },
        };
        summary.answers.push(DnsAnswer { name, data });
    }

    Ok(summary)
}

/// Decompress a domain name starting at `start`. Returns the name and the
/// offset of the byte *after* the name at its original location.
///
/// `literal_end` bounds how far a *literal* (non-pointer) label may extend in
/// the **original** run, before any compression jump. For a name living inside
/// an RR's RDATA (CNAME/PTR/SRV target) this is `rdata_start + rd_len`, so a
/// truncated record cannot make the name reach into the *next* record's bytes.
/// For owner names (question/answer), pass `msg.len()`. Once we follow a
/// pointer we are reading elsewhere in the message, so the bound relaxes to the
/// whole message (the pointer-target region is legitimately outside this RR).
fn parse_name(
    msg: &[u8],
    start: usize,
    literal_end: usize,
) -> Result<(String, usize), DecodeError> {
    let mut name = String::new();
    let mut pos = start;
    let mut next_after = None; // set at the first pointer jump
    let mut jumps = 0u8;
    let mut bound = literal_end.min(msg.len());

    loop {
        if pos >= bound {
            return Err(DecodeError::malformed("dns", "name runs past its record"));
        }
        let mut cur = Cursor::at(msg, pos)?;
        let len = cur.u8()?;

        match len & 0xC0 {
            0xC0 => {
                let low = cur.u8()?;
                let target = usize::from(len & 0x3F) << 8 | usize::from(low);
                // Pointers must go strictly backwards — kills loops outright.
                if target >= pos {
                    return Err(DecodeError::malformed("dns", "forward compression pointer"));
                }
                jumps = jumps.saturating_add(1);
                if jumps > MAX_POINTER_JUMPS {
                    return Err(DecodeError::malformed(
                        "dns",
                        "pointer jump budget exceeded",
                    ));
                }
                if next_after.is_none() {
                    next_after = Some(cur.pos());
                }
                pos = target;
                // We jumped out of the RR into shared compression space; the
                // per-record literal bound no longer applies.
                bound = msg.len();
            }
            0x00 => {
                if len == 0 {
                    // Root label: name complete.
                    let after = next_after.unwrap_or(cur.pos());
                    return Ok((name, after));
                }
                // A literal label must lie wholly within the current bound.
                if cur.pos().saturating_add(usize::from(len)) > bound {
                    return Err(DecodeError::malformed("dns", "label runs past its record"));
                }
                let label = cur.take(usize::from(len))?;
                if name.len().saturating_add(usize::from(len)) > MAX_NAME_LEN {
                    return Err(DecodeError::malformed("dns", "name too long"));
                }
                if !name.is_empty() {
                    name.push('.');
                }
                // Printable ASCII passthrough; anything else escaped.
                for &byte in label {
                    if byte.is_ascii_graphic() && byte != b'.' {
                        name.push(char::from(byte));
                    } else {
                        name.push('?');
                    }
                }
                pos = cur.pos();
            }
            _ => return Err(DecodeError::malformed("dns", "reserved label type")),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    /// Query for example.com, response with one A answer using a compression
    /// pointer back to the question name (offset 12 → 0xC00C).
    fn sample_response() -> Vec<u8> {
        let mut msg = vec![
            0xBE, 0xEF, // id
            0x81, 0x80, // QR=1, RD, RA
            0x00, 0x01, // 1 question
            0x00, 0x01, // 1 answer
            0x00, 0x00, 0x00, 0x00, // no authority/additional
        ];
        // question: 7"example"3"com"0, A, IN
        msg.extend_from_slice(b"\x07example\x03com\x00");
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // answer: pointer to offset 12, A, IN, ttl 60, rdlen 4, 93.184.216.34
        msg.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184, 216, 34]);
        msg
    }

    #[test]
    fn parses_response_with_compression() {
        let summary = parse(&sample_response(), false).unwrap();
        assert!(summary.is_response);
        assert_eq!(summary.queries[0].name, "example.com");
        assert_eq!(summary.answers.len(), 1);
        assert_eq!(summary.answers[0].name, "example.com");
        match summary.answers[0].data {
            DnsRData::A(ip) => assert_eq!(ip, Ipv4Addr::new(93, 184, 216, 34)),
            ref other => panic!("expected A record, got {other:?}"),
        }
    }

    #[test]
    fn rejects_pointer_loop() {
        let mut msg = sample_response();
        // Make the answer's pointer point at itself (offset 29 = 0xC0 0x1D).
        let ptr_at = 12 + 17; // header + question
        msg[ptr_at] = 0xC0;
        msg[ptr_at + 1] = u8::try_from(ptr_at).unwrap();
        assert!(parse(&msg, false).is_none());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[0x00; 4], false).is_none());
        assert!(parse(&[], false).is_none());
        // implausible counts
        let mut msg = sample_response();
        msg[4] = 0xFF;
        msg[5] = 0xFF;
        assert!(parse(&msg, false).is_none());
    }

    /// An SRV answer whose `rd_len` is 6 (priority+weight+port, no target) must
    /// not let the target name reach into the bytes of a following record.
    /// Before the `rd_len` bound was enforced, this parsed with the *next*
    /// record's name as a phantom SRV target; now the out-of-record read is
    /// rejected and the (best-effort) parse yields nothing for this message.
    #[test]
    fn srv_target_cannot_escape_its_rdata() {
        let mut msg = vec![
            0x00, 0x01, // id
            0x84, 0x00, // QR, AA
            0x00, 0x00, // 0 questions
            0x00, 0x02, // 2 answers
            0x00, 0x00, 0x00, 0x00,
        ];
        // Answer 1: SRV with rd_len=6 (no target bytes inside the record).
        msg.extend_from_slice(b"\x04_srv\x05local\x00"); // owner name
        msg.extend_from_slice(&[0x00, 33, 0x00, 0x01]); // type SRV, class IN
        msg.extend_from_slice(&[0, 0, 0, 60]); // ttl
        msg.extend_from_slice(&[0x00, 0x06]); // rd_len = 6
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x1F, 0x90]); // prio, weight, port 8080
        // Answer 2: a normal A record whose bytes the SRV target must NOT read.
        msg.extend_from_slice(b"\x04host\x05local\x00");
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x04, 10, 0, 0, 9]);

        // No SRV answer may carry a target borrowed from the next record.
        let leaked = parse(&msg, true).is_some_and(|summary| {
            summary
                .answers
                .iter()
                .any(|a| matches!(&a.data, DnsRData::Srv { target, .. } if target.contains("host")))
        });
        assert!(!leaked, "SRV target leaked the following record's name");
    }
}
