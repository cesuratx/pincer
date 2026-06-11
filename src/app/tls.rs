//! TLS `ClientHello` parsing for SNI extraction — the highest-value service
//! identification signal in encrypted traffic: one unencrypted hostname per
//! HTTPS connection.
//!
//! First-segment only: a `ClientHello` split across TCP segments yields
//! `None`, and the flow degrades gracefully to port + SYN-ACK evidence.
#![deny(clippy::arithmetic_side_effects)]

use serde::Serialize;

use crate::bytes::Cursor;
use crate::error::DecodeError;

const RECORD_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;

#[derive(Debug, Clone, Serialize)]
pub struct TlsClientHello {
    pub sni: Option<String>,
}

/// Parse a TLS `ClientHello` from the start of a TCP payload.
/// `None` = not a `ClientHello`.
#[must_use]
pub fn parse_client_hello(payload: &[u8]) -> Option<TlsClientHello> {
    parse_inner(payload).ok()
}

fn parse_inner(payload: &[u8]) -> Result<TlsClientHello, DecodeError> {
    let mut cur = Cursor::new(payload);

    // TLS record header
    if cur.u8()? != RECORD_HANDSHAKE {
        return Err(DecodeError::malformed("tls", "not a handshake record"));
    }
    if cur.u8()? != 3 {
        return Err(DecodeError::malformed("tls", "not TLS"));
    }
    cur.u8()?; // record minor version (3.1–3.4 all observed)
    // Bound everything below to the declared record body: bytes after it
    // belong to the *next* record, and a lying record length must never let
    // the extension walk read another structure's bytes as a ClientHello.
    let record_len = usize::from(cur.u16_be()?);
    let mut cur = Cursor::new(cur.take(record_len.min(cur.remaining()))?);

    // Handshake header
    if cur.u8()? != HANDSHAKE_CLIENT_HELLO {
        return Err(DecodeError::malformed("tls", "not a ClientHello"));
    }
    // Cross-check: the handshake must fit its record (a hello fragmented
    // across records is out of scope by the first-segment design — bounding
    // to the shorter of the two lengths keeps the walk inside bytes that the
    // ClientHello actually owns).
    let hs_len = u32::from_be_bytes([0, cur.u8()?, cur.u8()?, cur.u8()?]) as usize;
    let mut cur = Cursor::new(cur.take(hs_len.min(cur.remaining()))?);
    cur.u16_be()?; // client version
    cur.skip(32)?; // random
    let session_id_len = usize::from(cur.u8()?);
    cur.skip(session_id_len)?;
    let cipher_suites_len = usize::from(cur.u16_be()?);
    cur.skip(cipher_suites_len)?;
    let compression_len = usize::from(cur.u8()?);
    cur.skip(compression_len)?;

    if cur.is_empty() {
        return Ok(TlsClientHello { sni: None }); // legal: no extensions
    }
    let extensions_len = usize::from(cur.u16_be()?);
    let mut ext = Cursor::new(cur.take(extensions_len.min(cur.remaining()))?);

    while ext.remaining() >= 4 {
        let ext_type = ext.u16_be()?;
        let ext_len = usize::from(ext.u16_be()?);
        let body = ext.take(ext_len.min(ext.remaining()))?;
        if ext_type == EXT_SERVER_NAME {
            let mut sni = Cursor::new(body);
            sni.u16_be()?; // server name list length
            if sni.u8()? != 0 {
                continue; // only name_type 0 (host_name) is defined
            }
            let name_len = usize::from(sni.u16_be()?);
            let name = sni.take(name_len)?;
            // Longer than any legal DNS name ⇒ not hostname evidence; dropping
            // it also bounds the bytes a hostile capture can make us retain.
            if name.is_ascii() && !name.is_empty() && name.len() <= crate::app::MAX_NAME_LEN {
                let raw: String = name.iter().map(|&byte| char::from(byte)).collect();
                // Sanitize: an ASCII SNI can still carry ANSI escape bytes,
                // which must not reach a terminal/DOT cell unescaped.
                return Ok(TlsClientHello {
                    sni: Some(crate::app::sanitize_name(&raw)),
                });
            }
        }
    }

    Ok(TlsClientHello { sni: None })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use crate::fixtures;

    #[test]
    fn extracts_sni() {
        let hello = fixtures::tls_client_hello("example.com");
        let parsed = parse_client_hello(&hello).unwrap();
        assert_eq!(parsed.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn oversized_sni_is_not_hostname_evidence() {
        // Longer than any legal DNS name (253): parsed fine, but dropped —
        // this is what byte-bounds per-flow server_name retention.
        let long = "a".repeat(300);
        let hello = fixtures::tls_client_hello(&long);
        let parsed = parse_client_hello(&hello).unwrap();
        assert_eq!(parsed.sni, None);
    }

    #[test]
    fn lying_record_length_cannot_reach_past_the_record() {
        // Shrink the record-length field so the SNI extension falls outside
        // the declared record: the walk must stop at the boundary and yield
        // no SNI — never read the "next record's" bytes as this ClientHello.
        let mut hello = fixtures::tls_client_hello("example.com");
        hello[3] = 0;
        hello[4] = 44; // record claims 44 bytes: header + random only
        let parsed = parse_client_hello(&hello);
        assert!(parsed.is_none() || parsed.unwrap().sni.is_none());
    }

    #[test]
    fn lying_handshake_length_is_bounded_by_the_record() {
        // Handshake claims 3 bytes; everything after must be ignored.
        let mut hello = fixtures::tls_client_hello("example.com");
        hello[6] = 0;
        hello[7] = 0;
        hello[8] = 3;
        let parsed = parse_client_hello(&hello);
        assert!(parsed.is_none() || parsed.unwrap().sni.is_none());
    }

    #[test]
    fn rejects_non_tls() {
        assert!(parse_client_hello(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_client_hello(&[]).is_none());
        assert!(parse_client_hello(&[22, 2, 0, 0, 5, 1, 0, 0, 1, 0]).is_none());
    }
}
