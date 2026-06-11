//! HTTP/1.x request-line + Host header extraction.
//!
//! First-segment only by design: we do not reassemble TCP streams, and in
//! practice the request line and Host header sit in the first data segment.
//! Only the first 2 KiB of that segment are examined (`SCAN_LIMIT`).
#![deny(clippy::arithmetic_side_effects)]

use serde::Serialize;

/// How far into the segment we look for the Host header.
const SCAN_LIMIT: usize = 2048;

const METHODS: [&str; 8] = [
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT",
];

#[derive(Debug, Clone, Serialize)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
}

/// Parse an HTTP/1.x request from the start of a TCP payload.
/// `None` = does not look like an HTTP request.
#[must_use]
pub fn parse_request(payload: &[u8]) -> Option<HttpRequest> {
    // Method prefix first: O(8) against the first bytes, before the 2 KiB
    // window scan and the UTF-8 validation. Bulk non-HTTP TCP segments — the
    // dominant byte volume in real captures — reject right here. A request
    // the parse below would accept always starts `METHOD SP`, so this gate
    // changes no verdict.
    if !starts_with_method(payload) {
        return None;
    }
    let window = payload.get(..payload.len().min(SCAN_LIMIT))?;
    // Bound the UTF-8 requirement to the *header* region (up to the blank
    // line): a POST whose binary body starts inside the first segment must
    // not hide its own request line and Host header.
    let headers = window
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .and_then(|end| window.get(..end.checked_add(4)?))
        .unwrap_or(window);
    let text = std::str::from_utf8(headers).ok().or_else(|| {
        // If the region's final byte split a multi-byte UTF-8 sequence (common
        // when SCAN_LIMIT or the payload cuts mid-character), retry one byte
        // shorter. This is only a 1-byte trim, not general binary tolerance —
        // a request line and Host header are ASCII, so that suffices.
        std::str::from_utf8(headers.get(..headers.len().checked_sub(1)?)?).ok()
    })?;

    let (request_line, rest) = text.split_once("\r\n")?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?;
    let path = parts.next()?;
    let version = parts.next()?;
    if !METHODS.contains(&method) || !version.starts_with("HTTP/1.") {
        return None;
    }

    let host = rest
        .split("\r\n")
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            let value = value.trim();
            // Sanitize: the Host value can carry control/escape bytes that must
            // not reach a terminal/DOT cell unescaped (as DNS/DHCP names are).
            // Length-cap: longer than any legal hostname ⇒ not evidence.
            let value = normalize_host(value);
            (name.eq_ignore_ascii_case("host") && value.len() <= crate::app::MAX_NAME_LEN)
                .then(|| crate::app::sanitize_name(value))
        });

    Some(HttpRequest {
        method: method.to_string(),
        // Same sanitation as every other attacker-controlled string that can
        // reach a terminal or a report cell.
        path: crate::app::sanitize_name(path),
        host,
    })
}

/// Does the payload begin with `METHOD SP` for one of the known methods?
fn starts_with_method(payload: &[u8]) -> bool {
    METHODS.iter().any(|method| {
        payload.get(..method.len()) == Some(method.as_bytes())
            && payload.get(method.len()) == Some(&b' ')
    })
}

/// Strip a `:port` suffix (and the brackets of an IPv6 literal) so the stored
/// hostname matches what DNS/TLS evidence calls the same server.
fn normalize_host(value: &str) -> &str {
    if let Some(rest) = value.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(ip, _)| ip);
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parses_request_with_host() {
        let req = b"GET /status HTTP/1.1\r\nHost: intranet.local\r\nAccept: */*\r\n\r\n";
        let parsed = parse_request(req).unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.path, "/status");
        assert_eq!(parsed.host.as_deref(), Some("intranet.local"));
    }

    #[test]
    fn binary_body_in_first_segment_does_not_hide_the_request() {
        // A POST whose body starts within the 2 KiB window and is not UTF-8:
        // the headers are what matter, and they are clean.
        let mut req = b"POST /upload HTTP/1.1\r\nHost: files.local\r\n\r\n".to_vec();
        req.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x80, 0xC3, 0x28]); // invalid UTF-8
        let parsed = parse_request(&req).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.host.as_deref(), Some("files.local"));
    }

    #[test]
    fn host_port_suffix_and_ipv6_brackets_are_normalized() {
        let req = b"GET / HTTP/1.1\r\nHost: files.local:8080\r\n\r\n";
        assert_eq!(
            parse_request(req).unwrap().host.as_deref(),
            Some("files.local")
        );
        let req = b"GET / HTTP/1.1\r\nHost: [::1]:443\r\n\r\n";
        assert_eq!(parse_request(req).unwrap().host.as_deref(), Some("::1"));
    }

    #[test]
    fn oversized_host_is_not_hostname_evidence() {
        let req = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", "a".repeat(300));
        let parsed = parse_request(req.as_bytes()).unwrap();
        assert_eq!(parsed.host, None);
    }

    #[test]
    fn rejects_non_http() {
        assert!(parse_request(b"SSH-2.0-OpenSSH_9.6\r\n").is_none());
        assert!(parse_request(b"").is_none());
        assert!(parse_request(&[0x16, 0x03, 0x01, 0x02, 0x00]).is_none());
        // response, not request
        assert!(parse_request(b"HTTP/1.1 200 OK\r\n\r\n").is_none());
    }

    #[test]
    fn method_prefix_gate_changes_no_verdict() {
        // Bulk printable payload with a header terminator deep inside: the
        // old path paid the full window scan + UTF-8 pass to say None; the
        // method gate must say None too.
        let mut bulk = vec![b'A'; 2048];
        bulk.extend_from_slice(b"\r\n\r\n");
        assert!(parse_request(&bulk).is_none());
        // A method name not followed by a space is not a request line.
        assert!(parse_request(b"GETX / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_request(b"GET\r\nHost: x\r\n\r\n").is_none());
        // Passing the gate is not enough — the full parse still rules.
        assert!(parse_request(b"GET only-a-path-no-version\r\n\r\n").is_none());
    }
}
