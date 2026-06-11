//! HTTP/1.x request-line + Host header extraction.
//!
//! First-segment only by design: we do not reassemble TCP streams, and in
//! practice the request line and Host header sit in the first data segment.
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
    let window = payload.get(..payload.len().min(SCAN_LIMIT))?;
    let text = std::str::from_utf8(window).ok().or_else(|| {
        // If the window's final byte split a multi-byte UTF-8 sequence (common
        // when SCAN_LIMIT or the payload cuts mid-character), retry one byte
        // shorter. This is only a 1-byte trim, not general binary tolerance —
        // a request line and Host header are ASCII, so that suffices.
        std::str::from_utf8(window.get(..window.len().checked_sub(1)?)?).ok()
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
            // Sanitize: the Host value can carry control/escape bytes that must
            // not reach a terminal/DOT cell unescaped (as DNS/DHCP names are).
            name.eq_ignore_ascii_case("host")
                .then(|| crate::app::sanitize_name(value.trim()))
        });

    Some(HttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        host,
    })
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
    fn rejects_non_http() {
        assert!(parse_request(b"SSH-2.0-OpenSSH_9.6\r\n").is_none());
        assert!(parse_request(b"").is_none());
        assert!(parse_request(&[0x16, 0x03, 0x01, 0x02, 0x00]).is_none());
        // response, not request
        assert!(parse_request(b"HTTP/1.1 200 OK\r\n\r\n").is_none());
    }
}
