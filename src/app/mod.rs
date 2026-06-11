//! Best-effort application-layer sniffers.
//!
//! Chain of responsibility: each sniffer gets a cheap structural pre-check
//! (ports, first bytes) and returns `Option` — `None` simply means "not this
//! protocol", which is the normal case, not an error. A half-valid payload
//! also yields `None`: best-effort detection must produce no noise.
//!
//! Sniffers return **owned** [`AppEvent`]s — this is the deliberate seam
//! between the zero-copy packet path and the aggregating sinks.
#![deny(clippy::arithmetic_side_effects)]

pub mod dhcp;
pub mod dns;
pub mod http;
pub mod tls;

pub use dhcp::{DhcpMsgType, DhcpSummary};
pub use dns::{DnsAnswer, DnsQuery, DnsRData, DnsSummary};
pub use http::HttpRequest;
pub use tls::TlsClientHello;

use crate::decode::{PacketView, TransportView};

/// Longest name accepted as hostname evidence — the RFC 1035 limit. A TLS SNI
/// or HTTP Host longer than this is not a real hostname; dropping it (rather
/// than storing it) keeps per-flow/per-asset memory byte-bounded, not just
/// entry-bounded.
pub(crate) const MAX_NAME_LEN: usize = 253;

/// Replace any non-graphic byte in an attacker-controlled name with `?`. Used
/// for TLS SNI and HTTP Host/path, matching how DNS names are sanitized at the
/// source — so a string carrying ANSI escape bytes can never reach the
/// operator's terminal (or a DOT/table cell) unescaped. (DHCP's `printable`
/// additionally permits the space character: vendor-class strings like
/// `MSFT 5.0` carry one legitimately.)
#[must_use]
pub(crate) fn sanitize_name(raw: &str) -> String {
    // `is_ascii_graphic` keeps letters, digits, and `.-_` (every legitimate
    // hostname character) while turning control/escape bytes into `?`.
    raw.chars()
        .map(|ch| if ch.is_ascii_graphic() { ch } else { '?' })
        .collect()
}

#[derive(Debug, Clone)]
pub enum AppEvent {
    Dns(DnsSummary),
    Dhcp(DhcpSummary),
    Http(HttpRequest),
    Tls(TlsClientHello),
}

impl AppEvent {
    /// Hostname evidence this event carries about the *server* side of its
    /// connection (TLS SNI, HTTP Host header).
    #[must_use]
    pub fn server_name_hint(&self) -> Option<&str> {
        match self {
            Self::Tls(hello) => hello.sni.as_deref(),
            Self::Http(req) => req.host.as_deref(),
            Self::Dns(_) | Self::Dhcp(_) => None,
        }
    }

    /// Short protocol label for tables.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Dns(summary) if summary.is_mdns => "mdns",
            Self::Dns(_) => "dns",
            Self::Dhcp(_) => "dhcp",
            Self::Http(_) => "http",
            Self::Tls(_) => "tls",
        }
    }
}

const PORT_DNS: u16 = 53;
const PORT_DHCP_SERVER: u16 = 67;
const PORT_DHCP_CLIENT: u16 = 68;
const PORT_MDNS: u16 = 5353;
const PORT_LLMNR: u16 = 5355;

/// Try to extract an application event from a decoded packet.
#[must_use]
pub fn sniff(pkt: &PacketView<'_>) -> Option<AppEvent> {
    match pkt.transport.as_ref()? {
        TransportView::Udp(udp) => {
            let ports = (udp.src_port, udp.dst_port);
            let port_match = |port| ports.0 == port || ports.1 == port;
            if port_match(PORT_DNS) {
                dns::parse(udp.payload, false).map(AppEvent::Dns)
            // LLMNR shares the DNS wire format and multicast name-resolution
            // semantics; its events are deliberately folded under the "mdns"
            // label rather than given a fourth protocol bucket.
            } else if port_match(PORT_MDNS) || port_match(PORT_LLMNR) {
                dns::parse(udp.payload, true).map(AppEvent::Dns)
            } else if port_match(PORT_DHCP_SERVER) || port_match(PORT_DHCP_CLIENT) {
                dhcp::parse(udp.payload).map(AppEvent::Dhcp)
            } else {
                None
            }
        }
        TransportView::Tcp(tcp) if !tcp.payload.is_empty() => {
            // Content-based: TLS first (cheap one-byte check), then HTTP.
            tls::parse_client_hello(tcp.payload)
                .map(AppEvent::Tls)
                .or_else(|| http::parse_request(tcp.payload).map(AppEvent::Http))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_name;

    #[test]
    fn sanitize_name_neutralizes_terminal_escapes() {
        // An ANSI escape sequence is all-ASCII, so it must be defanged by the
        // name path, not just by a UTF-8 check.
        assert_eq!(sanitize_name("evil\u{1b}[2J\u{1b}[H"), "evil?[2J?[H");
        assert_eq!(sanitize_name("good-host.local"), "good-host.local");
        assert_eq!(sanitize_name("with\u{7}bell"), "with?bell");
    }
}
