//! DHCP (BOOTP) parsing. The interesting options for asset identification:
//! 53 message type, 12 hostname, 55 parameter request list (the classic
//! device fingerprint), 60 vendor class identifier.
#![deny(clippy::arithmetic_side_effects)]

use std::fmt;
use std::net::Ipv4Addr;

use serde::Serialize;

use crate::bytes::Cursor;
use crate::error::DecodeError;
use crate::types::MacAddr;

const MAGIC_COOKIE: u32 = 0x6382_5363;

const OPT_PAD: u8 = 0;
const OPT_SUBNET_MASK: u8 = 1;
const OPT_HOSTNAME: u8 = 12;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_LIST: u8 = 55;
const OPT_VENDOR_CLASS: u8 = 60;
const OPT_END: u8 = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DhcpMsgType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    Other(u8),
}

impl From<u8> for DhcpMsgType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for DhcpMsgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discover => write!(f, "DISCOVER"),
            Self::Offer => write!(f, "OFFER"),
            Self::Request => write!(f, "REQUEST"),
            Self::Decline => write!(f, "DECLINE"),
            Self::Ack => write!(f, "ACK"),
            Self::Nak => write!(f, "NAK"),
            Self::Release => write!(f, "RELEASE"),
            Self::Inform => write!(f, "INFORM"),
            Self::Other(code) => write!(f, "TYPE-{code}"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DhcpSummary {
    pub msg_type: DhcpMsgType,
    pub xid: u32,
    pub client_mac: MacAddr,
    /// `yiaddr` — the address the server assigns (OFFER/ACK).
    pub your_ip: Option<Ipv4Addr>,
    pub requested_ip: Option<Ipv4Addr>,
    pub server_id: Option<Ipv4Addr>,
    /// Option 1 — the subnet mask the server hands out (OFFER/ACK). Lets the
    /// asset inventory learn the *real* local segment size, not a /24 guess.
    pub subnet_mask: Option<Ipv4Addr>,
    /// `giaddr` — set when a relay forwarded this exchange from *another*
    /// segment: the client MAC and subnet then describe an off-link network,
    /// not the captured one.
    pub relay_ip: Option<Ipv4Addr>,
    pub hostname: Option<String>,
    pub vendor_class: Option<String>,
    /// Option 55 codes in request order — the device fingerprint.
    pub param_req_list: Vec<u8>,
}

impl DhcpSummary {
    /// Fingerprint in the conventional comma-separated form, e.g. `1,3,6,15`.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let codes: Vec<String> = self.param_req_list.iter().map(u8::to_string).collect();
        codes.join(",")
    }
}

/// Parse a DHCP message. `None` = does not look like DHCP.
#[must_use]
pub fn parse(payload: &[u8]) -> Option<DhcpSummary> {
    parse_inner(payload).ok()
}

fn parse_inner(payload: &[u8]) -> Result<DhcpSummary, DecodeError> {
    let mut cur = Cursor::new(payload);
    let op = cur.u8()?;
    if op != 1 && op != 2 {
        return Err(DecodeError::malformed("dhcp", "op is not request/reply"));
    }
    let htype = cur.u8()?;
    let hlen = cur.u8()?;
    if htype != 1 || hlen != 6 {
        return Err(DecodeError::malformed("dhcp", "not Ethernet hardware"));
    }
    cur.u8()?; // hops
    let xid = cur.u32_be()?;
    cur.u16_be()?; // secs
    cur.u16_be()?; // flags
    cur.ipv4()?; // ciaddr
    let yiaddr = cur.ipv4()?;
    cur.ipv4()?; // siaddr
    let giaddr = cur.ipv4()?;
    let client_mac = cur.mac()?;
    cur.skip(10)?; // rest of chaddr
    cur.skip(64)?; // sname
    cur.skip(128)?; // file
    if cur.u32_be()? != MAGIC_COOKIE {
        return Err(DecodeError::malformed("dhcp", "missing magic cookie"));
    }

    let mut summary = DhcpSummary {
        msg_type: DhcpMsgType::Other(0),
        xid,
        client_mac,
        your_ip: (!yiaddr.is_unspecified()).then_some(yiaddr),
        requested_ip: None,
        server_id: None,
        subnet_mask: None,
        relay_ip: (!giaddr.is_unspecified()).then_some(giaddr),
        hostname: None,
        vendor_class: None,
        param_req_list: Vec::new(),
    };
    let mut saw_msg_type = false;

    while !cur.is_empty() {
        let code = cur.u8()?;
        match code {
            OPT_PAD => continue,
            OPT_END => break,
            _ => {}
        }
        let len = usize::from(cur.u8()?);
        let value = cur.take(len)?;
        let mut val = Cursor::new(value);
        match code {
            OPT_MSG_TYPE => {
                summary.msg_type = DhcpMsgType::from(val.u8()?);
                saw_msg_type = true;
            }
            OPT_HOSTNAME => summary.hostname = Some(printable(value)),
            OPT_VENDOR_CLASS => summary.vendor_class = Some(printable(value)),
            OPT_SUBNET_MASK if len == 4 => summary.subnet_mask = Some(val.ipv4()?),
            OPT_REQUESTED_IP if len == 4 => summary.requested_ip = Some(val.ipv4()?),
            OPT_SERVER_ID if len == 4 => summary.server_id = Some(val.ipv4()?),
            OPT_PARAM_LIST => summary.param_req_list = value.to_vec(),
            _ => {}
        }
    }

    if !saw_msg_type {
        return Err(DecodeError::malformed("dhcp", "no message type option"));
    }
    Ok(summary)
}

/// Like `app::sanitize_name`, plus the space character — DHCP option values
/// (vendor class "MSFT 5.0") legitimately contain one; hostnames do not.
fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&byte| {
            if byte.is_ascii_graphic() || byte == b' ' {
                char::from(byte)
            } else {
                '?'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn discover(mac: MacAddr, hostname: &str, params: &[u8]) -> Vec<u8> {
        let mut msg = vec![1u8, 1, 6, 0]; // op, htype, hlen, hops
        msg.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // xid
        msg.extend_from_slice(&[0u8; 8]); // secs, flags, ciaddr
        msg.extend_from_slice(&[0u8; 12]); // yiaddr, siaddr, giaddr
        msg.extend_from_slice(&mac.0);
        msg.extend_from_slice(&[0u8; 10]); // chaddr padding
        msg.extend_from_slice(&[0u8; 192]); // sname + file
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&[53, 1, 1]); // DISCOVER
        msg.push(12);
        msg.push(u8::try_from(hostname.len()).unwrap());
        msg.extend_from_slice(hostname.as_bytes());
        msg.push(55);
        msg.push(u8::try_from(params.len()).unwrap());
        msg.extend_from_slice(params);
        msg.push(255);
        msg
    }

    #[test]
    fn parses_discover_with_fingerprint() {
        let mac = MacAddr([0x3C, 0x22, 0xFB, 1, 2, 3]);
        let summary = parse(&discover(mac, "carols-laptop", &[1, 3, 6, 15, 119])).unwrap();
        assert_eq!(summary.msg_type, DhcpMsgType::Discover);
        assert_eq!(summary.client_mac, mac);
        assert_eq!(summary.hostname.as_deref(), Some("carols-laptop"));
        assert_eq!(summary.fingerprint(), "1,3,6,15,119");
        assert!(summary.your_ip.is_none());
    }

    #[test]
    fn rejects_non_dhcp() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0xFF; 300]).is_none());
        // valid BOOTP shape but no magic cookie
        let mut msg = discover(MacAddr::ZERO, "x", &[1]);
        msg[236] ^= 0xFF;
        assert!(parse(&msg).is_none());
    }
}
