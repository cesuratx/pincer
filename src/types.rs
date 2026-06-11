//! Small shared value types: MAC addresses, timestamps, transport protocols.

use std::fmt;

use serde::Serialize;

/// Newtype over the raw 6 bytes; formats as `aa:bb:cc:dd:ee:ff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: Self = Self([0xFF; 6]);
    pub const ZERO: Self = Self([0; 6]);

    /// Group bit (LSB of first octet) set ⇒ multicast (includes broadcast).
    #[must_use]
    pub const fn is_multicast(self) -> bool {
        self.0[0] & 0x01 != 0
    }

    #[must_use]
    pub fn is_broadcast(self) -> bool {
        self == Self::BROADCAST
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [b0, b1, b2, b3, b4, b5] = self.0;
        write!(f, "{b0:02x}:{b1:02x}:{b2:02x}:{b3:02x}:{b4:02x}:{b5:02x}")
    }
}

impl Serialize for MacAddr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Capture timestamp normalized to seconds + nanoseconds since the Unix epoch.
/// Ord derives from field order, so flows sort chronologically for free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Timestamp {
    pub secs: u64,
    pub nanos: u32,
}

impl Timestamp {
    pub const ZERO: Self = Self { secs: 0, nanos: 0 };

    /// `9999-12-31T23:59:59Z` in Unix seconds. A pcapng interface with an
    /// extreme `if_tsresol` can otherwise yield a year ≥ 10000, which prints a
    /// 5-digit year that strict RFC 3339 parsers reject. We clamp so the
    /// Display contract (4-digit year) always holds; a real capture is never
    /// near this bound.
    const MAX_SECS: u64 = 253_402_300_799;

    #[must_use]
    pub const fn new(secs: u64, nanos: u32) -> Self {
        Self {
            secs: if secs > Self::MAX_SECS {
                Self::MAX_SECS
            } else {
                secs
            },
            nanos,
        }
    }

    /// Elapsed seconds since `earlier`, clamped at zero — capture timestamps
    /// are not guaranteed monotonic (multi-interface merges, clock steps).
    #[must_use]
    pub fn secs_since(self, earlier: Self) -> f64 {
        if self < earlier {
            return 0.0;
        }
        let secs = self.secs.saturating_sub(earlier.secs);
        let nanos = f64::from(self.nanos) - f64::from(earlier.nanos);
        secs as f64 + nanos / 1e9
    }
}

/// Days-to-civil-date conversion (Howard Hinnant's algorithm) so we can print
/// human timestamps without a date-time dependency.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    (year, month as u32, day as u32)
}

impl fmt::Display for Timestamp {
    /// RFC 3339 / ISO 8601 in UTC — human-readable *and* machine-parseable,
    /// with an explicit `Z` so no consumer has to guess the zone.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[allow(clippy::cast_possible_wrap)]
        let days = (self.secs / 86_400) as i64;
        let rem = self.secs % 86_400;
        let (year, month, day) = civil_from_days(days);
        let (hh, mm, ss) = (rem / 3600, rem % 3600 / 60, rem % 60);
        let micros = self.nanos / 1000;
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}.{micros:06}Z"
        )
    }
}

impl Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Transport protocol of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IpProto {
    Tcp,
    Udp,
    Sctp,
    Icmp,
    IcmpV6,
    Other(u8),
}

impl IpProto {
    #[must_use]
    pub const fn from_ip_number(proto: u8) -> Self {
        match proto {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            58 => Self::IcmpV6,
            132 => Self::Sctp,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for IpProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Sctp => write!(f, "sctp"),
            Self::Icmp => write!(f, "icmp"),
            Self::IcmpV6 => write!(f, "icmpv6"),
            Self::Other(n) => match ip_proto_name(*n) {
                Some(name) => write!(f, "{name}"),
                None => write!(f, "proto-{n}"),
            },
        }
    }
}

/// Name for an IANA IP protocol number we do not decode but recognize. These
/// are the infrastructure protocols a passive sensor should *name* rather than
/// bucket as anonymous "other": routing, redundancy, multicast, and tunnels
/// all tell you something about the network's shape.
#[must_use]
pub fn ip_proto_name(proto: u8) -> Option<&'static str> {
    Some(match proto {
        2 => "igmp",
        41 => "ip6-in-ip",
        47 => "gre",
        50 => "esp",
        51 => "ah",
        88 => "eigrp",
        89 => "ospf",
        94 => "ipip",
        103 => "pim",
        112 => "vrrp",
        115 => "l2tp",
        _ => return None,
    })
}

impl Serialize for IpProto {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_clamps_to_four_digit_year() {
        // A year-10000 timestamp must clamp so Display stays RFC-3339 valid.
        let huge = Timestamp::new(u64::MAX, 0);
        assert_eq!(huge.to_string(), "9999-12-31T23:59:59.000000Z");
        // A normal timestamp is untouched.
        assert_eq!(Timestamp::new(1_781_049_600, 0).secs, 1_781_049_600);
    }

    #[test]
    fn mac_display_and_flags() {
        let mac = MacAddr([0xAA, 0xBB, 0x0C, 0x01, 0x02, 0x03]);
        assert_eq!(mac.to_string(), "aa:bb:0c:01:02:03");
        assert!(!mac.is_multicast());
        assert!(MacAddr::BROADCAST.is_multicast());
        assert!(MacAddr([0x01, 0, 0x5E, 0, 0, 1]).is_multicast()); // IPv4 mcast OUI
    }

    #[test]
    fn timestamp_formats_utc() {
        // 2026-06-10 00:00:00 UTC
        let ts = Timestamp::new(1_781_049_600, 250_000);
        assert_eq!(ts.to_string(), "2026-06-10T00:00:00.000250Z");
        assert_eq!(Timestamp::ZERO.to_string(), "1970-01-01T00:00:00.000000Z");
    }

    #[test]
    fn named_ip_protocols_render_by_name() {
        assert_eq!(IpProto::from_ip_number(112).to_string(), "vrrp");
        assert_eq!(IpProto::from_ip_number(89).to_string(), "ospf");
        assert_eq!(IpProto::from_ip_number(47).to_string(), "gre");
        assert_eq!(IpProto::from_ip_number(50).to_string(), "esp");
        assert_eq!(IpProto::from_ip_number(2).to_string(), "igmp");
        // Unknown numbers still fall back to the explicit proto-N form.
        assert_eq!(IpProto::from_ip_number(200).to_string(), "proto-200");
    }

    #[test]
    fn secs_since_clamps_backwards_clock() {
        let early = Timestamp::new(100, 0);
        let late = Timestamp::new(101, 500_000_000);
        assert!((late.secs_since(early) - 1.5).abs() < 1e-9);
        assert!(early.secs_since(late).abs() < f64::EPSILON);
    }
}
