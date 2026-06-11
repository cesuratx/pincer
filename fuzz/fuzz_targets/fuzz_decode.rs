//! `decode_packet` across every supported link type on the same bytes, with
//! no container framing in the way — the layer decoders and app sniffers see
//! raw mutation directly. One extra Ethernet pass claims a longer wire
//! length to drive the snaplen-truncation bookkeeping.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pincer::app::sniff;
use pincer::decode::decode_packet;
use pincer::pcap::{LinkType, Record};

fuzz_target!(|data: &[u8]| {
    let orig_len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    for link_type in [
        LinkType::Ethernet,
        LinkType::LinuxSll,
        LinkType::LinuxSll2,
        LinkType::Raw,
        LinkType::NullLoop,
    ] {
        let record = Record {
            ts: None,
            orig_len,
            link_type,
            data,
        };
        if let Ok(pkt) = decode_packet(&record) {
            std::hint::black_box(pkt.ip_pair());
            std::hint::black_box(sniff(&pkt));
        }
    }
    let record = Record {
        ts: None,
        orig_len: orig_len.saturating_add(1),
        link_type: LinkType::Ethernet,
        data,
    };
    if let Ok(pkt) = decode_packet(&record) {
        std::hint::black_box(pkt.truncated);
    }
});
