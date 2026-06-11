//! Legacy pcap record stream: a valid global header prefix (little-endian µs
//! magic, Ethernet) so the fuzzed bytes are parsed as record headers and
//! bodies — per-record length fields, snaplen lies, and the truncated-tail
//! exit, not the magic check.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut file = pincer_fuzz::legacy_header_le();
    file.extend_from_slice(data);
    pincer_fuzz::drain_capture(&file);
});
