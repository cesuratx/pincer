//! pcapng block walking: a valid little-endian SHB+IDB prefix puts every
//! fuzzed byte past the magic/version gates and straight into the block
//! loop — option walks, EPB/SPB body checks, the interface table, and
//! mid-stream SHB resets.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut file = pincer_fuzz::shb_le();
    file.extend_from_slice(&pincer_fuzz::idb_le());
    file.extend_from_slice(data);
    pincer_fuzz::drain_capture(&file);
});
