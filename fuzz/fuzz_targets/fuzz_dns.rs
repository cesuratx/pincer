//! Straight into the DNS message parser — name decompression (the one place
//! wire bytes amplify into heap bytes) and the query/answer walks — in both
//! DNS and mDNS modes. Also asserts the documented depth contract
//! (`src/app/mod.rs`): `parse_shallow` must accept and reject exactly the
//! payloads `parse` does.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pincer::app::dns;

fuzz_target!(|data: &[u8]| {
    for is_mdns in [false, true] {
        let deep = dns::parse(data, is_mdns);
        let shallow = dns::parse_shallow(data, is_mdns);
        assert_eq!(
            deep.is_some(),
            shallow.is_some(),
            "depth modes must agree on accept/reject"
        );
        std::hint::black_box(deep);
    }
});
