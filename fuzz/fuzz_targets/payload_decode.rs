#![no_main]
//! `RecoveryKitPayload::from_bytes` and `::recover` must never panic on
//! arbitrary bytes or arbitrary shares, and a payload that decodes must
//! round-trip through `to_bytes`.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sss_gf256::{RecoveryKitPayload, Share};

#[derive(Arbitrary, Debug)]
struct Input {
    bytes: Vec<u8>,
    shares: Vec<(u8, Vec<u8>)>,
}

fuzz_target!(|input: Input| {
    if let Ok(payload) = RecoveryKitPayload::from_bytes(&input.bytes) {
        let again = payload.to_bytes().expect("a decoded payload re-encodes");
        let back = RecoveryKitPayload::from_bytes(&again).expect("re-encoded payload decodes");
        assert_eq!(back, payload);
    }
    let shares: Vec<Share> = input
        .shares
        .into_iter()
        .take(16)
        .map(|(x, y)| Share { x, y: y.into_iter().take(1024).collect() })
        .collect();
    let _ = RecoveryKitPayload::recover(&shares);
});
