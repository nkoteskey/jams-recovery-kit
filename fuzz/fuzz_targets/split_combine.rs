#![no_main]
//! Two properties, both must hold for every input:
//! 1. `split_secret(secret, k, n)` followed by `combine_shares` over any
//!    k-subset returns `secret` (round trip), and never panics for any
//!    (k, n) pair, valid or not.
//! 2. `combine_shares` never panics on arbitrary, attacker-shaped shares.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sss_gf256::{combine_shares, split_secret, Share};

#[derive(Arbitrary, Debug)]
struct Input {
    secret: Vec<u8>,
    threshold: u8,
    shares: u8,
    pick: u16,
    arbitrary_shares: Vec<(u8, Vec<u8>)>,
}

fuzz_target!(|input: Input| {
    // Keep the byte-wise polynomial work bounded per iteration.
    let secret: Vec<u8> = input.secret.into_iter().take(512).collect();
    let n = input.shares.min(16);
    if let Ok(shares) = split_secret(&secret, input.threshold, n) {
        let k = usize::from(input.threshold);
        // A deterministic k-subset chosen by `pick`.
        let start = usize::from(input.pick) % shares.len().max(1);
        let subset: Vec<Share> = shares.iter().cycle().skip(start).take(k).cloned().collect();
        let recovered = combine_shares(&subset).expect("k distinct valid shares combine");
        assert_eq!(recovered.as_slice(), secret.as_slice());
    }

    let arbitrary: Vec<Share> = input
        .arbitrary_shares
        .into_iter()
        .take(16)
        .map(|(x, y)| Share { x, y: y.into_iter().take(512).collect() })
        .collect();
    let _ = combine_shares(&arbitrary);
});
