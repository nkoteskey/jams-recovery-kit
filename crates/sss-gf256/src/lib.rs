//! Shamir's Secret Sharing over GF(2⁸), plus a versioned recovery-kit
//! payload that rides on top of it.
//!
//! [`split_secret`] splits an arbitrary byte string into `n` shares of
//! which any `k` reconstruct it via [`combine_shares`], and **fewer than
//! `k` reveal nothing**. The field is the AES/Rijndael GF(2⁸) with
//! reduction polynomial `0x11b`; the arithmetic is branch-free and uses no
//! lookup tables, so there is no secret-dependent memory access or control
//! flow in the share computation.
//!
//! [`RecoveryKitPayload`] is the envelope an application splits: an opaque
//! secret plus non-secret metadata (a display label, a creation time, an
//! extensible map), with a `kit_version` that a reader checks against an
//! explicit supported range before trusting the shape.
//!
//! # What this scheme does and does not provide
//!
//! - **Confidentiality:** any `k-1` shares are statistically independent of
//!   the secret.
//! - **Not integrity:** Shamir provides no authentication. A corrupted or
//!   forged share recombines to a *different* secret rather than an error.
//!   [`combine_shares`] validates share *shape* (consistent lengths,
//!   distinct non-zero indices) and [`RecoveryKitPayload::recover`] fails
//!   when the result does not decode, but a caller that needs to trust the
//!   recovered bytes must verify them against something it already knows
//!   (a public key, a digest). The `jams-recovery-kit` crate does exactly
//!   that on top of this one.
//! - **Not a threshold signature or a key-management system.** Shares are
//!   plain bytes; encrypting each share to its holder is the caller's job.
//!
//! Secret material ([`Share::y`], the reconstructed bytes, the payload's
//! key material, and the polynomial coefficients drawn during a split) is
//! zeroized on drop via the `zeroize` crate.

pub mod payload;

pub use payload::{RecoveryKitError, RecoveryKitPayload, CURRENT_KIT_VERSION, MIN_SUPPORTED_KIT_VERSION};

use zeroize::{Zeroize, Zeroizing};

/// Errors from splitting or recovering a secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryError {
    /// `threshold` was 0 or larger than the share count.
    #[error("threshold must be between 1 and the share count")]
    BadThreshold,
    /// The secret was empty.
    #[error("secret must be non-empty")]
    EmptySecret,
    /// No shares were supplied to [`combine_shares`].
    #[error("need at least one share to recover")]
    NoShares,
    /// Shares differ in length or repeat an x-coordinate.
    #[error("shares disagree on length or repeat an x-coordinate")]
    InconsistentShares,
    /// A share carried `x = 0`, which is the secret's own evaluation point.
    #[error("share index must be non-zero — x=0 IS the secret, not a valid share")]
    ZeroShareIndex,
    /// The operating system's random number source failed.
    #[error("operating-system randomness unavailable")]
    RandomnessUnavailable,
}

/// One share: the evaluation point `x` (never 0 — `x=0` is the secret) and
/// one y-value per secret byte.
///
/// `y` is zeroized when the share is dropped. `Debug` prints the index and
/// length only, never the bytes.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Share {
    /// Evaluation point, `1..=255`.
    pub x: u8,
    /// One field element per secret byte.
    pub y: Vec<u8>,
}

impl Drop for Share {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share")
            .field("x", &self.x)
            .field("len", &self.y.len())
            .finish_non_exhaustive()
    }
}

/// GF(2⁸) multiply (AES polynomial `0x11b`), branch-free: every step
/// computes a mask from one bit and applies it with AND/XOR, so neither
/// the control flow nor the memory access pattern depends on the operands.
#[must_use]
pub fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p: u8 = 0;
    for _ in 0..8 {
        let low_bit_mask = 0u8.wrapping_sub(b & 1);
        p ^= a & low_bit_mask;
        let high_bit_mask = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1b & high_bit_mask);
        b >>= 1;
    }
    p
}

/// GF(2⁸) exponentiation by squaring. The exponent is public (it is always
/// 254 here), so the loop over its bits leaks nothing.
fn gf_pow(base: u8, exp: u16) -> u8 {
    let mut base = base;
    let mut exp = exp;
    let mut acc: u8 = 1;
    while exp > 0 {
        let take = 0u8.wrapping_sub((exp & 1) as u8);
        acc = gf_mul(acc, base & take | 1 & !take);
        base = gf_mul(base, base);
        exp >>= 1;
    }
    acc
}

/// Multiplicative inverse in GF(2⁸): `a^254` (since `a^255 = 1`).
/// `gf_inv(0)` returns 0; callers never pass 0 (all x-coordinates are
/// non-zero and distinct, so every denominator is non-zero).
#[must_use]
pub fn gf_inv(a: u8) -> u8 {
    gf_pow(a, 254)
}

fn fill_random(buf: &mut [u8]) -> Result<(), RecoveryError> {
    getrandom::fill(buf).map_err(|_| RecoveryError::RandomnessUnavailable)
}

/// Split `secret` into `shares` shares, any `threshold` of which recover it.
///
/// Byte-wise: each secret byte is the constant term of an independent
/// random degree-`(threshold-1)` polynomial; share `i` is that polynomial
/// family evaluated at `x = i`.
pub fn split_secret(secret: &[u8], threshold: u8, shares: u8) -> Result<Vec<Share>, RecoveryError> {
    if secret.is_empty() {
        return Err(RecoveryError::EmptySecret);
    }
    // `shares` is a u8, so the 255-point limit of the field is enforced by
    // the type; the only invalid inputs are an empty secret and a threshold
    // outside `1..=shares`.
    if threshold < 1 || threshold > shares {
        return Err(RecoveryError::BadThreshold);
    }

    let degree = usize::from(threshold) - 1;
    let mut coeffs = Zeroizing::new(vec![0u8; degree * secret.len()]);
    if !coeffs.is_empty() {
        fill_random(&mut coeffs)?;
    }

    let mut out: Vec<Share> = (1..=shares)
        .map(|x| Share {
            x,
            y: Vec::with_capacity(secret.len()),
        })
        .collect();

    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        let base = byte_idx * degree;
        for share in &mut out {
            // Horner evaluation at share.x.
            let mut acc = 0u8;
            for c in (0..degree).rev() {
                acc = gf_mul(acc, share.x) ^ coeffs[base + c];
            }
            acc = gf_mul(acc, share.x) ^ secret_byte;
            share.y.push(acc);
        }
    }
    Ok(out)
}

/// Reconstruct the secret via Lagrange interpolation at `x = 0` over the
/// supplied shares. With at least `threshold` correct shares this is the
/// secret; with fewer it is (deterministically) wrong — the scheme reveals
/// nothing early. See the crate docs: this is confidentiality, not
/// integrity, and the caller must verify the result.
///
/// Rejects an empty set, mismatched lengths, duplicate indices, and any
/// share with `x = 0`: in the Lagrange basis a share at `x = 0` gets basis
/// 1 while every other share's basis collapses to 0, so a single forged
/// `x = 0` share would hijack the whole reconstruction and make the result
/// equal its own bytes regardless of every legitimate share.
pub fn combine_shares(shares: &[Share]) -> Result<Zeroizing<Vec<u8>>, RecoveryError> {
    let first = shares.first().ok_or(RecoveryError::NoShares)?;
    let len = first.y.len();
    for (i, s) in shares.iter().enumerate() {
        if s.x == 0 {
            return Err(RecoveryError::ZeroShareIndex);
        }
        if s.y.len() != len {
            return Err(RecoveryError::InconsistentShares);
        }
        if shares[..i].iter().any(|o| o.x == s.x) {
            return Err(RecoveryError::InconsistentShares);
        }
    }

    // Each share's Lagrange basis value at 0: Π_{m≠i} x_m / (x_i ⊕ x_m).
    let basis: Vec<u8> = shares
        .iter()
        .map(|si| {
            let mut num = 1u8;
            let mut den = 1u8;
            for sm in shares {
                if sm.x == si.x {
                    continue;
                }
                num = gf_mul(num, sm.x);
                den = gf_mul(den, si.x ^ sm.x);
            }
            gf_mul(num, gf_inv(den))
        })
        .collect();

    let mut secret = Zeroizing::new(Vec::with_capacity(len));
    for j in 0..len {
        let mut acc = 0u8;
        for (i, s) in shares.iter().enumerate() {
            acc ^= gf_mul(s.y[j], basis[i]);
        }
        secret.push(acc);
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference (branching, table-free) multiply to check the branch-free
    /// one against, over the whole 256×256 space.
    fn gf_mul_reference(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        for _ in 0..8 {
            if b & 1 != 0 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        p
    }

    #[test]
    fn gf_field_known_vectors() {
        // FIPS-197 worked examples.
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
        assert_eq!(gf_mul(0x57, 0x13), 0xfe);
        assert_eq!(gf_mul(0x53, 0xca), 0x01);
        assert_eq!(gf_mul(0xab, 1), 0xab);
        assert_eq!(gf_mul(0xab, 0), 0x00);
        for a in 1u8..=255 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse of {a:#x}");
        }
        assert_eq!(gf_inv(0), 0);
    }

    #[test]
    fn branch_free_multiply_matches_reference_everywhere() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(gf_mul(a, b), gf_mul_reference(a, b), "{a:#x} * {b:#x}");
                assert_eq!(gf_mul(a, b), gf_mul(b, a), "commutativity {a:#x} {b:#x}");
            }
        }
    }

    fn assert_every_k_subset_recovers(secret: &[u8], k: u8, shares: &[Share]) {
        let idxs: Vec<usize> = (0..shares.len()).collect();
        for mask in 1u32..(1 << shares.len()) {
            if mask.count_ones() != u32::from(k) {
                continue;
            }
            let subset: Vec<Share> = idxs
                .iter()
                .filter(|&&i| mask & (1 << i) != 0)
                .map(|&i| shares[i].clone())
                .collect();
            assert_eq!(
                combine_shares(&subset).unwrap().as_slice(),
                secret,
                "subset mask {mask:b} of {k}-of-{} failed",
                shares.len()
            );
        }
    }

    #[test]
    fn split_then_any_threshold_subset_recovers() {
        let secret = b"a-secret-key-stand-in-of-some-length";
        let shares = split_secret(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        assert!(shares.iter().all(|s| s.y.len() == secret.len()));
        assert_every_k_subset_recovers(secret, 3, &shares);
        assert_every_k_subset_recovers(secret, 4, &shares);
        assert_every_k_subset_recovers(secret, 5, &shares);
    }

    #[test]
    fn fewer_than_threshold_does_not_recover() {
        let secret = b"top-secret-payload";
        let shares = split_secret(secret, 3, 5).unwrap();
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                let pair = [shares[i].clone(), shares[j].clone()];
                assert_ne!(
                    combine_shares(&pair).unwrap().as_slice(),
                    secret,
                    "2 shares ({i},{j}) must not reconstruct a 3-of-5 secret"
                );
            }
        }
    }

    #[test]
    fn combine_rejects_a_forged_zero_index_share() {
        let secret = b"attack me if you can";
        let shares = split_secret(secret, 3, 5).unwrap();
        let forged = Share {
            x: 0,
            y: b"NOT the real secret!".to_vec(),
        };
        let mixed = vec![shares[0].clone(), shares[1].clone(), forged];
        assert_eq!(combine_shares(&mixed).unwrap_err(), RecoveryError::ZeroShareIndex);

        let only_forged = vec![Share {
            x: 0,
            y: secret.to_vec(),
        }];
        assert_eq!(
            combine_shares(&only_forged).unwrap_err(),
            RecoveryError::ZeroShareIndex
        );
    }

    #[test]
    fn shares_are_not_the_secret_in_the_clear() {
        let secret = b"do-not-leak-me";
        let shares = split_secret(secret, 2, 3).unwrap();
        for s in &shares {
            assert_ne!(&s.y, secret, "a k>=2 share must not equal the secret");
        }
    }

    #[test]
    fn threshold_one_every_share_is_the_secret() {
        let secret = b"k1";
        let shares = split_secret(secret, 1, 4).unwrap();
        for s in &shares {
            assert_eq!(
                combine_shares(std::slice::from_ref(s)).unwrap().as_slice(),
                secret
            );
        }
    }

    #[test]
    fn maximum_share_count_round_trips() {
        let secret = b"max";
        let shares = split_secret(secret, 255, 255).unwrap();
        assert_eq!(shares.len(), 255);
        assert_eq!(combine_shares(&shares).unwrap().as_slice(), secret);
    }

    #[test]
    fn large_random_secret_round_trips() {
        let mut secret = vec![0u8; 4096];
        getrandom::fill(&mut secret).unwrap();
        let shares = split_secret(&secret, 3, 5).unwrap();
        let recovered = combine_shares(&[shares[4].clone(), shares[1].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered.as_slice(), secret.as_slice());
    }

    #[test]
    fn split_rejects_bad_parameters() {
        assert_eq!(split_secret(b"", 2, 3), Err(RecoveryError::EmptySecret));
        assert_eq!(split_secret(b"x", 0, 3), Err(RecoveryError::BadThreshold));
        assert_eq!(split_secret(b"x", 4, 3), Err(RecoveryError::BadThreshold));
    }

    #[test]
    fn combine_rejects_malformed_share_sets() {
        assert_eq!(combine_shares(&[]), Err(RecoveryError::NoShares));
        let shares = split_secret(b"abcd", 2, 3).unwrap();
        let dup = [shares[0].clone(), shares[0].clone()];
        assert_eq!(combine_shares(&dup), Err(RecoveryError::InconsistentShares));
        let mut short = shares[1].clone();
        short.y.pop();
        assert_eq!(
            combine_shares(&[shares[0].clone(), short]),
            Err(RecoveryError::InconsistentShares)
        );
    }

    #[test]
    fn debug_never_prints_share_bytes() {
        let shares = split_secret(b"sensitive", 2, 2).unwrap();
        let text = format!("{:?}", shares[0]);
        assert!(text.contains("len: 9"));
        assert!(!text.contains("sensitive"));
        assert!(!text.contains('['));
    }

    #[test]
    fn share_serde_round_trip() {
        let shares = split_secret(b"serde", 2, 3).unwrap();
        let json = serde_json::to_string(&shares).unwrap();
        let back: Vec<Share> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, shares);
        assert_eq!(combine_shares(&back[..2]).unwrap().as_slice(), b"serde");
    }
}
