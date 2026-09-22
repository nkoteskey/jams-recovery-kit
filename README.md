# jams-recovery-kit

Two Rust crates for backing up an application identity as a set of
guardian shares and rebuilding it on a fresh install.

- **`sss-gf256`** — Shamir's Secret Sharing over GF(2⁸) (the AES field),
  with field arithmetic written branch-free and table-free at the source
  level, plus a versioned recovery-kit payload with an extensible metadata
  map.
- **`jams-recovery-kit`** — the glue: a `RecoverableIdentity` trait your
  identity type implements, `create_kit` / `recover_kit` functions, an
  application-id check, and one SHA-256 digest over the whole serialized
  payload.

Both crates are `publish = false`: they are released as source, reviewed
as a repository, and consumed as a path or git dependency. Publishing to a
registry is a separate decision the owner takes after the first external
review.

## What it does

```rust
use jams_recovery_kit::{create_kit, recover_identity, ImportError, RecoverableIdentity};

struct MyIdentity {
    secret: Vec<u8>,
}

impl RecoverableIdentity for MyIdentity {
    fn export_material(&self) -> Vec<u8> {
        self.secret.clone()
    }
    fn import_material(bytes: &[u8]) -> Result<Self, ImportError> {
        Ok(Self { secret: bytes.to_vec() })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = MyIdentity { secret: vec![7u8; 32] };
    let shares = create_kit(&identity, "example-app", Some("my laptop".into()), 3, 5)?;
    // hand one share to each of five guardians; later collect any three
    let (recovered, label) = recover_identity::<MyIdentity>(&shares[..3], "example-app")?;
    assert_eq!(recovered.secret, identity.secret);
    assert_eq!(label.as_deref(), Some("my laptop"));
    Ok(())
}
```

Any three of the five shares rebuild the identity. Two shares recombine
to bytes that fail the frame check (a length that does not fit, or a
digest that does not verify), and the call returns an error. A
kit made for a different application id is rejected by name. A payload
edited after the kit was made — label, extension, timestamp or material —
fails the digest.

`examples/synthetic_identity.rs` runs the whole flow with a throwaway
identity:

```sh
cargo run -p jams-recovery-kit --example synthetic_identity
```

## Why it exists

Applications that keep a long-lived private key on the device — and never
on a server — need a way for the user to get it back after a lost or wiped
device that does not involve the application's authors holding a copy.
Shamir splitting across people the user chooses is that mechanism. The
engine is small enough to read in one sitting, which is the point: it is
easier to review a few hundred lines of field arithmetic than to reason
about a larger dependency's threat model.

## How to run it

```sh
cargo test                                             # both crates, plus this README's example
cargo clippy --all-targets -- -D warnings              # pedantic lints are on
cargo fmt --all -- --check
cargo deny check                                       # licenses, bans, sources, advisories
cargo audit                                            # RustSec advisories
cargo +nightly fuzz run split_combine                  # see fuzz/
```

Minimum supported Rust: **1.85** (`rust-version` in `Cargo.toml`; CI runs
the suite on 1.85.0). `rust-toolchain.toml` pins the version CI uses for
lints.

## What it will not do

- **Authenticate a kit's origin.** The digest is unkeyed. It detects
  corruption, mismatched share sets and post-hoc edits; anyone who can
  hand you a share set can make one that verifies. If you need to know
  the recovered identity is the one you expect, compare it to something
  you already trust (a known public key, a fingerprint shown to the user)
  after recovery.
- **Encrypt shares to their holders.** Shares are plain bytes. Wrap each
  one for its guardian yourself.
- **Persist anything.** `recover_kit` returns the identity; storing it is
  the caller's job, so a confirmation screen can sit in between.
- **Read kits from any other implementation.** The payload format is
  this repository's own (length-prefixed JSON envelope with base64
  material, versioned, digest-framed). `MIN_SUPPORTED_KIT_VERSION` is the
  oldest envelope a build will read.

## Threat model

The secret is the exported identity material. Assumed attacker: someone
who obtains fewer than `threshold` shares, or who tampers with shares in
transit. Not defended against: an attacker holding `threshold` or more
shares (that is the design), or one who can read process memory while a
kit is being created or recovered.

**What the digest covers.** SHA-256 over a fixed domain prefix, the
payload length, and the complete serialized payload: application id and
identity material (inside `identity_key_material`), `display_label`,
`created_at_unix`, and every entry of `extensions`. It is verified before
the payload is decoded. It is not keyed.

**Zeroization.** `Share::y`, the recombined bytes, the payload's material,
the polynomial coefficients drawn during a split, and the base64 text of
the material are zeroized on drop. This narrows the window; it does not
close it: `serde_json`'s internal buffers during `to_vec`/`from_slice`,
the `String` a caller builds to display a share, and any `clone()` the
caller makes are outside this crate's control.

**Field arithmetic.** `gf_mul` and `gf_inv` are written branch-free and
table-free at the source level (masks and XOR, exponent loop over a public
constant). That is a statement about the source, not a guarantee about the
compiler's output on any given target.

**Hostile input backstops** (each has a test):

| Input | What stops it | Test |
|---|---|---|
| Deeply nested JSON in `extensions` | `serde_json`'s recursion limit (128 levels) — decode fails as `Corrupt` | `deeply_nested_extensions_are_rejected` |
| Non-canonical base64 in the material (bad padding, trailing bits) | `base64`'s `STANDARD` engine requires canonical padding — decode fails as `Corrupt` | `non_canonical_base64_is_rejected` |
| Duplicate keys in the payload document | `serde` derive rejects a duplicated field — decode fails as `Corrupt` | `duplicate_fields_are_rejected` |
| Truncated or over-long frames, lengths that do not fit | Explicit `split_at_checked` framing — `Decode(..)`, never a panic | `framed_decoder_never_panics`, fuzz target `framed_payload_decode` |
| Unsupported `kit_version` | Explicit range check — `UnsupportedVersion` | `above_current_version_is_rejected`, `below_min_supported_version_is_rejected` |

Properties the code claims, and where each is tested:

| Claim | Where |
|---|---|
| Any `k` of `n` shares recover; every `k`-subset is tested exhaustively for small `n` | `split_then_any_threshold_subset_recovers` |
| Fewer than `k` shares do not recover (checked for every pair of a 3-of-5 split) | `fewer_than_threshold_does_not_recover` |
| A forged `x = 0` share is rejected rather than hijacking the reconstruction | `combine_rejects_a_forged_zero_index_share` |
| Field multiply matches a reference implementation on all 65 536 inputs | `branch_free_multiply_matches_reference_everywhere` |
| A tampered label, extension, timestamp or material fails recovery | `tampered_*_fails_the_integrity_check` (four tests) |
| Malformed payloads and frames never panic | `malformed_inputs_never_panic`, `framed_decoder_never_panics`, and the fuzz targets |
| Secret buffers are zeroized on drop | `Zeroizing` wrappers and `Drop for Share`; not tested (no portable way to observe freed memory) |
| No `unsafe` | `unsafe_code = "forbid"` in the workspace lints (both crates inherit `[lints] workspace = true`) |

The "two shares fail cleanly" property is probabilistic: two shares of a
3-of-5 split recombine to bytes that fail the length check or the digest
with overwhelming probability (about 2⁻²⁵⁶ of passing the digest), not
with certainty. There are no
benchmarks in this repository and no performance claims.

## How this repository is reviewed

CI runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
with pedantic lints enabled, `cargo test` (which compiles this README's
example as a doctest), the suite on the minimum supported Rust,
`cargo deny check`, `cargo audit`, and a nightly build and seed-corpus
replay of the fuzz targets. Changes to `gf_mul`, `combine_shares`,
`unframe`, `unseal_material` or the payload's `from_bytes` should come
with a test that pins the property they touch, and the fuzz corpus under
`fuzz/corpus/` should be re-run.

Security reports: see `SECURITY.md`. Contributions: `CONTRIBUTING.md`.

`SOURCE` names the upstream commit these crates were extracted from.

## License

Apache-2.0 — see `LICENSE` and `NOTICE`.
