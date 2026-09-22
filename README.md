# jams-recovery-kit

Two Rust crates for backing up an application identity as a set of
guardian shares and rebuilding it on a fresh install.

- **`sss-gf256`** — Shamir's Secret Sharing over GF(2⁸) (the AES field),
  branch-free field arithmetic with no lookup tables, plus a versioned
  recovery-kit payload with an extensible metadata map.
- **`jams-recovery-kit`** — the glue: a `RecoverableIdentity` trait your
  identity type implements, `create_kit` / `recover_kit` functions, an
  application-id check, and a SHA-256 integrity check on the recovered
  material.

## What it does

```rust
use jams_recovery_kit::{create_kit, recover_identity, RecoverableIdentity, ImportError};

struct MyIdentity { secret: Vec<u8> }

impl RecoverableIdentity for MyIdentity {
    fn export_material(&self) -> Vec<u8> { self.secret.clone() }
    fn import_material(bytes: &[u8]) -> Result<Self, ImportError> {
        Ok(Self { secret: bytes.to_vec() })
    }
}

let identity = MyIdentity { secret: vec![0u8; 32] };
let shares = create_kit(&identity, "example-app", Some("my laptop".into()), 3, 5)?;
// hand one share to each of five guardians …
let (recovered, label) = recover_identity::<MyIdentity>(&shares[..3], "example-app")?;
```

Any three of the five shares rebuild the identity. Two shares recombine
to bytes that fail to decode, and the call returns an error rather than a
wrong identity. A kit made for a different application id is rejected by
name. A corrupted material blob that still decodes is caught by the
digest.

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
easier to review 300 lines of field arithmetic than to reason about a
larger dependency's threat model.

## How to run it

```sh
cargo test                                             # both crates
cargo clippy --all-targets -- -D warnings              # pedantic lints are on
cargo fmt --all -- --check
cargo deny check                                       # licenses, bans, sources, advisories
cargo audit                                            # RustSec advisories
cargo +nightly fuzz run split_combine                  # see fuzz/
```

Minimum supported Rust: 1.80 (see `Cargo.toml`); `rust-toolchain.toml`
pins the version CI uses.

## What it will not do

- **Integrity or authentication.** Shamir provides confidentiality only.
  This crate checks share *shape*, payload decoding, the application id,
  and a digest of the material — enough to detect accidental corruption
  and wrong-kit mistakes, not enough to detect a malicious quorum, since
  anyone holding `k` shares can produce a valid digest. If you need to
  know the recovered identity is the one you expect, compare it to
  something you already trust (a known public key, a fingerprint shown
  to the user) after recovery.
- **Encrypting shares to their holders.** Shares are plain bytes. Wrap
  each one for its guardian yourself.
- **Persisting anything.** `recover_kit` returns the identity; storing it
  is the caller's job, so a confirmation screen can sit in between.
- **Reading kits from any other implementation.** The payload format is
  this repository's own (JSON envelope, base64 material, versioned).
  `MIN_SUPPORTED_KIT_VERSION` is the oldest envelope a build will read.

## Threat model

The secret is the exported identity material. Assumed attacker: someone
who obtains fewer than `threshold` shares, or who tampers with shares in
transit. Not defended against: an attacker holding `threshold` or more
shares (that is the design), or one who can read process memory while a
kit is being created or recovered (zeroization narrows the window; it
does not close it).

Properties the code claims, and where each is tested:

| Claim | Where |
|---|---|
| Any `k` of `n` shares recover; every `k`-subset is tested exhaustively for small `n` | `sss-gf256` tests `split_then_any_threshold_subset_recovers` |
| Fewer than `k` shares do not recover (checked for every pair of a 3-of-5 split) | `fewer_than_threshold_does_not_recover` |
| A forged `x = 0` share is rejected rather than hijacking the reconstruction | `combine_rejects_a_forged_zero_index_share` |
| Field multiply is branch-free and matches a reference implementation on all 65 536 inputs | `branch_free_multiply_matches_reference_everywhere` |
| Malformed payloads and sealed blobs never panic | `malformed_inputs_never_panic`, `sealed_material_decoder_never_panics`, and the fuzz targets |
| Unsupported payload versions are rejected explicitly | `above_current_version_is_rejected`, `below_min_supported_version_is_rejected` |
| Secret buffers are zeroized on drop | `Zeroizing` wrappers and `Drop for Share`; not tested (no portable way to observe freed memory) |
| No `unsafe` | `unsafe_code = "forbid"` at the workspace level |

Timing: the field arithmetic has no secret-dependent branches or memory
accesses. Nothing else in the crate is claimed to be constant-time.
There are no benchmarks in this repository and no performance claims.

## How this repository is reviewed

CI runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
with pedantic lints enabled, `cargo test`, `cargo deny check`, `cargo
audit`, and a nightly build of the fuzz targets. Changes to `gf_mul`,
`combine_shares`, `unseal` or the payload's `from_bytes` should come with
a test that pins the property they touch, and the fuzz corpus under
`fuzz/corpus/` should be re-run.

`SOURCE` names the upstream commit these crates were extracted from.

## License

Apache-2.0 — see `LICENSE` and `NOTICE`.
