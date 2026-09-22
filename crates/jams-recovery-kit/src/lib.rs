//! Guardian recovery kit — glue between an application's identity type and
//! the [`sss_gf256`] Shamir engine.
//!
//! An application implements [`RecoverableIdentity`] for whatever holds its
//! long-lived secret (a signing keypair, a device key, a seed). This crate
//! then:
//!
//! 1. exports that material, tags it with the application id, and seals it
//!    with a SHA-256 digest into an opaque blob;
//! 2. places the blob in a [`RecoveryKitPayload`] (with an optional display
//!    label and an `extensions` map for anything else that should ride the
//!    same kit) and Shamir-splits it into `n` shares, any `k` of which
//!    reconstruct it;
//! 3. on recovery, recombines the shares, rejects an unsupported payload
//!    version, checks the application id, verifies the digest, and only
//!    then hands the bytes to [`RecoverableIdentity::import_material`].
//!
//! # What the digest does and does not do
//!
//! Shamir provides confidentiality, not authentication: fewer-than-threshold
//! or mismatched shares recombine to *wrong* bytes rather than an error.
//! The JSON envelope catches most of that by failing to decode; the digest
//! catches the rest (a corrupted material blob that still decodes). What
//! the digest does **not** do is authenticate the kit's origin: any party
//! holding `k` shares can produce a payload with a valid digest. If you
//! need origin authentication, verify the imported identity against
//! something you already trust (a known public key, a fingerprint shown to
//! the user) after `recover_kit` returns.
//!
//! Every buffer holding secret material is zeroized on drop.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub use sss_gf256::{
    RecoveryKitError, RecoveryKitPayload, Share, CURRENT_KIT_VERSION, MIN_SUPPORTED_KIT_VERSION,
};

/// Error type an identity's `import_material` may return.
pub type ImportError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// An identity that can be exported to bytes and rebuilt from them.
///
/// Implement this for the type that owns your application's long-lived
/// secret. `export_material` must return *everything* needed to rebuild an
/// equivalent identity; `import_material` must be the exact inverse and
/// must reject bytes it does not understand with an error, never a panic.
pub trait RecoverableIdentity: Sized {
    /// Serialize the identity's secret material. The returned buffer is
    /// wrapped in a zeroizing container immediately by this crate; callers
    /// that build the `Vec` themselves should avoid leaving copies around.
    fn export_material(&self) -> Vec<u8>;

    /// Rebuild an identity from bytes produced by [`Self::export_material`].
    fn import_material(bytes: &[u8]) -> std::result::Result<Self, ImportError>;
}

/// Errors from creating or recovering a kit.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The payload layer rejected the shares or the envelope.
    #[error(transparent)]
    Kit(#[from] RecoveryKitError),
    /// The application id is longer than the framing allows.
    #[error("application id too long ({0} bytes; limit is 65535)")]
    AppIdTooLong(usize),
    /// The material blob is larger than the framing allows.
    #[error("identity material too large ({0} bytes; limit is 4 GiB)")]
    MaterialTooLarge(usize),
    /// The sealed material blob inside the payload was malformed.
    #[error("decode identity material from kit: {0}")]
    Decode(&'static str),
    /// The kit was made for a different application.
    #[error("kit was created for {found:?} but this application is {expected:?}")]
    WrongApp {
        /// Application id found in the kit.
        found: String,
        /// Application id the caller expected.
        expected: String,
    },
    /// The material's digest did not verify — corrupt shares slipped past
    /// envelope decoding.
    #[error("recovered material failed the integrity check — corrupt or mismatched shares")]
    IntegrityCheckFailed,
    /// The identity type rejected the recovered bytes.
    #[error("import identity: {0}")]
    Import(#[source] ImportError),
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

const DIGEST_DOMAIN: &[u8] = b"recovery-kit-material-v1";
const DIGEST_LEN: usize = 32;

fn digest(app: &str, material: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    h.update((app.len() as u64).to_be_bytes());
    h.update(app.as_bytes());
    h.update((material.len() as u64).to_be_bytes());
    h.update(material);
    h.finalize().into()
}

/// Sealed material framing (all integers big-endian):
///
/// ```text
/// u16 app_len | app (UTF-8) | u32 material_len | material | 32-byte SHA-256
/// ```
fn seal(app: &str, material: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let app_len = u16::try_from(app.len()).map_err(|_| Error::AppIdTooLong(app.len()))?;
    let mat_len = u32::try_from(material.len()).map_err(|_| Error::MaterialTooLarge(material.len()))?;
    let mut out = Zeroizing::new(Vec::with_capacity(
        2 + app.len() + 4 + material.len() + DIGEST_LEN,
    ));
    out.extend_from_slice(&app_len.to_be_bytes());
    out.extend_from_slice(app.as_bytes());
    out.extend_from_slice(&mat_len.to_be_bytes());
    out.extend_from_slice(material);
    out.extend_from_slice(&digest(app, material));
    Ok(out)
}

/// Inverse of [`seal`]. Returns `(app, material)` after verifying the
/// digest. Never panics on malformed input.
fn unseal(bytes: &[u8]) -> Result<(String, Zeroizing<Vec<u8>>)> {
    let (app_len_bytes, rest) = bytes
        .split_at_checked(2)
        .ok_or(Error::Decode("truncated before app length"))?;
    let app_len = usize::from(u16::from_be_bytes([app_len_bytes[0], app_len_bytes[1]]));
    let (app_bytes, rest) = rest
        .split_at_checked(app_len)
        .ok_or(Error::Decode("truncated inside app id"))?;
    let app = std::str::from_utf8(app_bytes)
        .map_err(|_| Error::Decode("app id is not UTF-8"))?
        .to_owned();
    let (mat_len_bytes, rest) = rest
        .split_at_checked(4)
        .ok_or(Error::Decode("truncated before material length"))?;
    let mat_len = u32::from_be_bytes([
        mat_len_bytes[0],
        mat_len_bytes[1],
        mat_len_bytes[2],
        mat_len_bytes[3],
    ]);
    let mat_len = usize::try_from(mat_len).map_err(|_| Error::Decode("material length does not fit"))?;
    let (material, rest) = rest
        .split_at_checked(mat_len)
        .ok_or(Error::Decode("truncated inside material"))?;
    let (found_digest, rest) = rest
        .split_at_checked(DIGEST_LEN)
        .ok_or(Error::Decode("truncated inside digest"))?;
    if !rest.is_empty() {
        return Err(Error::Decode("trailing bytes after digest"));
    }
    let material = Zeroizing::new(material.to_vec());
    let expected = digest(&app, &material);
    // Constant-time comparison is not required for a digest over data the
    // holder already possesses, but there is no reason to leak the
    // position of the first mismatch either.
    let mismatch = found_digest
        .iter()
        .zip(expected.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if mismatch != 0 {
        return Err(Error::IntegrityCheckFailed);
    }
    Ok((app, material))
}

/// Split `identity` into a guardian recovery kit for application `app_id`:
/// `total_shares` shares, any `threshold` of which reconstruct it via
/// [`recover_identity`]. `display_label` is carried for display only.
pub fn create_kit<I: RecoverableIdentity>(
    identity: &I,
    app_id: &str,
    display_label: Option<String>,
    threshold: u8,
    total_shares: u8,
) -> Result<Vec<Share>> {
    create_kit_with_extensions(
        identity,
        app_id,
        display_label,
        BTreeMap::new(),
        threshold,
        total_shares,
    )
}

/// [`create_kit`], but with `extensions` set on the payload before
/// splitting — the slot for riding additional secrets or metadata
/// alongside the identity in the SAME kit, so a guardian holds one set of
/// shares that recovers everything.
pub fn create_kit_with_extensions<I: RecoverableIdentity>(
    identity: &I,
    app_id: &str,
    display_label: Option<String>,
    extensions: BTreeMap<String, serde_json::Value>,
    threshold: u8,
    total_shares: u8,
) -> Result<Vec<Share>> {
    let material = Zeroizing::new(identity.export_material());
    let sealed = seal(app_id, &material)?;
    let mut payload = RecoveryKitPayload::new(sealed.to_vec(), display_label);
    payload.extensions = extensions;
    Ok(payload.split(threshold, total_shares)?)
}

/// Everything [`recover_kit`] reconstructs from a set of shares.
#[derive(Debug)]
pub struct RecoveredKit<I> {
    /// The rebuilt identity.
    pub identity: I,
    /// Display-only label snapshot from the payload. Never re-derived.
    pub display_label: Option<String>,
    /// The payload's `extensions` map; empty for a kit that never set any.
    pub extensions: BTreeMap<String, serde_json::Value>,
    /// The payload's creation time, seconds since the Unix epoch.
    pub created_at_unix: u64,
}

/// Reconstruct everything a kit carries from `threshold`-or-more shares
/// produced by [`create_kit`]/[`create_kit_with_extensions`], WITHOUT
/// persisting anything — callers that want a confirmation screen before
/// committing use this, then persist once the user confirms.
///
/// `expected_app` guards against loading the wrong application's kit —
/// checked BEFORE the integrity check so the error names the actual
/// mismatch.
pub fn recover_kit<I: RecoverableIdentity>(shares: &[Share], expected_app: &str) -> Result<RecoveredKit<I>> {
    let payload = RecoveryKitPayload::recover(shares)?;
    let (found_app, material) = unseal_checked(&payload.identity_key_material, expected_app)?;
    debug_assert_eq!(found_app, expected_app);
    let identity = I::import_material(&material).map_err(Error::Import)?;
    Ok(RecoveredKit {
        identity,
        display_label: payload.display_label.clone(),
        extensions: payload.extensions.clone(),
        created_at_unix: payload.created_at_unix,
    })
}

/// Unseal, but report a wrong application id *before* the digest result,
/// so pasting another application's kit produces the more useful error.
fn unseal_checked(bytes: &[u8], expected_app: &str) -> Result<(String, Zeroizing<Vec<u8>>)> {
    match unseal(bytes) {
        Ok((app, material)) => {
            if app != expected_app {
                return Err(Error::WrongApp {
                    found: app,
                    expected: expected_app.to_owned(),
                });
            }
            Ok((app, material))
        }
        Err(Error::IntegrityCheckFailed) => {
            // The digest failed; still surface a wrong app id first if the
            // framing itself was readable.
            if let Some(app) = peek_app(bytes) {
                if app != expected_app {
                    return Err(Error::WrongApp {
                        found: app,
                        expected: expected_app.to_owned(),
                    });
                }
            }
            Err(Error::IntegrityCheckFailed)
        }
        Err(e) => Err(e),
    }
}

fn peek_app(bytes: &[u8]) -> Option<String> {
    let (len_bytes, rest) = bytes.split_at_checked(2)?;
    let len = usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]]));
    let (app, _) = rest.split_at_checked(len)?;
    std::str::from_utf8(app).ok().map(str::to_owned)
}

/// [`recover_kit`], returning just the `(identity, display_label)` pair
/// most callers want.
pub fn recover_identity<I: RecoverableIdentity>(
    shares: &[Share],
    expected_app: &str,
) -> Result<(I, Option<String>)> {
    let kit = recover_kit::<I>(shares, expected_app)?;
    Ok((kit.identity, kit.display_label))
}

/// Decode a sealed material blob without recovering shares — exposed for
/// fuzzing and tooling. Returns the application id and material.
pub fn decode_sealed_material(bytes: &[u8]) -> Result<(String, Zeroizing<Vec<u8>>)> {
    unseal(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic identity: a fixed-size random secret with a derived
    /// "public" byte so tests can check the recovered secret matches.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DemoIdentity {
        secret: Vec<u8>,
    }

    impl DemoIdentity {
        fn generate() -> Self {
            let mut secret = vec![0u8; 64];
            getrandom::getrandom(&mut secret).unwrap();
            Self { secret }
        }
        fn fingerprint(&self) -> u8 {
            self.secret.iter().fold(0u8, |a, b| a ^ b)
        }
    }

    impl RecoverableIdentity for DemoIdentity {
        fn export_material(&self) -> Vec<u8> {
            self.secret.clone()
        }
        fn import_material(bytes: &[u8]) -> std::result::Result<Self, ImportError> {
            if bytes.len() != 64 {
                return Err(format!("expected 64 bytes, got {}", bytes.len()).into());
            }
            Ok(Self {
                secret: bytes.to_vec(),
            })
        }
    }

    const APP: &str = "example-app";

    #[test]
    fn split_then_any_3_of_5_recovers_the_same_identity() {
        let original = DemoIdentity::generate();
        let shares = create_kit(&original, APP, Some("demo label".to_string()), 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        for combo in [[0, 1, 2], [1, 3, 4], [0, 2, 4]] {
            let subset: Vec<_> = combo.iter().map(|&i| shares[i].clone()).collect();
            let (recovered, label) = recover_identity::<DemoIdentity>(&subset, APP).unwrap();
            assert_eq!(recovered, original);
            assert_eq!(recovered.fingerprint(), original.fingerprint());
            assert_eq!(label.as_deref(), Some("demo label"));
        }
    }

    #[test]
    fn extensions_ride_the_kit_and_recover_intact() {
        let identity = DemoIdentity::generate();
        let mut extensions = BTreeMap::new();
        extensions.insert(
            "extra_material_v1".to_string(),
            serde_json::json!({"blob_b64": "AAECAw==", "note": null}),
        );
        let shares = create_kit_with_extensions(&identity, APP, None, extensions.clone(), 3, 5).unwrap();
        let kit = recover_kit::<DemoIdentity>(&shares[..3], APP).unwrap();
        assert_eq!(kit.extensions, extensions);
        assert_eq!(kit.identity, identity);
        assert!(kit.display_label.is_none());
    }

    #[test]
    fn create_kit_without_extensions_recovers_an_empty_map() {
        let identity = DemoIdentity::generate();
        let shares = create_kit(&identity, APP, None, 2, 3).unwrap();
        let kit = recover_kit::<DemoIdentity>(&shares[..2], APP).unwrap();
        assert!(kit.extensions.is_empty());
    }

    #[test]
    fn two_of_five_fails_cleanly() {
        let identity = DemoIdentity::generate();
        let shares = create_kit(&identity, APP, None, 3, 5).unwrap();
        let err = recover_identity::<DemoIdentity>(&shares[..2], APP).unwrap_err();
        assert!(
            matches!(err, Error::Kit(RecoveryKitError::Corrupt)),
            "got {err:?}"
        );
    }

    #[test]
    fn wrong_app_kit_is_rejected() {
        let identity = DemoIdentity::generate();
        let shares = create_kit(&identity, "other-app", None, 3, 5).unwrap();
        let err = recover_identity::<DemoIdentity>(&shares[..3], APP).unwrap_err();
        match err {
            Error::WrongApp { found, expected } => {
                assert_eq!(found, "other-app");
                assert_eq!(expected, APP);
            }
            other => panic!("expected WrongApp, got {other:?}"),
        }
    }

    #[test]
    fn corrupted_material_fails_the_integrity_check() {
        let identity = DemoIdentity::generate();
        let material = identity.export_material();
        let mut sealed = seal(APP, &material).unwrap().to_vec();
        // Flip one bit inside the material (not the framing, not the digest).
        sealed[2 + APP.len() + 4 + 10] ^= 0x01;
        let payload = RecoveryKitPayload::new(sealed, None);
        let shares = payload.split(2, 3).unwrap();
        let err = recover_identity::<DemoIdentity>(&shares[..2], APP).unwrap_err();
        assert!(matches!(err, Error::IntegrityCheckFailed), "got {err:?}");
    }

    #[test]
    fn wrong_version_kit_is_rejected_through_this_crates_api() {
        let identity = DemoIdentity::generate();
        let sealed = seal(APP, &identity.export_material()).unwrap();
        let mut payload = RecoveryKitPayload::new(sealed.to_vec(), None);
        payload.kit_version = CURRENT_KIT_VERSION + 1;
        let shares = payload.split(3, 5).unwrap();
        let err = recover_kit::<DemoIdentity>(&shares[..3], APP).unwrap_err();
        assert!(
            matches!(err, Error::Kit(RecoveryKitError::UnsupportedVersion { .. })),
            "got {err:?}"
        );
    }

    #[test]
    fn import_error_is_surfaced_not_swallowed() {
        #[derive(Debug)]
        struct Picky;
        impl RecoverableIdentity for Picky {
            fn export_material(&self) -> Vec<u8> {
                vec![1, 2, 3]
            }
            fn import_material(_: &[u8]) -> std::result::Result<Self, ImportError> {
                Err("never accepts".into())
            }
        }
        let shares = create_kit(&Picky, APP, None, 1, 1).unwrap();
        let err = recover_kit::<Picky>(&shares, APP).unwrap_err();
        assert!(matches!(err, Error::Import(_)));
        assert!(err.to_string().contains("never accepts"));
    }

    #[test]
    fn app_id_length_limit_is_enforced() {
        let identity = DemoIdentity::generate();
        let long = "a".repeat(70_000);
        let err = create_kit(&identity, &long, None, 2, 3).unwrap_err();
        assert!(matches!(err, Error::AppIdTooLong(70_000)));
    }

    #[test]
    fn sealed_material_decoder_never_panics() {
        let good = seal(APP, b"material").unwrap();
        for n in 0..good.len() {
            let _ = decode_sealed_material(&good[..n]);
        }
        let mut trailing = good.to_vec();
        trailing.push(0);
        assert!(matches!(decode_sealed_material(&trailing), Err(Error::Decode(_))));
        assert!(matches!(
            decode_sealed_material(&[0xff, 0xff]),
            Err(Error::Decode(_))
        ));
        assert!(matches!(
            decode_sealed_material(&[0, 1, 0xff]),
            Err(Error::Decode(_))
        ));
    }
}
