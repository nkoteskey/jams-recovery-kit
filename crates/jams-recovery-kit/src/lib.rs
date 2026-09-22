//! Guardian recovery kit — glue between an application's identity type and
//! the [`sss_gf256`] Shamir engine.
//!
//! An application implements [`RecoverableIdentity`] for whatever holds its
//! long-lived secret (a signing keypair, a device key, a seed). This crate
//! then:
//!
//! 1. exports that material and tags it with the application id;
//! 2. places it in a [`RecoveryKitPayload`] (with an optional display label
//!    and an `extensions` map for anything else that should ride the same
//!    kit), serializes the payload, and frames the WHOLE serialized payload
//!    under one SHA-256 digest;
//! 3. Shamir-splits the framed bytes into `n` shares, any `k` of which
//!    reconstruct them;
//! 4. on recovery, recombines the shares, verifies the digest over the
//!    entire payload, decodes it, rejects an unsupported payload version,
//!    checks the application id, and only then hands the material to
//!    [`RecoverableIdentity::import_material`].
//!
//! # What the digest covers, and what it is not
//!
//! The digest is computed over the complete serialized payload — the
//! application id, the identity material, the display label, the creation
//! time and every extension — with a fixed domain-separation prefix. A
//! change to any of those after the kit was made fails recovery with
//! [`Error::IntegrityCheckFailed`].
//!
//! The digest is **unkeyed**. It detects corruption and mismatched share
//! sets; it does not authenticate origin. Anyone who can hand you a share
//! set can make one that verifies. If you need to know the recovered
//! identity is the one you expect, compare it to something you already
//! trust (a known public key, a fingerprint shown to the user) after
//! `recover_kit` returns.
//!
//! Buffers holding secret material are zeroized on drop where this crate
//! owns them; see the README for what that does and does not cover.
#![doc = include_str!("../../../README.md")]

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
    /// A framed blob inside the kit was malformed.
    #[error("decode kit frame: {0}")]
    Decode(&'static str),
    /// The kit was made for a different application.
    #[error("kit was created for {found:?} but this application is {expected:?}")]
    WrongApp {
        /// Application id found in the kit.
        found: String,
        /// Application id the caller expected.
        expected: String,
    },
    /// The digest over the whole payload did not verify — corrupt or
    /// mismatched shares, or a payload edited after the kit was made.
    #[error("recovered payload failed the integrity check — corrupt, mismatched, or edited shares")]
    IntegrityCheckFailed,
    /// The identity type rejected the recovered bytes.
    #[error("import identity: {0}")]
    Import(#[source] ImportError),
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

const DIGEST_DOMAIN: &[u8] = b"recovery-kit-payload-v1";
const DIGEST_LEN: usize = 32;

fn digest(payload_bytes: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    h.update((payload_bytes.len() as u64).to_be_bytes());
    h.update(payload_bytes);
    h.finalize().into()
}

/// Outer frame, the bytes that are actually split (all integers big-endian):
///
/// ```text
/// u32 payload_len | payload (JSON) | 32-byte SHA-256(domain || len || payload)
/// ```
fn frame(payload_bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let len = u32::try_from(payload_bytes.len()).map_err(|_| Error::MaterialTooLarge(payload_bytes.len()))?;
    let mut out = Zeroizing::new(Vec::with_capacity(4 + payload_bytes.len() + DIGEST_LEN));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload_bytes);
    out.extend_from_slice(&digest(payload_bytes));
    Ok(out)
}

/// Inverse of [`frame`]: verifies the digest and returns the payload bytes.
/// Never panics on malformed input.
fn unframe(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let (len_bytes, rest) = bytes
        .split_at_checked(4)
        .ok_or(Error::Decode("truncated before payload length"))?;
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);
    let len = usize::try_from(len).map_err(|_| Error::Decode("payload length does not fit"))?;
    let (payload, rest) = rest
        .split_at_checked(len)
        .ok_or(Error::Decode("truncated inside payload"))?;
    let (found, rest) = rest
        .split_at_checked(DIGEST_LEN)
        .ok_or(Error::Decode("truncated inside digest"))?;
    if !rest.is_empty() {
        return Err(Error::Decode("trailing bytes after digest"));
    }
    let expected = digest(payload);
    // The digest is over data the holder already possesses, so a
    // constant-time comparison is not required; the fold simply avoids
    // leaking the position of the first mismatch for no benefit.
    let mismatch = found
        .iter()
        .zip(expected.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if mismatch != 0 {
        return Err(Error::IntegrityCheckFailed);
    }
    Ok(Zeroizing::new(payload.to_vec()))
}

/// Inner frame carried in `identity_key_material`:
///
/// ```text
/// u16 app_len | app (UTF-8) | u32 material_len | material
/// ```
fn seal_material(app: &str, material: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let app_len = u16::try_from(app.len()).map_err(|_| Error::AppIdTooLong(app.len()))?;
    let mat_len = u32::try_from(material.len()).map_err(|_| Error::MaterialTooLarge(material.len()))?;
    let mut out = Zeroizing::new(Vec::with_capacity(2 + app.len() + 4 + material.len()));
    out.extend_from_slice(&app_len.to_be_bytes());
    out.extend_from_slice(app.as_bytes());
    out.extend_from_slice(&mat_len.to_be_bytes());
    out.extend_from_slice(material);
    Ok(out)
}

fn unseal_material(bytes: &[u8]) -> Result<(String, Zeroizing<Vec<u8>>)> {
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
    if !rest.is_empty() {
        return Err(Error::Decode("trailing bytes after material"));
    }
    Ok((app, Zeroizing::new(material.to_vec())))
}

/// Build the payload for `identity`, frame it, and return the framed bytes.
fn build_framed<I: RecoverableIdentity>(
    identity: &I,
    app_id: &str,
    display_label: Option<String>,
    extensions: BTreeMap<String, serde_json::Value>,
) -> Result<Zeroizing<Vec<u8>>> {
    let material = Zeroizing::new(identity.export_material());
    let sealed = seal_material(app_id, &material)?;
    let mut payload = RecoveryKitPayload::new(sealed.to_vec(), display_label);
    payload.extensions = extensions;
    let bytes = payload.to_bytes()?;
    frame(&bytes)
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
/// shares that recovers everything. Extensions are covered by the digest.
pub fn create_kit_with_extensions<I: RecoverableIdentity>(
    identity: &I,
    app_id: &str,
    display_label: Option<String>,
    extensions: BTreeMap<String, serde_json::Value>,
    threshold: u8,
    total_shares: u8,
) -> Result<Vec<Share>> {
    let framed = build_framed(identity, app_id, display_label, extensions)?;
    Ok(sss_gf256::split_secret(&framed, threshold, total_shares).map_err(RecoveryKitError::from)?)
}

/// Everything [`recover_kit`] reconstructs from a set of shares.
///
/// `Debug` is implemented by hand and never prints the identity: the
/// identity type may hold secret material, and a `{:?}` in a log line is
/// the classic way it leaks.
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

impl<I> std::fmt::Debug for RecoveredKit<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveredKit")
            .field("identity", &format_args!("<{}>", std::any::type_name::<I>()))
            .field("display_label", &self.display_label)
            .field("extension_keys", &self.extensions.keys().collect::<Vec<_>>())
            .field("created_at_unix", &self.created_at_unix)
            .finish()
    }
}

/// Decode a framed kit blob (verifying the whole-payload digest) into its
/// payload without recovering shares — exposed for fuzzing and tooling.
pub fn decode_framed_payload(bytes: &[u8]) -> Result<RecoveryKitPayload> {
    let payload_bytes = unframe(bytes)?;
    Ok(RecoveryKitPayload::from_bytes(&payload_bytes)?)
}

/// Reconstruct everything a kit carries from `threshold`-or-more shares
/// produced by [`create_kit`]/[`create_kit_with_extensions`], WITHOUT
/// persisting anything — callers that want a confirmation screen before
/// committing use this, then persist once the user confirms.
///
/// Order of checks: share shape → digest over the whole payload → payload
/// decode and version → application id → identity import. Fewer than
/// `threshold` shares (or shares from different kits) fail at the digest
/// with [`Error::IntegrityCheckFailed`]; there is a roughly 2⁻²⁵⁶ chance
/// that random bytes carry a valid digest, so "never a wrong payload" is
/// probabilistic, not absolute.
pub fn recover_kit<I: RecoverableIdentity>(shares: &[Share], expected_app: &str) -> Result<RecoveredKit<I>> {
    let combined = sss_gf256::combine_shares(shares).map_err(RecoveryKitError::from)?;
    let payload = decode_framed_payload(&combined)?;
    let (found_app, material) = unseal_material(&payload.identity_key_material)?;
    if found_app != expected_app {
        return Err(Error::WrongApp {
            found: found_app,
            expected: expected_app.to_owned(),
        });
    }
    let identity = I::import_material(&material).map_err(Error::Import)?;
    Ok(RecoveredKit {
        identity,
        display_label: payload.display_label.clone(),
        extensions: payload.extensions.clone(),
        created_at_unix: payload.created_at_unix,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic identity: a fixed-size random secret with a derived
    /// fingerprint so tests can check the recovered secret matches.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DemoIdentity {
        secret: Vec<u8>,
    }

    impl DemoIdentity {
        fn generate() -> Self {
            let mut secret = vec![0u8; 64];
            getrandom::fill(&mut secret).unwrap();
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

    /// Build a kit whose payload JSON was edited AFTER framing (digest kept
    /// from the original), split it, and hand the shares to `recover_kit`.
    fn tampered_shares(edit: impl Fn(&mut serde_json::Value)) -> Vec<Share> {
        let identity = DemoIdentity::generate();
        let mut extensions = BTreeMap::new();
        extensions.insert("blob_a".to_string(), serde_json::json!({"n": 1}));
        let framed = build_framed(&identity, APP, Some("original".into()), extensions).unwrap();
        // Split the frame back into payload + digest, edit the payload.
        let len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        let mut value: serde_json::Value = serde_json::from_slice(&framed[4..4 + len]).unwrap();
        edit(&mut value);
        let edited = serde_json::to_vec(&value).unwrap();
        let mut forged = Vec::new();
        forged.extend_from_slice(&u32::try_from(edited.len()).unwrap().to_be_bytes());
        forged.extend_from_slice(&edited);
        forged.extend_from_slice(&framed[4 + len..]); // the ORIGINAL digest
        sss_gf256::split_secret(&forged, 2, 3).unwrap()
    }

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
            "blob_a".to_string(),
            serde_json::json!({"bytes_b64": "AAECAw==", "note": null}),
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
            matches!(err, Error::IntegrityCheckFailed | Error::Decode(_)),
            "expected a clean rejection, got {err:?}"
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
    fn tampered_display_label_fails_the_integrity_check() {
        let shares = tampered_shares(|v| v["display_label"] = serde_json::json!("edited"));
        let err = recover_kit::<DemoIdentity>(&shares[..2], APP).unwrap_err();
        assert!(matches!(err, Error::IntegrityCheckFailed), "got {err:?}");
    }

    #[test]
    fn tampered_extensions_fail_the_integrity_check() {
        let shares = tampered_shares(|v| v["extensions"]["blob_a"] = serde_json::json!({"n": 2}));
        let err = recover_kit::<DemoIdentity>(&shares[..2], APP).unwrap_err();
        assert!(matches!(err, Error::IntegrityCheckFailed), "got {err:?}");
    }

    #[test]
    fn tampered_created_at_fails_the_integrity_check() {
        let shares = tampered_shares(|v| v["created_at_unix"] = serde_json::json!(1));
        let err = recover_kit::<DemoIdentity>(&shares[..2], APP).unwrap_err();
        assert!(matches!(err, Error::IntegrityCheckFailed), "got {err:?}");
    }

    #[test]
    fn tampered_material_fails_the_integrity_check() {
        let shares = tampered_shares(|v| {
            let s = v["identity_key_material"].as_str().unwrap().to_owned();
            let mut chars: Vec<char> = s.chars().collect();
            chars[8] = if chars[8] == 'A' { 'B' } else { 'A' };
            v["identity_key_material"] = serde_json::json!(chars.into_iter().collect::<String>());
        });
        let err = recover_kit::<DemoIdentity>(&shares[..2], APP).unwrap_err();
        assert!(matches!(err, Error::IntegrityCheckFailed), "got {err:?}");
    }

    #[test]
    fn wrong_version_kit_is_rejected_through_this_crates_api() {
        let identity = DemoIdentity::generate();
        let sealed = seal_material(APP, &identity.export_material()).unwrap();
        let mut payload = RecoveryKitPayload::new(sealed.to_vec(), None);
        payload.kit_version = CURRENT_KIT_VERSION + 1;
        let framed = frame(&payload.to_bytes().unwrap()).unwrap();
        let shares = sss_gf256::split_secret(&framed, 3, 5).unwrap();
        let err = recover_kit::<DemoIdentity>(&shares[..3], APP).unwrap_err();
        assert!(
            matches!(err, Error::Kit(RecoveryKitError::UnsupportedVersion { .. })),
            "got {err:?}"
        );
    }

    #[test]
    fn import_error_is_surfaced_not_swallowed() {
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
    fn framed_decoder_never_panics() {
        let identity = DemoIdentity::generate();
        let good = build_framed(&identity, APP, None, BTreeMap::new()).unwrap();
        for n in 0..good.len() {
            let _ = decode_framed_payload(&good[..n]);
        }
        let mut trailing = good.to_vec();
        trailing.push(0);
        assert!(matches!(decode_framed_payload(&trailing), Err(Error::Decode(_))));
        assert!(matches!(
            decode_framed_payload(&[0xff, 0xff, 0xff, 0xff]),
            Err(Error::Decode(_))
        ));
        assert!(decode_framed_payload(&good).is_ok());
    }

    #[test]
    fn inner_material_decoder_never_panics() {
        let good = seal_material(APP, b"material").unwrap();
        for n in 0..good.len() {
            let _ = unseal_material(&good[..n]);
        }
        assert!(matches!(unseal_material(&[0xff, 0xff]), Err(Error::Decode(_))));
        assert!(matches!(unseal_material(&[0, 1, 0xff]), Err(Error::Decode(_))));
    }

    #[test]
    fn recovered_kit_debug_never_prints_the_identity() {
        let identity = DemoIdentity::generate();
        let shares = create_kit(&identity, APP, Some("label".into()), 1, 1).unwrap();
        let kit = recover_kit::<DemoIdentity>(&shares, APP).unwrap();
        let text = format!("{kit:?}");
        assert!(text.contains("<jams_recovery_kit::tests::DemoIdentity>"));
        assert!(text.contains("label"));
        assert!(!text.contains("secret"));
        // A printed byte vector would look like "[12, 34, ..."; the only
        // brackets allowed are the (empty) extension-key list.
        assert!(text.contains("extension_keys: []"));
        assert_eq!(text.matches('[').count(), 1);
    }
}
