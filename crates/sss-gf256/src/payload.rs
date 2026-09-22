//! The versioned envelope an application Shamir-splits.
//!
//! [`RecoveryKitPayload`] carries an opaque, caller-supplied secret
//! (`identity_key_material` — this crate never needs to know what it
//! contains) plus non-secret metadata, and an `extensions` slot so that
//! further secrets can ride the SAME kit later without a second recovery
//! flow or a payload-shape break.
//!
//! The wire form is JSON; `identity_key_material` is a base64 string (a
//! JSON number array costs roughly three characters per byte, base64 about
//! 1.33). The bytes of that JSON document are what gets split.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use zeroize::Zeroizing;

use crate::{combine_shares, split_secret, RecoveryError, Share};

/// Current wire version of [`RecoveryKitPayload`]. Bump it whenever the
/// payload shape changes in a way old readers cannot tolerate; a version
/// outside `[MIN_SUPPORTED_KIT_VERSION, CURRENT_KIT_VERSION]` is rejected
/// by [`RecoveryKitPayload::recover`] rather than silently misread.
pub const CURRENT_KIT_VERSION: u16 = 1;

/// Oldest `kit_version` [`RecoveryKitPayload::recover`] still accepts. Keep
/// it at `CURRENT_KIT_VERSION - 1` when you bump the current version, so a
/// kit made by the previous release still recovers (n-1 compatibility),
/// and document in the version history below what changed and how the
/// reader tells the two apart.
pub const MIN_SUPPORTED_KIT_VERSION: u16 = 1;

// Version history:
//   1 — initial public shape: JSON envelope, base64 key material, optional
//       display label, unix-seconds creation time, `extensions` map.

/// `#[serde(with = "base64_bytes")]` — a `Zeroizing<Vec<u8>>` as a base64
/// string.
mod base64_bytes {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(bytes: &Zeroizing<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes.as_slice()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<Vec<u8>>, D::Error> {
        let text = Zeroizing::new(String::deserialize(d)?);
        base64::engine::general_purpose::STANDARD
            .decode(text.as_bytes())
            .map(Zeroizing::new)
            .map_err(serde::de::Error::custom)
    }
}

/// Errors from [`RecoveryKitPayload::split`] / [`RecoveryKitPayload::recover`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryKitError {
    /// The underlying share arithmetic rejected its input.
    #[error(transparent)]
    Sss(#[from] RecoveryError),
    /// The recombined bytes did not decode as a payload — wrong shares,
    /// fewer than the threshold, or corrupt data.
    #[error("kit payload did not decode — wrong shares, fewer than the threshold, or corrupt data")]
    Corrupt,
    /// The payload decoded but carries a `kit_version` this build does not
    /// accept.
    #[error("kit version {found} is not supported by this build (expected {min}..={max})")]
    UnsupportedVersion {
        /// The version found in the payload.
        found: u16,
        /// [`MIN_SUPPORTED_KIT_VERSION`].
        min: u16,
        /// [`CURRENT_KIT_VERSION`].
        max: u16,
    },
}

/// The sealed bundle a recovery kit Shamir-splits.
///
/// `display_label` is a display-only snapshot (for example the
/// human-readable name the identity had when the kit was made). Nothing
/// here re-derives or re-asserts it on recovery; it is carried so a
/// recovery screen can show "this kit belongs to …" before committing.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecoveryKitPayload {
    /// Wire version; see [`CURRENT_KIT_VERSION`].
    pub kit_version: u16,
    /// The opaque secret. Zeroized on drop.
    #[serde(with = "base64_bytes")]
    pub identity_key_material: Zeroizing<Vec<u8>>,
    /// Display-only label snapshot.
    pub display_label: Option<String>,
    /// Creation time, seconds since the Unix epoch.
    pub created_at_unix: u64,
    /// Additional secrets or metadata that ride the same kit. Default
    /// empty; `#[serde(default)]` so a kit produced without it stays
    /// readable.
    #[serde(default)]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

impl std::fmt::Debug for RecoveryKitPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryKitPayload")
            .field("kit_version", &self.kit_version)
            .field("identity_key_material_len", &self.identity_key_material.len())
            .field("display_label", &self.display_label)
            .field("created_at_unix", &self.created_at_unix)
            .field("extension_keys", &self.extensions.keys().collect::<Vec<_>>())
            .finish()
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl RecoveryKitPayload {
    /// Build a fresh, unsplit payload at [`CURRENT_KIT_VERSION`] with an
    /// empty `extensions` map.
    #[must_use]
    pub fn new(identity_key_material: Vec<u8>, display_label: Option<String>) -> Self {
        Self {
            kit_version: CURRENT_KIT_VERSION,
            identity_key_material: Zeroizing::new(identity_key_material),
            display_label,
            created_at_unix: now_unix(),
            extensions: BTreeMap::new(),
        }
    }

    /// The exact bytes [`Self::split`] splits (the JSON wire form).
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, RecoveryKitError> {
        serde_json::to_vec(self)
            .map(Zeroizing::new)
            .map_err(|_| RecoveryKitError::Corrupt)
    }

    /// Decode a payload from its wire bytes, rejecting an unsupported
    /// `kit_version`. Never panics on malformed input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecoveryKitError> {
        let payload: Self = serde_json::from_slice(bytes).map_err(|_| RecoveryKitError::Corrupt)?;
        if payload.kit_version > CURRENT_KIT_VERSION || payload.kit_version < MIN_SUPPORTED_KIT_VERSION {
            return Err(RecoveryKitError::UnsupportedVersion {
                found: payload.kit_version,
                min: MIN_SUPPORTED_KIT_VERSION,
                max: CURRENT_KIT_VERSION,
            });
        }
        Ok(payload)
    }

    /// Serialize and Shamir-split this payload into `total_shares` shares,
    /// any `threshold` of which reconstruct it via [`Self::recover`].
    pub fn split(&self, threshold: u8, total_shares: u8) -> Result<Vec<Share>, RecoveryKitError> {
        let bytes = self.to_bytes()?;
        Ok(split_secret(&bytes, threshold, total_shares)?)
    }

    /// Reconstruct a payload from `threshold`-or-more shares. Fewer than the
    /// threshold (or shares from a different split) recombine to bytes that
    /// fail to decode — reported as [`RecoveryKitError::Corrupt`], never a
    /// silent wrong-payload return. A payload that decodes but carries an
    /// unsupported `kit_version` is rejected explicitly.
    pub fn recover(shares: &[Share]) -> Result<Self, RecoveryKitError> {
        let bytes = combine_shares(shares)?;
        Self::from_bytes(&bytes)
    }

    /// Base64 of the wire bytes, for callers that want to show or store the
    /// unsplit payload (for tests and tooling; splitting is the normal path).
    pub fn to_base64(&self) -> Result<Zeroizing<String>, RecoveryKitError> {
        let bytes = self.to_bytes()?;
        Ok(Zeroizing::new(
            base64::engine::general_purpose::STANDARD.encode(bytes.as_slice()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material() -> Vec<u8> {
        b"stand-in-identity-keypair-bytes".to_vec()
    }

    #[test]
    fn split_then_any_threshold_of_5_recovers_identical_payload() {
        let payload = RecoveryKitPayload::new(material(), Some("demo label".to_string()));
        let shares = payload.split(3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        for combo in [[0, 1, 2], [1, 3, 4], [0, 2, 4]] {
            let subset: Vec<_> = combo.iter().map(|&i| shares[i].clone()).collect();
            let recovered = RecoveryKitPayload::recover(&subset).unwrap();
            assert_eq!(recovered, payload, "3-of-5 subset {combo:?} must recover exactly");
        }
    }

    #[test]
    fn two_of_five_fails_cleanly_never_returns_a_wrong_payload() {
        let payload = RecoveryKitPayload::new(material(), None);
        let shares = payload.split(3, 5).unwrap();
        let err = RecoveryKitPayload::recover(&shares[..2]).unwrap_err();
        assert_eq!(err, RecoveryKitError::Corrupt);
    }

    #[test]
    fn above_current_version_is_rejected() {
        let mut payload = RecoveryKitPayload::new(material(), None);
        payload.kit_version = CURRENT_KIT_VERSION + 1;
        let shares = payload.split(3, 5).unwrap();
        let err = RecoveryKitPayload::recover(&shares[..3]).unwrap_err();
        assert_eq!(
            err,
            RecoveryKitError::UnsupportedVersion {
                found: CURRENT_KIT_VERSION + 1,
                min: MIN_SUPPORTED_KIT_VERSION,
                max: CURRENT_KIT_VERSION,
            }
        );
    }

    #[test]
    fn below_min_supported_version_is_rejected() {
        let mut payload = RecoveryKitPayload::new(material(), None);
        payload.kit_version = MIN_SUPPORTED_KIT_VERSION - 1;
        let bytes = payload.to_bytes().unwrap();
        let err = RecoveryKitPayload::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            RecoveryKitError::UnsupportedVersion { found: 0, .. }
        ));
    }

    #[test]
    fn min_supported_version_is_accepted() {
        let mut payload = RecoveryKitPayload::new(material(), None);
        payload.kit_version = MIN_SUPPORTED_KIT_VERSION;
        let shares = payload.split(3, 5).unwrap();
        let recovered = RecoveryKitPayload::recover(&shares[..3]).unwrap();
        assert_eq!(recovered.kit_version, MIN_SUPPORTED_KIT_VERSION);
    }

    #[test]
    fn extensions_slot_round_trips() {
        let mut payload = RecoveryKitPayload::new(material(), None);
        payload
            .extensions
            .insert("extra_keys_v1".to_string(), serde_json::json!({"items": []}));
        let shares = payload.split(2, 3).unwrap();
        let recovered = RecoveryKitPayload::recover(&shares[..2]).unwrap();
        assert_eq!(recovered.extensions, payload.extensions);
    }

    #[test]
    fn payload_missing_extensions_field_defaults_empty() {
        let legacy = serde_json::json!({
            "kit_version": CURRENT_KIT_VERSION,
            "identity_key_material": base64::engine::general_purpose::STANDARD.encode(material()),
            "display_label": null,
            "created_at_unix": 0,
        });
        let bytes = serde_json::to_vec(&legacy).unwrap();
        let recovered = RecoveryKitPayload::from_bytes(&bytes).unwrap();
        assert!(recovered.extensions.is_empty());
        assert_eq!(recovered.identity_key_material.as_slice(), material().as_slice());
    }

    #[test]
    fn malformed_inputs_never_panic() {
        for bytes in [
            &b""[..],
            b"{",
            b"null",
            b"[]",
            b"{\"kit_version\": \"one\"}",
            b"{\"kit_version\": 1, \"identity_key_material\": \"!!not base64!!\", \"created_at_unix\": 0}",
            b"{\"kit_version\": 1, \"identity_key_material\": \"AA==\", \"created_at_unix\": -1}",
            b"{\"kit_version\": 70000, \"identity_key_material\": \"AA==\", \"created_at_unix\": 0}",
            "{\"kit_version\": 1, \"identity_key_material\": \"AA==\", \"created_at_unix\": 0, \"display_label\": \"\u{0}\u{ffff}\"}".as_bytes(),
        ] {
            let _ = RecoveryKitPayload::from_bytes(bytes);
        }
    }

    #[test]
    fn debug_redacts_key_material() {
        let payload = RecoveryKitPayload::new(b"secret-bytes".to_vec(), Some("label".into()));
        let text = format!("{payload:?}");
        assert!(!text.contains("secret-bytes"));
        assert!(text.contains("identity_key_material_len: 12"));
    }
}
