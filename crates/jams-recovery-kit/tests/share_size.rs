//! Share-text size measurement. Records how large one share's text form is
//! for a realistically-shaped kit (a few kilobytes of identity material plus
//! an extension carrying more), so a change that balloons the encoding
//! fails a test whose name says what broke. The budget below is derived
//! from this fixture's own measurement, not from any external claim.

use std::collections::BTreeMap;

use base64::Engine as _;
use jams_recovery_kit::{create_kit_with_extensions, recover_kit, ImportError, RecoverableIdentity};

struct BigIdentity(Vec<u8>);

impl RecoverableIdentity for BigIdentity {
    fn export_material(&self) -> Vec<u8> {
        self.0.clone()
    }
    fn import_material(bytes: &[u8]) -> Result<Self, ImportError> {
        Ok(Self(bytes.to_vec()))
    }
}

/// How an application might encode one share as pasteable text.
fn encode_share_text(x: u8, y: &[u8]) -> String {
    format!("{x}:{}", base64::engine::general_purpose::STANDARD.encode(y))
}

#[test]
fn realistically_shaped_kit_share_text_stays_within_budget() {
    // ~9.5 KB of identity material (the size of a post-quantum signing +
    // KEM keypair) and ~6.7 KB riding in an extension.
    let identity = BigIdentity(vec![0xA5; 9_500]);
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let mut extensions = BTreeMap::new();
    extensions.insert(
        "extra_material_v1".to_string(),
        serde_json::json!({
            "first_b64": b64(&vec![0xAB_u8; 2_600]),
            "second_b64": b64(&vec![0xCD_u8; 2_500]),
            "third_b64": b64(&vec![0xEF_u8; 1_600]),
            "label": "demo label",
        }),
    );
    extensions.insert(
        "provenance_v1".to_string(),
        serde_json::json!({"source_platform": "desktop", "source_app": "example-app"}),
    );

    let shares = create_kit_with_extensions(
        &identity,
        "example-app",
        Some("demo label".to_string()),
        extensions,
        3,
        5,
    )
    .expect("create kit");

    let lengths: Vec<usize> = shares
        .iter()
        .map(|s| encode_share_text(s.x, &s.y).len())
        .collect();
    let max_len = *lengths.iter().max().unwrap();
    eprintln!("[share_size] per-share text length: {lengths:?} chars (max {max_len})");

    // Expected: material 9,500 B -> base64 in the envelope ~12.7 KB;
    // extensions ~9 KB of base64 plus JSON; share bytes == envelope bytes;
    // share text base64 of that ~1.33x. Around 30 KB. The budget leaves
    // headroom for envelope changes without hiding a 2x regression.
    assert!(
        max_len < 40_000,
        "share text ballooned: {max_len} chars (budget 40,000)"
    );

    let recovered = recover_kit::<BigIdentity>(&shares[..3], "example-app").expect("recover");
    assert_eq!(recovered.identity.0, identity.0);
    assert!(recovered.extensions.contains_key("extra_material_v1"));
    assert!(recovered.extensions.contains_key("provenance_v1"));
}
