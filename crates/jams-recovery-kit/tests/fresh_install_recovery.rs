//! Integration test: recovery on a fresh install ends with the SAME
//! identity as before "the wipe", and recovery wins over an auto-generated
//! placeholder.
//!
//! The identity here is a synthetic in-memory type with a file-backed
//! "store" in a temporary directory, standing in for whatever keystore a
//! real application uses.

use std::path::{Path, PathBuf};

use jams_recovery_kit::{create_kit, recover_identity, ImportError, RecoverableIdentity};

const APP: &str = "example-app";

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    secret: Vec<u8>,
}

impl FileIdentity {
    fn generate() -> Self {
        let mut secret = vec![0u8; 48];
        getrandom::getrandom(&mut secret).expect("os randomness");
        Self { secret }
    }

    fn path(dir: &Path) -> PathBuf {
        dir.join(format!("{APP}.identity"))
    }

    /// Load or generate — what an application's boot hook does.
    fn ensure(dir: &Path) -> Self {
        if let Ok(bytes) = std::fs::read(Self::path(dir)) {
            return Self { secret: bytes };
        }
        let fresh = Self::generate();
        fresh.persist(dir);
        fresh
    }

    fn load(dir: &Path) -> Option<Self> {
        std::fs::read(Self::path(dir)).ok().map(|secret| Self { secret })
    }

    fn persist(&self, dir: &Path) {
        std::fs::write(Self::path(dir), &self.secret).expect("write identity");
    }

    fn wipe(dir: &Path) {
        let _ = std::fs::remove_file(Self::path(dir));
    }
}

impl RecoverableIdentity for FileIdentity {
    fn export_material(&self) -> Vec<u8> {
        self.secret.clone()
    }

    fn import_material(bytes: &[u8]) -> Result<Self, ImportError> {
        if bytes.len() != 48 {
            return Err(format!("expected 48 bytes, got {}", bytes.len()).into());
        }
        Ok(Self {
            secret: bytes.to_vec(),
        })
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce).expect("os randomness");
    let dir = std::env::temp_dir().join(format!(
        "recovery-kit-test-{tag}-{:016x}",
        u64::from_be_bytes(nonce)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

#[test]
fn fresh_data_dir_recovery_ends_with_the_pre_wipe_identity() {
    let dir = temp_dir("fresh");

    // "Before the wipe": a real identity exists, and the user creates a kit.
    let pre_wipe = FileIdentity::ensure(&dir);
    let shares = create_kit(&pre_wipe, APP, Some("demo label".to_string()), 3, 5).expect("create kit");

    // "The wipe": exactly what a reinstall leaves behind.
    FileIdentity::wipe(&dir);
    assert!(FileIdentity::load(&dir).is_none());

    // A fresh install's boot hook runs BEFORE the user recovers — it
    // auto-generates a placeholder. Recovery must WIN over it.
    let auto_generated = FileIdentity::ensure(&dir);
    assert_ne!(
        auto_generated, pre_wipe,
        "sanity: the placeholder is a different key"
    );

    let (recovered, label) = recover_identity::<FileIdentity>(&shares[..3], APP).expect("recover");
    assert_eq!(recovered, pre_wipe);
    assert_eq!(label.as_deref(), Some("demo label"));
    recovered.persist(&dir);

    let reloaded = FileIdentity::load(&dir).expect("load after recovery");
    assert_eq!(reloaded, pre_wipe);
    assert_ne!(reloaded, auto_generated);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn two_of_five_shares_recover_nothing_on_a_fresh_data_dir() {
    let dir = temp_dir("short");

    let pre_wipe = FileIdentity::ensure(&dir);
    let shares = create_kit(&pre_wipe, APP, None, 3, 5).expect("create kit");
    FileIdentity::wipe(&dir);

    let err = recover_identity::<FileIdentity>(&shares[..2], APP).unwrap_err();
    assert!(
        matches!(err, jams_recovery_kit::Error::Kit(_)),
        "expected a clean Kit(Corrupt) rejection, got {err:?}"
    );
    // Fails CLEANLY: nothing from the bad attempt was ever persisted.
    assert!(FileIdentity::load(&dir).is_none());

    let _ = std::fs::remove_dir_all(&dir);
}
