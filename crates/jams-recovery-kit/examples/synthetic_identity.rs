//! Split a synthetic identity into a 3-of-5 kit and recover it from three
//! shares. Nothing here is a real key: the "identity" is a byte string
//! drawn from the OS random source for this run only.
//!
//!     cargo run --example synthetic_identity

use std::error::Error;

use jams_recovery_kit::{create_kit, recover_identity, ImportError, RecoverableIdentity};

/// A stand-in for an application's identity type.
#[derive(Debug, PartialEq, Eq)]
struct SyntheticIdentity {
    secret: Vec<u8>,
}

impl SyntheticIdentity {
    fn generate() -> Result<Self, Box<dyn Error>> {
        let mut secret = vec![0u8; 32];
        getrandom::fill(&mut secret).map_err(|e| e.to_string())?;
        Ok(Self { secret })
    }

    /// Something a UI could show so a user can confirm the right identity
    /// came back — here, a hex prefix of a digest of the secret.
    fn fingerprint(&self) -> String {
        use sha2::Digest as _;
        use std::fmt::Write as _;
        let digest = sha2::Sha256::digest(&self.secret);
        digest[..4].iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }
}

impl RecoverableIdentity for SyntheticIdentity {
    fn export_material(&self) -> Vec<u8> {
        self.secret.clone()
    }

    fn import_material(bytes: &[u8]) -> Result<Self, ImportError> {
        if bytes.len() != 32 {
            return Err(format!("expected 32 bytes, got {}", bytes.len()).into());
        }
        Ok(Self {
            secret: bytes.to_vec(),
        })
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let identity = SyntheticIdentity::generate()?;
    println!("identity fingerprint before: {}", identity.fingerprint());

    let shares = create_kit(&identity, "example-app", Some("demo label".to_string()), 3, 5)?;
    println!("split into {} shares; any 3 recover", shares.len());
    for share in &shares {
        println!("  share x={} ({} bytes)", share.x, share.y.len());
    }

    // Hand shares 1, 3 and 5 to three different guardians; later collect
    // them back.
    let from_guardians = [shares[0].clone(), shares[2].clone(), shares[4].clone()];
    let (recovered, label) = recover_identity::<SyntheticIdentity>(&from_guardians, "example-app")?;
    println!("recovered label: {}", label.as_deref().unwrap_or("(none)"));
    println!("identity fingerprint after:  {}", recovered.fingerprint());
    assert_eq!(recovered, identity);

    // Two shares are not enough, and fail cleanly rather than returning a
    // wrong identity.
    let too_few = [shares[1].clone(), shares[3].clone()];
    match recover_identity::<SyntheticIdentity>(&too_few, "example-app") {
        Err(e) => println!("two shares: {e}"),
        Ok(_) => unreachable!("two shares must never recover a 3-of-5 kit"),
    }
    Ok(())
}
