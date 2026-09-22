#![no_main]
//! The outer frame decoder in `jams-recovery-kit` (length | payload | digest)
//! must never panic on arbitrary bytes, and a blob that verifies must
//! decode to a payload.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = jams_recovery_kit::decode_framed_payload(data);
});
