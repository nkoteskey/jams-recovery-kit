#![no_main]
//! The sealed-material framing decoder in `jams-recovery-kit` must never
//! panic on arbitrary bytes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = jams_recovery_kit::decode_sealed_material(data);
});
