#![no_main]
use libfuzzer_sys::fuzz_target;
use nextssl_core::{Params, Value};

fuzz_target!(|data: &[u8]| {
    // First byte selects the key length (0..=127, so over-long keys are exercised too).
    let Some((&k, rest)) = data.split_first() else {
        return;
    };
    let k = usize::from(k & 0x7f).min(rest.len());
    let (key, msg) = rest.split_at(k);
    let params = Params::new().with("key", Value::Bytes(key.to_vec()));
    match nextssl_root::hash_with("blake2b-512", &params, msg) {
        Ok(d) => {
            assert!(key.len() <= 64);
            assert_eq!(d.len(), 64);
        }
        Err(_) => assert!(key.len() > 64),
    }
});
