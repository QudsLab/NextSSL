//! Adapter: xxHash XXH3_64bits (C, verbatim, symbols prefixed via XXH_NAMESPACE) -> nextssl `Checksum`.
//!
//! NON-CRYPTOGRAPHIC hash for accidental-corruption detection and hash tables only; it is
//! reachable through the root API only. Seed is fixed to 0. Output: 8 bytes, big-endian
//! (the canonical representation printed by `xxhsum`).

use core::ffi::c_void;
use nextssl_core::{Checksum, Len, Params, Result, Sizes};

const OUT: usize = 8;

mod ffi {
    use super::*;

    extern "C" {
        #[link_name = "nextssl__xxh3__XXH3_64bits"]
        fn hash(data: *const c_void, len: usize) -> u64;
    }

    #[allow(unsafe_code)]
    pub(super) fn run(data: &[u8]) -> u64 {
        // SAFETY: `data` is a valid slice; the callee reads exactly `data.len()` bytes and keeps no
        // pointer. A zero-length slice gives a non-null aligned pointer, which upstream accepts for len 0.
        unsafe { hash(data.as_ptr().cast::<c_void>(), data.len()) }
    }
}

struct Impl;

impl Checksum for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            out: Some(Len::fixed(OUT)),
            ..Sizes::NONE
        }
    }

    fn checksum(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(OUT).check("out", out.len())?;
        out.copy_from_slice(&ffi::run(data).to_be_bytes());
        Ok(())
    }
}

/// Registry constructor. The seed is fixed to 0; there are no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Checksum>> {
    Ok(Box::new(Impl))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::Error;
    use serde_json::Value as J;
    use std::path::PathBuf;

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd hex length");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
            .collect()
    }

    fn load(name: &str) -> J {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("kat")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    #[test]
    fn sizes_match_metadata() {
        assert_eq!(
            new(&Params::new()).unwrap().sizes().out,
            Some(Len::fixed(OUT))
        );
    }

    #[test]
    fn known_answers() {
        let c = new(&Params::new()).unwrap();
        let doc = load("xxh3.json");
        assert_eq!(doc["algorithm"], "xxh3");
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let data = unhex(v["data_hex"].as_str().unwrap());
            let want = unhex(v["out_hex"].as_str().unwrap());
            let mut got = vec![0u8; want.len()];
            c.checksum(&data, &mut got).unwrap();
            assert_eq!(got, want, "{}", v["id"]);
            n += 1;
        }
        assert!(n >= 4);
    }

    #[test]
    fn rejects_bad_output_length() {
        let c = new(&Params::new()).unwrap();
        for bad in [0usize, OUT - 1, OUT + 1, 64] {
            let mut out = vec![0xAAu8; bad];
            assert!(matches!(
                c.checksum(b"x", &mut out),
                Err(Error::InvalidLength { .. })
            ));
            assert!(out.iter().all(|&b| b == 0xAA));
        }
    }
}
