//! Adapter: xxHash XXH3 128-bit (XXH128, C, verbatim) (verbatim C, symbols renamed `nextssl__xxh128__*`) -> nextssl `Checksum`.
//!
//! NON-CRYPTOGRAPHIC; shares the xxh3 upstream copy (same commit). reachable through the root API only. Seeds fixed to 0. Output: 16 bytes, canonical (high64 then low64, big-endian).

use nextssl_core::{Checksum, Len, Params, Result, Sizes};

const OUT: usize = 16;

mod ffi {
    #![allow(unsafe_code)]
    use super::OUT;
    extern "C" {
        #[link_name = "nextssl__xxh128__shim_hash"]
        fn hash(data: *const u8, len: usize, out: *mut u8);
    }

    pub(super) fn run(data: &[u8]) -> [u8; OUT] {
        let mut o = [0u8; OUT];
        // SAFETY: `data` is a valid slice of `len` bytes (read only); `o` is a writable buffer of exactly OUT
        // bytes, which is all the shim writes; no pointer is kept.
        unsafe { hash(data.as_ptr(), data.len(), o.as_mut_ptr()) };
        o
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
        out.copy_from_slice(&ffi::run(data));
        Ok(())
    }
}

/// Registry constructor. No parameters.
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

    #[test]
    fn known_answers() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("kat")
            .join("xxh128.json");
        let doc: J = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(doc["algorithm"], "xxh128");
        let c = new(&Params::new()).unwrap();
        for v in doc["vectors"].as_array().unwrap() {
            let data = unhex(v["data_hex"].as_str().unwrap());
            let want = unhex(v["out_hex"].as_str().unwrap());
            let mut got = vec![0u8; want.len()];
            c.checksum(&data, &mut got).unwrap();
            assert_eq!(got, want, "{}", v["id"]);
        }
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
