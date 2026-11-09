//! Adapter: Ascon-Hash256 (ascon-c reference C) (C, verbatim) -> nextssl `Hash`. Output 32 bytes, no parameters.

use core::ffi::{c_int, c_ulonglong};
use nextssl_core::{Error, Hash, Params, Result};

const OUT_LEN: usize = 32;

mod ffi {
    use super::*;

    extern "C" {
        #[link_name = "nextssl__ascon_hash256__hash"]
        fn hash(out: *mut u8, input: *const u8, len: c_ulonglong) -> c_int;
    }

    /// Precondition (checked by the caller): `out.len() == OUT_LEN`.
    #[allow(unsafe_code)]
    pub(super) fn run(out: &mut [u8], data: &[u8]) -> bool {
        // SAFETY: `out` is a valid slice of exactly OUT_LEN bytes, the callee writes OUT_LEN bytes;
        // `data` is a valid slice read for `data.len()` bytes. No pointer is kept.
        unsafe { hash(out.as_mut_ptr(), data.as_ptr(), data.len() as c_ulonglong) == 0 }
    }
}

struct Impl;

impl Hash for Impl {
    fn output_len(&self) -> usize {
        OUT_LEN
    }

    fn digest(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        if out.len() != OUT_LEN {
            return Err(Error::BadOutputLen {
                expected: OUT_LEN,
                got: out.len(),
            });
        }
        if ffi::run(out, data) {
            Ok(())
        } else {
            Err(Error::Backend("ascon-hash256: hash failed"))
        }
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Hash>> {
    Ok(Box::new(Impl))
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn known_answers() {
        let h = new(&Params::new()).unwrap();
        let mut total = 0;
        for file in ["ascon-hash256.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "ascon-hash256");
            for v in doc["vectors"].as_array().unwrap() {
                let msg = unhex(v["msg_hex"].as_str().unwrap());
                let want = unhex(v["out_hex"].as_str().unwrap());
                let mut got = vec![0u8; OUT_LEN];
                h.digest(&msg, &mut got).unwrap();
                assert_eq!(got, want, "{}", v["id"]);
                total += 1;
            }
        }
        assert!(total >= 30, "too few vectors ran: {total}");
    }

    #[test]
    fn rejects_bad_output_len() {
        let h = new(&Params::new()).unwrap();
        for bad in [0, OUT_LEN - 1, OUT_LEN + 1] {
            let mut out = vec![0u8; bad];
            assert!(matches!(
                h.digest(b"x", &mut out),
                Err(Error::BadOutputLen { .. })
            ));
        }
    }
}
