//! Adapter: panama-le (Crypto++ panama.cpp, verbatim C++17; namespace renamed `nextssl_panama_le_CryptoPP`) -> nextssl `Hash` (32-byte output, no parameters).
//! All lengths are checked here before the C++ call; the C++ side is a one-shot digest (shim.cpp).

use core::ffi::{c_int, c_void};
use nextssl_core::{Error, Hash, Params, Result};

const OUT_LEN: usize = 32;

mod ffi {
    use super::*;

    extern "C" {
        #[link_name = "nextssl__panama_le__digest"]
        fn digest(data: *const c_void, len: usize, out: *mut c_void) -> c_int;
    }

    /// Precondition (checked by callers in this crate): `out.len() == OUT_LEN`.
    #[allow(unsafe_code)]
    pub(super) fn digest_oneshot(out: &mut [u8], data: &[u8]) -> bool {
        // SAFETY: `data` and `out` are valid slices for the lengths passed; the callee reads
        // exactly `data.len()` bytes and writes exactly OUT_LEN (= out.len()) bytes. Zero-length
        // slices give non-null aligned pointers, which the callee never reads when the length is 0.
        let rc = unsafe { digest(data.as_ptr().cast(), data.len(), out.as_mut_ptr().cast()) };
        rc == 0
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
        if ffi::digest_oneshot(out, data) {
            Ok(())
        } else {
            Err(Error::Backend("panama-le failed"))
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

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn wrong_output_length_is_refused() {
        let h = new(&Params::new()).unwrap();
        for bad in [0usize, OUT_LEN - 1, OUT_LEN + 1] {
            let mut out = vec![0u8; bad];
            assert!(matches!(
                h.digest(b"abc", &mut out),
                Err(Error::BadOutputLen { .. })
            ));
        }
    }

    #[test]
    fn deterministic_and_input_sensitive() {
        let h = new(&Params::new()).unwrap();
        let (mut a, mut b, mut c) = ([0u8; OUT_LEN], [0u8; OUT_LEN], [0u8; OUT_LEN]);
        h.digest(b"abc", &mut a).unwrap();
        h.digest(b"abc", &mut b).unwrap();
        h.digest(b"abd", &mut c).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn kat_file() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("kat/kat.json");
        let doc: J = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(doc["algorithm"], "panama-le");
        let h = new(&Params::new()).unwrap();
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let msg = unhex(v["msg_hex"].as_str().unwrap());
            let want = unhex(v["out_hex"].as_str().unwrap());
            let mut got = vec![0u8; OUT_LEN];
            h.digest(&msg, &mut got).unwrap();
            assert_eq!(got, want, "{}", v["id"]);
            n += 1;
        }
        assert!(n >= 2, "too few KATs ran: {n}");
    }
}
