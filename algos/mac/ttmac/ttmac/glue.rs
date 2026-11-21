//! Adapter: ttmac (Crypto++ ttmac.cpp, verbatim C++17; namespace renamed `nextssl_ttmac_CryptoPP`) -> nextssl `Mac`.
//! Key exactly 20 bytes, tag exactly 20 bytes (no truncation). All lengths are checked here before the C++ call.

use core::ffi::{c_int, c_void};
use nextssl_core::{Error, Len, Mac, Params, Result, Sizes, SymmetricKey};

const KEY_LEN: usize = 20;
const TAG_LEN: usize = 20;

mod ffi {
    use super::*;

    extern "C" {
        #[link_name = "nextssl__ttmac__tag"]
        fn tag(
            key: *const c_void,
            keylen: usize,
            data: *const c_void,
            len: usize,
            out: *mut c_void,
        ) -> c_int;
    }

    /// Precondition (checked by callers in this crate): `key.len() == KEY_LEN`, `out.len() == TAG_LEN`.
    #[allow(unsafe_code)]
    pub(super) fn run(key: &[u8], data: &[u8], out: &mut [u8]) -> bool {
        // SAFETY: `key` has exactly KEY_LEN readable bytes, `data` is a valid slice read for `data.len()`
        // bytes, `out` is a valid slice written for exactly TAG_LEN bytes. The callee keeps no pointer.
        let rc = unsafe {
            tag(
                key.as_ptr().cast(),
                key.len(),
                data.as_ptr().cast(),
                data.len(),
                out.as_mut_ptr().cast(),
            )
        };
        rc == 0
    }
}

struct Impl;

impl Mac for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(KEY_LEN)),
            tag: Some(Len::fixed(TAG_LEN)),
            ..Sizes::NONE
        }
    }

    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(KEY_LEN).check("key", key.len())?;
        Len::fixed(TAG_LEN).check("tag", out.len())?;
        if ffi::run(key.as_bytes(), data, out) {
            Ok(())
        } else {
            Err(Error::Backend("ttmac failed"))
        }
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Mac>> {
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

    fn key(bytes: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(bytes, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn known_answers() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("kat/kat.json");
        let doc: J = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(doc["algorithm"], "ttmac");
        let m = new(&Params::new()).unwrap();
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let k = key(&unhex(v["key_hex"].as_str().unwrap()));
            let data = unhex(v["data_hex"].as_str().unwrap());
            let want = unhex(v["tag_hex"].as_str().unwrap());
            let mut got = vec![0u8; TAG_LEN];
            m.tag(&k, &data, &mut got).unwrap();
            assert_eq!(got, want, "{}", v["id"]);
            assert!(m.verify(&k, &data, &want).unwrap());
            let mut bad = want.clone();
            bad[0] ^= 0x80;
            assert!(!m.verify(&k, &data, &bad).unwrap());
            n += 1;
        }
        assert!(n >= 3, "too few KATs ran: {n}");
    }

    #[test]
    fn rejects_bad_lengths() {
        let m = new(&Params::new()).unwrap();
        let k = key(&[1u8; KEY_LEN]);
        for bad in [0, TAG_LEN - 1, TAG_LEN + 1] {
            let mut out = vec![0xAAu8; bad];
            assert!(matches!(
                m.tag(&k, b"x", &mut out),
                Err(Error::InvalidLength { .. })
            ));
            assert!(out.iter().all(|&b| b == 0xAA), "output written on error");
        }
        for bad in [0, KEY_LEN - 1, KEY_LEN + 1] {
            let mut out = vec![0u8; TAG_LEN];
            assert!(matches!(
                m.tag(&key(&vec![1u8; bad]), b"x", &mut out),
                Err(Error::InvalidLength { .. })
            ));
        }
        let mut out = vec![0u8; TAG_LEN];
        m.tag(&k, &[], &mut out).unwrap();
    }
}
