//! Adapter: Chaskey-12 (ISO/IEC 29192-6), reference C (C, verbatim) -> nextssl `Mac`. Key exactly 16 bytes. Tag length selected by parameter `out_len` (1..=16 bytes, default 16).
//! All lengths are checked here before the C call; the C side is a thin shim (shim.c).

use core::ffi::{c_int, c_void};
use nextssl_core::{Error, Len, Mac, Params, Result, Sizes, SymmetricKey};

const KEY_LEN: usize = 16;
const TAG_MIN: u64 = 1;
const TAG_MAX: u64 = 16;

mod ffi {
    use super::*;

    extern "C" {
        #[link_name = "nextssl__chaskey__tag"]
        fn tag(
            key: *const c_void,
            data: *const c_void,
            len: usize,
            out: *mut c_void,
            outlen: usize,
        ) -> c_int;
    }

    /// Precondition (checked by callers in this crate): `key.len() == KEY_LEN`, `out.len()` is a
    /// supported tag length.
    #[allow(unsafe_code)]
    pub(super) fn run(key: &[u8], data: &[u8], out: &mut [u8]) -> bool {
        // SAFETY: `key` has exactly KEY_LEN readable bytes (precondition), `data` is a valid slice
        // read for `data.len()` bytes, `out` is a valid slice written for exactly `out.len()` bytes.
        // The callee keeps no pointer. Zero-length slices give non-null aligned pointers.
        let rc = unsafe {
            tag(
                key.as_ptr().cast(),
                data.as_ptr().cast(),
                data.len(),
                out.as_mut_ptr().cast(),
                out.len(),
            )
        };
        rc == 0
    }
}

struct Impl {
    tag_len: usize,
}

impl Mac for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(KEY_LEN)),
            tag: Some(Len::fixed(self.tag_len)),
            ..Sizes::NONE
        }
    }

    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(KEY_LEN).check("key", key.len())?;
        Len::fixed(self.tag_len).check("tag", out.len())?;
        if ffi::run(key.as_bytes(), data, out) {
            Ok(())
        } else {
            Err(Error::Backend("chaskey failed"))
        }
    }
}

/// Registry constructor. Optional parameter `out_len` (default 16).
pub fn new(params: &Params) -> Result<Box<dyn Mac>> {
    let n = params.get_u64("out_len").unwrap_or(16);
    if !(TAG_MIN..=TAG_MAX).contains(&n) {
        return Err(Error::ParamOutOfRange("out_len"));
    }
    Ok(Box::new(Impl {
        tag_len: n as usize,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::Value;
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

    fn key(bytes: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(bytes, Len::range(0, usize::MAX)).unwrap()
    }

    fn make(v: &J) -> Box<dyn Mac> {
        let mut p = Params::new();
        if let Some(n) = v.get("out_len").and_then(J::as_u64) {
            p.set("out_len", Value::U64(n));
        }
        new(&p).unwrap()
    }

    #[test]
    fn known_answers() {
        let mut total = 0;
        for file in ["chaskey.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "chaskey");
            for v in doc["vectors"].as_array().unwrap() {
                let id = v["id"].as_str().unwrap();
                let m = make(v);
                let k = key(&unhex(v["key_hex"].as_str().unwrap()));
                let data = unhex(v["data_hex"].as_str().unwrap());
                let want = unhex(v["tag_hex"].as_str().unwrap());
                let mut got = vec![0u8; want.len()];
                m.tag(&k, &data, &mut got).unwrap();
                assert_eq!(got, want, "{id}");
                assert!(m.verify(&k, &data, &want).unwrap(), "{id}");
                let mut bad = want.clone();
                bad[0] ^= 0x80;
                assert!(!m.verify(&k, &data, &bad).unwrap(), "{id} bitflip");
                total += 1;
            }
        }
        assert!(total >= 64, "too few vectors ran: {total}");
    }

    #[test]
    fn rejects_bad_lengths() {
        let m = new(&Params::new()).unwrap();
        let tl = m.sizes().tag.unwrap().max();
        let k = key(&[1u8; KEY_LEN]);
        for bad in [0, tl - 1, tl + 1, 65] {
            let mut out = vec![0xAAu8; bad];
            assert!(
                matches!(m.tag(&k, b"x", &mut out), Err(Error::InvalidLength { .. })),
                "tag {bad}"
            );
            assert!(out.iter().all(|&b| b == 0xAA), "output written on error");
        }
        for bad in [0, 1, KEY_LEN - 1, KEY_LEN + 1, 64] {
            assert!(
                matches!(
                    m.tag(&key(&vec![1u8; bad]), b"x", &mut vec![0u8; tl]),
                    Err(Error::InvalidLength { .. })
                ),
                "key {bad}"
            );
        }
    }

    #[test]
    fn unsupported_out_len_is_refused() {
        for bad in [0u64, 17, 1000] {
            let p = Params::new().with("out_len", Value::U64(bad));
            assert!(matches!(new(&p), Err(Error::ParamOutOfRange(_))), "{bad}");
        }
    }

    #[test]
    fn eight_byte_tag_is_prefix_of_sixteen_byte_tag() {
        let k = key(&[9u8; KEY_LEN]);
        let mut full = [0u8; 16];
        new(&Params::new())
            .unwrap()
            .tag(&k, b"prefix", &mut full)
            .unwrap();
        let mut short = [0u8; 8];
        new(&Params::new().with("out_len", Value::U64(8)))
            .unwrap()
            .tag(&k, b"prefix", &mut short)
            .unwrap();
        assert_eq!(short[..], full[..8]);
    }
}
