//! Adapter: RustCrypto `ctr` (`Ctr128BE<Aes256>`) -> nextssl `StreamCipher`.
//! Registered as a native stream cipher, not through the generic `Mode` trait.
//!
//! Key 32 bytes. `nonce` is the whole 16-byte initial counter block of NIST SP 800-38A; the
//! block is incremented as a 128-bit big-endian integer (mod 2^128). The caller owns nonce
//! uniqueness: never reuse a counter block under one key.

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher as _};
use ctr::Ctr128BE;
use nextssl_core::{Error, Len, Params, Result, Sizes, StreamCipher, SymmetricKey};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 16;

struct Aes256Ctr;

impl StreamCipher for Aes256Ctr {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(KEY_LEN)),
            nonce: Some(Len::fixed(NONCE_LEN)),
            ..Sizes::NONE
        }
    }

    fn apply_keystream(&self, key: &SymmetricKey, nonce: &[u8], data: &mut [u8]) -> Result<()> {
        Len::fixed(KEY_LEN).check("key", key.len())?;
        Len::fixed(NONCE_LEN).check("nonce", nonce.len())?;
        let mut cipher = Ctr128BE::<Aes256>::new_from_slices(key.as_bytes(), nonce)
            .map_err(|_| Error::Backend("aes-256-ctr key/iv setup"))?;
        // The keystream limit is 2^128 blocks, far above MAX_INPUT_LEN, so this cannot fail for
        // inputs the shell accepts; a failure is still surfaced, never ignored.
        cipher
            .try_apply_keystream(data)
            .map_err(|_| Error::InvalidInput("aes-256-ctr: keystream limit exceeded"))
    }
}

/// Registry constructor. AES-256-CTR takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn StreamCipher>> {
    Ok(Box::new(Aes256Ctr))
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

    fn key(bytes: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(bytes, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn sizes_match_metadata() {
        let s = new(&Params::new()).unwrap().sizes();
        assert_eq!(s.key, Some(Len::fixed(KEY_LEN)));
        assert_eq!(s.nonce, Some(Len::fixed(NONCE_LEN)));
    }

    #[test]
    fn all_kat_files() {
        let c = new(&Params::new()).unwrap();
        let mut n = 0;
        for file in ["sp800-38a.json", "xcheck-wrap.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "aes-256-ctr");
            for v in doc["vectors"].as_array().unwrap() {
                let id = v["id"].as_str().unwrap();
                let k = key(&unhex(v["key_hex"].as_str().unwrap()));
                let nonce = unhex(v["nonce_hex"].as_str().unwrap());
                let pt = unhex(v["data_hex"].as_str().unwrap());
                let ct = unhex(v["out_hex"].as_str().unwrap());
                let mut buf = pt.clone();
                c.apply_keystream(&k, &nonce, &mut buf).unwrap();
                assert_eq!(buf, ct, "encrypt {file}/{id}");
                c.apply_keystream(&k, &nonce, &mut buf).unwrap();
                assert_eq!(buf, pt, "decrypt {file}/{id}");
                n += 1;
            }
        }
        assert_eq!(n, 4);
    }

    #[test]
    fn rejects_bad_lengths_without_touching_data() {
        let c = new(&Params::new()).unwrap();
        for bad in [0usize, 16, 24, 31, 33] {
            let mut d = [0xAAu8; 20];
            let r = c.apply_keystream(&key(&vec![1u8; bad]), &[0u8; NONCE_LEN], &mut d);
            assert!(matches!(r, Err(Error::InvalidLength { .. })), "key {bad}");
            assert_eq!(d, [0xAAu8; 20]);
        }
        let k = key(&[1u8; KEY_LEN]);
        for bad in [0usize, 8, 12, 15, 17, 32] {
            let mut d = [0xAAu8; 20];
            let r = c.apply_keystream(&k, &vec![0u8; bad], &mut d);
            assert!(matches!(r, Err(Error::InvalidLength { .. })), "nonce {bad}");
            assert_eq!(d, [0xAAu8; 20]);
        }
        // Empty data is a valid no-op.
        c.apply_keystream(&k, &[0u8; NONCE_LEN], &mut []).unwrap();
    }
}
