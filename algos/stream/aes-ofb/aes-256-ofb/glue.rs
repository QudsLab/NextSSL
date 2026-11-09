//! Adapter: RustCrypto `ofb` (aes-256-ofb) -> nextssl `StreamCipher`.
//! Key 32 bytes, nonce/IV 16 bytes. Unauthenticated: pair with a MAC or use an AEAD.
//! Applying the keystream twice restores the data.

use aes::Aes256;
use nextssl_core::{Error, Len, Params, Result, Sizes, StreamCipher, SymmetricKey};
use ofb::cipher::{KeyIvInit, StreamCipher as _};
use ofb::Ofb;

const KEY_MIN: usize = 32;
const KEY_MAX: usize = 32;
const NONCE_LEN: usize = 16;

/// Key lengths the cipher accepts (anything else is `InvalidLength`).
fn key_ok(len: usize) -> bool {
    len == 32
}

struct Cipher;

impl StreamCipher for Cipher {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(32)),
            nonce: Some(Len::fixed(NONCE_LEN)),
            ..Sizes::NONE
        }
    }

    fn apply_keystream(&self, key: &SymmetricKey, nonce: &[u8], data: &mut [u8]) -> Result<()> {
        if !key_ok(key.len()) {
            return Err(Error::InvalidLength {
                what: "key",
                got: key.len(),
                min: KEY_MIN,
                max: KEY_MAX,
            });
        }
        Len::fixed(NONCE_LEN).check("nonce", nonce.len())?;
        let mut c = Ofb::<Aes256>::new_from_slices(key.as_bytes(), nonce)
            .map_err(|_| Error::Backend("aes-256-ofb key/iv setup"))?;
        c.try_apply_keystream(data)
            .map_err(|_| Error::InvalidInput("aes-256-ofb: keystream limit exceeded"))
    }
}

/// Registry constructor. AES-256-OFB takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn StreamCipher>> {
    Ok(Box::new(Cipher))
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

    /// Any-length key, so tests can hand the glue wrong sizes.
    fn key(bytes: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(bytes, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn sizes_match_metadata() {
        let s = new(&Params::new()).unwrap().sizes();
        assert_eq!(s.key, Some(Len::fixed(32)));
        assert_eq!(s.nonce, Some(Len::fixed(NONCE_LEN)));
    }

    #[test]
    fn all_kat_files() {
        let c = new(&Params::new()).unwrap();
        let mut n = 0;
        for file in ["acvp-ofb.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "aes-256-ofb");
            for v in doc["vectors"].as_array().unwrap() {
                let id = v["id"].as_str().unwrap();
                let k = key(&unhex(v["key_hex"].as_str().unwrap()));
                let nonce = unhex(v["nonce_hex"].as_str().unwrap());
                let offset = v.get("offset").and_then(J::as_u64).unwrap_or(0) as usize;
                let pt = unhex(v["data_hex"].as_str().unwrap());
                let ct = unhex(v["out_hex"].as_str().unwrap());
                // `offset` bytes of keystream are skipped by processing that many zero bytes first.
                let mut buf = vec![0u8; offset];
                buf.extend_from_slice(&pt);
                c.apply_keystream(&k, &nonce, &mut buf).unwrap();
                assert_eq!(&buf[offset..], &ct[..], "encrypt {file}/{id}");
                let mut back = vec![0u8; offset];
                back.extend_from_slice(&ct);
                c.apply_keystream(&k, &nonce, &mut back).unwrap();
                assert_eq!(&back[offset..], &pt[..], "decrypt {file}/{id}");
                n += 1;
            }
        }
        assert!(n >= 10, "too few KATs ran: {n}");
    }

    #[test]
    fn rejects_bad_lengths_without_touching_data() {
        let c = new(&Params::new()).unwrap();
        for bad in 0..=KEY_MAX + 1 {
            if key_ok(bad) {
                continue;
            }
            let mut d = [0xAAu8; 20];
            let r = c.apply_keystream(&key(&vec![1u8; bad]), &[0u8; NONCE_LEN], &mut d);
            assert!(matches!(r, Err(Error::InvalidLength { .. })), "key {bad}");
            assert_eq!(d, [0xAAu8; 20]);
        }
        let k = key(&[1u8; KEY_MIN]);
        for bad in [NONCE_LEN + 1, NONCE_LEN + 7] {
            let mut d = [0xAAu8; 20];
            let r = c.apply_keystream(&k, &vec![0u8; bad], &mut d);
            assert!(matches!(r, Err(Error::InvalidLength { .. })), "nonce {bad}");
            assert_eq!(d, [0xAAu8; 20]);
        }
        if NONCE_LEN > 0 {
            let mut d = [0xAAu8; 20];
            let mut short = vec![0u8; NONCE_LEN];
            short.pop();
            let r = c.apply_keystream(&k, &short, &mut d);
            assert!(matches!(r, Err(Error::InvalidLength { .. })), "short nonce");
            assert_eq!(d, [0xAAu8; 20]);
        }

        // Empty data is a valid no-op.
        c.apply_keystream(&k, &[0u8; NONCE_LEN], &mut []).unwrap();
    }
}
