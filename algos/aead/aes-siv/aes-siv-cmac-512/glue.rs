//! Adapter: RustCrypto `aes-siv` (aes-siv-cmac-512) -> nextssl `Aead`.
//! Key 64 bytes, nonce 0 bytes, tag 16 bytes. Output of `seal` is the 16-byte synthetic IV (tag) FIRST, then the ciphertext: `tag || ciphertext` as in RFC 5297, not `ciphertext || tag`.

use aes::Aes256;
use aes_siv::siv::Siv;
use aes_siv::KeyInit;
use cmac::Cmac;
use nextssl_core::{Aead, Error, Len, Params, Result, Sizes, SymmetricKey, Zeroizing};

const KEY_LEN: usize = 64;
const NONCE_LEN: usize = 0;
const TAG_LEN: usize = 16;

struct Cipher;

impl Cipher {
    fn check(key: &SymmetricKey, nonce: &[u8]) -> Result<()> {
        Len::fixed(KEY_LEN).check("key", key.len())?;
        Len::fixed(NONCE_LEN).check("nonce", nonce.len())
    }
}

impl Aead for Cipher {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(KEY_LEN)),
            nonce: Some(Len::fixed(NONCE_LEN)),
            tag: Some(Len::fixed(TAG_LEN)),
            ..Sizes::NONE
        }
    }

    fn seal(&self, key: &SymmetricKey, nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        Self::check(key, nonce)?;
        let mut siv = Siv::<Aes256, Cmac<Aes256>>::new_from_slice(key.as_bytes())
            .map_err(|_| Error::Backend("key setup"))?;
        siv.encrypt([aad], pt)
            .map_err(|_| Error::InvalidInput("aes-siv: input too long"))
    }

    fn open(
        &self,
        key: &SymmetricKey,
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        Self::check(key, nonce)?;
        Len::range(TAG_LEN, usize::MAX).check("ciphertext", ct.len())?;
        let mut siv = Siv::<Aes256, Cmac<Aes256>>::new_from_slice(key.as_bytes())
            .map_err(|_| Error::Backend("key setup"))?;
        let pt = siv
            .decrypt([aad], ct)
            .map_err(|_| Error::AuthenticationFailed)?;
        Ok(Zeroizing::new(pt))
    }
}

/// Registry constructor. aes-siv-cmac-512 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Aead>> {
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
        let s = Cipher.sizes();
        assert_eq!(s.key, Some(Len::fixed(KEY_LEN)));
        assert_eq!(s.nonce, Some(Len::fixed(NONCE_LEN)));
        assert_eq!(s.tag, Some(Len::fixed(TAG_LEN)));
    }

    #[test]
    fn all_kat_files() {
        let a = new(&Params::new()).unwrap();
        let (mut n, mut bad) = (0, 0);
        for file in ["wycheproof.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "aes-siv-cmac-512");
            for (i, v) in doc["vectors"].as_array().unwrap().iter().enumerate() {
                let id = v["id"].as_str().unwrap();
                let k = key(&unhex(v["key_hex"].as_str().unwrap()));
                let nonce = unhex(v["nonce_hex"].as_str().unwrap());
                let aad = unhex(v["aad_hex"].as_str().unwrap());
                let pt = unhex(v["pt_hex"].as_str().unwrap());
                let ct = unhex(v["ct_hex"].as_str().unwrap());
                assert_eq!(
                    a.seal(&k, &nonce, &aad, &pt).unwrap(),
                    ct,
                    "seal {file}/{id}"
                );
                assert_eq!(
                    &a.open(&k, &nonce, &aad, &ct).unwrap()[..],
                    &pt[..],
                    "open {file}/{id}"
                );
                if i < 12 {
                    for pos in 0..ct.len() {
                        let mut t = ct.clone();
                        t[pos] ^= 1;
                        assert_eq!(
                            a.open(&k, &nonce, &aad, &t).unwrap_err(),
                            Error::AuthenticationFailed,
                            "bitflip {pos} accepted {file}/{id}"
                        );
                    }
                    let mut bad_aad = aad.clone();
                    bad_aad.push(0);
                    assert_eq!(
                        a.open(&k, &nonce, &bad_aad, &ct).unwrap_err(),
                        Error::AuthenticationFailed
                    );
                }
                n += 1;
            }
            for v in doc["invalid"].as_array().into_iter().flatten() {
                let id = v["id"].as_str().unwrap();
                let k = key(&unhex(v["key_hex"].as_str().unwrap()));
                let nonce = unhex(v["nonce_hex"].as_str().unwrap());
                let aad = unhex(v["aad_hex"].as_str().unwrap());
                let ct = unhex(v["ct_hex"].as_str().unwrap());
                assert!(
                    a.open(&k, &nonce, &aad, &ct).is_err(),
                    "invalid accepted {file}/{id}"
                );
                bad += 1;
            }
        }
        assert!(n >= 5, "too few KATs ran: {n}");
        eprintln!("KAT vectors: {n} valid, {bad} invalid");
    }

    #[test]
    fn rejects_bad_lengths() {
        let a = new(&Params::new()).unwrap();
        let k = key(&[1u8; KEY_LEN]);
        let nonce = [2u8; NONCE_LEN];
        for bad in [0usize, 1, KEY_LEN - 1, KEY_LEN + 1] {
            let r = a.seal(&key(&vec![1u8; bad]), &nonce, b"", b"x");
            assert!(matches!(r, Err(Error::InvalidLength { .. })), "key {bad}");
        }
        let r = a.seal(&k, &[2u8; NONCE_LEN + 1], b"", b"x");
        assert!(matches!(r, Err(Error::InvalidLength { .. })), "long nonce");

        let r = a.open(&k, &nonce, b"", &[0u8; TAG_LEN - 1]);
        assert!(
            matches!(r, Err(Error::InvalidLength { .. })),
            "ct shorter than tag"
        );
    }
}
