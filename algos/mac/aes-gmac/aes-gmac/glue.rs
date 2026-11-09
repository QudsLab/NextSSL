//! Adapter: RustCrypto `aes-gcm` (GMAC, NIST SP 800-38D section 7.1) -> nextssl `Mac`.
//!
//! GMAC is GCM with an empty plaintext. A MAC call has only `key` and `data`, so the 96-bit IV
//! travels in `data`: **`data` = 12-byte IV || associated data** (the associated data may be
//! empty). The tag is 16 bytes. The caller owns IV uniqueness: authenticating two different
//! messages under one key and one IV lets an attacker forge tags (recover the GHASH key), so
//! never reuse an IV. `sizes().block = 12` records the IV prefix length.

use aes::Aes192;
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use nextssl_core::{Error, Len, Mac, Params, Result, Sizes, SymmetricKey, Zeroizing};

const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

fn gmac_g<C: AeadInOut + KeyInit>(key: &[u8], iv: &[u8], aad: &[u8]) -> Result<[u8; TAG_LEN]> {
    let cipher = C::new_from_slice(key).map_err(|_| Error::Backend("aes-gmac key setup"))?;
    let nonce = Nonce::<C>::try_from(iv).map_err(|_| Error::Backend("aes-gmac iv"))?;
    // Empty plaintext: the in-place buffer ends up holding only the tag.
    let mut buf = Vec::new();
    cipher
        .encrypt_in_place(&nonce, aad, &mut buf)
        .map_err(|_| Error::InvalidInput("aes-gmac: input too long"))?;
    <[u8; TAG_LEN]>::try_from(&buf[..]).map_err(|_| Error::Backend("aes-gmac tag"))
}

struct Impl;

impl Mac for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(16, 32)),
            tag: Some(Len::fixed(TAG_LEN)),
            block: Some(Len::fixed(IV_LEN)),
            ..Sizes::NONE
        }
    }

    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(TAG_LEN).check("tag", out.len())?;
        Len::range(IV_LEN, usize::MAX).check("data (12-byte IV || aad)", data.len())?;
        let (iv, aad) = data.split_at(IV_LEN);
        let k = key.as_bytes();
        let t = Zeroizing::new(match k.len() {
            16 => gmac_g::<Aes128Gcm>(k, iv, aad)?,
            24 => gmac_g::<AesGcm<Aes192, U12>>(k, iv, aad)?,
            32 => gmac_g::<Aes256Gcm>(k, iv, aad)?,
            n => {
                return Err(Error::InvalidLength {
                    what: "key",
                    got: n,
                    min: 16,
                    max: 32,
                })
            }
        });
        out.copy_from_slice(&t[..]);
        Ok(())
    }
}

/// Registry constructor. AES-GMAC takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Mac>> {
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

    /// Any-length key, so tests can hand the glue wrong sizes.
    fn key(bytes: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(bytes, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn all_kat_files() {
        let m = new(&Params::new()).unwrap();
        let (mut n, mut bad) = (0, 0);
        for file in ["acvp-gmac.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "aes-gmac");
            for v in doc["vectors"].as_array().unwrap() {
                let id = v["id"].as_str().unwrap();
                let k = key(&unhex(v["key_hex"].as_str().unwrap()));
                let data = unhex(v["data_hex"].as_str().unwrap());
                let tag = unhex(v["tag_hex"].as_str().unwrap());
                let mut out = vec![0u8; TAG_LEN];
                m.tag(&k, &data, &mut out).unwrap();
                // ACVP also has truncated tags (4 bytes): compare the prefix
                assert_eq!(&out[..tag.len()], &tag[..], "tag {file}/{id}");
                if tag.len() == TAG_LEN {
                    assert!(m.verify(&k, &data, &tag).unwrap(), "verify {file}/{id}");
                }
                n += 1;
            }
            for v in doc["invalid"].as_array().into_iter().flatten() {
                let id = v["id"].as_str().unwrap();
                let k = key(&unhex(v["key_hex"].as_str().unwrap()));
                let data = unhex(v["data_hex"].as_str().unwrap());
                let tag = unhex(v["tag_hex"].as_str().unwrap());
                let mut out = vec![0u8; TAG_LEN];
                m.tag(&k, &data, &mut out).unwrap();
                assert_ne!(&out[..tag.len()], &tag[..], "bad tag accepted {file}/{id}");
                bad += 1;
            }
        }
        assert!(n >= 10, "too few KATs ran: {n}");
        eprintln!("KAT vectors: {n} valid, {bad} invalid");
    }

    #[test]
    fn rejects_bad_lengths() {
        let m = new(&Params::new()).unwrap();
        let mut out = [0u8; TAG_LEN];
        for bad in [0usize, 8, 15, 17, 31, 33] {
            let r = m.tag(&key(&vec![1u8; bad]), &[0u8; 20], &mut out);
            assert!(matches!(r, Err(Error::InvalidLength { .. })), "key {bad}");
        }
        let k = key(&[1u8; 16]);
        assert!(
            m.tag(&k, &[0u8; IV_LEN - 1], &mut out).is_err(),
            "data shorter than the IV"
        );
        assert!(
            m.tag(&k, &[0u8; IV_LEN], &mut [0u8; 15]).is_err(),
            "short out"
        );
        // IV-only input (empty associated data) is valid
        m.tag(&k, &[0u8; IV_LEN], &mut out).unwrap();
    }
}
