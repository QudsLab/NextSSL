//! Adapter: RustCrypto `aes-gcm` (AES-256-GCM, 96-bit nonce, 128-bit tag) -> nextssl `Aead`.
//! Key 32 bytes, nonce 12 bytes, tag 16 bytes. Output of `seal` is `ciphertext || tag`.

use aes_gcm::aead::Nonce;
use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::Aes256Gcm;
use nextssl_core::{Aead, Error, Len, Params, Result, Sizes, SymmetricKey, Zeroizing};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

struct Aes256GcmAead;

impl Aes256GcmAead {
    fn cipher(key: &SymmetricKey) -> Result<Aes256Gcm> {
        Len::fixed(KEY_LEN).check("key", key.len())?;
        Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|_| Error::Backend("aes-256-gcm key setup"))
    }

    fn nonce(nonce: &[u8]) -> Result<Nonce<Aes256Gcm>> {
        Len::fixed(NONCE_LEN).check("nonce", nonce.len())?;
        Nonce::<Aes256Gcm>::try_from(nonce).map_err(|_| Error::Backend("aes-256-gcm nonce"))
    }
}

impl Aead for Aes256GcmAead {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(KEY_LEN)),
            nonce: Some(Len::fixed(NONCE_LEN)),
            tag: Some(Len::fixed(TAG_LEN)),
            ..Sizes::NONE
        }
    }

    fn seal(&self, key: &SymmetricKey, nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        let cipher = Self::cipher(key)?;
        let nonce = Self::nonce(nonce)?;
        let mut buf = Vec::new();
        buf.try_reserve_exact(pt.len() + TAG_LEN)
            .map_err(|_| Error::Backend("allocation failed"))?;
        buf.extend_from_slice(pt);
        match cipher.encrypt_in_place(&nonce, aad, &mut buf) {
            Ok(()) => Ok(buf),
            Err(_) => Err(Error::InvalidInput("aes-256-gcm: input too long")),
        }
    }

    fn open(
        &self,
        key: &SymmetricKey,
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let cipher = Self::cipher(key)?;
        let nonce = Self::nonce(nonce)?;
        Len::range(TAG_LEN, usize::MAX).check("ciphertext", ct.len())?;
        let mut buf = Zeroizing::new(Vec::new());
        buf.try_reserve_exact(ct.len())
            .map_err(|_| Error::Backend("allocation failed"))?;
        buf.extend_from_slice(ct);
        match cipher.decrypt_in_place(&nonce, aad, &mut *buf) {
            Ok(()) => Ok(buf),
            // `buf` is wiped on drop: no unauthenticated plaintext is released.
            Err(_) => Err(Error::AuthenticationFailed),
        }
    }
}

/// Registry constructor. AES-256-GCM takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Aead>> {
    Ok(Box::new(Aes256GcmAead))
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
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path:?}: {e}"))
    }

    /// Any-length key, so tests can hand the glue wrong sizes.
    fn key(bytes: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(bytes, Len::range(0, usize::MAX)).unwrap()
    }

    fn aead() -> Box<dyn Aead> {
        new(&Params::new()).unwrap()
    }

    fn is_len_err(e: &Error) -> bool {
        matches!(e, Error::InvalidLength { .. })
    }

    #[test]
    fn sizes_match_metadata() {
        let s = aead().sizes();
        assert_eq!(s.key, Some(Len::fixed(KEY_LEN)));
        assert_eq!(s.nonce, Some(Len::fixed(NONCE_LEN)));
        assert_eq!(s.tag, Some(Len::fixed(TAG_LEN)));
    }

    #[test]
    fn official_kats() {
        let a = aead();
        let mut n = 0;
        for file in ["sp800-38d.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "aes-256-gcm", "{file}");
            for v in doc["vectors"].as_array().unwrap() {
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
                let got = a.open(&k, &nonce, &aad, &ct).unwrap();
                assert_eq!(&got[..], &pt[..], "open {file}/{id}");
                // Any single flipped bit anywhere in ct||tag must be rejected.
                for pos in 0..ct.len() {
                    let mut bad = ct.clone();
                    bad[pos] ^= 0x01;
                    assert_eq!(
                        a.open(&k, &nonce, &aad, &bad).unwrap_err(),
                        Error::AuthenticationFailed,
                        "bitflip at {pos} accepted for {file}/{id}"
                    );
                }
                // Wrong AAD must be rejected.
                let mut bad_aad = aad.clone();
                bad_aad.push(0);
                assert_eq!(
                    a.open(&k, &nonce, &bad_aad, &ct).unwrap_err(),
                    Error::AuthenticationFailed,
                    "{file}/{id}"
                );
                n += 1;
            }
            for v in doc["invalid"].as_array().into_iter().flatten() {
                let id = v["id"].as_str().unwrap();
                let k = key(&unhex(v["key_hex"].as_str().unwrap()));
                let nonce = unhex(v["nonce_hex"].as_str().unwrap());
                let aad = unhex(v["aad_hex"].as_str().unwrap());
                let ct = unhex(v["ct_hex"].as_str().unwrap());
                assert_eq!(
                    a.open(&k, &nonce, &aad, &ct).unwrap_err(),
                    Error::AuthenticationFailed,
                    "invalid vector accepted: {file}/{id}"
                );
                n += 1;
            }
        }
        assert!(n >= 60, "suspiciously few official vectors ran: {n}");
        eprintln!("official KAT vectors run: {n}");
    }

    #[test]
    fn wycheproof() {
        let a = aead();
        let doc = load("wycheproof_aes_gcm_test.json");
        let (mut valid, mut invalid, mut wrong_size) = (0usize, 0usize, 0usize);
        for g in doc["testGroups"].as_array().unwrap() {
            for t in g["tests"].as_array().unwrap() {
                let tc = t["tcId"].as_u64().unwrap();
                let k = key(&unhex(t["key"].as_str().unwrap()));
                let nonce = unhex(t["iv"].as_str().unwrap());
                let aad = unhex(t["aad"].as_str().unwrap());
                let msg = unhex(t["msg"].as_str().unwrap());
                let mut ct_tag = unhex(t["ct"].as_str().unwrap());
                let tag = unhex(t["tag"].as_str().unwrap());
                ct_tag.extend_from_slice(&tag);
                let ctx = format!("wycheproof tcId {tc}");

                if k.len() != KEY_LEN || nonce.len() != NONCE_LEN || tag.len() != TAG_LEN {
                    // Sizes this algorithm does not offer: explicit error, never a fallback.
                    if k.len() != KEY_LEN || nonce.len() != NONCE_LEN {
                        assert!(
                            is_len_err(&a.seal(&k, &nonce, &aad, &msg).unwrap_err()),
                            "{ctx}"
                        );
                        assert!(
                            is_len_err(&a.open(&k, &nonce, &aad, &ct_tag).unwrap_err()),
                            "{ctx}"
                        );
                    } else {
                        // Shorter/longer tag: ct||tag has the wrong shape, must not authenticate.
                        assert!(a.open(&k, &nonce, &aad, &ct_tag).is_err(), "{ctx}");
                    }
                    wrong_size += 1;
                    continue;
                }
                match t["result"].as_str().unwrap() {
                    "valid" => {
                        assert_eq!(
                            a.seal(&k, &nonce, &aad, &msg).unwrap(),
                            ct_tag,
                            "seal {ctx}"
                        );
                        let got = a.open(&k, &nonce, &aad, &ct_tag).unwrap();
                        assert_eq!(&got[..], &msg[..], "open {ctx}");
                        valid += 1;
                    }
                    "invalid" => {
                        assert_eq!(
                            a.open(&k, &nonce, &aad, &ct_tag).unwrap_err(),
                            Error::AuthenticationFailed,
                            "invalid case accepted: {ctx}"
                        );
                        invalid += 1;
                    }
                    other => panic!("{ctx}: unexpected result {other:?}"),
                }
            }
        }
        let total = doc["numberOfTests"].as_u64().unwrap() as usize;
        assert_eq!(
            valid + invalid + wrong_size,
            total,
            "not every Wycheproof case ran"
        );
        assert!(valid > 0 && invalid > 0);
        eprintln!("wycheproof: total {total}, valid {valid}, invalid rejected {invalid}, unsupported-size rejected {wrong_size}");
    }

    #[test]
    fn rejects_bad_lengths_and_short_ciphertext() {
        let a = aead();
        let k = key(&[7u8; KEY_LEN]);
        let nonce = [1u8; NONCE_LEN];
        for bad_key in [0usize, KEY_LEN - 1, KEY_LEN + 1] {
            let bk = key(&vec![7u8; bad_key]);
            assert!(is_len_err(&a.seal(&bk, &nonce, b"", b"x").unwrap_err()));
            assert!(is_len_err(
                &a.open(&bk, &nonce, b"", &[0u8; 32]).unwrap_err()
            ));
        }
        for bad_nonce in [0usize, NONCE_LEN - 1, NONCE_LEN + 1] {
            let bn = vec![1u8; bad_nonce];
            assert!(is_len_err(&a.seal(&k, &bn, b"", b"x").unwrap_err()));
            assert!(is_len_err(&a.open(&k, &bn, b"", &[0u8; 32]).unwrap_err()));
        }
        for short in 0..TAG_LEN {
            assert!(is_len_err(
                &a.open(&k, &nonce, b"", &vec![0u8; short]).unwrap_err()
            ));
        }
        // Empty plaintext round-trips, output is exactly the tag.
        let sealed = a.seal(&k, &nonce, b"aad", b"").unwrap();
        assert_eq!(sealed.len(), TAG_LEN);
        assert!(a.open(&k, &nonce, b"aad", &sealed).unwrap().is_empty());
    }
}
