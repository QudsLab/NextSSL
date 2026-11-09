//! Adapter: RustCrypto `xts-mode` (aes-256-xts) -> nextssl `BlockMode`.
//! Key 64 bytes, nonce/IV/tweak 16 bytes, cipher block 16 bytes.

use aes::cipher::KeyInit;
use aes::Aes256;
use nextssl_core::ct_eq;
use nextssl_core::{BlockMode, Error, Len, Params, Result, Sizes, SymmetricKey, Zeroizing};
use xts_mode::Xts128;

const KEY_MIN: usize = 64;
const KEY_MAX: usize = 64;
const NONCE_MIN: usize = 16;
const NONCE_MAX: usize = 16;
const BLOCK_LEN: usize = 16;

/// Key lengths accepted (anything else is `InvalidLength`).
fn key_ok(len: usize) -> bool {
    len == 64
}

struct Mode {}

impl Mode {
    fn check(&self, key: &SymmetricKey, nonce: &[u8]) -> Result<()> {
        if !key_ok(key.len()) {
            return Err(Error::InvalidLength {
                what: "key",
                got: key.len(),
                min: KEY_MIN,
                max: KEY_MAX,
            });
        }
        Len::range(NONCE_MIN, NONCE_MAX).check("nonce", nonce.len())
    }
}

impl BlockMode for Mode {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(64)),
            nonce: Some(Len::fixed(16)),
            block: Some(Len::fixed(BLOCK_LEN)),
            ..Sizes::NONE
        }
    }

    fn encrypt(&self, key: &SymmetricKey, nonce: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        self.check(key, nonce)?;
        let (k1, k2) = key.as_bytes().split_at(KEY_MIN / 2);
        if ct_eq(k1, k2) {
            return Err(Error::InvalidInput(
                "xts: the two key halves must differ (FIPS 140-3 IG C.I)",
            ));
        }
        if pt.len() < BLOCK_LEN {
            return Err(Error::InvalidLength {
                what: "data",
                got: pt.len(),
                min: BLOCK_LEN,
                max: usize::MAX,
            });
        }
        let x = Xts128::<Aes256>::new(
            Aes256::new_from_slice(k1).map_err(|_| Error::Backend("aes-256-xts key setup"))?,
            Aes256::new_from_slice(k2).map_err(|_| Error::Backend("aes-256-xts key setup"))?,
        );
        let mut buf = pt.to_vec();
        let tweak = <[u8; 16]>::try_from(nonce).map_err(|_| Error::Backend("xts tweak"))?;
        x.encrypt_sector(&mut buf, tweak.into());
        Ok(buf)
    }

    fn decrypt(&self, key: &SymmetricKey, nonce: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.check(key, nonce)?;
        let (k1, k2) = key.as_bytes().split_at(KEY_MIN / 2);
        if ct_eq(k1, k2) {
            return Err(Error::InvalidInput(
                "xts: the two key halves must differ (FIPS 140-3 IG C.I)",
            ));
        }
        if ct.len() < BLOCK_LEN {
            return Err(Error::InvalidLength {
                what: "data",
                got: ct.len(),
                min: BLOCK_LEN,
                max: usize::MAX,
            });
        }
        let x = Xts128::<Aes256>::new(
            Aes256::new_from_slice(k1).map_err(|_| Error::Backend("aes-256-xts key setup"))?,
            Aes256::new_from_slice(k2).map_err(|_| Error::Backend("aes-256-xts key setup"))?,
        );
        let mut buf = Zeroizing::new(ct.to_vec());
        let tweak = <[u8; 16]>::try_from(nonce).map_err(|_| Error::Backend("xts tweak"))?;
        x.decrypt_sector(&mut buf, tweak.into());
        Ok(buf)
    }
}

/// Registry constructor.
pub fn new(_params: &Params) -> Result<Box<dyn BlockMode>> {
    Ok(Box::new(Mode {}))
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

    /// Any-length key, so tests can hand the glue wrong sizes.
    fn key(bytes: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(bytes, Len::range(0, usize::MAX)).unwrap()
    }

    fn params_of(v: &J) -> Params {
        let mut p = Params::new();
        if let Some(o) = v.get("params").and_then(J::as_object) {
            for (k, val) in o {
                if let Some(n) = val.as_u64() {
                    p.set(k, Value::U64(n));
                } else {
                    p.set(k, Value::Str(val.as_str().unwrap().to_string()));
                }
            }
        }
        p
    }

    #[test]
    fn sizes_match_metadata() {
        let s = new(&Params::new()).unwrap().sizes();
        assert_eq!(s.key, Some(Len::fixed(64)));
        assert_eq!(s.nonce, Some(Len::fixed(16)));
        assert_eq!(s.block, Some(Len::fixed(BLOCK_LEN)));
    }

    #[test]
    fn all_kat_files() {
        let (mut n, mut bad) = (0, 0);
        for file in ["acvp-xts.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "aes-256-xts");
            for v in doc["vectors"].as_array().unwrap() {
                let id = v["id"].as_str().unwrap();
                let m = new(&params_of(v)).unwrap();
                let k = key(&unhex(v["key_hex"].as_str().unwrap()));
                let nonce = unhex(v["nonce_hex"].as_str().unwrap());
                let pt = unhex(v["pt_hex"].as_str().unwrap());
                let ct = unhex(v["ct_hex"].as_str().unwrap());
                assert_eq!(
                    m.encrypt(&k, &nonce, &pt).unwrap(),
                    ct,
                    "encrypt {file}/{id}"
                );
                assert_eq!(
                    &m.decrypt(&k, &nonce, &ct).unwrap()[..],
                    &pt[..],
                    "decrypt {file}/{id}"
                );
                n += 1;
            }
            for v in doc["invalid"].as_array().into_iter().flatten() {
                let id = v["id"].as_str().unwrap();
                let m = new(&params_of(v)).unwrap();
                let k = key(&unhex(v["key_hex"].as_str().unwrap()));
                let nonce = unhex(v["nonce_hex"].as_str().unwrap());
                let ct = unhex(v["ct_hex"].as_str().unwrap());
                assert!(
                    m.decrypt(&k, &nonce, &ct).is_err(),
                    "invalid accepted {file}/{id}"
                );
                bad += 1;
            }
        }
        assert!(n >= 4, "too few KATs ran: {n}");
        eprintln!("KAT vectors: {n} valid, {bad} invalid");
    }

    #[test]
    fn rejects_bad_lengths() {
        let m = new(&Params::new()).unwrap();
        let data = [1u8; 32];
        for bad in 0..=KEY_MAX + 1 {
            if key_ok(bad) {
                continue;
            }
            let r = m.encrypt(&key(&vec![1u8; bad]), &[0u8; NONCE_MIN], &data);
            assert!(matches!(r, Err(Error::InvalidLength { .. })), "key {bad}");
        }
        let k = key(&[9u8; KEY_MIN]);
        let r = m.encrypt(&k, &[0u8; NONCE_MAX + 1], &data);
        assert!(matches!(r, Err(Error::InvalidLength { .. })), "long nonce");
        if NONCE_MIN > 0 {
            let mut short = vec![0u8; NONCE_MIN];
            short.pop();
            let r = m.encrypt(&k, &short, &data);
            assert!(matches!(r, Err(Error::InvalidLength { .. })), "short nonce");
        }
    }
}
