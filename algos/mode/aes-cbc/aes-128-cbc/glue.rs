//! Adapter: RustCrypto `cbc` (aes-128-cbc) -> nextssl `BlockMode`.
//! Key 16 bytes, nonce/IV/tweak 16 bytes, cipher block 16 bytes.

use aes::Aes128;
use cbc::cipher::block_padding::{NoPadding, Pkcs7};
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use nextssl_core::{BlockMode, Error, Len, Params, Result, Sizes, SymmetricKey, Zeroizing};

const KEY_MIN: usize = 16;
const KEY_MAX: usize = 16;
const NONCE_MIN: usize = 16;
const NONCE_MAX: usize = 16;
const BLOCK_LEN: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Padding {
    None,
    Pkcs7,
}

/// Key lengths accepted (anything else is `InvalidLength`).
fn key_ok(len: usize) -> bool {
    len == 16
}

struct Mode {
    padding: Padding,
}

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
            key: Some(Len::fixed(16)),
            nonce: Some(Len::fixed(16)),
            block: Some(Len::fixed(BLOCK_LEN)),
            ..Sizes::NONE
        }
    }

    fn encrypt(&self, key: &SymmetricKey, nonce: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        self.check(key, nonce)?;
        let e = cbc::Encryptor::<Aes128>::new_from_slices(key.as_bytes(), nonce)
            .map_err(|_| Error::Backend("aes-128-cbc key/iv setup"))?;
        match self.padding {
            Padding::None => {
                if pt.len() % BLOCK_LEN != 0 {
                    return Err(Error::InvalidInput(
                        "aes-128-cbc: data is not a multiple of 16 bytes (padding = none)",
                    ));
                }
                Ok(e.encrypt_padded_vec::<NoPadding>(pt))
            }
            Padding::Pkcs7 => Ok(e.encrypt_padded_vec::<Pkcs7>(pt)),
        }
    }

    fn decrypt(&self, key: &SymmetricKey, nonce: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.check(key, nonce)?;
        let d = cbc::Decryptor::<Aes128>::new_from_slices(key.as_bytes(), nonce)
            .map_err(|_| Error::Backend("aes-128-cbc key/iv setup"))?;
        let mut buf = Zeroizing::new(ct.to_vec());
        let n = match self.padding {
            Padding::None => {
                if ct.len() % BLOCK_LEN != 0 {
                    return Err(Error::InvalidInput(
                        "aes-128-cbc: data is not a multiple of 16 bytes (padding = none)",
                    ));
                }
                d.decrypt_padded::<NoPadding>(&mut buf)
                    .map_err(|_| Error::InvalidInput("aes-128-cbc: bad length"))?
                    .len()
            }
            Padding::Pkcs7 => d
                .decrypt_padded::<Pkcs7>(&mut buf)
                .map_err(|_| Error::InvalidInput("aes-128-cbc: invalid padding"))?
                .len(),
        };
        buf.truncate(n);
        Ok(buf)
    }
}

/// Registry constructor.
pub fn new(params: &Params) -> Result<Box<dyn BlockMode>> {
    let padding = match params.get_str("padding") {
        None | Some("none") => Padding::None,
        Some("pkcs7") => Padding::Pkcs7,
        Some(_) => return Err(Error::ParamOutOfRange("padding")),
    };
    Ok(Box::new(Mode { padding }))
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
        assert_eq!(s.key, Some(Len::fixed(16)));
        assert_eq!(s.nonce, Some(Len::fixed(16)));
        assert_eq!(s.block, Some(Len::fixed(BLOCK_LEN)));
    }

    #[test]
    fn all_kat_files() {
        let (mut n, mut bad) = (0, 0);
        for file in ["acvp-cbc.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "aes-128-cbc");
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
        assert!(n >= 10, "too few KATs ran: {n}");
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
