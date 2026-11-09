//! Adapter: RustCrypto `fpe` (aes-fpe-ff1) -> nextssl `BlockMode`.
//! Key 16/24/32 bytes, nonce/IV/tweak 0..=1024 bytes, cipher block 16 bytes.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use fpe::ff1::{FlexibleNumeralString, FF1};
use nextssl_core::{BlockMode, Error, Len, Params, Result, Sizes, SymmetricKey, Zeroizing};

const KEY_MIN: usize = 16;
const KEY_MAX: usize = 32;
const NONCE_MIN: usize = 0;
const NONCE_MAX: usize = 1024;
const BLOCK_LEN: usize = 16;

fn ff1_run<C: KeyInit + BlockCipherEncrypt + Clone>(
    key: &[u8],
    radix: u32,
    tweak: &[u8],
    x: FlexibleNumeralString,
    encrypt: bool,
) -> Result<Vec<u16>> {
    let f = FF1::<C>::new(key, radix).map_err(|_| Error::ParamOutOfRange("radix"))?;
    let r = if encrypt {
        f.encrypt(tweak, &x)
    } else {
        f.decrypt(tweak, &x)
    };
    r.map(Vec::<u16>::from)
        .map_err(|_| Error::InvalidInput("aes-ff1: numeral string length is outside the range allowed for this radix (radix^len >= 1_000_000, len >= 2)"))
}

/// Key lengths accepted (anything else is `InvalidLength`).
fn key_ok(len: usize) -> bool {
    matches!(len, 16 | 24 | 32)
}

struct Mode {
    radix: u32,
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
            key: Some(Len::range(16, 32)),
            nonce: Some(Len::range(0, 1024)),
            block: Some(Len::fixed(BLOCK_LEN)),
            ..Sizes::NONE
        }
    }

    fn encrypt(&self, key: &SymmetricKey, nonce: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        self.check(key, nonce)?;
        let radix = self.radix;
        if pt.iter().any(|&d| u32::from(d) >= radix) {
            return Err(Error::InvalidInput(
                "aes-ff1: a digit is not below the radix",
            ));
        }
        let x = FlexibleNumeralString::from(pt.iter().map(|&d| u16::from(d)).collect::<Vec<u16>>());
        let k = key.as_bytes();
        let y = match k.len() {
            16 => ff1_run::<Aes128>(k, radix, nonce, x, true)?,
            24 => ff1_run::<Aes192>(k, radix, nonce, x, true)?,
            _ => ff1_run::<Aes256>(k, radix, nonce, x, true)?,
        };
        Ok(y.iter().map(|&d| d as u8).collect())
    }

    fn decrypt(&self, key: &SymmetricKey, nonce: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.check(key, nonce)?;
        let radix = self.radix;
        if ct.iter().any(|&d| u32::from(d) >= radix) {
            return Err(Error::InvalidInput(
                "aes-ff1: a digit is not below the radix",
            ));
        }
        let x = FlexibleNumeralString::from(ct.iter().map(|&d| u16::from(d)).collect::<Vec<u16>>());
        let k = key.as_bytes();
        let y = match k.len() {
            16 => ff1_run::<Aes128>(k, radix, nonce, x, false)?,
            24 => ff1_run::<Aes192>(k, radix, nonce, x, false)?,
            _ => ff1_run::<Aes256>(k, radix, nonce, x, false)?,
        };
        Ok(Zeroizing::new(y.iter().map(|&d| d as u8).collect()))
    }
}

/// Registry constructor.
pub fn new(params: &Params) -> Result<Box<dyn BlockMode>> {
    let radix = u32::try_from(params.get_u64("radix").unwrap_or(10))
        .map_err(|_| Error::ParamOutOfRange("radix"))?;
    Ok(Box::new(Mode { radix }))
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
        assert_eq!(s.key, Some(Len::range(16, 32)));
        assert_eq!(s.nonce, Some(Len::range(0, 1024)));
        assert_eq!(s.block, Some(Len::fixed(BLOCK_LEN)));
    }

    #[test]
    fn all_kat_files() {
        let (mut n, mut bad) = (0, 0);
        for file in ["acvp-ff1.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "aes-fpe-ff1");
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
    }
}
