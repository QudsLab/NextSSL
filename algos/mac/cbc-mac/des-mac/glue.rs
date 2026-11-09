//! Adapter: RustCrypto `cbc-mac` + `des` (DES-MAC: CBC-MAC with DES and a zero IV, FIPS 113
//! (withdrawn) / ANSI X9.9) -> nextssl `Mac`.
//!
//! BROKEN tier: DES has a 56-bit key and raw CBC-MAC is only secure for one fixed message
//! length per key. Exposed for legacy interoperability only. Decisions:
//! - key: exactly 8 bytes (the parity bits are ignored by DES);
//! - message: whole 8-byte blocks only (`block = 8`), at least one block; a partial block is an
//!   error, never zero-padded (the upstream crate would pad silently), and the empty message is
//!   an error (its MAC would be the constant zero block);
//! - tag: exactly 8 bytes (FIPS 113 truncation to 16..63 bits is not offered).

use cbc_mac::{CbcMac, KeyInit, Mac as _};
use des::Des;
use nextssl_core::{Error, Len, Mac, Params, Result, Sizes, SymmetricKey, Zeroize};

const BLOCK: usize = 8;

struct Impl;

impl Mac for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(8)),
            tag: Some(Len::fixed(BLOCK)),
            block: Some(Len::fixed(BLOCK)),
            ..Sizes::NONE
        }
    }

    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(8).check("key", key.len())?;
        Len::fixed(BLOCK).check("tag", out.len())?;
        if data.is_empty() || data.len() % BLOCK != 0 {
            return Err(Error::InvalidLength {
                what: "message (whole 8-byte blocks required)",
                got: data.len(),
                min: BLOCK,
                max: usize::MAX - (usize::MAX % BLOCK),
            });
        }
        let mut mac = <CbcMac<Des> as KeyInit>::new_from_slice(key.as_bytes())
            .map_err(|_| Error::Backend("des-mac key setup"))?;
        mac.update(data);
        let mut full = mac.finalize().into_bytes();
        out.copy_from_slice(full.as_slice());
        full.as_mut_slice().zeroize();
        Ok(())
    }
}

/// Registry constructor. DES-MAC takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Mac>> {
    Ok(Box::new(Impl))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as J;
    use std::path::PathBuf;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
            .collect()
    }

    fn key(b: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(b, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn known_answers() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("kat/vectors.json");
        let doc: J = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(doc["algorithm"], "des-mac");
        let m = new(&Params::new()).unwrap();
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let k = key(&unhex(v["key_hex"].as_str().unwrap()));
            let data = unhex(v["data_hex"].as_str().unwrap());
            let want = unhex(v["tag_hex"].as_str().unwrap());
            let mut got = [0u8; 8];
            m.tag(&k, &data, &mut got).unwrap();
            assert_eq!(&got[..], &want[..], "{}", v["id"]);
            assert!(m.verify(&k, &data, &want).unwrap());
            n += 1;
        }
        assert!(n >= 20, "{n}");
    }

    #[test]
    fn strict_inputs() {
        let m = new(&Params::new()).unwrap();
        let k = key(&[3u8; 8]);
        let mut t = [0u8; 8];
        for bad in [0usize, 1, 7, 9, 15] {
            assert!(
                matches!(
                    m.tag(&k, &vec![1u8; bad], &mut t),
                    Err(Error::InvalidLength { .. })
                ),
                "message {bad}"
            );
        }
        for bad in [0usize, 7, 9, 16] {
            assert!(matches!(
                m.tag(&key(&vec![3u8; bad]), &[1u8; 8], &mut t),
                Err(Error::InvalidLength { .. })
            ));
        }
        assert!(m.tag(&k, &[1u8; 8], &mut [0u8; 16]).is_err());
    }
}
