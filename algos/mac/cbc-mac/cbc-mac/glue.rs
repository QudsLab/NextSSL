//! Adapter: RustCrypto `cbc-mac` + `aes` (raw CBC-MAC with a zero IV, ISO/IEC 9797-1 algorithm 1
//! with no padding) -> nextssl `Mac`.
//!
//! Raw CBC-MAC is only secure for messages of ONE fixed length per key; with variable lengths it
//! is forgeable. It is exposed for interoperability (legacy tier) and for building CMAC-like
//! constructions. Decisions:
//! - the AES variant follows the key length (16/24/32 bytes), any other length is refused;
//! - message: whole 16-byte blocks only (`block = 16`), at least one block; a partial block is an
//!   error, never zero-padded (the upstream crate would pad silently), and the empty message is
//!   an error (its MAC would be the constant zero block);
//! - tag: exactly 16 bytes (no truncation).

use aes::{Aes128, Aes192, Aes256};
use cbc_mac::{CbcMac, KeyInit, Mac as _};
use nextssl_core::{Error, Len, Mac, Params, Result, Sizes, SymmetricKey, Zeroize};

const BLOCK: usize = 16;

struct Impl;

macro_rules! run {
    ($c:ty, $key:expr, $data:expr, $out:expr) => {{
        let mut mac = <CbcMac<$c> as KeyInit>::new_from_slice($key)
            .map_err(|_| Error::Backend("cbc-mac key setup"))?;
        mac.update($data);
        let mut full = mac.finalize().into_bytes();
        $out.copy_from_slice(full.as_slice());
        full.as_mut_slice().zeroize();
        Ok(())
    }};
}

impl Mac for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(16, 32)),
            tag: Some(Len::fixed(BLOCK)),
            block: Some(Len::fixed(BLOCK)),
            ..Sizes::NONE
        }
    }

    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(BLOCK).check("tag", out.len())?;
        if data.is_empty() || data.len() % BLOCK != 0 {
            return Err(Error::InvalidLength {
                what: "message (whole 16-byte blocks required)",
                got: data.len(),
                min: BLOCK,
                max: usize::MAX - (usize::MAX % BLOCK),
            });
        }
        match key.len() {
            16 => run!(Aes128, key.as_bytes(), data, out),
            24 => run!(Aes192, key.as_bytes(), data, out),
            32 => run!(Aes256, key.as_bytes(), data, out),
            got => Err(Error::InvalidLength {
                what: "key",
                got,
                min: 16,
                max: 32,
            }),
        }
    }
}

/// Registry constructor. CBC-MAC takes no parameters.
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
        assert_eq!(doc["algorithm"], "cbc-mac");
        let m = new(&Params::new()).unwrap();
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let k = key(&unhex(v["key_hex"].as_str().unwrap()));
            let data = unhex(v["data_hex"].as_str().unwrap());
            let want = unhex(v["tag_hex"].as_str().unwrap());
            let mut got = [0u8; 16];
            m.tag(&k, &data, &mut got).unwrap();
            assert_eq!(&got[..], &want[..], "{}", v["id"]);
            assert!(m.verify(&k, &data, &want).unwrap());
            n += 1;
        }
        assert!(n >= 30, "{n}");
    }

    #[test]
    fn strict_inputs() {
        let m = new(&Params::new()).unwrap();
        let k = key(&[3u8; 16]);
        let mut t = [0u8; 16];
        for bad in [0usize, 1, 15, 17, 31] {
            assert!(
                matches!(
                    m.tag(&k, &vec![1u8; bad], &mut t),
                    Err(Error::InvalidLength { .. })
                ),
                "message {bad}"
            );
        }
        for bad in [0usize, 8, 15, 17, 31, 33] {
            assert!(matches!(
                m.tag(&key(&vec![3u8; bad]), &[1u8; 16], &mut t),
                Err(Error::InvalidLength { .. })
            ));
        }
        assert!(m.tag(&k, &[1u8; 16], &mut [0u8; 8]).is_err());
        assert!(m.tag(&k, &[1u8; 16], &mut [0u8; 17]).is_err());
    }
}
