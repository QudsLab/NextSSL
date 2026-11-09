//! Adapter: RustCrypto `ghash` (GHASH, NIST SP 800-38D section 6.4) -> nextssl `Mac`.
//!
//! GHASH is the universal hash of AES-GCM, NOT a general MAC: the 16-byte key `H` must be used
//! for one message only (a key that authenticates two messages is forgeable) and GMAC adds an
//! encrypted mask that this id does not. It is exposed so GCM-family constructions can be tested
//! and composed; prefer an AEAD. Decisions:
//! - key: exactly 16 bytes, and the all-zero key (which makes every tag zero) is refused;
//! - message: whole 16-byte blocks only (`block = 16`), at least one block; a partial block is an
//!   error, never zero-padded (GCM defines its own padding of A and C; this id has none);
//! - tag: exactly 16 bytes.

use ghash::universal_hash::UniversalHash;
use ghash::{GHash, Key};
use nextssl_core::{ct_eq, Error, Len, Mac, Params, Result, Sizes, SymmetricKey, Zeroizing};

const BLOCK: usize = 16;

struct Impl;

impl Mac for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(BLOCK)),
            tag: Some(Len::fixed(BLOCK)),
            block: Some(Len::fixed(BLOCK)),
            ..Sizes::NONE
        }
    }

    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(BLOCK).check("key", key.len())?;
        Len::fixed(BLOCK).check("tag", out.len())?;
        if data.is_empty() || data.len() % BLOCK != 0 {
            return Err(Error::InvalidLength {
                what: "message (whole 16-byte blocks required)",
                got: data.len(),
                min: BLOCK,
                max: usize::MAX - (usize::MAX % BLOCK),
            });
        }
        if ct_eq(key.as_bytes(), &[0u8; BLOCK]) {
            return Err(Error::InvalidInput("ghash: all-zero key"));
        }
        let k = Zeroizing::new(
            Key::try_from(key.as_bytes()).map_err(|_| Error::Backend("ghash key setup"))?,
        );
        let mut g = GHash::new(&k);
        g.update_padded(data); // no padding happens: the length is a block multiple
        let tag = Zeroizing::new(g.finalize());
        out.copy_from_slice(tag.as_slice());
        Ok(())
    }
}

/// Registry constructor. GHASH takes no parameters.
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
        assert_eq!(doc["algorithm"], "ghash");
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
        for bad in [0usize, 15, 17, 32] {
            assert!(matches!(
                m.tag(&key(&vec![3u8; bad]), &[1u8; 16], &mut t),
                Err(Error::InvalidLength { .. })
            ));
        }
        assert!(matches!(
            m.tag(&key(&[0u8; 16]), &[1u8; 16], &mut t),
            Err(Error::InvalidInput(_))
        ));
        assert!(m.tag(&k, &[1u8; 16], &mut [0u8; 8]).is_err());
    }
}
