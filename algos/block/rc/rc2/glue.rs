//! Adapter: RustCrypto `rc2` (rc2) -> nextssl `BlockCipher`.
//! Raw single-block permutation only (no mode, no padding). Block 8 bytes, key 1..=128 bytes.
//! Param `effective_bits` (RFC 2268 T1, 1..=1024): 0 means "key length in bits". Effective length above the key length is accepted as in the RFC.

use nextssl_core::{
    BlockCipher, Error, KeyedBlockCipher, Len, Params, Result, Sizes, SymmetricKey,
};
use rc2::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt};
use rc2::Rc2;

const KEY_MIN: usize = 1;
const KEY_MAX: usize = 128;
const BLOCK_LEN: usize = 8;

/// Key lengths the cipher accepts (anything else is `InvalidLength`).
fn key_ok(len: usize) -> bool {
    (KEY_MIN..=KEY_MAX).contains(&len)
}

fn check_key(len: usize) -> Result<()> {
    if key_ok(len) {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            what: "key",
            got: len,
            min: KEY_MIN,
            max: KEY_MAX,
        })
    }
}

fn check_block(len: usize) -> Result<()> {
    Len::fixed(BLOCK_LEN).check("block", len)
}

struct Cipher {
    /// Effective key length in bits (RFC 2268 T1); 0 = key length in bits.
    effective_bits: u64,
}

/// Key schedule held for many blocks.
struct Keyed(Rc2);

impl KeyedBlockCipher for Keyed {
    fn block_len(&self) -> usize {
        BLOCK_LEN
    }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        check_block(block.len())?;
        let mut b = Block::<Rc2>::try_from(&*block).map_err(|_| Error::Backend("rc2 block"))?;
        self.0.encrypt_block(&mut b);
        block.copy_from_slice(&b);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        check_block(block.len())?;
        let mut b = Block::<Rc2>::try_from(&*block).map_err(|_| Error::Backend("rc2 block"))?;
        self.0.decrypt_block(&mut b);
        block.copy_from_slice(&b);
        Ok(())
    }
}

impl BlockCipher for Cipher {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(1, 128)),
            block: Some(Len::fixed(BLOCK_LEN)),
            ..Sizes::NONE
        }
    }

    fn keyed(&self, key: &SymmetricKey) -> Result<Box<dyn KeyedBlockCipher>> {
        check_key(key.len())?;
        let bits = match self.effective_bits {
            0 => key.len() * 8,
            b => b as usize,
        };
        let c = Rc2::new_with_eff_key_len(key.as_bytes(), bits);
        Ok(Box::new(Keyed(c)))
    }
}

/// Registry constructor.
pub fn new(params: &Params) -> Result<Box<dyn BlockCipher>> {
    let effective_bits = params.get_u64("effective_bits").unwrap_or(0);
    Ok(Box::new(Cipher { effective_bits }))
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

    use nextssl_core::Value;

    fn params_of(v: &J) -> Params {
        let mut p = Params::new();
        if let Some(o) = v.get("params").and_then(J::as_object) {
            for (k, val) in o {
                if let Some(h) = k.strip_suffix("_hex") {
                    p.set(h, Value::Bytes(unhex(val.as_str().unwrap())));
                } else {
                    p.set(k, Value::U64(val.as_u64().unwrap()));
                }
            }
        }
        p
    }

    #[test]
    fn sizes_match_metadata() {
        let s = new(&Params::new()).unwrap().sizes();
        assert_eq!(s.key, Some(Len::range(1, 128)));
        assert_eq!(s.block, Some(Len::fixed(BLOCK_LEN)));
    }

    #[test]
    fn all_kat_files() {
        let mut n = 0;
        for file in ["rfc2268.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "rc2");
            for v in doc["vectors"].as_array().unwrap() {
                let id = v["id"].as_str().unwrap();
                let c = new(&params_of(v)).unwrap();
                let k = key(&unhex(v["key_hex"].as_str().unwrap()));
                let pt = unhex(v["pt_hex"].as_str().unwrap());
                let ct = unhex(v["ct_hex"].as_str().unwrap());
                let keyed = c.keyed(&k).unwrap();
                let mut b = pt.clone();
                keyed.encrypt_block(&mut b).unwrap();
                assert_eq!(b, ct, "encrypt {file}/{id}");
                keyed.decrypt_block(&mut b).unwrap();
                assert_eq!(b, pt, "decrypt {file}/{id}");
                n += 1;
            }
        }
        assert!(n >= 5, "too few KATs ran: {n}");
    }

    #[test]
    fn rejects_bad_lengths() {
        let c = new(&Params::new()).unwrap();
        for bad in 0..=KEY_MAX + 1 {
            if key_ok(bad) {
                continue;
            }
            let r = c.keyed(&key(&vec![1u8; bad]));
            assert!(matches!(r, Err(Error::InvalidLength { .. })), "key {bad}");
        }
        let k = key(&[1u8; KEY_MIN]);
        let keyed = c.keyed(&k).unwrap();
        for bad in [0usize, 1, BLOCK_LEN - 1, BLOCK_LEN + 1, 2 * BLOCK_LEN] {
            let mut blk = vec![0u8; bad];
            assert!(keyed.encrypt_block(&mut blk).is_err(), "block {bad}");
            assert!(keyed.decrypt_block(&mut blk).is_err(), "block {bad}");
        }
    }
}
