//! Adapter: RustCrypto `aes` (AES-256) -> nextssl `BlockCipher`.
//! Key 32 bytes, block 16 bytes. Raw single-block permutation only; modes live elsewhere.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes256, Block};
use nextssl_core::{
    BlockCipher, Error, KeyedBlockCipher, Len, Params, Result, Sizes, SymmetricKey,
};

const KEY_LEN: usize = 32;
const BLOCK_LEN: usize = 16;

struct Aes256Cipher;

/// Key schedule held for many blocks. `aes` is built with its `zeroize` feature, so the round
/// keys are wiped when this is dropped.
struct Keyed(Aes256);

fn check_block(len: usize) -> Result<()> {
    Len::fixed(BLOCK_LEN).check("block", len)
}

impl KeyedBlockCipher for Keyed {
    fn block_len(&self) -> usize {
        BLOCK_LEN
    }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        check_block(block.len())?;
        let mut b = Block::try_from(&*block).map_err(|_| Error::Backend("aes block"))?;
        self.0.encrypt_block(&mut b);
        block.copy_from_slice(&b);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        check_block(block.len())?;
        let mut b = Block::try_from(&*block).map_err(|_| Error::Backend("aes block"))?;
        self.0.decrypt_block(&mut b);
        block.copy_from_slice(&b);
        Ok(())
    }
}

impl BlockCipher for Aes256Cipher {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(KEY_LEN)),
            block: Some(Len::fixed(BLOCK_LEN)),
            ..Sizes::NONE
        }
    }

    fn keyed(&self, key: &SymmetricKey) -> Result<Box<dyn KeyedBlockCipher>> {
        Len::fixed(KEY_LEN).check("key", key.len())?;
        let cipher = Aes256::new_from_slice(key.as_bytes())
            .map_err(|_| Error::Backend("aes-256 key setup"))?;
        Ok(Box::new(Keyed(cipher)))
    }
}

/// Registry constructor. AES-256 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn BlockCipher>> {
    Ok(Box::new(Aes256Cipher))
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

    fn key(bytes: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(bytes, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn sizes_match_metadata() {
        let s = new(&Params::new()).unwrap().sizes();
        assert_eq!(s.key, Some(Len::fixed(KEY_LEN)));
        assert_eq!(s.block, Some(Len::fixed(BLOCK_LEN)));
    }

    #[test]
    fn official_kats() {
        let c = new(&Params::new()).unwrap();
        let doc = load("fips197.json");
        assert_eq!(doc["algorithm"], "aes-256");
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let id = v["id"].as_str().unwrap();
            let k = key(&unhex(v["key_hex"].as_str().unwrap()));
            let pt = unhex(v["pt_hex"].as_str().unwrap());
            let ct = unhex(v["ct_hex"].as_str().unwrap());
            let mut b = pt.clone();
            c.encrypt_block(&k, &mut b).unwrap();
            assert_eq!(b, ct, "encrypt {id}");
            c.decrypt_block(&k, &mut b).unwrap();
            assert_eq!(b, pt, "decrypt {id}");
            // Keyed object gives the same answers.
            let keyed = c.keyed(&k).unwrap();
            let mut b2 = pt.clone();
            keyed.encrypt_block(&mut b2).unwrap();
            assert_eq!(b2, ct, "keyed encrypt {id}");
            keyed.decrypt_block(&mut b2).unwrap();
            assert_eq!(b2, pt, "keyed decrypt {id}");
            n += 1;
        }
        assert!(n >= 5, "suspiciously few vectors: {n}");
    }

    #[test]
    fn rejects_bad_lengths() {
        let c = new(&Params::new()).unwrap();
        for bad in [0usize, 16, 24, 31, 33, 64] {
            let k = key(&vec![1u8; bad]);
            assert!(
                matches!(c.keyed(&k), Err(Error::InvalidLength { .. })),
                "key len {bad}"
            );
            assert!(matches!(
                c.encrypt_block(&k, &mut [0u8; BLOCK_LEN]),
                Err(Error::InvalidLength { .. })
            ));
        }
        let k = key(&[1u8; KEY_LEN]);
        for bad in [0usize, 1, 15, 17, 32] {
            let mut b = vec![0u8; bad];
            assert!(
                matches!(
                    c.encrypt_block(&k, &mut b),
                    Err(Error::InvalidLength { .. })
                ),
                "block {bad}"
            );
            assert!(
                matches!(
                    c.decrypt_block(&k, &mut b),
                    Err(Error::InvalidLength { .. })
                ),
                "block {bad}"
            );
            assert!(b.iter().all(|&x| x == 0), "buffer touched on error");
        }
    }
}
