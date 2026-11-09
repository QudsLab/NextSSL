//! Adapter: Nugine `zuc` (ZUC-256 v1.1 keystream, vendored) -> nextssl `StreamCipher`.
//!
//! Key 32 bytes, IV (nonce) 23 bytes. Raw keystream XOR only, no MAC. Unauthenticated: pair with a MAC.
//! The ZUC-256 addendum and the new-initialization variants are not implemented upstream and not offered here.
//! The upstream cipher's keystream limit is reported as an error and no byte is written in that case.

use nextssl_core::{Error, Len, Params, Result, Sizes, StreamCipher, SymmetricKey};
use zuc256_src::cipher::{KeyIvInit, StreamCipher as _};
use zuc256_src::zuc256::Zuc256StreamCipher;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 23;

struct Zuc256;

impl StreamCipher for Zuc256 {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(KEY_LEN)),
            nonce: Some(Len::fixed(NONCE_LEN)),
            ..Sizes::NONE
        }
    }

    fn apply_keystream(&self, key: &SymmetricKey, nonce: &[u8], data: &mut [u8]) -> Result<()> {
        Len::fixed(KEY_LEN).check("key", key.len())?;
        Len::fixed(NONCE_LEN).check("nonce", nonce.len())?;
        let mut c = Zuc256StreamCipher::new_from_slices(key.as_bytes(), nonce)
            .map_err(|_| Error::Backend("zuc-256 key/iv setup"))?;
        c.try_apply_keystream(data)
            .map_err(|_| Error::InvalidInput("zuc-256: keystream limit exceeded"))
    }
}

/// Registry constructor. This algorithm takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn StreamCipher>> {
    Ok(Box::new(Zuc256))
}
