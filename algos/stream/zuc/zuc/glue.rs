//! Adapter: `zuc` crate (ZUC-128 keystream) -> nextssl `StreamCipher`.
//!
//! Key 16 bytes, IV (nonce) 16 bytes. Raw keystream XOR only: the 3GPP EEA3 bearer/count/direction
//! framing is NOT applied. Unauthenticated: pair with a MAC. The upstream cipher's keystream limit
//! is reported as an error and no byte is written in that case.

use nextssl_core::{Error, Len, Params, Result, Sizes, StreamCipher, SymmetricKey};
use zuc::cipher::{KeyIvInit, StreamCipher as _};
use zuc::zuc128::Zuc128StreamCipher;

const KEY_LEN: usize = 16;
const NONCE_LEN: usize = 16;

struct Zuc128;

impl StreamCipher for Zuc128 {
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
        let mut c = Zuc128StreamCipher::new_from_slices(key.as_bytes(), nonce)
            .map_err(|_| Error::Backend("zuc-128 key/iv setup"))?;
        c.try_apply_keystream(data)
            .map_err(|_| Error::InvalidInput("zuc-128: keystream limit exceeded"))
    }
}

/// Registry constructor. This algorithm takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn StreamCipher>> {
    Ok(Box::new(Zuc128))
}
