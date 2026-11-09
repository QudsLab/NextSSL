//! Adapter: `hc-256` crate (HC-256 stream cipher) -> nextssl `StreamCipher`.
//!
//! Key 32 bytes, IV (nonce) 32 bytes. Raw keystream XOR. Unauthenticated: pair with a MAC.
//! The upstream cipher's keystream limit is reported as an error and no byte is written in that case.

use hc_256::cipher::{KeyIvInit, StreamCipher as _};
use hc_256::Hc256;
use nextssl_core::{Error, Len, Params, Result, Sizes, StreamCipher, SymmetricKey};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 32;

struct HcCipher;

impl StreamCipher for HcCipher {
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
        let mut c = Hc256::new_from_slices(key.as_bytes(), nonce)
            .map_err(|_| Error::Backend("hc-256 key/iv setup"))?;
        c.try_apply_keystream(data)
            .map_err(|_| Error::InvalidInput("hc-256: keystream limit exceeded"))
    }
}

/// Registry constructor. This algorithm takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn StreamCipher>> {
    Ok(Box::new(HcCipher))
}
