//! Adapter: RustCrypto `eme2` (EME2 wide-block tweakable mode, IEEE 1619.2) over Aes128 -> nextssl `BlockMode`.
//! Key 48 bytes (the EME2 key triple: cipher key plus two 16-byte mask keys), nonce = the 16-byte tweak
//! (associated data of EME2, hashed by the mode), data 16 bytes to `MAX_INPUT_LEN`, any length is a valid
//! wide block (no padding, no expansion). NOT authenticated: pair with a MAC.

use aes::Aes128;
use eme2::cipher::KeyIvInit;
use eme2::Eme2;
use nextssl_core::{check_len, BlockMode, Error, Len, Params, Result, Sizes, SymmetricKey, Zeroizing, MAX_INPUT_LEN};

const KEY_LEN: usize = 48;
const TWEAK_LEN: usize = 16;
const BLOCK_LEN: usize = 16;

struct Mode;

impl Mode {
    fn init(&self, key: &SymmetricKey, nonce: &[u8], len: usize) -> Result<Eme2<Aes128>> {
        Len::fixed(KEY_LEN).check("key", key.len())?;
        Len::fixed(TWEAK_LEN).check("nonce", nonce.len())?;
        check_len("data", len, BLOCK_LEN, MAX_INPUT_LEN)?;
        Eme2::<Aes128>::new_from_slices(key.as_bytes(), nonce).map_err(|_| Error::Backend("eme2 key setup"))
    }
}

impl BlockMode for Mode {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(KEY_LEN)),
            nonce: Some(Len::fixed(TWEAK_LEN)),
            block: Some(Len::fixed(BLOCK_LEN)),
            ..Sizes::NONE
        }
    }

    fn encrypt(&self, key: &SymmetricKey, nonce: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        let m = self.init(key, nonce, pt.len())?;
        let mut buf = pt.to_vec();
        m.encrypt(&mut buf).map_err(|_| Error::InvalidInput("eme2: data shorter than 16 bytes"))?;
        Ok(buf)
    }

    fn decrypt(&self, key: &SymmetricKey, nonce: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let m = self.init(key, nonce, ct.len())?;
        let mut buf = Zeroizing::new(ct.to_vec());
        m.decrypt(&mut buf).map_err(|_| Error::InvalidInput("eme2: data shorter than 16 bytes"))?;
        Ok(buf)
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn BlockMode>> {
    Ok(Box::new(Mode))
}
