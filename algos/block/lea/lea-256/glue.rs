//! Adapter: `lea` 0.5.4 `Lea256` (LEA, KS X 3246 / TTAK.KO-12.0223) -> nextssl `BlockCipher`. The crate is on the older RustCrypto
//! `cipher` 0.3 API (re-exported as `lea::cipher`), so this glue uses `NewBlockCipher` / `BlockEncrypt` / `BlockDecrypt`.
//! Raw single-block permutation only (no mode, no padding). Block 16 bytes, key 32 bytes.

use lea::cipher::generic_array::GenericArray;
use lea::cipher::{BlockDecrypt, BlockEncrypt, NewBlockCipher};
use lea::Lea256;
use nextssl_core::{BlockCipher, Error, KeyedBlockCipher, Len, Params, Result, Sizes, SymmetricKey};

const KEY_LEN: usize = 32;
const BLOCK_LEN: usize = 16;

struct Cipher;

struct Keyed(Lea256);

fn check_block(len: usize) -> Result<()> {
    Len::fixed(BLOCK_LEN).check("block", len)
}

impl KeyedBlockCipher for Keyed {
    fn block_len(&self) -> usize {
        BLOCK_LEN
    }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        check_block(block.len())?;
        self.0.encrypt_block(GenericArray::from_mut_slice(block));
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        check_block(block.len())?;
        self.0.decrypt_block(GenericArray::from_mut_slice(block));
        Ok(())
    }
}

impl BlockCipher for Cipher {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(KEY_LEN)),
            block: Some(Len::fixed(BLOCK_LEN)),
            ..Sizes::NONE
        }
    }

    fn keyed(&self, key: &SymmetricKey) -> Result<Box<dyn KeyedBlockCipher>> {
        Len::fixed(KEY_LEN).check("key", key.len())?;
        if key.len() != KEY_LEN {
            return Err(Error::Backend("lea key length"));
        }
        Ok(Box::new(Keyed(Lea256::new(GenericArray::from_slice(key.as_bytes())))))
    }
}

/// Registry constructor.
pub fn new(_params: &Params) -> Result<Box<dyn BlockCipher>> {
    Ok(Box::new(Cipher))
}
