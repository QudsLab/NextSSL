//! Adapter: noekeon (libtomcrypt noekeon.c) (verbatim C, symbols renamed `nextssl__noekeon__*`) -> nextssl `BlockCipher`.
//! Generated wiring, no crypto logic. UNTESTED (not yet compiled). Block 16 bytes, key 16 bytes
//! (descriptor in the upstream source). Byte order is whatever the upstream functions define; the glue
//! only moves bytes. The C side (shim.c) owns one upstream key schedule per keyed cipher and wipes it on free.

use core::ffi::c_void;
use nextssl_core::{
    BlockCipher, Error, KeyedBlockCipher, Len, Params, Result, Sizes, SymmetricKey, Zeroizing,
};

const BLOCK_LEN: usize = 16;

fn key_len() -> Len {
    Len::fixed(16)
}

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_void};
    extern "C" {
        #[link_name = "nextssl__noekeon__shim_new"]
        pub fn ctx_new(key: *const u8, keylen: c_int) -> *mut c_void;
        #[link_name = "nextssl__noekeon__shim_enc"]
        pub fn ctx_enc(ctx: *const c_void, input: *const u8, output: *mut u8) -> c_int;
        #[link_name = "nextssl__noekeon__shim_dec"]
        pub fn ctx_dec(ctx: *const c_void, input: *const u8, output: *mut u8) -> c_int;
        #[link_name = "nextssl__noekeon__shim_free"]
        pub fn ctx_free(ctx: *mut c_void);
    }
}

/// Owner of one C key schedule. Read-only after construction.
struct Ctx(*mut c_void);

// SAFETY: the pointer is a unique heap allocation owned by this value; after construction the C side only
// reads it (the upstream encrypt/decrypt take a const key schedule), so shared access is data-race free.
#[allow(unsafe_code)]
unsafe impl Send for Ctx {}
#[allow(unsafe_code)]
unsafe impl Sync for Ctx {}

impl Drop for Ctx {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: created by ctx_new, freed exactly once here (the shim wipes it first).
        unsafe { ffi::ctx_free(self.0) }
    }
}

struct Keyed(Ctx);

impl Keyed {
    fn apply(&self, enc: bool, block: &mut [u8]) -> Result<()> {
        Len::fixed(BLOCK_LEN).check("block", block.len())?;
        let mut out = Zeroizing::new(vec![0u8; BLOCK_LEN]);
        // SAFETY: the context is live (owned by self); input and output are distinct slices of exactly
        // one block, which is all the callee reads and writes.
        #[allow(unsafe_code)]
        let rc = unsafe {
            if enc {
                ffi::ctx_enc(self.0 .0, block.as_ptr(), out.as_mut_ptr())
            } else {
                ffi::ctx_dec(self.0 .0, block.as_ptr(), out.as_mut_ptr())
            }
        };
        if rc != 0 {
            return Err(Error::Backend("block operation failed"));
        }
        block.copy_from_slice(&out);
        Ok(())
    }
}

impl KeyedBlockCipher for Keyed {
    fn block_len(&self) -> usize {
        BLOCK_LEN
    }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        self.apply(true, block)
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        self.apply(false, block)
    }
}

struct Cipher;

impl BlockCipher for Cipher {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(key_len()),
            block: Some(Len::fixed(BLOCK_LEN)),
            ..Sizes::NONE
        }
    }

    fn keyed(&self, key: &SymmetricKey) -> Result<Box<dyn KeyedBlockCipher>> {
        key_len().check("key", key.len())?;
        // SAFETY: key is valid for key.len() bytes, checked against the upstream range above; the
        // callee copies what it needs and keeps no pointer to it.
        #[allow(unsafe_code)]
        let p = unsafe { ffi::ctx_new(key.as_bytes().as_ptr(), key.len() as core::ffi::c_int) };
        if p.is_null() {
            // The upstream setup rejected the key length or failed to allocate.
            return Err(Error::Backend("key setup failed"));
        }
        Ok(Box::new(Keyed(Ctx(p))))
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn BlockCipher>> {
    Ok(Box::new(Cipher))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: usize) -> SymmetricKey {
        SymmetricKey::from_bytes(&vec![7u8; n], Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn roundtrip_and_lengths() {
        let c = new(&Params::new()).unwrap();
        let min = c.sizes().key.unwrap().min();
        let k = c.keyed(&key(min)).unwrap();
        let orig: Vec<u8> = (0..BLOCK_LEN as u8).collect();
        let mut b = orig.clone();
        k.encrypt_block(&mut b).unwrap();
        assert_ne!(b, orig);
        k.decrypt_block(&mut b).unwrap();
        assert_eq!(b, orig);
        assert!(k.encrypt_block(&mut [0u8; BLOCK_LEN + 1]).is_err());
        assert!(c.keyed(&key(min.wrapping_sub(1))).is_err());
    }
}
