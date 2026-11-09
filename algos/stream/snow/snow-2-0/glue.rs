//! Adapter: snow-2-0 (eSTREAM ECRYPT synchronous API, verbatim C, symbols renamed `nextssl__snow_2_0__*`) -> nextssl `StreamCipher`.
//! Generated wiring, no crypto logic. UNTESTED (not yet compiled). Key 16 bytes, IV (nonce) 16 bytes: one (key, IV)
//! pair out of the sizes the upstream header allows (128-bit key and IV; 256-bit key also allowed upstream). Raw keystream XOR, unauthenticated: pair with a MAC.
//! The C side (shim.c) sets up and wipes a context per call.

use nextssl_core::{Error, Len, Params, Result, Sizes, StreamCipher, SymmetricKey};

const KEY_LEN: usize = 16;
const NONCE_LEN: usize = 16;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::c_int;
    extern "C" {
        #[link_name = "nextssl__snow_2_0__shim_apply"]
        pub fn apply(
            key: *const u8,
            keylen: c_int,
            iv: *const u8,
            ivlen: c_int,
            data: *mut u8,
            len: u32,
        ) -> c_int;
    }
}

struct Cipher;

impl StreamCipher for Cipher {
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
        let len = u32::try_from(data.len()).map_err(|_| Error::InvalidInput("data too long"))?;
        // SAFETY: key and nonce are valid for exactly KEY_LEN / NONCE_LEN bytes (checked above) and are only read;
        // `data` is a valid mutable slice of `len` bytes, processed in place; the callee keeps no pointer.
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::apply(
                key.as_bytes().as_ptr(),
                KEY_LEN as core::ffi::c_int,
                nonce.as_ptr(),
                NONCE_LEN as core::ffi::c_int,
                data.as_mut_ptr(),
                len,
            )
        };
        if rc != 0 {
            return Err(Error::Backend("stream setup failed"));
        }
        Ok(())
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn StreamCipher>> {
    Ok(Box::new(Cipher))
}
