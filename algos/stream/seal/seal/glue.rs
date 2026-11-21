//! Adapter: SEAL (Rogaway/Coppersmith; seal.c from the funet archive, verbatim old C, symbols renamed `nextssl__seal__*`) -> nextssl `StreamCipher`.
//! Glue only, no crypto logic. Key exactly 20 bytes, nonce = 4-byte big-endian position index n, at most 4096 bytes of data per call.
//! Keystream words are serialised little endian (a choice of this wrapper, not checked against a published vector). Unauthenticated.

use nextssl_core::{Error, Len, Params, Result, Sizes, StreamCipher, SymmetricKey};

const NONCE_LEN: usize = 4;
const MAX_LEN: usize = 4096;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_ulong};
    extern "C" {
        #[link_name = "nextssl__seal__shim_apply"]
        pub fn apply(
            key: *const u8,
            keylen: c_ulong,
            nonce: *const u8,
            noncelen: c_ulong,
            data: *mut u8,
            len: c_ulong,
        ) -> c_int;
    }
}

struct Cipher;

fn key_len() -> Len {
    Len::fixed(20)
}

impl StreamCipher for Cipher {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(key_len()),
            nonce: Some(Len::fixed(NONCE_LEN)),
            ..Sizes::NONE
        }
    }

    fn apply_keystream(&self, key: &SymmetricKey, nonce: &[u8], data: &mut [u8]) -> Result<()> {
        key_len().check("key", key.len())?;
        Len::fixed(NONCE_LEN).check("nonce", nonce.len())?;
        if data.len() > MAX_LEN {
            // The keystream is finite: refuse before touching `data` (no truncation, no wrap-around).
            return Err(Error::InvalidLength {
                what: "data",
                got: data.len(),
                min: 0,
                max: MAX_LEN,
            });
        }
        // SAFETY: key and nonce are valid for their (checked) lengths and only read; `data` is a valid mutable
        // slice processed in place; the callee keeps no pointer.
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::apply(
                key.as_bytes().as_ptr(),
                key.len() as core::ffi::c_ulong,
                nonce.as_ptr(),
                nonce.len() as core::ffi::c_ulong,
                data.as_mut_ptr(),
                data.len() as core::ffi::c_ulong,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(b, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn roundtrip_and_lengths() {
        let c = new(&Params::new()).unwrap();
        let kl = key_len().min();
        let k = key(&vec![9u8; kl]);
        let mut n = [0u8; NONCE_LEN];
        n[2] = 5;
        let mut d = *b"hello stream cipher";
        c.apply_keystream(&k, &n, &mut d).unwrap();
        assert_ne!(&d, b"hello stream cipher");
        c.apply_keystream(&k, &n, &mut d).unwrap();
        assert_eq!(&d, b"hello stream cipher");
        assert!(matches!(
            c.apply_keystream(&key(&vec![1u8; kl - 1]), &n, &mut d),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            c.apply_keystream(&k, &n[..NONCE_LEN - 1], &mut d),
            Err(Error::InvalidLength { .. })
        ));
        let mut big = vec![0u8; MAX_LEN + 1];
        assert!(matches!(
            c.apply_keystream(&k, &n, &mut big),
            Err(Error::InvalidLength { .. })
        ));
        assert!(big.iter().all(|b| *b == 0), "data untouched on error");
    }
}
