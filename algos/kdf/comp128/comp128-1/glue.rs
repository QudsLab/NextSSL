//! Adapter: libosmocore COMP128 version 1 (GSM A3/A8, GPL-2.0-or-later, verbatim C, symbols renamed `nextssl__comp128_1__*`) -> nextssl `Kdf`.
//! Glue only, no crypto logic. Shape: ikm = Ki (16 bytes), salt = RAND (16 bytes), no info, output = SRES (4) || Kc (8), exactly 12 bytes.
//! Tier broken: the algorithm is a secret operator design known from leaks and reverse engineering.

use nextssl_core::{Error, Kdf, Len, Params, Result, Sizes, SymmetricKey};

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::c_int;
    extern "C" {
        #[link_name = "nextssl__comp128_1__shim_derive"]
        pub fn derive(ki: *const u8, rnd: *const u8, out: *mut u8) -> c_int;
    }
}

struct Impl;

impl Kdf for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(16)),
            salt: Some(Len::fixed(16)),
            info: Some(Len::fixed(0)),
            out: Some(Len::fixed(12)),
            ..Sizes::NONE
        }
    }

    fn derive(&self, ikm: &SymmetricKey, salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(16).check("ikm", ikm.len())?;
        Len::fixed(16).check("salt", salt.len())?;
        Len::fixed(0).check("info", info.len())?;
        Len::fixed(12).check("out", out.len())?;
        // SAFETY: ikm and salt are valid for 16 bytes each (checked), out for 12 (checked); the callee keeps no pointer.
        #[allow(unsafe_code)]
        let rc = unsafe { ffi::derive(ikm.as_bytes().as_ptr(), salt.as_ptr(), out.as_mut_ptr()) };
        if rc != 0 {
            return Err(Error::Backend("comp128 failed"));
        }
        Ok(())
    }
}

/// Registry constructor.
pub fn new(_params: &Params) -> Result<Box<dyn Kdf>> {
    Ok(Box::new(Impl))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(b, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn deterministic_and_lengths() {
        let k = new(&Params::new()).unwrap();
        let ki = key(&[0x11u8; 16]);
        let (mut a, mut b) = ([0u8; 12], [0u8; 12]);
        k.derive(&ki, &[0x22u8; 16], &[], &mut a).unwrap();
        k.derive(&ki, &[0x22u8; 16], &[], &mut b).unwrap();
        assert_eq!(a, b);
        k.derive(&ki, &[0x23u8; 16], &[], &mut b).unwrap();
        assert_ne!(a, b);
        assert!(k.derive(&key(&[0u8; 15]), &[0u8; 16], &[], &mut a).is_err());
        assert!(k.derive(&ki, &[0u8; 15], &[], &mut a).is_err());
        assert!(k.derive(&ki, &[0u8; 16], b"x", &mut a).is_err());
        assert!(k.derive(&ki, &[0u8; 16], &[], &mut [0u8; 11]).is_err());
    }
}
