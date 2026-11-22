//! Adapter: libosmocore MILENAGE f2/f3/f4/f5 (3GPP TS 35.206, GPL-2.0-or-later, verbatim C, symbols renamed `nextssl__milenage__*`) -> nextssl `Kdf`.
//! Glue only, no crypto logic. Shape: ikm = K (16), salt = RAND (16), info = OPc (16), output = RES (8) || CK (16) || IK (16) || AK (6) = 46 bytes.

use nextssl_core::{Error, Kdf, Len, Params, Result, Sizes, SymmetricKey};

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::c_int;
    extern "C" {
        #[link_name = "nextssl__milenage__shim_derive"]
        pub fn derive(k: *const u8, rnd: *const u8, opc: *const u8, out: *mut u8) -> c_int;
    }
}

const OUT_LEN: usize = 46;

struct Impl;

impl Kdf for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(16)),
            salt: Some(Len::fixed(16)),
            info: Some(Len::fixed(16)),
            out: Some(Len::fixed(OUT_LEN)),
            ..Sizes::NONE
        }
    }

    fn derive(&self, ikm: &SymmetricKey, salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(16).check("ikm", ikm.len())?;
        Len::fixed(16).check("salt", salt.len())?;
        Len::fixed(16).check("info", info.len())?;
        Len::fixed(OUT_LEN).check("out", out.len())?;
        // SAFETY: ikm, salt and info are valid for 16 bytes each (checked), out for OUT_LEN (checked); the callee keeps no pointer.
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::derive(
                ikm.as_bytes().as_ptr(),
                salt.as_ptr(),
                info.as_ptr(),
                out.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(Error::Backend("milenage failed"));
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

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn key(b: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(b, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn known_answers() {
        let k = new(&Params::new()).unwrap();
        let (kk, rnd, opc, o) = ("000102030405060708090a0b0c0d0e0f", "00000000000000000000000000000000", "000102030405060708090a0b0c0d0e0f", "e9fc88ccc8a353817200a184d8f2c758fbdf87900ddbf27512cb2dd3e0ec8378f6fc1d606c619f47ec9320c2c230");
        let mut out = [0u8; OUT_LEN];
        k.derive(&key(&unhex(kk)), &unhex(rnd), &unhex(opc), &mut out)
            .unwrap();
        assert_eq!(out.to_vec(), unhex(o));
    }

    #[test]
    fn deterministic_and_lengths() {
        let k = new(&Params::new()).unwrap();
        let kk = key(&[0x11u8; 16]);
        let (mut a, mut b) = ([0u8; OUT_LEN], [0u8; OUT_LEN]);
        k.derive(&kk, &[0x22u8; 16], &[0x33u8; 16], &mut a).unwrap();
        k.derive(&kk, &[0x22u8; 16], &[0x33u8; 16], &mut b).unwrap();
        assert_eq!(a, b);
        k.derive(&kk, &[0x22u8; 16], &[0x34u8; 16], &mut b).unwrap();
        assert_ne!(a, b);
        assert!(k
            .derive(&key(&[0u8; 17]), &[0u8; 16], &[0u8; 16], &mut a)
            .is_err());
        assert!(k.derive(&kk, &[0u8; 16], &[0u8; 15], &mut a).is_err());
        assert!(k
            .derive(&kk, &[0u8; 16], &[0u8; 16], &mut [0u8; 45])
            .is_err());
    }
}
