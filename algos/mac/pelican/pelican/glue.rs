//! Adapter: libtomcrypt Pelican MAC (AES-based, 128-bit tag; verbatim C, symbols renamed `nextssl__pelican__*`) -> nextssl `Mac`.
//! Glue only, no crypto logic. The key is an AES key (16, 24 or 32 bytes: any other length is an error). The C side
//! (shim.c) sets up and wipes the upstream state per call. Pelican is an early MAC proposal with limited analysis: tier `unverified`.

use nextssl_core::{Error, Len, Mac, Params, Result, Sizes, SymmetricKey};

const TAG_LEN: usize = 16;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_ulong};
    extern "C" {
        #[link_name = "nextssl__pelican__shim_tag"]
        pub fn tag(key: *const u8, keylen: c_ulong, data: *const u8, len: c_ulong, out: *mut u8) -> c_int;
    }
}

struct Impl;

fn key_ok(n: usize) -> Result<()> {
    if matches!(n, 16 | 24 | 32) {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            what: "key",
            got: n,
            min: 16,
            max: 32,
        })
    }
}

impl Mac for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(16, 32)),
            tag: Some(Len::fixed(TAG_LEN)),
            ..Sizes::NONE
        }
    }

    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()> {
        key_ok(key.len())?;
        Len::fixed(TAG_LEN).check("tag", out.len())?;
        // SAFETY: key valid for key.len() bytes (checked), data for data.len(), out for exactly TAG_LEN bytes
        // (checked); the callee keeps no pointer.
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::tag(
                key.as_bytes().as_ptr(),
                key.len() as core::ffi::c_ulong,
                data.as_ptr(),
                data.len() as core::ffi::c_ulong,
                out.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(Error::Backend("pelican failed"));
        }
        Ok(())
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Mac>> {
    Ok(Box::new(Impl))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    fn key(b: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(b, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn known_answers() {
        let m = new(&Params::new()).unwrap();
        for (k, msg, t) in [("000102030405060708090a0b0c0d0e0f", "", "eb583715f834dee5a4d16ee4b9d7760e"), ("000102030405060708090a0b0c0d0e0f", "000102", "1c9740606c58172d0394197081c43854"), ("000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f", "03cc46b8aca79c361e8c6ea67b893249"), ("000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "89cc36581bdd4db578bbacf0ff8b0815"), ("000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202123", "4a7d454dcdb5da8d487816485d459599")] {
            let mut out = [0u8; TAG_LEN];
            m.tag(&key(&unhex(k)), &unhex(msg), &mut out).unwrap();
            assert_eq!(out.to_vec(), unhex(t));
            assert!(m.verify(&key(&unhex(k)), &unhex(msg), &unhex(t)).unwrap());
        }
    }

    #[test]
    fn roundtrip_and_lengths() {
        let m = new(&Params::new()).unwrap();
        let k = key(&[7u8; 32]);
        let mut a = [0u8; TAG_LEN];
        let mut b = [0u8; TAG_LEN];
        m.tag(&k, b"hello", &mut a).unwrap();
        m.tag(&k, b"hello", &mut b).unwrap();
        assert_eq!(a, b);
        m.tag(&k, b"hellp", &mut b).unwrap();
        assert_ne!(a, b);
        assert!(matches!(m.tag(&key(&[7u8; 20]), b"x", &mut a), Err(Error::InvalidLength { .. })));
        assert!(matches!(m.tag(&k, b"x", &mut [0u8; 15]), Err(Error::InvalidLength { .. })));
    }
}
