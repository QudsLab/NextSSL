//! Adapter: P1sec GEA-1 (GPRS keystream generator, AGPL-3.0-or-later, verbatim C, symbols renamed `nextssl__gea1__*`) -> nextssl `StreamCipher`.
//! Glue only, no crypto logic. Key exactly 8 bytes. Nonce = 5 bytes: 32-bit IV (as upstream stores it) then the direction byte (0 or 1).
//! At most 1523 bytes of data per call. Unauthenticated, educational-grade upstream: root only.

use nextssl_core::{Error, Len, Params, Result, Sizes, StreamCipher, SymmetricKey};

const NONCE_LEN: usize = 5;
const MAX_LEN: usize = 1523;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_ulong};
    extern "C" {
        #[link_name = "nextssl__gea1__shim_apply"]
        pub fn apply(key: *const u8, keylen: c_ulong, nonce: *const u8, noncelen: c_ulong, data: *mut u8, len: c_ulong) -> c_int;
    }
}

struct Cipher;

fn key_len() -> Len {
    Len::fixed(8)
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
        if nonce[4] > 1 {
            return Err(Error::ParamOutOfRange("direction"));
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

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    fn key(b: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(b, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn known_answers() {
        let c = new(&Params::new()).unwrap();
        for (k, n, d, o) in [("0000000000000000", "0000000000", "000000000000000000000000000000000000", "1fa198ab2114c38a9ebccb63ad4813a740c1"), ("55e303eb7d55b685", "da637a8301", "6e00cfe7b7fb974892b8cde5e43363397d85", "58dad06457b9fe1015da0776ed19907b7888"), ("a7265d1932a0d618", "0e9b8adf00", "96e7b1d92b1ea8fcdda41233c63294055383", "d72197f65d4d67b14d2cee812cb0b9bea0c9")] {
            let mut buf = unhex(d);
            c.apply_keystream(&key(&unhex(k)), &unhex(n), &mut buf).unwrap();
            assert_eq!(buf, unhex(o));
        }
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
        assert!(matches!(c.apply_keystream(&key(&vec![1u8; kl - 1]), &n, &mut d), Err(Error::InvalidLength { .. })));
        assert!(matches!(c.apply_keystream(&k, &n[..NONCE_LEN - 1], &mut d), Err(Error::InvalidLength { .. })));
        let mut big = vec![0u8; MAX_LEN + 1];
        assert!(matches!(c.apply_keystream(&k, &n, &mut big), Err(Error::InvalidLength { .. })));
        assert!(big.iter().all(|b| *b == 0), "data untouched on error");
    }
}
