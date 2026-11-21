//! Adapter: libtomcrypt SOSEMANUK (eSTREAM portfolio, verbatim C, symbols renamed `nextssl__sosemanuk__*`) -> nextssl `StreamCipher`.
//! Glue only, no crypto logic. Key 16..=32 bytes (upstream also accepts 1..=15 and pads: refused here), IV exactly 16 bytes
//! (upstream zero-pads shorter IVs: refused here). Raw keystream XOR, unauthenticated: pair with a MAC.

use nextssl_core::{Error, Len, Params, Result, Sizes, StreamCipher, SymmetricKey};

const NONCE_LEN: usize = 16;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_ulong};
    extern "C" {
        #[link_name = "nextssl__sosemanuk__shim_apply"]
        pub fn apply(
            key: *const u8,
            keylen: c_ulong,
            iv: *const u8,
            ivlen: c_ulong,
            data: *mut u8,
            len: c_ulong,
        ) -> c_int;
    }
}

struct Cipher;

impl StreamCipher for Cipher {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(16, 32)),
            nonce: Some(Len::fixed(NONCE_LEN)),
            ..Sizes::NONE
        }
    }

    fn apply_keystream(&self, key: &SymmetricKey, nonce: &[u8], data: &mut [u8]) -> Result<()> {
        Len::range(16, 32).check("key", key.len())?;
        Len::fixed(NONCE_LEN).check("nonce", nonce.len())?;
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
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn key(b: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(b, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn known_answers() {
        let c = new(&Params::new()).unwrap();
        for (k, n, d, o) in [("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000000000000004a0000000000000000", "4b696c726f792077617320686572652c20616e642074686572652e202e2e2e616e64206576657279776865726521", "7efe2e6f8f7715726a8814a65688299a86327f14d6b1949025bc73fd026c6ab8da8e7f617081e3bb99af199f2045"), ("0053a6f94c9ff24598eb3e91e4378add3083d6297ccf2275c81b6ec11467ba0d", "0d74db42a91077de45ac137ae148af16", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "55eb8d174c2e0351e5a53c90e84740eb0f5a24aafec8e0c9f9d2ce48b2adb0a34d2e8c4e016102607368ffa43a0f91550706e3548ad9e5ea15a53eb6f0ede9dc")] {
            let mut buf = unhex(d);
            c.apply_keystream(&key(&unhex(k)), &unhex(n), &mut buf).unwrap();
            assert_eq!(buf, unhex(o));
        }
    }

    #[test]
    fn roundtrip_and_lengths() {
        let c = new(&Params::new()).unwrap();
        let k = key(&[9u8; 16]);
        let n = [5u8; NONCE_LEN];
        let mut d = *b"hello stream cipher";
        c.apply_keystream(&k, &n, &mut d).unwrap();
        assert_ne!(&d, b"hello stream cipher");
        c.apply_keystream(&k, &n, &mut d).unwrap();
        assert_eq!(&d, b"hello stream cipher");
        assert!(matches!(
            c.apply_keystream(&key(&[1u8; 15]), &n, &mut d),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            c.apply_keystream(&k, &n[..8], &mut d),
            Err(Error::InvalidLength { .. })
        ));
    }
}
