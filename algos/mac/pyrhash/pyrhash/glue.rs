//! Adapter: pyrhash (SUPERCOP crypto_auth) (little) (verbatim C, symbols renamed `nextssl__pyrhash__*`) -> nextssl `Mac`.
//! Generated wiring, no crypto logic (SUPERCOP `crypto_auth` API). Fixed key and tag sizes from api.h.
//! `verify` is the trait's provided constant-time compare over `tag` (the upstream
//! `crypto_auth_verify` is not used).

use nextssl_core::{Error, Len, Mac, Params, Result, Sizes, SymmetricKey};

const KEY: usize = 16;
const TAG: usize = 8;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_ulonglong};
    extern "C" {
        #[link_name = "nextssl__pyrhash__crypto_auth"]
        pub fn auth(out: *mut u8, input: *const u8, len: c_ulonglong, k: *const u8) -> c_int;
    }
}

struct M;

impl Mac for M {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(KEY)),
            tag: Some(Len::fixed(TAG)),
            ..Sizes::NONE
        }
    }

    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(KEY).check("key", key.len())?;
        if out.len() != TAG {
            return Err(Error::InvalidLength {
                what: "tag",
                got: out.len(),
                min: TAG,
                max: TAG,
            });
        }
        // SAFETY: out is valid for TAG bytes and key for KEY bytes (both checked above); data for data.len().
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::auth(
                out.as_mut_ptr(),
                data.as_ptr(),
                data.len() as core::ffi::c_ulonglong,
                key.as_bytes().as_ptr(),
            )
        };
        if rc != 0 {
            return Err(Error::Backend("auth failed"));
        }
        Ok(())
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Mac>> {
    Ok(Box::new(M))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_verify_and_lengths() {
        let m = new(&Params::new()).unwrap();
        let key = SymmetricKey::from_bytes(&[7u8; KEY], Len::fixed(KEY)).unwrap();
        let mut t = vec![0u8; TAG];
        m.tag(&key, b"abc", &mut t).unwrap();
        let mut t2 = vec![0u8; TAG];
        m.tag(&key, b"abc", &mut t2).unwrap();
        assert_eq!(t, t2);
        assert!(m.verify(&key, b"abc", &t).unwrap());
        assert!(!m.verify(&key, b"abd", &t).unwrap());
        let mut bad = t.clone();
        bad[0] ^= 1;
        assert!(!m.verify(&key, b"abc", &bad).unwrap());
        assert!(m.tag(&key, b"abc", &mut vec![0u8; TAG + 1]).is_err());
        let short = SymmetricKey::from_bytes(&[7u8; KEY - 1], Len::fixed(KEY - 1)).unwrap();
        assert!(m.tag(&short, b"abc", &mut t).is_err());
        assert!(m.verify(&key, b"abc", &t[..TAG - 1]).is_err());
    }
}
