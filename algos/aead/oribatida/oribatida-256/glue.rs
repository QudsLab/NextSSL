//! Adapter: oribatida (.) (verbatim C, symbols renamed `nextssl__oribatida_256__*`) -> nextssl `Aead`.
//! Generated wiring, no crypto logic. UNTESTED (not yet compiled). Output of `seal` is
//! `ciphertext || tag`; the secret message number (nsec) is not used (always NULL).

use nextssl_core::{Aead, Error, Len, Params, Result, Sizes, SymmetricKey, Zeroizing};

const KEY: usize = 16;
const NONCE: usize = 16;
const TAG: usize = 16;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_ulonglong};
    extern "C" {
        #[link_name = "nextssl__oribatida_256__oribatida_256_aead_encrypt"]
        pub fn seal(
            c: *mut u8,
            clen: *mut c_ulonglong,
            m: *const u8,
            mlen: c_ulonglong,
            ad: *const u8,
            adlen: c_ulonglong,
            nsec: *const u8,
            npub: *const u8,
            k: *const u8,
        ) -> c_int;
        #[link_name = "nextssl__oribatida_256__oribatida_256_aead_decrypt"]
        pub fn open(
            m: *mut u8,
            mlen: *mut c_ulonglong,
            nsec: *mut u8,
            c: *const u8,
            clen: c_ulonglong,
            ad: *const u8,
            adlen: c_ulonglong,
            npub: *const u8,
            k: *const u8,
        ) -> c_int;
    }
}

struct A;

impl A {
    fn check(&self, key: &SymmetricKey, nonce: &[u8]) -> Result<()> {
        Len::fixed(KEY).check("key", key.len())?;
        Len::fixed(NONCE).check("nonce", nonce.len())
    }
}

impl Aead for A {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(KEY)),
            nonce: Some(Len::fixed(NONCE)),
            tag: Some(Len::fixed(TAG)),
            ..Sizes::NONE
        }
    }

    fn seal(&self, key: &SymmetricKey, nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        self.check(key, nonce)?;
        let mut out = vec![0u8; pt.len() + TAG];
        let mut clen: core::ffi::c_ulonglong = 0;
        // SAFETY: out has room for plaintext + tag (all the callee writes); every other pointer comes
        // from a live slice whose length is passed alongside; key/nonce lengths were checked above.
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::seal(
                out.as_mut_ptr(),
                &mut clen,
                pt.as_ptr(),
                pt.len() as core::ffi::c_ulonglong,
                aad.as_ptr(),
                aad.len() as core::ffi::c_ulonglong,
                core::ptr::null(),
                nonce.as_ptr(),
                key.as_bytes().as_ptr(),
            )
        };
        if rc != 0 || clen as usize != out.len() {
            return Err(Error::Backend("seal failed"));
        }
        Ok(out)
    }

    fn open(
        &self,
        key: &SymmetricKey,
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.check(key, nonce)?;
        Len::range(TAG, usize::MAX).check("ciphertext", ct.len())?;
        let mut out = Zeroizing::new(vec![0u8; ct.len()]);
        let mut mlen: core::ffi::c_ulonglong = 0;
        // SAFETY: out holds ct.len() bytes, more than the callee writes (ct.len() - TAG); the other
        // pointers come from live slices with their lengths; key/nonce lengths were checked above.
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::open(
                out.as_mut_ptr(),
                &mut mlen,
                core::ptr::null_mut(),
                ct.as_ptr(),
                ct.len() as core::ffi::c_ulonglong,
                aad.as_ptr(),
                aad.len() as core::ffi::c_ulonglong,
                nonce.as_ptr(),
                key.as_bytes().as_ptr(),
            )
        };
        if rc != 0 || mlen as usize != ct.len() - TAG {
            out.fill(0);
            return Err(Error::AuthenticationFailed);
        }
        out.truncate(mlen as usize);
        Ok(out)
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Aead>> {
    Ok(Box::new(A))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: usize) -> SymmetricKey {
        SymmetricKey::from_bytes(&vec![7u8; n], Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn roundtrip_tamper_and_lengths() {
        let a = new(&Params::new()).unwrap();
        let k = key(KEY);
        let n = vec![3u8; NONCE];
        let ct = a.seal(&k, &n, b"aad", b"hello world").unwrap();
        assert_eq!(ct.len(), 11 + TAG);
        assert_eq!(&a.open(&k, &n, b"aad", &ct).unwrap()[..], b"hello world");
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_eq!(a.open(&k, &n, b"aad", &bad).unwrap_err(), Error::AuthenticationFailed);
        assert!(matches!(a.seal(&key(KEY + 1), &n, b"", b"x"), Err(Error::InvalidLength { .. })));
        assert!(matches!(a.seal(&k, &vec![3u8; NONCE + 1], b"", b"x"), Err(Error::InvalidLength { .. })));
    }
}
