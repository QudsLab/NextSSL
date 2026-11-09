//! Adapter: HC-128 (Crypto++ HC128::Encryption) (verbatim C, symbols renamed `nextssl__hc128__*`) -> nextssl `StreamCipher`.
//! Generated wiring, no crypto logic. UNTESTED (not yet compiled). Uses the Crypto++ HC128 keystream (zeros encrypted) and XORs in glue.

use nextssl_core::{Error, Len, Params, Result, Sizes, StreamCipher, SymmetricKey, Zeroizing};

const KEY: usize = 16;
const NONCE: usize = 16;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_ulonglong};
    extern "C" {
        #[link_name = "nextssl__hc128__shim_stream"]
        pub fn stream(out: *mut u8, len: c_ulonglong, n: *const u8, k: *const u8) -> c_int;
    }
}

struct S;

impl StreamCipher for S {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(KEY)),
            nonce: Some(Len::fixed(NONCE)),
            ..Sizes::NONE
        }
    }

    fn apply_keystream(&self, key: &SymmetricKey, nonce: &[u8], data: &mut [u8]) -> Result<()> {
        Len::fixed(KEY).check("key", key.len())?;
        Len::fixed(NONCE).check("nonce", nonce.len())?;
        if data.is_empty() {
            return Ok(());
        }
        let mut ks = Zeroizing::new(vec![0u8; data.len()]);
        // SAFETY: ks is valid for data.len() bytes; key/nonce lengths checked above.
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::stream(
                ks.as_mut_ptr(),
                data.len() as core::ffi::c_ulonglong,
                nonce.as_ptr(),
                key.as_bytes().as_ptr(),
            )
        };
        if rc != 0 {
            return Err(Error::Backend("stream failed"));
        }
        for (d, k) in data.iter_mut().zip(ks.iter()) {
            *d ^= *k;
        }
        Ok(())
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn StreamCipher>> {
    Ok(Box::new(S))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn involution_and_lengths() {
        let s = new(&Params::new()).unwrap();
        let k = SymmetricKey::from_bytes(&vec![5u8; KEY], Len::range(0, usize::MAX)).unwrap();
        let n = vec![9u8; NONCE];
        let mut buf = b"The quick brown fox".to_vec();
        let orig = buf.clone();
        s.apply_keystream(&k, &n, &mut buf).unwrap();
        assert_ne!(buf, orig);
        s.apply_keystream(&k, &n, &mut buf).unwrap();
        assert_eq!(buf, orig);
        assert!(matches!(
            s.apply_keystream(&k, &vec![9u8; NONCE + 1], &mut buf),
            Err(Error::InvalidLength { .. })
        ));
    }
}
