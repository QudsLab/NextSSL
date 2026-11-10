//! Adapter: tango642 (SUPERCOP crypto_stream) (ref) (verbatim C, symbols renamed `nextssl__tango642__*`) -> nextssl `StreamCipher`.
//! Generated wiring, no crypto logic. UNTESTED (not yet compiled). Uses the upstream crypto_stream_xor.

use nextssl_core::{Error, Len, Params, Result, Sizes, StreamCipher, SymmetricKey, Zeroizing};

const KEY: usize = 32;
const NONCE: usize = 8;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_ulonglong};
    extern "C" {
        #[link_name = "nextssl__tango642__crypto_stream_xor"]
        pub fn xor(
            out: *mut u8,
            input: *const u8,
            len: c_ulonglong,
            n: *const u8,
            k: *const u8,
        ) -> c_int;
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
        let mut out = Zeroizing::new(vec![0u8; data.len()]);
        // SAFETY: out and data are valid for data.len() bytes; key/nonce lengths checked above.
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::xor(
                out.as_mut_ptr(),
                data.as_ptr(),
                data.len() as core::ffi::c_ulonglong,
                nonce.as_ptr(),
                key.as_bytes().as_ptr(),
            )
        };
        if rc != 0 {
            return Err(Error::Backend("stream xor failed"));
        }
        data.copy_from_slice(&out);
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
            s.apply_keystream(&k, &[9u8; NONCE + 1], &mut buf),
            Err(Error::InvalidLength { .. })
        ));
    }
}
