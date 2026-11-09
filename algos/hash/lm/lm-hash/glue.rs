//! Adapter: LM hash (LMOWFv1): uppercase the ASCII password, zero-pad to 14 bytes, split into two
//! 7-byte halves, expand each to a DES key and encrypt the constant "KGS!@#$%" (RustCrypto `des`).
//! The password is the input; it must be ASCII and at most 14 bytes (no truncation, no code-page
//! guessing). Cryptographically broken; only reachable through the root API.

use des::cipher::{Array, BlockCipherEncrypt, KeyInit};
use des::Des;
use nextssl_core::Zeroizing;
use nextssl_core::{Error, Hash, Params, Result};

const OUT_LEN: usize = 16;
const MAX_PW: usize = 14;
const MAGIC: [u8; 8] = *b"KGS!@#$%";

struct Impl;

/// 7 bytes -> 8-byte DES key (7 bits per byte, parity bit left 0; DES ignores parity).
fn expand_key(half: &[u8; 7]) -> Zeroizing<[u8; 8]> {
    let mut v: u64 = 0;
    for b in half {
        v = (v << 8) | u64::from(*b);
    }
    let mut key = Zeroizing::new([0u8; 8]);
    for (i, k) in key.iter_mut().enumerate() {
        *k = (((v >> (49 - 7 * i)) & 0x7f) as u8) << 1;
    }
    key
}

impl Hash for Impl {
    fn output_len(&self) -> usize {
        OUT_LEN
    }

    fn digest(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        if out.len() != OUT_LEN {
            return Err(Error::BadOutputLen {
                expected: OUT_LEN,
                got: out.len(),
            });
        }
        nextssl_core::check_len("password", data.len(), 0, MAX_PW)?;
        if !data.is_ascii() {
            return Err(Error::InvalidInput("LM password must be ASCII"));
        }
        let mut padded = Zeroizing::new([0u8; MAX_PW]);
        for (dst, src) in padded.iter_mut().zip(data) {
            *dst = src.to_ascii_uppercase();
        }
        for (i, half) in padded.chunks_exact(7).enumerate() {
            let mut h = [0u8; 7];
            h.copy_from_slice(half);
            let key = expand_key(&h);
            let des = Des::new_from_slice(key.as_slice()).map_err(|_| Error::Backend("DES key"))?;
            let mut block = Array::<u8, des::cipher::consts::U8>::from(MAGIC);
            des.encrypt_block(&mut block);
            out[i * 8..i * 8 + 8].copy_from_slice(block.as_slice());
        }
        Ok(())
    }
}

/// Registry constructor. This algorithm takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Hash>> {
    Ok(Box::new(Impl))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_output_length_is_refused() {
        let h = new(&Params::new()).unwrap();
        let n = h.output_len();
        let mut short = vec![0u8; n - 1];
        assert!(matches!(
            h.digest(b"abc", &mut short),
            Err(Error::BadOutputLen { .. })
        ));
        let mut long = vec![0u8; n + 1];
        assert!(matches!(
            h.digest(b"abc", &mut long),
            Err(Error::BadOutputLen { .. })
        ));
    }

    #[test]
    fn long_or_non_ascii_password_is_refused() {
        let h = new(&Params::new()).unwrap();
        let mut out = [0u8; 16];
        assert!(matches!(
            h.digest(&[b'a'; 15], &mut out),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            h.digest("caf\u{e9}".as_bytes(), &mut out),
            Err(Error::InvalidInput(_))
        ));
    }
}
