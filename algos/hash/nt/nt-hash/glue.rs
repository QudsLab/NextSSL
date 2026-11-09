//! Adapter: NT hash (NTOWFv1, MS-NLMP 3.3.1) = MD4(UTF-16LE(password)).
//! The password is the input as UTF-8 bytes; the UTF-16LE conversion is the only logic here and
//! the digest is the RustCrypto `md4` crate. Input that is not valid UTF-8 is an error (never
//! lossily converted). Broken tier: only reachable through the root API.

use md4::{Digest, Md4};
use nextssl_core::Zeroizing;
use nextssl_core::{Error, Hash, Params, Result};

const OUT_LEN: usize = 16;

struct Impl;

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
        let text = core::str::from_utf8(data)
            .map_err(|_| Error::InvalidInput("password must be valid UTF-8"))?;
        let mut utf16le = Zeroizing::new(Vec::with_capacity(data.len() * 2));
        for unit in text.encode_utf16() {
            utf16le.extend_from_slice(&unit.to_le_bytes());
        }
        out.copy_from_slice(Md4::digest(utf16le.as_slice()).as_slice());
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
    fn invalid_utf8_is_refused() {
        let h = new(&Params::new()).unwrap();
        let mut out = [0u8; 16];
        assert!(matches!(
            h.digest(&[0xff, 0xfe], &mut out),
            Err(Error::InvalidInput(_))
        ));
    }
}
