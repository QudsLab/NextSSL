//! `hmac(<digest>)` and `cmac(<cipher>)`: upstream generic MAC crates instantiated with the
//! digest or cipher type chosen by name. Same limits as the concrete `hmac-*` / `aes-cmac` ids.

use cbc::cipher::{BlockSizeUser, KeySizeUser};
use cmac::Cmac;
use hmac::digest::Digest;
use hmac::{Hmac, Mac as _};
use nextssl_core::{Error, Len, Mac, Result, Sizes, SymmetricKey, Zeroize};

const KEY_MIN: usize = 1;
const KEY_MAX: usize = 268_435_456;
const TAG_MIN: usize = 16;

/// Output length of the digest in bytes.
pub fn digest_len(name: &str) -> Result<usize> {
    with_digest!(name, D => Ok(<D as Digest>::output_size()))
}

/// `(block length, key length)` of the cipher in bytes.
pub fn cipher_dims(name: &str) -> Result<(usize, usize)> {
    with_cipher!(name, C => Ok((<C as BlockSizeUser>::block_size(), <C as KeySizeUser>::key_size())))
}

pub struct HmacMac {
    digest: &'static str,
    out: usize,
}

impl HmacMac {
    pub fn new(digest: &'static str) -> Result<Self> {
        Ok(Self {
            digest,
            out: digest_len(digest)?,
        })
    }
}

impl Mac for HmacMac {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(KEY_MIN, KEY_MAX)),
            tag: Some(Len::range(TAG_MIN.min(self.out), self.out)),
            ..Sizes::NONE
        }
    }

    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::range(KEY_MIN, KEY_MAX).check("key", key.len())?;
        Len::range(TAG_MIN.min(self.out), self.out).check("tag", out.len())?;
        with_digest!(self.digest, D => {
            let mut mac = <Hmac<D> as hmac::KeyInit>::new_from_slice(key.as_bytes())
                .map_err(|_| Error::Backend("hmac key setup"))?;
            mac.update(data);
            let mut full = mac.finalize().into_bytes();
            out.copy_from_slice(&full.as_slice()[..out.len()]);
            full.as_mut_slice().zeroize();
            Ok(())
        })
    }
}

pub struct CmacMac {
    cipher: &'static str,
    block: usize,
    key: usize,
}

impl CmacMac {
    pub fn new(cipher: &'static str) -> Result<Self> {
        let (block, key) = cipher_dims(cipher)?;
        Ok(Self { cipher, block, key })
    }
}

impl Mac for CmacMac {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(self.key)),
            tag: Some(Len::fixed(self.block)),
            ..Sizes::NONE
        }
    }

    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(self.key).check("key", key.len())?;
        Len::fixed(self.block).check("tag", out.len())?;
        with_cipher!(self.cipher, C => {
            let mut mac = <Cmac<C> as cmac::KeyInit>::new_from_slice(key.as_bytes())
                .map_err(|_| Error::Backend("cmac key setup"))?;
            mac.update(data);
            let mut full = mac.finalize().into_bytes();
            out.copy_from_slice(full.as_slice());
            full.as_mut_slice().zeroize();
            Ok(())
        })
    }
}
