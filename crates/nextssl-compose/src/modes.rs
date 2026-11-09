//! `cbc(<cipher>)`, `ecb(<cipher>)`, `cfb(<cipher>)`: the upstream `cbc`, `ecb` and `cfb-mode`
//! crates over the block cipher chosen by name. Same rules as the concrete `aes-*-cbc` ids:
//! `padding` is `none` (default; data must be a block multiple) or `pkcs7` for CBC and ECB.
//! CFB is a stream mode (no padding param). These give confidentiality only.

use crate::mac::cipher_dims;
use cbc::cipher::block_padding::{NoPadding, Pkcs7};
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit};
use nextssl_core::{
    BlockMode, Error, Len, ParamSpec, ParamType, Params, Result, Sizes, SymmetricKey, Zeroizing,
};

const PADDINGS: &[&str] = &["none", "pkcs7"];

pub const PADDING_PARAM: [ParamSpec; 1] = [ParamSpec {
    name: "padding",
    ty: ParamType::Enum(PADDINGS),
    min: 0,
    max: 0,
    required: false,
    default: Some(0),
}];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Which {
    Cbc,
    Ecb,
    Cfb,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Padding {
    None,
    Pkcs7,
}

pub struct CipherMode {
    which: Which,
    cipher: &'static str,
    block: usize,
    key: usize,
    padding: Padding,
}

impl CipherMode {
    pub fn new(which: Which, cipher: &'static str, params: &Params) -> Result<Self> {
        let specs: &[ParamSpec] = if which == Which::Cfb {
            &[]
        } else {
            &PADDING_PARAM
        };
        let p = params.validate(specs)?;
        let padding = match p.get_str("padding") {
            None | Some("none") => Padding::None,
            Some("pkcs7") => Padding::Pkcs7,
            Some(_) => return Err(Error::ParamOutOfRange("padding")),
        };
        let (block, key) = cipher_dims(cipher)?;
        Ok(Self {
            which,
            cipher,
            block,
            key,
            padding,
        })
    }

    fn nonce_len(&self) -> usize {
        if self.which == Which::Ecb {
            0
        } else {
            self.block
        }
    }

    fn check(&self, key: &SymmetricKey, nonce: &[u8]) -> Result<()> {
        Len::fixed(self.key).check("key", key.len())?;
        Len::fixed(self.nonce_len()).check("nonce", nonce.len())
    }

    fn check_block_multiple(&self, len: usize) -> Result<()> {
        if self.padding == Padding::None && self.which != Which::Cfb && len % self.block != 0 {
            return Err(Error::InvalidInput(
                "data is not a multiple of the block size (padding = none)",
            ));
        }
        Ok(())
    }
}

impl BlockMode for CipherMode {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(self.key)),
            nonce: Some(Len::fixed(self.nonce_len())),
            block: Some(Len::fixed(self.block)),
            ..Sizes::NONE
        }
    }

    fn encrypt(&self, key: &SymmetricKey, nonce: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        self.check(key, nonce)?;
        self.check_block_multiple(pt.len())?;
        let k = key.as_bytes();
        match self.which {
            Which::Cbc => with_cipher!(self.cipher, C => {
                let e = cbc::Encryptor::<C>::new_from_slices(k, nonce)
                    .map_err(|_| Error::Backend("cbc key/iv setup"))?;
                Ok(match self.padding {
                    Padding::None => e.encrypt_padded_vec::<NoPadding>(pt),
                    Padding::Pkcs7 => e.encrypt_padded_vec::<Pkcs7>(pt),
                })
            }),
            Which::Ecb => with_cipher!(self.cipher, C => {
                let e = ecb::Encryptor::<C>::new_from_slice(k)
                    .map_err(|_| Error::Backend("ecb key setup"))?;
                Ok(match self.padding {
                    Padding::None => e.encrypt_padded_vec::<NoPadding>(pt),
                    Padding::Pkcs7 => e.encrypt_padded_vec::<Pkcs7>(pt),
                })
            }),
            Which::Cfb => with_cipher!(self.cipher, C => {
                let mut e = cfb_mode::BufEncryptor::<C>::new_from_slices(k, nonce)
                    .map_err(|_| Error::Backend("cfb key/iv setup"))?;
                let mut buf = pt.to_vec();
                e.encrypt(&mut buf);
                Ok(buf)
            }),
        }
    }

    fn decrypt(&self, key: &SymmetricKey, nonce: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.check(key, nonce)?;
        if self.which != Which::Cfb && ct.len() % self.block != 0 {
            return Err(Error::InvalidInput(
                "ciphertext is not a whole number of blocks",
            ));
        }
        let k = key.as_bytes();
        let mut buf = Zeroizing::new(ct.to_vec());
        let n = match self.which {
            Which::Cbc => with_cipher!(self.cipher, C => {
                let d = cbc::Decryptor::<C>::new_from_slices(k, nonce)
                    .map_err(|_| Error::Backend("cbc key/iv setup"))?;
                match self.padding {
                    Padding::None => d.decrypt_padded::<NoPadding>(&mut buf).map(|b| b.len()),
                    Padding::Pkcs7 => d.decrypt_padded::<Pkcs7>(&mut buf).map(|b| b.len()),
                }
                .map_err(|_| Error::InvalidInput("cbc: invalid padding or length"))
            })?,
            Which::Ecb => with_cipher!(self.cipher, C => {
                let d = ecb::Decryptor::<C>::new_from_slice(k)
                    .map_err(|_| Error::Backend("ecb key setup"))?;
                match self.padding {
                    Padding::None => d.decrypt_padded::<NoPadding>(&mut buf).map(|b| b.len()),
                    Padding::Pkcs7 => d.decrypt_padded::<Pkcs7>(&mut buf).map(|b| b.len()),
                }
                .map_err(|_| Error::InvalidInput("ecb: invalid padding or length"))
            })?,
            Which::Cfb => with_cipher!(self.cipher, C => {
                let mut d = cfb_mode::BufDecryptor::<C>::new_from_slices(k, nonce)
                    .map_err(|_| Error::Backend("cfb key/iv setup"))?;
                d.decrypt(&mut buf);
                Ok(buf.len())
            })?,
        };
        buf.truncate(n);
        Ok(buf)
    }
}
