//! Adapter: RustCrypto `mgm` 0.4.6 (Multilinear Galois Mode, RFC 9058) over Magma (GOST R 34.12-2015, 64-bit block) -> nextssl `Aead`.
//! Key 32 bytes, nonce 8 bytes (the most significant bit of the first byte must be 0, RFC 9058; otherwise an error),
//! tag 8 bytes, associated data and plaintext up to MAX_INPUT_LEN (the mode's own limits are returned as errors).
//! Older dependency stack, see Cargo.toml.

use aead04::generic_array::GenericArray;
use aead04::{AeadInPlace, NewAead};
use magma07::Magma;
use mgm::Mgm;
use nextssl_core::{
    check_len, Aead, Error, Len, Params, Result, Sizes, SymmetricKey, Zeroizing, MAX_INPUT_LEN,
};

const KEY_LEN: usize = 32;
const NB: usize = 8;

type Inner = Mgm<Magma>;

struct Impl;

impl Impl {
    fn init(&self, key: &SymmetricKey, nonce: &[u8]) -> Result<Inner> {
        Len::fixed(KEY_LEN).check("key", key.len())?;
        Len::fixed(NB).check("nonce", nonce.len())?;
        if nonce[0] >> 7 != 0 {
            return Err(Error::InvalidInput(
                "mgm: the most significant bit of the nonce must be 0",
            ));
        }
        Ok(Inner::new(GenericArray::from_slice(key.as_bytes())))
    }
}

impl Aead for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(KEY_LEN)),
            nonce: Some(Len::fixed(NB)),
            tag: Some(Len::fixed(NB)),
            ..Sizes::NONE
        }
    }

    fn seal(&self, key: &SymmetricKey, nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        check_len("plaintext", pt.len(), 0, MAX_INPUT_LEN)?;
        check_len("aad", aad.len(), 0, MAX_INPUT_LEN)?;
        let c = self.init(key, nonce)?;
        let mut buf = pt.to_vec();
        let tag = c
            .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, &mut buf)
            .map_err(|_| Error::InvalidInput("mgm: input not allowed by the mode"))?;
        buf.extend_from_slice(tag.as_slice());
        Ok(buf)
    }

    fn open(
        &self,
        key: &SymmetricKey,
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        check_len("ciphertext", ct.len(), NB, MAX_INPUT_LEN + NB)?;
        check_len("aad", aad.len(), 0, MAX_INPUT_LEN)?;
        let c = self.init(key, nonce)?;
        let (body, tag) = ct.split_at(ct.len() - NB);
        let mut buf = Zeroizing::new(body.to_vec());
        c.decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            aad,
            &mut buf,
            GenericArray::from_slice(tag),
        )
        .map_err(|_| Error::AuthenticationFailed)?;
        Ok(buf)
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Aead>> {
    Ok(Box::new(Impl))
}
