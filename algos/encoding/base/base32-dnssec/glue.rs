//! Adapter: `data-encoding` BASE32_DNSSEC (base32hex lowercase without padding, RFC 5155 NSEC3) -> nextssl `Encoding`.
//!
//! Strict on decode: the text must decode and must re-encode to exactly the input (rejects non-canonical forms).
//! Input is limited to `nextssl_core::MAX_INPUT_LEN`.

use data_encoding::BASE32_DNSSEC;
use nextssl_core::{Encoding, Error, Params, Result};

struct Impl;

fn enc(data: &[u8]) -> Vec<u8> {
    BASE32_DNSSEC.encode(data).into_bytes()
}

fn dec(text: &[u8]) -> core::result::Result<Vec<u8>, ()> {
    BASE32_DNSSEC.decode(text).map_err(|_| ())
}

impl Encoding for Impl {
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("data", data.len(), 0, nextssl_core::MAX_INPUT_LEN)?;
        Ok(enc(data))
    }

    fn decode(&self, text: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("text", text.len(), 0, nextssl_core::MAX_INPUT_LEN)?;
        let data = dec(text).map_err(|()| Error::InvalidInput("invalid base32-dnssec"))?;
        if enc(&data) != text {
            return Err(Error::InvalidInput("non-canonical base32-dnssec"));
        }
        Ok(data)
    }
}

/// Registry constructor. base32-dnssec takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Encoding>> {
    Ok(Box::new(Impl))
}
