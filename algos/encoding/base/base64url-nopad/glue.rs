//! Adapter: `data-encoding` BASE64URL_NOPAD (RFC 4648 section 5 without padding, as used by JOSE) -> nextssl `Encoding`.
//!
//! Strict on decode: the text must decode and must re-encode to exactly the input (rejects non-canonical forms).
//! Input is limited to `nextssl_core::MAX_INPUT_LEN`.

use data_encoding::BASE64URL_NOPAD;
use nextssl_core::{Encoding, Error, Params, Result};

struct Impl;

fn enc(data: &[u8]) -> Vec<u8> {
    BASE64URL_NOPAD.encode(data).into_bytes()
}

fn dec(text: &[u8]) -> core::result::Result<Vec<u8>, ()> {
    BASE64URL_NOPAD.decode(text).map_err(|_| ())
}

impl Encoding for Impl {
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("data", data.len(), 0, nextssl_core::MAX_INPUT_LEN)?;
        Ok(enc(data))
    }

    fn decode(&self, text: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("text", text.len(), 0, nextssl_core::MAX_INPUT_LEN)?;
        let data = dec(text).map_err(|()| Error::InvalidInput("invalid base64url-nopad"))?;
        if enc(&data) != text {
            return Err(Error::InvalidInput("non-canonical base64url-nopad"));
        }
        Ok(data)
    }
}

/// Registry constructor. base64url-nopad takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Encoding>> {
    Ok(Box::new(Impl))
}
