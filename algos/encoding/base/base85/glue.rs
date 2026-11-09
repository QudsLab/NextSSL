//! Adapter: `base85` crate (RFC 1924 Base85) -> nextssl `Encoding`.
//!
//! Strict on decode: the text must be valid RFC 1924 alphabet and must re-encode to exactly the
//! input (rejects any non-canonical trailing group). Input is limited to nextssl_core::MAX_INPUT_LEN.

use nextssl_core::{Encoding, Error, Params, Result};

struct Impl;

impl Encoding for Impl {
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("data", data.len(), 0, nextssl_core::MAX_INPUT_LEN)?;
        Ok(base85::encode(data).into_bytes())
    }

    fn decode(&self, text: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("text", text.len(), 0, nextssl_core::MAX_INPUT_LEN)?;
        let s = std::str::from_utf8(text).map_err(|_| Error::InvalidInput("invalid base85"))?;
        let data = base85::decode(s).map_err(|_| Error::InvalidInput("invalid base85"))?;
        if base85::encode(&data).as_bytes() != text {
            return Err(Error::InvalidInput("non-canonical base85"));
        }
        Ok(data)
    }
}

/// Registry constructor. base85 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Encoding>> {
    Ok(Box::new(Impl))
}
