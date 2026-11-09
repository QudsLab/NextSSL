//! Adapter: `z32` crate (z-base-32, human-oriented Base32) -> nextssl `Encoding`.
//!
//! Strict on decode: the text must decode and must re-encode to exactly the input (rejects non-canonical
//! forms). The upstream decoder runs behind `catch_unwind` so a panic on hostile text becomes an error.
//! Input is limited to `nextssl_core::MAX_INPUT_LEN`.

use nextssl_core::{Encoding, Error, Params, Result};

struct Impl;

fn enc(data: &[u8]) -> Vec<u8> {
    z32::encode(data).into_bytes()
}

fn dec(text: &[u8]) -> core::result::Result<Vec<u8>, ()> {
    z32::decode(text).map_err(|_| ())
}

impl Encoding for Impl {
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("data", data.len(), 0, nextssl_core::MAX_INPUT_LEN)?;
        std::panic::catch_unwind(|| enc(data)).map_err(|_| Error::Backend("encoder failed"))
    }

    fn decode(&self, text: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("text", text.len(), 0, nextssl_core::MAX_INPUT_LEN)?;
        let data = std::panic::catch_unwind(|| dec(text))
            .map_err(|_| Error::InvalidInput("invalid z-base-32"))?
            .map_err(|()| Error::InvalidInput("invalid z-base-32"))?;
        if enc(&data) != text {
            return Err(Error::InvalidInput("non-canonical z-base-32"));
        }
        Ok(data)
    }
}

/// Registry constructor. z-base-32 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Encoding>> {
    Ok(Box::new(Impl))
}
