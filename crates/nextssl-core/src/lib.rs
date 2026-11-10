//! NextSSL core: shared error type, typed parameters, tiers, key types and algorithm traits.
//!
//! `no_std` + `alloc`. Every length is validated and reported; nothing is truncated.
//! Start with `API.md` in this crate when importing an algorithm.

#![no_std]

extern crate alloc;

mod error;
pub mod keys;
mod len;
mod params;
pub mod phc;
mod tier;
mod traits;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use error::{Error, Result};
pub use keys::{
    ct_eq, Ciphertext, PrivateKey, PublicKey, Seed, Share, SharedSecret, Signature, StatefulKey,
    SymmetricKey,
};
pub use len::{Len, Sizes};
pub use params::{ParamSpec, ParamType, Params, Value};
pub use tier::{Kind, Status, Tier};
pub use traits::{
    check_party, check_threshold, Aead, BlockCipher, BlockMode, Checksum, Drbg, Encoding,
    EntropySource, Hash, He, HeKeys, HeOp, Kdf, Kem, Kex, KeyedBlockCipher, Mac, Mode, Pake,
    PakeRole, PakeState, PakeStep, Pke, Pow, Prng, PwHash, Sign, StatefulSign, StreamCipher, Threshold,
    ThresholdOp, ThresholdSession, ThresholdState, ThresholdStep, Vdf, Xof, Zk, MAX_INPUT_LEN,
};
pub use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Checks `got` is within `min..=max`.
pub fn check_len(what: &'static str, got: usize, min: usize, max: usize) -> Result<()> {
    if got < min || got > max {
        Err(Error::InvalidLength {
            what,
            got,
            min,
            max,
        })
    } else {
        Ok(())
    }
}
