//! Deterministic entropy for KAT runners and tests. Compiled only with `cfg(test)` or the
//! `testing` cargo feature, which no release build enables. It is a separate type: nothing
//! can swap it in for the OS RNG at run time.

use crate::{EntropySource, Error, Result};
use alloc::vec::Vec;
use zeroize::Zeroize;

/// Hands out a fixed byte string, in order. Running dry is an error, so a KAT that consumes
/// a different amount of randomness than expected fails loudly.
pub struct FixedEntropy {
    bytes: Vec<u8>,
    pos: usize,
}

impl FixedEntropy {
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            pos: 0,
        }
    }

    /// Bytes not consumed yet.
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
}

impl Drop for FixedEntropy {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl EntropySource for FixedEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        if out.len() > self.remaining() {
            return Err(Error::EntropyFailure("fixed entropy exhausted"));
        }
        out.copy_from_slice(&self.bytes[self.pos..self.pos + out.len()]);
        self.pos += out.len();
        Ok(())
    }
}
