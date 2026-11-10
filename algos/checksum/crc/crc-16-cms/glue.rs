//! Adapter: `crc` crate (preset `CRC_16_CMS`, catalogue name `CRC-16/CMS`) -> nextssl `Checksum`.
//!
//! NON-CRYPTOGRAPHIC integrity check for accidental corruption only; reachable through the root API only.
//! Output: 2 byte(s), big-endian numeric value as printed in the CRC catalogue (width 16 bits).

use crc::{Crc, CRC_16_CMS};
use nextssl_core::{Checksum, Len, Params, Result, Sizes};

const ALGO: Crc<u16> = Crc::<u16>::new(&CRC_16_CMS);
const OUT: usize = 2;

struct Impl;

impl Checksum for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            out: Some(Len::fixed(OUT)),
            ..Sizes::NONE
        }
    }

    fn checksum(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(OUT).check("out", out.len())?;
        let b = ALGO.checksum(data).to_be_bytes();
        out.copy_from_slice(&b[b.len() - OUT..]);
        Ok(())
    }
}

/// Registry constructor. The preset is fixed; there are no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Checksum>> {
    Ok(Box::new(Impl))
}
