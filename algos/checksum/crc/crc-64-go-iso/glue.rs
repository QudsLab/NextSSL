//! Adapter: `crc` crate (preset `CRC_64_GO_ISO`, catalogue name `CRC-64/GO-ISO`) -> nextssl `Checksum`.
//!
//! NON-CRYPTOGRAPHIC integrity check for accidental corruption only; reachable through the root API only.
//! Output: 8 byte(s), big-endian numeric value as printed in the CRC catalogue (width 64 bits).

use crc::{Crc, CRC_64_GO_ISO};
use nextssl_core::{Checksum, Len, Params, Result, Sizes};

const ALGO: Crc<u64> = Crc::<u64>::new(&CRC_64_GO_ISO);
const OUT: usize = 8;

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
