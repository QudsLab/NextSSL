//! Adapter: `crc` crate (preset `CRC_30_CDMA`, catalogue name `CRC-30/CDMA`) -> nextssl `Checksum`.
//!
//! NON-CRYPTOGRAPHIC integrity check for accidental corruption only; reachable through the root API only.
//! Output: 4 byte(s), big-endian numeric value as printed in the CRC catalogue (width 30 bits).

use crc::{Crc, CRC_30_CDMA};
use nextssl_core::{Checksum, Len, Params, Result, Sizes};

const ALGO: Crc<u32> = Crc::<u32>::new(&CRC_30_CDMA);
const OUT: usize = 4;

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
