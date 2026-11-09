//! Adapter: itzmeanjan `turboshake` (turboshake256, RFC 9861 / ia.cr 2023/342) -> nextssl `Xof`.
//! Domain separation byte is the default 0x1F (the upstream takes it as a const generic, so it is not a parameter).
//! The input is absorbed in one call, `out` is squeezed in one call; `out` must be non-empty.

use nextssl_core::{Error, Len, Params, Result, Xof};
use turboshake::TurboShake256;

struct Impl;

impl Xof for Impl {
    fn squeeze(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::range(1, usize::MAX).check("out", out.len())?;
        let mut t = TurboShake256::default();
        t.absorb(data).map_err(|_| Error::Backend("turboshake absorb"))?;
        t.finalize::<{ TurboShake256::DEFAULT_DOMAIN_SEPARATOR }>()
            .map_err(|_| Error::Backend("turboshake finalize"))?;
        t.squeeze(out).map_err(|_| Error::Backend("turboshake squeeze"))
    }
}

/// Registry constructor. TurboSHAKE takes no parameters here.
pub fn new(_params: &Params) -> Result<Box<dyn Xof>> {
    Ok(Box::new(Impl))
}
