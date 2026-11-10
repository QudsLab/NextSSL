//! Adapter: RFC 9380 P521_XMD:SHA-512_SSWU_RO_ / _NU_ (`hash2curve` 0.14 + p521 0.14, RustCrypto) -> nextssl `HashToCurve`.
//! Output: SEC1 compressed point (67 bytes). The domain separation tag must be 1..=255 bytes;
//! an empty or longer tag is an error (never hashed down, never defaulted).

use hash2curve::GroupDigest;
use nextssl_core::{Error, HashToCurve, Len, Params, Result, Sizes};
use p521::elliptic_curve::sec1::ToSec1Point;

const OUT: usize = 67;
const DST: Len = Len::range(1, 255);

struct Impl;

fn encode(p: p521::ProjectivePoint) -> Vec<u8> {
    p.to_affine().to_sec1_point(true).as_bytes().to_vec()
}

impl HashToCurve for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            out: Some(Len::fixed(OUT)),
            ..Sizes::NONE
        }
    }

    fn hash(&self, msg: &[u8], dst: &[u8]) -> Result<Vec<u8>> {
        DST.check("dst", dst.len())?;
        let p = <p521::NistP521 as GroupDigest>::hash_from_bytes(&[msg], &[dst])
            .map_err(|_| Error::Backend("hash_to_curve"))?;
        Ok(encode(p))
    }

    fn encode(&self, msg: &[u8], dst: &[u8]) -> Result<Vec<u8>> {
        DST.check("dst", dst.len())?;
        let p = <p521::NistP521 as GroupDigest>::encode_from_bytes(&[msg], &[dst])
            .map_err(|_| Error::Backend("encode_to_curve"))?;
        Ok(encode(p))
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn HashToCurve>> {
    Ok(Box::new(Impl))
}
