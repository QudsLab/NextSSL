//! Adapter: HKDF-Expand only (RFC 5869 section 2.3) -> nextssl `Kdf`, generic over the closed
//! `hash` enum parameter (default `sha256`).
//!
//! Shape: `derive(ikm, salt, info, out)` treats `ikm` as the PRK (at least HashLen bytes) and
//! computes OKM = HKDF-Expand(PRK, info, out.len()). Expand has no salt: `salt` must be EMPTY
//! (declared `salt = 0`) and a non-empty one is an error, never ignored. Output
//! 1..=255*HashLen bytes. `expand` is the same operation; `extract` is `Unsupported`.
#![allow(dead_code)]

use hkdf::Hkdf;
use nextssl_core::{
    Error, Kdf, Len, ParamSpec, ParamType, Params, Result, Sizes, SymmetricKey, Zeroize,
};
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

const IKM_MAX: usize = 1 << 28;

/// Mirror of `[params.hash]` in `algo.toml`; the default is index 0.
const HASHES: &[&str] = &[
    "sha256",
    "sha384",
    "sha512",
    "sha224",
    "sha512-224",
    "sha512-256",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
];

const SPECS: [ParamSpec; 1] = [ParamSpec {
    name: "hash",
    ty: ParamType::Enum(HASHES),
    min: 0,
    max: 0,
    required: false,
    default: Some(0),
}];

#[derive(Clone, Copy)]
enum H {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl H {
    fn parse(s: &str) -> Option<H> {
        Some(match s {
            "sha224" => H::Sha224,
            "sha256" => H::Sha256,
            "sha384" => H::Sha384,
            "sha512" => H::Sha512,
            "sha512-224" => H::Sha512_224,
            "sha512-256" => H::Sha512_256,
            "sha3-224" => H::Sha3_224,
            "sha3-256" => H::Sha3_256,
            "sha3-384" => H::Sha3_384,
            "sha3-512" => H::Sha3_512,
            _ => return None,
        })
    }

    /// HashLen in bytes.
    fn len(self) -> usize {
        match self {
            H::Sha224 | H::Sha512_224 | H::Sha3_224 => 28,
            H::Sha256 | H::Sha512_256 | H::Sha3_256 => 32,
            H::Sha384 | H::Sha3_384 => 48,
            H::Sha512 | H::Sha3_512 => 64,
        }
    }

    /// Largest HKDF output: 255 * HashLen.
    fn max_out(self) -> usize {
        255 * self.len()
    }
}

/// Runs `$body` with the digest type bound to `$t`.
macro_rules! with_hash {
    ($h:expr, $t:ident => $body:expr) => {
        match $h {
            H::Sha224 => {
                type $t = Sha224;
                $body
            }
            H::Sha256 => {
                type $t = Sha256;
                $body
            }
            H::Sha384 => {
                type $t = Sha384;
                $body
            }
            H::Sha512 => {
                type $t = Sha512;
                $body
            }
            H::Sha512_224 => {
                type $t = Sha512_224;
                $body
            }
            H::Sha512_256 => {
                type $t = Sha512_256;
                $body
            }
            H::Sha3_224 => {
                type $t = Sha3_224;
                $body
            }
            H::Sha3_256 => {
                type $t = Sha3_256;
                $body
            }
            H::Sha3_384 => {
                type $t = Sha3_384;
                $body
            }
            H::Sha3_512 => {
                type $t = Sha3_512;
                $body
            }
        }
    };
}

fn parse_hash(params: &Params) -> Result<H> {
    let v = params.validate(&SPECS)?;
    let name = v.get_str("hash").ok_or(Error::ParamMissing("hash"))?;
    H::parse(name).ok_or(Error::ParamOutOfRange("hash"))
}

/// RFC 5869 section 2.2. Returns the PRK (HashLen bytes) as a key.
fn extract_prk(h: H, ikm: &SymmetricKey, salt: &[u8]) -> Result<SymmetricKey> {
    Len::range(1, IKM_MAX).check("ikm", ikm.len())?;
    with_hash!(h, D => {
        let (mut prk, _hk) = Hkdf::<D>::extract(Some(salt), ikm.as_bytes());
        let key = SymmetricKey::from_bytes(prk.as_slice(), Len::fixed(h.len()));
        prk.as_mut_slice().zeroize();
        key
    })
}

/// RFC 5869 section 2.3. `prk` must be at least HashLen bytes; `out` 1..=255*HashLen.
fn expand_okm(h: H, prk: &SymmetricKey, info: &[u8], out: &mut [u8]) -> Result<()> {
    Len::range(h.len(), IKM_MAX).check("prk", prk.len())?;
    Len::range(1, h.max_out()).check("out", out.len())?;
    with_hash!(h, D => {
        let hk = Hkdf::<D>::from_prk(prk.as_bytes())
            .map_err(|_| Error::Backend("hkdf prk setup"))?;
        hk.expand(info, out).map_err(|_| Error::InvalidLength {
            what: "out",
            got: out.len(),
            min: 1,
            max: h.max_out(),
        })
    })
}

struct Impl {
    hash: H,
}

impl Kdf for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(self.hash.len(), IKM_MAX)),
            out: Some(Len::range(1, self.hash.max_out())),
            salt: Some(Len::fixed(0)),
            ..Sizes::NONE
        }
    }

    fn derive(&self, ikm: &SymmetricKey, salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(0).check("salt", salt.len())?;
        expand_okm(self.hash, ikm, info, out)
    }

    fn expand(&self, prk: &SymmetricKey, info: &[u8], out: &mut [u8]) -> Result<()> {
        expand_okm(self.hash, prk, info, out)
    }
}

/// Registry constructor. Parameter `hash` (enum, default `sha256`).
pub fn new(params: &Params) -> Result<Box<dyn Kdf>> {
    Ok(Box::new(Impl {
        hash: parse_hash(params)?,
    }))
}

#[cfg(test)]
mod tests {

    use super::*;
    use nextssl_core::Value;
    use serde_json::Value as J;
    use std::path::PathBuf;

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd hex length");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
            .collect()
    }

    fn load(name: &str) -> J {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("kat")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    fn key(bytes: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(bytes, Len::range(0, usize::MAX)).unwrap()
    }

    fn kdf(hash: &str) -> Box<dyn Kdf> {
        new(&Params::new().with("hash", Value::Str(hash.into()))).unwrap()
    }

    #[test]
    fn unknown_hash_is_an_error_not_a_fallback() {
        for bad in ["md5", "sha1", "SHA256", ""] {
            let r = new(&Params::new().with("hash", Value::Str(bad.into())));
            assert!(matches!(r, Err(Error::ParamOutOfRange("hash"))), "{bad}");
        }
    }
    #[test]
    fn known_answers() {
        let doc = load("vectors.json");
        assert_eq!(doc["algorithm"], "hkdf-expand");
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let id = v["id"].as_str().unwrap();
            let h = kdf(v["hash"].as_str().unwrap());
            let prk = key(&unhex(v["prk_hex"].as_str().unwrap()));
            let info = unhex(v["info_hex"].as_str().unwrap());
            let want = unhex(v["out_hex"].as_str().unwrap());
            let mut got = vec![0u8; want.len()];
            h.derive(&prk, b"", &info, &mut got).unwrap();
            assert_eq!(got, want, "derive {id}");
            let mut got2 = vec![0u8; want.len()];
            h.expand(&prk, &info, &mut got2).unwrap();
            assert_eq!(got2, want, "expand {id}");
            n += 1;
        }
        assert_eq!(n, 53);
    }

    #[test]
    fn strict_shape() {
        let h = kdf("sha256");
        let prk = key(&[7u8; 32]);
        let mut out = [0u8; 42];
        h.derive(&prk, b"", b"i", &mut out).unwrap();
        // salt is not part of Expand: refused, not ignored
        assert!(matches!(
            h.derive(&prk, b"s", b"i", &mut out),
            Err(Error::InvalidLength { what: "salt", .. })
        ));
        // PRK shorter than HashLen
        assert!(matches!(
            h.derive(&key(&[7u8; 31]), b"", b"i", &mut out),
            Err(Error::InvalidLength { .. })
        ));
        for bad in [0usize, 255 * 32 + 1] {
            assert!(matches!(
                h.derive(&prk, b"", b"i", &mut vec![0u8; bad]),
                Err(Error::InvalidLength { .. })
            ));
        }
        h.derive(&prk, b"", b"i", &mut vec![0u8; 255 * 32]).unwrap();
        assert_eq!(h.extract(&prk, b"").unwrap_err(), Error::Unsupported);
    }
}
