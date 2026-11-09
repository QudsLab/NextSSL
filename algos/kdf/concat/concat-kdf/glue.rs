//! Adapter: RustCrypto `concat-kdf` (NIST SP 800-56A section 5.8.1 Concatenation KDF = SP 800-56C
//! rev.2 one-step KDF with a hash, a.k.a. SSKDF-hash) -> nextssl `Kdf`.
//!
//! `K(i) = H(counter_be32 || Z || OtherInfo)`, counter from 1, output = K(1)||K(2)..., cut to the
//! requested length. Mapping: `ikm` = shared secret Z (1 byte or more), `info` = OtherInfo /
//! FixedInfo (0..=65536 bytes), `salt` is not part of the hash-based one-step KDF: a non-empty
//! salt is an error. Param `hash` selects H. Output 1..=1048576 bytes (an explicit cap; the
//! standard allows 2^32-1 blocks). Intermediate hash outputs inside the crate are not wiped
//! (rule 9 gap).

use concat_kdf::derive_key_into;
use nextssl_core::{Error, Kdf, Len, Params, Result, Sizes, SymmetricKey};
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

const OUT_MAX: usize = 1 << 20;
const IKM_MAX: usize = 1 << 20;
const INFO_MAX: usize = 1 << 16;

#[derive(Clone, Copy)]
enum H {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

struct Impl {
    hash: H,
}

impl Kdf for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(1, IKM_MAX)),
            salt: Some(Len::fixed(0)),
            info: Some(Len::range(0, INFO_MAX)),
            out: Some(Len::range(1, OUT_MAX)),
            ..Sizes::NONE
        }
    }

    fn derive(&self, ikm: &SymmetricKey, salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
        Len::range(1, IKM_MAX).check("ikm", ikm.len())?;
        Len::fixed(0).check("salt (concat-kdf takes none)", salt.len())?;
        Len::range(0, INFO_MAX).check("info", info.len())?;
        Len::range(1, OUT_MAX).check("out", out.len())?;
        let z = ikm.as_bytes();
        let r = match self.hash {
            H::Sha224 => derive_key_into::<Sha224>(z, info, out),
            H::Sha256 => derive_key_into::<Sha256>(z, info, out),
            H::Sha384 => derive_key_into::<Sha384>(z, info, out),
            H::Sha512 => derive_key_into::<Sha512>(z, info, out),
            H::Sha3_224 => derive_key_into::<Sha3_224>(z, info, out),
            H::Sha3_256 => derive_key_into::<Sha3_256>(z, info, out),
            H::Sha3_384 => derive_key_into::<Sha3_384>(z, info, out),
            H::Sha3_512 => derive_key_into::<Sha3_512>(z, info, out),
        };
        r.map_err(|_| Error::Backend("concat-kdf"))
    }
}

/// Registry constructor. Param `hash` (enum, default `sha256`).
pub fn new(params: &Params) -> Result<Box<dyn Kdf>> {
    let hash = match params.get_str("hash") {
        None | Some("sha256") => H::Sha256,
        Some("sha224") => H::Sha224,
        Some("sha384") => H::Sha384,
        Some("sha512") => H::Sha512,
        Some("sha3-224") => H::Sha3_224,
        Some("sha3-256") => H::Sha3_256,
        Some("sha3-384") => H::Sha3_384,
        Some("sha3-512") => H::Sha3_512,
        Some(_) => return Err(Error::ParamOutOfRange("hash")),
    };
    Ok(Box::new(Impl { hash }))
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

    /// Any-length key, so tests can hand the glue wrong sizes.
    fn key(bytes: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(bytes, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn all_kat_files() {
        let mut n = 0;
        for file in ["acvp-onestep.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "concat-kdf");
            for v in doc["vectors"].as_array().unwrap() {
                let id = v["id"].as_str().unwrap();
                let kdf = new(&Params::new()
                    .with("hash", Value::Str(v["hash"].as_str().unwrap().to_string())))
                .unwrap();
                let z = key(&unhex(v["z_hex"].as_str().unwrap()));
                let info = unhex(v["info_hex"].as_str().unwrap());
                let dkm = unhex(v["dkm_hex"].as_str().unwrap());
                let mut out = vec![0u8; dkm.len()];
                kdf.derive(&z, b"", &info, &mut out).unwrap();
                assert_eq!(out, dkm, "{file}/{id}");
                n += 1;
            }
        }
        assert!(n >= 10, "too few KATs ran: {n}");
    }

    #[test]
    fn rejects_bad_inputs() {
        let kdf = new(&Params::new()).unwrap();
        let z = key(&[7u8; 32]);
        let mut out = [0u8; 16];
        assert!(
            kdf.derive(&z, b"salt", b"", &mut out).is_err(),
            "salt must not be ignored"
        );
        assert!(kdf.derive(&z, b"", b"", &mut []).is_err(), "empty output");
        assert!(
            kdf.derive(&key(&[]), b"", b"", &mut out).is_err(),
            "empty secret"
        );
        assert!(kdf.derive(&z, b"", &[0u8; INFO_MAX + 1], &mut out).is_err());
        let bad = new(&Params::new().with("hash", Value::Str("md5".into())));
        assert!(bad.is_err());
    }
}
