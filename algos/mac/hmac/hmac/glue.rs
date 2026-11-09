//! Adapter: RustCrypto `hmac` + `sha2`/`sha3` (HMAC, RFC 2104 / FIPS 198-1) -> nextssl `Mac`,
//! generic over the closed `hash` enum parameter (default `sha256`).
//!
//! Key: 1..=268435456 bytes (empty key refused). Tag: 16..=HashLen bytes; the tag is the
//! leftmost `out.len()` bytes of the full HMAC, so truncation happens only when the caller
//! asks for a declared shorter length. An unknown `hash` value is an error, never a fallback.
//! MD5/SHA-1 are deliberately not selectable (see hmac-md5 / hmac-sha1).

use hmac::{Hmac, KeyInit, Mac as _};
use nextssl_core::{
    Error, Len, Mac, ParamSpec, ParamType, Params, Result, Sizes, SymmetricKey, Zeroize,
};
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

const KEY_MIN: usize = 1;
const KEY_MAX: usize = 268435456;
const TAG_MIN: usize = 16;

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

    fn out_len(self) -> usize {
        match self {
            H::Sha224 | H::Sha512_224 | H::Sha3_224 => 28,
            H::Sha256 | H::Sha512_256 | H::Sha3_256 => 32,
            H::Sha384 | H::Sha3_384 => 48,
            H::Sha512 | H::Sha3_512 => 64,
        }
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

struct Impl {
    hash: H,
}

impl Mac for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(KEY_MIN, KEY_MAX)),
            tag: Some(Len::range(TAG_MIN, self.hash.out_len())),
            ..Sizes::NONE
        }
    }

    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::range(KEY_MIN, KEY_MAX).check("key", key.len())?;
        Len::range(TAG_MIN, self.hash.out_len()).check("tag", out.len())?;
        with_hash!(self.hash, D => {
            let mut mac = <Hmac<D> as KeyInit>::new_from_slice(key.as_bytes())
                .map_err(|_| Error::Backend("hmac key setup"))?;
            mac.update(data);
            let mut full = mac.finalize().into_bytes();
            out.copy_from_slice(&full.as_slice()[..out.len()]);
            full.as_mut_slice().zeroize();
            Ok(())
        })
    }
}

/// Registry constructor. Parameter `hash` (enum, default `sha256`); unknown values are errors.
pub fn new(params: &Params) -> Result<Box<dyn Mac>> {
    let v = params.validate(&SPECS)?;
    let name = v.get_str("hash").ok_or(Error::ParamMissing("hash"))?;
    let hash = H::parse(name).ok_or(Error::ParamOutOfRange("hash"))?;
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

    fn key(bytes: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(bytes, Len::range(0, usize::MAX)).unwrap()
    }

    fn mac(hash: &str) -> Box<dyn Mac> {
        new(&Params::new().with("hash", Value::Str(hash.into()))).unwrap()
    }

    #[test]
    fn default_is_sha256_and_sizes_follow_the_hash() {
        let d = new(&Params::new()).unwrap();
        assert_eq!(d.sizes().tag, Some(Len::range(16, 32)));
        for h in HASHES {
            let m = mac(h);
            let want = H::parse(h).unwrap().out_len();
            assert_eq!(m.sizes().tag, Some(Len::range(16, want)), "{h}");
        }
    }

    #[test]
    fn unknown_hash_is_an_error_not_a_fallback() {
        for bad in ["md5", "sha1", "SHA256", "", "sha-256"] {
            let r = new(&Params::new().with("hash", Value::Str(bad.into())));
            assert!(matches!(r, Err(Error::ParamOutOfRange("hash"))), "{bad}");
        }
        assert!(matches!(
            new(&Params::new().with("hash", Value::U32(1))),
            Err(Error::ParamType("hash"))
        ));
    }

    fn replay(file: &str) -> usize {
        let doc = load(file);
        assert_eq!(doc["algorithm"], "hmac");
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let id = v["id"].as_str().unwrap();
            let m = mac(v["hash"].as_str().unwrap());
            let k = key(&unhex(v["key_hex"].as_str().unwrap()));
            let data = unhex(v["data_hex"].as_str().unwrap());
            let want = unhex(v["tag_hex"].as_str().unwrap());
            let mut got = vec![0u8; want.len()];
            m.tag(&k, &data, &mut got).unwrap();
            assert_eq!(got, want, "{id}");
            assert!(m.verify(&k, &data, &want).unwrap(), "{id}");
            let mut bad = want.clone();
            bad[0] ^= 1;
            assert!(!m.verify(&k, &data, &bad).unwrap(), "{id}");
            n += 1;
        }
        n
    }

    #[test]
    fn rfc4231_and_python_vectors() {
        assert_eq!(replay("rfc4231.json"), 28);
        assert_eq!(replay("py-hmac.json"), 240);
    }

    #[test]
    fn wycheproof() {
        let files = [
            ("wycheproof_hmac_sha256_test.json", "sha256"),
            ("wycheproof_hmac_sha512_test.json", "sha512"),
            ("wycheproof_hmac_sha3_256_test.json", "sha3-256"),
            ("wycheproof_hmac_sha3_384_test.json", "sha3-384"),
            ("wycheproof_hmac_sha3_512_test.json", "sha3-512"),
        ];
        for (file, hash) in files {
            let doc = load(file);
            let m = mac(hash);
            let (mut ran, mut refused) = (0usize, 0usize);
            for g in doc["testGroups"].as_array().unwrap() {
                for t in g["tests"].as_array().unwrap() {
                    let tc = t["tcId"].as_u64().unwrap();
                    let k = key(&unhex(t["key"].as_str().unwrap()));
                    let msg = unhex(t["msg"].as_str().unwrap());
                    let tag = unhex(t["tag"].as_str().unwrap());
                    let declared = m.sizes().tag.unwrap().check("tag", tag.len()).is_ok();
                    match t["result"].as_str().unwrap() {
                        "valid" if declared => {
                            let mut got = vec![0u8; tag.len()];
                            m.tag(&k, &msg, &mut got).unwrap();
                            assert_eq!(got, tag, "{file} tcId {tc}");
                            assert!(m.verify(&k, &msg, &tag).unwrap());
                        }
                        "valid" => {
                            assert!(m.verify(&k, &msg, &tag).is_err(), "{file} tcId {tc}");
                            refused += 1;
                        }
                        "invalid" => assert!(
                            !m.verify(&k, &msg, &tag).unwrap_or(false),
                            "{file} invalid accepted, tcId {tc}"
                        ),
                        other => panic!("unexpected result {other:?}"),
                    }
                    ran += 1;
                }
            }
            assert_eq!(ran as u64, doc["numberOfTests"].as_u64().unwrap(), "{file}");
            eprintln!("{file}: {ran} cases, {refused} refused tag lengths");
        }
    }

    #[test]
    fn rejects_bad_lengths() {
        let m = mac("sha384");
        let k = key(&[1u8; 32]);
        for bad in [0usize, 15, 49] {
            let mut out = vec![0xAAu8; bad];
            assert!(matches!(
                m.tag(&k, b"x", &mut out),
                Err(Error::InvalidLength { .. })
            ));
            assert!(out.iter().all(|&b| b == 0xAA));
        }
        assert!(matches!(
            m.tag(&key(&[]), b"x", &mut [0u8; 16]),
            Err(Error::InvalidLength { .. })
        ));
    }
}
