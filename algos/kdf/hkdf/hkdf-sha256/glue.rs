//! Adapter: RustCrypto `hkdf` + `sha2` (HKDF-SHA-256, RFC 5869) -> nextssl `Kdf`.
//!
//! IKM 1..=2^28 bytes (empty refused). Output 1..=8160 bytes (255 * HashLen); asking for more
//! is an error, never a short output. An empty salt means HashLen zero bytes, as in RFC 5869.
//! `extract` returns the 32-byte PRK; `expand` accepts any PRK of at least 32 bytes.

use hkdf::Hkdf;
use nextssl_core::{Error, Kdf, Len, Params, Result, Sizes, SymmetricKey, Zeroize};
use sha2::Sha256;

const IKM_MIN: usize = 1;
const IKM_MAX: usize = 1 << 28;
const OUT_MIN: usize = 1;
const OUT_MAX: usize = 255 * 32;
const PRK_LEN: usize = 32;

struct HkdfSha256;

fn check_out(len: usize) -> Result<()> {
    Len::range(OUT_MIN, OUT_MAX).check("out", len)
}

fn expand_into(hk: &Hkdf<Sha256>, info: &[u8], out: &mut [u8]) -> Result<()> {
    hk.expand(info, out).map_err(|_| Error::InvalidLength {
        what: "out",
        got: out.len(),
        min: OUT_MIN,
        max: OUT_MAX,
    })
}

impl Kdf for HkdfSha256 {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(IKM_MIN, IKM_MAX)),
            out: Some(Len::range(OUT_MIN, OUT_MAX)),
            ..Sizes::NONE
        }
    }

    fn derive(&self, ikm: &SymmetricKey, salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
        Len::range(IKM_MIN, IKM_MAX).check("ikm", ikm.len())?;
        check_out(out.len())?;
        let (mut prk, hk) = Hkdf::<Sha256>::extract(Some(salt), ikm.as_bytes());
        prk.as_mut_slice().zeroize();
        expand_into(&hk, info, out)
    }

    fn extract(&self, ikm: &SymmetricKey, salt: &[u8]) -> Result<SymmetricKey> {
        Len::range(IKM_MIN, IKM_MAX).check("ikm", ikm.len())?;
        let (mut prk, _hk) = Hkdf::<Sha256>::extract(Some(salt), ikm.as_bytes());
        let key = SymmetricKey::from_bytes(prk.as_slice(), Len::fixed(PRK_LEN));
        prk.as_mut_slice().zeroize();
        key
    }

    fn expand(&self, prk: &SymmetricKey, info: &[u8], out: &mut [u8]) -> Result<()> {
        Len::range(PRK_LEN, IKM_MAX).check("prk", prk.len())?;
        check_out(out.len())?;
        let hk = Hkdf::<Sha256>::from_prk(prk.as_bytes())
            .map_err(|_| Error::Backend("hkdf-sha256 prk setup"))?;
        expand_into(&hk, info, out)
    }
}

/// Registry constructor. HKDF-SHA-256 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Kdf>> {
    Ok(Box::new(HkdfSha256))
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn kdf() -> Box<dyn Kdf> {
        new(&Params::new()).unwrap()
    }

    #[test]
    fn sizes_match_metadata() {
        let s = kdf().sizes();
        assert_eq!(s.key, Some(Len::range(1, 268_435_456)));
        assert_eq!(s.out, Some(Len::range(1, 8160)));
    }

    #[test]
    fn rfc5869_kats() {
        let h = kdf();
        let doc = load("rfc5869.json");
        assert_eq!(doc["algorithm"], "hkdf-sha256");
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let id = v["id"].as_str().unwrap();
            let ikm = key(&unhex(v["ikm_hex"].as_str().unwrap()));
            let salt = unhex(v["salt_hex"].as_str().unwrap());
            let info = unhex(v["info_hex"].as_str().unwrap());
            let prk_want = unhex(v["prk_hex"].as_str().unwrap());
            let okm = unhex(v["out_hex"].as_str().unwrap());

            let mut got = vec![0u8; okm.len()];
            h.derive(&ikm, &salt, &info, &mut got).unwrap();
            assert_eq!(got, okm, "derive {id}");

            let prk = h.extract(&ikm, &salt).unwrap();
            assert_eq!(prk.as_bytes(), &prk_want[..], "extract {id}");
            let mut got2 = vec![0u8; okm.len()];
            h.expand(&prk, &info, &mut got2).unwrap();
            assert_eq!(got2, okm, "expand {id}");
            n += 1;
        }
        assert_eq!(n, 3);
    }

    #[test]
    fn wycheproof() {
        let h = kdf();
        let doc = load("wycheproof_hkdf_sha256_test.json");
        let (mut valid, mut invalid) = (0usize, 0usize);
        for g in doc["testGroups"].as_array().unwrap() {
            for t in g["tests"].as_array().unwrap() {
                let tc = t["tcId"].as_u64().unwrap();
                let ikm = key(&unhex(t["ikm"].as_str().unwrap()));
                let salt = unhex(t["salt"].as_str().unwrap());
                let info = unhex(t["info"].as_str().unwrap());
                let size = usize::try_from(t["size"].as_u64().unwrap()).unwrap();
                let mut out = vec![0u8; size];
                match t["result"].as_str().unwrap() {
                    "valid" => {
                        let okm = unhex(t["okm"].as_str().unwrap());
                        assert_eq!(okm.len(), size, "tcId {tc}");
                        h.derive(&ikm, &salt, &info, &mut out).unwrap();
                        assert_eq!(out, okm, "tcId {tc}");
                        valid += 1;
                    }
                    "invalid" => {
                        let r = h.derive(&ikm, &salt, &info, &mut out);
                        assert!(
                            matches!(r, Err(Error::InvalidLength { .. })),
                            "invalid case accepted, tcId {tc}: {r:?}"
                        );
                        assert!(out.iter().all(|&b| b == 0), "output written on error");
                        invalid += 1;
                    }
                    other => panic!("tcId {tc}: unexpected result {other:?}"),
                }
            }
        }
        let total = usize::try_from(doc["numberOfTests"].as_u64().unwrap()).unwrap();
        assert_eq!(valid + invalid, total, "not every Wycheproof case ran");
        assert!(valid > 0 && invalid > 0);
        eprintln!("wycheproof: total {total}, valid {valid}, invalid rejected {invalid}");
    }

    #[test]
    fn rejects_bad_lengths() {
        let h = kdf();
        let ikm = key(&[1u8; 22]);
        for bad in [0usize, 8161, 10_000] {
            let mut out = vec![0u8; bad];
            assert!(
                matches!(
                    h.derive(&ikm, b"s", b"i", &mut out),
                    Err(Error::InvalidLength { .. })
                ),
                "out {bad}"
            );
            assert!(
                matches!(
                    h.expand(&key(&[2u8; 32]), b"i", &mut out),
                    Err(Error::InvalidLength { .. })
                ),
                "out {bad}"
            );
        }
        // Boundary: exactly 255 blocks is fine.
        h.derive(&ikm, b"s", b"i", &mut vec![0u8; 8160]).unwrap();
        // Empty IKM refused.
        assert!(matches!(
            h.derive(&key(&[]), b"s", b"i", &mut [0u8; 16]),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            h.extract(&key(&[]), b"s"),
            Err(Error::InvalidLength { .. })
        ));
        // PRK shorter than the hash length refused.
        for bad in [0usize, 1, 31] {
            assert!(
                matches!(
                    h.expand(&key(&vec![2u8; bad]), b"i", &mut [0u8; 16]),
                    Err(Error::InvalidLength { .. })
                ),
                "prk {bad}"
            );
        }
    }
}
