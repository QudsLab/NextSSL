//! Adapter: RustCrypto `cmac` + `aes` (AES-CMAC, RFC 4493 / NIST SP 800-38B) -> nextssl `Mac`.
//!
//! The AES variant follows the key length: 16 bytes = AES-128, 24 = AES-192, 32 = AES-256; any
//! other length is refused. Tag: exactly 16 bytes (no truncation offered).

use aes::{Aes128, Aes192, Aes256};
use cmac::{Cmac, KeyInit};
use nextssl_core::{Error, Len, Mac, Params, Result, Sizes, SymmetricKey, Zeroize};

const TAG_LEN: usize = 16;

struct Impl;

fn run<M: cmac::Mac + KeyInit>(key: &[u8], data: &[u8], out: &mut [u8]) -> Result<()> {
    let mut mac =
        <M as KeyInit>::new_from_slice(key).map_err(|_| Error::Backend("aes-cmac key setup"))?;
    mac.update(data);
    let mut full = mac.finalize().into_bytes();
    out.copy_from_slice(full.as_slice());
    full.as_mut_slice().zeroize();
    Ok(())
}

impl Mac for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(16, 32)),
            tag: Some(Len::fixed(TAG_LEN)),
            ..Sizes::NONE
        }
    }

    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(TAG_LEN).check("tag", out.len())?;
        match key.len() {
            16 => run::<Cmac<Aes128>>(key.as_bytes(), data, out),
            24 => run::<Cmac<Aes192>>(key.as_bytes(), data, out),
            32 => run::<Cmac<Aes256>>(key.as_bytes(), data, out),
            got => Err(Error::InvalidLength {
                what: "key",
                got,
                min: 16,
                max: 32,
            }),
        }
    }
}

/// Registry constructor. AES-CMAC takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Mac>> {
    Ok(Box::new(Impl))
}

#[cfg(test)]
#[allow(clippy::single_element_loop)]
mod tests {
    use super::*;
    use nextssl_core::Error;
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

    #[allow(unused_variables)]
    fn make(v: &J) -> Box<dyn Mac> {
        new(&Params::new()).unwrap()
    }

    fn mac() -> Box<dyn Mac> {
        make(&J::Null)
    }

    #[test]
    fn sizes_match_metadata() {
        let s = mac().sizes();
        assert_eq!(s.key, Some(Len::range(16, 32)));
        assert_eq!(s.tag, Some(Len::fixed(16)));
    }

    #[test]
    fn known_answers() {
        let mut total = 0;
        for file in ["rfc4493.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "aes-cmac");
            for v in doc["vectors"].as_array().unwrap() {
                let id = v["id"].as_str().unwrap();
                let m = make(v);
                let k = key(&unhex(v["key_hex"].as_str().unwrap()));
                let data = unhex(v["data_hex"].as_str().unwrap());
                let want = unhex(v["tag_hex"].as_str().unwrap());
                let mut got = vec![0u8; want.len()];
                m.tag(&k, &data, &mut got).unwrap();
                assert_eq!(got, want, "{id}");
                assert!(m.verify(&k, &data, &want).unwrap(), "{id}");
                for pos in 0..want.len() {
                    let mut bad = want.clone();
                    bad[pos] ^= 0x80;
                    assert!(!m.verify(&k, &data, &bad).unwrap(), "{id} bitflip {pos}");
                }
                // Different data is rejected (unless the key is degenerate and the tag is data-independent).
                let mut other = data.clone();
                other.push(0);
                let mut alt = vec![0u8; want.len()];
                m.tag(&k, &other, &mut alt).unwrap();
                if alt != want {
                    assert!(!m.verify(&k, &other, &want).unwrap(), "{id}");
                }
                total += 1;
            }
        }
        assert!(total >= 4, "too few vectors ran: {total}");
    }

    #[test]
    fn wycheproof() {
        let doc = load("wycheproof_aes_cmac_test.json");
        let (mut valid, mut invalid, mut shorter) = (0usize, 0usize, 0usize);
        for g in doc["testGroups"].as_array().unwrap() {
            for t in g["tests"].as_array().unwrap() {
                let tc = t["tcId"].as_u64().unwrap();
                let m = mac();
                let k = key(&unhex(t["key"].as_str().unwrap()));
                let msg = unhex(t["msg"].as_str().unwrap());
                let tag = unhex(t["tag"].as_str().unwrap());
                match t["result"].as_str().unwrap() {
                    "valid" => {
                        if m.sizes().tag.unwrap().check("tag", tag.len()).is_ok() {
                            let mut got = vec![0u8; tag.len()];
                            m.tag(&k, &msg, &mut got).unwrap();
                            assert_eq!(got, tag, "tcId {tc}");
                            assert!(m.verify(&k, &msg, &tag).unwrap(), "tcId {tc}");
                            valid += 1;
                        } else {
                            // Tag length outside the declared policy: refused, never truncated.
                            assert!(m.verify(&k, &msg, &tag).is_err(), "tcId {tc}");
                            shorter += 1;
                        }
                    }
                    "invalid" => {
                        assert!(
                            !m.verify(&k, &msg, &tag).unwrap_or(false),
                            "invalid accepted, tcId {tc}"
                        );
                        invalid += 1;
                    }
                    other => panic!("tcId {tc}: unexpected result {other:?}"),
                }
            }
        }
        let total = usize::try_from(doc["numberOfTests"].as_u64().unwrap()).unwrap();
        assert_eq!(
            valid + invalid + shorter,
            total,
            "not every Wycheproof case ran"
        );
        assert!(valid > 0);
        eprintln!("wycheproof: total {total}, valid {valid}, invalid rejected {invalid}, refused tag length {shorter}");
    }

    #[test]
    fn rejects_bad_lengths() {
        let m = mac();
        let k = key(&[1u8; 32]);
        for bad in [0, 15, 17] {
            let mut out = vec![0xAAu8; bad];
            assert!(
                matches!(m.tag(&k, b"x", &mut out), Err(Error::InvalidLength { .. })),
                "tag {bad}"
            );
            assert!(out.iter().all(|&b| b == 0xAA), "output written on error");
            assert!(
                matches!(
                    m.verify(&k, b"x", &vec![0u8; bad]),
                    Err(Error::InvalidLength { .. })
                ),
                "verify tag {bad}"
            );
        }
        for bad in [0, 1, 8, 15, 17, 20, 23, 25, 31, 33, 40] {
            assert!(
                matches!(
                    m.tag(&key(&vec![1u8; bad]), b"x", &mut [0u8; 16]),
                    Err(Error::InvalidLength { .. })
                ),
                "key {bad}"
            );
        }
    }
}
