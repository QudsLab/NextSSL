//! Adapter: `bcrypt` crate (bcrypt, Provos and Mazieres 1999; `$2b$` strings) -> nextssl `PwHash`.
//!
//! Policy: cost 4..=16 (log2 rounds; default 12), salt exactly 16 bytes, password 0..=71 bytes
//! with no NUL byte (bcrypt consumes at most 72 bytes INCLUDING the terminating NUL and cannot
//! carry embedded NULs, so longer or NUL-containing passwords are refused instead of being
//! silently truncated; pre-hash in the caller if you need long passwords). Raw output is the
//! 23-byte bcrypt hash. `hash` writes `$2b$`; `verify` accepts `$2b$`, `$2y$` and `$2a$` (the latter only for
//! ASCII passwords: with bytes >= 0x80 `$2a$` is ambiguous in the reference and is refused) and checks length, prefix and cost before any work.

use nextssl_core::{
    Error, Len, ParamSpec, ParamType, Params, PwHash, Result, Sizes, Value, Zeroizing,
};

const COST_MIN: u32 = 4;
const COST_MAX: u32 = 16;
const PW_MAX: usize = 71;
const SALT_LEN: usize = 16;
const OUT_LEN: usize = 23;
const MCF_LEN: usize = 60;

const SPECS: [ParamSpec; 1] = [ParamSpec {
    name: "cost",
    ty: ParamType::U32,
    min: COST_MIN as u64,
    max: COST_MAX as u64,
    required: false,
    default: Some(12),
}];

fn check_password(password: &[u8]) -> Result<()> {
    Len::range(0, PW_MAX).check("password", password.len())?;
    if password.contains(&0) {
        return Err(Error::InvalidInput(
            "bcrypt password must not contain a NUL byte",
        ));
    }
    Ok(())
}

fn salt_array(salt: &[u8]) -> Result<[u8; SALT_LEN]> {
    Len::fixed(SALT_LEN).check("salt", salt.len())?;
    let mut s = [0u8; SALT_LEN];
    s.copy_from_slice(salt);
    Ok(s)
}

struct Impl {
    cost: u32,
}

impl PwHash for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            salt: Some(Len::fixed(SALT_LEN)),
            out: Some(Len::fixed(OUT_LEN)),
            ..Sizes::NONE
        }
    }

    fn hash(&self, password: &[u8], salt: &[u8]) -> Result<String> {
        check_password(password)?;
        let salt = salt_array(salt)?;
        let parts = bcrypt::non_truncating_hash_with_salt(password, self.cost, salt)
            .map_err(|_| Error::Backend("bcrypt failed"))?;
        Ok(parts.format_for_version(bcrypt::Version::TwoB))
    }

    fn verify(&self, password: &[u8], phc: &str) -> Result<bool> {
        check_password(password)?;
        if phc.starts_with("$2a$") && !password.is_ascii() {
            return Err(Error::InvalidInput(
                "bcrypt $2a$ with an 8-bit password is ambiguous",
            ));
        }
        let b = phc.as_bytes();
        if phc.len() != MCF_LEN || !phc.is_ascii() {
            return Err(Error::InvalidInput("malformed bcrypt string"));
        }
        if !(phc.starts_with("$2b$") || phc.starts_with("$2a$") || phc.starts_with("$2y$"))
            || b[6] != b'$'
        {
            return Err(Error::InvalidInput("malformed bcrypt string"));
        }
        // Strict two-digit cost, range-checked before any work.
        if !b[4].is_ascii_digit() || !b[5].is_ascii_digit() {
            return Err(Error::InvalidInput("malformed bcrypt cost"));
        }
        let cost = u32::from(b[4] - b'0') * 10 + u32::from(b[5] - b'0');
        if !(COST_MIN..=COST_MAX).contains(&cost) {
            return Err(Error::ParamOutOfRange("cost"));
        }
        if !b[7..]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'.' || *c == b'/')
        {
            return Err(Error::InvalidInput("malformed bcrypt string"));
        }
        bcrypt::non_truncating_verify(password, phc)
            .map_err(|_| Error::InvalidInput("malformed bcrypt string"))
    }

    fn derive(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
        check_password(password)?;
        let salt = salt_array(salt)?;
        Len::fixed(OUT_LEN).check("out", out.len())?;
        // bcrypt hashes the password followed by its NUL terminator.
        let mut keyed = Zeroizing::new(Vec::with_capacity(password.len() + 1));
        keyed.extend_from_slice(password);
        keyed.push(0);
        let full = Zeroizing::new(bcrypt::bcrypt(self.cost, salt, &keyed));
        out.copy_from_slice(&full[..OUT_LEN]);
        Ok(())
    }
}

/// Registry constructor. Parameter: `cost` (`u32`, 4..=16, default 12).
pub fn new(params: &Params) -> Result<Box<dyn PwHash>> {
    let v = params.validate(&SPECS)?;
    match v.get("cost") {
        Some(Value::U32(c)) => Ok(Box::new(Impl { cost: *c })),
        _ => Err(Error::ParamType("cost")),
    }
}

#[cfg(test)]
#[allow(clippy::single_element_loop)]
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

    fn u32_of(v: &J, k: &str) -> u32 {
        u32::try_from(v[k].as_u64().unwrap()).unwrap()
    }

    fn inst(v: &J) -> Box<dyn PwHash> {
        let p = Params::new().with("cost", Value::U32(u32_of(v, "cost")));
        new(&p).unwrap()
    }

    /// Vectors flagged `heavy` (very many iterations or ~1 GiB) run only with NEXTSSL_HEAVY_KAT=1.
    fn skip_heavy(v: &J) -> bool {
        v["heavy"].as_bool().unwrap_or(false) && std::env::var_os("NEXTSSL_HEAVY_KAT").is_none()
    }

    #[test]
    fn sizes_match_metadata() {
        let s = new(&Params::new()).unwrap().sizes();
        assert_eq!(s.salt, Some(Len::fixed(16)));
        assert_eq!(s.out, Some(Len::fixed(23)));
    }

    #[test]
    fn known_answers() {
        let (mut ran, mut skipped) = (0usize, 0usize);
        for file in ["crypt_blowfish.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "bcrypt");
            for v in doc["vectors"].as_array().unwrap() {
                let id = v["id"].as_str().unwrap();
                if skip_heavy(v) {
                    skipped += 1;
                    continue;
                }
                let pw = unhex(v["password_hex"].as_str().unwrap());
                let salt = unhex(v["salt_hex"].as_str().unwrap());
                let want = unhex(v["out_hex"].as_str().unwrap());
                let h = inst(v);
                let mut got = vec![0u8; want.len()];
                h.derive(&pw, &salt, &mut got).unwrap();
                assert_eq!(got, want, "{id}");
                // PHC round trip through the same parameters.
                let phc = h.hash(&pw, &salt).unwrap();
                assert!(h.verify(&pw, &phc).unwrap(), "{id} verify");
                let mut wrong = pw.clone();
                wrong.push(b'x');
                assert!(!h.verify(&wrong, &phc).unwrap(), "{id} wrong password");
                if let Some(expect) = v["mcf"].as_str() {
                    assert_eq!(phc, expect, "{id} phc");
                }
                ran += 1;
            }
        }
        assert!(ran >= 11, "too few vectors ran: {ran}");
        eprintln!(
            "bcrypt: {ran} vectors ran, {skipped} heavy vectors skipped (set NEXTSSL_HEAVY_KAT=1)"
        );
    }

    #[test]
    fn dollar_2a_with_8bit_password_is_refused() {
        // In crypt_blowfish `$2a$` computes differently from `$2b$`/`$2y$` for passwords with
        // bytes >= 0x80, so the adapter refuses that combination instead of guessing.
        let h = new(&Params::new()).unwrap();
        let doc = load("crypt_blowfish.json");
        let list = doc["refused_2a"].as_array().unwrap();
        assert!(!list.is_empty());
        for v in list {
            let pw = unhex(v["password_hex"].as_str().unwrap());
            assert!(h.verify(&pw, v["source_mcf"].as_str().unwrap()).is_err());
        }
    }

    #[test]
    fn input_and_param_limits() {
        let h = new(&Params::new()).unwrap();
        let mut out = [0u8; 23];
        for n in [0, 15, 17] {
            assert!(
                matches!(
                    h.derive(b"pw", &vec![0u8; n], &mut out),
                    Err(Error::InvalidLength { what: "salt", .. })
                ),
                "salt {n}"
            );
            assert!(h.hash(b"pw", &vec![0u8; n]).is_err());
        }
        for n in [0, 22, 24] {
            assert!(
                matches!(
                    h.derive(b"pw", &[0u8; 16], &mut vec![0u8; n]),
                    Err(Error::InvalidLength { what: "out", .. })
                ),
                "out {n}"
            );
        }
        let bad = |name: &str, v: u32| new(&Params::new().with(name, Value::U32(v))).err().unwrap();
        assert!(
            matches!(bad("cost", 3), Error::ParamOutOfRange(_)),
            "cost 3"
        );
        assert!(
            matches!(bad("cost", 17), Error::ParamOutOfRange(_)),
            "cost 17"
        );

        let unknown = Params::new().with("salt", Value::Bytes(vec![0; 16]));
        assert!(matches!(new(&unknown), Err(Error::ParamUnknown)));
        let wrong_ty = Params::new().with("cost", Value::U64(12));
        assert!(matches!(new(&wrong_ty), Err(Error::ParamType(_))));
    }

    #[test]
    fn hostile_phc_strings_are_rejected_before_any_work() {
        let h = new(&Params::new()).unwrap();
        let _ = (); // bcrypt strings are literal
        let ok = String::from("$2b$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW");
        // Well-formed: parses, wrong password, so Ok(false).
        assert!(!h.verify(b"pw", &ok).unwrap());
        let cases = [
            String::from("$2b$12$abc"),
            String::from("$2b$03$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            String::from("$2b$17$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            String::from("$2b$99$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            String::from("$2b$31$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            String::from("$2x$12$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            String::from("$2c$12$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            String::from("$2b$12AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            String::from("$2b$1x$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            String::from("$2b$ 2$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            String::from("$2b$12$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            String::from("$2b$12$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            String::from("$2b$12$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!"),
            String::from("$2b$12$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAé"),
            String::from("$2b$+2$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            String::from("$2$12$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            String::new(),
            "$".repeat(5000),
        ];
        for c in &cases {
            assert!(h.verify(b"pw", c).is_err(), "must reject: {c:.80}");
        }
        assert!(h.verify(b"pw", "$2b$é$é$é").is_err());
    }
}
