//! Adapter: RustCrypto `pbkdf2` + `sha2` (PBKDF2-HMAC-SHA256, RFC 8018 / NIST SP 800-132) -> nextssl `PwHash`.
//!
//! Policy (the DoS guard): `iterations` 1..=16777216, salt 4..=64 bytes, output 16..=1024 bytes.
//! Short salts exist only because published vectors use them; callers should use 16 bytes or
//! more (the safe layer generates salts). The same ranges apply to a PHC string read by
//! `verify`, before any work is done. PHC form: `$pbkdf2-sha256$i=<n>$<salt>$<hash>`
//! (strict parser in `nextssl_core::phc`).

use nextssl_core::phc::{self, PhcParam, PhcSpec};
use nextssl_core::{
    ct_eq, Error, Len, ParamSpec, ParamType, Params, PwHash, Result, Sizes, Value, Zeroizing,
    MAX_INPUT_LEN,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

const I_MIN: u32 = 1;
const I_MAX: u32 = 16_777_216;
const I_DEFAULT: u32 = 600000;
const SALT_MIN: usize = 4;
const SALT_MAX: usize = 64;
const OUT_MIN: usize = 16;
const OUT_MAX: usize = 1024;
const OUT_DEFAULT: u32 = 32;

const PHC: PhcSpec = PhcSpec {
    id: "pbkdf2-sha256",
    version: None,
    params: &[PhcParam {
        name: "i",
        min: I_MIN,
        max: I_MAX,
    }],
    salt: Len::range(SALT_MIN, SALT_MAX),
    hash: Len::range(OUT_MIN, OUT_MAX),
};

/// Mirror of the `[params]` table in `algo.toml`.
const SPECS: [ParamSpec; 2] = [
    spec("iterations", I_MIN, I_MAX, I_DEFAULT),
    spec("out_len", OUT_MIN as u32, OUT_MAX as u32, OUT_DEFAULT),
];

const fn spec(name: &'static str, min: u32, max: u32, default: u32) -> ParamSpec {
    ParamSpec {
        name,
        ty: ParamType::U32,
        min: min as u64,
        max: max as u64,
        required: false,
        default: Some(default as u64),
    }
}

fn check_salt(salt: &[u8]) -> Result<()> {
    Len::range(SALT_MIN, SALT_MAX).check("salt", salt.len())
}

fn check_password(password: &[u8]) -> Result<()> {
    Len::range(0, MAX_INPUT_LEN).check("password", password.len())
}

/// Raw PBKDF2. Callers have already validated `iterations`, `salt` and `out.len()`.
fn run(iterations: u32, password: &[u8], salt: &[u8], out: &mut [u8]) {
    pbkdf2_hmac::<Sha256>(password, salt, iterations, out);
}

struct Impl {
    iterations: u32,
    out_len: usize,
}

impl PwHash for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            salt: Some(Len::range(SALT_MIN, SALT_MAX)),
            out: Some(Len::range(OUT_MIN, OUT_MAX)),
            ..Sizes::NONE
        }
    }

    fn hash(&self, password: &[u8], salt: &[u8]) -> Result<String> {
        let mut out = Zeroizing::new(vec![0u8; self.out_len]);
        self.derive(password, salt, &mut out)?;
        phc::write(&PHC, &[self.iterations], salt, &out)
    }

    fn verify(&self, password: &[u8], phc_str: &str) -> Result<bool> {
        check_password(password)?;
        let p = phc::parse(phc_str, &PHC)?;
        let mut mine = Zeroizing::new(vec![0u8; p.hash.len()]);
        run(p.params[0], password, &p.salt, &mut mine);
        Ok(ct_eq(&mine, &p.hash))
    }

    fn derive(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
        check_password(password)?;
        check_salt(salt)?;
        Len::range(OUT_MIN, OUT_MAX).check("out", out.len())?;
        run(self.iterations, password, salt, out);
        Ok(())
    }
}

fn get(params: &Params, name: &'static str) -> Result<u32> {
    match params.get(name) {
        Some(Value::U32(v)) => Ok(*v),
        _ => Err(Error::ParamType(name)),
    }
}

/// Registry constructor. Parameters: `iterations`, `out_len` (both `u32`; defaults and ranges in
/// `algo.toml`). Unknown names and out-of-range values are errors.
pub fn new(params: &Params) -> Result<Box<dyn PwHash>> {
    let v = params.validate(&SPECS)?;
    Ok(Box::new(Impl {
        iterations: get(&v, "iterations")?,
        out_len: get(&v, "out_len")? as usize,
    }))
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
        let p = Params::new()
            .with("iterations", Value::U32(u32_of(v, "iterations")))
            .with("out_len", Value::U32(u32_of(v, "out_len")));
        new(&p).unwrap()
    }

    /// Vectors flagged `heavy` (very many iterations or ~1 GiB) run only with NEXTSSL_HEAVY_KAT=1.
    fn skip_heavy(v: &J) -> bool {
        v["heavy"].as_bool().unwrap_or(false) && std::env::var_os("NEXTSSL_HEAVY_KAT").is_none()
    }

    #[test]
    fn sizes_match_metadata() {
        let s = new(&Params::new()).unwrap().sizes();
        assert_eq!(s.salt, Some(Len::range(4, 64)));
        assert_eq!(s.out, Some(Len::range(16, 1024)));
    }

    #[test]
    fn known_answers() {
        let (mut ran, mut skipped) = (0usize, 0usize);
        for file in ["vectors.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "pbkdf2-hmac-sha256");
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
                if let Some(expect) = v["phc"].as_str() {
                    assert_eq!(phc, expect, "{id} phc");
                }
                ran += 1;
            }
        }
        assert!(ran >= 60, "too few vectors ran: {ran}");
        eprintln!("pbkdf2-hmac-sha256: {ran} vectors ran, {skipped} heavy vectors skipped (set NEXTSSL_HEAVY_KAT=1)");
    }

    #[test]
    fn input_and_param_limits() {
        let h = new(&Params::new()).unwrap();
        let mut out = [0u8; 16];
        for n in [0, 3, 65] {
            assert!(
                matches!(
                    h.derive(b"pw", &vec![0u8; n], &mut out),
                    Err(Error::InvalidLength { what: "salt", .. })
                ),
                "salt {n}"
            );
            assert!(h.hash(b"pw", &vec![0u8; n]).is_err());
        }
        for n in [0, 15, 1025] {
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
            matches!(bad("iterations", 0), Error::ParamOutOfRange(_)),
            "iterations 0"
        );
        assert!(
            matches!(bad("iterations", 16777217), Error::ParamOutOfRange(_)),
            "iterations 16777217"
        );
        assert!(matches!(bad("out_len", 15), Error::ParamOutOfRange(_)));
        assert!(matches!(bad("out_len", 1025), Error::ParamOutOfRange(_)));
        let unknown = Params::new().with("salt", Value::Bytes(vec![0; 16]));
        assert!(matches!(new(&unknown), Err(Error::ParamUnknown)));
        let wrong_ty = Params::new().with("out_len", Value::U64(32));
        assert!(matches!(new(&wrong_ty), Err(Error::ParamType(_))));
    }

    #[test]
    fn hostile_phc_strings_are_rejected_before_any_work() {
        let h = new(&Params::new()).unwrap();
        let s = "c29tZXNhbHRzb21lc2FsdA"; // 16 bytes
        let hs = "CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"; // 32 bytes
        let ok = format!("$pbkdf2-sha256$i=1000${s}${hs}");
        // Well-formed: parses, wrong password, so Ok(false).
        assert!(!h.verify(b"pw", &ok).unwrap());
        let cases = [
            format!("$pbkdf2-sha256$i=1000${s}${hs}$"),
            format!("pbkdf2-sha256$i=1000${s}${hs}"),
            format!("$pbkdf2-sha256$i=1000${s}"),
            format!("$pbkdf2-sha256$i=1000${s}==${hs}"),
            format!("$pbkdf2-sha256$i=1000$c29tZXNhbHRzb21lc2FsdB${hs}"),
            format!("$pbkdf2-sha256$i=1000$c29tZXNhbHRzb21lc2F-dA${hs}"),
            format!("$pbkdf2-sha256$i=1000${s}$"),
            format!("$pbkdf2-sha256$i=1000$${hs}"),
            format!("$pbkdf2-sha256$i=1000 ${s}${hs}"),
            format!("$other$i=1000${s}${hs}"),
            format!("$pbkdf2-sha1$i=1000${s}${hs}"),
            format!("$pbkdf2-sha256$v=19$i=1000${s}${hs}"),
            format!("$pbkdf2-sha256$i=0${s}${hs}"),
            format!("$pbkdf2-sha256$i=16777217${s}${hs}"),
            format!("$pbkdf2-sha256$i=4294967295${s}${hs}"),
            format!("$pbkdf2-sha256$i=99999999999${s}${hs}"),
            format!("$pbkdf2-sha256$i=01000${s}${hs}"),
            format!("$pbkdf2-sha256$i=+1000${s}${hs}"),
            format!("$pbkdf2-sha256$i=1000,l=32${s}${hs}"),
            format!("$pbkdf2-sha256$i=${s}${hs}"),
            format!("$pbkdf2-sha256$i=1000$c29t${hs}"),
            String::new(),
            "$".repeat(5000),
        ];
        for c in &cases {
            assert!(h.verify(b"pw", c).is_err(), "must reject: {c:.80}");
        }
        assert!(h.verify(b"pw", "$pbkdf2-sha256$é$é$é").is_err());
    }
}
