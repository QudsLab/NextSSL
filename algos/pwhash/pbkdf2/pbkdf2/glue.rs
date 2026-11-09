//! Adapter: RustCrypto `pbkdf2` + `sha2`/`sha3` (PBKDF2-HMAC, RFC 8018 / NIST SP 800-132) ->
//! nextssl `PwHash`, generic over the closed `hash` enum parameter (default `sha256`).
//!
//! Policy (the DoS guard): `iterations` 1..=16777216, salt 4..=64 bytes, output 16..=1024 bytes.
//! Short salts exist only because published vectors use them; callers should use 16 bytes or
//! more. The same ranges apply to a PHC string read by `verify`, before any work is done. PHC
//! form: `$pbkdf2-<hash>$i=<n>$<salt>$<hash>` (strict parser in `nextssl_core::phc`); the id in
//! the string must name the configured hash. An unknown `hash` is an error, never a fallback.

use nextssl_core::phc::{self, PhcParam, PhcSpec};
use nextssl_core::{
    ct_eq, Error, Len, ParamSpec, ParamType, Params, PwHash, Result, Sizes, Value, Zeroizing,
    MAX_INPUT_LEN,
};
use pbkdf2::pbkdf2_hmac;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

const I_MIN: u32 = 1;
const I_MAX: u32 = 16_777_216;
const I_DEFAULT: u32 = 600000;
const SALT_MIN: usize = 4;
const SALT_MAX: usize = 64;
const OUT_MIN: usize = 16;
const OUT_MAX: usize = 1024;
const OUT_DEFAULT: u32 = 32;

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

    fn phc(self) -> &'static PhcSpec {
        match self {
            H::Sha224 => &PHC_SHA224,
            H::Sha256 => &PHC_SHA256,
            H::Sha384 => &PHC_SHA384,
            H::Sha512 => &PHC_SHA512,
            H::Sha512_224 => &PHC_SHA512_224,
            H::Sha512_256 => &PHC_SHA512_256,
            H::Sha3_224 => &PHC_SHA3_224,
            H::Sha3_256 => &PHC_SHA3_256,
            H::Sha3_384 => &PHC_SHA3_384,
            H::Sha3_512 => &PHC_SHA3_512,
        }
    }
}

const fn phc_spec(id: &'static str) -> PhcSpec {
    PhcSpec {
        id,
        version: None,
        params: &[PhcParam {
            name: "i",
            min: I_MIN,
            max: I_MAX,
        }],
        salt: Len::range(SALT_MIN, SALT_MAX),
        hash: Len::range(OUT_MIN, OUT_MAX),
    }
}

static PHC_SHA224: PhcSpec = phc_spec("pbkdf2-sha224");
static PHC_SHA256: PhcSpec = phc_spec("pbkdf2-sha256");
static PHC_SHA384: PhcSpec = phc_spec("pbkdf2-sha384");
static PHC_SHA512: PhcSpec = phc_spec("pbkdf2-sha512");
static PHC_SHA512_224: PhcSpec = phc_spec("pbkdf2-sha512-224");
static PHC_SHA512_256: PhcSpec = phc_spec("pbkdf2-sha512-256");
static PHC_SHA3_224: PhcSpec = phc_spec("pbkdf2-sha3-224");
static PHC_SHA3_256: PhcSpec = phc_spec("pbkdf2-sha3-256");
static PHC_SHA3_384: PhcSpec = phc_spec("pbkdf2-sha3-384");
static PHC_SHA3_512: PhcSpec = phc_spec("pbkdf2-sha3-512");

/// Mirror of the `[params]` table in `algo.toml`.
const SPECS: [ParamSpec; 3] = [
    ParamSpec {
        name: "hash",
        ty: ParamType::Enum(HASHES),
        min: 0,
        max: 0,
        required: false,
        default: Some(0),
    },
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
fn run(h: H, iterations: u32, password: &[u8], salt: &[u8], out: &mut [u8]) {
    match h {
        H::Sha224 => pbkdf2_hmac::<Sha224>(password, salt, iterations, out),
        H::Sha256 => pbkdf2_hmac::<Sha256>(password, salt, iterations, out),
        H::Sha384 => pbkdf2_hmac::<Sha384>(password, salt, iterations, out),
        H::Sha512 => pbkdf2_hmac::<Sha512>(password, salt, iterations, out),
        H::Sha512_224 => pbkdf2_hmac::<Sha512_224>(password, salt, iterations, out),
        H::Sha512_256 => pbkdf2_hmac::<Sha512_256>(password, salt, iterations, out),
        H::Sha3_224 => pbkdf2_hmac::<Sha3_224>(password, salt, iterations, out),
        H::Sha3_256 => pbkdf2_hmac::<Sha3_256>(password, salt, iterations, out),
        H::Sha3_384 => pbkdf2_hmac::<Sha3_384>(password, salt, iterations, out),
        H::Sha3_512 => pbkdf2_hmac::<Sha3_512>(password, salt, iterations, out),
    }
}

struct Impl {
    hash: H,
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
        phc::write(self.hash.phc(), &[self.iterations], salt, &out)
    }

    fn verify(&self, password: &[u8], phc_str: &str) -> Result<bool> {
        check_password(password)?;
        let p = phc::parse(phc_str, self.hash.phc())?;
        let mut mine = Zeroizing::new(vec![0u8; p.hash.len()]);
        run(self.hash, p.params[0], password, &p.salt, &mut mine);
        Ok(ct_eq(&mine, &p.hash))
    }

    fn derive(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
        check_password(password)?;
        check_salt(salt)?;
        Len::range(OUT_MIN, OUT_MAX).check("out", out.len())?;
        run(self.hash, self.iterations, password, salt, out);
        Ok(())
    }
}

fn get(params: &Params, name: &'static str) -> Result<u32> {
    match params.get(name) {
        Some(Value::U32(v)) => Ok(*v),
        _ => Err(Error::ParamType(name)),
    }
}

/// Registry constructor. Parameters: `hash` (enum, default `sha256`), `iterations`, `out_len`
/// (`u32`; defaults and ranges in `algo.toml`). Unknown names and values are errors.
pub fn new(params: &Params) -> Result<Box<dyn PwHash>> {
    let v = params.validate(&SPECS)?;
    let name = v.get_str("hash").ok_or(Error::ParamMissing("hash"))?;
    let hash = H::parse(name).ok_or(Error::ParamOutOfRange("hash"))?;
    Ok(Box::new(Impl {
        hash,
        iterations: get(&v, "iterations")?,
        out_len: get(&v, "out_len")? as usize,
    }))
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

    fn u32_of(v: &J, k: &str) -> u32 {
        u32::try_from(v[k].as_u64().unwrap()).unwrap()
    }

    fn inst(v: &J) -> Box<dyn PwHash> {
        let p = Params::new()
            .with("hash", Value::Str(v["hash"].as_str().unwrap().into()))
            .with("iterations", Value::U32(u32_of(v, "iterations")))
            .with("out_len", Value::U32(u32_of(v, "out_len")));
        new(&p).unwrap()
    }

    #[test]
    fn known_answers() {
        let doc = load("vectors.json");
        assert_eq!(doc["algorithm"], "pbkdf2");
        let mut ran = 0usize;
        for v in doc["vectors"].as_array().unwrap() {
            let id = v["id"].as_str().unwrap();
            if v["heavy"].as_bool().unwrap_or(false)
                && std::env::var_os("NEXTSSL_HEAVY_KAT").is_none()
            {
                continue;
            }
            let pw = unhex(v["password_hex"].as_str().unwrap());
            let salt = unhex(v["salt_hex"].as_str().unwrap());
            let want = unhex(v["out_hex"].as_str().unwrap());
            let h = inst(v);
            let mut got = vec![0u8; want.len()];
            h.derive(&pw, &salt, &mut got).unwrap();
            assert_eq!(got, want, "{id}");
            let phc = h.hash(&pw, &salt).unwrap();
            assert!(phc.starts_with(&format!("${}$", {
                let n = v["hash"].as_str().unwrap();
                format!("pbkdf2-{n}")
            })));
            assert!(h.verify(&pw, &phc).unwrap(), "{id} verify");
            let mut wrong = pw.clone();
            wrong.push(b'x');
            assert!(!h.verify(&wrong, &phc).unwrap(), "{id} wrong password");
            ran += 1;
        }
        assert!(ran >= 160, "too few vectors ran: {ran}");
    }

    #[test]
    fn unknown_hash_is_an_error_not_a_fallback() {
        for bad in ["sha1", "md5", "SHA256", ""] {
            let r = new(&Params::new().with("hash", Value::Str(bad.into())));
            assert!(matches!(r, Err(Error::ParamOutOfRange("hash"))), "{bad}");
        }
    }

    #[test]
    fn phc_id_must_match_the_configured_hash() {
        let sha256 = new(&Params::new().with("iterations", Value::U32(5))).unwrap();
        let phc = sha256.hash(b"pw", &[1u8; 16]).unwrap();
        assert!(phc.starts_with("$pbkdf2-sha256$i=5$"));
        let sha512 = new(&Params::new()
            .with("hash", Value::Str("sha512".into()))
            .with("iterations", Value::U32(5)))
        .unwrap();
        assert!(sha512.verify(b"pw", &phc).is_err(), "other hash id refused");
        assert!(sha256.verify(b"pw", &phc).unwrap());
    }

    #[test]
    fn input_and_param_limits() {
        let h = new(&Params::new()).unwrap();
        let mut out = [0u8; 16];
        for n in [0, 3, 65] {
            assert!(matches!(
                h.derive(b"pw", &vec![0u8; n], &mut out),
                Err(Error::InvalidLength { what: "salt", .. })
            ));
        }
        for n in [0, 15, 1025] {
            assert!(matches!(
                h.derive(b"pw", &[0u8; 16], &mut vec![0u8; n]),
                Err(Error::InvalidLength { what: "out", .. })
            ));
        }
        let bad = |name: &str, v: u32| new(&Params::new().with(name, Value::U32(v))).err().unwrap();
        assert!(matches!(bad("iterations", 0), Error::ParamOutOfRange(_)));
        assert!(matches!(
            bad("iterations", 16777217),
            Error::ParamOutOfRange(_)
        ));
        assert!(matches!(bad("out_len", 15), Error::ParamOutOfRange(_)));
        let hostile = "$pbkdf2-sha256$i=16777217$c29tZXNhbHRzb21lc2FsdA$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";
        assert!(h.verify(b"pw", hostile).is_err());
    }
}
