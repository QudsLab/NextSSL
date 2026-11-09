//! Adapter: RustCrypto `balloon-hash` (Balloon hashing, Boneh/Corrigan-Gibbs/Schechter 2016,
//! single-core `Algorithm::Balloon`, SHA-256) -> nextssl `PwHash`.
//!
//! UNVERIFIED tier: see `algo.toml`. Policy (the DoS guard): `s_cost` (blocks of 32 bytes)
//! 1..=1048576 (32 MiB), `t_cost` 1..=64, parallelism fixed at 1, salt 0..=64 bytes (the
//! published vectors use an empty salt; callers should use 16 bytes or more), output exactly
//! 32 bytes. The same ranges apply to a PHC string read by `verify`, before any allocation.
//! PHC form (ours; the id carries the hash): `$balloon-sha256$v=1$s=<n>,t=<n>$<salt>$<hash>`.

use balloon_hash::{Algorithm, Balloon, Params as BParams};
use nextssl_core::phc::{self, PhcParam, PhcSpec};
use nextssl_core::{
    ct_eq, Error, Len, ParamSpec, ParamType, Params, PwHash, Result, Sizes, Value, Zeroizing,
    MAX_INPUT_LEN,
};
use sha2::Sha256;

const S_MIN: u32 = 1;
const S_MAX: u32 = 1_048_576;
const T_MIN: u32 = 1;
const T_MAX: u32 = 64;
const SALT_MIN: usize = 0;
const SALT_MAX: usize = 64;
const OUT_LEN: usize = 32;

const PHC: PhcSpec = PhcSpec {
    id: "balloon-sha256",
    version: Some(1),
    params: &[
        PhcParam {
            name: "s",
            min: S_MIN,
            max: S_MAX,
        },
        PhcParam {
            name: "t",
            min: T_MIN,
            max: T_MAX,
        },
    ],
    salt: Len::range(SALT_MIN, SALT_MAX),
    hash: Len::fixed(OUT_LEN),
};

const SPECS: [ParamSpec; 2] = [
    spec("s_cost", S_MIN, S_MAX, 65_536),
    spec("t_cost", T_MIN, T_MAX, 3),
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

/// Raw Balloon. Callers have validated `s`, `t`, `salt` and `out.len() == 32`.
fn run(s: u32, t: u32, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
    let params =
        BParams::new(s, t, 1).map_err(|_| Error::Backend("balloon rejected parameters"))?;
    Balloon::<Sha256>::new(Algorithm::Balloon, params, None)
        .hash_password_into(password, salt, out)
        .map_err(|_| Error::Backend("balloon failed"))
}

struct Impl {
    s: u32,
    t: u32,
}

impl PwHash for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            salt: Some(Len::range(SALT_MIN, SALT_MAX)),
            out: Some(Len::fixed(OUT_LEN)),
            ..Sizes::NONE
        }
    }

    fn hash(&self, password: &[u8], salt: &[u8]) -> Result<String> {
        let mut out = Zeroizing::new(vec![0u8; OUT_LEN]);
        self.derive(password, salt, &mut out)?;
        phc::write(&PHC, &[self.s, self.t], salt, &out)
    }

    fn verify(&self, password: &[u8], phc_str: &str) -> Result<bool> {
        check_password(password)?;
        let p = phc::parse(phc_str, &PHC)?;
        let mut mine = Zeroizing::new(vec![0u8; OUT_LEN]);
        run(p.params[0], p.params[1], password, &p.salt, &mut mine)?;
        Ok(ct_eq(&mine, &p.hash))
    }

    fn derive(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
        check_password(password)?;
        check_salt(salt)?;
        Len::fixed(OUT_LEN).check("out", out.len())?;
        run(self.s, self.t, password, salt, out)
    }
}

fn get(params: &Params, name: &'static str) -> Result<u32> {
    match params.get(name) {
        Some(Value::U32(v)) => Ok(*v),
        _ => Err(Error::ParamType(name)),
    }
}

/// Registry constructor. Parameters: `s_cost`, `t_cost` (`u32`; defaults and ranges in `algo.toml`).
pub fn new(params: &Params) -> Result<Box<dyn PwHash>> {
    let v = params.validate(&SPECS)?;
    Ok(Box::new(Impl {
        s: get(&v, "s_cost")?,
        t: get(&v, "t_cost")?,
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
            .with("s_cost", Value::U32(u32_of(v, "s_cost")))
            .with("t_cost", Value::U32(u32_of(v, "t_cost")));
        new(&p).unwrap()
    }

    /// Vectors flagged `heavy` (very many iterations or ~1 GiB) run only with NEXTSSL_HEAVY_KAT=1.
    fn skip_heavy(v: &J) -> bool {
        v["heavy"].as_bool().unwrap_or(false) && std::env::var_os("NEXTSSL_HEAVY_KAT").is_none()
    }

    #[test]
    fn sizes_match_metadata() {
        let s = new(&Params::new()).unwrap().sizes();
        assert_eq!(s.salt, Some(Len::range(0, 64)));
        assert_eq!(s.out, Some(Len::fixed(32)));
    }

    #[test]
    fn known_answers() {
        let (mut ran, mut skipped) = (0usize, 0usize);
        for file in ["balloon-hash-tests.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "balloon");
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
        assert!(ran >= 5, "too few vectors ran: {ran}");
        eprintln!(
            "balloon: {ran} vectors ran, {skipped} heavy vectors skipped (set NEXTSSL_HEAVY_KAT=1)"
        );
    }

    #[test]
    fn input_and_param_limits() {
        let h = new(&Params::new()).unwrap();
        let mut out = [0u8; 32];
        for n in [65] {
            assert!(
                matches!(
                    h.derive(b"pw", &vec![0u8; n], &mut out),
                    Err(Error::InvalidLength { what: "salt", .. })
                ),
                "salt {n}"
            );
            assert!(h.hash(b"pw", &vec![0u8; n]).is_err());
        }
        for n in [0, 31, 33] {
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
            matches!(bad("s_cost", 0), Error::ParamOutOfRange(_)),
            "s_cost 0"
        );
        assert!(
            matches!(bad("s_cost", 1048577), Error::ParamOutOfRange(_)),
            "s_cost 1048577"
        );
        assert!(
            matches!(bad("t_cost", 0), Error::ParamOutOfRange(_)),
            "t_cost 0"
        );
        assert!(
            matches!(bad("t_cost", 65), Error::ParamOutOfRange(_)),
            "t_cost 65"
        );

        let unknown = Params::new().with("salt", Value::Bytes(vec![0; 16]));
        assert!(matches!(new(&unknown), Err(Error::ParamUnknown)));
        let wrong_ty = Params::new().with("s_cost", Value::U64(12));
        assert!(matches!(new(&wrong_ty), Err(Error::ParamType(_))));
    }

    #[test]
    fn hostile_phc_strings_are_rejected_before_any_work() {
        let h = new(&Params::new()).unwrap();
        let s = "c29tZXNhbHRzb21lc2FsdA"; // 16 bytes
        let hs = "CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"; // 32 bytes
        let ok = format!("$balloon-sha256$v=1$s=8,t=1${s}${hs}");
        // Well-formed: parses, wrong password, so Ok(false).
        assert!(!h.verify(b"pw", &ok).unwrap());
        let cases = [
            format!("$balloon-sha256$v=1$s=0,t=1${s}${hs}"),
            format!("$balloon-sha256$v=1$s=1048577,t=1${s}${hs}"),
            format!("$balloon-sha256$v=1$s=8,t=0${s}${hs}"),
            format!("$balloon-sha256$v=1$s=8,t=65${s}${hs}"),
            format!("$balloon-sha256$v=1$s=4294967295,t=1${s}${hs}"),
            format!("$balloon-sha256$v=1$s=8,t=4294967295${s}${hs}"),
            format!("$balloon-sha256$v=1$s=8${s}${hs}"),
            format!("$balloon-sha256$v=1$t=1,s=8${s}${hs}"),
            format!("$balloon-sha256$v=1$s=8,t=1,p=1${s}${hs}"),
            format!("$balloon-sha256$s=8,t=1${s}${hs}"),
            format!("$balloon-sha256$v=2$s=8,t=1${s}${hs}"),
            format!("$balloon$v=1$s=8,t=1${s}${hs}"),
            format!("$argon2id$v=1$s=8,t=1${s}${hs}"),
            format!("$balloon-sha256$v=1$s=08,t=1${s}${hs}"),
            format!("$balloon-sha256$v=1$s=+8,t=1${s}${hs}"),
            format!("$balloon-sha256$v=1$s=8,t=1${s}"),
            format!("$balloon-sha256$v=1$s=8,t=1${s}${hs}$"),
            format!("balloon-sha256$v=1$s=8,t=1${s}${hs}"),
            format!("$balloon-sha256$v=1$s=8,t=1${s}==${hs}"),
            format!("$balloon-sha256$v=1$s=8,t=1${s}$AAAA"),
            format!("$balloon-sha256$v=1$s=8,t=1${s}$"),
            String::new(),
            "$".repeat(5000),
        ];
        for c in &cases {
            assert!(h.verify(b"pw", c).is_err(), "must reject: {c:.80}");
        }
        assert!(h.verify(b"pw", "$balloon-sha256$é$é$é").is_err());
    }
}
