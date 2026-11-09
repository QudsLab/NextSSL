//! Adapter: RustCrypto `argon2` -> nextssl `PwHash` (Argon2i, version 0x13).
//!
//! Policy (the DoS guard): `m_kib` 8..=4194304, `t` 1..=1024, `p` 1..=255 (and `m_kib >= 8 p`,
//! an Argon2 requirement), salt 16..=64 bytes, output 16..=1024 bytes. The same ranges apply to
//! parameters read from a PHC string, *before* any memory is allocated.
//!
//! PHC strings are written and parsed by `nextssl_core::phc` (strict: exactly
//! `$argon2i$v=19$m=<m>,t=<t>,p=<p>$<salt>$<hash>`, canonical decimals, canonical unpadded
//! standard base64, ranges checked before anything is decoded). Upstream's `phc` crate caps
//! salt/hash at 48/64 bytes, below our schema, so it is not used.

use argon2::{Algorithm, Argon2, Params as ArgonParams, Version};
use nextssl_core::phc::{self, PhcParam, PhcSpec};
use nextssl_core::{
    ct_eq, Error, Len, ParamSpec, ParamType, Params, PwHash, Result, Sizes, Value, Zeroizing,
    MAX_INPUT_LEN,
};

const M_MIN: u32 = 8;
const M_MAX: u32 = 4_194_304;
const T_MIN: u32 = 1;
const T_MAX: u32 = 1024;
const P_MIN: u32 = 1;
const P_MAX: u32 = 255;
const SALT_MIN: usize = 16;
const SALT_MAX: usize = 64;
const OUT_MIN: usize = 16;
const OUT_MAX: usize = 1024;

/// PHC shape and policy; the ranges are the same constants `Cost::check` uses.
const PHC: PhcSpec = PhcSpec {
    id: "argon2i",
    version: Some(19),
    params: &[
        PhcParam {
            name: "m",
            min: M_MIN,
            max: M_MAX,
        },
        PhcParam {
            name: "t",
            min: T_MIN,
            max: T_MAX,
        },
        PhcParam {
            name: "p",
            min: P_MIN,
            max: P_MAX,
        },
    ],
    salt: Len::range(SALT_MIN, SALT_MAX),
    hash: Len::range(OUT_MIN, OUT_MAX),
};

/// Mirror of the `[params]` table in `algo.toml`, used so `new` validates exactly like the
/// registry does (unknown name, wrong type, out of range, defaults filled in).
const SPECS: [ParamSpec; 4] = [
    spec("m_kib", M_MIN, M_MAX, 65_536),
    spec("t", T_MIN, T_MAX, 3),
    spec("p", P_MIN, P_MAX, 1),
    spec("out_len", OUT_MIN as u32, OUT_MAX as u32, 32),
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

#[derive(Clone, Copy)]
struct Cost {
    m: u32,
    t: u32,
    p: u32,
}

impl Cost {
    fn check(self) -> Result<()> {
        in_range("m_kib", self.m, M_MIN, M_MAX)?;
        in_range("t", self.t, T_MIN, T_MAX)?;
        in_range("p", self.p, P_MIN, P_MAX)?;
        // Argon2 needs at least 8 blocks per lane.
        if self.m < self.p * 8 {
            return Err(Error::ParamOutOfRange("m_kib"));
        }
        Ok(())
    }
}

fn in_range(name: &'static str, v: u32, min: u32, max: u32) -> Result<()> {
    if (min..=max).contains(&v) {
        Ok(())
    } else {
        Err(Error::ParamOutOfRange(name))
    }
}

fn check_salt(salt: &[u8]) -> Result<()> {
    Len::range(SALT_MIN, SALT_MAX).check("salt", salt.len())
}

fn check_password(password: &[u8]) -> Result<()> {
    Len::range(0, MAX_INPUT_LEN).check("password", password.len())
}

/// Raw Argon2i. Callers have already validated `cost`, `salt` and `out.len()`.
fn argon2i_into(cost: Cost, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
    let params = ArgonParams::new(cost.m, cost.t, cost.p, Some(out.len()))
        .map_err(|_| Error::Backend("argon2 rejected parameters"))?;
    Argon2::new(Algorithm::Argon2i, Version::V0x13, params)
        .hash_password_into(password, salt, out)
        .map_err(|_| Error::Backend("argon2 failed"))
}

fn encode_phc(cost: Cost, salt: &[u8], hash: &[u8]) -> Result<String> {
    phc::write(&PHC, &[cost.m, cost.t, cost.p], salt, hash)
}

struct Parsed {
    cost: Cost,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

fn parse_phc(s: &str) -> Result<Parsed> {
    let p = phc::parse(s, &PHC)?;
    let cost = Cost {
        m: p.params[0],
        t: p.params[1],
        p: p.params[2],
    };
    // Cross-parameter rule, checked before any memory is allocated for hashing.
    cost.check()?;
    Ok(Parsed {
        cost,
        salt: p.salt,
        hash: p.hash,
    })
}

struct Argon2iHash {
    cost: Cost,
    out_len: usize,
}

impl PwHash for Argon2iHash {
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
        encode_phc(self.cost, salt, &out)
    }

    fn verify(&self, password: &[u8], phc: &str) -> Result<bool> {
        check_password(password)?;
        let p = parse_phc(phc)?;
        let mut mine = Zeroizing::new(vec![0u8; p.hash.len()]);
        argon2i_into(p.cost, password, &p.salt, &mut mine)?;
        Ok(ct_eq(&mine, &p.hash))
    }

    fn derive(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
        check_password(password)?;
        check_salt(salt)?;
        Len::range(OUT_MIN, OUT_MAX).check("out", out.len())?;
        argon2i_into(self.cost, password, salt, out)
    }
}

fn get(params: &Params, name: &'static str) -> Result<u32> {
    match params.get(name) {
        Some(Value::U32(v)) => Ok(*v),
        _ => Err(Error::ParamType(name)),
    }
}

/// Registry constructor. Parameters: `m_kib`, `t`, `p`, `out_len` (all `u32`; defaults and
/// ranges in `algo.toml`). Unknown names and out-of-range values are errors.
pub fn new(params: &Params) -> Result<Box<dyn PwHash>> {
    let v = params.validate(&SPECS)?;
    let cost = Cost {
        m: get(&v, "m_kib")?,
        t: get(&v, "t")?,
        p: get(&v, "p")?,
    };
    cost.check()?;
    Ok(Box::new(Argon2iHash {
        cost,
        out_len: get(&v, "out_len")? as usize,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as Json;

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn vectors(src: &str) -> Vec<Json> {
        let doc: Json = serde_json::from_str(src).unwrap();
        doc["vectors"].as_array().unwrap().clone()
    }

    fn u32_of(v: &Json, k: &str) -> u32 {
        u32::try_from(v[k].as_u64().unwrap()).unwrap()
    }

    fn inst(v: &Json) -> Box<dyn PwHash> {
        let p = Params::new()
            .with("m_kib", Value::U32(u32_of(v, "m_kib")))
            .with("t", Value::U32(u32_of(v, "t")))
            .with("p", Value::U32(u32_of(v, "p")))
            .with("out_len", Value::U32(u32_of(v, "out_len")));
        new(&p).unwrap()
    }

    /// RFC 9106 section 5.2 uses a secret and associated data, which `PwHash` does not expose,
    /// so this checks the pinned upstream directly.
    #[test]
    fn rfc9106_section_5_2_upstream() {
        let v: Json = serde_json::from_str(include_str!("kat/rfc9106.json")).unwrap();
        let h = |k: &str| unhex(v[k].as_str().unwrap());
        let ad = argon2::AssociatedData::new(&h("ad_hex")).unwrap();
        let params = argon2::ParamsBuilder::new()
            .m_cost(u32_of(&v, "m_kib"))
            .t_cost(u32_of(&v, "t"))
            .p_cost(u32_of(&v, "p"))
            .data(ad)
            .output_len(u32_of(&v, "out_len") as usize)
            .build()
            .unwrap();
        let secret = h("secret_hex");
        let a =
            Argon2::new_with_secret(&secret, Algorithm::Argon2i, Version::V0x13, params).unwrap();
        let mut out = [0u8; 32];
        a.hash_password_into(&h("password_hex"), &h("salt_hex"), &mut out)
            .unwrap();
        assert_eq!(out.to_vec(), h("tag_hex"));
    }

    /// phc-winner-argon2 `src/test.c` lines 233-264 (8-byte salts, below our minimum): the raw
    /// upstream must match, our PHC writer must reproduce the reference string, our PHC parser
    /// must reject it only for the short salt, and the glue must refuse the short salt.
    #[test]
    fn phc_winner_argon2_test_c() {
        let list = vectors(include_str!("kat/phc-winner-argon2-test-c.json"));
        assert_eq!(list.len(), 8);
        for v in &list {
            let pw = unhex(v["password_hex"].as_str().unwrap());
            let salt = unhex(v["salt_hex"].as_str().unwrap());
            let want = unhex(v["out_hex"].as_str().unwrap());
            let cost = Cost {
                m: u32_of(v, "m_kib"),
                t: u32_of(v, "t"),
                p: u32_of(v, "p"),
            };
            let mut out = vec![0u8; 32];
            argon2i_into(cost, &pw, &salt, &mut out).unwrap();
            assert_eq!(out, want, "{}", v["id"]);
            assert_eq!(
                // The reference uses 8-byte salts; write with a spec that allows them.
                phc::write(
                    &PhcSpec {
                        salt: Len::range(8, 64),
                        ..PHC
                    },
                    &[cost.m, cost.t, cost.p],
                    &salt,
                    &out
                )
                .unwrap(),
                v["phc"].as_str().unwrap(),
                "{}",
                v["id"]
            );
            // Short salt: glue refuses, parser refuses.
            assert!(matches!(
                inst(v).derive(&pw, &salt, &mut out),
                Err(Error::InvalidLength { what: "salt", .. })
            ));
            assert!(matches!(
                inst(v).verify(&pw, v["phc"].as_str().unwrap()),
                Err(Error::InvalidLength { what: "salt", .. })
            ));
        }
    }

    /// Independent reference vectors (argon2-cffi / phc-winner-argon2 C) through the glue.
    #[test]
    fn reference_vectors_through_glue() {
        let list = vectors(include_str!("kat/argon2-cffi-reference.json"));
        assert!(list.len() >= 9);
        for v in &list {
            let pw = unhex(v["password_hex"].as_str().unwrap());
            let salt = unhex(v["salt_hex"].as_str().unwrap());
            let want = unhex(v["out_hex"].as_str().unwrap());
            let phc = v["phc"].as_str().unwrap();
            let h = inst(v);

            let mut out = vec![0u8; want.len()];
            h.derive(&pw, &salt, &mut out).unwrap();
            assert_eq!(out, want, "{}", v["id"]);
            assert_eq!(h.hash(&pw, &salt).unwrap(), phc, "{}", v["id"]);
            // verify uses the string's own parameters, not the instance's.
            let default = new(&Params::new()).unwrap();
            assert!(default.verify(&pw, phc).unwrap(), "{}", v["id"]);
            let mut wrong = pw.clone();
            wrong.push(b'x');
            assert!(!default.verify(&wrong, phc).unwrap(), "{}", v["id"]);
        }
    }

    #[test]
    fn input_and_param_limits() {
        let h = new(&Params::new()).unwrap();
        let mut out = [0u8; 32];
        for n in [0usize, 15, 65] {
            assert!(matches!(
                h.derive(b"pw", &vec![0u8; n], &mut out),
                Err(Error::InvalidLength { what: "salt", .. })
            ));
            assert!(h.hash(b"pw", &vec![0u8; n]).is_err());
        }
        for n in [0usize, 15, 1025] {
            assert!(matches!(
                h.derive(b"pw", &[0u8; 16], &mut vec![0u8; n]),
                Err(Error::InvalidLength { what: "out", .. })
            ));
        }
        let bad = |name: &str, v: u32| new(&Params::new().with(name, Value::U32(v))).err().unwrap();
        assert!(matches!(bad("m_kib", 7), Error::ParamOutOfRange(_)));
        assert!(matches!(bad("m_kib", 4_194_305), Error::ParamOutOfRange(_)));
        assert!(matches!(bad("t", 0), Error::ParamOutOfRange(_)));
        assert!(matches!(bad("t", 1025), Error::ParamOutOfRange(_)));
        assert!(matches!(bad("p", 0), Error::ParamOutOfRange(_)));
        assert!(matches!(bad("p", 256), Error::ParamOutOfRange(_)));
        assert!(matches!(bad("out_len", 15), Error::ParamOutOfRange(_)));
        assert!(matches!(bad("out_len", 1025), Error::ParamOutOfRange(_)));
        // m < 8 p
        let p = Params::new()
            .with("m_kib", Value::U32(64))
            .with("p", Value::U32(9));
        assert!(matches!(new(&p), Err(Error::ParamOutOfRange("m_kib"))));
        let unknown = Params::new().with("salt", Value::Bytes(vec![0; 16]));
        assert!(matches!(new(&unknown), Err(Error::ParamUnknown)));
        let wrong_ty = Params::new().with("t", Value::U64(3));
        assert!(matches!(new(&wrong_ty), Err(Error::ParamType(_))));
    }

    #[test]
    fn hostile_phc_strings_are_rejected_before_any_work() {
        let h = new(&Params::new()).unwrap();
        let s = "c29tZXNhbHRzb21lc2FsdA"; // 16 bytes
        let hs = "CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"; // 32 bytes
        let ok = format!("$argon2i$v=19$m=8,t=1,p=1${s}${hs}");
        // The well-formed string parses (wrong password, so Ok(false), no error).
        assert!(!h.verify(b"pw", &ok).unwrap());

        let cases = [
            // DoS: memory, time, lanes outside the schema
            format!("$argon2i$v=19$m=4294967295,t=1,p=1${s}${hs}"),
            format!("$argon2i$v=19$m=4194305,t=1,p=1${s}${hs}"),
            format!("$argon2i$v=19$m=8,t=4294967295,p=1${s}${hs}"),
            format!("$argon2i$v=19$m=8,t=1025,p=1${s}${hs}"),
            format!("$argon2i$v=19$m=8,t=0,p=1${s}${hs}"),
            format!("$argon2i$v=19$m=8,t=1,p=0${s}${hs}"),
            format!("$argon2i$v=19$m=8192,t=1,p=256${s}${hs}"),
            format!("$argon2i$v=19$m=64,t=1,p=9${s}${hs}"), // m < 8p
            format!("$argon2i$v=19$m=99999999999,t=1,p=1${s}${hs}"),
            // wrong algorithm / version
            format!("$argon2id$v=19$m=8,t=1,p=1${s}${hs}"),
            format!("$argon2d$v=19$m=8,t=1,p=1${s}${hs}"),
            format!("$scrypt$v=19$m=8,t=1,p=1${s}${hs}"),
            format!("$argon2i$v=16$m=8,t=1,p=1${s}${hs}"),
            format!("$argon2i$m=8,t=1,p=1${s}${hs}"),
            // structure
            format!("argon2i$v=19$m=8,t=1,p=1${s}${hs}"),
            format!("$argon2i$v=19$m=8,t=1,p=1${s}"),
            format!("$argon2i$v=19$m=8,t=1,p=1${s}${hs}$"),
            format!("$argon2i$v=19$t=1,m=8,p=1${s}${hs}"),
            format!("$argon2i$v=19$m=8,t=1${s}${hs}"),
            format!("$argon2i$v=19$m=8,t=1,p=1,keyid=AA${s}${hs}"),
            format!("$argon2i$v=19$m=08,t=1,p=1${s}${hs}"),
            format!("$argon2i$v=19$m=+8,t=1,p=1${s}${hs}"),
            format!("$argon2i$v=19$m=8,t=1,p=1 ${s}${hs}"),
            format!("$argon2i$v=19$m=,t=1,p=1${s}${hs}"),
            // encoding: padding, bad alphabet, non-canonical trailing bits, short salt/hash
            format!("$argon2i$v=19$m=8,t=1,p=1${s}==${hs}"),
            format!("$argon2i$v=19$m=8,t=1,p=1$c29tZXNhbHRzb21lc2FsdB${hs}"),
            format!("$argon2i$v=19$m=8,t=1,p=1$c29tZXNhbHRzb21lc2F-dA${hs}"),
            format!("$argon2i$v=19$m=8,t=1,p=1$c29tZXNhbHQ${hs}"),
            format!("$argon2i$v=19$m=8,t=1,p=1${s}$AAAA"),
            format!("$argon2i$v=19$m=8,t=1,p=1${s}$"),
            format!("$argon2i$v=19$m=8,t=1,p=1$${hs}"),
            String::new(),
            "$".repeat(5000),
        ];
        for c in &cases {
            assert!(h.verify(b"pw", c).is_err(), "must reject: {c:.80}");
        }
        // Non-ASCII.
        assert!(h.verify(b"pw", "$argon2i$v=19$m=8,t=1,p=1$é$é").is_err());
    }
}
