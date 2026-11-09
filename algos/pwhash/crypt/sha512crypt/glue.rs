//! Adapter: RustCrypto `sha-crypt` (SHA-512-crypt, Ulrich Drepper's specification) -> nextssl `PwHash`.
//!
//! String form: `$6$[rounds=<n>$]<salt>$86 characters` (crypt(3) Base64). `rounds` 1000..=10000000
//! (the spec clamps below 1000 silently; here it is an error), written only when it is not
//! the specification default 5000. The salt is 1..=16 characters of `./0-9A-Za-z` (the
//! specification truncates longer salts silently; here it is an error). Password 0..=1024
//! bytes (the algorithm is quadratic in the password length). Raw output is the 64-byte
//! digest. `verify` parses strictly: canonical decimals, exact lengths and alphabet, canonical
//! trailing bits, rounds checked before any work.

use base64ct::{Base64ShaCrypt, Encoding};
use nextssl_core::{
    ct_eq, Error, Len, ParamSpec, ParamType, Params, PwHash, Result, Sizes, Value, Zeroizing,
};

const ROUNDS_MIN: u32 = 1_000;
const ROUNDS_MAX: u32 = 10_000_000;
const ROUNDS_DEFAULT: u32 = 100_000;
const ROUNDS_SPEC_DEFAULT: u32 = 5_000;
const SALT_MIN: usize = 1;
const SALT_MAX: usize = 16;
const PW_MAX: usize = 1024;
const OUT_LEN: usize = 64;
const HASH_CHARS: usize = 86;
const PREFIX: &str = "$6$";

const SPECS: [ParamSpec; 1] = [ParamSpec {
    name: "rounds",
    ty: ParamType::U32,
    min: ROUNDS_MIN as u64,
    max: ROUNDS_MAX as u64,
    required: false,
    default: Some(ROUNDS_DEFAULT as u64),
}];

fn check_password(password: &[u8]) -> Result<()> {
    Len::range(0, PW_MAX).check("password", password.len())
}

fn salt_char_ok(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'.' || c == b'/'
}

fn check_salt(salt: &[u8]) -> Result<()> {
    Len::range(SALT_MIN, SALT_MAX).check("salt", salt.len())?;
    if !salt.iter().all(|&c| salt_char_ok(c)) {
        return Err(Error::InvalidInput("sha-crypt salt must use ./0-9A-Za-z"));
    }
    Ok(())
}

/// Output byte order of the crypt(3) string: the digest bytes are emitted in this order before
/// the crypt Base64 step. Copied verbatim from sha-crypt 0.6.0 `src/mcf.rs`
/// (`TRANSPOSITION_TABLE`; the crate keeps it private behind its `password-hash` feature);
/// the Drepper vectors verify it.
const ORDER: [usize; OUT_LEN] = [
    42, 21, 0, 1, 43, 22, 23, 2, 44, 45, 24, 3, 4, 46, 25, 26, 5, 47, 48, 27, 6, 7, 49, 28, 29, 8,
    50, 51, 30, 9, 10, 52, 31, 32, 11, 53, 54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15, 16, 58,
    37, 38, 17, 59, 60, 39, 18, 19, 61, 40, 41, 20, 62, 63,
];

/// Raw digest in crypt order. Callers have validated everything.
fn run(rounds: u32, password: &[u8], salt: &[u8]) -> Result<[u8; OUT_LEN]> {
    let params = sha_crypt::Params::new(rounds).map_err(|_| Error::ParamOutOfRange("rounds"))?;
    let raw = Zeroizing::new(sha_crypt::sha512_crypt(password, salt, params));
    let mut out = [0u8; OUT_LEN];
    for (o, &i) in out.iter_mut().zip(ORDER.iter()) {
        *o = raw[i];
    }
    Ok(out)
}

fn encode(rounds: u32, salt: &[u8], digest: &[u8]) -> Result<String> {
    let salt = core::str::from_utf8(salt).map_err(|_| Error::InvalidInput("salt"))?;
    let mut s = String::from(PREFIX);
    if rounds != ROUNDS_SPEC_DEFAULT {
        s.push_str(&format!("rounds={rounds}$"));
    }
    s.push_str(salt);
    s.push('$');
    s.push_str(&Base64ShaCrypt::encode_string(digest));
    Ok(s)
}

struct Parsed {
    rounds: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

fn parse(s: &str) -> Result<Parsed> {
    const BAD: Error = Error::InvalidInput("malformed sha-crypt string");
    if !s.is_ascii() || s.len() > 128 {
        return Err(BAD);
    }
    let rest = s.strip_prefix(PREFIX).ok_or(BAD)?;
    let (rounds, rest) = match rest.strip_prefix("rounds=") {
        Some(r) => {
            let (num, tail) = r.split_once('$').ok_or(BAD)?;
            let nb = num.as_bytes();
            if nb.is_empty()
                || nb.len() > 9
                || !nb.iter().all(u8::is_ascii_digit)
                || (nb.len() > 1 && nb[0] == b'0')
            {
                return Err(BAD);
            }
            let n: u32 = num.parse().map_err(|_| BAD)?;
            (n, tail)
        }
        None => (ROUNDS_SPEC_DEFAULT, rest),
    };
    if !(ROUNDS_MIN..=ROUNDS_MAX).contains(&rounds) {
        return Err(Error::ParamOutOfRange("rounds"));
    }
    let (salt, hash) = rest.split_once('$').ok_or(BAD)?;
    check_salt(salt.as_bytes()).map_err(|_| BAD)?;
    if hash.len() != HASH_CHARS || !hash.bytes().all(salt_char_ok) {
        return Err(BAD);
    }
    let raw = Base64ShaCrypt::decode_vec(hash).map_err(|_| BAD)?;
    if Base64ShaCrypt::encode_string(&raw) != hash {
        return Err(BAD);
    }
    Ok(Parsed {
        rounds,
        salt: salt.as_bytes().to_vec(),
        hash: raw,
    })
}

struct Impl {
    rounds: u32,
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
        check_password(password)?;
        check_salt(salt)?;
        let d = Zeroizing::new(run(self.rounds, password, salt)?);
        encode(self.rounds, salt, &d[..])
    }

    fn verify(&self, password: &[u8], phc: &str) -> Result<bool> {
        check_password(password)?;
        let p = parse(phc)?;
        let d = Zeroizing::new(run(p.rounds, password, &p.salt)?);
        Ok(ct_eq(&d[..], &p.hash))
    }

    fn derive(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
        check_password(password)?;
        check_salt(salt)?;
        Len::fixed(OUT_LEN).check("out", out.len())?;
        let d = Zeroizing::new(run(self.rounds, password, salt)?);
        out.copy_from_slice(&d[..]);
        Ok(())
    }
}

/// Registry constructor. Parameter: `rounds` (`u32`, 1000..=10000000, default 100000).
pub fn new(params: &Params) -> Result<Box<dyn PwHash>> {
    let v = params.validate(&SPECS)?;
    match v.get("rounds") {
        Some(Value::U32(r)) => Ok(Box::new(Impl { rounds: *r })),
        _ => Err(Error::ParamType("rounds")),
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
        let p = Params::new().with("rounds", Value::U32(u32_of(v, "rounds")));
        new(&p).unwrap()
    }

    /// Vectors flagged `heavy` (very many iterations or ~1 GiB) run only with NEXTSSL_HEAVY_KAT=1.
    fn skip_heavy(v: &J) -> bool {
        v["heavy"].as_bool().unwrap_or(false) && std::env::var_os("NEXTSSL_HEAVY_KAT").is_none()
    }

    #[test]
    fn sizes_match_metadata() {
        let s = new(&Params::new()).unwrap().sizes();
        assert_eq!(s.salt, Some(Len::range(1, 16)));
        assert_eq!(s.out, Some(Len::fixed(64)));
    }

    #[test]
    fn known_answers() {
        let (mut ran, mut skipped) = (0usize, 0usize);
        for file in ["drepper.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "sha512crypt");
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
        assert!(ran >= 7, "too few vectors ran: {ran}");
        eprintln!("sha512crypt: {ran} vectors ran, {skipped} heavy vectors skipped (set NEXTSSL_HEAVY_KAT=1)");
    }

    #[test]
    fn input_and_param_limits() {
        let h = new(&Params::new()).unwrap();
        let mut out = [0u8; 64];
        for n in [0, 17] {
            assert!(
                matches!(
                    h.derive(b"pw", &vec![0u8; n], &mut out),
                    Err(Error::InvalidLength { what: "salt", .. })
                ),
                "salt {n}"
            );
            assert!(h.hash(b"pw", &vec![0u8; n]).is_err());
        }
        for n in [0, 63, 65] {
            assert!(
                matches!(
                    h.derive(b"pw", &[b'a'; 16], &mut vec![0u8; n]),
                    Err(Error::InvalidLength { what: "out", .. })
                ),
                "out {n}"
            );
        }
        let bad = |name: &str, v: u32| new(&Params::new().with(name, Value::U32(v))).err().unwrap();
        assert!(
            matches!(bad("rounds", 999), Error::ParamOutOfRange(_)),
            "rounds 999"
        );
        assert!(
            matches!(bad("rounds", 10000001), Error::ParamOutOfRange(_)),
            "rounds 10000001"
        );

        let unknown = Params::new().with("salt", Value::Bytes(vec![0; 16]));
        assert!(matches!(new(&unknown), Err(Error::ParamUnknown)));
        let wrong_ty = Params::new().with("rounds", Value::U64(12));
        assert!(matches!(new(&wrong_ty), Err(Error::ParamType(_))));
    }

    #[test]
    fn hostile_phc_strings_are_rejected_before_any_work() {
        let h = new(&Params::new()).unwrap();
        let _ = ();
        let ok = String::from("$6$rounds=1000$saltsalt$......................................................................................");
        // Well-formed: parses, wrong password, so Ok(false).
        assert!(!h.verify(b"pw", &ok).unwrap());
        let cases = [
            String::from("$6$rounds=999$saltsalt$......................................................................................"),
            String::from("$6$rounds=10000001$saltsalt$......................................................................................"),
            String::from("$6$rounds=4294967295$saltsalt$......................................................................................"),
            String::from("$6$rounds=01000$saltsalt$......................................................................................"),
            String::from("$6$rounds=+1000$saltsalt$......................................................................................"),
            String::from("$6$rounds=$saltsalt$......................................................................................"),
            String::from("$6$rounds=1000$$......................................................................................"),
            String::from("$6$rounds=1000$saltsaltsaltsaltX$......................................................................................"),
            String::from("$6$rounds=1000$salt salt$......................................................................................"),
            String::from("$6$rounds=1000$saltsalt$....................................................................................."),
            String::from("$6$rounds=1000$saltsalt$......................................................................................."),
            String::from("$6$rounds=1000$saltsalt$.....................................................................................!"),
            String::from("$6$rounds=1000$saltsalt$.....................................................................................Z"),
            String::from("$5$rounds=1000$saltsalt$......................................................................................"),
            String::from("$1$rounds=1000$saltsalt$......................................................................................"),
            String::from("6$rounds=1000$saltsalt$......................................................................................"),
            String::from("$6$rounds=1000$saltsalt$......................................................................................$"),
            String::from("$6$rounds=1000$......................................................................................"),
            String::from("$6$saltsalt"),
            String::from("$6$rounds=1000$saltsalt$.....................................................................................é"),


            String::new(),
            "$".repeat(5000),
        ];
        for c in &cases {
            assert!(h.verify(b"pw", c).is_err(), "must reject: {c:.80}");
        }
        assert!(h.verify(b"pw", "$6$é$é$é").is_err());
    }
}
