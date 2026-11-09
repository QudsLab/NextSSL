//! Adapter: `pwhash` crate (BSDi extended DES-crypt, `_` format) -> nextssl `PwHash`.
//!
//! String form `_<4 chars rounds><4 chars salt><11 chars hash>` (crypt Base64, `./0-9A-Za-z`,
//! rounds and salt 24-bit little-endian). Param `rounds` 1..=1048575 (default 7250; the
//! algorithm allows up to 2^24-1, capped here so a hostile string cannot demand unbounded
//! work). Salt exactly 4 characters. Password 0..=1024 bytes. `derive` is not offered.

use nextssl_core::{ct_eq, Error, Len, Params, PwHash, Result, Sizes};

const ROUNDS_MAX: u64 = (1 << 20) - 1;
const ROUNDS_DEFAULT: u64 = 7250;
const SALT_LEN: usize = 4;
const PW_MAX: usize = 1024;
const HASH_CHARS: usize = 11;
const CRYPT64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// Byte range of the salt inside a canonical string (used by tests).
#[cfg(test)]
const SALT_RANGE: (usize, usize) = (5, 9);

fn alphabet_ok(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'.' || c == b'/'
}

fn check_salt(salt: &[u8]) -> Result<()> {
    Len::fixed(SALT_LEN).check("salt", salt.len())?;
    if !salt.iter().all(|&c| alphabet_ok(c)) {
        return Err(Error::InvalidInput("bsdi-crypt salt must use ./0-9A-Za-z"));
    }
    Ok(())
}

fn check_password(password: &[u8]) -> Result<()> {
    Len::range(0, PW_MAX).check("password", password.len())
}

fn enc_rounds(rounds: u32) -> String {
    (0..4)
        .map(|i| CRYPT64[((rounds >> (6 * i)) & 63) as usize] as char)
        .collect()
}

fn dec_rounds(s: &[u8]) -> Option<u32> {
    let mut r = 0u32;
    for (i, &c) in s.iter().enumerate() {
        let v = CRYPT64.iter().position(|&x| x == c)? as u32;
        r |= v << (6 * i);
    }
    Some(r)
}

#[allow(deprecated)] // pwhash marks every legacy crypt as deprecated for new passwords
fn run(rounds: u32, password: &[u8], salt: &[u8]) -> Result<String> {
    let salt = core::str::from_utf8(salt).map_err(|_| Error::InvalidInput("salt"))?;
    let setup = format!("_{}{}", enc_rounds(rounds), salt);
    pwhash::bsdi_crypt::hash_with(setup.as_str(), password)
        .map_err(|_| Error::Backend("bsdi-crypt"))
}

struct Impl {
    rounds: u32,
}

impl PwHash for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            salt: Some(Len::fixed(SALT_LEN)),
            out: Some(Len::fixed(8)),
            ..Sizes::NONE
        }
    }

    fn hash(&self, password: &[u8], salt: &[u8]) -> Result<String> {
        check_password(password)?;
        check_salt(salt)?;
        run(self.rounds, password, salt)
    }

    fn verify(&self, password: &[u8], phc: &str) -> Result<bool> {
        const BAD: Error = Error::InvalidInput("malformed bsdi-crypt string");
        check_password(password)?;
        let b = phc.as_bytes();
        if !phc.is_ascii()
            || b.len() != 1 + 4 + SALT_LEN + HASH_CHARS
            || b[0] != b'_'
            || !b[1..].iter().all(|&c| alphabet_ok(c))
        {
            return Err(BAD);
        }
        let rounds = dec_rounds(&b[1..5]).ok_or(BAD)?;
        if rounds == 0 || u64::from(rounds) > ROUNDS_MAX {
            return Err(Error::ParamOutOfRange("rounds"));
        }
        let mine = run(rounds, password, &b[5..9])?;
        Ok(ct_eq(mine.as_bytes(), b))
    }

    fn derive(&self, _password: &[u8], _salt: &[u8], _out: &mut [u8]) -> Result<()> {
        Err(Error::Unsupported)
    }
}

/// Registry constructor. Param `rounds` (1..=1048575, default 7250).
pub fn new(params: &Params) -> Result<Box<dyn PwHash>> {
    let rounds = params.get_u64("rounds").unwrap_or(ROUNDS_DEFAULT);
    if rounds == 0 || rounds > ROUNDS_MAX {
        return Err(Error::ParamOutOfRange("rounds"));
    }
    Ok(Box::new(Impl {
        rounds: rounds as u32,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as J;
    use std::path::PathBuf;

    fn load(name: &str) -> J {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("kat")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    #[test]
    fn all_kat_files() {
        let mut n = 0;
        for file in ["john-tests.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "bsdicrypt");
            for v in doc["vectors"].as_array().unwrap() {
                let id = v["id"].as_str().unwrap();
                let hash = v["hash"].as_str().unwrap();
                let pw = v["password"].as_str().unwrap().as_bytes();
                let h = new(&Params::new()).unwrap();
                assert!(h.verify(pw, hash).unwrap(), "verify {file}/{id}");
                assert!(
                    !h.verify(b"wrong password", hash).unwrap(),
                    "wrong pw {file}/{id}"
                );
                let salt = &hash.as_bytes()[SALT_RANGE.0..SALT_RANGE.1];
                let rounds = dec_rounds(&hash.as_bytes()[1..5]).unwrap();
                let hh =
                    new(&Params::new().with("rounds", nextssl_core::Value::U64(u64::from(rounds))))
                        .unwrap();
                assert_eq!(hh.hash(pw, salt).unwrap(), hash, "hash {file}/{id}");
                n += 1;
            }
        }
        assert!(n >= 5, "too few KATs ran: {n}");
    }

    #[test]
    fn rejects_malformed_strings_and_bad_inputs() {
        let h = new(&Params::new()).unwrap();
        for bad in [
            "",
            "$",
            "$2$abc$def",
            "_",
            "_@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
            "_J9..CCCCXBrJUJV154",
        ] {
            assert!(h.verify(b"x", bad).is_err(), "accepted {bad:?}");
        }
        assert!(h.hash(b"pw", b"bad salt!").is_err());
        assert!(h.hash(&vec![b'a'; 2000], &b"saltsalt"[..4]).is_err());
        assert!(
            h.derive(b"pw", b"saltsalt", &mut [0u8; 8]).is_err(),
            "derive must be Unsupported"
        );
    }
}
