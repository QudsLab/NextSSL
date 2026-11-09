//! Adapter: `pwhash` crate (MD5-crypt, FreeBSD `$1$`, Poul-Henning Kamp 1994) -> nextssl `PwHash`.
//!
//! String form `$1$<salt>$<22 chars>`. Salt 0..=8 characters of `./0-9A-Za-z` (the original also
//! accepts other bytes and silently truncates longer salts; here a longer or out-of-alphabet
//! salt is an error). Password 0..=1024 bytes. MD5-crypt has a fixed 1000-iteration cost: no
//! cost parameter. `derive` is not offered (the crypt string is the only output form).

use nextssl_core::{ct_eq, Error, Len, Params, PwHash, Result, Sizes};

const SALT_MAX: usize = 8;
const PW_MAX: usize = 1024;
const HASH_CHARS: usize = 22;
const PREFIX: &str = "$1$";

fn alphabet_ok(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'.' || c == b'/'
}

fn check_salt(salt: &[u8]) -> Result<()> {
    Len::range(0, SALT_MAX).check("salt", salt.len())?;
    if !salt.iter().all(|&c| alphabet_ok(c)) {
        return Err(Error::InvalidInput("md5-crypt salt must use ./0-9A-Za-z"));
    }
    Ok(())
}

fn check_password(password: &[u8]) -> Result<()> {
    Len::range(0, PW_MAX).check("password", password.len())
}

#[allow(deprecated)] // pwhash marks every legacy crypt as deprecated for new passwords
fn run(password: &[u8], salt: &[u8]) -> Result<String> {
    let salt = core::str::from_utf8(salt).map_err(|_| Error::InvalidInput("salt"))?;
    let setup = format!("{PREFIX}{salt}$");
    pwhash::md5_crypt::hash_with(setup.as_str(), password).map_err(|_| Error::Backend("md5-crypt"))
}

struct Impl;

impl PwHash for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            salt: Some(Len::range(0, SALT_MAX)),
            out: Some(Len::fixed(16)),
            ..Sizes::NONE
        }
    }

    fn hash(&self, password: &[u8], salt: &[u8]) -> Result<String> {
        check_password(password)?;
        check_salt(salt)?;
        run(password, salt)
    }

    fn verify(&self, password: &[u8], phc: &str) -> Result<bool> {
        const BAD: Error = Error::InvalidInput("malformed md5-crypt string");
        check_password(password)?;
        if !phc.is_ascii() || phc.len() > PREFIX.len() + SALT_MAX + 1 + HASH_CHARS {
            return Err(BAD);
        }
        let rest = phc.strip_prefix(PREFIX).ok_or(BAD)?;
        let (salt, hash) = rest.split_once('$').ok_or(BAD)?;
        check_salt(salt.as_bytes()).map_err(|_| BAD)?;
        if hash.len() != HASH_CHARS || !hash.bytes().all(alphabet_ok) {
            return Err(BAD);
        }
        let mine = run(password, salt.as_bytes())?;
        Ok(ct_eq(mine.as_bytes(), phc.as_bytes()))
    }

    fn derive(&self, _password: &[u8], _salt: &[u8], _out: &mut [u8]) -> Result<()> {
        Err(Error::Unsupported)
    }
}

/// Registry constructor. MD5-crypt takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn PwHash>> {
    Ok(Box::new(Impl))
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
            assert_eq!(doc["algorithm"], "md5crypt");
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

                assert_eq!(
                    h.hash(pw, &hash.as_bytes()[3..3 + hash[3..].find('$').unwrap()])
                        .unwrap(),
                    hash,
                    "hash {file}/{id}"
                );
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
            "$1$",
            "$1$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
            "$1$abc$short",
        ] {
            assert!(h.verify(b"x", bad).is_err(), "accepted {bad:?}");
        }
        assert!(h.hash(b"pw", b"bad salt!").is_err());
        assert!(h.hash(&vec![b'a'; 2000], &b"saltsalt"[..8]).is_err());
        assert!(
            h.derive(b"pw", b"saltsalt", &mut [0u8; 16]).is_err(),
            "derive must be Unsupported"
        );
    }
}
