//! Strict PHC string format reader and writer (`$id$v=<n>$k=v,k=v$<salt>$<hash>`).
//!
//! One parser for every password-hashing algorithm, so a hostile string is handled in one
//! audited place. The grammar is deliberately narrow:
//!
//! - ASCII only, at most [`MAX_LEN`] bytes, checked before anything else;
//! - exactly the algorithm id, the version field (if the spec has one) and the parameters the
//!   [`PhcSpec`] lists, in that order, with no extras and no whitespace;
//! - parameter values are canonical decimals (`1..=10` digits, no sign, no leading zero, fit
//!   `u32`) and are range-checked against the spec **before** the salt or hash is decoded, so
//!   a hostile string can never make the caller allocate memory or burn time;
//! - salt and hash are canonical unpadded standard base64 (no padding, no non-zero trailing
//!   bits, alphabet `A-Za-z0-9+/` only); their decoded length is computed from the encoded
//!   length and checked against the spec **before** decoding.
//!
//! Cross-parameter rules (for example Argon2's `m >= 8 p`) are the algorithm's job and are
//! applied to the returned [`Phc`] before any work is done.

use crate::{Error, Len, Result};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use base64ct::{Base64Unpadded, Encoding};

/// Longest PHC string accepted. A valid Argon2 string is under 1500 bytes; anything longer is
/// rejected unparsed.
pub const MAX_LEN: usize = 2048;

const MALFORMED: Error = Error::InvalidInput("malformed PHC string");

/// One numeric parameter of a PHC format, with its policy range.
#[derive(Debug, Clone, Copy)]
pub struct PhcParam {
    pub name: &'static str,
    pub min: u32,
    pub max: u32,
}

/// Shape and policy of one algorithm's PHC strings.
#[derive(Debug, Clone, Copy)]
pub struct PhcSpec {
    /// Algorithm id as written in the string (`argon2id`).
    pub id: &'static str,
    /// `Some(19)` means the string carries `v=19`; `None` means no version field.
    pub version: Option<u32>,
    /// Parameters in the exact order they must appear.
    pub params: &'static [PhcParam],
    /// Allowed salt length in bytes.
    pub salt: Len,
    /// Allowed hash length in bytes.
    pub hash: Len,
}

/// A parsed PHC string. `params[i]` belongs to `spec.params[i]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phc {
    pub params: Vec<u32>,
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
}

/// Canonical decimal: 1..=10 ASCII digits, no leading zero (except "0" itself), fits `u32`.
fn parse_decimal(s: &str) -> Result<u32> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 10 || !b.iter().all(u8::is_ascii_digit) {
        return Err(MALFORMED);
    }
    if b.len() > 1 && b[0] == b'0' {
        return Err(MALFORMED);
    }
    s.parse::<u32>().map_err(|_| MALFORMED)
}

/// Decoded byte length of `n` unpadded base64 characters, or `None` if `n` cannot occur.
fn b64_decoded_len(n: usize) -> Option<usize> {
    let tail = match n % 4 {
        0 => 0,
        2 => 1,
        3 => 2,
        _ => return None,
    };
    Some(n / 4 * 3 + tail)
}

/// Length-checks then strictly decodes a base64 field. The check uses the encoded length, so
/// nothing is allocated for an out-of-policy field.
fn decode_field(s: &str, what: &'static str, len: Len) -> Result<Vec<u8>> {
    let n = b64_decoded_len(s.len()).ok_or(MALFORMED)?;
    len.check(what, n)?;
    Base64Unpadded::decode_vec(s).map_err(|_| MALFORMED)
}

/// Parses `phc` under `spec`. See the module docs for what is accepted.
pub fn parse(phc: &str, spec: &PhcSpec) -> Result<Phc> {
    if phc.len() > MAX_LEN || !phc.is_ascii() {
        return Err(MALFORMED);
    }
    let parts: Vec<&str> = phc.split('$').collect();
    let want = 5 + usize::from(spec.version.is_some());
    if parts.len() != want || !parts[0].is_empty() {
        return Err(MALFORMED);
    }
    if parts[1] != spec.id {
        return Err(Error::InvalidInput("PHC algorithm id mismatch"));
    }
    let mut i = 2;
    if let Some(v) = spec.version {
        if parts[2] != format!("v={v}") {
            return Err(Error::InvalidInput("unsupported PHC version"));
        }
        i = 3;
    }
    let kv: Vec<&str> = parts[i].split(',').collect();
    if kv.len() != spec.params.len() {
        return Err(MALFORMED);
    }
    let mut params = Vec::with_capacity(spec.params.len());
    for (item, p) in kv.iter().zip(spec.params) {
        let value = item
            .strip_prefix(p.name)
            .and_then(|r| r.strip_prefix('='))
            .ok_or(MALFORMED)?;
        let v = parse_decimal(value)?;
        // Policy check before any decoding: a hostile string must never reach the allocator.
        if v < p.min || v > p.max {
            return Err(Error::ParamOutOfRange(p.name));
        }
        params.push(v);
    }
    let salt = decode_field(parts[i + 1], "salt", spec.salt)?;
    let hash = decode_field(parts[i + 2], "hash", spec.hash)?;
    Ok(Phc { params, salt, hash })
}

/// Writes a PHC string, applying the same policy as [`parse`] so that everything written can
/// be read back.
pub fn write(spec: &PhcSpec, params: &[u32], salt: &[u8], hash: &[u8]) -> Result<String> {
    if params.len() != spec.params.len() {
        return Err(Error::InvalidInput("wrong number of PHC parameters"));
    }
    spec.salt.check("salt", salt.len())?;
    spec.hash.check("hash", hash.len())?;
    let mut s = format!("${}", spec.id);
    if let Some(v) = spec.version {
        s.push_str(&format!("$v={v}"));
    }
    s.push('$');
    for (n, (v, p)) in params.iter().zip(spec.params).enumerate() {
        if *v < p.min || *v > p.max {
            return Err(Error::ParamOutOfRange(p.name));
        }
        if n > 0 {
            s.push(',');
        }
        s.push_str(&format!("{}={v}", p.name));
    }
    s.push('$');
    s.push_str(&Base64Unpadded::encode_string(salt));
    s.push('$');
    s.push_str(&Base64Unpadded::encode_string(hash));
    if s.len() > MAX_LEN {
        return Err(Error::InvalidLength {
            what: "PHC string",
            got: s.len(),
            min: 0,
            max: MAX_LEN,
        });
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    /// Same shape and ranges as Argon2id, the strictest user of this module.
    const SPEC: PhcSpec = PhcSpec {
        id: "argon2id",
        version: Some(19),
        params: &[
            PhcParam {
                name: "m",
                min: 8,
                max: 4_194_304,
            },
            PhcParam {
                name: "t",
                min: 1,
                max: 1024,
            },
            PhcParam {
                name: "p",
                min: 1,
                max: 255,
            },
        ],
        salt: Len::range(16, 64),
        hash: Len::range(16, 1024),
    };

    const S: &str = "c29tZXNhbHRzb21lc2FsdA"; // 16 bytes
    const HS: &str = "CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"; // 32 bytes

    #[test]
    fn round_trip_and_exact_output() {
        let ok = format!("$argon2id$v=19$m=8,t=1,p=1${S}${HS}");
        let p = parse(&ok, &SPEC).unwrap();
        assert_eq!(p.params, vec![8, 1, 1]);
        assert_eq!((p.salt.len(), p.hash.len()), (16, 32));
        assert_eq!(write(&SPEC, &p.params, &p.salt, &p.hash).unwrap(), ok);
    }

    #[test]
    fn spec_without_version() {
        const NOV: PhcSpec = PhcSpec {
            version: None,
            ..SPEC
        };
        let ok = format!("$argon2id$m=8,t=1,p=1${S}${HS}");
        assert!(parse(&ok, &NOV).is_ok());
        assert!(parse(&format!("$argon2id$v=19$m=8,t=1,p=1${S}${HS}"), &NOV).is_err());
        assert_eq!(parse(&ok, &SPEC), Err(MALFORMED));
    }

    #[test]
    fn hostile_phc_strings_are_rejected_before_any_work() {
        let (s, hs) = (S, HS);
        let cases = [
            // DoS: memory, time, lanes outside the schema
            format!("$argon2id$v=19$m=4294967295,t=1,p=1${s}${hs}"),
            format!("$argon2id$v=19$m=4194305,t=1,p=1${s}${hs}"),
            format!("$argon2id$v=19$m=8,t=4294967295,p=1${s}${hs}"),
            format!("$argon2id$v=19$m=8,t=1025,p=1${s}${hs}"),
            format!("$argon2id$v=19$m=8,t=0,p=1${s}${hs}"),
            format!("$argon2id$v=19$m=8,t=1,p=0${s}${hs}"),
            format!("$argon2id$v=19$m=8192,t=1,p=256${s}${hs}"),
            format!("$argon2id$v=19$m=99999999999,t=1,p=1${s}${hs}"),
            // wrong algorithm / version
            format!("$argon2i$v=19$m=8,t=1,p=1${s}${hs}"),
            format!("$argon2d$v=19$m=8,t=1,p=1${s}${hs}"),
            format!("$scrypt$v=19$m=8,t=1,p=1${s}${hs}"),
            format!("$argon2id$v=16$m=8,t=1,p=1${s}${hs}"),
            format!("$argon2id$m=8,t=1,p=1${s}${hs}"),
            // structure
            format!("argon2id$v=19$m=8,t=1,p=1${s}${hs}"),
            format!("$argon2id$v=19$m=8,t=1,p=1${s}"),
            format!("$argon2id$v=19$m=8,t=1,p=1${s}${hs}$"),
            format!("$argon2id$v=19$t=1,m=8,p=1${s}${hs}"),
            format!("$argon2id$v=19$m=8,t=1${s}${hs}"),
            format!("$argon2id$v=19$m=8,t=1,p=1,keyid=AA${s}${hs}"),
            format!("$argon2id$v=19$m=08,t=1,p=1${s}${hs}"),
            format!("$argon2id$v=19$m=+8,t=1,p=1${s}${hs}"),
            format!("$argon2id$v=19$m=8,t=1,p=1 ${s}${hs}"),
            format!("$argon2id$v=19$m=,t=1,p=1${s}${hs}"),
            // encoding: padding, bad alphabet, non-canonical trailing bits, short salt/hash
            format!("$argon2id$v=19$m=8,t=1,p=1${s}==${hs}"),
            format!("$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHRzb21lc2FsdB${hs}"),
            format!("$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHRzb21lc2F-dA${hs}"),
            format!("$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHQ${hs}"),
            format!("$argon2id$v=19$m=8,t=1,p=1${s}$AAAA"),
            format!("$argon2id$v=19$m=8,t=1,p=1${s}$"),
            format!("$argon2id$v=19$m=8,t=1,p=1$${hs}"),
            String::new(),
            "$".repeat(5000),
            // Non-ASCII.
            "$argon2id$v=19$m=8,t=1,p=1$é$é".to_string(),
        ];
        assert_eq!(cases.len(), 33);
        for c in &cases {
            assert!(parse(c, &SPEC).is_err(), "must reject: {c:.80}");
        }
    }

    #[test]
    fn policy_errors_are_specific_and_precede_decoding() {
        // Out-of-range m with an undecodable salt: the range error must win (no decoding yet).
        let bad = "$argon2id$v=19$m=4194305,t=1,p=1$!!!$!!!";
        assert_eq!(parse(bad, &SPEC), Err(Error::ParamOutOfRange("m")));
        // Short salt is a length error, not a decode error.
        let short = format!("$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHQ${HS}");
        assert!(matches!(
            parse(&short, &SPEC),
            Err(Error::InvalidLength { what: "salt", .. })
        ));
        // A huge salt is rejected from its encoded length alone.
        let huge = "A".repeat(1500);
        let big = format!("$argon2id$v=19$m=8,t=1,p=1${huge}${HS}");
        assert!(matches!(
            parse(&big, &SPEC),
            Err(Error::InvalidLength { what: "salt", .. })
        ));
        assert_eq!(
            parse(&format!("$argon2id$v=19$m=8,t=1,p=1${S}$A"), &SPEC),
            Err(MALFORMED)
        );
    }

    #[test]
    fn writer_enforces_the_same_policy() {
        let salt = [1u8; 16];
        let hash = [2u8; 32];
        assert!(write(&SPEC, &[8, 1, 1], &salt, &hash).is_ok());
        assert!(write(&SPEC, &[7, 1, 1], &salt, &hash).is_err());
        assert!(write(&SPEC, &[8, 1], &salt, &hash).is_err());
        assert!(write(&SPEC, &[8, 1, 1], &salt[..15], &hash).is_err());
        assert!(write(&SPEC, &[8, 1, 1], &salt, &hash[..15]).is_err());
    }
}
