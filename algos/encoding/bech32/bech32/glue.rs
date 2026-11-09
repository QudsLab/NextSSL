//! Adapter: rust-bitcoin `bech32` (BIP-173) -> nextssl `Encoding`, bytes <-> text.
//!
//! The data is a byte string: it is regrouped from 8-bit to 5-bit symbols (zero padded) for
//! encoding, and back for decoding. Shape decisions:
//! - the human-readable part is the REQUIRED `hrp` parameter (no default, 1..=83 characters of
//!   US-ASCII 33..=126); encoding writes it lowercase, decoding rejects any other HRP;
//! - the whole string is limited to 90 characters (BIP-173), in both directions;
//! - decoding is strict: the checksum must be Bech32 (a Bech32m string is an error), the string
//!   must be all lowercase or all uppercase, and the data must be a canonical byte string
//!   (padding bits zero and shorter than one symbol), checked by re-encoding the result.
//!
//! Segwit addresses carry a witness-version symbol before the program; they are not modelled
//! here (they are a protocol layer, not a bytes <-> text encoding).

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{encode_lower, Bech32, Hrp};
use nextssl_core::{Encoding, Error, Len, ParamSpec, ParamType, Params, Result};

const MAX_LEN: usize = 90;

/// Mirror of `[params.hrp]` in `algo.toml`.
const SPECS: [ParamSpec; 1] = [ParamSpec {
    name: "hrp",
    ty: ParamType::Str,
    min: 1,
    max: 83,
    required: true,
    default: None,
}];

struct Impl {
    hrp: Hrp,
}

impl Encoding for Impl {
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let s = encode_lower::<Bech32>(self.hrp, data)
            .map_err(|_| Error::InvalidInput("bech32: data too long for the checksum"))?;
        Len::range(0, MAX_LEN).check("bech32 string", s.len())?;
        Ok(s.into_bytes())
    }

    fn decode(&self, text: &[u8]) -> Result<Vec<u8>> {
        Len::range(0, MAX_LEN).check("bech32 string", text.len())?;
        let s = core::str::from_utf8(text).map_err(|_| Error::InvalidInput("bech32: not ASCII"))?;
        let checked = CheckedHrpstring::new::<Bech32>(s)
            .map_err(|_| Error::InvalidInput("bech32: malformed string or bad checksum"))?;
        if checked.hrp() != self.hrp {
            return Err(Error::InvalidInput(
                "bech32: unexpected human-readable part",
            ));
        }
        let bytes: Vec<u8> = checked.byte_iter().collect();
        // Canonical form only: re-encoding must give back the input (rejects non-zero or
        // surplus padding bits, which the byte iterator would silently drop).
        let again = encode_lower::<Bech32>(self.hrp, &bytes)
            .map_err(|_| Error::InvalidInput("bech32: re-encoding failed"))?;
        if again != s.to_ascii_lowercase() {
            return Err(Error::InvalidInput("bech32: non-canonical padding bits"));
        }
        Ok(bytes)
    }
}

/// Registry constructor. `hrp` is required; there is no default.
pub fn new(params: &Params) -> Result<Box<dyn Encoding>> {
    let v = params.validate(&SPECS)?;
    let hrp = v.get_str("hrp").ok_or(Error::ParamMissing("hrp"))?;
    let hrp = Hrp::parse(hrp).map_err(|_| Error::ParamOutOfRange("hrp"))?;
    Ok(Box::new(Impl { hrp }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::Value;
    use serde_json::Value as J;
    use std::path::PathBuf;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
            .collect()
    }

    fn enc(hrp: &str) -> Box<dyn Encoding> {
        new(&Params::new().with("hrp", Value::Str(hrp.into()))).unwrap()
    }

    fn doc() -> J {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("kat/vectors.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn known_answers_and_invalid() {
        let d = doc();
        assert_eq!(d["algorithm"], "bech32");
        for v in d["vectors"].as_array().unwrap() {
            let e = enc(v["params"]["hrp"].as_str().unwrap());
            let data = unhex(v["data_hex"].as_str().unwrap());
            let text = v["text"].as_str().unwrap();
            assert_eq!(e.encode(&data).unwrap(), text.as_bytes(), "{}", v["id"]);
            assert_eq!(e.decode(text.as_bytes()).unwrap(), data, "{}", v["id"]);
        }
        for b in d["invalid"].as_array().unwrap() {
            let e = enc(b["params"]["hrp"].as_str().unwrap());
            let text = b["text"].as_str().unwrap();
            assert!(e.decode(text.as_bytes()).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn hrp_is_required_and_checked() {
        assert!(matches!(
            new(&Params::new()),
            Err(Error::ParamMissing("hrp"))
        ));
        for bad in ["", "a b", "\u{7f}"] {
            let r = new(&Params::new().with("hrp", Value::Str(bad.into())));
            assert!(r.is_err(), "{bad:?}");
        }
        assert!(new(&Params::new().with("hrp", Value::Str("x".repeat(84)))).is_err());
        // a string for another HRP is refused
        let s = enc("bc").encode(b"hello").unwrap();
        assert!(enc("tb").decode(&s).is_err());
        assert_eq!(enc("bc").decode(&s).unwrap(), b"hello");
    }

    #[test]
    fn case_and_length_rules() {
        let e = enc("a");
        // all-uppercase is accepted, mixed case is not
        assert_eq!(e.decode(b"A12UEL5L").unwrap(), b"");
        assert!(e.decode(b"A12uel5l").is_err());
        // output is lowercase
        assert_eq!(e.encode(b"").unwrap(), b"a12uel5l");
        // 90 characters is the ceiling
        let e = enc("bc");
        let ok = e.encode(&[7u8; 49]).unwrap();
        assert_eq!(ok.len(), 2 + 1 + (49usize * 8).div_ceil(5) + 6);
        assert!(ok.len() <= 90);
        assert!(e.encode(&[7u8; 60]).is_err());
    }
}
