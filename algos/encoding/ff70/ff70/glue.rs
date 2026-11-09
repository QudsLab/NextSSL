//! FlexFrame-70 (FF70), the owner's own framed text encoding, in safe Rust.
//!
//! Frame: `[Header](Config){Data|Sum}[Meta]`.
//! - `Config` is empty, or `-` followed by the excluded alphabet characters. The alphabet is the
//!   70 symbols `0-9 a-z A-Z @#$%&;:|` minus the excluded ones; `|` is the data/sum separator and
//!   always excluded, so the real base is 69 at most (kept for compatibility with the C original).
//! - `Data` is the payload as a big-endian number in that base. Each leading zero byte is one
//!   `alphabet[0]` symbol, so `n` zero bytes are `n` symbols and an empty payload is an empty
//!   Data field.
//! - `Sum` is the first 4 bytes of BLAKE3(payload) in the same encoding. **It detects accidents
//!   only. It is not a MAC or a signature and gives no integrity against an attacker.**
//!
//! Strict rules (every one an explicit error, nothing truncated or ignored): printable ASCII only;
//! header at most 31 bytes, config at most 63, meta at most 127, none containing `]`; `exclude`
//! strictly ascending ASCII, inside the alphabet, no `|` (so one payload has one encoding), base at
//! least 2 (16 or more recommended); exactly one `|`; the `[Meta]` section is required and nothing
//! may follow it; whole frame at most 16 KiB and payload at most 4 KiB (decoding is quadratic).
//!
//! `decode` through the registry checks that the frame's header and exclude equal the instance's
//! `header` and `exclude` parameters and returns the payload; use [`parse`] to read any frame
//! including its `meta`.

use nextssl_core::{ct_eq, Encoding, Error, Len, ParamSpec, ParamType, Params, Result};

const SET: &[u8; 70] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@#$%&;:|";
const SEP: u8 = b'|';
const SUM_LEN: usize = 4;
const HEADER_MAX: usize = 31;
const EXCLUDE_MAX: usize = 62;
const META_MAX: usize = 127;
/// Largest frame accepted or produced.
pub const MAX_FRAME: usize = 16 * 1024;
/// Largest payload accepted or produced.
pub const MAX_PAYLOAD: usize = 4 * 1024;

const fn text_spec(name: &'static str, max: usize) -> ParamSpec {
    ParamSpec {
        name,
        ty: ParamType::Str,
        min: 0,
        max: max as u64,
        required: false,
        default: None,
    }
}

/// Mirror of the `[params]` tables in `algo.toml`.
const SPECS: [ParamSpec; 3] = [
    text_spec("header", HEADER_MAX),
    text_spec("exclude", EXCLUDE_MAX),
    text_spec("meta", META_MAX),
];

/// A parsed and verified frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: String,
    pub exclude: String,
    pub meta: String,
    pub payload: Vec<u8>,
}

fn check_text(what: &'static str, s: &str, max: usize) -> Result<()> {
    Len::range(0, max).check(what, s.len())?;
    if !s.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(Error::InvalidInput("ff70: printable ASCII only"));
    }
    if s.contains(']') {
        return Err(Error::InvalidInput(
            "ff70: ']' is not allowed in header or meta",
        ));
    }
    Ok(())
}

/// Validates a canonical exclude list and returns the alphabet.
fn alphabet(exclude: &str) -> Result<Vec<u8>> {
    let ex = exclude.as_bytes();
    Len::range(0, EXCLUDE_MAX).check("exclude", ex.len())?;
    if !ex.windows(2).all(|w| w[0] < w[1]) {
        return Err(Error::InvalidInput(
            "ff70: exclude must be strictly ascending (sorted, no duplicates)",
        ));
    }
    if !ex.iter().all(|c| *c != SEP && SET.contains(c)) {
        return Err(Error::InvalidInput(
            "ff70: exclude may only list alphabet symbols other than '|'",
        ));
    }
    let al: Vec<u8> = SET
        .iter()
        .copied()
        .filter(|c| *c != SEP && !ex.contains(c))
        .collect();
    if al.len() < 2 {
        return Err(Error::InvalidInput(
            "ff70: alphabet base must be at least 2",
        ));
    }
    Ok(al)
}

fn encode_number(data: &[u8], al: &[u8]) -> Vec<u8> {
    let base = al.len() as u32;
    let zeros = data.iter().take_while(|b| **b == 0).count();
    let mut num = data[zeros..].to_vec();
    let mut digits = Vec::new();
    let mut start = 0;
    while start < num.len() {
        let mut rem = 0u32;
        for b in &mut num[start..] {
            let v = (rem << 8) | u32::from(*b);
            *b = (v / base) as u8;
            rem = v % base;
        }
        digits.push(al[rem as usize]);
        while start < num.len() && num[start] == 0 {
            start += 1;
        }
    }
    let mut out = vec![al[0]; zeros];
    out.extend(digits.iter().rev());
    out
}

fn decode_number(text: &[u8], al: &[u8]) -> Result<Vec<u8>> {
    let base = al.len() as u32;
    let mut value = [255u8; 256];
    for (i, c) in al.iter().enumerate() {
        value[*c as usize] = i as u8;
    }
    let zeros = text.iter().take_while(|c| **c == al[0]).count();
    let mut num: Vec<u8> = Vec::new(); // little endian
    for &c in &text[zeros..] {
        let d = value[c as usize];
        if d == 255 {
            return Err(Error::InvalidInput("ff70: symbol outside the alphabet"));
        }
        let mut carry = u32::from(d);
        for b in &mut num {
            let v = u32::from(*b) * base + carry;
            *b = v as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            num.push(carry as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(num.iter().rev());
    Ok(out)
}

fn checksum(payload: &[u8]) -> [u8; SUM_LEN] {
    let h = blake3::hash(payload);
    let mut s = [0u8; SUM_LEN];
    s.copy_from_slice(&h.as_bytes()[..SUM_LEN]);
    s
}

fn encode_frame(header: &str, exclude: &str, meta: &str, data: &[u8]) -> Result<String> {
    check_text("header", header, HEADER_MAX)?;
    check_text("meta", meta, META_MAX)?;
    let al = alphabet(exclude)?;
    Len::range(0, MAX_PAYLOAD).check("payload", data.len())?;
    let body = String::from_utf8(encode_number(data, &al))
        .map_err(|_| Error::Backend("ff70: non-ASCII symbol"))?;
    let sum = String::from_utf8(encode_number(&checksum(data), &al))
        .map_err(|_| Error::Backend("ff70: non-ASCII symbol"))?;
    let cfg = if exclude.is_empty() {
        String::new()
    } else {
        format!("-{exclude}")
    };
    let frame = format!("[{header}]({cfg}){{{body}|{sum}}}[{meta}]");
    Len::range(0, MAX_FRAME).check("frame", frame.len())?;
    Ok(frame)
}

const FORMAT: Error = Error::InvalidInput("ff70: malformed frame");

/// Parses and verifies a frame (`[Header](Config){Data|Sum}[Meta]`), strictly.
pub fn parse(text: &[u8]) -> Result<Frame> {
    Len::range(0, MAX_FRAME).check("frame", text.len())?;
    if !text.iter().all(|b| (0x20..0x7f).contains(b)) {
        return Err(Error::InvalidInput("ff70: printable ASCII only"));
    }
    let s = core::str::from_utf8(text).map_err(|_| FORMAT)?;
    let rest = s.strip_prefix('[').ok_or(FORMAT)?;
    let (header, rest) = rest.split_once(']').ok_or(FORMAT)?;
    check_text("header", header, HEADER_MAX)?;
    let rest = rest.strip_prefix('(').ok_or(FORMAT)?;
    let (cfg, rest) = rest.split_once(')').ok_or(FORMAT)?;
    let exclude = if cfg.is_empty() {
        ""
    } else {
        let e = cfg.strip_prefix('-').ok_or(FORMAT)?;
        if e.is_empty() {
            return Err(Error::InvalidInput("ff70: empty exclude list after '-'"));
        }
        e
    };
    let al = alphabet(exclude)?;
    let rest = rest.strip_prefix('{').ok_or(FORMAT)?;
    let (body, rest) = rest.split_once('}').ok_or(FORMAT)?;
    let (data_s, sum_s) = body.split_once('|').ok_or(FORMAT)?;
    // Exactly one '|': a second one is not in the alphabet and fails below.
    let meta = rest
        .strip_prefix('[')
        .and_then(|m| m.strip_suffix(']'))
        .ok_or(Error::InvalidInput(
            "ff70: the [Meta] section is required and must end the frame",
        ))?;
    check_text("meta", meta, META_MAX)?;
    let payload = decode_number(data_s.as_bytes(), &al)?;
    Len::range(0, MAX_PAYLOAD).check("payload", payload.len())?;
    let sum = decode_number(sum_s.as_bytes(), &al)?;
    if sum.len() != SUM_LEN || !ct_eq(&sum, &checksum(&payload)) {
        return Err(Error::InvalidInput("ff70: checksum mismatch"));
    }
    Ok(Frame {
        header: header.to_string(),
        exclude: exclude.to_string(),
        meta: meta.to_string(),
        payload,
    })
}

struct Impl {
    header: String,
    exclude: String,
    meta: String,
}

impl Encoding for Impl {
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(encode_frame(&self.header, &self.exclude, &self.meta, data)?.into_bytes())
    }

    fn decode(&self, text: &[u8]) -> Result<Vec<u8>> {
        let f = parse(text)?;
        if f.header != self.header {
            return Err(Error::InvalidInput("ff70: unexpected header"));
        }
        if f.exclude != self.exclude {
            return Err(Error::InvalidInput("ff70: unexpected exclude list"));
        }
        Ok(f.payload)
    }
}

/// Registry constructor. Parameters `header`, `exclude`, `meta` (strings, default empty).
pub fn new(params: &Params) -> Result<Box<dyn Encoding>> {
    let v = params.validate(&SPECS)?;
    let get = |n: &str| v.get_str(n).unwrap_or("").to_string();
    let (header, exclude, meta) = (get("header"), get("exclude"), get("meta"));
    check_text("header", &header, HEADER_MAX)?;
    check_text("meta", &meta, META_MAX)?;
    alphabet(&exclude)?;
    Ok(Box::new(Impl {
        header,
        exclude,
        meta,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::Value;
    use serde_json::Value as J;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn enc(header: &str, exclude: &str, meta: &str) -> Box<dyn Encoding> {
        new(&Params::new()
            .with("header", Value::Str(header.into()))
            .with("exclude", Value::Str(exclude.into()))
            .with("meta", Value::Str(meta.into())))
        .unwrap()
    }

    #[test]
    fn known_answers_both_directions() {
        let doc: J = serde_json::from_str(include_str!("kat/vectors.json")).unwrap();
        let vs = doc["vectors"].as_array().unwrap();
        assert!(vs.len() >= 15);
        for v in vs {
            let id = v["id"].as_str().unwrap();
            let p = &v["params"];
            let (header, exclude, meta) = (
                p["header"].as_str().unwrap(),
                p["exclude"].as_str().unwrap(),
                p["meta"].as_str().unwrap(),
            );
            let e = enc(header, exclude, meta);
            let data = unhex(v["data_hex"].as_str().unwrap());
            let frame = v["text"].as_str().unwrap();
            assert_eq!(e.encode(&data).unwrap(), frame.as_bytes(), "{id}");
            assert_eq!(e.decode(frame.as_bytes()).unwrap(), data, "{id}");
            let f = parse(frame.as_bytes()).unwrap();
            assert_eq!(f.meta, meta, "{id}");
            assert_eq!(f.payload, data, "{id}");
        }
        let plain = enc("", "", "");
        for bad in doc["invalid"].as_array().unwrap() {
            let t = bad["text"].as_str().unwrap();
            assert!(plain.decode(t.as_bytes()).is_err(), "accepted {t:?}");
        }
    }

    #[test]
    fn empty_and_all_zero_payloads_round_trip() {
        let e = enc("", "", "");
        for n in [0usize, 1, 2, 5, 33] {
            let z = vec![0u8; n];
            let f = e.encode(&z).unwrap();
            assert_eq!(e.decode(&f).unwrap(), z, "{n} zero bytes");
        }
        assert!(String::from_utf8(e.encode(&[]).unwrap())
            .unwrap()
            .starts_with("[](){|"));
        let mixed = [0u8, 0, 7, 0, 255];
        assert_eq!(e.decode(&e.encode(&mixed).unwrap()).unwrap(), mixed);
    }

    #[test]
    fn pseudo_random_round_trips_across_bases() {
        let mut x = 0x1234_5678u32;
        for exclude in ["", "&@", "#$%&:;", "$&@ABCDEFGHIJKLMNOPQRSTUVWXYZ"] {
            if exclude.contains(' ') {
                continue;
            }
            let e = enc("H", exclude, "m");
            for len in 0..80usize {
                let data: Vec<u8> = (0..len)
                    .map(|_| {
                        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                        let b = (x >> 24) as u8;
                        if x & 0x300 == 0 {
                            0
                        } else {
                            b
                        }
                    })
                    .collect();
                let f = e.encode(&data).unwrap();
                assert_eq!(e.decode(&f).unwrap(), data, "{exclude:?} {len}");
            }
        }
    }

    #[test]
    fn parameter_defects_are_errors() {
        let bad = |h: &str, ex: &str, m: &str| {
            new(&Params::new()
                .with("header", Value::Str(h.into()))
                .with("exclude", Value::Str(ex.into()))
                .with("meta", Value::Str(m.into())))
            .is_err()
        };
        assert!(bad("a]b", "", ""), "']' in header");
        assert!(bad("", "", "a]b"), "']' in meta");
        assert!(bad(&"h".repeat(32), "", ""), "header over 31 bytes");
        assert!(bad("", "", &"m".repeat(128)), "meta over 127 bytes");
        assert!(bad("", "@&", ""), "unsorted exclude");
        assert!(bad("", "&&", ""), "duplicate exclude");
        assert!(bad("", "(", ""), "'(' is not an alphabet symbol");
        assert!(bad("", "|", ""), "'|' is always excluded already");
        assert!(bad("", "é", ""), "non-ASCII");
        assert!(bad("tab\there", "", ""), "control character");
        let big: String = SET
            .iter()
            .filter(|c| **c != SEP)
            .map(|c| *c as char)
            .collect();
        assert!(bad("", &big, ""), "base 0");
        let mut sorted: Vec<u8> = big.bytes().collect();
        sorted.sort_unstable();
        let almost = String::from_utf8(sorted[..sorted.len() - 1].to_vec()).unwrap();
        assert!(bad("", &almost, ""), "base 1 / over the config limit");
        assert!(new(&Params::new().with("bogus", Value::U32(1))).is_err());
    }

    #[test]
    fn hostile_frames_are_rejected() {
        let e = enc("K", "", "m");
        let good = String::from_utf8(e.encode(b"payload").unwrap()).unwrap();
        assert_eq!(good, good.trim());
        let cases = [
            format!("{good}x"),
            good.trim_end_matches(']').to_string(),
            good.replace("[m]", ""),
            good.replacen("(){", "(-){", 1),
            good.replacen('|', "||", 1),
            good.replacen('|', "", 1),
            good.replacen("[K]", "[X]", 1),
            good.replacen("[K](", "[K](-@", 1),
            String::new(),
            "[](){|}[]".to_string(),
            "[".repeat(10),
            format!("[K](){{{}|{}}}[m]", "0".repeat(MAX_FRAME), "0"),
        ];
        for c in cases {
            assert!(e.decode(c.as_bytes()).is_err(), "{c:.60}");
        }
        // bad checksum (flip the last sum symbol)
        let mut bad = good.clone().into_bytes();
        let i = good.rfind('}').unwrap() - 1;
        bad[i] = if bad[i] == b'0' { b'1' } else { b'0' };
        assert!(e.decode(&bad).is_err());
        // control characters, non-ASCII
        assert!(parse("[K](){|}[m]\n".as_bytes()).is_err());
        assert!(parse("[K](){\u{e9}|}[m]".as_bytes()).is_err());
        // wrong header / exclude for the instance, but fine for parse()
        let other = enc("X", "", "m");
        assert!(other.decode(good.as_bytes()).is_err());
        assert_eq!(parse(good.as_bytes()).unwrap().header, "K");
        // payload cap
        assert!(e.encode(&[1u8; MAX_PAYLOAD + 1]).is_err());
        assert!(e.encode(&vec![1u8; MAX_PAYLOAD]).is_ok());
    }
}
