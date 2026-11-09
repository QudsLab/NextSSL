//! `hashcash(<hash>)`: hashcash v1 stamps (`1:bits:date:resource:ext:rand:counter`) over any
//! registered hash, XOF (32 bytes) or checksum (the `oneshot` slot). Spec: hashcash.org.
//!
//! Challenge: `date:resource:ext:rand` (4 fields, no control characters, at most 256 bytes;
//! `date` is 6, 10 or 12 digits: `YYMMDD[hhmm[ss]]`; `resource` is not empty). Difficulty is
//! the number of leading zero bits (1..=min(64, digest bits)). The solution is the counter text
//! (1..=32 characters of the base-64 alphabet). A stamp is valid when the hash of the whole
//! stamp text has at least `bits` leading zero bits. Calendar dates are not checked here; an
//! application that wants expiry checks `date` itself.
//!
//! `solve` tries counters `0..max_work` and returns `Error::WorkLimitExceeded` when none works.

use crate::parts::OneShot;
use nextssl_core::{Checksum, Error, Hash, Kind, Len, Params, Pow, Result, Sizes, Xof};
use nextssl_registry::{all, new_checksum_in, new_hash_in, new_xof_in, Policy};

const CHALLENGE_MAX: usize = 256;
const SOLUTION_MAX: usize = 32;
const XOF_BYTES: usize = 32;
const BITS_CAP: u32 = 64;
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

enum Dyn {
    Hash(Box<dyn Hash>),
    Xof(Box<dyn Xof>),
    Checksum(Box<dyn Checksum>, usize),
}

pub struct Hashcash {
    h: Dyn,
    out_bits: u32,
}

impl Hashcash {
    pub fn new(slot: OneShot) -> Result<Self> {
        let p: Params = slot.info.smoke_params();
        let (h, out) = match slot.info.kind {
            Kind::Hash => {
                let h = new_hash_in(all(), Policy::Any, slot.info.id, &p)?;
                let n = h.output_len();
                (Dyn::Hash(h), n)
            }
            Kind::Xof => (
                Dyn::Xof(new_xof_in(all(), Policy::Any, slot.info.id, &p)?),
                XOF_BYTES,
            ),
            Kind::Checksum => {
                let c = new_checksum_in(all(), Policy::Any, slot.info.id, &p)?;
                let n = c.sizes().out.ok_or(Error::Unsupported)?.max();
                (Dyn::Checksum(c, n), n)
            }
            _ => return Err(Error::WrongKind),
        };
        Ok(Self {
            h,
            out_bits: u32::try_from(out * 8).map_err(|_| Error::Unsupported)?,
        })
    }

    fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.h {
            Dyn::Hash(h) => {
                let mut out = vec![0u8; h.output_len()];
                h.digest(data, &mut out)?;
                Ok(out)
            }
            Dyn::Xof(x) => {
                let mut out = vec![0u8; XOF_BYTES];
                x.squeeze(data, &mut out)?;
                Ok(out)
            }
            Dyn::Checksum(c, n) => {
                let mut out = vec![0u8; *n];
                c.checksum(data, &mut out)?;
                Ok(out)
            }
        }
    }

    fn check_difficulty(&self, d: u32) -> Result<()> {
        let (lo, hi) = self.difficulty();
        if d < lo || d > hi {
            return Err(Error::ParamOutOfRange("difficulty"));
        }
        Ok(())
    }

    fn stamp(challenge: &[u8], bits: u32, counter: &[u8]) -> Vec<u8> {
        let mut s = format!("1:{bits}:").into_bytes();
        s.extend_from_slice(challenge);
        s.push(b':');
        s.extend_from_slice(counter);
        s
    }
}

fn leading_zero_bits(d: &[u8]) -> u32 {
    let mut n = 0;
    for &b in d {
        if b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

fn check_challenge(c: &[u8]) -> Result<()> {
    Len::range(1, CHALLENGE_MAX).check("challenge", c.len())?;
    if !c.iter().all(|b| (0x20..0x7f).contains(b)) {
        return Err(Error::InvalidInput(
            "hashcash challenge: printable ASCII only",
        ));
    }
    let fields: Vec<&[u8]> = c.split(|b| *b == b':').collect();
    if fields.len() != 4 {
        return Err(Error::InvalidInput(
            "hashcash challenge: want date:resource:ext:rand",
        ));
    }
    let date = fields[0];
    if !matches!(date.len(), 6 | 10 | 12) || !date.iter().all(u8::is_ascii_digit) {
        return Err(Error::InvalidInput(
            "hashcash challenge: date must be 6, 10 or 12 digits",
        ));
    }
    if fields[1].is_empty() {
        return Err(Error::InvalidInput("hashcash challenge: empty resource"));
    }
    Ok(())
}

/// Counter as base-64 digits, most significant first (`0` is `A`).
fn counter_text(mut n: u64) -> Vec<u8> {
    let mut d = Vec::new();
    loop {
        d.push(B64[(n & 63) as usize]);
        n >>= 6;
        if n == 0 {
            break;
        }
    }
    d.reverse();
    d
}

impl Pow for Hashcash {
    fn sizes(&self) -> Sizes {
        Sizes {
            out: Some(Len::range(1, SOLUTION_MAX)),
            ..Sizes::NONE
        }
    }

    fn difficulty(&self) -> (u32, u32) {
        (1, self.out_bits.min(BITS_CAP))
    }

    fn solve(&self, challenge: &[u8], difficulty: u32, max_work: u64) -> Result<Vec<u8>> {
        self.check_difficulty(difficulty)?;
        check_challenge(challenge)?;
        if max_work == 0 {
            return Err(Error::ParamOutOfRange("max_work"));
        }
        for n in 0..max_work {
            let counter = counter_text(n);
            let d = self.digest(&Self::stamp(challenge, difficulty, &counter))?;
            if leading_zero_bits(&d) >= difficulty {
                return Ok(counter);
            }
        }
        Err(Error::WorkLimitExceeded)
    }

    fn verify(&self, challenge: &[u8], solution: &[u8], difficulty: u32) -> Result<bool> {
        self.check_difficulty(difficulty)?;
        check_challenge(challenge)?;
        Len::range(1, SOLUTION_MAX).check("solution", solution.len())?;
        if !solution.iter().all(|b| B64.contains(b)) {
            return Err(Error::InvalidInput(
                "hashcash solution: base-64 alphabet only",
            ));
        }
        let d = self.digest(&Self::stamp(challenge, difficulty, solution))?;
        Ok(leading_zero_bits(&d) >= difficulty)
    }
}
