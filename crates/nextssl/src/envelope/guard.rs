//! Pre-parse structural guard for untrusted CBOR.
//!
//! Walks the raw bytes iteratively (no recursion) and refuses, before any CBOR library builds a
//! value tree: nesting deeper than `max_depth`, more than `max_items` data items, string or
//! container lengths that claim more than the input holds, indefinite-length items, reserved
//! additional-info values, and trailing bytes. COSE structures are small and definite-length,
//! so none of this rejects a legitimate envelope.

use nextssl_core::{Error, Result};

const BAD: Error = Error::InvalidInput("malformed or oversized CBOR");

/// Checks that `data` is exactly one well-formed, definite-length CBOR item within limits.
pub fn check(data: &[u8], max_depth: usize, max_items: usize) -> Result<()> {
    let mut pos = 0usize;
    let mut items = 0usize;
    // Remaining children of every open container/tag; its length is the current depth.
    let mut stack: Vec<u64> = Vec::new();
    loop {
        items += 1;
        if items > max_items {
            return Err(BAD);
        }
        let b = *data.get(pos).ok_or(BAD)?;
        pos += 1;
        let major = b >> 5;
        let ai = b & 31;
        let arg: u64 = match ai {
            0..=23 => u64::from(ai),
            24..=27 => {
                let n = 1usize << (ai - 24);
                let end = pos.checked_add(n).ok_or(BAD)?;
                let bytes = data.get(pos..end).ok_or(BAD)?;
                pos = end;
                bytes.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x))
            }
            _ => return Err(BAD), // 28..=30 reserved, 31 indefinite length / break
        };
        let mut opened = false;
        match major {
            0 | 1 | 7 => {}
            2 | 3 => {
                let len = usize::try_from(arg).map_err(|_| BAD)?;
                pos = pos.checked_add(len).ok_or(BAD)?;
                if pos > data.len() {
                    return Err(BAD);
                }
            }
            4..=6 => {
                let children = match major {
                    4 => arg,
                    5 => arg.checked_mul(2).ok_or(BAD)?,
                    _ => 1,
                };
                // Every child needs at least one byte.
                if children > (data.len() - pos) as u64 {
                    return Err(BAD);
                }
                if children > 0 {
                    if stack.len() + 1 > max_depth {
                        return Err(BAD);
                    }
                    stack.push(children);
                    opened = true;
                }
            }
            _ => return Err(BAD),
        }
        if opened {
            continue;
        }
        // A leaf (or empty container) completed: close every container it finishes.
        loop {
            match stack.last_mut() {
                None => return if pos == data.len() { Ok(()) } else { Err(BAD) },
                Some(top) => {
                    *top -= 1;
                    if *top == 0 {
                        stack.pop();
                    } else {
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_simple_and_rejects_bad() {
        assert!(check(&[0x83, 1, 2, 3], 4, 10).is_ok());
        assert!(check(&[0x82, 1], 4, 10).is_err(), "truncated array");
        assert!(check(&[0x01, 0x02], 4, 10).is_err(), "trailing byte");
        assert!(check(&[0x5f, 0xff], 4, 10).is_err(), "indefinite");
        assert!(check(&[0x9f, 0xff], 4, 10).is_err(), "indefinite array");
        assert!(
            check(&[0x5a, 0xff, 0xff, 0xff, 0xff], 4, 10).is_err(),
            "huge bstr"
        );
        assert!(check(
            &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            4,
            10
        )
        .is_err());
        assert!(check(&[0x1c], 4, 10).is_err(), "reserved ai");
        assert!(check(&[], 4, 10).is_err());
        assert!(check(&[0xc0, 0x01], 4, 10).is_ok(), "tag");
    }

    #[test]
    fn depth_and_item_limits() {
        let nested = |n: usize| {
            let mut v = vec![0x81u8; n];
            v.push(0);
            v
        };
        assert!(check(&nested(4), 4, 100).is_ok());
        assert!(check(&nested(5), 4, 100).is_err());
        assert!(check(&nested(100_000), 16, 1_000_000).is_err());
        let mut wide = vec![0x98, 200];
        wide.extend(std::iter::repeat(0u8).take(200));
        assert!(check(&wide, 4, 300).is_ok());
        assert!(check(&wide, 4, 100).is_err());
    }
}
