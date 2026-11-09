//! Strict parser for composition strings: `ctor(arg[,arg...])`, nested.
//!
//! Rules: at most 128 bytes, at most 4 levels of calls, at most 4 arguments per call, no
//! whitespace, lowercase only, characters `a-z 0-9 - _ . ( ) ,`. Anything else is an explicit
//! error; nothing is normalised silently (aliases are resolved later, by the planner).

use nextssl_core::{Error, Result};

pub const MAX_LEN: usize = 128;
pub const MAX_DEPTH: usize = 4;
pub const MAX_ARGS: usize = 4;

/// Parsed composition tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A bare name: a digest, cipher or registered algorithm id.
    Leaf(String),
    /// A constructor with arguments.
    Call { name: String, args: Vec<Node> },
}

impl Node {
    /// The text form of the tree (without any alias resolution).
    pub fn render(&self) -> String {
        match self {
            Node::Leaf(n) => n.clone(),
            Node::Call { name, args } => {
                let a: Vec<String> = args.iter().map(Node::render).collect();
                format!("{name}({})", a.join(","))
            }
        }
    }
}

fn ident_byte(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'_' | b'.')
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn ident(&mut self) -> Result<String> {
        let start = self.i;
        while self.peek().is_some_and(ident_byte) {
            self.i += 1;
        }
        if start == self.i {
            return Err(Error::InvalidInput("composition: expected a name"));
        }
        // Only ASCII bytes were accepted, so this cannot fail.
        String::from_utf8(self.b[start..self.i].to_vec())
            .map_err(|_| Error::InvalidInput("composition: not ASCII"))
    }

    fn node(&mut self, depth: usize) -> Result<Node> {
        let name = self.ident()?;
        if self.peek() != Some(b'(') {
            return Ok(Node::Leaf(name));
        }
        if depth + 1 > MAX_DEPTH {
            return Err(Error::InvalidInput("composition: nesting deeper than 4"));
        }
        self.i += 1;
        let mut args = Vec::new();
        loop {
            args.push(self.node(depth + 1)?);
            if args.len() > MAX_ARGS {
                return Err(Error::InvalidInput("composition: more than 4 arguments"));
            }
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b')') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(Error::InvalidInput("composition: expected ',' or ')'")),
            }
        }
        Ok(Node::Call { name, args })
    }
}

/// Parses a composition string. A bare name is a valid tree; the planner decides whether a
/// leaf is acceptable where it appears.
pub fn parse(spec: &str) -> Result<Node> {
    if spec.is_empty() || spec.len() > MAX_LEN {
        return Err(Error::InvalidLength {
            what: "composition",
            got: spec.len(),
            min: 1,
            max: MAX_LEN,
        });
    }
    let ok = spec
        .bytes()
        .all(|c| ident_byte(c) || matches!(c, b'(' | b')' | b','));
    if !ok {
        return Err(Error::InvalidInput(
            "composition: only lowercase a-z 0-9 - _ . ( ) , are allowed (no whitespace)",
        ));
    }
    let mut p = Parser {
        b: spec.as_bytes(),
        i: 0,
    };
    let n = p.node(0)?;
    if p.i != spec.len() {
        return Err(Error::InvalidInput("composition: trailing input"));
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested() {
        let n = parse("pbkdf2(hmac(sha3-256))").unwrap();
        assert_eq!(n.render(), "pbkdf2(hmac(sha3-256))");
        assert!(matches!(parse("sha256").unwrap(), Node::Leaf(_)));
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "",
            "hmac(",
            "hmac()",
            "hmac(sha256",
            "hmac(sha256))",
            "hmac(sha256)x",
            "HMAC(sha256)",
            "hmac( sha256)",
            "hmac(sha256,)",
            "hmac(,sha256)",
            "(sha256)",
            "hmac(sha256)(a)",
            "a(b(c(d(e(f)))))",
            "h(a,b,c,d,e)",
            "hmac(sha256);",
            "hmac(sha 256)",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} must be rejected");
        }
        assert!(parse("a(b(c(d(e))))").is_ok(), "depth 4 is allowed");
        assert!(
            parse(&format!("a({})", "b".repeat(130))).is_err(),
            "length cap"
        );
    }
}
