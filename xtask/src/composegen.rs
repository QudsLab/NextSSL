//! Composition-engine generator: `digest` / `digests` / `cipher` fields of `algo.toml` ->
//! `crates/nextssl-compose/src/generated.rs` (slot tables and the `with_digest!` /
//! `with_cipher!` dispatch macros) and the generated blocks of that crate's `Cargo.toml`.
//!
//! The dispatch is glue only: the crypto stays in the upstream generic crates (`hmac`, `hkdf`,
//! `pbkdf2`, `cmac`, `cbc`, ...) instantiated with the digest or cipher type named here.
//! SHA-2, SHA-3 and AES are always compiled in; every other type is behind the cargo feature
//! `compose-all`, and selecting one without it is an explicit `Unsupported` error.

use super::{is_ident, Algo, Res};
use nextssl_core::Kind;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Crates (library names) compiled without `compose-all`.
const DEFAULT_LIBS: &[&str] = &["sha2", "sha3", "aes"];

fn path_ok(p: &str) -> bool {
    match p.split_once("::") {
        Some((lib, ty)) => {
            !lib.is_empty()
                && lib
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                && !ty.is_empty()
                && ty.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// Per-algorithm checks of the engine fields (called from `validate`).
pub fn validate_slots(a: &Algo, kind: Kind) -> Res<()> {
    let ctx = |m: &str| format!("{}: {m}", a.id);
    let has_digest = a.digest.is_some() || !a.digests.is_empty();
    if has_digest && kind != Kind::Hash {
        return Err(ctx("`digest`/`digests` are only valid for kind hash"));
    }
    if a.digest.is_some() && !a.digests.is_empty() {
        return Err(ctx("use either `digest` or `digests`, not both"));
    }
    if a.cipher.is_some() && kind != Kind::BlockCipher {
        return Err(ctx("`cipher` is only valid for kind blockcipher"));
    }
    if let Some(v) = &a.slot_version {
        if !(has_digest || a.cipher.is_some()) || !v.starts_with('=') || v.len() < 2 {
            return Err(ctx(
                "`slot_version` is an exact pin and needs a digest/cipher slot",
            ));
        }
    }
    if has_digest || a.cipher.is_some() {
        if a.upstream.krate.is_none() || a.upstream.version.is_none() {
            return Err(ctx(
                "`digest`/`cipher` need a crate upstream with a version",
            ));
        }
        if a.copyleft {
            return Err(ctx("copyleft algorithms cannot be composition slots"));
        }
    }
    for p in a
        .digest
        .iter()
        .chain(a.digests.values())
        .chain(a.cipher.iter())
    {
        if !path_ok(p) {
            return Err(ctx(&format!("bad type path {p:?} (want `lib::Type`)")));
        }
    }
    for name in a.digests.keys() {
        if !is_ident(name) {
            return Err(ctx(&format!("bad slot name {name:?}")));
        }
    }
    Ok(())
}

struct Slot {
    name: String,
    path: String,
    algo: String,
    tier: String,
    aliases: Vec<String>,
    krate: String,
    version: String,
    cipher: bool,
}

impl Slot {
    fn lib(&self) -> &str {
        self.path.split("::").next().unwrap_or("")
    }
    fn default_set(&self) -> bool {
        DEFAULT_LIBS.contains(&self.lib())
    }
}

fn collect(algos: &[Algo]) -> Res<(Vec<Slot>, Vec<Slot>)> {
    let (mut digests, mut ciphers) = (Vec::new(), Vec::new());
    for a in algos {
        let mut push = |name: &str, path: &str, cipher: bool, aliases: &[String]| {
            let s = Slot {
                name: name.to_string(),
                path: path.to_string(),
                algo: a.id.clone(),
                tier: a.tier.clone(),
                aliases: aliases.to_vec(),
                krate: a.upstream.krate.clone().unwrap_or_default(),
                version: a
                    .slot_version
                    .clone()
                    .or_else(|| a.upstream.version.clone())
                    .unwrap_or_default(),
                cipher,
            };
            if cipher {
                ciphers.push(s);
            } else {
                digests.push(s);
            }
        };
        if let Some(p) = &a.digest {
            push(&a.id, p, false, &a.aliases);
        }
        for (n, p) in &a.digests {
            push(n, p, false, &[]);
        }
        if let Some(p) = &a.cipher {
            push(&a.id, p, true, &a.aliases);
        }
    }
    for list in [&mut digests, &mut ciphers] {
        list.sort_by(|x, y| x.name.cmp(&y.name));
        for w in list.windows(2) {
            if w[0].name == w[1].name {
                return Err(format!("duplicate composition slot name {}", w[0].name));
            }
        }
    }
    Ok((digests, ciphers))
}

/// Dependencies by library name: `(package, version, is_cipher, in default set)`.
fn deps(digests: &[Slot], ciphers: &[Slot]) -> Res<BTreeMap<String, (String, String, bool, bool)>> {
    let mut m: BTreeMap<String, (String, String, bool, bool)> = BTreeMap::new();
    for s in digests.iter().chain(ciphers.iter()) {
        let e = (
            s.krate.clone(),
            s.version.clone(),
            s.cipher,
            s.default_set(),
        );
        match m.get(s.lib()) {
            Some(prev) if prev.0 != e.0 || prev.1 != e.1 => {
                return Err(format!(
                    "composition slots disagree on crate `{}`: {} {} vs {} {}",
                    s.lib(),
                    prev.0,
                    prev.1,
                    e.0,
                    e.1
                ))
            }
            Some(_) => {}
            None => {
                m.insert(s.lib().to_string(), e);
            }
        }
    }
    Ok(m)
}

fn tier_variant(t: &str) -> String {
    let mut c = t.chars();
    c.next().unwrap().to_uppercase().collect::<String>() + c.as_str()
}

fn table(out: &mut String, name: &str, slots: &[Slot]) {
    let _ = writeln!(out, "pub const {name}: &[Part] = &[");
    for s in slots {
        let al: Vec<String> = s.aliases.iter().map(|a| format!("{a:?}")).collect();
        let compiled = if s.default_set() {
            "true".to_string()
        } else {
            "cfg!(feature = \"compose-all\")".to_string()
        };
        let _ = writeln!(
            out,
            "Part {{ name: {:?}, aliases: &[{}], algo: {:?}, tier: Tier::{}, compiled: {compiled} }},",
            s.name,
            al.join(", "),
            s.algo,
            tier_variant(&s.tier)
        );
    }
    let _ = writeln!(out, "];\n");
}

fn dispatch(out: &mut String, mac: &str, slots: &[Slot]) {
    let _ = writeln!(out, "#[allow(unused_macros)]\nmacro_rules! {mac} {{");
    let _ = writeln!(
        out,
        "($name:expr, $t:ident => $body:expr) => {{ match $name {{"
    );
    for s in slots {
        if s.default_set() {
            let _ = writeln!(out, "{:?} => {{ type $t = {}; $body }}", s.name, s.path);
        } else {
            let _ = writeln!(
                out,
                "#[cfg(feature = \"compose-all\")] {:?} => {{ type $t = {}; $body }}",
                s.name, s.path
            );
            let _ = writeln!(
                out,
                "#[cfg(not(feature = \"compose-all\"))] {:?} => Err(nextssl_core::Error::Unsupported),",
                s.name
            );
        }
    }
    let _ = writeln!(
        out,
        "_ => Err(nextssl_core::Error::UnknownAlgorithm), }} }}; }}\n"
    );
}

pub fn gen_compose(algos: &[Algo]) -> Res<String> {
    let (digests, ciphers) = collect(algos)?;
    let mut s = String::new();
    s.push_str(
        "// @generated by `cargo xtask gen` from the `digest`, `digests` and `cipher` fields of\n\
         // algos/**/algo.toml. Do not edit.\n\n\
         use nextssl_core::Tier;\n\n\
         /// One selectable digest or block-cipher type.\n\
         #[derive(Debug, Clone, Copy)]\n\
         pub struct Part {\n\
         /// Slot name used in composition strings.\n\
         pub name: &'static str,\n\
         pub aliases: &'static [&'static str],\n\
         /// Registry id of the algorithm that declared the slot.\n\
         pub algo: &'static str,\n\
         pub tier: Tier,\n\
         /// False when the type needs the `compose-all` cargo feature.\n\
         pub compiled: bool,\n\
         }\n\n",
    );
    table(&mut s, "DIGESTS", &digests);
    table(&mut s, "CIPHERS", &ciphers);
    dispatch(&mut s, "with_digest", &digests);
    dispatch(&mut s, "with_cipher", &ciphers);
    Ok(s)
}

pub fn gen_compose_cargo(algos: &[Algo]) -> Res<String> {
    let path = super::root().join("crates/nextssl-compose/Cargo.toml");
    let cur = std::fs::read_to_string(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .replace("\r\n", "\n");
    let (digests, ciphers) = collect(algos)?;
    let all = deps(&digests, &ciphers)?;
    let mut dep_text = String::new();
    let mut feat: Vec<String> = Vec::new();
    for (lib, (pkg, ver, cipher, default)) in &all {
        let mut f = format!("version = {ver:?}, default-features = false");
        if pkg != lib {
            f = format!("package = {pkg:?}, {f}");
        }
        if *cipher {
            f.push_str(", features = [\"zeroize\"]");
        }
        if !default {
            f.push_str(", optional = true");
            feat.push(format!("\"dep:{lib}\""));
        }
        let _ = writeln!(dep_text, "{lib} = {{ {f} }}");
    }
    let feats = format!("compose-all = [{}]\n", feat.join(", "));
    let mut out = cur.clone();
    for (what, body) in [("DEPENDENCIES", dep_text), ("FEATURES", feats)] {
        let begin = format!("# BEGIN GENERATED {what} (cargo xtask gen)\n");
        let end = format!("# END GENERATED {what}");
        let b = out
            .find(&begin)
            .ok_or(format!("compose Cargo.toml: BEGIN {what} marker missing"))?;
        let e = out
            .find(&end)
            .ok_or(format!("compose Cargo.toml: END {what} marker missing"))?;
        out = format!("{}{}{}", &out[..b + begin.len()], body, &out[e..]);
    }
    Ok(out)
}
