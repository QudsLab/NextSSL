//! Flat root accessors: `crates/nextssl-root/src/generated.rs`.
//!
//! One module per algorithm id (`sha3-256` -> `sha3_256`, ids starting with a digit get the
//! prefix `a_`) with kind-specific free functions that call the string-based functions of
//! `nextssl-root` with that id, plus `ID` and `INFO`. The generator fails when two ids map to
//! the same module name or a module name collides with an item of the root crate (the file is
//! also `include!`d, so the compiler would reject a clash too).

use crate::{Algo, Res};
use nextssl_core::Kind;
use std::collections::BTreeMap;
use std::fmt::Write as _;

const KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub",
    "ref", "return", "self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use",
    "where", "while", "abstract", "become", "box", "do", "final", "gen", "macro", "override",
    "priv", "try", "typeof", "unsized", "virtual", "yield",
];

/// Names that exist in the extern prelude or are used inside the generated file.
const EXTERN_NAMES: &[&str] = &[
    "std",
    "core",
    "alloc",
    "nextssl",
    "nextssl_core",
    "nextssl_registry",
    "nextssl_root",
    "generated",
    "tests",
];

/// Rust module name for an algorithm id.
pub fn module_name(id: &str) -> String {
    let m = id.replace('-', "_");
    if m.starts_with(|c: char| c.is_ascii_digit()) {
        format!("a_{m}")
    } else {
        m
    }
}

/// Identifiers declared at the top level of the root crate source, plus everything its `use`
/// statements bring in. Deliberately over-approximate.
pub fn root_item_names(lib_rs: &str) -> Vec<String> {
    fn idents(s: &str) -> Vec<String> {
        s.split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect()
    }
    let mut names = Vec::new();
    let mut in_use = false;
    let mut use_buf = String::new();
    for line in lib_rs.lines() {
        if in_use {
            use_buf.push_str(line);
            use_buf.push(' ');
            if line.contains(';') {
                in_use = false;
                names.extend(use_names(&use_buf));
                use_buf.clear();
            }
            continue;
        }
        if line.starts_with(char::is_whitespace) || line.starts_with("//") {
            continue; // nested item or comment
        }
        let mut l = line;
        for p in ["pub(crate) ", "pub "] {
            if let Some(r) = l.strip_prefix(p) {
                l = r;
            }
        }
        if let Some(rest) = l.strip_prefix("use ") {
            if rest.contains(';') {
                names.extend(use_names(rest));
            } else {
                in_use = true;
                use_buf = format!("{rest} ");
            }
            continue;
        }
        for kw in [
            "fn ", "mod ", "struct ", "enum ", "type ", "const ", "static ", "trait ", "union ",
        ] {
            if let Some(rest) = l.strip_prefix(kw) {
                if let Some(n) = idents(rest).into_iter().next() {
                    names.push(n);
                }
            }
        }
    }
    names
}

/// Names a `use` statement may introduce: every identifier not followed by `::`, `as` targets,
/// and the path segment before `::{self`.
fn use_names(stmt: &str) -> Vec<String> {
    let stmt = stmt.split(';').next().unwrap_or("");
    let toks: Vec<&str> = stmt
        .split(|c: char| c.is_whitespace() || c == ',' || c == '{' || c == '}')
        .filter(|t| !t.is_empty())
        .collect();
    let mut out = Vec::new();
    let mut prev_path: Option<String> = None;
    for t in toks {
        // `a::b::c` or `a::b::{` split by '{' leaves `a::b::`
        let segs: Vec<&str> = t.split("::").filter(|s| !s.is_empty()).collect();
        if t.ends_with("::") {
            prev_path = segs.last().map(|s| s.to_string());
            continue;
        }
        match segs.last() {
            Some(&"self") => {
                if let Some(p) = &prev_path {
                    out.push(p.clone());
                }
            }
            Some(&"as") => {}
            Some(s) => out.push((*s).to_string()),
            None => {}
        }
        if segs.len() > 1 && !t.ends_with("::") {
            prev_path = None;
        }
    }
    out
}

struct Op {
    name: String,
    /// Parameters after `params`/before the call.
    args: String,
    ret: String,
    /// Root function (`<root>` and `<root>_with`).
    root: String,
    /// Arguments forwarded to the root function after the algorithm id (and `params`).
    call: String,
    /// Generate `<name>_with(params, ...)` too.
    with: bool,
    /// Root function takes the algorithm id first.
    alg_first: bool,
}

fn op(name: &str, args: &str, ret: &str, root: &str, call: &str) -> Op {
    Op {
        name: name.to_string(),
        args: args.to_string(),
        ret: ret.to_string(),
        root: root.to_string(),
        call: call.to_string(),
        with: true,
        alg_first: true,
    }
}

fn no_with(o: Op) -> Op {
    Op { with: false, ..o }
}

const VEC: &str = "crate::Result<Vec<u8>>";
const ZVEC: &str = "crate::Result<::nextssl_core::Zeroizing<Vec<u8>>>";
const KEY: &str = "&::nextssl_core::SymmetricKey";
const PK: &str = "&::nextssl_core::PublicKey";
const SK: &str = "&::nextssl_core::PrivateKey";
const PAIR: &str = "crate::Result<(::nextssl_core::PublicKey, ::nextssl_core::PrivateKey)>";

/// The operations generated per kind. Kinds not listed here (mode, rng, drbg, pow, pake,
/// statefulsign, he) have no root string API and get `ID` and `INFO` only.
fn ops(kind: Kind) -> Vec<Op> {
    match kind {
        Kind::Hash => vec![op("hash", "data: &[u8]", VEC, "hash", "data")],
        Kind::Xof => vec![op(
            "squeeze",
            "data: &[u8], out_len: usize",
            VEC,
            "xof",
            "data, out_len",
        )],
        Kind::Checksum => vec![op("checksum", "data: &[u8]", VEC, "checksum", "data")],
        Kind::Encoding => vec![
            op("encode", "data: &[u8]", VEC, "encode", "data"),
            op("decode", "text: &[u8]", VEC, "decode", "text"),
        ],
        Kind::Mac => vec![
            op(
                "tag",
                &format!("key: {KEY}, data: &[u8]"),
                VEC,
                "mac",
                "key, data",
            ),
            op(
                "verify",
                &format!("key: {KEY}, data: &[u8], tag: &[u8]"),
                "crate::Result<bool>",
                "mac_verify",
                "key, data, tag",
            ),
        ],
        Kind::Kdf => vec![op(
            "derive",
            &format!("ikm: {KEY}, salt: &[u8], info: &[u8], out_len: usize"),
            ZVEC,
            "kdf",
            "ikm, salt, info, out_len",
        )],
        Kind::PwHash => vec![
            op(
                "hash",
                "password: &[u8]",
                "crate::Result<String>",
                "password_hash",
                "password",
            ),
            op(
                "hash_salted",
                "password: &[u8], salt: &[u8]",
                "crate::Result<String>",
                "password_hash_salted",
                "password, salt",
            ),
            op(
                "verify",
                "password: &[u8], phc: &str",
                "crate::Result<bool>",
                "password_verify",
                "password, phc",
            ),
            op(
                "derive",
                "password: &[u8], salt: &[u8], out_len: usize",
                ZVEC,
                "password_derive",
                "password, salt, out_len",
            ),
        ],
        Kind::Aead => vec![
            op(
                "seal",
                &format!("key: {KEY}, nonce: &[u8], aad: &[u8], pt: &[u8]"),
                VEC,
                "aead_seal",
                "key, nonce, aad, pt",
            ),
            op(
                "open",
                &format!("key: {KEY}, nonce: &[u8], aad: &[u8], ct: &[u8]"),
                ZVEC,
                "aead_open",
                "key, nonce, aad, ct",
            ),
            // COSE_Encrypt0 envelope with a fresh random nonce; no `params` form.
            no_with(op(
                "encrypt",
                &format!("key: {KEY}, plaintext: &[u8], aad: &[u8]"),
                VEC,
                "encrypt_with_key",
                "key, plaintext, aad",
            )),
            no_with(op(
                "decrypt",
                &format!("key: {KEY}, envelope: &[u8], aad: &[u8]"),
                ZVEC,
                "decrypt_as",
                "key, envelope, aad",
            )),
        ],
        Kind::BlockCipher => vec![
            op(
                "encrypt_block",
                &format!("key: {KEY}, block: &mut [u8]"),
                "crate::Result<()>",
                "block_encrypt",
                "key, block",
            ),
            op(
                "decrypt_block",
                &format!("key: {KEY}, block: &mut [u8]"),
                "crate::Result<()>",
                "block_decrypt",
                "key, block",
            ),
        ],
        Kind::StreamCipher => vec![op(
            "apply_keystream",
            &format!("key: {KEY}, nonce: &[u8], data: &mut [u8]"),
            "crate::Result<()>",
            "stream_apply",
            "key, nonce, data",
        )],
        Kind::Kem => vec![
            op("keygen", "", PAIR, "kem_keygen", ""),
            op(
                "encapsulate",
                &format!("pk: {PK}"),
                "crate::Result<(::nextssl_core::Ciphertext, ::nextssl_core::SharedSecret)>",
                "kem_encapsulate",
                "pk",
            ),
            op(
                "decapsulate",
                &format!("sk: {SK}, ct: &::nextssl_core::Ciphertext"),
                "crate::Result<::nextssl_core::SharedSecret>",
                "kem_decapsulate",
                "sk, ct",
            ),
        ],
        Kind::Kex => vec![
            op("keygen", "", PAIR, "kex_keygen", ""),
            op(
                "agree",
                &format!("sk: {SK}, peer_pk: {PK}"),
                "crate::Result<::nextssl_core::SharedSecret>",
                "kex_agree",
                "sk, peer_pk",
            ),
        ],
        Kind::Sign => vec![
            op("keygen", "", PAIR, "sign_keygen", ""),
            // COSE_Sign1 envelope with the OS RNG; no `params` form.
            no_with(op(
                "sign",
                &format!("sk: {SK}, message: &[u8], aad: &[u8]"),
                VEC,
                "sign",
                "sk, message, aad",
            )),
            no_with(op(
                "verify",
                &format!("pk: {PK}, envelope: &[u8], aad: &[u8]"),
                VEC,
                "verify",
                "pk, envelope, aad",
            )),
        ],
        Kind::BlockMode => vec![
            op(
                "encrypt",
                &format!("key: {KEY}, nonce: &[u8], data: &[u8]"),
                VEC,
                "blockmode_encrypt",
                "key, nonce, data",
            ),
            op(
                "decrypt",
                &format!("key: {KEY}, nonce: &[u8], data: &[u8]"),
                "crate::Result<::nextssl_core::Zeroizing<Vec<u8>>>",
                "blockmode_decrypt",
                "key, nonce, data",
            ),
        ],
        // Root-only kinds (BRIEF_kinds.md): string entry points in nextssl-root, no envelope.
        Kind::Pke => vec![
            op("keygen", "", PAIR, "pke_keygen", ""),
            op(
                "encrypt",
                &format!("pk: {PK}, pt: &[u8], label: &[u8]"),
                VEC,
                "pke_encrypt",
                "pk, pt, label",
            ),
            op(
                "decrypt",
                &format!("sk: {SK}, ct: &[u8], label: &[u8]"),
                ZVEC,
                "pke_decrypt",
                "sk, ct, label",
            ),
        ],
        Kind::Zk => vec![
            op("setup", "setup_params: &[u8]", VEC, "zk_setup", "setup_params"),
            op(
                "prove",
                "setup: &[u8], statement: &[u8], witness: &[u8]",
                VEC,
                "zk_prove",
                "setup, statement, witness",
            ),
            op(
                "verify",
                "setup: &[u8], statement: &[u8], proof: &[u8]",
                "crate::Result<bool>",
                "zk_verify",
                "setup, statement, proof",
            ),
        ],
        Kind::Vdf => vec![
            op(
                "eval",
                "challenge: &[u8], t: u64",
                "crate::Result<(Vec<u8>, Vec<u8>)>",
                "vdf_eval",
                "challenge, t",
            ),
            op(
                "verify",
                "challenge: &[u8], t: u64, output: &[u8], proof: &[u8]",
                "crate::Result<bool>",
                "vdf_verify",
                "challenge, t, output, proof",
            ),
        ],
        Kind::Threshold => vec![
            op(
                "split",
                "secret: &[u8], t: usize, n: usize",
                "crate::Result<Vec<::nextssl_core::Share>>",
                "threshold_split",
                "secret, t, n",
            ),
            op(
                "combine",
                "shares: &[::nextssl_core::Share]",
                ZVEC,
                "threshold_combine",
                "shares",
            ),
        ],
        // Interactive or multi-object kinds are used through `nextssl_registry::new_<kind>_in`.
        Kind::Mode
        | Kind::Rng
        | Kind::Drbg
        | Kind::Pow
        | Kind::Pake
        | Kind::StatefulSign
        | Kind::He => vec![],
    }
}

fn fn_item(o: &Op, with_params: bool) -> String {
    let mut decl: Vec<&str> = Vec::new();
    let mut call: Vec<&str> = Vec::new();
    if o.alg_first {
        call.push("ID");
    }
    if with_params {
        decl.push("params: &::nextssl_core::Params");
        call.push("params");
    }
    if !o.args.is_empty() {
        decl.push(&o.args);
    }
    if !o.call.is_empty() {
        call.push(&o.call);
    }
    let (suffix, root_fn) = if with_params {
        ("_with", format!("{}_with", o.root))
    } else {
        ("", o.root.clone())
    };
    format!(
        "    pub fn {}{suffix}({}) -> {} {{\n        crate::{root_fn}({})\n    }}\n",
        o.name,
        decl.join(", "),
        o.ret,
        call.join(", "),
    )
}

/// Builds `generated.rs` (unformatted). `lib_rs` is the source of the root crate, used for
/// the collision check.
pub fn gen_root(algos: &[Algo], lib_rs: &str) -> Res<String> {
    let mut reserved: Vec<String> = root_item_names(lib_rs);
    reserved.extend(EXTERN_NAMES.iter().map(|s| s.to_string()));
    let mut modules: BTreeMap<String, &Algo> = BTreeMap::new();
    for a in algos {
        let m = module_name(&a.id);
        if KEYWORDS.contains(&m.as_str()) {
            return Err(format!(
                "root accessor: module name `{m}` for id {} is a Rust keyword",
                a.id
            ));
        }
        if reserved.contains(&m) {
            return Err(format!(
                "root accessor: module `{m}` (id {}) collides with an item of nextssl-root",
                a.id
            ));
        }
        if let Some(prev) = modules.insert(m.clone(), a) {
            return Err(format!(
                "root accessor: ids {} and {} both map to module `{m}`",
                prev.id, a.id
            ));
        }
    }

    let mut s = String::new();
    s.push_str("// @generated by `cargo xtask gen` from algos/**/algo.toml. DO NOT EDIT.\n");
    s.push_str("// Included into the crate root of `nextssl-root` (see lib.rs).\n\n");
    // Ordered by id so the output is deterministic.
    let mut by_id: Vec<(&String, &Algo)> = modules.iter().map(|(m, a)| (m, *a)).collect();
    by_id.sort_by(|x, y| x.1.id.cmp(&y.1.id));
    for (m, a) in &by_id {
        let kind = Kind::parse(&a.kind).expect("validated kind");
        let gate = match crate::cfg_gate(a) {
            Some(g) => format!("#[cfg({g})]\n"),
            None => String::new(),
        };
        let has_required = a.params.values().any(|p| p.required);
        let _ = writeln!(s, "/// `{}` ({}, tier {}).", a.id, a.kind, a.tier);
        if has_required {
            let _ = writeln!(
                s,
                "/// Has required parameters: only the `*_with` forms can succeed."
            );
        }
        s.push_str(&gate);
        let _ = writeln!(s, "pub mod {m} {{");
        let _ = writeln!(s, "    /// Registry id.");
        let _ = writeln!(s, "    pub const ID: &str = {:?};", a.id);
        let _ = writeln!(
            s,
            "    /// Registry entry: metadata, sizes and parameter schema."
        );
        let _ = writeln!(
            s,
            "    pub static INFO: ::std::sync::LazyLock<&'static ::nextssl_registry::AlgoInfo> =\n        ::std::sync::LazyLock::new(|| ::nextssl_registry::lookup(ID).expect(\"registered id\"));"
        );
        for o in ops(kind) {
            // The plain form uses schema defaults, which cannot work when a parameter is
            // required. Envelope ops (no `_with` form) take no parameters at all.
            if !has_required {
                s.push_str(&fn_item(&o, false));
            }
            if o.with {
                s.push_str(&fn_item(&o, true));
            }
        }
        let _ = writeln!(s, "}}\n");
    }

    // Test list: one entry per module, referencing the module so a missing one fails to
    // compile, and the registry is compared against it.
    s.push_str("#[cfg(test)]\nmod generated_module_list {\n");
    s.push_str("    /// `(id, INFO id)` for every generated module.\n");
    s.push_str("    fn modules() -> Vec<(&'static str, &'static str)> {\n        vec![\n");
    for (m, a) in &by_id {
        if let Some(g) = crate::cfg_gate(a) {
            let _ = writeln!(s, "            #[cfg({g})]");
        }
        let _ = writeln!(s, "            ({:?}, crate::{m}::INFO.id),", a.id);
    }
    s.push_str("        ]\n    }\n\n");
    s.push_str(
        "    #[test]\n    fn every_registered_id_has_a_root_module() {\n\
         \x20       let listed = modules();\n\
         \x20       for (id, info_id) in &listed {\n\
         \x20           assert_eq!(id, info_id, \"module INFO names a different algorithm\");\n\
         \x20       }\n\
         \x20       let mut registered: Vec<&str> = nextssl_registry::all().iter().map(|a| a.id).collect();\n\
         \x20       let mut have: Vec<&str> = listed.iter().map(|(id, _)| *id).collect();\n\
         \x20       registered.sort_unstable();\n\
         \x20       have.sort_unstable();\n\
         \x20       assert_eq!(registered, have, \"registry and generated root modules differ\");\n\
         \x20   }\n}\n",
    );
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_names() {
        assert_eq!(module_name("sha3-256"), "sha3_256");
        assert_eq!(module_name("3des"), "a_3des");
        assert_eq!(module_name("md5"), "md5");
    }

    #[test]
    fn root_names_are_collected() {
        let src = "use nextssl::envelope::{self, Limits};\nuse nextssl_core::{EntropySource, Params as P};\n\
                   pub use nextssl_core::{Error, Result};\npub fn hash(a: u8) {}\nfn os_rng() {}\n\
                   pub mod inner {}\n    fn nested() {}\nconst MAX: usize = 1;\n";
        let n = root_item_names(src);
        for want in [
            "envelope",
            "Limits",
            "EntropySource",
            "Error",
            "Result",
            "hash",
            "os_rng",
            "inner",
            "MAX",
        ] {
            assert!(n.iter().any(|x| x == want), "{want} missing in {n:?}");
        }
        assert!(!n.iter().any(|x| x == "nested"));
    }
}

#[cfg(test)]
mod collision_tests {
    use super::*;

    fn algo(id: &str, kind: &str, extra: &str) -> Algo {
        let text = format!(
            "id = \"{id}\"\nkind = \"{kind}\"\ncategory = \"c\"\nfamily = \"f\"\ntier = \"safe\"\nstatus = \"active\"\n\
             upstream = {{ crate = \"x\", version = \"=1.0.0\", license = \"MIT\" }}\n{extra}\n[kat]\nfiles = [\"kat/a.json\"]\n"
        );
        let mut a: Algo = toml::from_str(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        a.dir = format!("c/f/{id}");
        a
    }

    const LIB: &str = "pub fn hash(a: u8) {}\nfn os_rng() {}\nuse nextssl_core::{Error, Result};\n";

    #[test]
    fn two_ids_one_module_is_an_error() {
        let e = gen_root(&[algo("3x", "hash", ""), algo("a-3x", "hash", "")], LIB).unwrap_err();
        assert!(e.contains("both map to module `a_3x`"), "{e}");
    }

    #[test]
    fn clash_with_a_root_item_is_an_error() {
        let e = gen_root(&[algo("hash", "hash", "")], LIB).unwrap_err();
        assert!(e.contains("collides"), "{e}");
        let e = gen_root(&[algo("os-rng", "hash", "")], LIB).unwrap_err();
        assert!(e.contains("collides"), "{e}");
        let e = gen_root(&[algo("match", "hash", "")], LIB).unwrap_err();
        assert!(e.contains("keyword"), "{e}");
    }

    #[test]
    fn modules_and_test_list_are_generated() {
        let params = "[params.hrp]\ntype = \"str\"\nmin = 1\nmax = 8\nrequired = true\ntest_value = \"ab\"\n";
        let s = gen_root(
            &[
                algo("sha3-256", "hash", ""),
                algo("bech32", "encoding", params),
            ],
            LIB,
        )
        .unwrap();
        assert!(s.contains("pub mod sha3_256 {"));
        assert!(s.contains("pub fn hash(data: &[u8])"));
        assert!(s.contains("pub fn hash_with(params: &::nextssl_core::Params, data: &[u8])"));
        // required param: only the `_with` forms exist
        assert!(s.contains("pub fn encode_with("));
        assert!(!s.contains("pub fn encode(data"));
        assert!(s.contains("every_registered_id_has_a_root_module"));
        assert!(s.contains("(\"sha3-256\", crate::sha3_256::INFO.id)"));
    }
}
