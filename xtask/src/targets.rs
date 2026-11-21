//! `exclude_targets` in algo.toml: keeps the algorithm crate buildable everywhere by making it an
//! empty crate on an excluded target. `cargo xtask gen` owns two marker blocks:
//! - `glue.rs`: a crate-level `#![cfg(not(..))]` after the leading `//!` lines;
//! - `build.rs`: an early return at the top of `fn main()` on the excluded target.
//!
//! The registry entry carries the same predicate (`cfg_gate`), so the id is absent there, never
//! silently replaced.

use crate::{target_gate, Algo};
use std::path::PathBuf;

const GLUE_MARK: &str = "// TARGET GATE (cargo xtask gen, from algo.toml exclude_targets)\n";
const BUILD_BEGIN: &str =
    "    // BEGIN TARGET GATE (cargo xtask gen, from algo.toml exclude_targets)\n";
const BUILD_END: &str = "    // END TARGET GATE\n";

fn strip_glue(s: &str) -> String {
    match s.find(GLUE_MARK) {
        Some(i) => {
            let rest = &s[i + GLUE_MARK.len()..];
            let nl = rest.find('\n').map_or(rest.len(), |n| n + 1);
            format!("{}{}", &s[..i], &rest[nl..])
        }
        None => s.to_string(),
    }
}

fn strip_build(s: &str) -> String {
    match (s.find(BUILD_BEGIN), s.find(BUILD_END)) {
        (Some(b), Some(e)) if e > b => format!("{}{}", &s[..b], &s[e + BUILD_END.len()..]),
        _ => s.to_string(),
    }
}

/// Expected glue.rs text.
fn glue(cur: &str, gate: Option<&str>) -> String {
    let base = strip_glue(cur);
    let Some(g) = gate else { return base };
    // Insert after the leading block of `//!` lines (inner doc comments).
    let mut at = 0;
    for line in base.split_inclusive('\n') {
        if line.starts_with("//!") {
            at += line.len();
        } else {
            break;
        }
    }
    format!("{}{GLUE_MARK}#![cfg({g})]\n{}", &base[..at], &base[at..])
}

/// cfg-expression check usable inside build.rs (CARGO_CFG_* env vars).
fn build_test(a: &Algo) -> String {
    let parts: Vec<String> = a
        .exclude_targets
        .iter()
        .map(|t| match t.as_str() {
            "msvc" => "std::env::var(\"CARGO_CFG_TARGET_ENV\").as_deref() == Ok(\"msvc\")".into(),
            "wasm32" => {
                "std::env::var(\"CARGO_CFG_TARGET_ARCH\").as_deref() == Ok(\"wasm32\")".into()
            }
            other => unreachable!("validated target {other}"),
        })
        .collect();
    parts.join("\n        || ")
}

/// Expected build.rs text.
fn build(cur: &str, a: &Algo) -> Result<String, String> {
    let base = strip_build(cur);
    if a.exclude_targets.is_empty() {
        return Ok(base);
    }
    let main = "fn main() {\n";
    let i = base
        .find(main)
        .ok_or_else(|| format!("{}: build.rs has no `fn main() {{`", a.id))?
        + main.len();
    let reason = a.exclude_reason.as_deref().unwrap_or_default();
    // rustfmt puts the opening brace of a multi-line condition on its own line; emit the same
    // layout so `cargo fmt` and `cargo xtask gen --check` agree.
    let open = if a.exclude_targets.len() > 1 {
        "\n    {"
    } else {
        " {"
    };
    Ok(format!(
        "{}{BUILD_BEGIN}    // Excluded: {reason}\n    if {}{open}\n        return;\n    }}\n{BUILD_END}{}",
        &base[..i],
        build_test(a),
        &base[i..]
    ))
}

/// (path, expected content) for every glue.rs / build.rs whose expected text differs from disk.
pub fn outputs(root: &std::path::Path, algos: &[Algo]) -> Result<Vec<(PathBuf, String)>, String> {
    let mut out = Vec::new();
    for a in algos {
        let dir = root.join("algos").join(&a.dir);
        let gate = target_gate(a);
        for (name, is_glue) in [("glue.rs", true), ("build.rs", false)] {
            let p = dir.join(name);
            let Ok(raw) = std::fs::read_to_string(&p) else {
                continue;
            };
            let cur = raw.replace("\r\n", "\n");
            let want = if is_glue {
                glue(&cur, gate.as_deref())
            } else {
                build(&cur, a)?
            };
            if want != cur {
                out.push((p, want));
            }
        }
    }
    Ok(out)
}
