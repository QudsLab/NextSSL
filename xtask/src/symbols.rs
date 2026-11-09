//! `cargo xtask check-symbols`: REBUILD_PLAN section 7 symbol rules.
//!
//! 1. Every C ABI symbol exported by the `nextssl-ffi` cdylib starts with `nextssl_`, and every
//!    function declared in `nextssl.h` is really exported.
//! 2. Every unmangled global symbol defined by our own Rust code in the staticlib starts with
//!    `nextssl_`.
//! 3. Every global symbol defined by a C upstream object (the archive built by each C algo's
//!    build.rs, and the C members of the staticlib) starts with `nextssl__<algo>__`.
//!
//! Rust-mangled names (`_ZN..`, `_R..`) and std/compiler-runtime symbols are ignored.
//! Needs `nm` (binutils) or `llvm-nm`; when neither exists the check is SKIPPED with a message.

use crate::{load, root, Res};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// One defined global symbol and the archive member (object file) that defines it, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sym {
    pub member: Option<String>,
    pub name: String,
}

/// Parses default-format `nm` output (`addr type name`), including archive member headers
/// (`member.o:` lines). Only externally visible, defined symbols are returned.
pub fn parse_nm(out: &str) -> Vec<Sym> {
    let mut member: Option<String> = None;
    let mut syms = Vec::new();
    for line in out.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        if let Some(m) = line.strip_suffix(':') {
            if !m.contains(' ') {
                member = Some(m.to_string());
                continue;
            }
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() < 2 {
            continue;
        }
        let name = toks[toks.len() - 1];
        let ty = toks[toks.len() - 2];
        // Skip undefined and local symbols; keep only defined externals.
        if ty.len() != 1 {
            continue;
        }
        let c = ty.chars().next().unwrap();
        if c == 'U' || c == 'w' || c == 'v' || c.is_ascii_lowercase() && c != 'i' {
            continue;
        }
        syms.push(Sym {
            member: member.clone(),
            name: name.to_string(),
        });
    }
    syms
}

/// Mach-O prepends an underscore to every C symbol.
fn norm(name: &str) -> &str {
    if cfg!(target_os = "macos") {
        name.strip_prefix('_').unwrap_or(name)
    } else {
        name
    }
}

fn is_rust_mangled(n: &str) -> bool {
    n.starts_with("_ZN") || n.starts_with("_R") || n.starts_with('$')
}

/// Symbols the toolchain or linker adds to every shared object / runtime; not ours to rename.
fn is_toolchain_symbol(n: &str) -> bool {
    const EXACT: &[&str] = &[
        "_init",
        "_fini",
        "_edata",
        "_end",
        "__bss_start",
        "__data_start",
        "data_start",
        "__dso_handle",
        "_IO_stdin_used",
        "__TMC_END__",
        "_GLOBAL_OFFSET_TABLE_",
        "_DYNAMIC",
        "__gmon_start__",
        "__cxa_finalize",
        "__cxa_atexit",
        "_mh_dylib_header",
        "DllMain",
        "_fltused",
    ];
    EXACT.contains(&n)
        || n.starts_with("__rust")
        || n.starts_with("__rdl_")
        || n.starts_with("__rg_")
        || n.starts_with("__rustc")
        || n.starts_with("rust_")
        || n.starts_with("__imp_")
        || n.starts_with("DW.ref.")
}

/// std / compiler_builtins / third-party Rust runtime members of the staticlib: their unmangled
/// symbols are libc-style helpers (`memcpy`, `__udivti3`, ...) and are not part of our ABI.
fn is_runtime_symbol(n: &str) -> bool {
    is_toolchain_symbol(n)
        || n.starts_with("__")
        || matches!(
            n,
            "memcpy" | "memmove" | "memset" | "memcmp" | "bcmp" | "strlen" | "abort" | "floor"
        )
}

/// Pure rule for the cdylib export table. Returns the offending names.
pub fn bad_exports(exports: &[Sym]) -> Vec<String> {
    exports
        .iter()
        .map(|s| norm(&s.name))
        .filter(|n| !n.starts_with("nextssl_") && !is_rust_mangled(n) && !is_toolchain_symbol(n))
        .map(str::to_string)
        .collect()
}

/// Pure rule for the C prefixes: every symbol must start with one of `prefixes`.
pub fn bad_c_symbols(syms: &[Sym], prefixes: &[String]) -> Vec<String> {
    syms.iter()
        .map(|s| norm(&s.name))
        .filter(|n| !prefixes.iter().any(|p| n.starts_with(p.as_str())))
        .map(str::to_string)
        .collect()
}

/// Crates shipped with the Rust toolchain: their unmangled symbols (libm, memcpy, ...) are
/// the platform runtime and are not part of NextSSL's ABI.
const SYSROOT_CRATES: &[&str] = &[
    "compiler_builtins",
    "std",
    "core",
    "alloc",
    "panic_abort",
    "panic_unwind",
    "unwind",
    "libc",
    "hashbrown",
    "std_detect",
    "rustc_demangle",
    "gimli",
    "addr2line",
    "object",
    "memchr",
    "miniz_oxide",
    "adler2",
    "cfg_if",
    "rustc_std_workspace_core",
    "rustc_std_workspace_alloc",
];

/// Crate name of an object member such as `sha2-1a2b.xyz.rcgu.o` or `nextssl_ffi.abc.rcgu.o`.
fn crate_of(member: &str) -> &str {
    member.split(['-', '.']).next().unwrap_or("")
}

/// Rust-compiled object members (`*.rcgu.o`) versus C objects.
fn is_rust_member(m: &str) -> bool {
    m.contains(".rcgu.o") || m.ends_with(".rcgu.obj")
}

/// Pure rule for the staticlib.
/// - Rust members of our own crates (`nextssl_*`): unmangled globals must be `nextssl_*`.
/// - Other Rust members (std, compiler_builtins, third-party crates): runtime symbols only.
/// - C members that also appear in a C upstream's archive (`c_members`): `nextssl__<algo>__*`.
/// - Remaining C members are compiler-rt objects shipped inside compiler_builtins: runtime only.
pub fn bad_staticlib(
    syms: &[Sym],
    c_prefixes: &[String],
    c_members: &BTreeSet<String>,
) -> Vec<String> {
    let mut bad = Vec::new();
    for s in syms {
        let n = norm(&s.name);
        if is_rust_mangled(n) {
            continue;
        }
        let member = s.member.as_deref().unwrap_or("");
        let krate = crate_of(member);
        let ours = krate == "nextssl" || krate.starts_with("nextssl_");
        let ok = if c_members.contains(member) {
            c_prefixes.iter().any(|p| n.starts_with(p.as_str()))
        } else if is_rust_member(member) && ours {
            n.starts_with("nextssl_") || is_toolchain_symbol(n)
        } else if is_rust_member(member) && SYSROOT_CRATES.contains(&krate) {
            true
        } else {
            is_runtime_symbol(n) || n.starts_with("nextssl_")
        };
        if !ok {
            bad.push(format!("{n}  (in {member})"));
        }
    }
    bad
}

fn find_nm() -> Option<String> {
    let mut cands = vec!["llvm-nm".to_string(), "nm".to_string()];
    // rustup's llvm-tools component ships llvm-nm inside the sysroot.
    if let Ok(o) = Command::new("rustc").args(["--print", "sysroot"]).output() {
        let sysroot = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if let Ok(rd) = std::fs::read_dir(Path::new(&sysroot).join("lib/rustlib")) {
            for e in rd.flatten() {
                for ext in ["llvm-nm", "llvm-nm.exe"] {
                    let p = e.path().join("bin").join(ext);
                    if p.is_file() {
                        cands.insert(0, p.display().to_string());
                    }
                }
            }
        }
    }
    cands.into_iter().find(|c| {
        Command::new(c)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

fn nm(tool: &str, file: &Path, dynamic: bool) -> Res<Vec<Sym>> {
    let mut cmd = Command::new(tool);
    if dynamic && cfg!(target_os = "linux") {
        cmd.arg("-D");
    } else {
        cmd.arg("-g");
    }
    cmd.arg("--defined-only").arg(file);
    let out = cmd.output().map_err(|e| format!("{tool}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{tool} {} failed: {}",
            file.display(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(parse_nm(&String::from_utf8_lossy(&out.stdout)))
}

struct Built {
    staticlib: PathBuf,
    cdylib: PathBuf,
    /// (algo id, build-script out dir)
    c_out_dirs: Vec<(String, PathBuf)>,
}

fn build(c_ids: &[String]) -> Res<Built> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args([
            "build",
            "-p",
            "nextssl-ffi",
            // Copyleft C upstreams (sparkle) only build with this feature; check them too.
            "--features",
            "copyleft",
            "--message-format=json-render-diagnostics",
        ])
        .current_dir(root())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("cargo build: {e}"))?;
    if !out.status.success() {
        return Err("cargo build -p nextssl-ffi failed".into());
    }
    let (mut staticlib, mut cdylib) = (None, None);
    let mut c_out_dirs = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let pkg = v["package_id"].as_str().unwrap_or("");
        match v["reason"].as_str() {
            Some("compiler-artifact")
                if pkg.contains("nextssl-ffi") || pkg.contains("nextssl_ffi") =>
            {
                for f in v["filenames"].as_array().into_iter().flatten() {
                    let p = PathBuf::from(f.as_str().unwrap_or(""));
                    match p.extension().and_then(|e| e.to_str()) {
                        Some("a") | Some("lib") if !p.to_string_lossy().ends_with(".dll.lib") => {
                            staticlib = Some(p)
                        }
                        Some("so") | Some("dylib") | Some("dll") => cdylib = Some(p),
                        _ => {}
                    }
                }
            }
            Some("build-script-executed") => {
                for id in c_ids {
                    let name = format!("nextssl-algo-{id}");
                    if pkg.contains(&format!("#{name}@")) || pkg.starts_with(&format!("{name} ")) {
                        if let Some(d) = v["out_dir"].as_str() {
                            c_out_dirs.push((id.clone(), PathBuf::from(d)));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(Built {
        staticlib: staticlib.ok_or("staticlib artifact not reported by cargo")?,
        cdylib: cdylib.ok_or("cdylib artifact not reported by cargo")?,
        c_out_dirs,
    })
}

fn header_functions() -> Res<BTreeSet<String>> {
    let p = root().join("crates/nextssl-ffi/include/nextssl.h");
    let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut set = BTreeSet::new();
    for line in text.lines() {
        // Function declarations look like `int32_t nextssl_hash(` / `const char *nextssl_version(void);`
        if let Some(i) = line.find("nextssl_") {
            let rest = &line[i..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            if rest[end..].starts_with('(') && !line.trim_start().starts_with("//") {
                set.insert(rest[..end].to_string());
            }
        }
    }
    Ok(set)
}

pub fn run() -> Res<()> {
    let Some(tool) = find_nm() else {
        println!(
            "check-symbols: SKIPPED: neither llvm-nm nor nm found on this machine. \
             Run it in Docker (docker/test.sh with NEXTSSL_SYMBOLS=1) or install LLVM/binutils."
        );
        return Ok(());
    };
    let algos = load()?;
    let c_ids: Vec<String> = algos
        .iter()
        .filter(|a| a.upstream.repo.is_some() || a.upstream.url.is_some())
        .map(|a| a.id.clone())
        .collect();
    let c_prefix = |id: &str| format!("nextssl__{}__", id.replace('-', "_"));
    let prefixes: Vec<String> = c_ids.iter().map(|i| c_prefix(i)).collect();

    let built = build(&c_ids)?;
    let mut failures: Vec<String> = Vec::new();
    println!("nm tool: {tool}");

    // 1. cdylib export table.
    let exports = nm(&tool, &built.cdylib, true)?;
    let bad = bad_exports(&exports);
    let exported: BTreeSet<&str> = exports.iter().map(|s| norm(&s.name)).collect();
    let n_ours = exported
        .iter()
        .filter(|n| n.starts_with("nextssl_"))
        .count();
    println!(
        "cdylib {}: {} defined exports, {n_ours} nextssl_*",
        built.cdylib.display(),
        exports.len()
    );
    failures.extend(
        bad.iter()
            .map(|n| format!("cdylib exports non-nextssl_ symbol: {n}")),
    );
    for f in header_functions()? {
        if !exported.contains(f.as_str()) {
            failures.push(format!(
                "nextssl.h declares {f} but the cdylib does not export it"
            ));
        }
    }

    // Archives built by the C upstreams' build.rs (their object names identify C members).
    let mut c_members = BTreeSet::new();
    let mut c_archives: Vec<(String, PathBuf, Vec<Sym>)> = Vec::new();
    for id in &c_ids {
        let Some((_, dir)) = built.c_out_dirs.iter().find(|(i, _)| i == id) else {
            failures.push(format!("no build output found for C algo {id}"));
            continue;
        };
        let mut archives: Vec<PathBuf> = std::fs::read_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("a") | Some("lib")
                )
            })
            .collect();
        archives.sort();
        if archives.is_empty() {
            failures.push(format!("C algo {id}: no archive in {}", dir.display()));
        }
        for ar in archives {
            let syms = nm(&tool, &ar, false)?;
            c_members.extend(syms.iter().filter_map(|s| s.member.clone()));
            c_archives.push((id.clone(), ar, syms));
        }
    }

    // 2+3a. staticlib members.
    let st = nm(&tool, &built.staticlib, false)?;
    let in_static: BTreeSet<&str> = st.iter().filter_map(|s| s.member.as_deref()).collect();
    let matched = c_members
        .iter()
        .filter(|m| in_static.contains(m.as_str()))
        .count();
    println!(
        "staticlib: {matched}/{} C upstream objects found by name",
        c_members.len()
    );
    if matched != c_members.len() {
        failures.push(
            "staticlib does not contain every C upstream object (cannot attribute C symbols)"
                .into(),
        );
    }
    let bad = bad_staticlib(&st, &prefixes, &c_members);
    println!(
        "staticlib {}: {} defined globals checked",
        built.staticlib.display(),
        st.len()
    );
    failures.extend(bad.into_iter().map(|n| format!("staticlib: {n}")));

    // 3b. each C upstream's own archive.
    for (id, ar, syms) in &c_archives {
        let bad = bad_c_symbols(syms, &[c_prefix(id)]);
        println!(
            "C upstream {id}: {} defined globals in {}, expected prefix {}",
            syms.len(),
            ar.file_name().unwrap().to_string_lossy(),
            c_prefix(id)
        );
        if syms.is_empty() {
            failures.push(format!(
                "C algo {id}: archive defines no symbols (bad parse?)"
            ));
        }
        failures.extend(
            bad.into_iter()
                .map(|n| format!("C algo {id}: symbol {n} lacks prefix {}", c_prefix(id))),
        );
    }

    if failures.is_empty() {
        println!("check-symbols: PASS");
        Ok(())
    } else {
        for f in &failures {
            eprintln!("  FAIL {f}");
        }
        Err(format!("{} symbol rule violation(s)", failures.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(member: Option<&str>, name: &str) -> Sym {
        Sym {
            member: member.map(str::to_string),
            name: name.to_string(),
        }
    }

    #[test]
    fn parses_nm_with_members() {
        let out = "\nfoo.o:\n0000000000000000 T nextssl__x__f\n                 U memcpy\n0000000000000010 t local\n0000000000000020 D nextssl_v\n";
        let v = parse_nm(out);
        assert_eq!(
            v,
            vec![
                s(Some("foo.o"), "nextssl__x__f"),
                s(Some("foo.o"), "nextssl_v")
            ]
        );
    }

    #[test]
    fn export_rules() {
        let ok = [
            s(None, "nextssl_hash"),
            s(None, "_ZN4core3fmt5write17h0123E"),
            s(None, "_init"),
        ];
        assert!(bad_exports(&ok).is_empty());
        let bad = [s(None, "nextssl_hash"), s(None, "blake2b_update")];
        assert_eq!(bad_exports(&bad), vec!["blake2b_update".to_string()]);
    }

    #[test]
    fn c_prefix_rules() {
        let p = vec!["nextssl__blake2b_512__".to_string()];
        let syms = [
            s(None, "nextssl__blake2b_512__blake2b"),
            s(None, "blake2b_final"),
        ];
        assert_eq!(bad_c_symbols(&syms, &p), vec!["blake2b_final".to_string()]);
    }

    #[test]
    fn staticlib_rules() {
        let p = vec!["nextssl__blake2b_512__".to_string()];
        let ours = "nextssl_ffi-1.nextssl_ffi.2-cgu.0.rcgu.o";
        let std = "sha2-1.sha2.2-cgu.0.rcgu.o";
        let sys = "compiler_builtins-1.cb.2-cgu.0.rcgu.o";
        let syms = [
            s(Some(ours), "nextssl_hash"),
            s(Some(ours), "leaked"),
            s(Some(sys), "fmod"),
            s(Some(std), "__rust_alloc"),
            s(Some(std), "memcpy"),
            s(Some(std), "mystery_symbol"),
            s(Some("0abc-blake2b-ref.o"), "nextssl__blake2b_512__blake2b"),
            s(Some("0abc-blake2b-ref.o"), "blake2b_init"),
        ];
        let cm: BTreeSet<String> = ["0abc-blake2b-ref.o".to_string()].into();
        let bad = bad_staticlib(&syms, &p, &cm);
        assert_eq!(bad.len(), 3, "{bad:?}");
        assert!(bad[0].starts_with("leaked") && bad[1].starts_with("mystery_symbol"));
        assert!(bad[2].starts_with("blake2b_init"));
        // A compiler-rt C object (not one of ours) may define `__*` helpers.
        let rt = [s(Some("45c9-cmpti2.o"), "__cmpti2")];
        assert!(bad_staticlib(&rt, &p, &cm).is_empty());
    }
}
