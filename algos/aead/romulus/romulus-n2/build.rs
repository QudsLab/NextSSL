//! Generated wiring. Compiles the verbatim upstream sources in two passes: pass 1 finds every
//! global symbol the code defines (C++ free functions by their plain name), pass 2 force-includes a
//! header that renames each of them to `nextssl__romulus_n2__<name>` (no two upstreams can collide).
//! C and C++ sources are built separately (cc `.cpp(true)` only for the C++ set).
//! `NEXTSSL_C_SANITIZE=1` adds ASan/UBSan(trap).
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

const SOURCES: &[&str] = &[
    "upstream/romulus.c",
    "upstream/internal-skinny128.c",
    "upstream/aead-common.c",
];
const CPP_SOURCES: &[&str] = &[];
const INCLUDES: &[&str] = &["upstream"];
const DEFINES: &[(&str, &str)] = &[];
const PREFIX: &str = "nextssl__romulus_n2__";

fn base(cpp: bool) -> cc::Build {
    let mut b = cc::Build::new();
    b.warnings(false).opt_level(2);
    if cpp {
        b.cpp(true);
    }
    for i in INCLUDES {
        b.include(i);
    }
    for (k, v) in DEFINES {
        b.define(k, if v.is_empty() { None } else { Some(*v) });
    }
    for s in if cpp { CPP_SOURCES } else { SOURCES } {
        b.file(s);
    }
    if std::env::var("NEXTSSL_C_SANITIZE").is_ok_and(|v| v == "1") {
        b.flag("-fsanitize=address,undefined")
            .flag("-fsanitize-trap=undefined")
            .flag("-fno-omit-frame-pointer")
            .flag("-g")
            .opt_level(1);
    }
    b
}

fn defined_symbols(objs: &[PathBuf]) -> BTreeSet<String> {
    use object::{Architecture, BinaryFormat, Object, ObjectSymbol, SymbolKind};
    let mut out = BTreeSet::new();
    for o in objs {
        let data = std::fs::read(o).expect("read object");
        let f = object::File::parse(&*data).expect("parse object");
        let strip = f.format() == BinaryFormat::MachO
            || (f.format() == BinaryFormat::Coff && f.architecture() == Architecture::I386);
        for s in f.symbols() {
            if s.is_undefined() || !s.is_global() {
                continue;
            }
            if !matches!(
                s.kind(),
                SymbolKind::Text | SymbolKind::Data | SymbolKind::Unknown
            ) {
                continue;
            }
            let Ok(mut n) = s.name() else { continue };
            if strip {
                n = n.strip_prefix('_').unwrap_or(n);
            }
            // Itanium-mangled free function `_Z<len><name>...`: rename the plain identifier.
            if let Some(r) = n
                .strip_prefix("_Z")
                .filter(|r| r.as_bytes().first().is_some_and(|c| c.is_ascii_digit()))
            {
                let digits: String = r.chars().take_while(|c| c.is_ascii_digit()).collect();
                let len: usize = digits.parse().unwrap_or(0);
                let rest = &r[digits.len()..];
                if len > 0 && rest.len() >= len {
                    let id = &rest[..len];
                    if !id.starts_with("__")
                        && !id.as_bytes()[0].is_ascii_digit()
                        && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                    {
                        out.insert(id.to_string());
                    }
                }
                continue;
            }
            let ok = !n.is_empty()
                && !n.starts_with("__")
                && !n.starts_with("nextssl__")
                && n != "_fltused"
                && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                && !n.as_bytes()[0].is_ascii_digit();
            if ok {
                out.insert(n.to_string());
            }
        }
    }
    out
}

fn main() {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let sets = [
        (false, SOURCES.is_empty(), "probe", "nextssl_romulus_n2"),
        (
            true,
            CPP_SOURCES.is_empty(),
            "probe_cpp",
            "nextssl_romulus_n2_cpp",
        ),
    ];
    let mut objs = Vec::new();
    for (cpp, empty, dir, _) in sets {
        if empty {
            continue;
        }
        let mut probe = base(cpp);
        probe.out_dir(out.join(dir));
        std::fs::create_dir_all(out.join(dir)).unwrap();
        objs.extend(probe.compile_intermediates());
    }
    let syms = defined_symbols(&objs);
    let hdr = out.join("nextssl_prefix.h");
    let mut f = std::fs::File::create(&hdr).unwrap();
    for s in &syms {
        writeln!(f, "#define {s} {PREFIX}{s}").unwrap();
    }
    drop(f);
    for (cpp, empty, _, lib) in sets {
        if empty {
            continue;
        }
        let mut b = base(cpp);
        if b.get_compiler().is_like_msvc() {
            b.flag(format!("/FI{}", hdr.display()));
        } else {
            b.flag("-include").flag(hdr.to_str().unwrap());
        }
        link_shared(&mut b, lib, cpp);
    }
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    println!("cargo:rerun-if-changed=upstream");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-changed=shim.cpp");
    println!("cargo:rerun-if-changed=build.rs");
}

// BEGIN SHARED LINK (cargo xtask build-link)
// Compiles `b`, then publishes the static library into one directory shared by every C-backed
// algorithm (see xtask/src/buildlink.rs). The library is renamed `<lib>_<hash>` so names stay unique.
fn link_shared(b: &mut cc::Build, lib: &str, cpp: bool) {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    b.cargo_metadata(false).compile(lib);
    let msvc = b.get_compiler().is_like_msvc();
    let pkg_dir = out.parent().expect("OUT_DIR has a parent");
    let tag = pkg_dir
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.rsplit('-').next())
        .unwrap_or("0");
    let shared = pkg_dir
        .parent()
        .expect("build dir")
        .join("nextssl-c-libs");
    std::fs::create_dir_all(&shared).expect("create shared lib dir");
    let uniq = format!("{lib}_{tag}");
    let file = |n: &str| if msvc { format!("{n}.lib") } else { format!("lib{n}.a") };
    let tmp = shared.join(format!("{}.tmp", file(&uniq)));
    std::fs::copy(out.join(file(lib)), &tmp).expect("copy static library");
    std::fs::rename(&tmp, shared.join(file(&uniq))).expect("publish static library");
    println!("cargo:rustc-link-search=native={}", shared.display());
    println!("cargo:rustc-link-lib=static={uniq}");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CFLAGS");
    if cpp {
        let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
        let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
        let std_lib = std::env::var("CXXSTDLIB").ok().unwrap_or_else(|| {
            match os.as_str() {
                _ if env == "msvc" => "",
                "macos" | "ios" | "tvos" | "watchos" | "freebsd" | "openbsd" | "android"
                | "wasi" | "emscripten" => "c++",
                _ => "stdc++",
            }
            .to_string()
        });
        if !std_lib.is_empty() {
            println!("cargo:rustc-link-lib={std_lib}");
        }
    }
}
// END SHARED LINK
