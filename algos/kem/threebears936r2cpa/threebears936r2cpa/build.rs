//! Generated wiring. Compiles the verbatim PQClean sources in two passes: pass 1 finds every
//! global symbol the C code defines, pass 2 force-includes a header that renames each of them to
//! `nextssl__threebears936r2cpa__<name>` (no two upstreams can collide). `NEXTSSL_C_SANITIZE=1` adds ASan/UBSan(trap).
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

const SOURCES: &[&str] = &[
    "upstream/ref/kem.c",
    "upstream/ref/melas_fec.c",
    "upstream/ref/ring.c",
    "upstream/ref/shake.c",
    "upstream/ref/threebears.c",
    "shim.c",
];
const INCLUDES: &[&str] = &["upstream/ref", "compat"];
const PREFIX: &str = "nextssl__threebears936r2cpa__";

fn base() -> cc::Build {
    let mut b = cc::Build::new();
    b.warnings(false).opt_level(2);

    // Force-included preamble: scheme macros upstream's own build passes on the command line, plus (MSVC only) a no-op
    // `__attribute__` (GNU annotations carry no semantics for the portable C; cl.exe cannot take a function-like macro with /D).
    let mut pre = String::from("");
    let msvc = b.get_compiler().is_like_msvc();
    if msvc {
        pre.push_str("#define __attribute__(x)\n");
    }
    if !pre.is_empty() {
        let h = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("nextssl_pre.h");
        std::fs::write(&h, pre).unwrap();
        if msvc {
            b.flag(format!("/FI{}", h.display()));
        } else {
            b.flag("-include").flag(h.to_str().unwrap());
        }
    }
    for i in INCLUDES {
        b.include(i);
    }
    for s in SOURCES {
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
    let mut probe = base();
    probe.out_dir(out.join("probe"));
    std::fs::create_dir_all(out.join("probe")).unwrap();
    let objs = probe.compile_intermediates();
    let syms = defined_symbols(&objs);
    let hdr = out.join("nextssl_prefix.h");
    let mut f = std::fs::File::create(&hdr).unwrap();
    for s in &syms {
        writeln!(f, "#define {s} {PREFIX}{s}").unwrap();
    }
    drop(f);
    let mut b = base();
    if b.get_compiler().is_like_msvc() {
        b.flag(format!("/FI{}", hdr.display()));
    } else {
        b.flag("-include").flag(hdr.to_str().unwrap());
    }
    link_shared(&mut b, "nextssl_threebears936r2cpa", false);
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    println!("cargo:rerun-if-changed=upstream");
    println!("cargo:rerun-if-changed=shim.c");
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
