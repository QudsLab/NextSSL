//! Generated wiring. Compiles the verbatim PQClean sources in two passes: pass 1 finds every
//! global symbol the C code defines, pass 2 force-includes a header that renames each of them to
//! `nextssl__simple128gift__<name>` (no two upstreams can collide). `NEXTSSL_C_SANITIZE=1` adds ASan/UBSan(trap).
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

const SOURCES: &[&str] = &[
    "upstream/ref/GIFT_128-128.c",
    "upstream/ref/encrypt.c",
    "upstream/ref/simple_128-128.c",
];
const INCLUDES: &[&str] = &["upstream/ref", "compat"];
const PREFIX: &str = "nextssl__simple128gift__";

fn base() -> cc::Build {
    let mut b = cc::Build::new();
    // Plain `char` is unsigned on Linux ARM but signed on x86, Windows and Apple, where the
    // upstreams were written and tested (Khichidi-1's `char i; i >= 0` loop never ends unsigned).
    if !b.get_compiler().is_like_msvc() {
        b.flag("-fsigned-char");
    }
    // Pin the C dialect: GCC 15 defaults to C23, where `int f()` means no parameters; that breaks
    // K&R-era upstreams. gnu17 is the dialect these sources were written against.
    if !b.get_compiler().is_like_msvc() {
        b.flag("-std=gnu17");
    }
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

/// Names the compiler, sanitizers or linker define in an object; never renamed. Every other
/// global (including upstream names that start with `__`) gets the per-algorithm prefix.
fn toolchain_name(n: &str) -> bool {
    const P: &[&str] = &[
        "__asan",
        // ASan module globals (three underscores, e.g. ___asan_globals_registered).
        "___asan",
        "__odr_asan",
        "__ubsan",
        "__sancov",
        "__llvm",
        "__prof",
        "__covrec",
        "__gcov",
        "__imp_",
        "__start_",
        "__stop_",
        "__cxa",
        "__gxx",
        "__clang",
        "__emutls",
        "__tls",
        // MSVC auto-vectorizer flag (COMDAT, merged by the linker; emitted only at -O2).
        "__isa_available",
    ];
    P.iter().any(|p| n.starts_with(p))
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
            // A Mach-O common symbol (tentative definition, -fcommon) is N_UNDF with its size as the
            // value: object reports it undefined, so it counts as defined when its address is not 0
            // (CI run 45581879065: macOS SPHINCS+ crates shared one unrenamed `state_seeded`).
            if (s.is_undefined() && s.address() == 0) || !s.is_global() {
                continue;
            }
            if !matches!(
                s.kind(),
                SymbolKind::Text | SymbolKind::Data | SymbolKind::Tls | SymbolKind::Unknown
            ) {
                continue;
            }
            let Ok(mut n) = s.name() else { continue };
            if strip {
                n = n.strip_prefix('_').unwrap_or(n);
            }
            let ok = !n.is_empty()
                && !toolchain_name(n)
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
    // Compiles the upstream, or reuses the identical result of an earlier build when CI enables the
    // cache (NEXTSSL_C_CACHE); see crates/nextssl-cbuild.
    nextssl_cbuild::cached(build_main);
}

fn build_main() {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let mut probe = base();
    // Only lists the defined globals; the optimisation level does not change that set.
    probe.opt_level(0);
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
    link_shared(&mut b, "nextssl_simple128gift", false);
    // The final objects must define no global the -O0 probe missed (see check_prefixed).
    check_prefixed(&out);
    nextssl_cbuild::directive!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    if std::path::Path::new("upstream").exists() {
        nextssl_cbuild::directive!("cargo:rerun-if-changed=upstream");
    }
    if std::path::Path::new("shim.c").exists() {
        nextssl_cbuild::directive!("cargo:rerun-if-changed=shim.c");
    }
    nextssl_cbuild::directive!("cargo:rerun-if-changed=compat");
    nextssl_cbuild::directive!("cargo:rerun-if-changed=build.rs");
}

// BEGIN SHARED LINK (cargo xtask build-link)
// Compiles `b`, then publishes the static library into one directory shared by every C-backed
// algorithm (see xtask/src/buildlink.rs). The library is renamed `<lib>_<hash>` so names stay unique.
fn link_shared(b: &mut cc::Build, lib: &str, cpp: bool) {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    // Signed overflow and shifts into or of the sign bit wrap (two's complement), as the reference
    // code assumes, instead of being undefined: the optimiser can no longer drop or reorder that
    // arithmetic (UBSan, CI run 45581879065: 137 crates). cl.exe has no such option.
    if !b.get_compiler().is_like_msvc() {
        b.flag("-fwrapv");
    } else if b.get_compiler().is_like_clang_cl() {
        b.flag("/clang:-fwrapv");
    }
    b.cargo_metadata(false).compile(lib);
    let msvc = b.get_compiler().is_like_msvc();
    let pkg_dir = out.parent().expect("OUT_DIR has a parent");
    let tag = pkg_dir
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.rsplit('-').next())
        .unwrap_or("0");
    // One directory for every crate, next to the per-crate build dirs: build/<pkg>-<hash>/out
    // (classic layout) or build/<pkg>/<hash>/out (cargo build-dir layout used by nightly).
    let build_dir = out
        .ancestors()
        .find(|p| p.file_name().is_some_and(|n| n == "build"))
        .expect("OUT_DIR is inside a `build` directory");
    let shared = build_dir.join("nextssl-c-libs");
    std::fs::create_dir_all(&shared).expect("create shared lib dir");
    let uniq = format!("{lib}_{tag}");
    let file = |n: &str| {
        if msvc {
            format!("{n}.lib")
        } else {
            format!("lib{n}.a")
        }
    };
    let tmp = shared.join(format!("{}.tmp", file(&uniq)));
    std::fs::copy(out.join(file(lib)), &tmp).expect("copy static library");
    std::fs::rename(&tmp, shared.join(file(&uniq))).expect("publish static library");
    nextssl_cbuild::directive!("cargo:rustc-link-search=native={}", shared.display());
    nextssl_cbuild::directive!("cargo:rustc-link-lib=static={uniq}");
    nextssl_cbuild::directive!("cargo:rerun-if-env-changed=CC");
    nextssl_cbuild::directive!("cargo:rerun-if-env-changed=CFLAGS");
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
            nextssl_cbuild::directive!("cargo:rustc-link-lib={std_lib}");
        }
    }
}
// END SHARED LINK

/// The probe (pass 1) runs at -O0 only to list the globals the upstream defines; the set of external
/// definitions does not depend on the optimisation level. This parses the final optimised objects
/// and stops the build if any of them defines a global that was not renamed, so a symbol the probe
/// missed can never reach the link (where it could collide with another upstream).
fn check_prefixed(out: &std::path::Path) {
    fn walk(dir: &std::path::Path, acc: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).expect("read OUT_DIR").flatten() {
            let p = e.path();
            if p.is_dir() {
                let name = e.file_name();
                if name != "probe" && name != "probe_cpp" && name != "patched-upstream" {
                    walk(&p, acc);
                }
            } else if p.extension().is_some_and(|x| x == "o" || x == "obj")
                && !p.file_stem().is_some_and(|s| s == "flag_check")
            {
                acc.push(p);
            }
        }
    }
    let mut objs = Vec::new();
    walk(out, &mut objs);
    assert!(
        !objs.is_empty(),
        "no object files found under {}",
        out.display()
    );
    let missed = defined_symbols(&objs);
    assert!(
        missed.is_empty(),
        "globals defined by the optimised build but not renamed (the -O0 probe missed them): {missed:?}"
    );
}
