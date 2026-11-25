//! Generated wiring. Compiles the verbatim upstream sources in two passes: pass 1 finds every
//! global symbol the code defines (C++ free functions by their plain name), pass 2 force-includes a
//! header that renames each of them to `nextssl__xmssmt_shake256_40_8_256__<name>` (no two upstreams can collide).
//! C and C++ sources are built separately (cc `.cpp(true)` only for the C++ set).
//! `NEXTSSL_C_SANITIZE=1` adds ASan/UBSan(trap).
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

const SOURCES: &[&str] = &[
    "upstream/params.c",
    "upstream/hash.c",
    "upstream/fips202.c",
    "upstream/hash_address.c",
    "upstream/wots.c",
    "upstream/xmss.c",
    "upstream/xmss_core.c",
    "upstream/xmss_commons.c",
    "upstream/utils.c",
    "upstream/liboqs/src/common/common.c",
    "upstream/liboqs/src/common/sha2/sha2.c",
    "upstream/liboqs/src/common/sha2/sha2_c.c",
    "upstream/liboqs/src/common/sha2/sha2_impl.c",
    "shim.c",
];
const CPP_SOURCES: &[&str] = &[];
const INCLUDES: &[&str] = &[
    "upstream",
    "upstream/liboqs/src/common",
    "upstream/liboqs/src/common/sha2",
    "compat",
];
const DEFINES: &[(&str, &str)] = &[];
const PREFIX: &str = "nextssl__xmssmt_shake256_40_8_256__";

/// Targets with a 32-bit C `long` (Windows, wasm32, other 32-bit) only: xmss_core.c reads the
/// signing index with `idx = (unsigned long)bytes_to_ull(...)` into an `unsigned long long`. With a
/// 32-bit `long` the cast drops the high bits, so an index >= 2^32 (total height 40/60) would sign
/// with a reused one-time key, and an exhausted key (index set to all ones) would sign again. The
/// compiled copy (OUT_DIR) casts to `unsigned long long`, the value the code means on LP64; LP64
/// targets compile the verbatim file.
fn index_fix_source(src: &str) -> PathBuf {
    let long_is_32 = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        || std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH").as_deref() == Ok("32");
    if !long_is_32 || !src.ends_with("/xmss_core.c") {
        return PathBuf::from(src);
    }
    let text = std::fs::read_to_string(src).expect("read xmss_core.c");
    let from = "(unsigned long)bytes_to_ull(";
    assert_eq!(
        text.matches(from).count(),
        1,
        "xmss_core.c: expected one `{from}`"
    );
    let p = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("xmss_core_index64.c");
    std::fs::write(&p, text.replace(from, "(unsigned long long)bytes_to_ull("))
        .expect("write xmss_core_index64.c");
    p
}

fn base(cpp: bool) -> cc::Build {
    let mut b = cc::Build::new();
    // Plain `char` is unsigned on Linux ARM but signed on x86, Windows and Apple, where the
    // upstreams were written and tested (Khichidi-1's `char i; i >= 0` loop never ends unsigned).
    if !b.get_compiler().is_like_msvc() {
        b.flag("-fsigned-char");
    }
    // The upstream uses C99 variable-length arrays (and GNU C), which cl.exe cannot compile. On MSVC
    // targets it is compiled with clang-cl instead: same ABI and object format, linked by link.exe.
    if b.get_compiler().is_like_msvc() {
        b.compiler(clang_cl());
        // cl.exe merges C tentative definitions (common symbols); clang-cl defaults to -fno-common.
        // Same single definition as cl.exe and GCC -fcommon builds; link.exe merges COFF commons.
        b.flag("/clang:-fcommon");
    }
    // Pin the C dialect: GCC 15 defaults to C23, where `int f()` means no parameters; that breaks
    // K&R-era upstreams. gnu17 is the dialect these sources were written against.
    if !cpp && !b.get_compiler().is_like_msvc() {
        b.flag("-std=gnu17");
    }
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
    // liboqs' own CMake defines OQS_HAVE_POSIX_MEMALIGN wherever posix_memalign exists (every
    // non-Windows target, wasi-libc too); without it common.c includes <malloc.h>, which macOS lacks.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        b.define("OQS_HAVE_POSIX_MEMALIGN", None);
    }
    for s in if cpp { CPP_SOURCES } else { SOURCES } {
        b.file(index_fix_source(s));
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
            // Itanium-mangled C++ name: rename the outermost identifier, i.e. a free function
            // (`_Z<len><name>`) or the class of a member, vtable, typeinfo or thunk
            // (`_ZN[rVK]<len><class>`, `_ZTV/_ZTI/_ZTS<len><class>`, `_ZTh/_ZTv<offsets>_N..`).
            // std names (`_ZNSt..`, `_ZSt..`) have no length digit there and are left alone.
            if let Some(r) = n.strip_prefix("_Z").map(|r| {
                let r = ["TV", "TI", "TS"]
                    .iter()
                    .find_map(|p| r.strip_prefix(p))
                    .or_else(|| {
                        r.strip_prefix("Th")
                            .or_else(|| r.strip_prefix("Tv"))
                            .map(|t| {
                                t.trim_start_matches(|c: char| {
                                    c == 'n' || c == '_' || c.is_ascii_digit()
                                })
                            })
                    })
                    .unwrap_or(r);
                r.strip_prefix('N')
                    .map(|t| t.trim_start_matches(['r', 'V', 'K']))
                    .unwrap_or(r)
            }) {
                if !r.as_bytes().first().is_some_and(|c| c.is_ascii_digit()) {
                    continue;
                }
                let digits: String = r.chars().take_while(|c| c.is_ascii_digit()).collect();
                let len: usize = digits.parse().unwrap_or(0);
                let rest = &r[digits.len()..];
                if len > 0 && rest.len() >= len {
                    let id = &rest[..len];
                    if !toolchain_name(id)
                        && !id.starts_with("nextssl__")
                        && !id.as_bytes()[0].is_ascii_digit()
                        && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                    {
                        out.insert(id.to_string());
                    }
                }
                continue;
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
    let sets = [
        (
            false,
            SOURCES.is_empty(),
            "probe",
            "nextssl_xmssmt_shake256_40_8_256",
        ),
        (
            true,
            CPP_SOURCES.is_empty(),
            "probe_cpp",
            "nextssl_xmssmt_shake256_40_8_256_cpp",
        ),
    ];
    let mut objs = Vec::new();
    for (cpp, empty, dir, _) in sets {
        if empty {
            continue;
        }
        let mut probe = base(cpp);
        // C only lists the defined globals at -O0 (the set does not depend on the level);
        // C++ inline and template code can differ per level, so C++ probes at the real one.
        if !cpp {
            probe.opt_level(0);
        }
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
    // The final objects must define no global the -O0 probe missed (see check_prefixed).
    check_prefixed(&out);
    nextssl_cbuild::directive!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    nextssl_cbuild::directive!("cargo:rerun-if-changed=upstream");
    nextssl_cbuild::directive!("cargo:rerun-if-changed=shim.c");
    nextssl_cbuild::directive!("cargo:rerun-if-changed=compat");
    nextssl_cbuild::directive!("cargo:rerun-if-changed=build.rs");
}

/// clang-cl for MSVC targets: `NEXTSSL_CLANG_CL`, then PATH, then the LLVM installer's default
/// directory. There is no fallback to cl.exe (it cannot compile this upstream).
fn clang_cl() -> PathBuf {
    nextssl_cbuild::directive!("cargo:rerun-if-env-changed=NEXTSSL_CLANG_CL");
    if let Some(p) = std::env::var_os("NEXTSSL_CLANG_CL") {
        return PathBuf::from(p);
    }
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    dirs.push(PathBuf::from(r"C:\Program Files\LLVM\bin"));
    for d in dirs {
        let c = d.join("clang-cl.exe");
        if c.is_file() {
            return c;
        }
    }
    panic!(
        "this algorithm's C upstream needs clang-cl on MSVC targets (C99 variable-length arrays): \
         install LLVM or set NEXTSSL_CLANG_CL to clang-cl.exe"
    );
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
