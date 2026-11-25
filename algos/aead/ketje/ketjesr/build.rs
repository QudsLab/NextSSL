//! Generated wiring. Compiles the verbatim upstream sources in two passes: pass 1 finds every
//! global symbol the code defines (C++ free functions by their plain name), pass 2 force-includes a
//! header that renames each of them to `nextssl__ketjesr__<name>` (no two upstreams can collide).
//! C and C++ sources are built separately (cc `.cpp(true)` only for the C++ set).
//! `NEXTSSL_C_SANITIZE=1` adds ASan/UBSan(trap).
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

const SOURCES: &[&str] = &[];
const CPP_SOURCES: &[&str] = &[
    "upstream/ketjesrv2/Keccak-f.cpp",
    "upstream/ketjesrv2/Ketjev2.cpp",
    "upstream/ketjesrv2/bitstring.cpp",
    "upstream/ketjesrv2/encrypt.cpp",
    "upstream/ketjesrv2/monkey.cpp",
    "upstream/ketjesrv2/padding.cpp",
    "upstream/ketjesrv2/transformations.cpp",
    "shim.cpp",
];
const INCLUDES: &[&str] = &["upstream/ketjesrv2", "compat"];
const DEFINES: &[(&str, &str)] = &[];
const PREFIX: &str = "nextssl__ketjesr__";

fn base(cpp: bool) -> cc::Build {
    let mut b = cc::Build::new();
    // Plain `char` is unsigned on Linux ARM but signed on x86, Windows and Apple, where the
    // upstreams were written and tested (Khichidi-1's `char i; i >= 0` loop never ends unsigned).
    if !b.get_compiler().is_like_msvc() {
        b.flag("-fsigned-char");
    }
    // Pin the C dialect: GCC 15 defaults to C23, where `int f()` means no parameters; that breaks
    // K&R-era upstreams. gnu17 is the dialect these sources were written against.
    if !cpp && !b.get_compiler().is_like_msvc() {
        b.flag("-std=gnu17");
    }
    b.warnings(false).opt_level(2);
    if cpp {
        b.cpp(true);
        // The tag-mismatch macro of upstream.patches (compat/nextssl_ketje_tag.h).
        if b.get_compiler().is_like_msvc() {
            b.flag("/FInextssl_ketje_tag.h");
        } else {
            b.flag("-include").flag("compat/nextssl_ketje_tag.h");
        }
    }
    for i in INCLUDES {
        b.include(up(i));
    }
    for (k, v) in DEFINES {
        b.define(k, if v.is_empty() { None } else { Some(*v) });
    }
    for s in if cpp { CPP_SOURCES } else { SOURCES } {
        b.file(up(s));
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
        (false, SOURCES.is_empty(), "probe", "nextssl_ketjesr"),
        (
            true,
            CPP_SOURCES.is_empty(),
            "probe_cpp",
            "nextssl_ketjesr_cpp",
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
    if std::path::Path::new("upstream").exists() {
        nextssl_cbuild::directive!("cargo:rerun-if-changed=upstream");
    }
    if std::path::Path::new("shim.c").exists() {
        nextssl_cbuild::directive!("cargo:rerun-if-changed=shim.c");
    }
    if std::path::Path::new("shim.cpp").exists() {
        nextssl_cbuild::directive!("cargo:rerun-if-changed=shim.cpp");
    }
    nextssl_cbuild::directive!("cargo:rerun-if-changed=compat");
    nextssl_cbuild::directive!("cargo:rerun-if-changed=upstream.patches");
    nextssl_cbuild::directive!("cargo:rerun-if-changed=build.rs");
}

// BEGIN SHARED LINK (cargo xtask build-link)
// Compiles `b`, then publishes the static library into one directory shared by every C-backed
// algorithm (see xtask/src/buildlink.rs). The library is renamed `<lib>_<hash>` so names stay unique.
fn link_shared(b: &mut cc::Build, lib: &str, cpp: bool) {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let wasm = std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32");
    if cpp && wasm {
        // wasi libc++ has no threads: give it the single-threaded std::mutex C++ upstreams expect.
        let h = out.join("nextssl_wasi_cxx.h");
        std::fs::write(&h, "/* NextSSL compat (not upstream), force-included only for C++ upstreams on wasm32.\n * 1. The wasi libc++ is built with _LIBCPP_HAS_NO_THREADS, so <mutex> declares no std::mutex, while\n *    upstreams such as Crypto++ guard lazy singletons with one. A wasm32 module without the threads\n *    proposal runs on one thread, so a lock that does nothing is exact.\n * 2. The wasi libc++abi has no exception support (__cxa_throw is missing). The glue validates every\n *    length and parameter before calling the upstream, so a throw is not expected; if one happens the\n *    module stops loudly (abort) instead of continuing. Weak, so the C++ libraries can link together. */\n#ifndef NEXTSSL_WASI_CXX_H\n#define NEXTSSL_WASI_CXX_H\n#include <cstddef>\n#include <cstdio>\n#include <cstdlib>\n#include <mutex>\n#include <typeinfo>\n#if defined(_LIBCPP_HAS_NO_THREADS)\nnamespace std {\nclass mutex {\npublic:\n    constexpr mutex() noexcept = default;\n    mutex(const mutex &) = delete;\n    mutex &operator=(const mutex &) = delete;\n    void lock() noexcept {}\n    bool try_lock() noexcept { return true; }\n    void unlock() noexcept {}\n};\n} // namespace std\n#endif\nextern \"C\" {\n__attribute__((weak)) void *__cxa_allocate_exception(std::size_t n) noexcept {\n    void *p = std::malloc(n);\n    if (!p) std::abort();\n    return p;\n}\n__attribute__((weak, noreturn)) void __cxa_throw(void *, std::type_info *, void (*)(void *)) {\n    std::fputs(\"nextssl: C++ exception thrown in a wasm32 build (no exception support), aborting\\n\", stderr);\n    std::abort();\n}\n}\n#endif\n").expect("write nextssl_wasi_cxx.h");
        b.flag("-include").flag(h.to_str().expect("utf-8 OUT_DIR"));
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
        if wasm {
            // wasm32 (wasi libc++): the C++ library and its ABI runtime; the toolchain supplies -L (docker/test.sh).
            nextssl_cbuild::directive!("cargo:rustc-link-lib=c++");
            nextssl_cbuild::directive!("cargo:rustc-link-lib=c++abi");
        } else if !std_lib.is_empty() {
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

// BEGIN UPSTREAM PATCHES (upstream.patches, listed in docs/UPSTREAM_CHANGES.md)
/// A path under `upstream/` mapped into the patched copy of the tree; other paths are unchanged.
fn up(p: &str) -> PathBuf {
    match p.strip_prefix("upstream") {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => {
            patched_upstream().join(rest.trim_start_matches('/'))
        }
        _ => PathBuf::from(p),
    }
}

/// Copy of upstream/ in OUT_DIR with the replacements of `upstream.patches` applied; the files on
/// disk stay verbatim. Each patch names a file, the exact text to find, how many times it occurs
/// and its replacement; any other count stops the build, so a changed upstream is never patched
/// blindly. The reason for every patch is in upstream.patches and docs/UPSTREAM_CHANGES.md.
fn patched_upstream() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dst = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("patched-upstream");
        let _ = std::fs::remove_dir_all(&dst);
        copy_tree(std::path::Path::new("upstream"), &dst);
        let spec = std::fs::read_to_string("upstream.patches").expect("read upstream.patches");
        for p in parse_patches(&spec) {
            let rel = p
                .file
                .strip_prefix("upstream/")
                .expect("patch file under upstream/");
            let path = dst.join(rel);
            let text = std::fs::read_to_string(&path).expect("read patched file");
            let n = text.matches(p.find.as_str()).count();
            assert_eq!(
                n, p.count,
                "{}: `{}` occurs {n} times, expected {}",
                p.file, p.find, p.count
            );
            std::fs::write(&path, text.replace(p.find.as_str(), p.replace.as_str()))
                .expect("write patched file");
        }
        dst
    })
}

struct Patch {
    file: String,
    count: usize,
    find: String,
    replace: String,
}

/// `patch:` starts a record; `file:`, `count:`, `find:` and `replace:` follow (the value is the
/// rest of the line after `key: `). `why:` lines and lines starting with `#` are documentation.
fn parse_patches(spec: &str) -> Vec<Patch> {
    let mut out: Vec<Patch> = Vec::new();
    for line in spec.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with("patch:") {
            out.push(Patch {
                file: String::new(),
                count: 0,
                find: String::new(),
                replace: String::new(),
            });
        } else if let Some(p) = out.last_mut() {
            if let Some(v) = line.strip_prefix("file: ") {
                p.file = v.to_string();
            } else if let Some(v) = line.strip_prefix("count: ") {
                p.count = v.parse().expect("count is a number");
            } else if let Some(v) = line.strip_prefix("find: ") {
                p.find = v.to_string();
            } else if let Some(v) = line.strip_prefix("replace: ") {
                p.replace = v.to_string();
            }
        }
    }
    for p in &out {
        assert!(
            !p.file.is_empty() && p.count > 0 && !p.find.is_empty(),
            "upstream.patches: incomplete record"
        );
    }
    out
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).expect("create patched tree");
    for e in std::fs::read_dir(from).expect("read upstream dir") {
        let e = e.expect("dir entry");
        let target = to.join(e.file_name());
        if e.file_type().expect("file type").is_dir() {
            copy_tree(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), &target).expect("copy upstream file");
        }
    }
}
