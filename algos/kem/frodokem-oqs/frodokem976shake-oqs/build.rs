//! Generated wiring. Compiles the verbatim upstream sources in two passes: pass 1 finds every
//! global symbol the code defines (C++ free functions by their plain name), pass 2 force-includes a
//! header that renames each of them to `nextssl__frodokem976shake_oqs__<name>` (no two upstreams can collide).
//! C and C++ sources are built separately (cc `.cpp(true)` only for the C++ set).
//! `NEXTSSL_C_SANITIZE=1` adds ASan/UBSan(trap).
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

const SOURCES: &[&str] = &[
    "upstream/src/kem/frodokem/external/frodo/frodo976shake.c",
    "upstream/src/common/common.c",
    "upstream/src/common/sha3/sha3.c",
    "upstream/src/common/sha3/sha3x4.c",
    "compat/ns_xkcp_plain64.c",
    "compat/ns_xkcp_times4.c",
    "compat/ns_xkcp_sha3.c",
    "compat/ns_xkcp_sha3x4.c",
    "shim.c",
];
const CPP_SOURCES: &[&str] = &[];
const INCLUDES: &[&str] = &[
    "upstream/src/kem/frodokem",
    "upstream/src/kem/frodokem/external/frodo",
    "upstream/src/common",
    "upstream/src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits",
    "upstream/src/common/sha3/xkcp_low/KeccakP-1600times4/serial",
    "upstream/src/common/sha3",
    "upstream/src/common/aes",
    "upstream/src/common/sha2",
    "upstream/src/common/rand",
    "compat",
];
const DEFINES: &[(&str, &str)] = &[("OQS_ENABLE_KEM_frodokem_976_shake", "1")];
const PREFIX: &str = "nextssl__frodokem976shake_oqs__";

fn base(cpp: bool) -> cc::Build {
    let mut b = cc::Build::new();
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
        "__asan", "__odr_asan", "__ubsan", "__sancov", "__llvm", "__prof", "__covrec", "__gcov",
        "__imp_", "__start_", "__stop_", "__cxa", "__gxx", "__clang", "__emutls", "__tls",
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
            if s.is_undefined() || !s.is_global() {
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
                        r.strip_prefix("Th").or_else(|| r.strip_prefix("Tv")).map(|t| {
                            t.trim_start_matches(|c: char| c == 'n' || c == '_' || c.is_ascii_digit())
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
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let sets = [
        (
            false,
            SOURCES.is_empty(),
            "probe",
            "nextssl_frodokem976shake_oqs",
        ),
        (
            true,
            CPP_SOURCES.is_empty(),
            "probe_cpp",
            "nextssl_frodokem976shake_oqs_cpp",
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
    let shared = pkg_dir.parent().expect("build dir").join("nextssl-c-libs");
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
