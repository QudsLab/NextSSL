//! Generated wiring. Compiles the verbatim PQClean sources in two passes: pass 1 finds every
//! global symbol the C code defines, pass 2 force-includes a header that renames each of them to
//! `nextssl__ryde3s_r2__<name>` (no two upstreams can collide). `NEXTSSL_C_SANITIZE=1` adds ASan/UBSan(trap).
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

const SOURCES: &[&str] = &[
    "upstream/ryde3s/lib/XKCP/KeccakHash.c",
    "upstream/ryde3s/lib/XKCP/KeccakHashtimes4.c",
    "upstream/ryde3s/lib/XKCP/KeccakSponge.c",
    "upstream/ryde3s/lib/XKCP/KeccakSpongetimes4.c",
    "upstream/ryde3s/lib/XKCP/SimpleFIPS202.c",
    "upstream/ryde3s/src/ggm_tree.c",
    "upstream/ryde3s/src/keypair.c",
    "upstream/ryde3s/src/parsing.c",
    "upstream/ryde3s/src/rbc-61/rbc_61_elt.c",
    "upstream/ryde3s/src/rbc-61/rbc_61_mat.c",
    "upstream/ryde3s/src/rbc-61/rbc_61_mat_fq.c",
    "upstream/ryde3s/src/rbc-61/rbc_61_vec.c",
    "upstream/ryde3s/src/rbc-61/rbc_61_vspace.c",
    "upstream/ryde3s/src/sign.c",
    "upstream/ryde3s/src/signature.c",
    "upstream/ryde3s/src/tcith.c",
    "upstream/ryde3s/src/verification.c",
    "upstream/ryde3s/lib/XKCP/opt64/KeccakP-1600-opt64.c",
    "upstream/ryde3s/lib/XKCP/opt64/KeccakP-1600-times4-on1.c",
    "shim.c",
];
const INCLUDES: &[&str] = &[
    "upstream/ryde3s/src",
    "upstream/ryde3s/lib/XKCP",
    "upstream/ryde3s/lib/randombytes",
    "upstream/ryde3s/src/rbc-61",
    "upstream/ryde3s/src/wrapper",
    "upstream/ryde3s/lib/XKCP/opt64",
];
const PREFIX: &str = "nextssl__ryde3s_r2__";

/// Non-x86 targets only (wasm32, aarch64): rbc_*_elt.c computes the degree with x86 inline asm
/// `__asm__ volatile("bsr %1,%0;" : "=r"(index) : "r"(X));` (index of the highest set bit of X). The
/// compiled copy (OUT_DIR) replaces exactly those statements with `63 - __builtin_clzll(X)`, the same value
/// for X != 0; for X == 0 bsr leaves the index undefined and the upstream masks it out, so 0 is used there.
/// x86 targets compile the verbatim file.
fn portable_source(src: &str) -> PathBuf {
    const HEAD: &str = "__asm__ volatile(\"bsr %1,%0;\" : \"=r\"(index) : \"r\"(";
    let x86 = matches!(
        std::env::var("CARGO_CFG_TARGET_ARCH").as_deref(),
        Ok("x86_64") | Ok("x86")
    );
    let text = std::fs::read_to_string(src).expect("read upstream source");
    if x86 || !text.contains(HEAD) {
        return PathBuf::from(src);
    }
    let mut out_text = String::new();
    let mut rest = text.as_str();
    while let Some(i) = rest.find(HEAD) {
        let after = &rest[i + HEAD.len()..];
        let end = after.find("));").expect("bsr statement end");
        let x = &after[..end];
        out_text.push_str(&rest[..i]);
        out_text.push_str(&format!(
            "index = ({x} != 0) ? (int64_t)(63 - __builtin_clzll((unsigned long long)({x}))) : 0;"
        ));
        rest = &after[end + 3..];
    }
    out_text.push_str(rest);
    let name = src.replace('/', "_");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join(format!("portable_{name}"));
    std::fs::write(&out, out_text).expect("write portable copy");
    out
}

fn base() -> cc::Build {
    let mut b = cc::Build::new();
    // POSIX/glibc headers the upstream includes; MSVC targets get stand-ins (compat/msvc).
    if b.get_compiler().is_like_msvc() {
        b.include("compat/msvc");
    }
    // The upstream uses C99 variable-length arrays (and GNU C), which cl.exe cannot compile. On MSVC
    // targets it is compiled with clang-cl instead: same ABI and object format, linked by link.exe.
    if b.get_compiler().is_like_msvc() {
        b.compiler(clang_cl());
        // cl.exe merges C tentative definitions (common symbols); clang-cl defaults to -fno-common.
        // Same single definition as cl.exe and GCC -fcommon builds; link.exe merges COFF commons.
        b.flag("/clang:-fcommon");
    }
    // The only upstream implementation uses x86 SIMD intrinsics. Off x86 (wasm32, aarch64) the x86
    // intrinsic headers come from SIMDe (third_party/simde/x86-shim, portable C); x86 targets are unchanged.
    if !matches!(
        std::env::var("CARGO_CFG_TARGET_ARCH").as_deref(),
        Ok("x86_64") | Ok("x86")
    ) {
        let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../../..");
        b.include(root.join("third_party/simde/x86-shim"));
        println!(
            "cargo:rerun-if-changed={}",
            root.join("third_party/simde").display()
        );
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
    // cl.exe only: clang-cl understands GNU attributes (its own headers need them).
    if msvc && !b.get_compiler().is_like_clang_cl() {
        pre.push_str(
            "#define __attribute__(x)
",
        );
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
        let f = portable_source(s);
        if f.as_os_str() != std::ffi::OsStr::new(s) {
            // the copy lives in OUT_DIR: keep the original directory for its "..." includes
            b.include(std::path::Path::new(s).parent().unwrap());
        }
        b.file(f);
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
    link_shared(&mut b, "nextssl_ryde3s_r2", false);
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    if std::path::Path::new("upstream").exists() {
        println!("cargo:rerun-if-changed=upstream");
    }
    if std::path::Path::new("shim.c").exists() {
        println!("cargo:rerun-if-changed=shim.c");
    }
    println!("cargo:rerun-if-changed=build.rs");
}

/// clang-cl for MSVC targets: `NEXTSSL_CLANG_CL`, then PATH, then the LLVM installer's default
/// directory. There is no fallback to cl.exe (it cannot compile this upstream).
fn clang_cl() -> PathBuf {
    println!("cargo:rerun-if-env-changed=NEXTSSL_CLANG_CL");
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
