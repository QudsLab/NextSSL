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
    let text = std::fs::read_to_string(up(src)).expect("read upstream source");
    if x86 || !text.contains(HEAD) {
        return up(src);
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
    // Plain `char` is unsigned on Linux ARM but signed on x86, Windows and Apple, where the
    // upstreams were written and tested (Khichidi-1's `char i; i >= 0` loop never ends unsigned).
    if !b.get_compiler().is_like_msvc() {
        b.flag("-fsigned-char");
    }
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
        nextssl_cbuild::directive!(
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
        b.include(up(i));
    }
    for s in SOURCES {
        let f = portable_source(s);
        if f != up(s) {
            // the copy lives in OUT_DIR: keep the original directory for its "..." includes
            b.include(up(s).parent().unwrap());
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
    link_shared(&mut b, "nextssl_ryde3s_r2", false);
    // The final objects must define no global the -O0 probe missed (see check_prefixed).
    check_prefixed(&out);
    nextssl_cbuild::directive!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    if std::path::Path::new("upstream").exists() {
        nextssl_cbuild::directive!("cargo:rerun-if-changed=upstream");
    }
    if std::path::Path::new("shim.c").exists() {
        nextssl_cbuild::directive!("cargo:rerun-if-changed=shim.c");
    }
    nextssl_cbuild::directive!("cargo:rerun-if-changed=upstream.patches");
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
