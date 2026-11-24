//! Generated wiring. Compiles the verbatim PQClean sources in two passes: pass 1 finds every
//! global symbol the C code defines, pass 2 force-includes a header that renames each of them to
//! `nextssl__ed448goldilocks__<name>` (no two upstreams can collide). `NEXTSSL_C_SANITIZE=1` adds ASan/UBSan(trap).
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

const SOURCES: &[&str] = &[
    "upstream/32/barrett_field.c",
    "upstream/32/crandom.c",
    "upstream/32/ec_point.c",
    "upstream/32/goldilocks.c",
    "upstream/32/magic.c",
    "upstream/32/p448.c",
    "upstream/32/scalarmul.c",
    "upstream/32/sha512.c",
    "upstream/32/sign.c",
    "shim.c",
];
const INCLUDES: &[&str] = &["upstream/32", "compat"];
const PREFIX: &str = "nextssl__ed448goldilocks__";

/// upstream/32/goldilocks.c seeds a process-global generator from /dev/urandom in goldilocks_init()
/// and draws every key seed from it in goldilocks_keygen(), so the caller's EntropySource was never
/// used (and on targets without /dev/urandom, e.g. wasm32, init failed). The file on disk stays
/// verbatim; the compiled copy makes two exact replacements:
/// 1. keygen takes its seed from `randombytes` (shim.c, backed by the EntropySource; a failure
///    returns an error, the glue reports it);
/// 2. init seeds the now unused global generator from a constant instead of opening a file.
///    The global generator has no other use in the library (sign and verify are deterministic).
fn entropy_copy(src: &str) -> PathBuf {
    let text = std::fs::read_to_string(src).expect("read upstream/32/goldilocks.c");
    let reps: [(&str, &str); 3] = [
        (
            "#include \"intrinsics.h\"\n",
            "#include \"intrinsics.h\"\nint randombytes(unsigned char *output, unsigned long long n);\n",
        ),
        (
            "    int criff_res = crandom_init_from_file(&goldilocks_global.rand,\n        GOLDILOCKS_RANDOM_INIT_FILE,\n        GOLDILOCKS_RANDOM_RESEED_INTERVAL,\n        GOLDILOCKS_RANDOM_RESEEDS_MANDATORY);\n",
            "    crandom_init_from_buffer(&goldilocks_global.rand, \"nextssl: key seeds come from the EntropySource\");\n    int criff_res = 0;\n",
        ),
        (
            "    int ret = crandom_generate(&goldilocks_global.rand, proto, sizeof(proto));\n",
            "    int ret = randombytes(proto, sizeof(proto));\n",
        ),
    ];
    let mut out = text.replace("\r\n", "\n");
    for (from, to) in reps {
        assert_eq!(
            out.matches(from).count(),
            1,
            "goldilocks.c: expected one `{from}`"
        );
        out = out.replace(from, to);
    }
    let p = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("goldilocks_entropy.c");
    std::fs::write(&p, out).expect("write goldilocks_entropy.c");
    p
}

/// aarch64 only; the sources are then compiled from a copy of upstream/32 (OUT_DIR) whose word.h has
/// these exact changes. 1. macOS: word.h's `#ifdef __APPLE__` block assumes an Intel Mac and
/// byte-swaps with x86 `bswapq` inline asm; the copy has `x = __builtin_bswap64(x);` (same result).
/// 2. Without `__ARM_NEON__` (GCC on Linux, clang-cl on Windows; Apple clang defines it), word.h
/// takes its `_WIN64 || __amd64__ || __X86_64__ || __aarch64__` branch, made for 64-bit words: a
/// 64-bit big_register_t. This tree has 32-bit words, so br_is_zero() and br_set_to_mask() give
/// 32-bit masks that select only the low half of each register in the constant-time table lookup
/// and conditional swap, and every signature fails to verify (CI run 45393949691, linux-arm64 and
/// windows-arm64). The copy takes that branch for 64-bit words only; with 32-bit words the
/// portable branch (32-bit big_register_t) is used, as on every 32-bit target. Other targets
/// (x86 uses its SSE2 branch, wasm32 the portable one) compile upstream/32 unchanged.
fn apple_arm_tree() -> Option<PathBuf> {
    let mac = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos");
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("aarch64") {
        return None;
    }
    let dst = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("upstream32_aarch64");
    std::fs::create_dir_all(&dst).expect("create copy dir");
    for e in std::fs::read_dir("upstream/32").expect("read upstream/32") {
        let p = e.expect("dir entry").path();
        if p.is_file() {
            std::fs::copy(&p, dst.join(p.file_name().unwrap())).expect("copy upstream file");
        }
    }
    let w = dst.join("word.h");
    let mut text = std::fs::read_to_string(&w).expect("read word.h");
    let mut edits = vec![(
        "#elif _WIN64 || __amd64__ || __X86_64__ || __aarch64__\n",
        "#elif (_WIN64 || __amd64__ || __X86_64__ || __aarch64__) && WORD_BITS == 64\n",
    )];
    if mac {
        edits.push((
            "    __asm__ (\"bswapq %0\" : \"+r\"(x));\n",
            "    x = __builtin_bswap64(x);\n",
        ));
    }
    for (find, replace) in edits {
        assert_eq!(
            text.matches(find).count(),
            1,
            "word.h: expected one `{find}`"
        );
        text = text.replace(find, replace);
    }
    std::fs::write(&w, text).expect("write word.h");
    Some(dst)
}

fn base() -> cc::Build {
    let mut b = cc::Build::new();
    // Plain `char` is unsigned on Linux ARM but signed on x86, Windows and Apple, where the
    // upstreams were written and tested (Khichidi-1's `char i; i >= 0` loop never ends unsigned).
    if !b.get_compiler().is_like_msvc() {
        b.flag("-fsigned-char");
    }
    // POSIX headers the upstream includes; MSVC targets get stand-ins (compat/msvc).
    if b.get_compiler().is_like_msvc() {
        b.include("compat/msvc");
    }
    // posix_memalign does not exist on MSVC targets; see compat/msvc/nextssl_posix_memalign.h.
    if b.get_compiler().is_like_msvc() {
        let h = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("compat/msvc/nextssl_posix_memalign.h");
        b.flag(format!("/FI{}", h.display()));
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
    let tree = apple_arm_tree();
    if let Some(t) = &tree {
        b.include(t);
    }
    for i in INCLUDES {
        b.include(i);
    }
    // intrinsics.h/word.h use the BSD type u_int64_t; wasi-libc (musl) declares it only with _BSD_SOURCE.
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32") {
        b.define("_BSD_SOURCE", None);
    }
    for s in SOURCES {
        // On aarch64 the upstream/32 files come from the patched copy (see apple_arm_tree).
        let src = match (&tree, s.strip_prefix("upstream/32/")) {
            (Some(t), Some(name)) => t.join(name).to_string_lossy().into_owned(),
            _ => s.to_string(),
        };
        if *s == "upstream/32/goldilocks.c" {
            b.file(entropy_copy(&src));
        } else {
            b.file(&src);
        }
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
    link_shared(&mut b, "nextssl_ed448goldilocks", false);
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
