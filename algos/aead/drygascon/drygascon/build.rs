//! Compiles the verbatim upstream sources. Every exported upstream symbol is renamed with
//! a `nextssl__drygascon__` prefix (via `-D` defines, no source edits) so no two upstreams can collide.
//!
//! `NEXTSSL_C_SANITIZE=1` compiles the C with `-fsanitize=address,undefined`. ASan needs a
//! sanitizer runtime at link time (build with `RUSTFLAGS=-Zsanitizer=address`, which supplies
//! it). UBSan runs in trap mode (`-fsanitize-trap=undefined`): any UB aborts the test with
//! SIGILL, and no second sanitizer runtime is linked (two runtimes collide).

const EXPORTED: &[&str] = &[
    "aead_check_tag",
    "aead_check_tag_precheck",
    "drygascon128_aead_decrypt_core",
    "drygascon128_aead_encrypt_core",
    "drygascon128_cipher",
    "drygascon128_f_impl",
    "drygascon128_f_wrap",
    "drygascon128_hash",
    "drygascon128_hash_algorithm",
    "drygascon128k16_aead_decrypt",
    "drygascon128k16_aead_encrypt",
    "drygascon128k16_cipher",
    "drygascon128k32_aead_decrypt",
    "drygascon128k32_aead_encrypt",
    "drygascon128k32_cipher",
    "drygascon128k56_aead_decrypt",
    "drygascon128k56_aead_encrypt",
    "drygascon128k56_cipher",
    "drygascon256_aead_decrypt",
    "drygascon256_aead_encrypt",
    "drygascon256_cipher",
    "drygascon256_hash",
    "drygascon256_hash_algorithm",
    "drysponge128_g",
    "drysponge128_g_core",
    "drysponge128_safe_alignement",
    "drysponge128_setup",
    "drysponge256_f_absorb",
    "drysponge256_g",
    "drysponge256_g_core",
    "drysponge256_setup",
    "gascon128_core_round",
    "gascon256_core_round",
];

const SOURCES: &[&str] = &[
    "upstream/aead-common.c",
    "upstream/drygascon.c",
    "upstream/internal-drysponge.c",
];

fn sanitize(b: &mut cc::Build) {
    if std::env::var("NEXTSSL_C_SANITIZE").is_ok_and(|v| v == "1") {
        b.flag("-fsanitize=address,undefined")
            .flag("-fsanitize-trap=undefined")
            .flag("-fno-omit-frame-pointer")
            .flag("-g")
            .opt_level(1);
    }
}

fn main() {
    // Compiles the upstream, or reuses the identical result of an earlier build when CI enables the
    // cache (NEXTSSL_C_CACHE); see crates/nextssl-cbuild.
    nextssl_cbuild::cached(build_main);
}

fn build_main() {
    let mut b = cc::Build::new();
    // Windows on ARM64 (cl.exe): the upstream's endianness check lists _M_ARM but not _M_ARM64 and says to define
    // __LITTLE_ENDIAN__ in the compiler flags instead.
    // Windows on ARM64 is always little-endian. Other targets compile unchanged.
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("aarch64")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        b.define("__LITTLE_ENDIAN__", None);
    }
    // Plain `char` is unsigned on Linux ARM but signed on x86, Windows and Apple, where the
    // upstreams were written and tested (Khichidi-1's `char i; i >= 0` loop never ends unsigned).
    if !b.get_compiler().is_like_msvc() {
        b.flag("-fsigned-char");
    }
    for f in SOURCES {
        b.file(f);
    }
    b.file("shim.c").include("upstream").warnings(false);
    // The upstream needs its `__attribute__((aligned(16)))` state: drygascon128_aead_encrypt_core
    // returns -1 when the state is not 16-byte aligned. cl.exe has no __attribute__ (msvc_compat.h
    // would drop it), so on MSVC targets the C is compiled with clang-cl, which keeps the alignment:
    // same ABI and object format, linked by link.exe (CI run 45416349331: "seal failed" on
    // windows-arm64, where the stack slot was not 16-byte aligned).
    if b.get_compiler().is_like_msvc() {
        b.compiler(clang_cl());
    }
    for sym in EXPORTED {
        b.define(sym, Some(format!("nextssl__drygascon__{sym}").as_str()));
    }
    sanitize(&mut b);
    // Pin the C dialect: GCC 15 defaults to C23, where `int f()` means no parameters; that breaks
    // K&R-era upstreams. gnu17 is the dialect these sources were written against.
    if !b.get_compiler().is_like_msvc() {
        b.flag("-std=gnu17");
    }
    link_shared(&mut b, "nextssl_drygascon", false);
    nextssl_cbuild::directive!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    if std::path::Path::new("upstream").exists() {
        nextssl_cbuild::directive!("cargo:rerun-if-changed=upstream");
    }
    if std::path::Path::new("shim.c").exists() {
        nextssl_cbuild::directive!("cargo:rerun-if-changed=shim.c");
    }
    nextssl_cbuild::directive!("cargo:rerun-if-changed=build.rs");
}

fn clang_cl() -> std::path::PathBuf {
    nextssl_cbuild::directive!("cargo:rerun-if-env-changed=NEXTSSL_CLANG_CL");
    if let Some(p) = std::env::var_os("NEXTSSL_CLANG_CL") {
        return std::path::PathBuf::from(p);
    }
    let mut dirs: Vec<std::path::PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    dirs.push(std::path::PathBuf::from(r"C:\Program Files\LLVM\bin"));
    for d in dirs {
        let c = d.join("clang-cl.exe");
        if c.is_file() {
            return c;
        }
    }
    panic!(
        "drygascon's C upstream needs clang-cl on MSVC targets (aligned state): \
         install LLVM or set NEXTSSL_CLANG_CL to clang-cl.exe"
    );
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
