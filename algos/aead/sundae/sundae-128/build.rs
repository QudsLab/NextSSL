//! Compiles the verbatim upstream sources. Every exported upstream symbol is renamed with
//! a `nextssl__sundae_128__` prefix (via `-D` defines, no source edits) so no two upstreams can collide.
//!
//! `NEXTSSL_C_SANITIZE=1` compiles the C with `-fsanitize=address,undefined`. ASan needs a
//! sanitizer runtime at link time (build with `RUSTFLAGS=-Zsanitizer=address`, which supplies
//! it). UBSan runs in trap mode (`-fsanitize-trap=undefined`): any UB aborts the test with
//! SIGILL, and no second sanitizer runtime is linked (two runtimes collide).

const EXPORTED: &[&str] = &[
    "aead_check_tag",
    "aead_check_tag_precheck",
    "gift128b_decrypt",
    "gift128b_encrypt",
    "gift128b_encrypt_preloaded",
    "gift128b_init",
    "gift128n_decrypt",
    "gift128n_encrypt",
    "gift128n_init",
    "gift128t_decrypt",
    "gift128t_encrypt",
    "sundae_gift_0_aead_decrypt",
    "sundae_gift_0_aead_encrypt",
    "sundae_gift_0_cipher",
    "sundae_gift_128_aead_decrypt",
    "sundae_gift_128_aead_encrypt",
    "sundae_gift_128_cipher",
    "sundae_gift_64_aead_decrypt",
    "sundae_gift_64_aead_encrypt",
    "sundae_gift_64_cipher",
    "sundae_gift_96_aead_decrypt",
    "sundae_gift_96_aead_encrypt",
    "sundae_gift_96_cipher",
];

const SOURCES: &[&str] = &[
    "upstream/aead-common.c",
    "upstream/internal-gift128.c",
    "upstream/sundae-gift.c",
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
    for sym in EXPORTED {
        b.define(sym, Some(format!("nextssl__sundae_128__{sym}").as_str()));
    }
    sanitize(&mut b);
    // Pin the C dialect: GCC 15 defaults to C23, where `int f()` means no parameters; that breaks
    // K&R-era upstreams. gnu17 is the dialect these sources were written against.
    if !b.get_compiler().is_like_msvc() {
        b.flag("-std=gnu17");
    }
    link_shared(&mut b, "nextssl_sundae_128", false);
    nextssl_cbuild::directive!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    if std::path::Path::new("upstream").exists() {
        nextssl_cbuild::directive!("cargo:rerun-if-changed=upstream");
    }
    if std::path::Path::new("shim.c").exists() {
        nextssl_cbuild::directive!("cargo:rerun-if-changed=shim.c");
    }
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
