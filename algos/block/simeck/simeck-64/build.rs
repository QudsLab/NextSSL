//! Generated wiring. The verbatim Crypto++ sources are compiled in C++17 mode with the namespace
//! `CryptoPP` renamed to `nextssl_simeck_64_CryptoPP` (a `-D` define, no source edits), so every
//! mangled upstream symbol is unique to this algorithm and several Crypto++-backed ids link into one
//! binary. Portable build: assembly and SIMD paths are switched off. The only exported symbols are the
//! `extern "C"` `nextssl__simeck_64__*` functions of `shim.cpp`. `NEXTSSL_C_SANITIZE=1` adds ASan/UBSan(trap).
const SOURCES: &[&str] = &[
    "upstream/cryptlib.cpp",
    "upstream/misc.cpp",
    "upstream/algparam.cpp",
    "upstream/queue.cpp",
    "upstream/filters.cpp",
    "upstream/fips140.cpp",
    "upstream/allocate.cpp",
    "upstream/mqueue.cpp",
    "upstream/simeck.cpp",
    "shim.cpp",
];

fn main() {
    // Compiles the upstream, or reuses the identical result of an earlier build when CI enables the
    // cache (NEXTSSL_C_CACHE); see crates/nextssl-cbuild.
    nextssl_cbuild::cached(build_main);
}

fn build_main() {
    let mut b = cc::Build::new();
    // Plain `char` is unsigned on Linux ARM but signed on x86, Windows and Apple, where the
    // upstreams were written and tested (Khichidi-1's `char i; i >= 0` loop never ends unsigned).
    if !b.get_compiler().is_like_msvc() {
        b.flag("-fsigned-char");
    }
    b.cpp(true).warnings(false).opt_level(2);
    if b.get_compiler().is_like_msvc() {
        b.flag("/std:c++17").flag("/EHsc");
    } else {
        b.flag("-std=c++17");
    }
    b.include("upstream");
    b.define("CryptoPP", Some("nextssl_simeck_64_CryptoPP"));
    // cryptlib.cpp defines one extern "C" global (LibraryVersion); rename it too.
    b.define("LibraryVersion", Some("nextssl__simeck_64__LibraryVersion"));
    b.define("CRYPTOPP_DISABLE_ASM", None);
    b.define("CRYPTOPP_DISABLE_SSE2", None);
    b.define("CRYPTOPP_NO_ASSIGN_TO_INTEGER", None);
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
    link_shared(&mut b, "nextssl_simeck_64", true);
    nextssl_cbuild::directive!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    if std::path::Path::new("upstream").exists() {
        nextssl_cbuild::directive!("cargo:rerun-if-changed=upstream");
    }
    if std::path::Path::new("shim.cpp").exists() {
        nextssl_cbuild::directive!("cargo:rerun-if-changed=shim.cpp");
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
