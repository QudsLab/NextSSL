//! Generated wiring. The verbatim Crypto++ sources are compiled in C++17 mode with the namespace
//! `CryptoPP` renamed to `nextssl_simon_64_CryptoPP` (a `-D` define, no source edits), so every
//! mangled upstream symbol is unique to this algorithm and several Crypto++-backed ids link into one
//! binary. Portable build: assembly and SIMD paths are switched off. The only exported symbols are the
//! `extern "C"` `nextssl__simon_64__*` functions of `shim.cpp`. `NEXTSSL_C_SANITIZE=1` adds ASan/UBSan(trap).
const SOURCES: &[&str] = &[
    "upstream/cryptlib.cpp",
    "upstream/misc.cpp",
    "upstream/algparam.cpp",
    "upstream/queue.cpp",
    "upstream/filters.cpp",
    "upstream/fips140.cpp",
    "upstream/allocate.cpp",
    "upstream/mqueue.cpp",
    "upstream/simon.cpp",
    "shim.cpp",
];

fn main() {
    let mut b = cc::Build::new();
    b.cpp(true).warnings(false).opt_level(2);
    if b.get_compiler().is_like_msvc() {
        b.flag("/std:c++17").flag("/EHsc");
    } else {
        b.flag("-std=c++17");
    }
    b.include("upstream");
    b.define("CryptoPP", Some("nextssl_simon_64_CryptoPP"));
    // cryptlib.cpp defines one extern "C" global (LibraryVersion); rename it too.
    b.define("LibraryVersion", Some("nextssl_simon_64_LibraryVersion"));
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
    link_shared(&mut b, "nextssl_simon_64", true);
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    if std::path::Path::new("upstream").exists() {
        println!("cargo:rerun-if-changed=upstream");
    }
    if std::path::Path::new("shim.cpp").exists() {
        println!("cargo:rerun-if-changed=shim.cpp");
    }
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
    let shared = pkg_dir
        .parent()
        .expect("build dir")
        .join("nextssl-c-libs");
    std::fs::create_dir_all(&shared).expect("create shared lib dir");
    let uniq = format!("{lib}_{tag}");
    let file = |n: &str| if msvc { format!("{n}.lib") } else { format!("lib{n}.a") };
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
