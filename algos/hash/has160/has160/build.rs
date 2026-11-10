//! Compiles the verbatim upstream C sources. Every exported upstream symbol is renamed with
//! a `nextssl__has160__` prefix (via `-D` defines, no source edits) so no two upstreams can collide.
//!
//! `NEXTSSL_C_SANITIZE=1` compiles the C with `-fsanitize=address,undefined`. ASan needs a
//! sanitizer runtime at link time (build with `RUSTFLAGS=-Zsanitizer=address`, which supplies
//! it). UBSan runs in trap mode (`-fsanitize-trap=undefined`): any UB aborts the test with
//! SIGILL, and no second sanitizer runtime is linked (two runtimes collide).

const EXPORTED: &[&str] = &[
    "has_cpu_feature",
    "rhash_has160_final",
    "rhash_has160_init",
    "rhash_has160_update",
    "rhash_swap_copy_str_to_u32",
    "rhash_swap_copy_str_to_u64",
    "rhash_swap_copy_u64_to_str",
    "rhash_swap_memset_to_u32",
    "rhash_u32_mem_swap",
];

fn main() {
    let mut b = cc::Build::new();
    b.file("upstream/has160.c")
        .file("upstream/byte_order.c")
        .file("shim.c")
        .include("upstream")
        .warnings(false);

    for sym in EXPORTED {
        b.define(sym, Some(format!("nextssl__has160__{sym}").as_str()));
    }
    if std::env::var("NEXTSSL_C_SANITIZE").is_ok_and(|v| v == "1") {
        b.flag("-fsanitize=address,undefined")
            .flag("-fsanitize-trap=undefined")
            .flag("-fno-omit-frame-pointer")
            .flag("-g")
            .opt_level(1);
    }
    link_shared(&mut b, "nextssl_has160", false);
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    println!("cargo:rerun-if-changed=upstream");
    println!("cargo:rerun-if-changed=shim.c");
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
