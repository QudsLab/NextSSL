//! Compiles the verbatim upstream C sources. Every exported upstream symbol is renamed with
//! a `nextssl__luffa__` prefix (via `-D` defines, no source edits) so no two upstreams can collide.
//!
//! `NEXTSSL_C_SANITIZE=1` compiles the C with `-fsanitize=address,undefined`. ASan needs a
//! sanitizer runtime at link time (build with `RUSTFLAGS=-Zsanitizer=address`, which supplies
//! it). UBSan runs in trap mode (`-fsanitize-trap=undefined`): any UB aborts the test with
//! SIGILL, and no second sanitizer runtime is linked (two runtimes collide).

const EXPORTED: &[&str] = &[
    "sph_luffa224",
    "sph_luffa224_addbits_and_close",
    "sph_luffa224_close",
    "sph_luffa224_init",
    "sph_luffa256",
    "sph_luffa256_addbits_and_close",
    "sph_luffa256_close",
    "sph_luffa256_init",
    "sph_luffa384",
    "sph_luffa384_addbits_and_close",
    "sph_luffa384_close",
    "sph_luffa384_init",
    "sph_luffa512",
    "sph_luffa512_addbits_and_close",
    "sph_luffa512_close",
    "sph_luffa512_init",
];

fn main() {
    let mut b = cc::Build::new();
    b.file("upstream/luffa.c")
        .file("shim.c")
        .include("upstream")
        .warnings(false);

    for sym in EXPORTED {
        b.define(sym, Some(format!("nextssl__luffa__{sym}").as_str()));
    }
    if std::env::var("NEXTSSL_C_SANITIZE").is_ok_and(|v| v == "1") {
        b.flag("-fsanitize=address,undefined")
            .flag("-fsanitize-trap=undefined")
            .flag("-fno-omit-frame-pointer")
            .flag("-g")
            .opt_level(1);
    }
    b.compile("nextssl_luffa");
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    println!("cargo:rerun-if-changed=upstream");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-changed=build.rs");
}
