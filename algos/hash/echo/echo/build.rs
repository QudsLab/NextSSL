//! Compiles the verbatim upstream C sources. Every exported upstream symbol is renamed with
//! a `nextssl__echo__` prefix (via `-D` defines, no source edits) so no two upstreams can collide.
//!
//! `NEXTSSL_C_SANITIZE=1` compiles the C with `-fsanitize=address,undefined`. ASan needs a
//! sanitizer runtime at link time (build with `RUSTFLAGS=-Zsanitizer=address`, which supplies
//! it). UBSan runs in trap mode (`-fsanitize-trap=undefined`): any UB aborts the test with
//! SIGILL, and no second sanitizer runtime is linked (two runtimes collide).

const EXPORTED: &[&str] = &[
    "sph_echo224",
    "sph_echo224_addbits_and_close",
    "sph_echo224_close",
    "sph_echo224_init",
    "sph_echo256",
    "sph_echo256_addbits_and_close",
    "sph_echo256_close",
    "sph_echo256_init",
    "sph_echo384",
    "sph_echo384_addbits_and_close",
    "sph_echo384_close",
    "sph_echo384_init",
    "sph_echo512",
    "sph_echo512_addbits_and_close",
    "sph_echo512_close",
    "sph_echo512_init",
];

fn main() {
    let mut b = cc::Build::new();
    b.file("upstream/echo.c")
        .file("shim.c")
        .include("upstream")
        .warnings(false);

    for sym in EXPORTED {
        b.define(sym, Some(format!("nextssl__echo__{sym}").as_str()));
    }
    if std::env::var("NEXTSSL_C_SANITIZE").is_ok_and(|v| v == "1") {
        b.flag("-fsanitize=address,undefined")
            .flag("-fsanitize-trap=undefined")
            .flag("-fno-omit-frame-pointer")
            .flag("-g")
            .opt_level(1);
    }
    b.compile("nextssl_echo");
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    println!("cargo:rerun-if-changed=upstream");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-changed=build.rs");
}
