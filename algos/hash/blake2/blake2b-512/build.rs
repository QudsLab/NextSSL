//! Compiles the verbatim BLAKE2 reference C sources. Every exported upstream symbol is
//! renamed with a `nextssl__blake2b_512__` prefix so no two upstreams can ever collide.
//!
//! `NEXTSSL_C_SANITIZE=1` compiles the C with `-fsanitize=address,undefined`. ASan needs a
//! sanitizer runtime at link time (build with `RUSTFLAGS=-Zsanitizer=address`, which supplies
//! it). UBSan runs in trap mode (`-fsanitize-trap=undefined`): any UB aborts the test with
//! SIGILL, and no second sanitizer runtime is linked (two runtimes collide).

const EXPORTED: &[&str] = &[
    "blake2",
    "blake2b",
    "blake2b_init",
    "blake2b_init_key",
    "blake2b_init_param",
    "blake2b_update",
    "blake2b_final",
];

fn main() {
    let mut b = cc::Build::new();
    b.file("upstream/blake2b-ref.c")
        .include("upstream")
        .warnings(false);
    for sym in EXPORTED {
        b.define(sym, Some(format!("nextssl__blake2b_512__{sym}").as_str()));
    }
    if std::env::var("NEXTSSL_C_SANITIZE").is_ok_and(|v| v == "1") {
        b.flag("-fsanitize=address,undefined")
            .flag("-fsanitize-trap=undefined")
            .flag("-fno-omit-frame-pointer")
            .flag("-g")
            .opt_level(1);
    }
    b.compile("nextssl_blake2b_512");
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    println!("cargo:rerun-if-changed=upstream");
    println!("cargo:rerun-if-changed=build.rs");
}
