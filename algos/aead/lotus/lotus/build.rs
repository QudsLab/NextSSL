//! Compiles the verbatim upstream sources. Every exported upstream symbol is renamed with
//! a `nextssl__lotus__` prefix (via `-D` defines, no source edits) so no two upstreams can collide.
//!
//! `NEXTSSL_C_SANITIZE=1` compiles the C with `-fsanitize=address,undefined`. ASan needs a
//! sanitizer runtime at link time (build with `RUSTFLAGS=-Zsanitizer=address`, which supplies
//! it). UBSan runs in trap mode (`-fsanitize-trap=undefined`): any UB aborts the test with
//! SIGILL, and no second sanitizer runtime is linked (two runtimes collide).

const EXPORTED: &[&str] = &[
    "aead_check_tag",
    "aead_check_tag_precheck",
    "gift64n_decrypt",
    "gift64n_encrypt",
    "gift64n_init",
    "gift64n_update_round_keys",
    "gift64t_decrypt",
    "gift64t_encrypt",
    "locus_aead_cipher",
    "locus_aead_decrypt",
    "locus_aead_encrypt",
    "lotus_aead_cipher",
    "lotus_aead_decrypt",
    "lotus_aead_encrypt",
];

const SOURCES: &[&str] = &[
    "upstream/aead-common.c",
    "upstream/internal-gift64.c",
    "upstream/lotus-locus.c",
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
    let mut b = cc::Build::new();
    for f in SOURCES {
        b.file(f);
    }
    b.file("shim.c").include("upstream").warnings(false);
    for sym in EXPORTED {
        b.define(sym, Some(format!("nextssl__lotus__{sym}").as_str()));
    }
    sanitize(&mut b);
    b.compile("nextssl_lotus");
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    println!("cargo:rerun-if-changed=upstream");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-changed=build.rs");
}
