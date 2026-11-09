//! Compiles the verbatim upstream sources. Every exported upstream symbol is renamed with
//! a `nextssl__drygascon_256__` prefix (via `-D` defines, no source edits) so no two upstreams can collide.
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
    let mut b = cc::Build::new();
    for f in SOURCES {
        b.file(f);
    }
    b.file("shim.c").include("upstream").warnings(false);
    if b.get_compiler().is_like_msvc() {
        b.include(".");
        b.flag("/FImsvc_compat.h");
    }
    for sym in EXPORTED {
        b.define(sym, Some(format!("nextssl__drygascon_256__{sym}").as_str()));
    }
    sanitize(&mut b);
    b.compile("nextssl_drygascon_256");
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    println!("cargo:rerun-if-changed=upstream");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-changed=build.rs");
}
