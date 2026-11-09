//! Compiles the verbatim upstream sources. Every exported upstream symbol is renamed with
//! a `nextssl__ascon_aead128a__` prefix (via `-D` defines, no source edits) so no two upstreams can collide.
//!
//! `NEXTSSL_C_SANITIZE=1` compiles the C with `-fsanitize=address,undefined`. ASan needs a
//! sanitizer runtime at link time (build with `RUSTFLAGS=-Zsanitizer=address`, which supplies
//! it). UBSan runs in trap mode (`-fsanitize-trap=undefined`): any UB aborts the test with
//! SIGILL, and no second sanitizer runtime is linked (two runtimes collide).

const EXPORTED: &[&str] = &[
    "aead_check_tag",
    "aead_check_tag_precheck",
    "ascon128_aead_decrypt",
    "ascon128_aead_encrypt",
    "ascon128_cipher",
    "ascon128a_aead_decrypt",
    "ascon128a_aead_encrypt",
    "ascon128a_cipher",
    "ascon80pq_aead_decrypt",
    "ascon80pq_aead_encrypt",
    "ascon80pq_cipher",
    "ascon_from_sliced",
    "ascon_permute",
    "ascon_permute_sliced",
    "ascon_to_sliced",
];

const SOURCES: &[&str] = &[
    "upstream/aead-common.c",
    "upstream/ascon128.c",
    "upstream/internal-ascon.c",
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
        b.define(
            sym,
            Some(format!("nextssl__ascon_aead128a__{sym}").as_str()),
        );
    }
    sanitize(&mut b);
    b.compile("nextssl_ascon_aead128a");
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    println!("cargo:rerun-if-changed=upstream");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-changed=build.rs");
}
