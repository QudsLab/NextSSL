//! Compiles the verbatim upstream sources. Every exported upstream symbol is renamed with
//! a `nextssl__romulus_hash__` prefix (via `-D` defines, no source edits) so no two upstreams can collide.
//!
//! `NEXTSSL_C_SANITIZE=1` compiles the C with `-fsanitize=address,undefined`. ASan needs a
//! sanitizer runtime at link time (build with `RUSTFLAGS=-Zsanitizer=address`, which supplies
//! it). UBSan runs in trap mode (`-fsanitize-trap=undefined`): any UB aborts the test with
//! SIGILL, and no second sanitizer runtime is linked (two runtimes collide).

const EXPORTED: &[&str] = &[
    "AddConstants",
    "AddKey",
    "BLOCK_SIZE",
    "MixColumn",
    "N_RNDS",
    "P",
    "RC",
    "ShiftRows",
    "SubCell8",
    "TWEAKEY_P",
    "TWEAKEY_SIZE",
    "crypto_hash",
    "enc",
    "hirose_128_128_256",
    "initialize",
    "ipad_128",
    "ipad_256",
    "sbox_8",
    "skinny_128_384_plus_enc",
];

const SOURCES: &[&str] = &["upstream/hash.c", "upstream/skinny_reference.c"];

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
        b.define(sym, Some(format!("nextssl__romulus_hash__{sym}").as_str()));
    }
    sanitize(&mut b);
    b.compile("nextssl_romulus_hash");
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    println!("cargo:rerun-if-changed=upstream");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-changed=build.rs");
}
