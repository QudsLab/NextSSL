//! Compiles the verbatim upstream C sources. Every exported upstream symbol is renamed with
//! a `nextssl__yescrypt__` prefix (via `-D` defines, no source edits) so no two upstreams can collide.
//!
//! `NEXTSSL_C_SANITIZE=1` compiles the C with `-fsanitize=address,undefined`. ASan needs a
//! sanitizer runtime at link time (build with `RUSTFLAGS=-Zsanitizer=address`, which supplies
//! it). UBSan runs in trap mode (`-fsanitize-trap=undefined`): any UB aborts the test with
//! SIGILL, and no second sanitizer runtime is linked (two runtimes collide).

const EXPORTED: &[&str] = &[
    "PBKDF2_SHA256",
    "crypto_scrypt",
    "insecure_memzero_ptr",
    "libcperciva_HMAC_SHA256_Buf",
    "libcperciva_HMAC_SHA256_Final",
    "libcperciva_HMAC_SHA256_Init",
    "libcperciva_HMAC_SHA256_Update",
    "libcperciva_SHA256_Buf",
    "libcperciva_SHA256_Final",
    "libcperciva_SHA256_Init",
    "libcperciva_SHA256_Update",
    "yescrypt",
    "yescrypt_digest_shared",
    "yescrypt_encode_params",
    "yescrypt_encode_params_r",
    "yescrypt_free_local",
    "yescrypt_free_shared",
    "yescrypt_init_local",
    "yescrypt_init_shared",
    "yescrypt_kdf",
    "yescrypt_r",
    "yescrypt_reencrypt",
];

fn main() {
    let mut b = cc::Build::new();
    b.file("upstream/yescrypt-ref.c")
        .file("upstream/yescrypt-common.c")
        .file("upstream/sha256.c")
        .file("upstream/insecure_memzero.c")
        .file("shim.c")
        .include("upstream")
        .warnings(false);

    for sym in EXPORTED {
        b.define(sym, Some(format!("nextssl__yescrypt__{sym}").as_str()));
    }
    if std::env::var("NEXTSSL_C_SANITIZE").is_ok_and(|v| v == "1") {
        b.flag("-fsanitize=address,undefined")
            .flag("-fsanitize-trap=undefined")
            .flag("-fno-omit-frame-pointer")
            .flag("-g")
            .opt_level(1);
    }
    b.compile("nextssl_yescrypt");
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    println!("cargo:rerun-if-changed=upstream");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-changed=build.rs");
}
