//! Compiles the verbatim upstream C sources. Every exported upstream symbol is renamed with
//! a `nextssl__md6__` prefix (via `-D` defines, no source edits) so no two upstreams can collide.
//!
//! `NEXTSSL_C_SANITIZE=1` compiles the C with `-fsanitize=address,undefined`. ASan needs a
//! sanitizer runtime at link time (build with `RUSTFLAGS=-Zsanitizer=address`, which supplies
//! it). UBSan runs in trap mode (`-fsanitize-trap=undefined`): any UB aborts the test with
//! SIGILL, and no second sanitizer runtime is linked (two runtimes collide).

const EXPORTED: &[&str] = &[
    "S0",
    "Smask",
    "append_bits",
    "compression_hook",
    "md6_byte_order",
    "md6_byte_reverse",
    "md6_compress",
    "md6_compress_block",
    "md6_compute_hex_hashval",
    "md6_default_r",
    "md6_detect_byte_order",
    "md6_final",
    "md6_full_hash",
    "md6_full_init",
    "md6_hash",
    "md6_init",
    "md6_main_compression_loop",
    "md6_make_control_word",
    "md6_make_nodeID",
    "md6_pack",
    "md6_process",
    "md6_reverse_little_endian",
    "md6_standard_compress",
    "md6_update",
    "trim_hashval",
];

fn main() {
    let mut b = cc::Build::new();
    b.file("upstream/md6_compress.c")
        .file("upstream/md6_compression_hook.c")
        .file("upstream/md6_mode.c")
        .file("shim.c")
        .include("upstream")
        .warnings(false);

    for sym in EXPORTED {
        b.define(sym, Some(format!("nextssl__md6__{sym}").as_str()));
    }
    if std::env::var("NEXTSSL_C_SANITIZE").is_ok_and(|v| v == "1") {
        b.flag("-fsanitize=address,undefined")
            .flag("-fsanitize-trap=undefined")
            .flag("-fno-omit-frame-pointer")
            .flag("-g")
            .opt_level(1);
    }
    b.compile("nextssl_md6");
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    println!("cargo:rerun-if-changed=upstream");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-changed=build.rs");
}
