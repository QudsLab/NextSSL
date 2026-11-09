//! Generated wiring. Compiles the verbatim PQClean sources in two passes: pass 1 finds every
//! global symbol the C code defines, pass 2 force-includes a header that renames each of them to
//! `nextssl__hufu__<name>` (no two upstreams can collide). `NEXTSSL_C_SANITIZE=1` adds ASan/UBSan(trap).
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

const SOURCES: &[&str] = &["upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/aes/aes.c", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/gen_mat.c", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/normaldist/fixpoint.c", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/normaldist/normaldist.c", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/pack.c", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/rANS/compress.c", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/random/random.c", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/sampling/samplez.c", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/sampling/sampling.c", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/sha3/fips202.c", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/sha3/shake.c", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/sign.c", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/util.c", "shim.c"];
const INCLUDES: &[&str] = &["upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/aes", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/normaldist", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/rANS", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/random", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/sampling", "upstream/HuFu-noKATs/HuFu/Reference_Implementation/crypto_sign/HuFu_NIST3/sha3"];
const PREFIX: &str = "nextssl__hufu__";

fn base() -> cc::Build {
    let mut b = cc::Build::new();
    b.warnings(false).opt_level(2);
    for i in INCLUDES {
        b.include(i);
    }
    for s in SOURCES {
        b.file(s);
    }
    if std::env::var("NEXTSSL_C_SANITIZE").is_ok_and(|v| v == "1") {
        b.flag("-fsanitize=address,undefined")
            .flag("-fsanitize-trap=undefined")
            .flag("-fno-omit-frame-pointer")
            .flag("-g")
            .opt_level(1);
    }
    b
}

fn defined_symbols(objs: &[PathBuf]) -> BTreeSet<String> {
    use object::{Architecture, BinaryFormat, Object, ObjectSymbol, SymbolKind};
    let mut out = BTreeSet::new();
    for o in objs {
        let data = std::fs::read(o).expect("read object");
        let f = object::File::parse(&*data).expect("parse object");
        let strip = f.format() == BinaryFormat::MachO
            || (f.format() == BinaryFormat::Coff && f.architecture() == Architecture::I386);
        for s in f.symbols() {
            if s.is_undefined() || !s.is_global() {
                continue;
            }
            if !matches!(s.kind(), SymbolKind::Text | SymbolKind::Data | SymbolKind::Unknown) {
                continue;
            }
            let Ok(mut n) = s.name() else { continue };
            if strip {
                n = n.strip_prefix('_').unwrap_or(n);
            }
            let ok = !n.is_empty()
                && !n.starts_with("__")
                && !n.starts_with("nextssl__")
                && n != "_fltused"
                && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                && !n.as_bytes()[0].is_ascii_digit();
            if ok {
                out.insert(n.to_string());
            }
        }
    }
    out
}

fn main() {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let mut probe = base();
    probe.out_dir(out.join("probe"));
    std::fs::create_dir_all(out.join("probe")).unwrap();
    let objs = probe.compile_intermediates();
    let syms = defined_symbols(&objs);
    let hdr = out.join("nextssl_prefix.h");
    let mut f = std::fs::File::create(&hdr).unwrap();
    for s in &syms {
        writeln!(f, "#define {s} {PREFIX}{s}").unwrap();
    }
    drop(f);
    let mut b = base();
    if b.get_compiler().is_like_msvc() {
        b.flag(&format!("/FI{}", hdr.display()));
    } else {
        b.flag("-include").flag(hdr.to_str().unwrap());
    }
    b.compile("nextssl_hufu");
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    println!("cargo:rerun-if-changed=upstream");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-changed=build.rs");
}
