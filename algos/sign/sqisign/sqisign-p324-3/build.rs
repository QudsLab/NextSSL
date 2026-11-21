//! Generated wiring. Compiles the verbatim upstream sources in two passes: pass 1 finds every
//! global symbol the code defines (C++ free functions by their plain name), pass 2 force-includes a
//! header that renames each of them to `nextssl__sqisign_p324_3__<name>` (no two upstreams can collide).
//! C and C++ sources are built separately (cc `.cpp(true)` only for the C++ set).
//! `NEXTSSL_C_SANITIZE=1` adds ASan/UBSan(trap).
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

const SOURCES: &[&str] = &[
    "upstream/src/sig/sqisign/the-sqisign_sqisign_p324_3_ref/api.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_p324_3_ref/e0_basis.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_p324_3_ref/ec_params.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_p324_3_ref/endomorphism_action.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_p324_3_ref/fp_p324_3.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_p324_3_ref/quaternion_data.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_p324_3_ref/torsion_constants.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/algebra.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/basis.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/biextension.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/common.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/dim2.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/dim2id2iso.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/dim4.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/ec.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/encode_public.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/encode_secret.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/finit.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/gaussian_xgcd.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/gluing.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/hd.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/id2iso.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/ideal.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/integers.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/isog.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/keygen.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/lattice.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/lehmer_xgcd.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/lll_applications.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/lll_dim4.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/lll_lg2.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/mem.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/modqx.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/mp.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/normalize.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/printer.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/prng.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/protocol.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/qlapoty.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/random_input_generation.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/sig.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/sign.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/splitting.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/sqisign.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/stdorder.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/theta_isogenies.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/theta_structure.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common/verify.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common_ref/fp.c",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common_ref/fp2.c",
    "upstream/src/common/common.c",
    "upstream/src/common/sha3/sha3.c",
    "upstream/src/common/sha3/sha3x4.c",
    "upstream/src/common/pqclean_shims/fips202.c",
    "compat/ns_xkcp_plain64.c",
    "compat/ns_xkcp_times4.c",
    "compat/ns_xkcp_sha3.c",
    "compat/ns_xkcp_sha3x4.c",
    "shim.c",
];
const CPP_SOURCES: &[&str] = &[];
const INCLUDES: &[&str] = &[
    "upstream/src/sig/sqisign/the-sqisign_sqisign_p324_3_ref",
    "upstream/src/common/pqclean_shims",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common",
    "upstream/src/sig/sqisign/the-sqisign_sqisign_common_ref",
    "upstream/src/common",
    "upstream/src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits",
    "upstream/src/common/sha3/xkcp_low/KeccakP-1600times4/serial",
    "upstream/src/common/sha3",
    "upstream/src/common/aes",
    "upstream/src/common/sha2",
    "upstream/src/common/rand",
    "compat",
];
const DEFINES: &[(&str, &str)] = &[
    ("SQISIGN_BUILD_TYPE_REF", "ON"),
    ("SQISIGN_VARIANT", "p324_3"),
    ("SQISIGN_GF_IMPL_REF", "ON"),
    ("ENABLE_SIGN", "ON"),
    ("SQISIGN_NAMESPACE_GENERIC_AS_VARIANT", "1"),
];
const PREFIX: &str = "nextssl__sqisign_p324_3__";

fn base(cpp: bool) -> cc::Build {
    let mut b = cc::Build::new();
    b.warnings(false).opt_level(2);
    if cpp {
        b.cpp(true);
    }
    for i in INCLUDES {
        b.include(i);
    }
    for (k, v) in DEFINES {
        b.define(k, if v.is_empty() { None } else { Some(*v) });
    }
    for s in if cpp { CPP_SOURCES } else { SOURCES } {
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
            if !matches!(
                s.kind(),
                SymbolKind::Text | SymbolKind::Data | SymbolKind::Unknown
            ) {
                continue;
            }
            let Ok(mut n) = s.name() else { continue };
            if strip {
                n = n.strip_prefix('_').unwrap_or(n);
            }
            // Itanium-mangled free function `_Z<len><name>...`: rename the plain identifier.
            if let Some(r) = n
                .strip_prefix("_Z")
                .filter(|r| r.as_bytes().first().is_some_and(|c| c.is_ascii_digit()))
            {
                let digits: String = r.chars().take_while(|c| c.is_ascii_digit()).collect();
                let len: usize = digits.parse().unwrap_or(0);
                let rest = &r[digits.len()..];
                if len > 0 && rest.len() >= len {
                    let id = &rest[..len];
                    if !id.starts_with("__")
                        && !id.as_bytes()[0].is_ascii_digit()
                        && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                    {
                        out.insert(id.to_string());
                    }
                }
                continue;
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
    // BEGIN TARGET GATE (cargo xtask gen, from algo.toml exclude_targets)
    // Excluded: MSVC cannot build the upstream C: error C2143: syntax error: missing ')' before '*'
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        return;
    }
    // END TARGET GATE
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let sets = [
        (false, SOURCES.is_empty(), "probe", "nextssl_sqisign_p324_3"),
        (
            true,
            CPP_SOURCES.is_empty(),
            "probe_cpp",
            "nextssl_sqisign_p324_3_cpp",
        ),
    ];
    let mut objs = Vec::new();
    for (cpp, empty, dir, _) in sets {
        if empty {
            continue;
        }
        let mut probe = base(cpp);
        probe.out_dir(out.join(dir));
        std::fs::create_dir_all(out.join(dir)).unwrap();
        objs.extend(probe.compile_intermediates());
    }
    let syms = defined_symbols(&objs);
    let hdr = out.join("nextssl_prefix.h");
    let mut f = std::fs::File::create(&hdr).unwrap();
    for s in &syms {
        writeln!(f, "#define {s} {PREFIX}{s}").unwrap();
    }
    drop(f);
    for (cpp, empty, _, lib) in sets {
        if empty {
            continue;
        }
        let mut b = base(cpp);
        if b.get_compiler().is_like_msvc() {
            b.flag(format!("/FI{}", hdr.display()));
        } else {
            b.flag("-include").flag(hdr.to_str().unwrap());
        }
        link_shared(&mut b, lib, cpp);
    }
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_SANITIZE");
    println!("cargo:rerun-if-changed=upstream");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-changed=shim.cpp");
    println!("cargo:rerun-if-changed=build.rs");
}

// BEGIN SHARED LINK (cargo xtask build-link)
// Compiles `b`, then publishes the static library into one directory shared by every C-backed
// algorithm (see xtask/src/buildlink.rs). The library is renamed `<lib>_<hash>` so names stay unique.
fn link_shared(b: &mut cc::Build, lib: &str, cpp: bool) {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    b.cargo_metadata(false).compile(lib);
    let msvc = b.get_compiler().is_like_msvc();
    let pkg_dir = out.parent().expect("OUT_DIR has a parent");
    let tag = pkg_dir
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.rsplit('-').next())
        .unwrap_or("0");
    let shared = pkg_dir.parent().expect("build dir").join("nextssl-c-libs");
    std::fs::create_dir_all(&shared).expect("create shared lib dir");
    let uniq = format!("{lib}_{tag}");
    let file = |n: &str| {
        if msvc {
            format!("{n}.lib")
        } else {
            format!("lib{n}.a")
        }
    };
    let tmp = shared.join(format!("{}.tmp", file(&uniq)));
    std::fs::copy(out.join(file(lib)), &tmp).expect("copy static library");
    std::fs::rename(&tmp, shared.join(file(&uniq))).expect("publish static library");
    println!("cargo:rustc-link-search=native={}", shared.display());
    println!("cargo:rustc-link-lib=static={uniq}");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CFLAGS");
    if cpp {
        let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
        let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
        let std_lib = std::env::var("CXXSTDLIB").ok().unwrap_or_else(|| {
            match os.as_str() {
                _ if env == "msvc" => "",
                "macos" | "ios" | "tvos" | "watchos" | "freebsd" | "openbsd" | "android"
                | "wasi" | "emscripten" => "c++",
                _ => "stdc++",
            }
            .to_string()
        });
        if !std_lib.is_empty() {
            println!("cargo:rustc-link-lib={std_lib}");
        }
    }
}
// END SHARED LINK
