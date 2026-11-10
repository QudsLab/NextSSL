//! `cargo xtask build-link [--check]`: normalise the C `build.rs` files so every C-backed
//! algorithm links through ONE shared native search directory.
//!
//! Why: cc emits `cargo:rustc-link-search=native=<this crate's OUT_DIR>`, and cargo passes one
//! `-L native=...` per C build script to every dependent rustc. With several hundred distinct
//! directories rustc fails on Windows (past ~32 KB of distinct search paths) with a misleading
//! `E0463 can't find crate`. Identical paths are de-duplicated by rustc, so each build script
//! now copies its static library under a unique name (`<lib>_<hash of the OUT_DIR>`) into
//! `<target>/<profile>/build/nextssl-c-libs` and emits that single directory.
//!
//! The rewrite is idempotent. It replaces the one `b.compile(<lib>);` call and appends a helper.

use std::path::Path;

const MARK: &str = "// BEGIN SHARED LINK (cargo xtask build-link)";

const HELPER: &str = r#"
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
    let shared = pkg_dir
        .parent()
        .expect("build dir")
        .join("nextssl-c-libs");
    std::fs::create_dir_all(&shared).expect("create shared lib dir");
    let uniq = format!("{lib}_{tag}");
    let file = |n: &str| if msvc { format!("{n}.lib") } else { format!("lib{n}.a") };
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
"#;

fn rewrite(src: &str) -> Result<Option<String>, String> {
    if src.contains(MARK) {
        return Ok(None);
    }
    let cpp = src.contains("b.compile(lib);");
    let (needle, arg) = if cpp {
        ("b.compile(lib);", "lib".to_string())
    } else {
        let i = src
            .find("b.compile(\"")
            .ok_or("no `b.compile(\"...\");` call")?;
        let j = src[i..].find(");").ok_or("unterminated compile call")? + i;
        (&src[i..j + 2], src[i + 10..j].to_string())
    };
    if src.matches(needle).count() != 1 {
        return Err("compile call is not unique".into());
    }
    let flag = if cpp { "cpp" } else { "false" };
    let call = format!("link_shared(&mut b, {arg}, {flag});");
    let mut s = src.replacen(needle, &call, 1);
    s.push_str(HELPER);
    Ok(Some(s))
}

pub fn run(check: bool) -> Result<(), String> {
    let algos = crate::root().join("algos");
    let mut files = Vec::new();
    collect(&algos, &mut files);
    files.sort();
    let (mut changed, mut total) = (0, 0);
    for f in files {
        total += 1;
        let src = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        match rewrite(&src).map_err(|e| format!("{}: {e}", f.display()))? {
            None => {}
            Some(new) => {
                changed += 1;
                if !check {
                    std::fs::write(&f, new).map_err(|e| format!("{}: {e}", f.display()))?;
                }
            }
        }
    }
    println!("{total} build.rs files, {changed} {}", if check { "need rewriting" } else { "rewritten" });
    if check && changed > 0 {
        return Err("build.rs files are not normalised (run `cargo xtask build-link`)".into());
    }
    Ok(())
}

fn collect(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "upstream") {
                continue;
            }
            collect(&p, out);
        } else if p.file_name().is_some_and(|n| n == "build.rs") {
            out.push(p);
        }
    }
}
