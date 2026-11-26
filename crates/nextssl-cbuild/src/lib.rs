//! Build-script helper for the C-backed algorithm crates: a content-addressed cache of the finished,
//! symbol-renamed static libraries.
//!
//! Only active when `NEXTSSL_C_CACHE` names a directory (CI test jobs). Without it, `cached` just runs
//! the build script's own `build_main`, so local builds, crates.io users and release builds are
//! unchanged and always compile from source.
//!
//! The cache key is two independent digests (SHA-256 and BLAKE3) of everything that can change the
//! compiled library:
//! * every file of the crate except `glue.rs` and `kat/` (Rust glue and test vectors are not compiled
//!   into the C library): upstream sources, patches, compat headers, shims and build.rs;
//! * every path the build script watches with `rerun-if-changed`, also outside the crate;
//! * the workspace `Cargo.lock` (the `cc` version and every build dependency);
//! * the C and C++ compiler path, size and `--version` output, and clang-cl's on MSVC targets;
//! * every environment variable the C build can read (CC*, CFLAGS*, AR*, CARGO_CFG_*, TARGET, HOST,
//!   OPT_LEVEL, DEBUG, PROFILE, NEXTSSL_*, the runner OS, ...);
//! * the macOS/iOS SDK path and build version, or the glibc version (not the runner image version);
//! * this crate's own source.
//!
//! A cached entry is used only when both digests match, and each stored library still matches its
//! own SHA-256 and BLAKE3; otherwise the library is compiled from source as without the cache. On a
//! hit, the directives the build script printed when the entry was made are printed again, with the
//! machine-specific paths filled in. The renamed-symbol check of the build script ran when the
//! library was built; the bytes are proven unchanged since.

use sha2::Digest;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static RECORDED: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Prints one build-script directive and records it so a cache hit can repeat it. Use `directive!`.
pub fn emit(line: String) {
    println!("{line}");
    RECORDED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(line);
}

/// `println!` for build-script directives (`cargo:...`), recorded for the cache.
#[macro_export]
macro_rules! directive {
    ($($t:tt)*) => {
        $crate::emit(::std::format!($($t)*))
    };
}

const SCHEME: &str = "nextssl-cbuild cache v1";

/// SHA-256 and BLAKE3 fed the same, length-prefixed fields.
struct Dual {
    sha: sha2::Sha256,
    b3: blake3::Hasher,
}

impl Dual {
    fn new() -> Self {
        Dual {
            sha: sha2::Sha256::new(),
            b3: blake3::Hasher::new(),
        }
    }

    fn field(&mut self, tag: &str, data: &[u8]) {
        for part in [
            tag.as_bytes(),
            &[0u8],
            &(data.len() as u64).to_le_bytes(),
            data,
        ] {
            self.sha.update(part);
            self.b3.update(part);
        }
    }

    fn finish(self) -> (String, String) {
        (
            hex(&self.sha.finalize()),
            self.b3.finalize().to_hex().to_string(),
        )
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn digests(data: &[u8]) -> (String, String) {
    (
        hex(&sha2::Sha256::digest(data)),
        blake3::hash(data).to_hex().to_string(),
    )
}

/// Files under `dir`, sorted by relative path ('/' separators); `skip` decides by relative path.
fn files(dir: &Path, skip: &dyn Fn(&str) -> bool) -> Vec<(String, PathBuf)> {
    fn walk(
        base: &Path,
        dir: &Path,
        skip: &dyn Fn(&str) -> bool,
        out: &mut Vec<(String, PathBuf)>,
    ) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            let rel = p
                .strip_prefix(base)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            if skip(&rel) {
                continue;
            }
            if p.is_dir() {
                walk(base, &p, skip, out);
            } else {
                out.push((rel, p));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, skip, &mut out);
    out.sort();
    out
}

fn hash_path(h: &mut Dual, p: &Path) {
    if p.is_dir() {
        for (rel, f) in files(p, &|_| false) {
            h.field(&rel, &std::fs::read(&f).unwrap_or_default());
        }
    } else if p.is_file() {
        h.field("file", &std::fs::read(p).unwrap_or_default());
    } else {
        h.field("missing", &[]);
    }
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

struct Ctx {
    manifest: PathBuf,
    root: PathBuf,
    shared: PathBuf,
    tag: String,
}

impl Ctx {
    fn new() -> Self {
        let manifest = PathBuf::from(env("CARGO_MANIFEST_DIR"));
        let root = manifest
            .ancestors()
            .find(|p| p.join("Cargo.lock").is_file())
            .unwrap_or(&manifest)
            .to_path_buf();
        // Same layout as link_shared in every build.rs (xtask/src/buildlink.rs).
        let out = PathBuf::from(env("OUT_DIR"));
        let tag = out
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .and_then(|n| n.rsplit('-').next())
            .unwrap_or("0")
            .to_string();
        let shared = out
            .ancestors()
            .find(|p| p.file_name().is_some_and(|n| n == "build"))
            .map(|b| b.join("nextssl-c-libs"))
            .unwrap_or_else(|| out.join("nextssl-c-libs"));
        Ctx {
            manifest,
            root,
            shared,
            tag,
        }
    }

    fn base_key(&self) -> (String, String) {
        let mut h = Dual::new();
        h.field("scheme", SCHEME.as_bytes());
        h.field("cbuild", include_str!("lib.rs").as_bytes());
        h.field(
            "Cargo.lock",
            &std::fs::read(self.root.join("Cargo.lock")).unwrap_or_default(),
        );
        let mut vars: Vec<(String, String)> =
            std::env::vars().filter(|(k, _)| relevant_env(k)).collect();
        vars.sort();
        for (k, v) in &vars {
            h.field(&format!("env:{k}"), v.as_bytes());
        }
        for tool in compilers() {
            h.field("tool", tool.as_bytes());
        }
        let skip = |rel: &str| {
            rel == "glue.rs"
                || rel == "kat"
                || rel.starts_with("kat/")
                || rel == "target"
                || rel.starts_with("target/")
        };
        for (rel, p) in files(&self.manifest, &skip) {
            h.field(
                &format!("crate:{rel}"),
                &std::fs::read(&p).unwrap_or_default(),
            );
        }
        h.finish()
    }

    /// Absolute paths in a directive replaced by placeholders, so an entry is valid on another
    /// machine with another checkout path.
    fn neutral(&self, line: &str) -> String {
        let mut s = line.replace(&self.shared.display().to_string(), "@SHARED@");
        s = s.replace(&self.root.display().to_string(), "@ROOT@");
        if let Some(name) = s.strip_prefix("cargo:rustc-link-lib=static=") {
            if let Some(stem) = name.strip_suffix(&format!("_{}", self.tag)) {
                s = format!("cargo:rustc-link-lib=static={stem}_@TAG@");
            }
        }
        s
    }

    fn concrete(&self, line: &str) -> String {
        line.replace("@SHARED@", &self.shared.display().to_string())
            .replace("@ROOT@", &self.root.display().to_string())
            .replace("@TAG@", &self.tag)
    }

    /// Full key: the base key plus the contents of every watched path.
    fn full_key(&self, base: &(String, String), watched: &[String]) -> (String, String) {
        let mut h = Dual::new();
        h.field("base-sha256", base.0.as_bytes());
        h.field("base-blake3", base.1.as_bytes());
        for w in watched {
            let p = PathBuf::from(self.concrete(w));
            let p = if p.is_absolute() {
                p
            } else {
                self.manifest.join(p)
            };
            h.field(&format!("watch:{w}"), &[]);
            hash_path(&mut h, &p);
        }
        h.finish()
    }
}

/// Environment the C build reads: cc-rs's tool and flag variables (also the `_<target>` and
/// `TARGET_`/`HOST_` forms), Cargo's target description, our NEXTSSL_* switches, the SDK and
/// toolchain locations and the runner OS. Names that vary per machine without changing the build
/// (HOSTNAME, RUNNER_*, PATH order, ...) are left out on purpose, and so is the runner image version:
/// GitHub rolls several image versions at once with the same toolchain (run 45828577802: every macOS
/// entry missed). The system headers are keyed by `sysroot_identity` instead.
fn relevant_env(k: &str) -> bool {
    const EXACT: &[&str] = &[
        "CC",
        "CXX",
        "AR",
        "RANLIB",
        "CFLAGS",
        "CXXFLAGS",
        "CPPFLAGS",
        "ARFLAGS",
        "TARGET",
        "HOST",
        "OPT_LEVEL",
        "DEBUG",
        "PROFILE",
        "CXXSTDLIB",
        "SDKROOT",
        "INCLUDE",
        "LIB",
        "VCINSTALLDIR",
        "VCToolsVersion",
        "WindowsSdkVersion",
        "MACOSX_DEPLOYMENT_TARGET",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "ImageOS",
    ];
    const PREFIXES: &[&str] = &[
        "CC_",
        "CXX_",
        "AR_",
        "RANLIB_",
        "CFLAGS_",
        "CXXFLAGS_",
        "CPPFLAGS_",
        "ARFLAGS_",
        "CXXSTDLIB_",
        "TARGET_CC",
        "TARGET_CXX",
        "TARGET_AR",
        "TARGET_CFLAGS",
        "TARGET_CXXFLAGS",
        "HOST_CC",
        "HOST_CXX",
        "HOST_AR",
        "HOST_CFLAGS",
        "HOST_CXXFLAGS",
        "CARGO_CFG_",
        "CRATE_CC_",
        "NEXTSSL_",
        "WASI_SDK",
    ];
    k != "NEXTSSL_C_CACHE" && (EXACT.contains(&k) || PREFIXES.iter().any(|p| k.starts_with(p)))
}

/// Identity of every compiler the build script can use: path, size and `--version` output.
fn compilers() -> Vec<String> {
    let mut paths: Vec<(PathBuf, Vec<(std::ffi::OsString, std::ffi::OsString)>)> = Vec::new();
    for cpp in [false, true] {
        let mut b = cc::Build::new();
        b.cargo_metadata(false)
            .cargo_warnings(false)
            .emit_rerun_if_env_changed(false)
            .cpp(cpp);
        if let Ok(t) = b.try_get_compiler() {
            let envs = t
                .get_envs()
                .map(|(k, v)| (k.to_os_string(), v.to_os_string()))
                .collect();
            paths.push((t.path().to_path_buf(), envs));
        }
    }
    if env("CARGO_CFG_TARGET_ENV") == "msvc" {
        // build.rs clang_cl(): NEXTSSL_CLANG_CL, then PATH, then the default install.
        let mut cands = vec![PathBuf::from(env("NEXTSSL_CLANG_CL"))];
        for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
            cands.push(dir.join("clang-cl.exe"));
        }
        cands.push(PathBuf::from(r"C:\Program Files\LLVM\bin\clang-cl.exe"));
        if let Some(p) = cands.into_iter().find(|p| p.is_file()) {
            paths.push((p, Vec::new()));
        }
    }
    let mut ids: Vec<String> = paths
        .into_iter()
        .map(|(p, envs)| {
            let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            let mut cmd = std::process::Command::new(&p);
            cmd.arg("--version");
            for (k, v) in envs {
                cmd.env(k, v);
            }
            let out = cmd
                .output()
                .map(|o| {
                    let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
                    s.push_str(&String::from_utf8_lossy(&o.stderr));
                    s
                })
                .unwrap_or_default();
            format!("{}|{size}|{out}", p.display())
        })
        .collect();
    ids.extend(sysroot_identity());
    ids
}

/// The SDK and C library the compilers build against: the macOS/iOS SDK path and build version, or
/// the glibc version. Empty where neither applies (MSVC is covered by INCLUDE/LIB and the tool).
fn sysroot_identity() -> Vec<String> {
    let run = |cmd: &str, args: &[&str]| {
        std::process::Command::new(cmd)
            .args(args)
            .output()
            .map(|o| {
                format!(
                    "{cmd} {args:?}: {}",
                    String::from_utf8_lossy(&o.stdout).trim()
                )
            })
            .unwrap_or_default()
    };
    match env("CARGO_CFG_TARGET_VENDOR").as_str() {
        "apple" => vec![
            run("xcrun", &["--show-sdk-path"]),
            run("xcrun", &["--show-sdk-build-version"]),
        ],
        _ if env("CARGO_CFG_TARGET_ENV") == "gnu" && env("CARGO_CFG_TARGET_OS") == "linux" => {
            vec![run("getconf", &["GNU_LIBC_VERSION"])]
        }
        _ => Vec::new(),
    }
}

struct Manifest {
    key: (String, String),
    full: (String, String),
    watched: Vec<String>,
    libs: Vec<(String, String, String)>, // (file name with @TAG@, sha256, blake3)
    directives: Vec<String>,
}

fn read_manifest(p: &Path) -> Option<Manifest> {
    let text = std::fs::read_to_string(p).ok()?;
    let mut m = Manifest {
        key: Default::default(),
        full: Default::default(),
        watched: Vec::new(),
        libs: Vec::new(),
        directives: Vec::new(),
    };
    for line in text.lines() {
        let (k, v) = line.split_once(' ')?;
        match k {
            "key-sha256" => m.key.0 = v.to_string(),
            "key-blake3" => m.key.1 = v.to_string(),
            "full-sha256" => m.full.0 = v.to_string(),
            "full-blake3" => m.full.1 = v.to_string(),
            "watch" => m.watched.push(v.to_string()),
            "lib" => {
                let mut it = v.splitn(3, ' ');
                m.libs.push((
                    it.next()?.to_string(),
                    it.next()?.to_string(),
                    it.next()?.to_string(),
                ));
            }
            "directive" => m.directives.push(v.to_string()),
            _ => return None,
        }
    }
    Some(m)
}

fn try_hit(ctx: &Ctx, entry: &Path, base: &(String, String)) -> bool {
    let Some(m) = read_manifest(&entry.join("manifest")) else {
        return false;
    };
    if &m.key != base || ctx.full_key(base, &m.watched) != m.full {
        return false;
    }
    let mut blobs = Vec::new();
    for (i, (name, sha, b3)) in m.libs.iter().enumerate() {
        let Ok(data) = std::fs::read(entry.join(format!("lib{i}"))) else {
            return false;
        };
        if digests(&data) != (sha.clone(), b3.clone()) {
            return false;
        }
        blobs.push((ctx.concrete(name), data));
    }
    if std::fs::create_dir_all(&ctx.shared).is_err() {
        return false;
    }
    for (name, data) in &blobs {
        let dst = ctx.shared.join(name);
        let tmp = ctx.shared.join(format!("{name}.tmp"));
        if std::fs::write(&tmp, data).is_err() || std::fs::rename(&tmp, &dst).is_err() {
            return false;
        }
    }
    for d in &m.directives {
        println!("{}", ctx.concrete(d));
    }
    // Mark the entry as used by this run; tools/ccache_prune.py drops entries no run used.
    if let Ok(f) = std::fs::File::options()
        .append(true)
        .open(entry.join("manifest"))
    {
        let _ = f.set_modified(std::time::SystemTime::now());
    }
    true
}

fn store(ctx: &Ctx, entry: &Path, base: &(String, String)) -> Result<(), String> {
    let recorded = RECORDED.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut watched = Vec::new();
    let mut libs = Vec::new();
    for line in &recorded {
        if let Some(p) = line.strip_prefix("cargo:rerun-if-changed=") {
            watched.push(ctx.neutral(p));
        }
        if let Some(uniq) = line.strip_prefix("cargo:rustc-link-lib=static=") {
            let name = [format!("lib{uniq}.a"), format!("{uniq}.lib")]
                .into_iter()
                .find(|n| ctx.shared.join(n).is_file())
                .ok_or_else(|| {
                    format!(
                        "static library {uniq} not found in {}",
                        ctx.shared.display()
                    )
                })?;
            let data = std::fs::read(ctx.shared.join(&name)).map_err(|e| e.to_string())?;
            libs.push((
                ctx.neutral(&name)
                    .replace(&format!("_{}", ctx.tag), "_@TAG@"),
                data,
            ));
        }
    }
    if libs.is_empty() {
        return Err("the build script published no static library".into());
    }
    let full = ctx.full_key(base, &watched);
    let mut text = String::new();
    let _ = writeln!(text, "key-sha256 {}", base.0);
    let _ = writeln!(text, "key-blake3 {}", base.1);
    let _ = writeln!(text, "full-sha256 {}", full.0);
    let _ = writeln!(text, "full-blake3 {}", full.1);
    for w in &watched {
        let _ = writeln!(text, "watch {w}");
    }
    let parent = entry.parent().ok_or("cache entry has no parent")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let tmp = parent.join(format!(".tmp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    for (i, (name, data)) in libs.iter().enumerate() {
        let (sha, b3) = digests(data);
        let _ = writeln!(text, "lib {name} {sha} {b3}");
        std::fs::write(tmp.join(format!("lib{i}")), data).map_err(|e| e.to_string())?;
    }
    for line in &recorded {
        let _ = writeln!(text, "directive {}", ctx.neutral(line));
    }
    std::fs::write(tmp.join("manifest"), text).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(entry);
    if std::fs::rename(&tmp, entry).is_err() {
        // Another build of the same crate stored the entry first.
        let _ = std::fs::remove_dir_all(&tmp);
    }
    Ok(())
}

/// Runs `build_main` (the build script's own compile-and-link), or replays a cached result whose key
/// matches bit for bit. Without `NEXTSSL_C_CACHE` it is exactly `build_main()`.
pub fn cached(build_main: fn()) {
    let root = match std::env::var("NEXTSSL_C_CACHE") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => {
            build_main();
            return;
        }
    };
    println!("cargo:rerun-if-env-changed=NEXTSSL_C_CACHE");
    let ctx = Ctx::new();
    let base = ctx.base_key();
    let entry = root
        .join(env("TARGET"))
        .join(env("CARGO_PKG_NAME"))
        .join(&base.0);
    if try_hit(&ctx, &entry, &base) {
        return;
    }
    build_main();
    if let Err(e) = store(&ctx, &entry, &base) {
        println!("cargo:warning=nextssl-cbuild: result not cached: {e}");
    }
}
