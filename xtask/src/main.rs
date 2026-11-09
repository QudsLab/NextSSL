//! `cargo xtask gen [--check]`: algos/**/algo.toml -> registry tables, docs/algo.generated.json
//! and the C header. Output is deterministic (algorithms sorted by id).
//! `cargo xtask check-symbols`: symbol-prefix rules (see symbols.rs).
//! `cargo xtask new ...`: scaffold an algorithm folder (see scaffold.rs).

mod composegen;
mod rootgen;
mod scaffold;
mod symbols;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use nextssl_core::Kind;

const TIERS: &[&str] = &[
    "safe",
    "standard",
    "legacy",
    "broken",
    "research",
    "unverified",
];
const STATUSES: &[&str] = &["importing", "active", "deprecated", "revoked"];

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Upstream {
    /// Rust crate upstream.
    #[serde(rename = "crate", default, skip_serializing_if = "Option::is_none")]
    krate: Option<String>,
    /// Exact pin, e.g. "=1.2.3".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    /// Source repository upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit: Option<String>,
    /// Non-git source (an official tarball/zip/single file): download URL, pinned by `sha256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    /// 64 hex digits, sha256 of the file at `url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    license: String,
    /// Files copied verbatim into upstream/.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    files: Vec<String>,
}

/// `default` of a parameter: a number for `u32`/`u64`, one of `values` for `enum`.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
enum ParamDefault {
    Num(u64),
    Text(String),
}

/// One `[params.<name>]` table. Types: `u32`, `u64`, `bytes`, `str` (these need `max`), and
/// `enum` (closed string set `values`, optional `default` that must be one of them).
/// A `required` param has no default; it must be a `str` with a `test_value` so generic tests
/// can instantiate the algorithm.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Param {
    #[serde(rename = "type")]
    ty: String,
    #[serde(default)]
    min: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max: Option<u64>,
    #[serde(default)]
    required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default: Option<ParamDefault>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    test_value: Option<String>,
}

/// One `[sizes]` entry: a fixed byte count (`key = 32`) or a range (`key = { min = 16, max = 32 }`).
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(untagged)]
enum LenToml {
    Fixed(u64),
    Range { min: u64, max: u64 },
}

impl LenToml {
    fn bounds(self) -> (u64, u64) {
        match self {
            LenToml::Fixed(n) => (n, n),
            LenToml::Range { min, max } => (min, max),
        }
    }

    fn rust(self) -> String {
        match self {
            LenToml::Fixed(n) => format!("Len::fixed({n})"),
            LenToml::Range { min, max } => format!("Len::range({min}, {max})"),
        }
    }
}

macro_rules! sizes_toml {
    ($($f:ident),*) => {
        /// `[sizes]` table; field meanings are documented on `nextssl_core::Sizes`.
        #[derive(Debug, Deserialize, Serialize, Clone, Default)]
        #[serde(deny_unknown_fields)]
        struct SizesToml {
            $(#[serde(default, skip_serializing_if = "Option::is_none")] $f: Option<LenToml>,)*
        }

        impl SizesToml {
            fn is_empty(&self) -> bool {
                true $(&& self.$f.is_none())*
            }

            fn fields(&self) -> Vec<(&'static str, Option<LenToml>)> {
                vec![$((stringify!($f), self.$f)),*]
            }
        }
    };
}
sizes_toml!(key, nonce, tag, block, out, salt, pk, sk, ct, ss, sig, seed, coins, ctx, info);

impl SizesToml {
    /// The same sizes as `nextssl_core::Sizes`, so the required-fields rule has one source.
    fn to_core(&self) -> Res<nextssl_core::Sizes> {
        let mut s = nextssl_core::Sizes::NONE;
        for (name, v) in self.fields() {
            let Some(v) = v else { continue };
            let (min, max) = v.bounds();
            if min > max {
                return Err(format!("sizes.{name}: min > max"));
            }
            if max > u64::from(u32::MAX) {
                return Err(format!("sizes.{name}: max exceeds u32"));
            }
            let l = nextssl_core::Len::range(min as usize, max as usize);
            match name {
                "key" => s.key = Some(l),
                "nonce" => s.nonce = Some(l),
                "tag" => s.tag = Some(l),
                "block" => s.block = Some(l),
                "out" => s.out = Some(l),
                "salt" => s.salt = Some(l),
                "pk" => s.pk = Some(l),
                "sk" => s.sk = Some(l),
                "ct" => s.ct = Some(l),
                "ss" => s.ss = Some(l),
                "sig" => s.sig = Some(l),
                "seed" => s.seed = Some(l),
                "coins" => s.coins = Some(l),
                "ctx" => s.ctx = Some(l),
                _ => s.info = Some(l),
            }
        }
        Ok(s)
    }

    fn rust(&self) -> String {
        let parts: Vec<String> = self
            .fields()
            .into_iter()
            .filter_map(|(n, v)| v.map(|v| format!("{n}: Some({})", v.rust())))
            .collect();
        if parts.is_empty() {
            "Sizes::NONE".into()
        } else {
            format!("Sizes {{ {}, ..Sizes::NONE }}", parts.join(", "))
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Kat {
    files: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Algo {
    id: String,
    kind: String,
    category: String,
    family: String,
    #[serde(default)]
    aliases: Vec<String>,
    tier: String,
    status: String,
    #[serde(default)]
    standards: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cose_alg: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    oid: String,
    #[serde(default)]
    fips: bool,
    /// GPL/LGPL/AGPL upstream: only reachable with the `copyleft` cargo feature.
    #[serde(default)]
    copyleft: bool,
    /// Heavy upstream (big dependency tree): the algorithm is an optional dependency of the
    /// registry, enabled by the cargo feature of this name (shared by siblings that use the same
    /// upstream). The default build stays small.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    feature: Option<String>,
    #[serde(default, skip_serializing_if = "SizesToml::is_empty")]
    sizes: SizesToml,
    /// Composition engine, kind `hash`: crate path of the RustCrypto `Digest` type behind this
    /// algorithm (`"sha2::Sha256"`). The slot name is the algorithm id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    /// Like `digest` for a family id with several fixed-output variants: slot name -> type path.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    digests: BTreeMap<String, String>,
    /// Composition engine, kind `blockcipher`: crate path of the RustCrypto block cipher type
    /// (`"aes::Aes256"`). The slot name is the algorithm id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cipher: Option<String>,
    /// Exact pin of the crate that provides the `digest` / `cipher` type when it must differ from
    /// `upstream.version` (sha3 0.12 has no block-level core, so HMAC needs 0.11.x).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    slot_version: Option<String>,
    upstream: Upstream,
    /// `smoke = "skip"` (kinds `zk`, `he`, `threshold` only): the generic registry round trip is
    /// not run because setup is too heavy. `smoke_reason` is then required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    smoke: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    smoke_reason: Option<String>,
    #[serde(default)]
    params: BTreeMap<String, Param>,
    kat: Kat,
    /// Filled in by the loader: `category/family/id`.
    #[serde(skip_deserializing, default)]
    dir: String,
}

type Res<T> = Result<T, String>;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn find_algo_tomls(dir: &Path, out: &mut Vec<PathBuf>) -> Res<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            find_algo_tomls(&p, out)?;
        } else if p.file_name().is_some_and(|n| n == "algo.toml") {
            out.push(p);
        }
    }
    Ok(())
}

fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !s.starts_with('-')
}

fn validate(a: &Algo, dir: &Path) -> Res<()> {
    let id = &a.id;
    let ctx = |m: &str| format!("{id}: {m}");
    if !is_ident(id) {
        return Err(ctx("id must match [a-z0-9][a-z0-9-]*"));
    }
    let Some(kind) = Kind::parse(&a.kind) else {
        let known: Vec<&str> = Kind::ALL.iter().map(|k| k.as_str()).collect();
        return Err(ctx(&format!("unknown kind {} (known: {known:?})", a.kind)));
    };
    composegen::validate_slots(a, kind)?;
    let sizes = a.sizes.to_core().map_err(|e| ctx(&e))?;
    if let Some(missing) = sizes.missing_for(kind) {
        return Err(ctx(&format!(
            "kind {} requires [sizes] {missing} (required: {:?})",
            a.kind,
            kind.required_sizes()
        )));
    }
    if let Some(f) = &a.feature {
        if !is_ident(f) || matches!(f.as_str(), "copyleft" | "default" | "compose-all" | "testing" | "all-heavy")
        {
            return Err(ctx("feature must be a lowercase cargo feature name, not a reserved one"));
        }
    }
    match (a.smoke.as_deref(), a.smoke_reason.as_deref()) {
        (None, None) => {}
        (Some("skip"), Some(r)) if !r.trim().is_empty() => {
            if !matches!(kind, Kind::Zk | Kind::He | Kind::Threshold) {
                return Err(ctx("smoke = \"skip\" is allowed only for zk, he and threshold"));
            }
        }
        _ => {
            return Err(ctx(
                "smoke must be \"skip\" together with a non-empty smoke_reason",
            ))
        }
    }
    if !a.oid.is_empty()
        && !a
            .oid
            .split('.')
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    {
        return Err(ctx("oid must be dotted decimal"));
    }
    if a.upstream.license.contains("GPL") && !a.upstream.license.contains(" OR ") && !a.copyleft {
        return Err(ctx("GPL-family license requires copyleft = true"));
    }
    if !TIERS.contains(&a.tier.as_str()) {
        return Err(ctx(&format!("unknown tier {}", a.tier)));
    }
    if !STATUSES.contains(&a.status.as_str()) {
        return Err(ctx(&format!("unknown status {}", a.status)));
    }
    if a.dir != format!("{}/{}/{}", a.category, a.family, a.id) {
        return Err(ctx(&format!(
            "folder algos/{} must equal category/family/id",
            a.dir
        )));
    }
    for al in &a.aliases {
        if al.is_empty() || al.contains(char::is_whitespace) {
            return Err(ctx("bad alias"));
        }
    }
    // upstream: exactly one of crate or repo
    let u = &a.upstream;
    if u.license.trim().is_empty() {
        return Err(ctx("upstream.license is required"));
    }
    if u.url.is_some() != u.sha256.is_some() {
        return Err(ctx("upstream.url and upstream.sha256 go together"));
    }
    if u.url.is_some() && (u.repo.is_some() || u.commit.is_some() || u.krate.is_some()) {
        return Err(ctx(
            "upstream.url+sha256 replaces repo+commit (and crate); give only one pin form",
        ));
    }
    let git_or_url = u.repo.clone().or_else(|| u.url.clone());
    match (&u.krate, &git_or_url) {
        (Some(c), None) => {
            let v = u.version.as_deref().unwrap_or("");
            if !v.starts_with('=') || v.len() < 2 {
                return Err(ctx("upstream.version must be an exact pin like =1.2.3"));
            }
            let cargo: toml::Table = std::fs::read_to_string(dir.join("Cargo.toml"))
                .map_err(|e| ctx(&format!("Cargo.toml: {e}")))?
                .parse()
                .map_err(|e| ctx(&format!("Cargo.toml: {e}")))?;
            // The dependency may be renamed (`rsa09 = { package = "rsa", version = ".." }`) to keep
            // two incompatible releases of one crate apart; the pin is checked on the package.
            let deps = cargo.get("dependencies").and_then(|d| d.as_table());
            let dep = deps
                .and_then(|d| {
                    d.get(c.as_str()).or_else(|| {
                        d.values().find(|v| {
                            v.get("package").and_then(|p| p.as_str()) == Some(c.as_str())
                        })
                    })
                })
                .ok_or_else(|| ctx(&format!("Cargo.toml does not depend on {c}")))?;
            let ver = match dep {
                toml::Value::String(s) => Some(s.as_str()),
                toml::Value::Table(t) => t.get("version").and_then(|v| v.as_str()),
                _ => None,
            };
            if ver != Some(v) {
                return Err(ctx(&format!(
                    "Cargo.toml pins {c} to {ver:?} but algo.toml says {v}"
                )));
            }
        }
        (None, Some(_)) => {
            if let Some(url) = &u.url {
                if !(url.starts_with("https://") || url.starts_with("http://")) {
                    return Err(ctx("upstream.url must be an http(s) URL"));
                }
                let h = u.sha256.as_deref().unwrap_or("");
                if h.len() != 64 || !h.chars().all(|x| x.is_ascii_hexdigit()) {
                    return Err(ctx("upstream.sha256 must be 64 hex digits"));
                }
            } else {
                let c = u.commit.as_deref().unwrap_or("");
                if c.len() != 40 || !c.chars().all(|x| x.is_ascii_hexdigit()) {
                    return Err(ctx("upstream.commit must be a full 40-hex sha"));
                }
            }
            if u.files.is_empty() {
                return Err(ctx("upstream.files must list the verbatim files"));
            }
            for f in &u.files {
                // A file is listed either flat (`upstream/<basename>`) or by its relative path
                // inside `upstream/` (upstream trees keep their layout, e.g. PQClean's `common/`).
                let base = Path::new(f).file_name().unwrap().to_owned();
                if !dir.join("upstream").join(f).is_file()
                    && !dir.join("upstream").join(&base).is_file()
                {
                    return Err(ctx(&format!("upstream/{} missing", base.to_string_lossy())));
                }
            }
            if !dir.join("upstream/COPYING").is_file()
                && !dir.join("upstream/LICENSE").is_file()
                && !dir.join("upstream/LICENSE.txt").is_file()
            {
                return Err(ctx("upstream license file missing"));
            }
            if !dir.join("build.rs").is_file() {
                return Err(ctx("C upstream requires build.rs"));
            }
        }
        _ => {
            return Err(ctx(
                "upstream needs exactly one of `crate`, `repo`+`commit`, or `url`+`sha256`",
            ))
        }
    }
    // package name
    let cargo: toml::Table = std::fs::read_to_string(dir.join("Cargo.toml"))
        .map_err(|e| ctx(&format!("Cargo.toml: {e}")))?
        .parse()
        .map_err(|e| ctx(&format!("Cargo.toml: {e}")))?;
    let name = cargo
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str());
    if name != Some(format!("nextssl-algo-{id}").as_str()) {
        return Err(ctx(&format!("package name must be nextssl-algo-{id}")));
    }
    if !dir.join("glue.rs").is_file() {
        return Err(ctx("glue.rs missing"));
    }
    if a.kat.files.is_empty() {
        return Err(ctx("at least one KAT file is required"));
    }
    for f in &a.kat.files {
        if !dir.join(f).is_file() {
            return Err(ctx(&format!("KAT file {f} missing")));
        }
    }
    for (n, p) in &a.params {
        validate_param(n, p).map_err(|m| ctx(&format!("param {n}: {m}")))?;
    }
    Ok(())
}

fn validate_param(name: &str, p: &Param) -> Res<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err("name must match [a-z0-9_]+".into());
    }
    if !matches!(p.ty.as_str(), "u32" | "u64" | "bytes" | "str" | "enum") {
        return Err("type must be u32|u64|bytes|str|enum".into());
    }
    if p.required && p.default.is_some() {
        return Err("required and default are exclusive".into());
    }
    if p.test_value.is_some() && !(p.ty == "str" && p.required) {
        return Err("test_value is only for required str params".into());
    }
    if p.required && !(p.ty == "str" && p.test_value.is_some()) {
        return Err("a required param must be type str with a test_value".into());
    }
    if p.ty == "enum" {
        if p.max.is_some() || p.min != 0 {
            return Err("enum takes no min/max".into());
        }
        if p.values.is_empty() {
            return Err("enum needs a non-empty `values` list".into());
        }
        let mut seen = BTreeSet::new();
        for v in &p.values {
            if v.is_empty() || v.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(format!("bad enum value {v:?}"));
            }
            if !seen.insert(v) {
                return Err(format!("duplicate enum value {v:?}"));
            }
        }
        match &p.default {
            None => {}
            Some(ParamDefault::Text(d)) if p.values.contains(d) => {}
            Some(_) => return Err("enum default must be one of `values`".into()),
        }
        return Ok(());
    }
    if !p.values.is_empty() {
        return Err("`values` is only for enum params".into());
    }
    let Some(max) = p.max else {
        return Err("max is required".into());
    };
    if p.min > max {
        return Err("min > max".into());
    }
    match (&p.default, p.ty.as_str()) {
        (None, _) => {}
        (Some(ParamDefault::Num(d)), "u32" | "u64") => {
            if *d < p.min || *d > max {
                return Err("default outside min..=max".into());
            }
        }
        (Some(_), "u32" | "u64") => return Err("numeric default must be a number".into()),
        (Some(_), _) => return Err("default only for numeric and enum params".into()),
    }
    if p.ty == "u32" && max > u64::from(u32::MAX) {
        return Err("max exceeds u32".into());
    }
    if let (Some(tv), "str") = (&p.test_value, p.ty.as_str()) {
        if (tv.len() as u64) < p.min || (tv.len() as u64) > max {
            return Err("test_value length outside min..=max".into());
        }
    }
    Ok(())
}

fn load() -> Res<Vec<Algo>> {
    let algos_dir = root().join("algos");
    let mut files = Vec::new();
    find_algo_tomls(&algos_dir, &mut files)?;
    let mut algos = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        let mut a: Algo = toml::from_str(&text).map_err(|e| format!("{}: {e}", f.display()))?;
        let dir = f.parent().unwrap();
        a.dir = dir
            .strip_prefix(&algos_dir)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        validate(&a, dir).map_err(|e| format!("{}: {e}", f.display()))?;
        algos.push(a);
    }
    algos.sort_by(|x, y| x.id.cmp(&y.id));
    let mut seen = BTreeSet::new();
    for a in &algos {
        for n in std::iter::once(&a.id).chain(a.aliases.iter()) {
            if !seen.insert(n.clone()) {
                return Err(format!("duplicate id/alias {n}"));
            }
        }
    }
    let mut cose = BTreeMap::new();
    for a in &algos {
        if let Some(c) = a.cose_alg {
            if let Some(prev) = cose.insert(c, a.id.clone()) {
                return Err(format!("cose_alg {c} used by both {prev} and {}", a.id));
            }
        }
    }
    Ok(algos)
}

fn crate_name(id: &str) -> String {
    format!("nextssl-algo-{id}")
}

fn lib_ident(id: &str) -> String {
    format!("nextssl_algo_{}", id.replace('-', "_"))
}

/// Rust identifier of an enum variant (`Tier::Safe`, `Kind::PwHash`) from its toml string.
fn variant(kind_or_enum: &str, s: &str) -> String {
    match kind_or_enum {
        "kind" => format!("{:?}", Kind::parse(s).expect("validated kind")),
        _ => {
            let mut c = s.chars();
            c.next().unwrap().to_uppercase().collect::<String>() + c.as_str()
        }
    }
}

fn rust_str_list(v: &[String]) -> String {
    let items: Vec<String> = v.iter().map(|s| format!("{s:?}")).collect();
    format!("&[{}]", items.join(", "))
}

fn gen_registry(algos: &[Algo]) -> String {
    let mut s = String::new();
    s.push_str("// @generated by `cargo xtask gen` from algos/**/algo.toml. DO NOT EDIT.\n\n");
    s.push_str("use crate::{AlgoInfo, Ctor};\n");
    s.push_str("#[allow(unused_imports)]\n");
    s.push_str("use nextssl_core::{Kind, Len, ParamSpec, ParamType, Sizes, Status, Tier};\n\n");
    s.push_str("pub static ALGORITHMS: &[AlgoInfo] = &[\n");
    for a in algos {
        let lib = lib_ident(&a.id);
        let kind = variant("kind", &a.kind);
        if let Some(g) = cfg_gate(a) {
            let _ = writeln!(s, "    #[cfg({g})]");
        }
        let _ = writeln!(s, "    AlgoInfo {{");
        let _ = writeln!(s, "        id: {:?},", a.id);
        let _ = writeln!(s, "        kind: Kind::{kind},");
        let _ = writeln!(s, "        category: {:?},", a.category);
        let _ = writeln!(s, "        family: {:?},", a.family);
        let _ = writeln!(s, "        aliases: {},", rust_str_list(&a.aliases));
        let _ = writeln!(s, "        tier: Tier::{},", variant("", &a.tier));
        let _ = writeln!(s, "        status: Status::{},", variant("", &a.status));
        let _ = writeln!(s, "        standards: {},", rust_str_list(&a.standards));
        let _ = writeln!(s, "        license: {:?},", a.upstream.license);
        let _ = writeln!(s, "        copyleft: {},", a.copyleft);
        // C/C++ upstream (git repo or pinned url) is linked through FFI; a crate is pure Rust.
        let _ = writeln!(
            s,
            "        c_backed: {},",
            a.upstream.repo.is_some() || a.upstream.url.is_some()
        );
        let _ = writeln!(s, "        fips: {},", a.fips);
        let _ = match a.cose_alg {
            Some(n) => writeln!(s, "        cose_alg: Some({n}),"),
            None => writeln!(s, "        cose_alg: None,"),
        };
        let _ = writeln!(s, "        oid: {:?},", a.oid);
        let _ = writeln!(s, "        sizes: {},", a.sizes.rust());
        if a.params.is_empty() {
            let _ = writeln!(s, "        params: &[],");
        } else {
            let _ = writeln!(s, "        params: &[");
            for (n, p) in &a.params {
                let ty = match p.ty.as_str() {
                    "u32" => "U32".to_string(),
                    "u64" => "U64".to_string(),
                    "bytes" => "Bytes".to_string(),
                    "enum" => format!("Enum({})", rust_str_list(&p.values)),
                    _ => "Str".to_string(),
                };
                let def = match &p.default {
                    Some(ParamDefault::Num(d)) => format!("Some({d})"),
                    // enum default: index of the value in `values` (validated to exist)
                    Some(ParamDefault::Text(t)) => {
                        let i = p.values.iter().position(|v| v == t).unwrap_or(0);
                        format!("Some({i})")
                    }
                    None => "None".into(),
                };
                let _ = writeln!(
                    s,
                    "            ParamSpec {{ name: {n:?}, ty: ParamType::{ty}, min: {}, max: {}, required: {}, default: {def} }},",
                    p.min,
                    p.max.unwrap_or(0),
                    p.required
                );
            }
            let _ = writeln!(s, "        ],");
        }
        let tests: Vec<String> = a
            .params
            .iter()
            .filter_map(|(n, p)| p.test_value.as_ref().map(|v| format!("({n:?}, {v:?})")))
            .collect();
        let _ = writeln!(s, "        test_params: &[{}],", tests.join(", "));
        let _ = writeln!(s, "        dir: {:?},", a.dir);
        let _ = writeln!(s, "        kat: {},", rust_str_list(&a.kat.files));
        let _ = match (&a.smoke, &a.smoke_reason) {
            (Some(_), Some(r)) => writeln!(s, "        smoke_skip: Some({r:?}),"),
            _ => writeln!(s, "        smoke_skip: None,"),
        };
        let _ = writeln!(s, "        ctor: Ctor::{kind}({lib}::new),");
        let _ = writeln!(s, "    }},");
    }
    s.push_str("];\n");
    s
}

/// Formats generated Rust with rustfmt so `cargo fmt --check` stays green.
fn rustfmt(src: String) -> Res<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("rustfmt")
        .args(["--edition", "2021"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("rustfmt: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("rustfmt stdin")?
        .write_all(src.as_bytes())
        .map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err("rustfmt failed on generated code".into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"))
}

/// `cfg(..)` predicate that gates an algorithm: `copyleft`, its heavy `feature`, or both.
pub(crate) fn cfg_gate(a: &Algo) -> Option<String> {
    match (a.copyleft, &a.feature) {
        (false, None) => None,
        (true, None) => Some("feature = \"copyleft\"".into()),
        (false, Some(f)) => Some(format!("feature = {f:?}")),
        (true, Some(f)) => Some(format!("all(feature = \"copyleft\", feature = {f:?})")),
    }
}

/// Heavy feature name -> crate names that it enables, sorted.
fn heavy_features(algos: &[Algo]) -> BTreeMap<String, Vec<String>> {
    let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for a in algos {
        if let Some(f) = &a.feature {
            m.entry(f.clone()).or_default().push(crate_name(&a.id));
        }
    }
    m
}

/// The generated `[features]` block of `nextssl-root`: every heavy feature forwards to the
/// registry; `all-heavy` turns them all on.
fn root_feature_block(algos: &[Algo]) -> String {
    let heavy = heavy_features(algos);
    let mut s = String::new();
    for f in heavy.keys() {
        let _ = writeln!(s, "{f} = [\"nextssl-registry/{f}\"]");
    }
    let all: Vec<String> = heavy.keys().map(|f| format!("{f:?}")).collect();
    let _ = writeln!(s, "all-heavy = [{}]", all.join(", "));
    s
}

fn gen_root_cargo(algos: &[Algo]) -> Res<String> {
    let path = root().join("crates/nextssl-root/Cargo.toml");
    let cur = std::fs::read_to_string(&path)
        .map_err(|e| e.to_string())?
        .replace("\r\n", "\n");
    let begin = "# BEGIN GENERATED FEATURES (cargo xtask gen)\n";
    let end = "# END GENERATED FEATURES";
    let b = cur
        .find(begin)
        .ok_or("root Cargo.toml: BEGIN FEATURES marker missing")?;
    let e = cur
        .find(end)
        .ok_or("root Cargo.toml: END FEATURES marker missing")?;
    Ok(format!(
        "{}{}{}",
        &cur[..b + begin.len()],
        root_feature_block(algos),
        &cur[e..]
    ))
}

/// Rewrites the generated blocks of the registry `Cargo.toml` (dependencies and features).
/// Copyleft and heavy algorithms are optional dependencies enabled only by their feature.
fn splice_registry_cargo(cur: &str, algos: &[Algo]) -> Res<String> {
    let cur = cur.replace("\r\n", "\n");
    let mut out = cur.clone();
    let mut deps = String::new();
    let mut feat: Vec<String> = Vec::new();
    for a in algos {
        if a.copyleft || a.feature.is_some() {
            let _ = writeln!(
                deps,
                "{} = {{ path = \"../../algos/{}\", optional = true }}",
                crate_name(&a.id),
                a.dir
            );
            if a.copyleft {
                feat.push(format!("\"dep:{}\"", crate_name(&a.id)));
            }
        } else {
            let _ = writeln!(
                deps,
                "{} = {{ path = \"../../algos/{}\" }}",
                crate_name(&a.id),
                a.dir
            );
        }
    }
    let mut feats = format!("copyleft = [{}]\n", feat.join(", "));
    let heavy = heavy_features(algos);
    for (f, crates) in &heavy {
        let deps: Vec<String> = crates.iter().map(|c| format!("\"dep:{c}\"")).collect();
        let _ = writeln!(feats, "{f} = [{}]", deps.join(", "));
    }
    let all: Vec<String> = heavy.keys().map(|f| format!("{f:?}")).collect();
    let _ = writeln!(feats, "all-heavy = [{}]", all.join(", "));
    for (what, body) in [("DEPENDENCIES", deps), ("FEATURES", feats)] {
        let begin = format!("# BEGIN GENERATED {what} (cargo xtask gen)\n");
        let end = format!("# END GENERATED {what}");
        let b = out
            .find(&begin)
            .ok_or(format!("registry Cargo.toml: BEGIN {what} marker missing"))?;
        let e = out
            .find(&end)
            .ok_or(format!("registry Cargo.toml: END {what} marker missing"))?;
        out = format!("{}{}{}", &out[..b + begin.len()], body, &out[e..]);
    }
    Ok(out)
}

fn gen_registry_cargo(algos: &[Algo]) -> Res<String> {
    let path = root().join("crates/nextssl-registry/Cargo.toml");
    let cur = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    splice_registry_cargo(&cur, algos)
}

#[derive(Serialize)]
struct Doc<'a> {
    generated_by: &'static str,
    algorithms: &'a [Algo],
}

fn gen_json(algos: &[Algo]) -> String {
    let doc = Doc {
        generated_by: "cargo xtask gen",
        algorithms: algos,
    };
    let mut s = serde_json::to_string_pretty(&doc).expect("json");
    s.push('\n');
    s
}

fn gen_header() -> Res<String> {
    let dir = root().join("crates/nextssl-ffi");
    let cfg = cbindgen::Config::from_file(dir.join("cbindgen.toml"))?;
    let bindings = cbindgen::Builder::new()
        .with_crate(&dir)
        .with_config(cfg)
        .generate()
        .map_err(|e| format!("cbindgen: {e}"))?;
    let mut buf = Vec::new();
    bindings.write(&mut buf);
    let s = String::from_utf8(buf).map_err(|e| e.to_string())?;
    Ok(s.replace("\r\n", "\n"))
}

fn run_gen(check: bool) -> Res<()> {
    let algos = load()?;
    let r = root();
    let root_lib = std::fs::read_to_string(r.join("crates/nextssl-root/src/lib.rs"))
        .map_err(|e| format!("nextssl-root lib.rs: {e}"))?
        .replace("\r\n", "\n");
    let outputs: Vec<(PathBuf, String)> = vec![
        (
            r.join("crates/nextssl-registry/src/generated.rs"),
            rustfmt(gen_registry(&algos))?,
        ),
        (
            r.join("crates/nextssl-registry/Cargo.toml"),
            gen_registry_cargo(&algos)?,
        ),
        (
            r.join("crates/nextssl-root/Cargo.toml"),
            gen_root_cargo(&algos)?,
        ),
        (
            r.join("crates/nextssl-root/src/generated.rs"),
            rustfmt(rootgen::gen_root(&algos, &root_lib)?)?,
        ),
        (
            r.join("crates/nextssl-compose/src/generated.rs"),
            rustfmt(composegen::gen_compose(&algos)?)?,
        ),
        (
            r.join("crates/nextssl-compose/Cargo.toml"),
            composegen::gen_compose_cargo(&algos)?,
        ),
        (r.join("docs/algo.generated.json"), gen_json(&algos)),
        (
            r.join("crates/nextssl-ffi/include/nextssl.h"),
            gen_header()?,
        ),
    ];
    let mut stale = Vec::new();
    for (p, content) in &outputs {
        let cur = std::fs::read_to_string(p)
            .unwrap_or_default()
            .replace("\r\n", "\n");
        if &cur != content {
            if check {
                stale.push(p.display().to_string());
            } else {
                if let Some(d) = p.parent() {
                    std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
                }
                std::fs::write(p, content).map_err(|e| format!("{}: {e}", p.display()))?;
                println!("wrote {}", p.strip_prefix(&r).unwrap_or(p).display());
            }
        }
    }
    if !stale.is_empty() {
        return Err(format!(
            "generated files are stale (run `cargo xtask gen`): {stale:?}"
        ));
    }
    println!("{} algorithms ok", algos.len());
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let res = match args.first().map(String::as_str) {
        Some("gen") => run_gen(args.iter().any(|a| a == "--check")),
        Some("check-symbols") => symbols::run(),
        Some("new") => scaffold::run(&args[1..]),
        _ => Err(
            "usage: cargo xtask gen [--check] | check-symbols | new <category>/<family>/<id> ..."
                .to_string(),
        ),
    };
    if let Err(e) = res {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn algo(extra: &str, kind: &str) -> Algo {
        let (top, tables) = extra
            .split_once("[sizes]")
            .map_or((extra, String::new()), |(t, s)| (t, format!("[sizes]{s}")));
        let text = format!(
            "id = \"x\"\nkind = \"{kind}\"\ncategory = \"c\"\nfamily = \"f\"\ntier = \"safe\"\nstatus = \"active\"\n\
             cose_alg = -7\noid = \"1.2.3\"\n{top}\nupstream = {{ crate = \"x\", version = \"=1.0.0\", license = \"MIT\" }}\n\
             [kat]\nfiles = [\"kat/a.json\"]\n{tables}\n"
        );
        let mut a: Algo = toml::from_str(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        a.dir = "c/f/x".into();
        a
    }

    #[test]
    fn copyleft_algorithms_are_feature_gated_in_code_and_cargo() {
        let mut free = algo("", "pow");
        free.id = "free".into();
        let mut gpl = algo("copyleft = true", "pow");
        gpl.id = "gpl-thing".into();
        gpl.dir = "c/f/gpl-thing".into();
        let code = gen_registry(&[free, gpl]);
        assert!(code
            .contains("#[cfg(feature = \"copyleft\")]\n    AlgoInfo {\n        id: \"gpl-thing\""));
        assert_eq!(
            code.matches("#[cfg(feature").count(),
            1,
            "only the copyleft entry is gated"
        );
        assert!(code.contains("cose_alg: Some(-7)") && code.contains("oid: \"1.2.3\""));
        assert!(code.contains("Ctor::Pow(nextssl_algo_gpl_thing::new)"));

        let mut free = algo("", "pow");
        free.id = "free".into();
        let mut gpl = algo("copyleft = true", "pow");
        gpl.id = "gpl-thing".into();
        gpl.dir = "c/f/gpl-thing".into();
        let cur = "[dependencies]\n# BEGIN GENERATED DEPENDENCIES (cargo xtask gen)\n# END GENERATED DEPENDENCIES\n[features]\n# BEGIN GENERATED FEATURES (cargo xtask gen)\n# END GENERATED FEATURES\n";
        let out = splice_registry_cargo(cur, &[free, gpl]).unwrap();
        assert!(out.contains("nextssl-algo-free = { path = \"../../algos/c/f/x\" }"));
        assert!(out.contains(
            "nextssl-algo-gpl-thing = { path = \"../../algos/c/f/gpl-thing\", optional = true }"
        ));
        assert!(out.contains("copyleft = [\"dep:nextssl-algo-gpl-thing\"]"));
        // regenerating from a different algorithm set replaces the blocks
        assert!(!splice_registry_cargo(&out, &[])
            .unwrap()
            .contains("gpl-thing"));
    }

    #[test]
    fn sizes_are_required_per_kind_and_rendered() {
        let a = algo("", "aead");
        let core = a.sizes.to_core().unwrap();
        assert_eq!(core.missing_for(Kind::Aead), Some("key"));
        let a = algo(
            "[sizes]\nkey = 32\nnonce = { min = 8, max = 12 }\ntag = 16",
            "aead",
        );
        assert!(a.sizes.to_core().unwrap().missing_for(Kind::Aead).is_none());
        assert_eq!(
            a.sizes.rust(),
            "Sizes { key: Some(Len::fixed(32)), nonce: Some(Len::range(8, 12)), tag: Some(Len::fixed(16)), ..Sizes::NONE }"
        );
        assert_eq!(algo("", "pow").sizes.rust(), "Sizes::NONE");
        let bad = algo("[sizes]\nkey = { min = 9, max = 3 }", "mac");
        assert!(bad.sizes.to_core().unwrap_err().contains("min > max"));
    }

    #[test]
    fn every_kind_generates_a_ctor_variant_that_exists() {
        for k in Kind::ALL {
            let mut a = algo("", k.as_str());
            a.id = "x".into();
            let code = gen_registry(&[a]);
            assert!(code.contains(&format!("kind: Kind::{k:?},")), "{k:?}");
            assert!(code.contains(&format!("ctor: Ctor::{k:?}(")), "{k:?}");
        }
    }
}

#[cfg(test)]
mod param_tests {
    use super::*;

    fn param(text: &str) -> Param {
        toml::from_str(text).unwrap_or_else(|e| panic!("{e}\n{text}"))
    }

    #[test]
    fn existing_numeric_params_still_validate() {
        let p = param("type = \"u32\"\nmin = 1\nmax = 10\ndefault = 3\n");
        assert!(validate_param("t", &p).is_ok());
        let p = param("type = \"u32\"\nmin = 1\nmax = 10\ndefault = 11\n");
        assert!(validate_param("t", &p).is_err());
        let p = param("type = \"str\"\nmin = 0\nmax = 8\n");
        assert!(validate_param("custom", &p).is_ok());
    }

    #[test]
    fn enum_rules() {
        let ok = param("type = \"enum\"\nvalues = [\"a\", \"b\"]\ndefault = \"b\"\n");
        assert!(validate_param("hash", &ok).is_ok());
        for bad in [
            "type = \"enum\"\nvalues = []\n",
            "type = \"enum\"\nvalues = [\"a\", \"a\"]\n",
            "type = \"enum\"\nvalues = [\"a\"]\ndefault = \"z\"\n",
            "type = \"enum\"\nvalues = [\"a\"]\ndefault = 0\n",
            "type = \"enum\"\nvalues = [\"a\"]\nmax = 3\n",
            "type = \"u32\"\nmin = 0\nmax = 3\nvalues = [\"a\"]\n",
        ] {
            assert!(validate_param("hash", &param(bad)).is_err(), "{bad}");
        }
        // generated spec: enum with default index
        let mut a = Algo::__test_default();
        a.params.insert("hash".into(), ok);
        let code = gen_registry(&[a]);
        assert!(
            code.contains("ty: ParamType::Enum(&[\"a\", \"b\"])"),
            "{code}"
        );
        assert!(code.contains("default: Some(1)"));
    }

    #[test]
    fn required_str_needs_test_value() {
        let ok = param("type = \"str\"\nmin = 1\nmax = 8\nrequired = true\ntest_value = \"ab\"\n");
        assert!(validate_param("hrp", &ok).is_ok());
        let no_tv = param("type = \"str\"\nmin = 1\nmax = 8\nrequired = true\n");
        assert!(validate_param("hrp", &no_tv).is_err());
        let long =
            param("type = \"str\"\nmin = 1\nmax = 2\nrequired = true\ntest_value = \"abc\"\n");
        assert!(validate_param("hrp", &long).is_err());
        let num = param("type = \"u32\"\nmin = 1\nmax = 2\nrequired = true\n");
        assert!(validate_param("n", &num).is_err());
        let mut a = Algo::__test_default();
        a.params.insert("hrp".into(), ok);
        assert!(gen_registry(&[a]).contains("test_params: &[(\"hrp\", \"ab\")]"));
    }
}

#[cfg(test)]
impl Algo {
    fn __test_default() -> Algo {
        let text = "id = \"x\"\nkind = \"encoding\"\ncategory = \"c\"\nfamily = \"f\"\ntier = \"safe\"\nstatus = \"active\"\n\
                    upstream = { crate = \"x\", version = \"=1.0.0\", license = \"MIT\" }\n[kat]\nfiles = [\"kat/a.json\"]\n";
        let mut a: Algo = toml::from_str(text).unwrap();
        a.dir = "c/f/x".into();
        a
    }
}
