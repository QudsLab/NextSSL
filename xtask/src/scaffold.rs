//! `cargo xtask new <category>/<family>/<id> --kind <kind>
//!  (--upstream-crate <name>=<ver> | --upstream-c <repo-url>@<40-hex-commit>) [--license <spdx>]`
//!
//! Creates the folder skeleton for one algorithm. It never touches the network: the importer
//! (human or agent) copies the upstream files and KATs afterwards. Until then `cargo xtask gen`
//! refuses the folder (no KAT file, no upstream files), and the glue stub returns
//! `Error::Unimplemented` instead of pretending to work.

use crate::{is_ident, Res};
use nextssl_core::Kind;
use std::path::{Path, PathBuf};

const USAGE: &str = "usage: cargo xtask new <category>/<family>/<id> --kind <kind> \
(--upstream-crate <name>=<ver> | --upstream-c <repo-url>@<40-hex-commit>) [--license <spdx>]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    /// Rust crate pinned exactly.
    Crate { name: String, version: String },
    /// C repository pinned to a commit.
    C { repo: String, commit: String },
}

#[derive(Debug, Clone)]
pub struct Spec {
    pub category: String,
    pub family: String,
    pub id: String,
    pub kind: String,
    pub upstream: Upstream,
    pub license: String,
}

pub fn parse_path(s: &str) -> Res<(String, String, String)> {
    let parts: Vec<&str> = s.split('/').collect();
    let [c, f, i] = parts.as_slice() else {
        return Err(format!("`{s}` must be <category>/<family>/<id>"));
    };
    for (what, v) in [("category", c), ("family", f), ("id", i)] {
        if !is_ident(v) {
            return Err(format!("{what} `{v}` must match [a-z0-9][a-z0-9-]*"));
        }
    }
    Ok((c.to_string(), f.to_string(), i.to_string()))
}

fn parse_crate(s: &str) -> Res<Upstream> {
    let (name, ver) = s
        .split_once('=')
        .ok_or_else(|| format!("--upstream-crate `{s}` must be <name>=<version>"))?;
    let ver = ver.strip_prefix('=').unwrap_or(ver);
    let name_ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    let core = ver.split(['-', '+']).next().unwrap_or("");
    let nums: Vec<&str> = core.split('.').collect();
    let ver_ok = nums.len() == 3
        && nums
            .iter()
            .all(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
        && ver
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-+".contains(c));
    if !name_ok || !ver_ok {
        return Err(format!(
            "--upstream-crate `{s}`: need a crate name and an exact x.y.z version"
        ));
    }
    Ok(Upstream::Crate {
        name: name.to_string(),
        version: format!("={ver}"),
    })
}

fn parse_c(s: &str) -> Res<Upstream> {
    let (repo, commit) = s
        .rsplit_once('@')
        .ok_or_else(|| format!("--upstream-c `{s}` must be <repo-url>@<40-hex-commit>"))?;
    if !(repo.starts_with("https://") || repo.starts_with("http://"))
        || repo
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\\')
    {
        return Err(format!("--upstream-c repo `{repo}` must be an http(s) URL"));
    }
    if commit.len() != 40 || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("--upstream-c commit must be a full 40-hex sha (no branches or tags)".into());
    }
    Ok(Upstream::C {
        repo: repo.to_string(),
        commit: commit.to_ascii_lowercase(),
    })
}

pub fn parse_args(args: &[String]) -> Res<Spec> {
    let mut path = None;
    let (mut kind, mut krate, mut c, mut license) = (None, None, None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = |flag: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))
        };
        match a.as_str() {
            "--kind" => kind = Some(val("--kind")?),
            "--upstream-crate" => krate = Some(val("--upstream-crate")?),
            "--upstream-c" => c = Some(val("--upstream-c")?),
            "--license" => license = Some(val("--license")?),
            s if s.starts_with("--") => return Err(format!("unknown flag {s}\n{USAGE}")),
            s if path.is_none() => path = Some(s.to_string()),
            s => return Err(format!("unexpected argument {s}\n{USAGE}")),
        }
    }
    let path = path.ok_or_else(|| USAGE.to_string())?;
    let (category, family, id) = parse_path(&path)?;
    let kind = kind.ok_or_else(|| format!("--kind is required\n{USAGE}"))?;
    if Kind::parse(&kind).is_none() {
        let known: Vec<&str> = Kind::ALL.iter().map(|k| k.as_str()).collect();
        return Err(format!("--kind {kind}: must be one of {known:?}"));
    }
    let upstream = match (krate, c) {
        (Some(k), None) => parse_crate(&k)?,
        (None, Some(c)) => parse_c(&c)?,
        _ => {
            return Err(format!(
                "give exactly one of --upstream-crate or --upstream-c\n{USAGE}"
            ))
        }
    };
    let license = license.unwrap_or_else(|| "NOASSERTION".to_string());
    if license.trim().is_empty()
        || license
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_control())
    {
        return Err("--license must be an SPDX expression".into());
    }
    Ok(Spec {
        category,
        family,
        id,
        kind,
        upstream,
        license,
    })
}

fn algo_toml(s: &Spec) -> String {
    let up = match &s.upstream {
        Upstream::Crate { name, version } => format!(
            "{{ crate = {name:?}, version = {version:?}, license = {:?} }}",
            s.license
        ),
        Upstream::C { repo, commit } => format!(
            "{{ repo = {repo:?}, commit = {commit:?}, license = {:?}, files = [] }}",
            s.license
        ),
    };
    let req = Kind::parse(&s.kind).expect("validated").required_sizes();
    let sizes = if req.is_empty() {
        String::new()
    } else {
        let lines: String = req.iter().map(|f| format!("# {f} = 0\n")).collect();
        format!(
            "\n# Fill in: a number (fixed) or {{ min = .., max = .. }}. See crates/nextssl-core/API.md.\n[sizes]\n{lines}"
        )
    };
    format!(
        "# Scaffolded by `cargo xtask new`. Not importable until the steps in README.md are done.\n\
         id        = {:?}\n\
         kind      = {:?}\n\
         category  = {:?}\n\
         family    = {:?}\n\
         aliases   = []\n\
         # `research` keeps it off the safe API until the owner classifies the tier.\n\
         tier      = \"research\"\n\
         status    = \"importing\"\n\
         standards = []\n\
         fips      = false\n\
         copyleft  = false\n\
         upstream  = {up}\n\
         \n\
         [kat]\n\
         files = []\n{sizes}",
        s.id, s.kind, s.category, s.family
    )
}

fn cargo_toml(s: &Spec) -> String {
    let mut t = format!(
        "[package]\n\
         name = \"nextssl-algo-{}\"\n\
         version.workspace = true\n\
         edition.workspace = true\n\
         license.workspace = true\n\
         rust-version.workspace = true\n\
         publish.workspace = true\n",
        s.id
    );
    if matches!(s.upstream, Upstream::C { .. }) {
        t.push_str("build = \"build.rs\"\n");
    }
    t.push_str("\n[lib]\npath = \"glue.rs\"\n\n[dependencies]\nnextssl-core.workspace = true\n");
    match &s.upstream {
        Upstream::Crate { name, version } => {
            t.push_str(&format!(
                "{name} = {{ version = {version:?}, default-features = false }}\n\n[lints]\nworkspace = true\n"
            ));
        }
        Upstream::C { .. } => {
            t.push_str(
                "zeroize.workspace = true\n\n[build-dependencies]\ncc = \"1\"\n\n\
                 # Per-algo C wrapper: the only place besides nextssl-ffi allowed to use unsafe.\n\
                 [lints.rust]\nunsafe_code = \"deny\"\n\n[lints.clippy]\nall = { level = \"warn\", priority = -1 }\n",
            );
        }
    }
    t
}

/// (imports, method stubs) for one kind; the trait name is `Kind::trait_name`. Signatures must
/// match `nextssl_core::traits`; the scaffold test compiles every kind to keep them in sync.
fn stub_parts(kind: Kind) -> (&'static str, &'static str) {
    match kind {
        Kind::Hash => (
            "Error, Hash, Params, Result",
            r#"    fn output_len(&self) -> usize {
        0 // TODO: digest length
    }

    fn digest(&self, _data: &[u8], _out: &mut [u8]) -> Result<()> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Xof => (
            "Error, Params, Result, Xof",
            r#"    fn squeeze(&self, _data: &[u8], _out: &mut [u8]) -> Result<()> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Checksum => (
            "Checksum, Error, Params, Result, Sizes",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: out
    }

    fn checksum(&self, _data: &[u8], _out: &mut [u8]) -> Result<()> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Encoding => (
            "Encoding, Error, Params, Result",
            r#"    fn encode(&self, _data: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Unimplemented)
    }

    fn decode(&self, _text: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Mac => (
            "Error, Mac, Params, Result, Sizes, SymmetricKey",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: key, tag
    }

    fn tag(&self, _key: &SymmetricKey, _data: &[u8], _out: &mut [u8]) -> Result<()> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Kdf => (
            "Error, Kdf, Params, Result, Sizes, SymmetricKey",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: out
    }

    fn derive(
        &self,
        _ikm: &SymmetricKey,
        _salt: &[u8],
        _info: &[u8],
        _out: &mut [u8],
    ) -> Result<()> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::PwHash => (
            "Error, Params, PwHash, Result, Sizes",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: salt, out
    }

    fn hash(&self, _password: &[u8], _salt: &[u8]) -> Result<String> {
        Err(Error::Unimplemented)
    }

    fn verify(&self, _password: &[u8], _phc: &str) -> Result<bool> {
        Err(Error::Unimplemented)
    }

    fn derive(&self, _password: &[u8], _salt: &[u8], _out: &mut [u8]) -> Result<()> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Aead => (
            "Aead, Error, Params, Result, Sizes, SymmetricKey, Zeroizing",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: key, nonce, tag
    }

    fn seal(
        &self,
        _key: &SymmetricKey,
        _nonce: &[u8],
        _aad: &[u8],
        _pt: &[u8],
    ) -> Result<Vec<u8>> {
        Err(Error::Unimplemented)
    }

    fn open(
        &self,
        _key: &SymmetricKey,
        _nonce: &[u8],
        _aad: &[u8],
        _ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::BlockCipher => (
            "BlockCipher, Error, KeyedBlockCipher, Params, Result, Sizes, SymmetricKey",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: key, block
    }

    fn keyed(&self, _key: &SymmetricKey) -> Result<Box<dyn KeyedBlockCipher>> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::StreamCipher => (
            "Error, Params, Result, Sizes, StreamCipher, SymmetricKey",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: key, nonce
    }

    fn apply_keystream(
        &self,
        _key: &SymmetricKey,
        _nonce: &[u8],
        _data: &mut [u8],
    ) -> Result<()> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::BlockMode => (
            "BlockMode, Error, Params, Result, Sizes, SymmetricKey, Zeroizing",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: key, nonce, block
    }

    fn encrypt(&self, _key: &SymmetricKey, _nonce: &[u8], _pt: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Unimplemented)
    }

    fn decrypt(
        &self,
        _key: &SymmetricKey,
        _nonce: &[u8],
        _ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Mode => (
            "BlockCipher, Error, Mode, Params, Result, Sizes, SymmetricKey, Zeroizing",
            r#"    fn sizes(&self, _cipher: &dyn BlockCipher) -> Result<Sizes> {
        Err(Error::Unimplemented)
    }

    fn encrypt(
        &self,
        _cipher: &dyn BlockCipher,
        _key: &SymmetricKey,
        _iv: &[u8],
        _pt: &[u8],
    ) -> Result<Vec<u8>> {
        Err(Error::Unimplemented)
    }

    fn decrypt(
        &self,
        _cipher: &dyn BlockCipher,
        _key: &SymmetricKey,
        _iv: &[u8],
        _ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Kem => (
            "Ciphertext, Error, Kem, Params, PrivateKey, PublicKey, Result, Seed, SharedSecret, Sizes",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: pk, sk, ct, ss, seed, coins
    }

    fn keygen_from_seed(&self, _seed: &Seed) -> Result<(PublicKey, PrivateKey)> {
        Err(Error::Unimplemented)
    }

    fn encaps_from_coins(
        &self,
        _pk: &PublicKey,
        _coins: &Seed,
    ) -> Result<(Ciphertext, SharedSecret)> {
        Err(Error::Unimplemented)
    }

    fn decaps(&self, _sk: &PrivateKey, _ct: &Ciphertext) -> Result<SharedSecret> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Kex => (
            "Error, Kex, Params, PrivateKey, PublicKey, Result, Seed, SharedSecret, Sizes",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: pk, sk, ss, seed
    }

    fn keypair_from_seed(&self, _seed: &Seed) -> Result<(PublicKey, PrivateKey)> {
        Err(Error::Unimplemented)
    }

    fn agree(&self, _sk: &PrivateKey, _peer_pk: &PublicKey) -> Result<SharedSecret> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Sign => (
            "EntropySource, Error, Params, PrivateKey, PublicKey, Result, Seed, Sign, Signature, Sizes",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: pk, sk, sig, seed, ctx
    }

    fn keygen_from_seed(&self, _seed: &Seed) -> Result<(PublicKey, PrivateKey)> {
        Err(Error::Unimplemented)
    }

    fn sign(
        &self,
        _sk: &PrivateKey,
        _msg: &[u8],
        _ctx: &[u8],
        _rng: &mut dyn EntropySource,
    ) -> Result<Signature> {
        Err(Error::Unimplemented)
    }

    fn verify(
        &self,
        _pk: &PublicKey,
        _msg: &[u8],
        _ctx: &[u8],
        _sig: &Signature,
    ) -> Result<bool> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Rng => (
            "EntropySource, Error, Params, Result",
            r#"    fn fill(&mut self, _out: &mut [u8]) -> Result<()> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Drbg => (
            "Drbg, Error, Params, Result, Sizes",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: seed (entropy input length)
    }

    fn security_strength(&self) -> usize {
        0 // TODO: bits
    }

    fn max_request_len(&self) -> usize {
        0 // TODO: bytes per generate call
    }

    fn instantiate(&mut self, _entropy: &[u8], _personalization: &[u8]) -> Result<()> {
        Err(Error::Unimplemented)
    }

    fn reseed(&mut self, _entropy: &[u8], _additional: &[u8]) -> Result<()> {
        Err(Error::Unimplemented)
    }

    fn generate(&mut self, _additional: &[u8], _out: &mut [u8]) -> Result<()> {
        Err(Error::Unimplemented)
    }

    fn uninstantiate(&mut self) {}
"#,
        ),
        Kind::Pow => ("Error, Params, Pow, Result", ""),
        Kind::Zk => (
            "EntropySource, Error, Params, Result, Zk",
            r#"    fn setup(&self, _params: &[u8], _rng: &mut dyn EntropySource) -> Result<Vec<u8>> {
        Err(Error::Unimplemented)
    }

    fn prove(
        &self,
        _setup: &[u8],
        _statement: &[u8],
        _witness: &[u8],
        _rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        Err(Error::Unimplemented)
    }

    fn verify(&self, _setup: &[u8], _statement: &[u8], _proof: &[u8]) -> Result<bool> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Threshold => (
            "Error, Params, Result, Threshold",
            r#"    fn max_parties(&self) -> usize {
        0 // TODO: largest n
    }
"#,
        ),
        Kind::Prng => (
            "Error, Params, Prng, Result, Sizes",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: seed and out ranges
    }

    fn generate(&self, _seed: &[u8], _out: &mut [u8]) -> Result<()> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Vdf => (
            "Error, Params, Result, Vdf",
            r#"    fn max_t(&self) -> u64 {
        0 // TODO: the max_t cap
    }

    fn eval(&self, _challenge: &[u8], _t: u64) -> Result<(Vec<u8>, Vec<u8>)> {
        Err(Error::Unimplemented)
    }

    fn verify(&self, _challenge: &[u8], _t: u64, _output: &[u8], _proof: &[u8]) -> Result<bool> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Pke => (
            "EntropySource, Error, Params, Pke, PrivateKey, PublicKey, Result, Sizes, Zeroizing",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: pk, sk, ct, out, ctx
    }

    fn encrypt(
        &self,
        _pk: &PublicKey,
        _pt: &[u8],
        _label: &[u8],
        _rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        Err(Error::Unimplemented)
    }

    fn decrypt(
        &self,
        _sk: &PrivateKey,
        _ct: &[u8],
        _label: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::Pake => (
            "EntropySource, Error, Pake, PakeRole, PakeState, Params, Result, Sizes",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: key (password length), ss
    }

    fn start(
        &self,
        _role: PakeRole,
        _password: &[u8],
        _context: &[u8],
        _rng: &mut dyn EntropySource,
    ) -> Result<(Box<dyn PakeState>, Vec<u8>)> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::StatefulSign => (
            "Error, Params, PublicKey, Result, Signature, Sizes, StatefulKey, StatefulSign",
            r#"    fn sizes(&self) -> Sizes {
        Sizes::NONE // TODO: pk, sk, sig, seed
    }

    fn max_signatures(&self) -> u64 {
        0 // TODO
    }

    fn remaining(&self, _key: &StatefulKey) -> Result<u64> {
        Err(Error::Unimplemented)
    }

    fn sign(
        &self,
        _key: &mut StatefulKey,
        _msg: &[u8],
        _persist: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Signature> {
        Err(Error::Unimplemented)
    }

    fn verify(&self, _pk: &PublicKey, _msg: &[u8], _sig: &Signature) -> Result<bool> {
        Err(Error::Unimplemented)
    }
"#,
        ),
        Kind::He => (
            "EntropySource, Error, He, HeKeys, HeOp, Params, PrivateKey, PublicKey, Result, Zeroizing",
            r#"    fn ops(&self) -> &'static [HeOp] {
        &[]
    }

    fn keygen(&self, _params: &[u8], _rng: &mut dyn EntropySource) -> Result<HeKeys> {
        Err(Error::Unimplemented)
    }

    fn encrypt(
        &self,
        _public: &PublicKey,
        _pt: &[u8],
        _rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        Err(Error::Unimplemented)
    }

    fn decrypt(&self, _secret: &PrivateKey, _ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Err(Error::Unimplemented)
    }

    fn eval(&self, _op: HeOp, _cts: &[&[u8]], _evk: &PublicKey) -> Result<Vec<u8>> {
        Err(Error::Unimplemented)
    }
"#,
        ),
    }
}

/// Trait implemented by algorithms of `kind` (`Kind::Rng` is `EntropySource`).
fn trait_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Rng => "EntropySource",
        Kind::Hash => "Hash",
        Kind::Xof => "Xof",
        Kind::Mac => "Mac",
        Kind::Kdf => "Kdf",
        Kind::PwHash => "PwHash",
        Kind::Aead => "Aead",
        Kind::BlockCipher => "BlockCipher",
        Kind::StreamCipher => "StreamCipher",
        Kind::Mode => "Mode",
        Kind::BlockMode => "BlockMode",
        Kind::Kem => "Kem",
        Kind::Kex => "Kex",
        Kind::Sign => "Sign",
        Kind::Drbg => "Drbg",
        Kind::Encoding => "Encoding",
        Kind::Checksum => "Checksum",
        Kind::Pow => "Pow",
        Kind::Zk => "Zk",
        Kind::Threshold => "Threshold",
        Kind::Vdf => "Vdf",
        Kind::Prng => "Prng",
        Kind::Pke => "Pke",
        Kind::Pake => "Pake",
        Kind::StatefulSign => "StatefulSign",
        Kind::He => "He",
    }
}

fn glue_rs(s: &Spec) -> String {
    let kind = Kind::parse(&s.kind).expect("kind validated by parse_args");
    let (imports, methods) = stub_parts(kind);
    let tr = trait_name(kind);
    let body = if methods.is_empty() {
        String::new()
    } else {
        format!("\n{methods}")
    };
    format!(
        "//! Adapter stub for `{id}` ({kind}). Not implemented: the upstream has not been imported yet.\n\
         //! Replace `Stub` with a real adapter that validates every length and parameter, and fill in\n\
         //! `sizes()` so it matches `[sizes]` in algo.toml. See crates/nextssl-core/API.md.\n\n\
         use nextssl_core::{{{imports}}};\n\n\
         #[allow(dead_code)]\n\
         struct Stub;\n\n\
         impl {tr} for Stub {{{body}}}\n\n\
         /// Registry constructor.\n\
         pub fn new(_params: &Params) -> Result<Box<dyn {tr}>> {{\n    Err(Error::Unimplemented)\n}}\n",
        id = s.id,
        kind = s.kind
    )
}

fn build_rs(s: &Spec) -> String {
    let prefix = format!("nextssl__{}__", s.id.replace('-', "_"));
    format!(
        "//! TODO(import): compile the verbatim C files from `upstream/` with `cc`.\n\
         //! Every exported upstream symbol must be renamed with a `define()` to the prefix\n\
         //! `{prefix}` (see algos/hash/blake2/blake2b-512/build.rs). `cargo xtask check-symbols`\n\
         //! fails on anything else. Honour NEXTSSL_C_SANITIZE=1 like the blake2b build.rs.\n\n\
         fn main() {{\n    println!(\"cargo:rerun-if-changed=build.rs\");\n}}\n"
    )
}

fn readme(s: &Spec) -> String {
    let src = match &s.upstream {
        Upstream::Crate { name, version } => format!("Rust crate `{name}` {version}"),
        Upstream::C { repo, commit } => format!("C repository {repo} at commit {commit}"),
    };
    let mut steps = vec![
        "Confirm the upstream license and put the real SPDX id in `algo.toml` (`upstream.license`)."
            .to_string(),
        "Set `tier`, `standards`, `aliases`, `params` and the `[sizes]` the kind requires in `algo.toml` (owner decides the tier)."
            .to_string(),
    ];
    match &s.upstream {
        Upstream::Crate { .. } => {
            steps.push("Write the adapter in `glue.rs` using the pinned crate (replace the `Error::Unimplemented` stub).".into());
        }
        Upstream::C { .. } => {
            steps.push("Copy the upstream C files verbatim into `upstream/` with its LICENSE/COPYING; list them in `upstream.files`.".into());
            steps.push("Write `build.rs` (symbol prefix defines) and the `glue.rs` adapter with `// SAFETY:` notes.".into());
        }
    }
    steps.push("Add KAT vectors under `kat/` and list them in `[kat] files`.".into());
    steps.push("Run `cargo xtask gen`, then the Docker suite (`NEXTSSL_ALL=1`).".into());
    let list: String = steps
        .iter()
        .enumerate()
        .map(|(i, t)| format!("{}. {t}\n", i + 1))
        .collect();
    format!(
        "# {id}\n\n\
         Scaffolded by `cargo xtask new`; nothing has been imported yet.\n\n\
         - Upstream: {src}\n\
         - Status: `importing` (the glue stub returns `Error::Unimplemented`)\n\n\
         ## To finish the import\n\n{list}",
        id = s.id
    )
}

/// Writes the skeleton under `<algos_dir>/<category>/<family>/<id>`. Fails if it already exists.
pub fn scaffold(algos_dir: &Path, s: &Spec) -> Res<PathBuf> {
    let dir = algos_dir.join(&s.category).join(&s.family).join(&s.id);
    if dir.exists() {
        return Err(format!("{} already exists", dir.display()));
    }
    let w = |name: &str, content: String| -> Res<()> {
        let p = dir.join(name);
        std::fs::write(&p, content).map_err(|e| format!("{}: {e}", p.display()))
    };
    std::fs::create_dir_all(dir.join("kat")).map_err(|e| format!("{}: {e}", dir.display()))?;
    w("kat/.gitkeep", String::new())?;
    w("algo.toml", algo_toml(s))?;
    w("Cargo.toml", cargo_toml(s))?;
    // rustfmt-clean from the start, so `cargo fmt --check` never trips on a fresh scaffold.
    w("glue.rs", crate::rustfmt(glue_rs(s))?)?;
    w("README.md", readme(s))?;
    if matches!(s.upstream, Upstream::C { .. }) {
        std::fs::create_dir_all(dir.join("upstream")).map_err(|e| e.to_string())?;
        w("upstream/.gitkeep", String::new())?;
        w("build.rs", build_rs(s))?;
    }
    Ok(dir)
}

pub fn run(args: &[String]) -> Res<()> {
    let spec = parse_args(args)?;
    let dir = scaffold(&crate::root().join("algos"), &spec)?;
    println!("scaffolded {}", dir.display());
    println!(
        "next: import upstream + KATs (see README.md there); `cargo xtask gen` fails until then"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{validate, Algo};

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Tmp {
            let p =
                std::env::temp_dir().join(format!("nextssl-xtask-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn load(dir: &Path, rel: &str) -> Algo {
        let text = std::fs::read_to_string(dir.join("algo.toml")).unwrap();
        let mut a: Algo = toml::from_str(&text).expect("scaffolded algo.toml parses");
        a.dir = rel.to_string();
        a
    }

    #[test]
    fn scaffolds_rust_crate_hash() {
        let t = Tmp::new("crate");
        let spec = parse_args(&args(&[
            "hash/sha3/sha3-256",
            "--kind",
            "hash",
            "--upstream-crate",
            "sha3=0.10.8",
        ]))
        .unwrap();
        let dir = scaffold(&t.0, &spec).unwrap();
        let a = load(&dir, "hash/sha3/sha3-256");
        assert_eq!(a.status, "importing");
        assert_eq!(a.upstream.version.as_deref(), Some("=0.10.8"));
        // The skeleton is deliberately not importable yet, and says why.
        let err = validate(&a, &dir).unwrap_err();
        assert!(err.contains("[sizes] out"), "{err}");
        let glue = std::fs::read_to_string(dir.join("glue.rs")).unwrap();
        assert!(glue.contains("Error::Unimplemented") && glue.contains("dyn Hash"));
        assert!(dir.join("kat").is_dir() && dir.join("README.md").is_file());
        assert!(!dir.join("upstream").exists());
        // A second run refuses to overwrite.
        assert!(scaffold(&t.0, &spec)
            .unwrap_err()
            .contains("already exists"));
    }

    #[test]
    fn scaffolds_c_encoding() {
        let t = Tmp::new("c");
        let commit = "ed1974ea83433eba7b2d95c5dcd9ac33cb847913";
        let spec = parse_args(&args(&[
            "encoding/base/base32",
            "--kind",
            "encoding",
            "--upstream-c",
            &format!("https://example.org/x/y.git@{commit}"),
            "--license",
            "MIT",
        ]))
        .unwrap();
        let dir = scaffold(&t.0, &spec).unwrap();
        let a = load(&dir, "encoding/base/base32");
        assert_eq!(a.upstream.commit.as_deref(), Some(commit));
        assert_eq!(a.upstream.license, "MIT");
        let err = validate(&a, &dir).unwrap_err();
        assert!(err.contains("files"), "{err}");
        let glue = std::fs::read_to_string(dir.join("glue.rs")).unwrap();
        assert!(glue.contains("dyn Encoding"));
        let build = std::fs::read_to_string(dir.join("build.rs")).unwrap();
        assert!(build.contains("nextssl__base32__"));
        assert!(dir.join("upstream").is_dir());
    }

    #[test]
    fn rejects_bad_input() {
        let with = |extra: &[&str]| {
            let mut v = vec!["a/b/c", "--kind", "hash"];
            v.extend_from_slice(extra);
            parse_args(&args(&v))
        };
        assert!(with(&["--upstream-crate", "sha3=0.10.8"]).is_ok());
        assert!(with(&["--upstream-crate", "sha3"]).is_err());
        assert!(with(&["--upstream-crate", "sha3=0.10"]).is_err());
        assert!(with(&["--upstream-c", "https://x/y@main"]).is_err());
        assert!(with(&["--upstream-c", "git@github.com:x/y.git@abc"]).is_err());
        assert!(with(&[]).is_err());
        let base = ["--kind", "hash", "--upstream-crate", "x=1.0.0"];
        let mk = |p: &str| {
            let mut v = vec![p];
            v.extend_from_slice(&base);
            parse_args(&args(&v))
        };
        assert!(mk("a/b").is_err());
        assert!(mk("A/b/c").is_err());
        assert!(parse_args(&args(&[
            "a/b/c",
            "--kind",
            "nope",
            "--upstream-crate",
            "x=1.0.0"
        ]))
        .is_err());
    }
}

#[cfg(test)]
mod all_kinds {
    use super::*;

    #[test]
    fn every_kind_scaffolds_an_algo_toml_that_parses_and_a_matching_glue_stub() {
        for kind in Kind::ALL {
            let s = Spec {
                category: "test".into(),
                family: "fam".into(),
                id: format!("x-{}", kind.as_str()),
                kind: kind.as_str().into(),
                upstream: Upstream::Crate {
                    name: "sha2".into(),
                    version: "=0.11.1".into(),
                },
                license: "MIT".into(),
            };
            let toml_text = algo_toml(&s);
            let a: crate::Algo = toml::from_str(&toml_text).expect("scaffold toml parses");
            assert_eq!(a.kind, kind.as_str());
            assert!(!a.copyleft);
            let glue = glue_rs(&s);
            assert!(glue.contains(&format!("impl {} for Stub", trait_name(kind))));
            assert!(glue.contains(&format!("dyn {}>", trait_name(kind))));
            assert!(glue.contains("Error::Unimplemented"));
            // Kinds with required sizes list them for the importer.
            for f in kind.required_sizes() {
                assert!(toml_text.contains(&format!("# {f} = 0")), "{kind:?} {f}");
            }
        }
    }
}
