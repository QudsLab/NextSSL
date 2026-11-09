//! Discovery: the registry as JSON. Written by hand (no serde) so the ABI crate stays small.

use nextssl_core::{Error, Kind, Len, ParamType, Sizes};
use nextssl_registry as reg;
use reg::{AlgoInfo, Policy};
use std::fmt::Write;

/// The C functions that operate on a kind (names without the `nextssl_` / `nextssl_root_` prefix).
pub fn ops_for(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::Hash => &["hash_with"],
        Kind::Xof => &["xof"],
        Kind::Mac => &["mac", "mac_verify"],
        Kind::Kdf => &["kdf"],
        Kind::PwHash => &["pwhash", "pwhash_salted", "pwhash_verify", "pwhash_derive"],
        Kind::Aead => &["aead_seal", "aead_open"],
        Kind::BlockCipher => &["blockcipher_encrypt", "blockcipher_decrypt"],
        Kind::StreamCipher => &["stream_apply"],
        Kind::Mode => &["mode_encrypt", "mode_decrypt"],
        Kind::BlockMode => &["blockmode_encrypt", "blockmode_decrypt"],
        Kind::Kem => &["kem_keygen", "kem_encaps", "kem_decaps"],
        Kind::Kex => &["kex_keygen", "kex_agree"],
        Kind::Sign => &["sign_keygen", "sign_detached", "verify_detached"],
        Kind::Rng => &["rng_fill"],
        Kind::Drbg => &["drbg_new", "drbg_generate", "drbg_reseed", "drbg_free"],
        Kind::Encoding => &["encode_with", "decode_with"],
        Kind::Checksum => &["checksum"],
        Kind::Pow => &["pow_solve", "pow_verify"],
        Kind::Zk => &["zk_setup", "zk_prove", "zk_verify"],
        Kind::Threshold => &[
            "threshold_split",
            "threshold_combine",
            "threshold_start",
            "threshold_step",
            "threshold_free",
        ],
        Kind::Vdf => &["vdf_eval", "vdf_verify"],
        Kind::Pke => &["pke_keygen", "pke_encrypt", "pke_decrypt"],
        Kind::Pake => &["pake_start", "pake_step", "pake_free"],
        Kind::StatefulSign => &[
            "stateful_keygen",
            "stateful_sign",
            "stateful_verify",
            "stateful_remaining",
        ],
        Kind::He => &["he_keygen", "he_encrypt", "he_decrypt", "he_eval"],
    }
}

fn esc(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn strs(out: &mut String, items: &[&str]) {
    out.push('[');
    for (i, s) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        esc(out, s);
    }
    out.push(']');
}

fn len(out: &mut String, l: Len) {
    let _ = write!(out, "{{\"min\":{},\"max\":{}}}", l.min(), l.max());
}

fn sizes(out: &mut String, s: &Sizes) {
    out.push('{');
    let mut first = true;
    for (name, l) in s.fields() {
        if let Some(l) = l {
            if !first {
                out.push(',');
            }
            first = false;
            esc(out, name);
            out.push(':');
            len(out, l);
        }
    }
    out.push('}');
}

fn params(out: &mut String, a: &AlgoInfo) {
    out.push('[');
    for (i, p) in a.params.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"name\":");
        esc(out, p.name);
        let (ty, values) = match p.ty {
            ParamType::U32 => ("u32", None),
            ParamType::U64 => ("u64", None),
            ParamType::Bytes => ("bytes", None),
            ParamType::Str => ("str", None),
            ParamType::Enum(v) => ("enum", Some(v)),
        };
        let _ = write!(out, ",\"type\":\"{ty}\",\"required\":{}", p.required);
        if values.is_none() {
            let _ = write!(out, ",\"min\":{},\"max\":{}", p.min, p.max);
        }
        out.push_str(",\"default\":");
        match (p.default, values) {
            (Some(d), Some(v)) => esc(out, v.get(d as usize).copied().unwrap_or("")),
            (Some(d), None) => {
                let _ = write!(out, "{d}");
            }
            (None, _) => out.push_str("null"),
        }
        if let Some(v) = values {
            out.push_str(",\"values\":");
            strs(out, v);
        }
        out.push('}');
    }
    out.push(']');
}

fn algo(out: &mut String, a: &AlgoInfo) {
    out.push_str("{\"id\":");
    esc(out, a.id);
    out.push_str(",\"kind\":");
    esc(out, a.kind.as_str());
    out.push_str(",\"category\":");
    esc(out, a.category);
    out.push_str(",\"family\":");
    esc(out, a.family);
    out.push_str(",\"aliases\":");
    strs(out, a.aliases);
    out.push_str(",\"tier\":");
    esc(out, a.tier.as_str());
    out.push_str(",\"status\":");
    esc(out, a.status.as_str());
    out.push_str(",\"standards\":");
    strs(out, a.standards);
    out.push_str(",\"license\":");
    esc(out, a.license);
    let safe = reg::allowed(a.tier, Policy::Safe) && !a.kind.root_only();
    let _ = write!(
        out,
        ",\"copyleft\":{},\"c_backed\":{},\"safe_api\":{},\"root_only_kind\":{}",
        a.copyleft,
        a.c_backed,
        safe,
        a.kind.root_only()
    );
    match a.cose_alg {
        Some(c) => {
            let _ = write!(out, ",\"cose_alg\":{c}");
        }
        None => out.push_str(",\"cose_alg\":null"),
    }
    out.push_str(",\"oid\":");
    esc(out, a.oid);
    out.push_str(",\"sizes\":");
    sizes(out, &a.sizes);
    out.push_str(",\"params\":");
    params(out, a);
    out.push_str(",\"ops\":");
    strs(out, ops_for(a.kind));
    out.push('}');
}

/// All algorithms, optionally only of kind `kind` (a `Kind::as_str` name).
pub fn list(kind: Option<&str>) -> Result<String, Error> {
    let filter = match kind.filter(|k| !k.is_empty()) {
        None => None,
        Some(k) => Some(Kind::parse(k).ok_or(Error::InvalidInput("unknown kind filter"))?),
    };
    let mut out = String::from("{\"abi_version\":");
    let _ = write!(out, "{},\"algorithms\":[", crate::NEXTSSL_ABI_VERSION);
    let mut first = true;
    for a in reg::all().iter().filter(|a| match filter {
        None => true,
        Some(k) => a.kind == k,
    }) {
        if !first {
            out.push(',');
        }
        first = false;
        algo(&mut out, a);
    }
    out.push_str("]}");
    Ok(out)
}

/// One algorithm by id or alias.
pub fn info(name: &str) -> Result<String, Error> {
    let a = reg::lookup(name).ok_or(Error::UnknownAlgorithm)?;
    let mut out = String::new();
    algo(&mut out, a);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_and_info_are_well_formed() {
        if !cfg!(miri) {
            // the full listing is too slow for Miri; the kind-filtered one below covers the code
            let all = list(None).unwrap();
            assert!(all.starts_with("{\"abi_version\":"));
            assert!(all.ends_with("]}"));
            assert_eq!(all.matches("\"id\":").count(), reg::all().len());
        }
        let kems = list(Some("kem")).unwrap();
        assert!(kems.contains("ml-kem-768") && !kems.contains("\"sha256\""));
        assert!(list(Some("nope")).is_err());
        let i = info("sha256").unwrap();
        assert!(i.contains("\"kind\":\"hash\"") && i.contains("\"safe_api\":true"));
        assert_eq!(info("zzz"), Err(Error::UnknownAlgorithm));
    }

    #[test]
    fn every_kind_has_ops() {
        for k in Kind::ALL {
            assert!(!ops_for(k).is_empty(), "{}", k.as_str());
        }
    }
}
