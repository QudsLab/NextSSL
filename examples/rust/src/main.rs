//! NextSSL from Rust, using the crates directly (no C ABI, no unsafe).
//!
//!   cargo run --release -- --list            list all algorithms
//!   cargo run --release -- --list kem        list one kind
//!   cargo run --release -- sha256            run the demo for an algorithm (safe policy)
//!   cargo run --release -- --root md5        other tiers need --root
//!   cargo run --release -- --info ml-kem-768
//!
//! The registry is the single table of algorithms; `Policy::Safe` admits only the `safe` and
//! `standard` tiers (anything else is `Error::TierNotAllowed`), `Policy::Any` is what
//! `nextssl_root` uses. Nothing here implements cryptography.

use nextssl_core::{
    Ciphertext, Kind, Len, Params, PrivateKey, PublicKey, SymmetricKey, Value, Zeroizing,
};
use nextssl_registry as reg;
use reg::{AlgoInfo, Policy};
use std::process::ExitCode;

type Res<T> = Result<T, nextssl_core::Error>;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn show(label: &str, d: &[u8]) {
    let h = hex(d);
    let shown = if h.len() <= 96 {
        h
    } else {
        format!("{}...", &h[..96])
    };
    println!("  {label:<14} {shown} ({} bytes)", d.len());
}

/// A length inside the algorithm's declared range, as close to `prefer` as possible.
fn pick(l: Option<Len>, prefer: usize) -> usize {
    l.map_or(prefer, |l| prefer.clamp(l.min(), l.max()))
}

fn tamper(b: &[u8]) -> Vec<u8> {
    let mut c = b.to_vec();
    c[0] ^= 1;
    c
}

/// `name=value;name=value` parameters, typed by the algorithm's declared schema.
fn parse_params(info: &AlgoInfo, text: Option<&str>) -> Res<Params> {
    let mut p = Params::new();
    for item in text.unwrap_or("").split(';').filter(|s| !s.is_empty()) {
        let (k, v) = item
            .split_once('=')
            .ok_or(nextssl_core::Error::InvalidInput(
                "parameter must be name=value",
            ))?;
        let spec = info
            .params
            .iter()
            .find(|s| s.name == k)
            .ok_or(nextssl_core::Error::ParamUnknown)?;
        let value = match spec.ty {
            nextssl_core::ParamType::U32 => Value::U32(
                v.parse()
                    .map_err(|_| nextssl_core::Error::ParamType(spec.name))?,
            ),
            nextssl_core::ParamType::U64 => Value::U64(
                v.parse()
                    .map_err(|_| nextssl_core::Error::ParamType(spec.name))?,
            ),
            _ => Value::Str(v.to_string()),
        };
        p.set(spec.name, value);
    }
    Ok(p)
}

fn demo(info: &AlgoInfo, policy: Policy, text: Option<&str>) -> Res<()> {
    let all = reg::all();
    let alg = info.id;
    let p = parse_params(info, text)?;
    let mut rng = reg::new_rng_in(all, policy, "os-entropy", &Params::new())?;
    let mut random = |n: usize| -> Res<Zeroizing<Vec<u8>>> {
        let mut b = Zeroizing::new(vec![0u8; n]);
        rng.fill(&mut b)?;
        Ok(b)
    };
    let s = info.sizes;
    match info.kind {
        Kind::Hash => {
            let d = reg::hash_in(all, policy, alg, &p, b"abc")?;
            show("digest(abc)", &d);
            // The same call through the convenience crates: `nextssl` (safe tiers) or `nextssl_root`.
            let via_api = if matches!(policy, Policy::Safe) {
                nextssl::hash(alg, b"abc")?
            } else {
                nextssl_root::hash(alg, b"abc")?
            };
            println!(
                "  convenience API {}",
                if via_api == d {
                    "same digest"
                } else {
                    "DIFFERENT (bug!)"
                }
            );
            let known = [
                (
                    "sha256",
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                ),
                ("sha1", "a9993e364706816aba3e25717850c26c9cd0d89d"),
                ("md5", "900150983cd24fb0d6963f7d28e17f72"),
            ];
            match known.iter().find(|(n, _)| *n == alg) {
                Some((_, want)) => println!(
                    "  known answer    {}",
                    if hex(&d) == *want {
                        "MATCH".to_string()
                    } else {
                        format!("MISMATCH (expected {want})")
                    }
                ),
                None => println!("  known answer    (none built into this example)"),
            }
        }
        Kind::Xof => {
            let x = reg::new_xof_in(all, policy, alg, &p)?;
            let mut out = vec![0u8; 48];
            x.squeeze(b"abc", &mut out)?;
            show("xof(abc,48)", &out);
        }
        Kind::Checksum => {
            let c = reg::new_checksum_in(all, policy, alg, &p)?;
            let mut out = vec![0u8; c.sizes().out.ok_or(nextssl_core::Error::Unsupported)?.max()];
            c.checksum(b"123456789", &mut out)?;
            show("check", &out);
            if alg == "crc32" {
                println!(
                    "  known answer    {}",
                    if hex(&out) == "cbf43926" {
                        "MATCH"
                    } else {
                        "MISMATCH (expected cbf43926)"
                    }
                );
            }
        }
        Kind::Encoding => {
            let raw = [0u8, b'h', b'i', 0xff, 1, 2, 3];
            let e = reg::encode_in(all, policy, alg, &p, &raw)?;
            println!("  encoded         {}", String::from_utf8_lossy(&e));
            let back = reg::decode_in(all, policy, alg, &p, &e)?;
            println!(
                "  round trip      {}",
                if back == raw { "OK" } else { "FAILED" }
            );
        }
        Kind::Mac => {
            let m = reg::new_mac_in(all, policy, alg, &p)?;
            let key = SymmetricKey::from_bytes(&random(pick(s.key, 32))?, Len::range(0, 1 << 20))?;
            let mut tag = vec![0u8; m.sizes().tag.ok_or(nextssl_core::Error::Unsupported)?.max()];
            m.tag(&key, b"abc", &mut tag)?;
            show("tag", &tag);
            println!("  verify          {}", m.verify(&key, b"abc", &tag)?);
            println!(
                "  verify tampered {}",
                m.verify(&key, b"abc", &tamper(&tag))?
            );
        }
        Kind::Kdf => {
            let k = reg::new_kdf_in(all, policy, alg, &p)?;
            let ikm = SymmetricKey::from_bytes(&random(pick(s.key, 32))?, Len::range(0, 1 << 20))?;
            let mut out = vec![0u8; 32];
            k.derive(&ikm, b"salt-16-bytes!!!", b"ctx", &mut out)?;
            show("derived(32)", &out);
        }
        Kind::Aead => {
            let a = reg::new_aead_in(all, policy, alg, &p)?;
            let key = SymmetricKey::from_bytes(&random(pick(s.key, 32))?, Len::range(0, 1 << 20))?;
            let nonce = random(pick(s.nonce, 12))?;
            let ct = a.seal(&key, &nonce, b"header", b"attack at dawn")?;
            show("ciphertext", &ct);
            let pt = a.open(&key, &nonce, b"header", &ct)?;
            println!(
                "  round trip      {}",
                if &pt[..] == b"attack at dawn" {
                    "OK"
                } else {
                    "FAILED"
                }
            );
            match a.open(&key, &nonce, b"header", &tamper(&ct)) {
                Ok(_) => println!("  tampered        ACCEPTED (bug!)"),
                Err(e) => println!("  tampered        rejected: {e}"),
            }
        }
        Kind::Kem => {
            let k = reg::new_kem_in(all, policy, alg, &p)?;
            let (pk, sk) = k.keygen(&mut *reg::new_rng_in(
                all,
                policy,
                "os-entropy",
                &Params::new(),
            )?)?;
            let (ct, ss) = k.encaps(
                &pk,
                &mut *reg::new_rng_in(all, policy, "os-entropy", &Params::new())?,
            )?;
            let ss2 = k.decaps(
                &sk,
                &Ciphertext::from_bytes(ct.as_bytes(), Len::range(0, 1 << 24))?,
            )?;
            show("public key", pk.as_bytes());
            show("ciphertext", ct.as_bytes());
            show("shared secret", ss.as_bytes());
            println!("  secrets equal   {}", ss == ss2);
        }
        Kind::Kex => {
            let k = reg::new_kex_in(all, policy, alg, &p)?;
            let mut r = reg::new_rng_in(all, policy, "os-entropy", &Params::new())?;
            let (pa, sa) = k.keypair(&mut *r)?;
            let (pb, sb) = k.keypair(&mut *r)?;
            let s1 = k.agree(&sa, &pb)?;
            let s2 = k.agree(&sb, &pa)?;
            show("shared secret", s1.as_bytes());
            println!("  both sides equal {}", s1 == s2);
        }
        Kind::Sign => {
            let sg = reg::new_sign_in(all, policy, alg, &p)?;
            let mut r = reg::new_rng_in(all, policy, "os-entropy", &Params::new())?;
            let (pk, sk): (PublicKey, PrivateKey) = sg.keygen(&mut *r)?;
            let sig = sg.sign(&sk, b"sign this", b"", &mut *r)?;
            show("public key", pk.as_bytes());
            show("signature", sig.as_bytes());
            println!(
                "  verify          {}",
                sg.verify(&pk, b"sign this", b"", &sig)?
            );
            println!(
                "  wrong message   {}",
                sg.verify(&pk, b"sign that", b"", &sig)?
            );
        }
        Kind::Rng => {
            let mut r = reg::new_rng_in(all, policy, alg, &p)?;
            let mut out = [0u8; 16];
            r.fill(&mut out)?;
            show("random(16)", &out);
        }
        other => println!(
            "  no demo for kind '{}' in the Rust example (the Python example covers every kind)",
            other.as_str()
        ),
    }
    Ok(())
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let root = args.iter().any(|a| a == "--root");
    args.retain(|a| a != "--root");
    let mut params = None;
    if let Some(i) = args.iter().position(|a| a == "--params") {
        params = args.get(i + 1).cloned();
        args.drain(i..(i + 2).min(args.len()));
    }
    let policy = if root { Policy::Any } else { Policy::Safe };

    if args.is_empty() || args[0] == "--list" || args[0] == "-l" {
        let kind = args.get(1).map(String::as_str);
        println!("{:<34}{:<14}{:<11}access", "id", "kind", "tier");
        let mut n = 0;
        let mut kinds = std::collections::BTreeMap::new();
        for a in reg::all()
            .iter()
            .filter(|a| kind.is_none_or(|k| a.kind.as_str() == k))
        {
            let access = if reg::allowed(a.tier, Policy::Safe) && !a.kind.root_only() {
                "safe"
            } else {
                "root"
            };
            println!(
                "{:<34}{:<14}{:<11}{access}",
                a.id,
                a.kind.as_str(),
                a.tier.as_str()
            );
            *kinds.entry(a.kind.as_str()).or_insert(0) += 1;
            n += 1;
        }
        let ks: Vec<String> = kinds.iter().map(|(k, c)| format!("{k}={c}")).collect();
        println!("\n{n} algorithms\nkinds: {}", ks.join(", "));
        return ExitCode::SUCCESS;
    }
    if args[0] == "--info" {
        let Some(a) = args.get(1).and_then(|n| reg::lookup(n)) else {
            eprintln!("unknown algorithm");
            return ExitCode::from(1);
        };
        println!(
            "id={} kind={} tier={} license={} sizes={:?} params={:?}",
            a.id,
            a.kind.as_str(),
            a.tier.as_str(),
            a.license,
            a.sizes,
            a.params
        );
        return ExitCode::SUCCESS;
    }
    let Some(info) = reg::lookup(&args[0]) else {
        eprintln!("unknown algorithm '{}'", args[0]);
        return ExitCode::from(1);
    };
    println!(
        "{}  kind={}  tier={}  license={}  api={}",
        info.id,
        info.kind.as_str(),
        info.tier.as_str(),
        info.license,
        if reg::allowed(info.tier, Policy::Safe) && !info.kind.root_only() {
            "safe"
        } else {
            "root only"
        }
    );
    match demo(info, policy, params.as_deref()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            println!("  error: {e} (code {})", e.code());
            if matches!(e, nextssl_core::Error::TierNotAllowed(_)) && !root {
                println!("  this tier is not reachable from the safe policy; rerun with --root to accept the risk");
            }
            ExitCode::from(e.code() as u8)
        }
    }
}
