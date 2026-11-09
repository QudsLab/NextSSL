#!/usr/bin/env node
// NextSSL from JavaScript (WebAssembly). One file: a small binding plus a demo per algorithm kind.
//
//   node nextssl_demo.mjs                    list all algorithms
//   node nextssl_demo.mjs --list kem         list one kind
//   node nextssl_demo.mjs sha256             run the demo for an algorithm (safe API)
//   node nextssl_demo.mjs --root md5         other tiers need --root
//   node nextssl_demo.mjs --info ml-kem-768
//
// The module is the C ABI library built for wasm32-wasip1 (docs/bindings/js.md). It runs in Node
// 20 or newer with the small WASI shim below (random, clock and stderr only); the binding part of
// this file uses only standard WebAssembly and `crypto.getRandomValues`; import { NextSSL } from
// it in a browser module and call NextSSL.load(await (await fetch(url)).arrayBuffer()) (see
// docs/bindings/js.md for what was and was not tested). The CLI finds the wasm file through
// NEXTSSL_WASM or ../../target/docker-out/wasm/nextssl_ffi.wasm.

// Node-only imports are loaded inside main(), so this file can also be imported in a browser.

const OK = 0, ERR_BAD_OUTPUT_LEN = 10, ERR_AUTH_FAILED = 14;
const enc = new TextEncoder();
const dec = new TextDecoder();

export class NextSSLError extends Error {
  constructor(code, message, op) {
    super(`${op}: ${message} (code ${code})`);
    this.code = code;
    this.op = op;
  }
}

/** Minimal WASI preview-1 imports: enough for the library (random, clock, stderr, no files). */
function wasiShim(getMemory) {
  const view = () => new DataView(getMemory().buffer);
  const ENOSYS = 52, EBADF = 8;
  const base = {
    random_get(ptr, len) {
      const mem = new Uint8Array(getMemory().buffer, ptr, len);
      for (let off = 0; off < len; off += 65536) crypto.getRandomValues(mem.subarray(off, Math.min(off + 65536, len)));
      return 0;
    },
    clock_time_get(_id, _prec, out) {
      view().setBigUint64(out, BigInt(Date.now()) * 1000000n, true);
      return 0;
    },
    fd_write(fd, iovs, iovsLen, nwritten) {
      if (fd !== 1 && fd !== 2) return EBADF;
      const v = view();
      let total = 0, text = "";
      for (let i = 0; i < iovsLen; i++) {
        const p = v.getUint32(iovs + i * 8, true), n = v.getUint32(iovs + i * 8 + 4, true);
        text += dec.decode(new Uint8Array(getMemory().buffer, p, n));
        total += n;
      }
      console.error(text.trimEnd());
      v.setUint32(nwritten, total, true);
      return 0;
    },
    environ_sizes_get(countPtr, sizePtr) { const v = view(); v.setUint32(countPtr, 0, true); v.setUint32(sizePtr, 0, true); return 0; },
    environ_get() { return 0; },
    args_sizes_get(countPtr, sizePtr) { const v = view(); v.setUint32(countPtr, 0, true); v.setUint32(sizePtr, 0, true); return 0; },
    args_get() { return 0; },
    proc_exit(code) { throw new Error(`wasm called proc_exit(${code})`); },
    fd_fdstat_get() { return EBADF; },
  };
  return new Proxy(base, { get: (t, k) => t[k] ?? (() => ENOSYS) });
}

/** Thin wrapper over the C ABI exports of the wasm module. */
export class NextSSL {
  constructor(instance, root = false) {
    this.x = instance.exports;
    this.root = root;
    this.mem = () => this.x.memory.buffer;
  }

  static async load(wasmBytes, root = false) {
    const holder = { memory: null };
    const mod = await WebAssembly.compile(wasmBytes);
    const instance = await WebAssembly.instantiate(mod, { wasi_snapshot_preview1: wasiShim(() => holder.memory) });
    holder.memory = instance.exports.memory;
    if (instance.exports._initialize) instance.exports._initialize();
    return new NextSSL(instance, root);
  }

  alloc(n) {
    const p = this.x.nextssl_buf_alloc(n);
    if (!p) throw new Error(`nextssl_buf_alloc(${n}) failed`);
    return p;
  }

  message(code) {
    const p = this.x.nextssl_error_message(code);
    const u8 = new Uint8Array(this.mem());
    let e = p;
    while (u8[e] !== 0) e++;
    return dec.decode(u8.subarray(p, e));
  }

  version() {
    const p = this.x.nextssl_version();
    const u8 = new Uint8Array(this.mem());
    let e = p;
    while (u8[e] !== 0) e++;
    return dec.decode(u8.subarray(p, e));
  }

  /**
   * Calls nextssl_[root_]op. `sig` has one letter per argument before the outputs:
   * t = C string (null allowed), b = bytes (Uint8Array), z = size_t, u = uint32, q = uint64.
   * Returns the output Uint8Arrays (buffers grow automatically); with outs = 0 returns the status.
   */
  call(op, sig, args, outs = 1, okCodes = []) {
    const name = (this.root ? "nextssl_root_" : "nextssl_") + op;
    const fn = this.x[name];
    if (!fn) throw new NextSSLError(3, "no such function (root-only operations need --root)", op);
    let caps = new Array(outs).fill(256);
    for (;;) {
      const owned = []; // [ptr, size] pairs to free
      const mk = (size) => { const p = this.alloc(size); owned.push([p, size]); return p; };
      try {
        const c = [];
        for (let i = 0; i < sig.length; i++) {
          const a = args[i];
          switch (sig[i]) {
            case "t": {
              if (a === null || a === undefined) { c.push(0); break; }
              const b = enc.encode(a);
              const p = mk(b.length + 1);
              new Uint8Array(this.mem(), p, b.length).set(b);
              c.push(p);
              break;
            }
            case "b": {
              const s = mk(8);
              let p = 0;
              if (a.length) { p = mk(a.length); new Uint8Array(this.mem(), p, a.length).set(a); }
              const v = new DataView(this.mem());
              v.setUint32(s, p, true);
              v.setUint32(s + 4, a.length, true);
              c.push(s);
              break;
            }
            case "z": case "u": c.push(Number(a)); break;
            case "q": c.push(BigInt(a)); break;
            default: throw new Error(`bad signature letter ${sig[i]}`);
          }
        }
        const bufs = caps.map((cap) => mk(Math.max(cap, 1)));
        const structs = caps.map((cap, i) => {
          const s = mk(12);
          const v = new DataView(this.mem());
          v.setUint32(s, bufs[i], true);
          v.setUint32(s + 4, cap, true);
          v.setUint32(s + 8, 0, true);
          return s;
        });
        const rc = fn(...c, ...structs);
        const lens = structs.map((s) => new DataView(this.mem()).getUint32(s + 8, true));
        if (rc === ERR_BAD_OUTPUT_LEN) { caps = lens.map((n) => Math.max(n, 1)); continue; }
        if (rc !== OK && !okCodes.includes(rc)) throw new NextSSLError(rc, this.message(rc), op);
        if (outs === 0) return rc;
        return bufs.map((p, i) => new Uint8Array(this.mem(), p, lens[i]).slice());
      } finally {
        for (const [p, n] of owned) this.x.nextssl_buf_free(p, n);
      }
    }
  }

  /** Verify-style call: true when valid, false for AUTHENTICATION_FAILED, throws otherwise. */
  check(op, sig, args) {
    return this.call(op, sig, args, 0, [ERR_AUTH_FAILED]) === OK;
  }

  random(n) { return this.call("rng_fill", "ttz", ["os-entropy", null, n])[0]; }

  json(fnName, arg) {
    let cap = 1;
    for (;;) {
      const p = this.alloc(Math.max(cap, 1)), s = this.alloc(12);
      let a = 0, an = 0;
      try {
        if (arg !== null && arg !== undefined) {
          const b = enc.encode(arg);
          an = b.length + 1;
          a = this.alloc(an);
          new Uint8Array(this.mem(), a, b.length).set(b);
        }
        const v = new DataView(this.mem());
        v.setUint32(s, p, true); v.setUint32(s + 4, cap, true); v.setUint32(s + 8, 0, true);
        const rc = this.x[fnName](a, s);
        const len = new DataView(this.mem()).getUint32(s + 8, true);
        if (rc === ERR_BAD_OUTPUT_LEN) { cap = len; continue; }
        if (rc !== OK) throw new NextSSLError(rc, this.message(rc), fnName);
        return JSON.parse(dec.decode(new Uint8Array(this.mem(), p, len)));
      } finally {
        this.x.nextssl_buf_free(p, Math.max(cap, 1));
        this.x.nextssl_buf_free(s, 12);
        if (a) this.x.nextssl_buf_free(a, an);
      }
    }
  }

  algorithms(kind = null) { return this.json("nextssl_algorithms_json", kind).algorithms; }
  info(name) { return this.json("nextssl_algorithm_info_json", name); }
}

// ----------------------------------------------------------------------------------------------
// Demo
// ----------------------------------------------------------------------------------------------

const KNOWN_ABC = {
  sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  sha1: "a9993e364706816aba3e25717850c26c9cd0d89d",
  md5: "900150983cd24fb0d6963f7d28e17f72",
};
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const bytes = (s) => enc.encode(s);
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const tamper = (b) => { const c = b.slice(); c[0] ^= 1; return c; };
const pick = (info, field, prefer) => {
  const r = info.sizes[field];
  return r ? Math.max(r.min, Math.min(prefer, r.max)) : prefer;
};
function show(label, d) {
  const h = hex(d);
  console.log(`  ${label.padEnd(14)} ${h.length <= 96 ? h : h.slice(0, 96) + "..."} (${d.length} bytes)`);
}

function demo(ns, info, p) {
  const alg = info.id;
  switch (info.kind) {
    case "hash": {
      const d = ns.call("hash_with", "ttb", [alg, p, bytes("abc")])[0];
      show("digest(abc)", d);
      const want = KNOWN_ABC[alg];
      console.log(want ? `  known answer    ${hex(d) === want ? "MATCH" : `MISMATCH (expected ${want})`}` : "  known answer    (none built into this example)");
      break;
    }
    case "xof": show("xof(abc,48)", ns.call("xof", "ttbz", [alg, p, bytes("abc"), 48])[0]); break;
    case "checksum": {
      const c = ns.call("checksum", "ttb", [alg, p, bytes("123456789")])[0];
      show("check", c);
      if (alg === "crc32") console.log(`  known answer    ${hex(c) === "cbf43926" ? "MATCH" : "MISMATCH (expected cbf43926)"}`);
      break;
    }
    case "encoding": {
      const raw = Uint8Array.from([0, 104, 105, 255, 1, 2, 3]);
      const e = ns.call("encode_with", "ttb", [alg, p, raw])[0];
      console.log(`  encoded         ${dec.decode(e)}`);
      console.log(`  round trip      ${same(ns.call("decode_with", "ttb", [alg, p, e])[0], raw) ? "OK" : "FAILED"}`);
      break;
    }
    case "mac": {
      const key = ns.random(pick(info, "key", 32));
      const tag = ns.call("mac", "ttbbz", [alg, p, key, bytes("abc"), 0])[0];
      show("tag", tag);
      console.log(`  verify          ${ns.check("mac_verify", "ttbbb", [alg, p, key, bytes("abc"), tag])}`);
      console.log(`  verify tampered ${ns.check("mac_verify", "ttbbb", [alg, p, key, bytes("abc"), tamper(tag)])}`);
      break;
    }
    case "kdf": {
      const ikm = ns.random(pick(info, "key", 32));
      show("derived(32)", ns.call("kdf", "ttbbbz", [alg, p, ikm, bytes("salt-16-bytes!!!"), bytes("ctx"), 32])[0]);
      break;
    }
    case "aead": {
      const key = ns.random(pick(info, "key", 32)), nonce = ns.random(pick(info, "nonce", 12));
      const ct = ns.call("aead_seal", "ttbbbb", [alg, p, key, nonce, bytes("header"), bytes("attack at dawn")])[0];
      show("ciphertext", ct);
      const pt = ns.call("aead_open", "ttbbbb", [alg, p, key, nonce, bytes("header"), ct])[0];
      console.log(`  round trip      ${dec.decode(pt) === "attack at dawn" ? "OK" : "FAILED"}`);
      try {
        ns.call("aead_open", "ttbbbb", [alg, p, key, nonce, bytes("header"), tamper(ct)]);
        console.log("  tampered        ACCEPTED (bug!)");
      } catch (e) {
        if (!(e instanceof NextSSLError)) throw e;
        console.log(`  tampered        rejected: ${e.message}`);
      }
      break;
    }
    case "kem": {
      const [pk, sk] = ns.call("kem_keygen", "tt", [alg, p], 2);
      const [ct, ss] = ns.call("kem_encaps", "ttb", [alg, p, pk], 2);
      const ss2 = ns.call("kem_decaps", "ttbb", [alg, p, sk, ct])[0];
      show("public key", pk); show("ciphertext", ct); show("shared secret", ss);
      console.log(`  secrets equal   ${same(ss, ss2)}`);
      break;
    }
    case "kex": {
      const [pa, sa] = ns.call("kex_keygen", "tt", [alg, p], 2);
      const [pb, sb] = ns.call("kex_keygen", "tt", [alg, p], 2);
      const s1 = ns.call("kex_agree", "ttbb", [alg, p, sa, pb])[0];
      const s2 = ns.call("kex_agree", "ttbb", [alg, p, sb, pa])[0];
      show("shared secret", s1);
      console.log(`  both sides equal ${same(s1, s2)}`);
      break;
    }
    case "sign": {
      const [pk, sk] = ns.call("sign_keygen", "tt", [alg, p], 2);
      const none = new Uint8Array(0);
      const sig = ns.call("sign_detached", "ttbbb", [alg, p, sk, bytes("sign this"), none])[0];
      show("public key", pk); show("signature", sig);
      console.log(`  verify          ${ns.check("verify_detached", "ttbbbb", [alg, p, pk, bytes("sign this"), none, sig])}`);
      console.log(`  wrong message   ${ns.check("verify_detached", "ttbbbb", [alg, p, pk, bytes("sign that"), none, sig])}`);
      break;
    }
    case "rng": show("random(16)", ns.call("rng_fill", "ttz", [alg, p, 16])[0]); break;
    default:
      console.log(`  no demo for kind '${info.kind}' in the JS example (the Python example covers every kind);`);
      console.log(`  its C functions are: ${info.ops.join(", ")}`);
  }
}

function listing(ns, kind) {
  const algs = ns.algorithms(kind);
  console.log(`${"id".padEnd(34)}${"kind".padEnd(14)}${"tier".padEnd(11)}access`);
  const kinds = {};
  for (const a of algs) {
    console.log(`${a.id.padEnd(34)}${a.kind.padEnd(14)}${a.tier.padEnd(11)}${a.safe_api ? "safe" : "root"}`);
    kinds[a.kind] = (kinds[a.kind] ?? 0) + 1;
  }
  const ks = Object.keys(kinds).sort().map((k) => `${k}=${kinds[k]}`).join(", ");
  console.log(`\n${algs.length} algorithms, library ${ns.version()}\nkinds: ${ks}`);
}

async function main(argv) {
  const root = argv.includes("--root");
  argv = argv.filter((a) => a !== "--root");
  let params = null;
  const pi = argv.indexOf("--params");
  if (pi >= 0) { params = argv[pi + 1]; argv.splice(pi, 2); }
  const { readFileSync, existsSync } = await import("node:fs");
  const { fileURLToPath } = await import("node:url");
  const { dirname, resolve } = await import("node:path");
  const here = dirname(fileURLToPath(import.meta.url));
  const path = process.env.NEXTSSL_WASM || resolve(here, "../../target/docker-out/wasm/nextssl_ffi.wasm");
  if (!existsSync(path)) {
    console.error(`nextssl_ffi.wasm not found at ${path}: build it (docs/bindings/js.md) or set NEXTSSL_WASM`);
    return 2;
  }
  const ns = await NextSSL.load(readFileSync(path), root);
  if (!argv.length || argv[0] === "--list" || argv[0] === "-l") { listing(ns, argv[1] ?? null); return 0; }
  if (argv[0] === "--info") { console.log(JSON.stringify(ns.info(argv[1]), null, 2)); return 0; }
  const info = ns.info(argv[0]);
  console.log(`${info.id}  kind=${info.kind}  tier=${info.tier}  license=${info.license}  api=${info.safe_api ? "safe" : "root only"}`);
  try {
    demo(ns, info, params);
  } catch (e) {
    if (!(e instanceof NextSSLError)) throw e;
    console.log(`  error: ${e.message}`);
    if (e.code === 3 && !root) console.log("  this tier is not reachable from the safe API; rerun with --root to accept the risk");
    return e.code;
  }
  return 0;
}

// Run the CLI only when executed by Node as the entry point (not when imported).
if (typeof process !== "undefined" && process.versions?.node && process.argv[1]) {
  const { pathToFileURL } = await import("node:url");
  if (import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
}
