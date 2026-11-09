#!/usr/bin/env python3
"""NextSSL from Python (ctypes). One file: a small binding plus a demo for every algorithm kind.

    python nextssl_demo.py                    list all algorithms
    python nextssl_demo.py --list kem         list one kind
    python nextssl_demo.py sha256             run the demo for an algorithm (safe API)
    python nextssl_demo.py --root md5         legacy/broken/research/unverified tiers need --root
    python nextssl_demo.py --info ml-kem-768  show the registry entry as JSON
    python nextssl_demo.py --all [kind]       run every algorithm's demo (root API) and summarize

The library is found through NEXTSSL_LIB, or in ../../target/{release,debug} (see
docs/bindings/python.md). Nothing here implements cryptography: every operation is a call into
the NextSSL C ABI.
"""

import ctypes
import json
import os
import sys
import time

# ---------------------------------------------------------------------------------------------
# Binding
# ---------------------------------------------------------------------------------------------

OK = 0
ERR_BAD_OUTPUT_LEN = 10
ERR_AUTHENTICATION_FAILED = 14


class _In(ctypes.Structure):
    _fields_ = [("ptr", ctypes.c_void_p), ("len", ctypes.c_size_t)]


class _Out(ctypes.Structure):
    _fields_ = [("ptr", ctypes.c_void_p), ("cap", ctypes.c_size_t), ("len", ctypes.c_size_t)]


class NextSSLError(Exception):
    """A non-zero NEXTSSL_ERR_* code. `code` is the number, str(e) the library's message."""

    def __init__(self, code, message, op):
        super().__init__(f"{op}: {message} (code {code})")
        self.code = code
        self.op = op


class U32(int):
    """Marks an argument as a C uint32_t."""


class U64(int):
    """Marks an argument as a C uint64_t."""


class U16(int):
    """Marks an argument as a C uint16_t."""


def _find_library():
    env = os.environ.get("NEXTSSL_LIB")
    if env:
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    names = {"win32": "nextssl_ffi.dll", "darwin": "libnextssl_ffi.dylib"}
    name = names.get(sys.platform, "libnextssl_ffi.so")
    for profile in ("release", "debug"):
        p = os.path.join(here, "..", "..", "target", profile, name)
        if os.path.exists(p):
            return os.path.normpath(p)
    sys.exit("libnextssl_ffi not found: build it (cargo build -p nextssl-ffi --release) "
             "or set NEXTSSL_LIB to its path")


class NextSSL:
    """Thin wrapper over the C ABI. `root=True` uses the nextssl_root_* entry points."""

    def __init__(self, path=None, root=False):
        self.lib = ctypes.CDLL(path or _find_library())
        self.root = root
        self.lib.nextssl_error_message.restype = ctypes.c_char_p
        self.lib.nextssl_error_message.argtypes = [ctypes.c_int32]
        self.lib.nextssl_abi_version.restype = ctypes.c_uint32
        self.lib.nextssl_version.restype = ctypes.c_char_p

    # -- errors and buffers -------------------------------------------------------------------

    def message(self, code):
        return self.lib.nextssl_error_message(code).decode()

    HANDLE_OPS = ("drbg_generate", "drbg_reseed", "drbg_free")

    def _fn(self, op):
        # Operations on an existing handle carry no tier prefix: the tier was checked at creation.
        prefix = "nextssl_" if op in self.HANDLE_OPS else ("nextssl_root_" if self.root else "nextssl_")
        fn = getattr(self.lib, prefix + op, None)
        if fn is None:
            raise NextSSLError(3, "this operation exists only as nextssl_root_* (pass --root)", op)
        fn.restype = ctypes.c_int32
        return fn

    @staticmethod
    def _arg(a, keep):
        if a is None:
            return None
        if isinstance(a, str):
            return a.encode()
        if isinstance(a, (bytes, bytearray)):
            buf = (ctypes.c_ubyte * max(len(a), 1)).from_buffer_copy(bytes(a) or b"\0")
            keep.append(buf)
            s = _In(ctypes.cast(buf, ctypes.c_void_p) if len(a) else None, len(a))
            keep.append(s)
            return ctypes.byref(s)
        if isinstance(a, U32):
            return ctypes.c_uint32(a)
        if isinstance(a, U64):
            return ctypes.c_uint64(a)
        if isinstance(a, U16):
            return ctypes.c_uint16(a)
        if isinstance(a, int):
            return ctypes.c_size_t(a)
        raise TypeError(f"unsupported argument {type(a)}")

    def call(self, op, *args, outs=1, status_ok=(OK,)):
        """Calls nextssl_[root_]<op>. Byte-string arguments become nextssl_in, `outs` output
        buffers are allocated (and grown when the library reports a larger size). Returns the
        list of output byte strings, or the status code when outs == 0."""
        fn = self._fn(op)
        keep = []
        cargs = [self._arg(a, keep) for a in args]
        caps = [256] * outs
        while True:
            bufs = [ctypes.create_string_buffer(c) for c in caps]
            structs = [_Out(ctypes.cast(b, ctypes.c_void_p), c, 0) for b, c in zip(bufs, caps)]
            rc = fn(*cargs, *[ctypes.byref(s) for s in structs])
            if rc == ERR_BAD_OUTPUT_LEN:
                caps = [max(s.len, 1) for s in structs]
                continue
            break
        if rc not in status_ok:
            raise NextSSLError(rc, self.message(rc), op)
        if outs == 0:
            return rc
        return [bytes(b.raw[: s.len]) for b, s in zip(bufs, structs)]

    def check(self, op, *args):
        """For verify-style calls: True when valid, False for AUTHENTICATION_FAILED, raises otherwise."""
        rc = self.call(op, *args, outs=0, status_ok=(OK, ERR_AUTHENTICATION_FAILED))
        return rc == OK

    # -- discovery ------------------------------------------------------------------------------

    def _json(self, fn, arg):
        bufs = [ctypes.create_string_buffer(1)]
        cap = 1
        while True:
            buf = ctypes.create_string_buffer(cap)
            out = _Out(ctypes.cast(buf, ctypes.c_void_p), cap, 0)
            rc = fn(arg, ctypes.byref(out))
            if rc == ERR_BAD_OUTPUT_LEN:
                cap = out.len
                continue
            if rc != OK:
                raise NextSSLError(rc, self.message(rc), "json")
            return json.loads(buf.raw[: out.len])

    def algorithms(self, kind=None):
        fn = self.lib.nextssl_algorithms_json
        fn.restype = ctypes.c_int32
        return self._json(fn, kind.encode() if kind else None)["algorithms"]

    def info(self, name):
        fn = self.lib.nextssl_algorithm_info_json
        fn.restype = ctypes.c_int32
        return self._json(fn, name.encode())

    def random(self, n):
        return self.call("rng_fill", "os-entropy", None, n)[0] if n > 0 else b""

    def new_handle(self, op, *args):
        h = ctypes.c_uint64(0)
        fn = self._fn(op)
        keep = []
        rc = fn(*[self._arg(a, keep) for a in args], ctypes.byref(h))
        if rc != OK:
            raise NextSSLError(rc, self.message(rc), op)
        return h.value


# ---------------------------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------------------------

KNOWN_HASH_ABC = {
    "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "sha1": "a9993e364706816aba3e25717850c26c9cd0d89d",
    "md5": "900150983cd24fb0d6963f7d28e17f72",
}


def pick(info, field, prefer):
    """A length inside the algorithm's declared range, as close to `prefer` as possible."""
    r = info["sizes"].get(field)
    if not r:
        return prefer
    return max(r["min"], min(prefer, r["max"]))


def auto_params(info):
    """Parameters the algorithm requires (no default), filled with a sensible demo value."""
    parts = []
    for prm in info["params"]:
        if prm["required"] and prm["default"] is None:
            if prm["type"] == "enum":
                parts.append(f"{prm['name']}={prm['values'][0]}")
            elif prm["type"] == "str":
                parts.append(f"{prm['name']}=bc")
            elif prm["type"] in ("u32", "u64"):
                parts.append(f"{prm['name']}={prm['min']}")
    return ";".join(parts) or None


def show(label, data):
    h = data.hex()
    print(f"  {label:<14} {h if len(h) <= 96 else h[:96] + '...'} ({len(data)} bytes)")


def tamper(b):
    return bytes([b[0] ^ 1]) + b[1:]


def demo(ns, info, p):
    kind = info["kind"]
    alg = info["id"]
    msg = b"abc"
    if kind == "hash":
        d = ns.call("hash_with", alg, p, msg)[0]
        show("digest(abc)", d)
        want = KNOWN_HASH_ABC.get(alg)
        if want:
            print("  known answer   ", "MATCH" if d.hex() == want else f"MISMATCH (expected {want})")
        else:
            print("  known answer    (none built into this example; the library's KAT suite checks it)")
    elif kind == "xof":
        show("xof(abc, 48)", ns.call("xof", alg, p, msg, 48)[0])
    elif kind == "checksum":
        try:
            c = ns.call("checksum", alg, p, b"123456789")[0]
        except NextSSLError:
            c = ns.call("checksum", alg, p, b"1234567890")[0]  # some checksums need an even length
        show("check(123456789)", c)
        if alg == "crc32":
            print("  known answer   ", "MATCH" if c.hex() == "cbf43926" else "MISMATCH (expected cbf43926)")
    elif kind == "encoding":
        e = ns.call("encode_with", alg, p, b"\x00hello, nextssl\xff")[0]
        print(f"  encoded         {e.decode(errors='replace')}")
        back = ns.call("decode_with", alg, p, e)[0]
        print("  round trip     ", "OK" if back == b"\x00hello, nextssl\xff" else "FAILED")
    elif kind == "mac":
        key = ns.random(pick(info, "key", 32))
        msg = b"0123456789abcdef" * 4  # a whole number of blocks: CBC-MAC style MACs need that
        tag = ns.call("mac", alg, p, key, msg, 0)[0]
        show("tag", tag)
        print("  verify         ", ns.check("mac_verify", alg, p, key, msg, tag))
        print("  verify tampered", ns.check("mac_verify", alg, p, key, msg, tamper(tag)))
    elif kind == "kdf":
        sz = info["sizes"]
        ikm = ns.random(pick(info, "key", 32))
        salt = b"" if sz.get("salt", {}).get("max", 1) == 0 else b"salt-16-bytes!!!"
        extra = b"" if sz.get("info", {}).get("max", 1) == 0 else b"ctx"
        out = ns.call("kdf", alg, p, ikm, salt, extra, pick(info, "out", 32))[0]
        show("derived", out)
    elif kind == "pwhash":
        t0 = time.time()
        pw = b"hunter2"
        try:
            phc = ns.call("pwhash", alg, p, pw)[0]
        except NextSSLError as e:
            if e.code != 9:
                raise
            # crypt(3)-style schemes want a salt in their own alphabet: supply one explicitly
            salt = b"NextSSL1"[: info["sizes"]["salt"]["max"]]
            phc = ns.call("pwhash_salted", alg, p, pw, salt)[0]
        print(f"  hash string     {phc.decode()}  ({time.time() - t0:.2f}s)")
        print("  verify correct ", ns.check("pwhash_verify", alg, p, pw, phc))
        print("  verify wrong   ", ns.check("pwhash_verify", alg, p, b"battery", phc))
    elif kind == "aead":
        key = ns.random(pick(info, "key", 32))
        nonce = ns.random(pick(info, "nonce", 12))
        ct = ns.call("aead_seal", alg, p, key, nonce, b"header", b"attack at dawn")[0]
        show("ciphertext", ct)
        pt = ns.call("aead_open", alg, p, key, nonce, b"header", ct)[0]
        print("  round trip     ", "OK" if pt == b"attack at dawn" else "FAILED")
        try:
            ns.call("aead_open", alg, p, key, nonce, b"header", tamper(ct))
            print("  tampered       ", "ACCEPTED (bug!)")
        except NextSSLError as e:
            print(f"  tampered        rejected: {e.args[0]}")
    elif kind == "blockcipher":
        key = ns.random(pick(info, "key", 32))
        block = bytes(range(info["sizes"]["block"]["min"]))
        ct = ns.call("blockcipher_encrypt", alg, p, key, block)[0]
        show("encrypted", ct)
        print("  round trip     ", "OK" if ns.call("blockcipher_decrypt", alg, p, key, ct)[0] == block else "FAILED")
    elif kind == "streamcipher":
        key = ns.random(pick(info, "key", 32))
        nonce = ns.random(pick(info, "nonce", 12))
        ct = ns.call("stream_apply", alg, p, key, nonce, b"stream me")[0]
        show("ciphertext", ct)
        print("  round trip     ", "OK" if ns.call("stream_apply", alg, p, key, nonce, ct)[0] == b"stream me" else "FAILED")
    elif kind == "blockmode":
        key = ns.random(pick(info, "key", 32))
        nonce = ns.random(pick(info, "nonce", 16))
        data = bytes(range(64))
        if info["family"] == "aes-fpe":
            data = bytes(i % 10 for i in range(32))  # format-preserving: one digit (< radix) per byte
        ct = ns.call("blockmode_encrypt", alg, p, key, nonce, data)[0]
        show("ciphertext", ct)
        print("  round trip     ", "OK" if ns.call("blockmode_decrypt", alg, p, key, nonce, ct)[0] == data else "FAILED")
    elif kind == "kem":
        pk, sk = ns.call("kem_keygen", alg, p, outs=2)
        ct, ss = ns.call("kem_encaps", alg, p, pk, outs=2)
        ss2 = ns.call("kem_decaps", alg, p, sk, ct)[0]
        show("public key", pk)
        show("ciphertext", ct)
        show("shared secret", ss)
        print("  secrets equal  ", ss == ss2)
    elif kind == "kex":
        pa, sa = ns.call("kex_keygen", alg, p, outs=2)
        pb, sb = ns.call("kex_keygen", alg, p, outs=2)
        s1 = ns.call("kex_agree", alg, p, sa, pb)[0]
        s2 = ns.call("kex_agree", alg, p, sb, pa)[0]
        show("shared secret", s1)
        print("  both sides equal", s1 == s2)
    elif kind == "sign":
        pk, sk = ns.call("sign_keygen", alg, p, outs=2)
        sig = ns.call("sign_detached", alg, p, sk, b"sign this", b"")[0]
        show("public key", pk)
        show("signature", sig)
        print("  verify         ", ns.check("verify_detached", alg, p, pk, b"sign this", b"", sig))
        print("  wrong message  ", ns.check("verify_detached", alg, p, pk, b"sign that", b"", sig))
    elif kind == "rng":
        show("random(16)", ns.call("rng_fill", alg, p, 16)[0])
    elif kind == "drbg":
        h = ns.new_handle("drbg_new", alg, p, ns.random(pick(info, "seed", 48)), ns.random(16), b"nextssl-demo")
        try:
            a = ns.call("drbg_generate", U64(h), b"", 32)[0]
            b = ns.call("drbg_generate", U64(h), b"", 32)[0]
        finally:
            ns.call("drbg_free", U64(h), outs=0)
        show("generate #1", a)
        show("generate #2", b)
    elif kind == "pke":
        pk, sk = ns.call("pke_keygen", alg, p, outs=2)
        ct = ns.call("pke_encrypt", alg, p, pk, b"public-key message", b"")[0]
        show("ciphertext", ct)
        print("  round trip     ", ns.call("pke_decrypt", alg, p, sk, ct, b"")[0] == b"public-key message")
    elif kind == "statefulsign":
        pk, st = ns.call("stateful_keygen", alg, p, outs=2)
        for i in range(2):
            sig, st = ns.call("stateful_sign", alg, p, st, f"message {i}".encode(), outs=2)
            ok = ns.check("stateful_verify", alg, p, pk, f"message {i}".encode(), sig)
            rem = ctypes.c_uint64()
            mx = ctypes.c_uint64()
            fn = ns._fn("stateful_remaining")
            keep = []
            rc = fn(ns._arg(alg, keep), ns._arg(p, keep), ns._arg(st, keep), ctypes.byref(rem), ctypes.byref(mx))
            print(f"  signature {i}: verifies={ok}, signatures left {rem.value}/{mx.value} (rc {rc})")
        print("  note: the new state must be stored before the signature is used")
    elif kind == "pake":
        h = [None, None]
        queue = [[], []]  # messages waiting for party 0 and party 1
        for role in (0, 1):
            h[role], first = _pake_start(ns, alg, p, role)
            if first:
                queue[1 - role].append(first)
        secret = [None, None]
        rounds = 0
        while (secret[0] is None or secret[1] is None) and rounds < 16:
            moved = False
            for me in (0, 1):
                if secret[me] is None and queue[me]:
                    msg = queue[me].pop(0)
                    done, out, ss = _pake_step(ns, h[me], msg)
                    moved = True
                    if out:
                        queue[1 - me].append(out)
                    if done:
                        secret[me] = ss
            rounds += 1
            if not moved:
                break
        if secret[0] is None or secret[1] is None:
            raise RuntimeError("PAKE did not finish")
        show("shared secret A", secret[0])
        show("shared secret B", secret[1])
        print("  equal          ", secret[0] == secret[1])
    elif kind == "threshold":
        secret = b"split me three ways"
        packed = ns.call("threshold_split", alg, p, secret, 3, 5)[0]
        shares = _unpack(packed)
        print(f"  split into {len(shares)} shares of {len(shares[0])} bytes, any 3 rebuild the secret")
        sub = _pack(shares[1:4])
        print("  3 shares       ", ns.call("threshold_combine", alg, p, sub)[0] == secret)
    elif kind == "vdf":
        out, proof = ns.call("vdf_eval", alg, p, b"challenge", U64(16), outs=2)
        show("output", out)
        print("  verify         ", ns.check("vdf_verify", alg, p, b"challenge", U64(16), out, proof))
    else:
        print(f"  no demo for kind '{kind}' in this example (kind needs scheme-specific encodings: "
              f"see docs/bindings/python.md); the C functions are {info['ops']}")


def _pack(items):
    return b"".join(len(i).to_bytes(4, "little") + i for i in items)


def _unpack(buf):
    out, i = [], 0
    while i < len(buf):
        n = int.from_bytes(buf[i:i + 4], "little")
        out.append(buf[i + 4:i + 4 + n])
        i += 4 + n
    return out


def _pake_start(ns, alg, p, role):
    h = ctypes.c_uint64(0)
    cap = 4096
    buf = ctypes.create_string_buffer(cap)
    out = _Out(ctypes.cast(buf, ctypes.c_void_p), cap, 0)
    fn = ns._fn("pake_start")
    keep = []
    rc = fn(ns._arg(alg, keep), ns._arg(p, keep), ctypes.c_uint32(role), ns._arg(b"hunter2", keep),
            ns._arg(b"nextssl-demo", keep), ctypes.byref(h), ctypes.byref(out))
    if rc != OK:
        raise NextSSLError(rc, ns.message(rc), "pake_start")
    return h.value, bytes(buf.raw[: out.len])


def _pake_step(ns, handle, peer_msg):
    """One PAKE step. Returns (done, message_for_peer, shared_secret_or_empty)."""
    caps = [65536, 65536]
    bufs = [ctypes.create_string_buffer(c) for c in caps]
    outs = [_Out(ctypes.cast(b, ctypes.c_void_p), c, 0) for b, c in zip(bufs, caps)]
    done = ctypes.c_uint32(0)
    fn = ns._fn("pake_step")
    keep = []
    rc = fn(ctypes.c_uint64(handle), ns._arg(peer_msg, keep), ctypes.byref(outs[0]), ctypes.byref(outs[1]),
            ctypes.byref(done))
    if rc != OK:
        raise NextSSLError(rc, ns.message(rc), "pake_step")
    return bool(done.value), bytes(bufs[0].raw[: outs[0].len]), bytes(bufs[1].raw[: outs[1].len])


def listing(ns, kind):
    algs = ns.algorithms(kind)
    print(f"{'id':<34}{'kind':<14}{'tier':<11}access")
    for a in algs:
        access = "safe" if a["safe_api"] else "root"
        print(f"{a['id']:<34}{a['kind']:<14}{a['tier']:<11}{access}")
    kinds = {}
    for a in algs:
        kinds[a["kind"]] = kinds.get(a["kind"], 0) + 1
    print(f"\n{len(algs)} algorithms, ABI v{ns.lib.nextssl_abi_version()}, library {ns.lib.nextssl_version().decode()}")
    print("kinds:", ", ".join(f"{k}={n}" for k, n in sorted(kinds.items())))


def run_all(ns, kind):
    """Runs the demo for every algorithm (or one kind) and prints a summary. Uses the root API."""
    import contextlib
    import io
    ns.root = True
    ok, bad, nodemo = 0, [], []
    for a in ns.algorithms(kind):
        buf = io.StringIO()
        t0 = time.time()
        try:
            with contextlib.redirect_stdout(buf):
                demo(ns, a, auto_params(a))
            text = buf.getvalue()
            if "no demo for kind" in text:
                nodemo.append(a["id"])
            elif any(w in text for w in ("FAILED", "ACCEPTED", "MISMATCH", "equal   False", "equal False")):
                bad.append((a["id"], "wrong result: " + text.strip().splitlines()[-1]))
            else:
                ok += 1
        except Exception as e:  # report every failure, keep going
            bad.append((a["id"], f"{a['kind']}: {e}"))
        if time.time() - t0 > 20:
            print(f"  slow: {a['id']} took {time.time() - t0:.1f}s")
    print(f"demo ok: {ok}   no demo for kind: {len(nodemo)}   failed: {len(bad)}")
    for name, why in bad:
        print(f"  FAIL {name}: {why}")
    for name in nodemo:
        print(f"  no demo: {name}")
    return 1 if bad else 0


def main(argv):
    root = "--root" in argv
    argv = [a for a in argv if a != "--root"]
    params = None
    if "--params" in argv:
        i = argv.index("--params")
        params = argv[i + 1]
        del argv[i:i + 2]
    ns = NextSSL(root=root)
    if not argv or argv[0] in ("--list", "-l"):
        listing(ns, argv[1] if len(argv) > 1 else None)
        return 0
    if argv[0] == "--all":
        return run_all(ns, argv[1] if len(argv) > 1 else None)
    if argv[0] == "--info":
        print(json.dumps(ns.info(argv[1]), indent=2))
        return 0
    info = ns.info(argv[0])
    params = params or auto_params(info)
    print(f"{info['id']}  kind={info['kind']}  tier={info['tier']}  license={info['license']}"
          f"  api={'safe' if info['safe_api'] else 'root only'}")
    try:
        demo(ns, info, params)
    except NextSSLError as e:
        print(f"  error: {e}")
        if e.code == 3 and not root:
            print("  this tier is not reachable from the safe API; rerun with --root to accept the risk")
        return e.code
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
