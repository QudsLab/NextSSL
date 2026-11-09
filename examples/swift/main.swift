// NextSSL from Swift. One file: a small dlopen/dlsym binding plus a demo per algorithm kind.
// No header or module map is needed; the C ABI structs are mirrored below.
//
//   swiftc -O -swift-version 5 main.swift -o nextssl_demo
//   ./nextssl_demo                     list all algorithms
//   ./nextssl_demo --list kem          list one kind
//   ./nextssl_demo sha256              run the demo for an algorithm (safe API)
//   ./nextssl_demo --root md5          other tiers need --root
//   ./nextssl_demo --info ml-kem-768
//
// The library is found through NEXTSSL_LIB or ../../target/{release,debug}. Every operation is a
// call into the NextSSL C ABI; nothing here implements cryptography.

import Foundation

// MARK: - C ABI mirror

struct NIn {
    var ptr: UnsafePointer<UInt8>?
    var len: Int
}

struct NOut {
    var ptr: UnsafeMutablePointer<UInt8>?
    var cap: Int
    var len: Int
}

typealias CS = UnsafePointer<CChar>
typealias PIn = UnsafePointer<NIn>
typealias POut = UnsafeMutablePointer<NOut>
// @convention(c) cannot mention Swift structs, so the C function types take raw pointers; Swift
// converts a typed pointer to a raw one implicitly at the call.
typealias RIn = UnsafeRawPointer
typealias ROut = UnsafeMutableRawPointer

// One function type per call shape: (alg, params, inputs..., size?, outputs...) -> status.
typealias FData = @convention(c) (CS, CS?, RIn, ROut) -> Int32
typealias FXof = @convention(c) (CS, CS?, RIn, Int, ROut) -> Int32
typealias FMac = @convention(c) (CS, CS?, RIn, RIn, Int, ROut) -> Int32
typealias FIn3 = @convention(c) (CS, CS?, RIn, RIn, RIn) -> Int32
typealias FKdf = @convention(c) (CS, CS?, RIn, RIn, RIn, Int, ROut) -> Int32
typealias FAead = @convention(c) (CS, CS?, RIn, RIn, RIn, RIn, ROut) -> Int32
typealias FKeygen = @convention(c) (CS, CS?, ROut, ROut) -> Int32
typealias FEncaps = @convention(c) (CS, CS?, RIn, ROut, ROut) -> Int32
typealias FIn2Out = @convention(c) (CS, CS?, RIn, RIn, ROut) -> Int32
typealias FSign = @convention(c) (CS, CS?, RIn, RIn, RIn, ROut) -> Int32
typealias FIn4 = @convention(c) (CS, CS?, RIn, RIn, RIn, RIn) -> Int32
typealias FRng = @convention(c) (CS, CS?, Int, ROut) -> Int32
typealias FJson = @convention(c) (CS?, ROut) -> Int32

let ERR_BAD_OUTPUT_LEN: Int32 = 10
let ERR_AUTH_FAILED: Int32 = 14

struct NextSSLError: Error, CustomStringConvertible {
    let code: Int32
    let message: String
    let op: String
    var description: String { "\(op): \(message) (code \(code))" }
}

/// Owns the temporary C memory of one operation.
final class Scratch {
    private var blocks: [UnsafeMutableRawPointer] = []

    func input(_ bytes: [UInt8]) -> PIn {
        let s = UnsafeMutablePointer<NIn>.allocate(capacity: 1)
        blocks.append(UnsafeMutableRawPointer(s))
        if bytes.isEmpty {
            s.initialize(to: NIn(ptr: nil, len: 0))
        } else {
            let b = UnsafeMutablePointer<UInt8>.allocate(capacity: bytes.count)
            blocks.append(UnsafeMutableRawPointer(b))
            b.initialize(from: bytes, count: bytes.count)
            s.initialize(to: NIn(ptr: UnsafePointer(b), len: bytes.count))
        }
        return PIn(s)
    }

    func output(cap: Int) -> POut {
        let s = POut.allocate(capacity: 1)
        let b = UnsafeMutablePointer<UInt8>.allocate(capacity: max(cap, 1))
        blocks.append(UnsafeMutableRawPointer(s))
        blocks.append(UnsafeMutableRawPointer(b))
        s.initialize(to: NOut(ptr: b, cap: cap, len: 0))
        return s
    }

    deinit {
        for b in blocks {
            b.deallocate()
        }
    }
}

final class NextSSL {
    let handle: UnsafeMutableRawPointer
    let root: Bool

    init(path: String, root: Bool) {
        guard let h = dlopen(path, RTLD_NOW) else {
            FileHandle.standardError.write(Data("cannot load \(path): \(String(cString: dlerror()))\n".utf8))
            exit(2)
        }
        handle = h
        self.root = root
    }

    func sym<T>(_ op: String, _ type: T.Type, rootOnlyOk: Bool = false) throws -> T {
        let name = (root ? "nextssl_root_" : "nextssl_") + op
        guard let p = dlsym(handle, name) else {
            throw NextSSLError(code: 3, message: "no such function (root-only operations need --root)", op: op)
        }
        return unsafeBitCast(p, to: T.self)
    }

    func plain<T>(_ name: String, _ type: T.Type) -> T {
        guard let p = dlsym(handle, name) else { fatalError("missing symbol \(name)") }
        return unsafeBitCast(p, to: T.self)
    }

    func message(_ code: Int32) -> String {
        let f = plain("nextssl_error_message", (@convention(c) (Int32) -> UnsafePointer<CChar>).self)
        return String(cString: f(code))
    }

    func versionString() -> String {
        let f = plain("nextssl_version", (@convention(c) () -> UnsafePointer<CChar>).self)
        return String(cString: f())
    }

    /// Runs `body` with `outs` output buffers, growing them while the library reports BAD_OUTPUT_LEN.
    /// Status codes in `ok` are accepted besides 0.
    @discardableResult
    func run(_ op: String, outs: Int, ok: [Int32] = [], _ body: (Scratch, [POut]) -> Int32) throws -> [[UInt8]] {
        var caps = [Int](repeating: 256, count: outs)
        while true {
            let sc = Scratch()
            let os = caps.map { sc.output(cap: $0) }
            let rc = body(sc, os)
            if rc == ERR_BAD_OUTPUT_LEN {
                caps = os.map { max($0.pointee.len, 1) }
                continue
            }
            if rc != 0 && !ok.contains(rc) { throw NextSSLError(code: rc, message: message(rc), op: op) }
            lastStatus = rc
            return os.map { o in
                o.pointee.len == 0 ? [] : Array(UnsafeBufferPointer(start: o.pointee.ptr, count: o.pointee.len))
            }
        }
    }

    var lastStatus: Int32 = 0

    // Typed helpers over the shapes above.
    func data(_ op: String, _ alg: String, _ p: String?, _ d: [UInt8]) throws -> [UInt8] {
        let f: FData = try sym(op, FData.self)
        return try run(op, outs: 1) { sc, o in f(alg, p, sc.input(d), o[0]) }[0]
    }

    func xof(_ alg: String, _ p: String?, _ d: [UInt8], _ n: Int) throws -> [UInt8] {
        let f: FXof = try sym("xof", FXof.self)
        return try run("xof", outs: 1) { sc, o in f(alg, p, sc.input(d), n, o[0]) }[0]
    }

    func mac(_ alg: String, _ p: String?, _ key: [UInt8], _ d: [UInt8]) throws -> [UInt8] {
        let f: FMac = try sym("mac", FMac.self)
        return try run("mac", outs: 1) { sc, o in f(alg, p, sc.input(key), sc.input(d), 0, o[0]) }[0]
    }

    func macVerify(_ alg: String, _ p: String?, _ key: [UInt8], _ d: [UInt8], _ tag: [UInt8]) throws -> Bool {
        let f: FIn3 = try sym("mac_verify", FIn3.self)
        try run("mac_verify", outs: 0, ok: [ERR_AUTH_FAILED]) { sc, _ in f(alg, p, sc.input(key), sc.input(d), sc.input(tag)) }
        return lastStatus == 0
    }

    func kdf(_ alg: String, _ p: String?, _ ikm: [UInt8], _ salt: [UInt8], _ info: [UInt8], _ n: Int) throws -> [UInt8] {
        let f: FKdf = try sym("kdf", FKdf.self)
        return try run("kdf", outs: 1) { sc, o in f(alg, p, sc.input(ikm), sc.input(salt), sc.input(info), n, o[0]) }[0]
    }

    func aead(_ op: String, _ alg: String, _ p: String?, _ key: [UInt8], _ nonce: [UInt8], _ aad: [UInt8], _ d: [UInt8]) throws -> [UInt8] {
        let f: FAead = try sym(op, FAead.self)
        return try run(op, outs: 1) { sc, o in f(alg, p, sc.input(key), sc.input(nonce), sc.input(aad), sc.input(d), o[0]) }[0]
    }

    func keygen(_ op: String, _ alg: String, _ p: String?) throws -> (pk: [UInt8], sk: [UInt8]) {
        let f: FKeygen = try sym(op, FKeygen.self)
        let r = try run(op, outs: 2) { _, o in f(alg, p, o[0], o[1]) }
        return (r[0], r[1])
    }

    func encaps(_ alg: String, _ p: String?, _ pk: [UInt8]) throws -> (ct: [UInt8], ss: [UInt8]) {
        let f: FEncaps = try sym("kem_encaps", FEncaps.self)
        let r = try run("kem_encaps", outs: 2) { sc, o in f(alg, p, sc.input(pk), o[0], o[1]) }
        return (r[0], r[1])
    }

    func in2out(_ op: String, _ alg: String, _ p: String?, _ a: [UInt8], _ b: [UInt8]) throws -> [UInt8] {
        let f: FIn2Out = try sym(op, FIn2Out.self)
        return try run(op, outs: 1) { sc, o in f(alg, p, sc.input(a), sc.input(b), o[0]) }[0]
    }

    func sign(_ alg: String, _ p: String?, _ sk: [UInt8], _ msg: [UInt8]) throws -> [UInt8] {
        let f: FSign = try sym("sign_detached", FSign.self)
        return try run("sign_detached", outs: 1) { sc, o in f(alg, p, sc.input(sk), sc.input(msg), sc.input([]), o[0]) }[0]
    }

    func verify(_ alg: String, _ p: String?, _ pk: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) throws -> Bool {
        let f: FIn4 = try sym("verify_detached", FIn4.self)
        try run("verify_detached", outs: 0, ok: [ERR_AUTH_FAILED]) { sc, _ in
            f(alg, p, sc.input(pk), sc.input(msg), sc.input([]), sc.input(sig))
        }
        return lastStatus == 0
    }

    func rng(_ alg: String, _ p: String?, _ n: Int) throws -> [UInt8] {
        let f: FRng = try sym("rng_fill", FRng.self)
        return try run("rng_fill", outs: 1) { _, o in f(alg, p, n, o[0]) }[0]
    }

    func random(_ n: Int) throws -> [UInt8] { try rng("os-entropy", nil, n) }

    func json(_ fn: String, _ arg: String?) throws -> [String: Any] {
        let f: FJson = plain(fn, FJson.self)
        let bytes = try run(fn, outs: 1) { _, o in f(arg, o[0]) }[0]
        guard let obj = try JSONSerialization.jsonObject(with: Data(bytes)) as? [String: Any] else {
            throw NextSSLError(code: 9, message: "unexpected JSON", op: fn)
        }
        return obj
    }

    func algorithms(_ kind: String?) throws -> [[String: Any]] {
        (try json("nextssl_algorithms_json", kind))["algorithms"] as? [[String: Any]] ?? []
    }

    func info(_ name: String) throws -> [String: Any] { try json("nextssl_algorithm_info_json", name) }
}

// MARK: - Demo

let knownABC = [
    "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "sha1": "a9993e364706816aba3e25717850c26c9cd0d89d",
    "md5": "900150983cd24fb0d6963f7d28e17f72",
]

func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
func bytes(_ s: String) -> [UInt8] { Array(s.utf8) }
func tamper(_ b: [UInt8]) -> [UInt8] { var c = b; c[0] ^= 1; return c }

func pick(_ info: [String: Any], _ field: String, _ prefer: Int) -> Int {
    guard let sizes = info["sizes"] as? [String: Any], let r = sizes[field] as? [String: Any],
          let lo = r["min"] as? Int, let hi = r["max"] as? Int else { return prefer }
    return max(lo, min(prefer, hi))
}

func show(_ label: String, _ d: [UInt8]) {
    let h = hex(d)
    let shown = h.count <= 96 ? h : String(h.prefix(96)) + "..."
    print("  " + label.padding(toLength: 14, withPad: " ", startingAt: 0) + " \(shown) (\(d.count) bytes)")
}

func demo(_ ns: NextSSL, _ info: [String: Any], _ p: String?) throws {
    let alg = info["id"] as! String
    switch info["kind"] as! String {
    case "hash":
        let d = try ns.data("hash_with", alg, p, bytes("abc"))
        show("digest(abc)", d)
        if let want = knownABC[alg] {
            print("  known answer    " + (hex(d) == want ? "MATCH" : "MISMATCH (expected \(want))"))
        } else {
            print("  known answer    (none built into this example)")
        }
    case "xof":
        show("xof(abc,48)", try ns.xof(alg, p, bytes("abc"), 48))
    case "checksum":
        let c = try ns.data("checksum", alg, p, bytes("123456789"))
        show("check", c)
        if alg == "crc32" { print("  known answer    " + (hex(c) == "cbf43926" ? "MATCH" : "MISMATCH (expected cbf43926)")) }
    case "encoding":
        let raw: [UInt8] = [0, 104, 105, 255, 1, 2, 3]
        let e = try ns.data("encode_with", alg, p, raw)
        print("  encoded         " + String(decoding: e, as: UTF8.self))
        print("  round trip      " + (try ns.data("decode_with", alg, p, e) == raw ? "OK" : "FAILED"))
    case "mac":
        let key = try ns.random(pick(info, "key", 32))
        let tag = try ns.mac(alg, p, key, bytes("abc"))
        show("tag", tag)
        print("  verify          \(try ns.macVerify(alg, p, key, bytes("abc"), tag))")
        print("  verify tampered \(try ns.macVerify(alg, p, key, bytes("abc"), tamper(tag)))")
    case "kdf":
        let ikm = try ns.random(pick(info, "key", 32))
        show("derived(32)", try ns.kdf(alg, p, ikm, bytes("salt-16-bytes!!!"), bytes("ctx"), 32))
    case "aead":
        let key = try ns.random(pick(info, "key", 32))
        let nonce = try ns.random(pick(info, "nonce", 12))
        let ct = try ns.aead("aead_seal", alg, p, key, nonce, bytes("header"), bytes("attack at dawn"))
        show("ciphertext", ct)
        let pt = try ns.aead("aead_open", alg, p, key, nonce, bytes("header"), ct)
        print("  round trip      " + (pt == bytes("attack at dawn") ? "OK" : "FAILED"))
        do {
            _ = try ns.aead("aead_open", alg, p, key, nonce, bytes("header"), tamper(ct))
            print("  tampered        ACCEPTED (bug!)")
        } catch let e as NextSSLError {
            print("  tampered        rejected: \(e)")
        }
    case "kem":
        let kp = try ns.keygen("kem_keygen", alg, p)
        let enc = try ns.encaps(alg, p, kp.pk)
        let ss2 = try ns.in2out("kem_decaps", alg, p, kp.sk, enc.ct)
        show("public key", kp.pk)
        show("ciphertext", enc.ct)
        show("shared secret", enc.ss)
        print("  secrets equal   \(enc.ss == ss2)")
    case "kex":
        let a = try ns.keygen("kex_keygen", alg, p)
        let b = try ns.keygen("kex_keygen", alg, p)
        let s1 = try ns.in2out("kex_agree", alg, p, a.sk, b.pk)
        let s2 = try ns.in2out("kex_agree", alg, p, b.sk, a.pk)
        show("shared secret", s1)
        print("  both sides equal \(s1 == s2)")
    case "sign":
        let kp = try ns.keygen("sign_keygen", alg, p)
        let sig = try ns.sign(alg, p, kp.sk, bytes("sign this"))
        show("public key", kp.pk)
        show("signature", sig)
        print("  verify          \(try ns.verify(alg, p, kp.pk, bytes("sign this"), sig))")
        print("  wrong message   \(try ns.verify(alg, p, kp.pk, bytes("sign that"), sig))")
    case "rng":
        show("random(16)", try ns.rng(alg, p, 16))
    default:
        print("  no demo for kind '\(info["kind"] as! String)' in the Swift example (the Python example covers every kind);")
        print("  its C functions are: \((info["ops"] as? [String] ?? []).joined(separator: ", "))")
    }
}

func findLibrary() -> String {
    if let e = ProcessInfo.processInfo.environment["NEXTSSL_LIB"], !e.isEmpty { return e }
    #if os(macOS)
    let name = "libnextssl_ffi.dylib"
    #elseif os(Windows)
    let name = "nextssl_ffi.dll"
    #else
    let name = "libnextssl_ffi.so"
    #endif
    for profile in ["release", "debug"] {
        let p = FileManager.default.currentDirectoryPath + "/../../target/\(profile)/\(name)"
        if FileManager.default.fileExists(atPath: p) { return p }
    }
    FileHandle.standardError.write(Data("libnextssl_ffi not found: build it (cargo build -p nextssl-ffi --release) or set NEXTSSL_LIB\n".utf8))
    exit(2)
}

func listing(_ ns: NextSSL, _ kind: String?) throws {
    let algs = try ns.algorithms(kind)
    func pad(_ s: String, _ n: Int) -> String { s.padding(toLength: n, withPad: " ", startingAt: 0) }
    print(pad("id", 34) + pad("kind", 14) + pad("tier", 11) + "access")
    var kinds: [String: Int] = [:]
    for a in algs {
        let k = a["kind"] as! String
        print(pad(a["id"] as! String, 34) + pad(k, 14) + pad(a["tier"] as! String, 11) + ((a["safe_api"] as? Bool) == true ? "safe" : "root"))
        kinds[k, default: 0] += 1
    }
    let ks = kinds.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: ", ")
    print("\n\(algs.count) algorithms, library \(ns.versionString())\nkinds: \(ks)")
}

func mainEntry() -> Int32 {
    var args = Array(CommandLine.arguments.dropFirst())
    let root = args.contains("--root")
    args.removeAll { $0 == "--root" }
    var params: String? = nil
    if let i = args.firstIndex(of: "--params"), i + 1 < args.count {
        params = args[i + 1]
        args.removeSubrange(i...(i + 1))
    }
    let ns = NextSSL(path: findLibrary(), root: root)
    do {
        if args.isEmpty || args[0] == "--list" || args[0] == "-l" {
            try listing(ns, args.count > 1 ? args[1] : nil)
            return 0
        }
        if args[0] == "--info" {
            let data = try JSONSerialization.data(withJSONObject: try ns.info(args[1]), options: [.prettyPrinted, .sortedKeys])
            print(String(decoding: data, as: UTF8.self))
            return 0
        }
        let info = try ns.info(args[0])
        print("\(info["id"]!)  kind=\(info["kind"]!)  tier=\(info["tier"]!)  license=\(info["license"]!)  api=\((info["safe_api"] as? Bool) == true ? "safe" : "root only")")
        do {
            try demo(ns, info, params)
        } catch let e as NextSSLError {
            print("  error: \(e)")
            if e.code == 3 && !root { print("  this tier is not reachable from the safe API; rerun with --root to accept the risk") }
            return e.code
        }
    } catch {
        print("error: \(error)")
        return 1
    }
    return 0
}

exit(mainEntry())
