// NextSSL from Java (Panama foreign function API, JDK 22 or newer). One file: a small binding
// plus a demo per algorithm kind. Run it straight from source:
//
//   java --enable-native-access=ALL-UNNAMED NextSSLDemo.java                 list all algorithms
//   java --enable-native-access=ALL-UNNAMED NextSSLDemo.java --list kem      list one kind
//   java --enable-native-access=ALL-UNNAMED NextSSLDemo.java sha256          demo (safe API)
//   java --enable-native-access=ALL-UNNAMED NextSSLDemo.java --root md5      other tiers need --root
//   java --enable-native-access=ALL-UNNAMED NextSSLDemo.java --info ml-kem-768
//
// The library is found through NEXTSSL_LIB or ../../target/{release,debug}. Every operation is a
// call into the NextSSL C ABI; nothing here implements cryptography. size_t is taken as 64-bit.

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class NextSSLDemo {
    static final int OK = 0, ERR_BAD_OUTPUT_LEN = 10, ERR_AUTH_FAILED = 14;

    /** A non-zero NEXTSSL_ERR_* code. */
    static final class NextSSLError extends RuntimeException {
        final int code;

        NextSSLError(int code, String message, String op) {
            super(op + ": " + message + " (code " + code + ")");
            this.code = code;
        }
    }

    // ------------------------------------------------------------------------------------------
    // Binding
    // ------------------------------------------------------------------------------------------

    /** Minimal wrapper over the C ABI. root = true uses the nextssl_root_* entry points. */
    static final class NextSSL {
        final Linker linker = Linker.nativeLinker();
        final Arena libArena = Arena.ofAuto();
        final SymbolLookup lookup;
        final boolean root;
        final Map<String, MethodHandle> handles = new HashMap<>();

        NextSSL(Path lib, boolean root) {
            this.lookup = SymbolLookup.libraryLookup(lib, libArena);
            this.root = root;
        }

        MethodHandle handle(String fullName, String sig, int outs) {
            return handles.computeIfAbsent(fullName + "/" + sig + "/" + outs, k -> {
                List<java.lang.foreign.MemoryLayout> params = new ArrayList<>();
                for (char c : sig.toCharArray()) {
                    params.add(switch (c) {
                        case 't', 'b' -> ValueLayout.ADDRESS;
                        case 'z', 'q' -> ValueLayout.JAVA_LONG;
                        case 'u' -> ValueLayout.JAVA_INT;
                        default -> throw new IllegalArgumentException("bad signature letter " + c);
                    });
                }
                for (int i = 0; i < outs; i++) params.add(ValueLayout.ADDRESS);
                MemorySegment sym = lookup.find(fullName).orElseThrow(
                        () -> new NextSSLError(3, "no such function (root-only operations need --root)", fullName));
                return linker.downcallHandle(sym,
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, params.toArray(new java.lang.foreign.MemoryLayout[0])));
            });
        }

        String message(int code) {
            try {
                MethodHandle h = linker.downcallHandle(lookup.find("nextssl_error_message").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
                MemorySegment s = (MemorySegment) h.invokeExact(code);
                return s.reinterpret(256).getString(0);
            } catch (Throwable t) {
                throw new RuntimeException(t);
            }
        }

        String staticString(String fn) {
            try {
                MethodHandle h = linker.downcallHandle(lookup.find(fn).orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.ADDRESS));
                MemorySegment s = (MemorySegment) h.invokeExact();
                return s.reinterpret(64).getString(0);
            } catch (Throwable t) {
                throw new RuntimeException(t);
            }
        }

        /**
         * Calls nextssl_[root_]op. sig has one letter per argument before the outputs:
         * t = C string (null allowed), b = bytes (nextssl_in), z = size_t, u = uint32, q = uint64.
         * Returns the output byte arrays (buffers grow automatically).
         */
        byte[][] call(String op, String sig, Object[] args, int outs, int... okCodes) {
            String name = (root ? "nextssl_root_" : "nextssl_") + op;
            MethodHandle h = handle(name, sig, outs);
            long[] caps = new long[outs];
            Arrays.fill(caps, 256);
            while (true) {
                try (Arena a = Arena.ofConfined()) {
                    List<Object> all = new ArrayList<>();
                    for (int i = 0; i < sig.length(); i++) {
                        Object v = args[i];
                        all.add(switch (sig.charAt(i)) {
                            case 't' -> v == null ? MemorySegment.NULL : a.allocateFrom((String) v);
                            case 'b' -> inStruct(a, (byte[]) v);
                            case 'z', 'q' -> ((Number) v).longValue();
                            case 'u' -> ((Number) v).intValue();
                            default -> throw new IllegalArgumentException();
                        });
                    }
                    MemorySegment[] bufs = new MemorySegment[outs];
                    MemorySegment[] structs = new MemorySegment[outs];
                    for (int i = 0; i < outs; i++) {
                        bufs[i] = a.allocate(Math.max(caps[i], 1));
                        structs[i] = a.allocate(24, 8);
                        structs[i].set(ValueLayout.ADDRESS, 0, bufs[i]);
                        structs[i].set(ValueLayout.JAVA_LONG, 8, caps[i]);
                        structs[i].set(ValueLayout.JAVA_LONG, 16, 0L);
                        all.add(structs[i]);
                    }
                    int rc = (int) h.invokeWithArguments(all);
                    if (rc == ERR_BAD_OUTPUT_LEN) {
                        for (int i = 0; i < outs; i++) caps[i] = Math.max(structs[i].get(ValueLayout.JAVA_LONG, 16), 1);
                        continue;
                    }
                    boolean ok = rc == OK;
                    for (int c : okCodes) ok |= rc == c;
                    if (!ok) throw new NextSSLError(rc, message(rc), op);
                    byte[][] res = new byte[outs][];
                    for (int i = 0; i < outs; i++) {
                        long n = structs[i].get(ValueLayout.JAVA_LONG, 16);
                        res[i] = bufs[i].asSlice(0, n).toArray(ValueLayout.JAVA_BYTE);
                    }
                    if (outs == 0) return new byte[][] {new byte[] {(byte) rc}};
                    return res;
                } catch (NextSSLError e) {
                    throw e;
                } catch (Throwable t) {
                    throw new RuntimeException(t);
                }
            }
        }

        static MemorySegment inStruct(Arena a, byte[] bytes) {
            MemorySegment s = a.allocate(16, 8);
            if (bytes.length > 0) {
                MemorySegment buf = a.allocate(bytes.length);
                buf.copyFrom(MemorySegment.ofArray(bytes));
                s.set(ValueLayout.ADDRESS, 0, buf);
            } else {
                s.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);
            }
            s.set(ValueLayout.JAVA_LONG, 8, (long) bytes.length);
            return s;
        }

        /** Verify-style call: true when valid, false for AUTHENTICATION_FAILED, throws otherwise. */
        boolean check(String op, String sig, Object[] args) {
            return call(op, sig, args, 0, ERR_AUTH_FAILED)[0][0] == OK;
        }

        byte[] random(int n) {
            return call("rng_fill", "ttz", new Object[] {"os-entropy", null, (long) n}, 1)[0];
        }

        Map<String, Object> json(String fn, String arg) {
            long cap = 1;
            while (true) {
                try (Arena a = Arena.ofConfined()) {
                    MethodHandle h = linker.downcallHandle(lookup.find(fn).orElseThrow(),
                            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
                    MemorySegment buf = a.allocate(cap);
                    MemorySegment out = a.allocate(24, 8);
                    out.set(ValueLayout.ADDRESS, 0, buf);
                    out.set(ValueLayout.JAVA_LONG, 8, cap);
                    out.set(ValueLayout.JAVA_LONG, 16, 0L);
                    MemorySegment argSeg = arg == null ? MemorySegment.NULL : a.allocateFrom(arg);
                    int rc = (int) h.invokeExact(argSeg, out);
                    if (rc == ERR_BAD_OUTPUT_LEN) {
                        cap = out.get(ValueLayout.JAVA_LONG, 16);
                        continue;
                    }
                    if (rc != OK) throw new NextSSLError(rc, message(rc), fn);
                    long n = out.get(ValueLayout.JAVA_LONG, 16);
                    String text = new String(buf.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE), StandardCharsets.UTF_8);
                    @SuppressWarnings("unchecked")
                    Map<String, Object> m = (Map<String, Object>) new Json(text).parse();
                    return m;
                } catch (NextSSLError e) {
                    throw e;
                } catch (Throwable t) {
                    throw new RuntimeException(t);
                }
            }
        }

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> algorithms(String kind) {
            return (List<Map<String, Object>>) json("nextssl_algorithms_json", kind).get("algorithms");
        }

        Map<String, Object> info(String name) {
            return json("nextssl_algorithm_info_json", name);
        }
    }

    /** Tiny JSON reader (the library's discovery output is plain JSON; Java has no built-in parser). */
    static final class Json {
        final String s;
        int i;

        Json(String s) {
            this.s = s;
        }

        Object parse() {
            Object v = value();
            ws();
            if (i != s.length()) throw new IllegalStateException("trailing JSON");
            return v;
        }

        void ws() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        }

        Object value() {
            ws();
            char c = s.charAt(i);
            if (c == '{') {
                i++;
                Map<String, Object> m = new java.util.LinkedHashMap<>();
                ws();
                if (s.charAt(i) == '}') { i++; return m; }
                while (true) {
                    ws();
                    String k = string();
                    ws();
                    i++; // ':'
                    m.put(k, value());
                    ws();
                    if (s.charAt(i++) == '}') return m;
                }
            }
            if (c == '[') {
                i++;
                List<Object> l = new ArrayList<>();
                ws();
                if (s.charAt(i) == ']') { i++; return l; }
                while (true) {
                    l.add(value());
                    ws();
                    if (s.charAt(i++) == ']') return l;
                }
            }
            if (c == '"') return string();
            if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
            if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            if (s.startsWith("null", i)) { i += 4; return null; }
            int j = i;
            while (j < s.length() && "+-0123456789.eE".indexOf(s.charAt(j)) >= 0) j++;
            Long n = Long.parseLong(s.substring(i, j));
            i = j;
            return n;
        }

        String string() {
            StringBuilder b = new StringBuilder();
            i++; // opening quote
            while (s.charAt(i) != '"') {
                char c = s.charAt(i++);
                if (c == '\\') {
                    char e = s.charAt(i++);
                    switch (e) {
                        case 'n' -> b.append('\n');
                        case 't' -> b.append('\t');
                        case 'r' -> b.append('\r');
                        case 'u' -> { b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; }
                        default -> b.append(e);
                    }
                } else {
                    b.append(c);
                }
            }
            i++;
            return b.toString();
        }
    }

    // ------------------------------------------------------------------------------------------
    // Demo
    // ------------------------------------------------------------------------------------------

    static final HexFormat HEX = HexFormat.of();
    static final Map<String, String> KNOWN_ABC = Map.of(
            "sha256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "sha1", "a9993e364706816aba3e25717850c26c9cd0d89d",
            "md5", "900150983cd24fb0d6963f7d28e17f72");

    static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static int pick(Map<String, Object> info, String field, int prefer) {
        @SuppressWarnings("unchecked")
        Map<String, Object> sizes = (Map<String, Object>) info.get("sizes");
        @SuppressWarnings("unchecked")
        Map<String, Object> r = (Map<String, Object>) sizes.get(field);
        if (r == null) return prefer;
        return (int) Math.max((Long) r.get("min"), Math.min(prefer, (Long) r.get("max")));
    }

    static void show(String label, byte[] d) {
        String h = HEX.formatHex(d);
        System.out.printf("  %-14s %s (%d bytes)%n", label, h.length() <= 96 ? h : h.substring(0, 96) + "...", d.length);
    }

    static byte[] tamper(byte[] x) {
        byte[] y = x.clone();
        y[0] ^= 1;
        return y;
    }

    static void demo(NextSSL ns, Map<String, Object> info, String p) {
        String alg = (String) info.get("id");
        String kind = (String) info.get("kind");
        switch (kind) {
            case "hash" -> {
                byte[] d = ns.call("hash_with", "ttb", new Object[] {alg, p, b("abc")}, 1)[0];
                show("digest(abc)", d);
                String want = KNOWN_ABC.get(alg);
                System.out.println(want == null ? "  known answer    (none built into this example)"
                        : "  known answer    " + (HEX.formatHex(d).equals(want) ? "MATCH" : "MISMATCH (expected " + want + ")"));
            }
            case "xof" -> show("xof(abc,48)", ns.call("xof", "ttbz", new Object[] {alg, p, b("abc"), 48L}, 1)[0]);
            case "checksum" -> {
                byte[] c = ns.call("checksum", "ttb", new Object[] {alg, p, b("123456789")}, 1)[0];
                show("check", c);
                if (alg.equals("crc32")) {
                    System.out.println("  known answer    " + (HEX.formatHex(c).equals("cbf43926") ? "MATCH" : "MISMATCH (expected cbf43926)"));
                }
            }
            case "encoding" -> {
                byte[] raw = {0, 'h', 'i', (byte) 0xff, 1, 2, 3};
                byte[] e = ns.call("encode_with", "ttb", new Object[] {alg, p, raw}, 1)[0];
                System.out.println("  encoded         " + new String(e, StandardCharsets.UTF_8));
                byte[] back = ns.call("decode_with", "ttb", new Object[] {alg, p, e}, 1)[0];
                System.out.println("  round trip      " + (Arrays.equals(back, raw) ? "OK" : "FAILED"));
            }
            case "mac" -> {
                byte[] key = ns.random(pick(info, "key", 32));
                byte[] tag = ns.call("mac", "ttbbz", new Object[] {alg, p, key, b("abc"), 0L}, 1)[0];
                show("tag", tag);
                System.out.println("  verify          " + ns.check("mac_verify", "ttbbb", new Object[] {alg, p, key, b("abc"), tag}));
                System.out.println("  verify tampered " + ns.check("mac_verify", "ttbbb", new Object[] {alg, p, key, b("abc"), tamper(tag)}));
            }
            case "kdf" -> {
                byte[] ikm = ns.random(pick(info, "key", 32));
                show("derived(32)", ns.call("kdf", "ttbbbz", new Object[] {alg, p, ikm, b("salt-16-bytes!!!"), b("ctx"), 32L}, 1)[0]);
            }
            case "aead" -> {
                byte[] key = ns.random(pick(info, "key", 32));
                byte[] nonce = ns.random(pick(info, "nonce", 12));
                byte[] ct = ns.call("aead_seal", "ttbbbb", new Object[] {alg, p, key, nonce, b("header"), b("attack at dawn")}, 1)[0];
                show("ciphertext", ct);
                byte[] pt = ns.call("aead_open", "ttbbbb", new Object[] {alg, p, key, nonce, b("header"), ct}, 1)[0];
                System.out.println("  round trip      " + (Arrays.equals(pt, b("attack at dawn")) ? "OK" : "FAILED"));
                try {
                    ns.call("aead_open", "ttbbbb", new Object[] {alg, p, key, nonce, b("header"), tamper(ct)}, 1);
                    System.out.println("  tampered        ACCEPTED (bug!)");
                } catch (NextSSLError e) {
                    System.out.println("  tampered        rejected: " + e.getMessage());
                }
            }
            case "kem" -> {
                byte[][] kp = ns.call("kem_keygen", "tt", new Object[] {alg, p}, 2);
                byte[][] enc = ns.call("kem_encaps", "ttb", new Object[] {alg, p, kp[0]}, 2);
                byte[] ss2 = ns.call("kem_decaps", "ttbb", new Object[] {alg, p, kp[1], enc[0]}, 1)[0];
                show("public key", kp[0]);
                show("ciphertext", enc[0]);
                show("shared secret", enc[1]);
                System.out.println("  secrets equal   " + Arrays.equals(enc[1], ss2));
            }
            case "kex" -> {
                byte[][] a = ns.call("kex_keygen", "tt", new Object[] {alg, p}, 2);
                byte[][] c = ns.call("kex_keygen", "tt", new Object[] {alg, p}, 2);
                byte[] s1 = ns.call("kex_agree", "ttbb", new Object[] {alg, p, a[1], c[0]}, 1)[0];
                byte[] s2 = ns.call("kex_agree", "ttbb", new Object[] {alg, p, c[1], a[0]}, 1)[0];
                show("shared secret", s1);
                System.out.println("  both sides equal " + Arrays.equals(s1, s2));
            }
            case "sign" -> {
                byte[][] kp = ns.call("sign_keygen", "tt", new Object[] {alg, p}, 2);
                byte[] sig = ns.call("sign_detached", "ttbbb", new Object[] {alg, p, kp[1], b("sign this"), new byte[0]}, 1)[0];
                show("public key", kp[0]);
                show("signature", sig);
                System.out.println("  verify          " + ns.check("verify_detached", "ttbbbb", new Object[] {alg, p, kp[0], b("sign this"), new byte[0], sig}));
                System.out.println("  wrong message   " + ns.check("verify_detached", "ttbbbb", new Object[] {alg, p, kp[0], b("sign that"), new byte[0], sig}));
            }
            case "rng" -> show("random(16)", ns.call("rng_fill", "ttz", new Object[] {alg, p, 16L}, 1)[0]);
            default -> System.out.println("  no demo for kind '" + kind + "' in the Java example (the Python example covers every kind);\n"
                    + "  its C functions are: " + info.get("ops"));
        }
    }

    static Path findLibrary() {
        String env = System.getenv("NEXTSSL_LIB");
        if (env != null && !env.isEmpty()) return Path.of(env);
        String os = System.getProperty("os.name").toLowerCase();
        String name = os.contains("win") ? "nextssl_ffi.dll" : os.contains("mac") ? "libnextssl_ffi.dylib" : "libnextssl_ffi.so";
        for (String profile : new String[] {"release", "debug"}) {
            Path p = Path.of("..", "..", "target", profile, name).toAbsolutePath().normalize();
            if (Files.isRegularFile(p)) return p;
        }
        System.err.println("libnextssl_ffi not found: build it (cargo build -p nextssl-ffi --release) or set NEXTSSL_LIB");
        System.exit(2);
        return null;
    }

    static void listing(NextSSL ns, String kind) {
        List<Map<String, Object>> algs = ns.algorithms(kind);
        System.out.printf("%-34s%-14s%-11s%s%n", "id", "kind", "tier", "access");
        Map<String, Integer> kinds = new TreeMap<>();
        for (Map<String, Object> a : algs) {
            System.out.printf("%-34s%-14s%-11s%s%n", a.get("id"), a.get("kind"), a.get("tier"),
                    Boolean.TRUE.equals(a.get("safe_api")) ? "safe" : "root");
            kinds.merge((String) a.get("kind"), 1, Integer::sum);
        }
        StringBuilder k = new StringBuilder();
        kinds.forEach((key, n) -> k.append(k.length() > 0 ? ", " : "").append(key).append('=').append(n));
        System.out.printf("%n%d algorithms, ABI v%s, library %s%nkinds: %s%n", algs.size(), "1", ns.staticString("nextssl_version"), k);
    }

    public static void main(String[] argv) {
        List<String> args = new ArrayList<>(List.of(argv));
        boolean root = args.remove("--root");
        String params = null;
        int pi = args.indexOf("--params");
        if (pi >= 0) {
            params = args.get(pi + 1);
            args.subList(pi, pi + 2).clear();
        }
        NextSSL ns = new NextSSL(findLibrary(), root);
        if (args.isEmpty() || args.get(0).equals("--list") || args.get(0).equals("-l")) {
            listing(ns, args.size() > 1 ? args.get(1) : null);
            return;
        }
        if (args.get(0).equals("--info")) {
            System.out.println(ns.info(args.get(1)));
            return;
        }
        Map<String, Object> info = ns.info(args.get(0));
        System.out.printf("%s  kind=%s  tier=%s  license=%s  api=%s%n", info.get("id"), info.get("kind"), info.get("tier"),
                info.get("license"), Boolean.TRUE.equals(info.get("safe_api")) ? "safe" : "root only");
        try {
            demo(ns, info, params);
        } catch (NextSSLError e) {
            System.out.println("  error: " + e.getMessage());
            if (e.code == 3 && !root) {
                System.out.println("  this tier is not reachable from the safe API; rerun with --root to accept the risk");
            }
            System.exit(e.code);
        }
    }
}
