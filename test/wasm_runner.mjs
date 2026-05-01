/**
 * wasm_runner.mjs — Emscripten WASM test runner for NextSSL
 *
 * Usage (called from run_tests.py):
 *   node wasm_runner.mjs <path/to/nextssl.js>
 *
 * Reads a JSON array of test vectors from stdin:
 *   [{ algo, input_hex, expected_hex, label }, ...]
 *
 * Writes a JSON array of results to stdout:
 *   [{ label, status: "pass"|"fail"|"skip", msg? }, ...]
 *
 * The Emscripten build must export nextssl_init and nextssl_hash_compute.
 */
import { createRequire } from "module";
import { readFileSync } from "fs";
import { argv, stdin } from "process";

const jsPath = argv[2];
if (!jsPath) {
    process.stderr.write("Usage: node wasm_runner.mjs <path/to/nextssl.js>\n");
    process.exit(1);
}

// Read all stdin synchronously
function readStdin() {
    const chunks = [];
    try {
        const buf = readFileSync("/dev/stdin");
        return buf.toString("utf8");
    } catch {
        // Windows fallback
        return readFileSync(0, "utf8");
    }
}

const vectors = JSON.parse(readStdin());

// Load the Emscripten module.  The generated .js file typically does one of:
//   module.exports = factory          (CommonJS)
//   export default factory            (ESM — rare in Emscripten output)
// We use createRequire for CJS compatibility.
const require = createRequire(import.meta.url);
let factory;
try {
    factory = require(jsPath);
} catch (e) {
    process.stderr.write(`Failed to require ${jsPath}: ${e.message}\n`);
    process.exit(1);
}

// Emscripten factory may be a function (called to get the Module) or an object.
const Module = typeof factory === "function" ? await factory() : await factory;

// Wait for WASM to be ready (Module.ready or Module.onRuntimeInitialized)
if (Module.ready) {
    await Module.ready;
}

// Initialise the library
const rc_init = Module._nextssl_init ? Module._nextssl_init() : 0;
if (rc_init !== 0) {
    process.stderr.write(`nextssl_init() returned ${rc_init}\n`);
    process.exit(1);
}

// Helper: allocate a buffer in WASM heap, return pointer
function mallocBytes(bytes) {
    if (bytes.length === 0) return 0;
    const ptr = Module._malloc(bytes.length);
    Module.HEAPU8.set(bytes, ptr);
    return ptr;
}

function mallocSize(n) {
    return Module._malloc(n);
}

function readBytes(ptr, len) {
    return Buffer.from(Module.HEAPU8.subarray(ptr, ptr + len));
}

// MAX_DIGEST — large enough for any hash
const MAX_DIGEST = 1024;

const results = [];

for (const vec of vectors) {
    const { algo, input_hex, expected_hex, label } = vec;

    try {
        const input = Buffer.from(input_hex, "hex");
        const expected = Buffer.from(expected_hex, "hex");

        const algoPtr = Module.allocateUTF8 ? Module.allocateUTF8(algo) : (() => {
            const enc = new TextEncoder().encode(algo + "\0");
            const p = Module._malloc(enc.length);
            Module.HEAPU8.set(enc, p);
            return p;
        })();
        const dataPtr = mallocBytes(input);
        const outPtr = mallocSize(MAX_DIGEST);
        // out_len is a size_t stored at a pointer; allocate 8 bytes
        const outLenPtr = Module._malloc(8);
        // Write MAX_DIGEST as initial capacity (little-endian 64-bit)
        Module.HEAP32[outLenPtr >> 2] = MAX_DIGEST;
        Module.HEAP32[(outLenPtr >> 2) + 1] = 0;

        const rc = Module._nextssl_hash_compute(
            algoPtr, dataPtr, input.length, outPtr, outLenPtr
        );

        // Read back out_len
        const outLen = Module.HEAP32[outLenPtr >> 2];
        const got = readBytes(outPtr, outLen);

        Module._free(algoPtr);
        if (dataPtr) Module._free(dataPtr);
        Module._free(outPtr);
        Module._free(outLenPtr);

        if (rc !== 0) {
            results.push({ label, status: "fail", msg: `nextssl_hash_compute returned ${rc}` });
        } else if (got.equals(expected)) {
            results.push({ label, status: "pass" });
        } else {
            results.push({
                label, status: "fail",
                msg: `got ${got.toString("hex")} expected ${expected.toString("hex")}`,
            });
        }
    } catch (e) {
        results.push({ label, status: "fail", msg: String(e) });
    }
}

process.stdout.write(JSON.stringify(results) + "\n");
