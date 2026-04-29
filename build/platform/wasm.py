"""
build/platform/wasm.py — NextSSL WebAssembly build helper.

Called by root build.py. Do not invoke directly.
"""

import logging
import shutil
import subprocess
import sys
import time
from pathlib import Path

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT     = Path(__file__).resolve().parent.parent.parent
SRC      = ROOT / "src"
TEMP_DIR = ROOT / "temp"
WEB_OUT  = ROOT / "bin" / "web"

sys.path.insert(0, str(ROOT / "build" / "helpers"))
from c_parser import extract_api_declarations

# ─── Exported API symbols ─────────────────────────────────────────────────────

EXTRA_EXPORTED_FUNCTIONS = [
    # Memory management (required by Emscripten consumers)
    "_malloc",
    "_free",
]

WASM_ALLOWED_EXPORT_PREFIXES = (
    "nextssl_seed_",
    "nextssl_hash_",
    "nextssl_sym_",
    "nextssl_aead_",
    "nextssl_mac_",
    "nextssl_kdf_",
    "nextssl_modern_seed_",
    "nextssl_asym_",
    "nextssl_enc_",
    "nextssl_pow_",
    "nextssl_cost_",
    "nextssl_pqc_",
)

WASM_ALLOWED_EXPORT_NAMES = {
    "nextssl_init",
}

WASM_EXCLUDED_EXPORT_PREFIXES = (
    "nextssl_asym_rsa_",
    "nextssl_asym_sm2_",
)

WASM_ALLOWED_EXPORT_SUFFIXES = (
    "_format_record",
    "_verify_record",
)

# ─── Include paths ────────────────────────────────────────────────────────────

INCLUDE_DIRS = [
    SRC / "root",
    SRC,
    SRC / "common",
    SRC / "common/encoding",
    SRC / "common/sanitizer",
    SRC / "hash",
    SRC / "hash/interface",
    SRC / "hash/fast",
    SRC / "hash/blake",
    SRC / "hash/legacy",
    SRC / "hash/memory_hard",
    SRC / "hash/skein",
    SRC / "hash/sponge",
    SRC / "seed",
    SRC / "seed/hash",
    SRC / "seed/random",
    SRC / "seed/rng",
    SRC / "seed/drbg",
    SRC / "seed/udbf",
    SRC / "modern",
    SRC / "modern/symmetric",
    SRC / "modern/aead",
    SRC / "modern/mac",
    SRC / "modern/kdf",
    SRC / "modern/encoding",
    SRC / "modern/curve_math",
    SRC / "modern/asymmetric",
    SRC / "modern/asymmetric/rsa",
    SRC / "modern/asymmetric/micro_ecc",
    SRC / "pow",
    SRC / "pow/core",
    SRC / "pow/client",
    SRC / "pow/server",
    SRC / "pow/dhcm",
    SRC / "pqc",
    SRC / "pqc/common",
    SRC / "root/hash",
    SRC / "root/seed",
    SRC / "root/modern",
    SRC / "root/pqc",
    SRC / "root/pow",
]

_LOG_LEVELS = {"debug": logging.DEBUG, "info": logging.INFO,
               "warning": logging.WARNING, "error": logging.ERROR}

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_logger(name: str, level: int, log_path: Path) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    con = logging.StreamHandler(sys.stdout)
    con.setLevel(level)
    con.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s",
                                       datefmt="%H:%M:%S"))
    logger.addHandler(con)
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(message)s",
                                      datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(fh)
    return logger


def _run_logged(cmd: list, log_path: Path, logger: logging.Logger,
                cwd=None, label="") -> int:
    label = label or " ".join(str(c) for c in cmd[:3])
    logger.info("Running: %s", label)
    logger.debug("CMD: %s", " ".join(str(c) for c in cmd))
    logger.debug("CWD: %s", cwd or ROOT)
    with open(log_path, "a", encoding="utf-8", errors="replace") as lf:
        lf.write(f"\n{'='*60}\nCMD: {' '.join(str(c) for c in cmd)}\n"
                 f"CWD: {cwd or ROOT}\n{'='*60}\n\n")
        proc = subprocess.run([str(c) for c in cmd], stdout=lf, stderr=lf,
                              cwd=str(cwd or ROOT))
    logger.debug("%s exited with code %d", label, proc.returncode)
    return proc.returncode


def _tail_log(log_path: Path, logger: logging.Logger, n: int = 50):
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        tail = lines[-n:]
        logger.error("── Last %d lines of %s ──", len(tail), log_path.name)
        for line in tail:
            logger.error("  %s", line)
        logger.error("──────────────────────────────────────────")
    except FileNotFoundError:
        logger.warning("Log not found: %s", log_path)


def find_emcc() -> str:
    emcc = shutil.which("emcc")
    if emcc:
        return emcc
    for c in [
        Path("C:/emsdk/upstream/emscripten/emcc"),
        Path.home() / "emsdk/upstream/emscripten/emcc",
    ]:
        if c.exists():
            return str(c)
    return None


def collect_exported_functions() -> list[str]:
    exports = set(EXTRA_EXPORTED_FUNCTIONS)

    for _, name in extract_api_declarations(SRC / "root"):
        if name in WASM_ALLOWED_EXPORT_NAMES:
            exports.add(f"_{name}")
            continue
        if any(name.startswith(prefix) for prefix in WASM_EXCLUDED_EXPORT_PREFIXES):
            continue
        if any(name.startswith(prefix) for prefix in WASM_ALLOWED_EXPORT_PREFIXES):
            exports.add(f"_{name}")
            continue
        if any(name.endswith(suffix) for suffix in WASM_ALLOWED_EXPORT_SUFFIXES):
            exports.add(f"_{name}")

    return sorted(exports)


def collect_sources() -> list:
    exclude_patterns = [
        "/aarch64/",
        "/pqc/common/keccak2x/",
        "/hash/interface/hash_ops_disabled_stubs.c",
        "/pow/pow_api.c",
        "/pqc/kem/",
        "/pqc/sign/",
        "/memory_hard/balloon/",
        "/memory_hard/catena/",
        "/memory_hard/lyra2/",
        "/memory_hard/makwa/",
        "/memory_hard/pomelo/",
        "/memory_hard/scrypt/",
        "/memory_hard/yescrypt/",
        "skeinBlockNo3F",
        "blake3_avx2",
        "blake3_avx512",
        "blake3_sse2",
        "blake3_sse41",
        "keccak4x/KeccakP-1600-times4-SIMD256",
        "/memory_hard/opt.c",
    ]
    sources = []
    for f in SRC.rglob("*.c"):
        fp = f.as_posix()
        if not any(pat in fp for pat in exclude_patterns):
            sources.append(f)

    # Re-add pqc ref/ sources
    for pqc_sub in ["kem", "sign"]:
        for ref_dir in (SRC / "pqc" / pqc_sub).glob("*/ref"):
            sources.extend(ref_dir.glob("*.c"))
    pqc_main = SRC / "pqc" / "pqc_main.c"
    if pqc_main.exists() and pqc_main not in sources:
        sources.append(pqc_main)
    for f in (SRC / "pqc" / "common").rglob("*.c"):
        fp = f.as_posix()
        if "/aarch64/" in fp or "keccak2x" in fp or "SIMD256" in fp:
            continue
        if f not in sources:
            sources.append(f)
    return sources

# ─── Entry point ─────────────────────────────────────────────────────────────

def build(variant: str, build_dir: Path, jobs: int, clean: bool, log_path: Path,
          log_level: str = "error"):
    """
    variant: 'wasm32' (default) or 'wasm64' (enables -sMEMORY64=1)
    """
    level  = _LOG_LEVELS.get(log_level, logging.ERROR)
    logger = _make_logger("nextssl.build.wasm", level, log_path)

    logger.info("NextSSL WASM Build  variant=%s", variant)

    TEMP_DIR.mkdir(exist_ok=True)
    WEB_OUT.mkdir(parents=True, exist_ok=True)
    build_dir.mkdir(parents=True, exist_ok=True)

    emcc = find_emcc()
    if not emcc:
        logger.error("emcc not found. Install Emscripten and run emsdk_env first.")
        sys.exit(1)

    logger.info("emcc    : %s", emcc)
    logger.info("Variant : %s", variant)
    logger.info("Out     : bin/web/")

    if clean and build_dir.exists():
        logger.info("Cleaning %s ...", build_dir.relative_to(ROOT))
        shutil.rmtree(build_dir)
        build_dir.mkdir(parents=True)

    sources = collect_sources()
    logger.info("Sources : %d .c files", len(sources))
    exported_functions = collect_exported_functions()
    logger.info("Exports : %d symbols", len(exported_functions))

    exported = ",".join(exported_functions)
    wasm_out = WEB_OUT / "libnextssl.wasm"
    js_out   = WEB_OUT / "libnextssl.js"

    resp_args: list = []
    resp_args += [str(s).replace("\\", "/") for s in sources]
    for inc in INCLUDE_DIRS:
        if inc.exists():
            resp_args += ["-I", str(inc).replace("\\", "/")]
    resp_args += [
        "-O2",
        "-std=gnu11",
        "-Wall",
        "-Wno-unused-parameter",
        "-Wno-sign-compare",
        "-Wno-missing-field-initializers",
        "-DENABLE_ML_KEM",
        "-DENABLE_ML_DSA",
        "-DENABLE_FALCON",
        "-DENABLE_HQC",
        "-DENABLE_MCELIECE",
        "-DENABLE_SPHINCS",
        "-DHAVE_ED448",
        "-DHAVE_CURVE448",
        "-DBLAKE3_NO_AVX2",
        "-DBLAKE3_NO_AVX512",
        "-DBLAKE3_NO_SSE2",
        "-DBLAKE3_NO_SSE41",
        "-s", "MODULARIZE=1",
        "-s", "EXPORT_NAME=NextSSL",
        "-s", f"EXPORTED_FUNCTIONS=[{exported}]",
        "-s", "EXPORTED_RUNTIME_METHODS=[ccall,cwrap,getValue,setValue,UTF8ToString,stringToUTF8]",
        "-s", "ALLOW_MEMORY_GROWTH=1",
        "-s", "INITIAL_MEMORY=33554432",
        "-s", "ENVIRONMENT=web,node",
        "-s", "ASSERTIONS=0",
    ]
    if variant == "wasm64":
        resp_args += ["-s", "MEMORY64=1"]

    resp_args += ["-o", str(js_out).replace("\\", "/")]

    resp_file = TEMP_DIR / "emcc_args.rsp"
    with open(resp_file, "w", encoding="utf-8") as f:
        for arg in resp_args:
            f.write(f'"{arg}"\n' if " " in arg else f"{arg}\n")

    logger.debug("Response file: %s (%d bytes)", resp_file, resp_file.stat().st_size)
    logger.info("Step 1/1: Compiling all sources to WASM ...")

    rc = _run_logged([emcc, f"@{resp_file}"], log_path, logger, cwd=ROOT, label="emcc @response_file")
    if rc != 0:
        logger.error("emcc failed (exit %d)", rc)
        _tail_log(log_path, logger, 60)
        sys.exit(rc)

    if js_out.exists():
        wasm_size = wasm_out.stat().st_size if wasm_out.exists() else 0
        logger.info("[OK] bin/web/libnextssl.js    (%d bytes)", js_out.stat().st_size)
        if wasm_out.exists():
            logger.info("[OK] bin/web/libnextssl.wasm  (%d bytes)", wasm_size)
    else:
        logger.error("Output not found after build")
        sys.exit(1)
