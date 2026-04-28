"""
build/platform/macos.py — NextSSL macOS native build helper.

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
TEMP_DIR = ROOT / "temp"

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


def _detect_cmake(logger: logging.Logger) -> str:
    cmake = shutil.which("cmake")
    if not cmake:
        logger.error("cmake not found on PATH")
        sys.exit(1)
    logger.debug("cmake: %s", cmake)
    return cmake


def _detect_make(logger: logging.Logger) -> str:
    for c in ("ninja", "make"):
        found = shutil.which(c)
        if found:
            logger.debug("Build tool: %s (%s)", c, found)
            return c
    logger.error("No build tool found (ninja/make)")
    sys.exit(1)


# ─── Entry point ─────────────────────────────────────────────────────────────

def build(variant: str, build_dir: Path, bin_dir: Path, jobs: int,
          clean: bool, log_path: Path, log_level: str = "error"):
    level  = _LOG_LEVELS.get(log_level, logging.ERROR)
    logger = _make_logger("nextssl.build.macos", level, log_path)

    osx_arch = {"arm64": "arm64", "x86_64": "x86_64"}.get(variant, variant)

    logger.info("NextSSL macOS Build  variant=%s  OSX_ARCH=%s", variant, osx_arch)
    logger.debug("build_dir : %s", build_dir)
    logger.debug("bin_dir   : %s", bin_dir)
    logger.debug("jobs      : %d  clean=%s", jobs, clean)

    TEMP_DIR.mkdir(exist_ok=True)
    build_dir.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)

    cmake     = _detect_cmake(logger)
    gen_flags = ["-G", "Ninja"] if shutil.which("ninja") else []
    logger.debug("Generator flags: %s", gen_flags)

    logger.info("CMake   : %s", cmake)
    logger.info("Variant : %s (OSX_ARCH=%s)", variant, osx_arch)
    logger.info("Out     : %s", bin_dir.relative_to(ROOT))

    if clean and build_dir.exists():
        logger.info("Cleaning %s ...", build_dir.relative_to(ROOT))
        shutil.rmtree(build_dir)
        build_dir.mkdir(parents=True)

    toolchain = Path(__file__).parent / "macos.cmake"
    cmake_flags = [
        cmake, str(ROOT),
        "-DCMAKE_BUILD_TYPE=Release",
        "-DNEXTSSL_SHARED=ON",
        f"-DCMAKE_OSX_ARCHITECTURES={osx_arch}",
        f"-DCMAKE_RUNTIME_OUTPUT_DIRECTORY={bin_dir}",
        f"-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={bin_dir}",
        f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
    ]
    cmake_flags += gen_flags

    configure_log = TEMP_DIR / "cmake_configure.log"
    configure_log.write_text("")

    logger.info("Step 1/2: CMake configure ...")
    rc = _run_logged(cmake_flags, configure_log, logger, cwd=build_dir, label="cmake configure")
    if rc != 0:
        logger.error("Configure failed (exit %d)", rc)
        _tail_log(configure_log, logger, 50)
        sys.exit(rc)
    logger.info("Configure: OK")

    make_tool = _detect_make(logger)
    build_cmd = (["ninja", f"-j{jobs}"] if make_tool == "ninja"
                 else [cmake, "--build", ".", "--", f"-j{jobs}"])

    compile_log = TEMP_DIR / "compile.log"
    compile_log.write_text("")

    logger.info("Step 2/2: Compiling (%d jobs) ...", jobs)
    rc = _run_logged(build_cmd, compile_log, logger, cwd=build_dir, label="compile")
    if rc != 0:
        logger.error("Compile failed (exit %d)", rc)
        _tail_log(compile_log, logger, 60)
        sys.exit(rc)

    logger.info("Build: SUCCESS")
    artifacts = list(bin_dir.glob("*.dylib")) + list(bin_dir.glob("*.a"))
    if artifacts:
        logger.info("Artifacts: %s", [str(a.relative_to(ROOT)) for a in artifacts])
    else:
        logger.warning("No artifacts found in %s", bin_dir)
