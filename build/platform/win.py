"""
build/platform/win.py — NextSSL Windows native build helper.

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
TEMP_DIR = ROOT / ".temp"

_LOG_LEVELS = {"debug": logging.DEBUG, "info": logging.INFO,
               "warning": logging.WARNING, "error": logging.ERROR}

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_logger(name: str, level: int, log_path: Path) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)          # capture everything; handlers filter
    logger.handlers.clear()
    # Console — respects the user-chosen level
    con = logging.StreamHandler(sys.stdout)
    con.setLevel(level)
    con.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s",
                                       datefmt="%H:%M:%S"))
    logger.addHandler(con)
    # File — always DEBUG so the full build transcript is captured
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
        proc = subprocess.run(
            [str(c) for c in cmd],
            stdout=lf, stderr=lf,
            cwd=str(cwd or ROOT),
        )
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


def _detect_generator(logger: logging.Logger) -> list:
    if shutil.which("ninja"):
        logger.debug("Generator: Ninja")
        return ["-G", "Ninja"]
    if shutil.which("mingw32-make") or shutil.which("make"):
        logger.debug("Generator: MinGW Makefiles")
        return ["-G", "MinGW Makefiles"]
    logger.debug("Generator: CMake default")
    return []


def _detect_make(logger: logging.Logger) -> str:
    for c in ("ninja", "mingw32-make", "make"):
        found = shutil.which(c)
        if found:
            logger.debug("Build tool: %s (%s)", c, found)
            return c
    logger.error("No build tool found (ninja/mingw32-make/make)")
    sys.exit(1)


# ─── Entry point ─────────────────────────────────────────────────────────────

def build(variant: str, build_dir: Path, bin_dir: Path, jobs: int,
          clean: bool, log_path: Path, log_level: str = "info"):
    level   = _LOG_LEVELS.get(log_level, logging.INFO)
    logger  = _make_logger("nextssl.build.win", level, log_path)

    logger.info("NextSSL Windows Build  variant=%s", variant)
    logger.info("build_dir : %s", build_dir)
    logger.info("bin_dir   : %s", bin_dir)
    logger.info("log_path  : %s", log_path)
    logger.info("jobs=%d  clean=%s", jobs, clean)

    TEMP_DIR.mkdir(exist_ok=True)
    build_dir.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)

    cmake     = _detect_cmake(logger)
    gen_flags = _detect_generator(logger)

    # Log cmake + compiler versions for debug traceability
    try:
        cmake_ver = subprocess.check_output([cmake, "--version"],
                                            text=True, stderr=subprocess.STDOUT).splitlines()[0]
        logger.info("cmake    : %s", cmake_ver)
    except Exception:
        logger.info("CMake    : %s", cmake)
    cc = shutil.which("cc") or shutil.which("gcc") or "(unknown)"
    try:
        cc_ver = subprocess.check_output([cc, "--version"],
                                         text=True, stderr=subprocess.STDOUT).splitlines()[0]
        logger.info("compiler : %s", cc_ver)
    except Exception:
        logger.info("compiler : %s", cc)
    logger.info("Variant  : %s", variant)
    logger.info("Out      : %s", bin_dir.relative_to(ROOT))

    if clean and build_dir.exists():
        logger.info("Cleaning %s ...", build_dir.relative_to(ROOT))
        shutil.rmtree(build_dir)
        build_dir.mkdir(parents=True)

    toolchain = Path(__file__).parent / "win.cmake"
    cmake_flags = [
        cmake, str(ROOT),
        "-DCMAKE_BUILD_TYPE=Release",
        "-DNEXTSSL_SHARED=ON",
        f"-DCMAKE_RUNTIME_OUTPUT_DIRECTORY={bin_dir}",
        f"-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={bin_dir}",
        # Redirect import library (.dll.a) to build scratch — keeps bin/ clean
        f"-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY={build_dir}",
        f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
    ]
    cmake_flags += gen_flags

    configure_log = TEMP_DIR / "cmake_configure.log"
    configure_log.write_text("", encoding="utf-8")

    logger.info("Step 1/2: CMake configure ...")
    rc = _run_logged(cmake_flags, configure_log, logger, cwd=build_dir, label="cmake configure")
    if rc != 0:
        logger.error("Configure failed (exit %d)", rc)
        _tail_log(configure_log, logger, 80)
        sys.exit(rc)
    logger.info("Configure: OK — full output in %s", configure_log)

    make_tool = _detect_make(logger)
    build_cmd = (["ninja", "-v", f"-j{jobs}"] if make_tool == "ninja"
                 else [cmake, "--build", ".", "--verbose", "--", f"-j{jobs}"])

    compile_log = TEMP_DIR / "compile.log"
    compile_log.write_text("", encoding="utf-8")

    logger.info("Step 2/2: Compiling (%d jobs) ...", jobs)
    rc = _run_logged(build_cmd, compile_log, logger, cwd=build_dir, label="compile")
    if rc != 0:
        logger.error("Compile failed (exit %d)", rc)
        _tail_log(compile_log, logger, 80)
        sys.exit(rc)

    # Remove .dll.a import library from bin/ — only the .dll is needed
    for stale in bin_dir.glob("*.dll.a"):
        stale.unlink()
        logger.info("Removed import lib: %s", stale.name)

    logger.info("Build: SUCCESS")
    artifacts = list(bin_dir.glob("*.dll")) + list(bin_dir.glob("*.lib"))
    for a in artifacts:
        size_kb = a.stat().st_size // 1024
        logger.info("Artifact : %s  (%d KB)", a.relative_to(ROOT), size_kb)
    if not artifacts:
        logger.warning("No artifacts found in %s", bin_dir)
    logger.info("Full compile log : %s", compile_log)
    logger.info("Full configure log: %s", configure_log)
