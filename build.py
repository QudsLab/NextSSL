"""
build.py — NextSSL build entry point.

Usage:
    python build.py                                        # auto-detect platform
    python build.py --platform win x86_64
    python build.py --platform linux arm64
    python build.py --platform macos arm64
    python build.py --platform wasm wasm32
    python build.py --platform wasm wasm64
    python build.py --platform win x86_64 --clean
    python build.py --platform wasm wasm32 --jobs 8
    python build.py --platform win x86_64 --log-level debug

Scratch dir : .build_cache/<tag>_<variant>/   (never inside build/)
Log files   : .temp/build_<tag>_<variant>.log
Artifacts   : bin/<tag>/<variant>/*.dll  (no .dll.a)
"""

import argparse
import importlib.util
import logging
import platform
import sys
from pathlib import Path
# import shutil for build scripts cleanup
import shutil

ROOT  = Path(__file__).resolve().parent
BUILD = ROOT / "build" / "platform"
TEMP  = ROOT / ".temp"

_OS_MAP   = {"windows": "win", "darwin": "macos", "linux": "linux"}
_ARCH_MAP = {"amd64": "x86_64", "aarch64": "arm64", "arm64": "arm64"}

_LOG_LEVELS = {"debug": logging.DEBUG, "info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}


def _setup_logger(level: int) -> logging.Logger:
    logger = logging.getLogger("nextssl.build")
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        fmt = logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s",
                                datefmt="%H:%M:%S")
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    return logger


def auto_platform():
    tag  = _OS_MAP.get(platform.system().lower(), platform.system().lower())
    arch = _ARCH_MAP.get(platform.machine().lower(), platform.machine().lower())
    return tag, arch


def main():
    parser = argparse.ArgumentParser(description="NextSSL build")
    parser.add_argument("--platform",  nargs=2, metavar=("TAG", "VARIANT"), help="Platform tag and variant, e.g. win x86_64 / wasm wasm32")
    parser.add_argument("--clean",     action="store_true", help="Wipe scratch dir before build")
    parser.add_argument("--jobs",      type=int, default=4)
    parser.add_argument("--log-file",  type=str, default=None, help="Override log file path (default: .temp/build_<tag>_<variant>.log)")
    parser.add_argument("--log-level", choices=["debug", "info", "warning", "error"], default="info", help="Console log verbosity (default: info)")
    args = parser.parse_args()

    logger = _setup_logger(_LOG_LEVELS[args.log_level])

    tag, variant = args.platform if args.platform else auto_platform()
    logger.info("Platform: %s  Variant: %s", tag, variant)

    TEMP.mkdir(exist_ok=True)
    log_path = Path(args.log_file) if args.log_file else TEMP / f"build_{tag}_{variant}.log"
    logger.debug("Log file: %s", log_path)

    build_dir = ROOT / ".build_cache" / f"{tag}_{variant}"
    logger.debug("Scratch dir: %s", build_dir)

    script = BUILD / f"{tag}.py"
    if not script.exists():
        logger.error("No build script for platform '%s' (looked for %s)", tag, script)
        sys.exit(1)

    logger.debug("Loading platform script: %s", script)
    spec = importlib.util.spec_from_file_location(f"platform_{tag}", script)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    logger.info("Starting build (%s jobs, clean=%s)", args.jobs, args.clean)

    if tag == "wasm":
        mod.build(variant=variant, build_dir=build_dir, jobs=args.jobs, clean=args.clean, log_path=log_path, log_level=args.log_level)
    else:
        bin_dir = ROOT / "bin" / tag / variant
        logger.debug("Bin dir: %s", bin_dir)
        mod.build(variant=variant, build_dir=build_dir, bin_dir=bin_dir, jobs=args.jobs, clean=args.clean, log_path=log_path, log_level=args.log_level)
    logger.info("Build complete.")

    # after build let's cleanup .build_cache to save disk space
    if build_dir.exists():
        logger.info("Cleaning up scratch dir %s ...", build_dir.relative_to(ROOT))
        shutil.rmtree(build_dir)
    # and remove the .build_cache directory too
    build_cache = ROOT / ".build_cache"
    if build_cache.exists() and not any(build_cache.iterdir()):
        logger.info("Removing empty scratch cache dir %s ...", build_cache.relative_to(ROOT))
        build_cache.rmdir()
    print(f"\nDone. Log: {log_path}")

if __name__ == "__main__":
    main()
