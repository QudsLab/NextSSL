"""Sequential CI build runner with durable per-variant logs."""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LOGS_ROOT = ROOT / "logs"
BIN_ROOT = ROOT / "bin"
BUILD_ROOT = ROOT / ".ci_build"

WIN_ARCHES = {
    "x86_64": "x64",
    "x86": "Win32",
    "arm64": "ARM64",
}

DEFAULT_VARIANTS = {
    "win": ["x86_64", "x86", "arm64"],
    "linux": ["x86_64", "x86", "arm64", "armv7", "riscv64"],
    "macos": ["x86_64", "arm64"],
    "wasm": ["wasm32"],
}


def command_text(command: list[object]) -> str:
    parts = [str(part) for part in command]
    if os.name == "nt":
        return subprocess.list2cmdline(parts)
    return " ".join(shlex.quote(part) for part in parts)


def reset_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_lines(path: Path, lines: list[str]) -> None:
    ensure_dir(path.parent)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_logged(command: list[object], log_path: Path, cwd: Path | None = None,
               env: dict[str, str] | None = None) -> int:
    ensure_dir(log_path.parent)
    with log_path.open("a", encoding="utf-8", errors="replace") as handle:
        handle.write("\n" + "=" * 78 + "\n")
        handle.write(f"CMD: {command_text(command)}\n")
        handle.write(f"CWD: {cwd or ROOT}\n")
        handle.write("=" * 78 + "\n\n")
        process = subprocess.run(
            [str(part) for part in command],
            stdout=handle,
            stderr=handle,
            cwd=str(cwd or ROOT),
            env=env,
            check=False,
        )
    return process.returncode


def copy_if_exists(source: Path, dest: Path) -> None:
    if source.exists():
        ensure_dir(dest.parent)
        shutil.copy2(source, dest)


def find_tool(name: str) -> str | None:
    return shutil.which(name)


def build_common_cmake_args(bin_dir: Path) -> list[str]:
    return [
        "-DCMAKE_BUILD_TYPE=Release",
        "-DNEXTSSL_SHARED=ON",
        f"-DCMAKE_RUNTIME_OUTPUT_DIRECTORY={bin_dir}",
        f"-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={bin_dir}",
        f"-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY={bin_dir}",
    ]


def write_variant_info(platform: str, variant: str, log_dir: Path) -> None:
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    write_lines(
        log_dir / "job_info.txt",
        [
            f"platform: {platform}",
            f"variant: {variant}",
            f"run_id: {os.environ.get('GITHUB_RUN_ID', 'local')}",
            f"attempt: {os.environ.get('GITHUB_RUN_ATTEMPT', '1')}",
            f"sha: {os.environ.get('GITHUB_SHA', 'local')}",
            f"ref: {os.environ.get('GITHUB_REF', 'local')}",
            f"started: {started}",
        ],
    )


def write_environment_info(log_dir: Path) -> None:
    tools = ["cmake", "ninja", "ccache", "sccache", "cl", "gcc", "g++", "emcc", sys.executable]
    lines: list[str] = []
    for tool in tools:
        if tool == sys.executable:
            lines.append(f"python={sys.executable}")
            continue
        resolved = find_tool(tool)
        if resolved:
            lines.append(f"{tool}={resolved}")
    lines.append("")

    interesting_names = [
        name for name in sorted(os.environ)
        if any(token in name.upper() for token in ["PATH", "CMAKE", "CC", "CXX", "VC", "EMSDK", "EMSCRIPTEN", "SDKROOT"])
    ]
    for name in interesting_names:
        lines.append(f"{name}={os.environ[name]}")

    write_lines(log_dir / "env.txt", lines)


def copy_cmake_diagnostics(build_dir: Path, log_dir: Path) -> None:
    cmake_dir = build_dir / "CMakeFiles"
    copy_if_exists(cmake_dir / "CMakeError.log", log_dir / "CMakeError.log")
    copy_if_exists(cmake_dir / "CMakeOutput.log", log_dir / "CMakeOutput.log")


def append_lines(path: Path, lines: list[str]) -> None:
    ensure_dir(path.parent)
    with path.open("a", encoding="utf-8", errors="replace") as handle:
        handle.write("\n")
        for line in lines:
            handle.write(f"{line}\n")


def cleanup_build_dir(build_dir: Path) -> None:
    if build_dir.exists():
        shutil.rmtree(build_dir)

    parent = build_dir.parent
    if parent.exists() and not any(parent.iterdir()):
        parent.rmdir()

    if BUILD_ROOT.exists() and not any(BUILD_ROOT.iterdir()):
        BUILD_ROOT.rmdir()


def record_result(log_dir: Path, success: bool, exit_code: int) -> None:
    status = "success" if success else "failed"
    write_lines(log_dir / "result.txt", [f"status: {status}", f"exit_code: {exit_code}"])


def annotate_windows_arm64_failure(log_path: Path) -> None:
    if not log_path.exists():
        return

    text = log_path.read_text(encoding="utf-8", errors="replace")
    if "Platform='ARM64'" not in text:
        return
    if "BaseOutputPath/OutputPath property is not set" not in text:
        return

    append_lines(
        log_path,
        [
            "[ci_runner] Note: local Windows ARM64 configure failed before compilation.",
            "[ci_runner] This machine does not appear to have the MSBuild ARM64 platform/toolset installed.",
            "[ci_runner] The log is complete; resolve the local Visual Studio ARM64 workload or validate ARM64 on CI.",
        ],
    )


def windows_configure_args(variant: str, build_dir: Path, bin_dir: Path) -> list[str]:
    generator = os.environ.get("NEXTSSL_WINDOWS_GENERATOR", "Visual Studio 17 2022")
    args = [
        "cmake",
        "-S", str(ROOT),
        "-B", str(build_dir),
        "-G", generator,
        "-A", WIN_ARCHES[variant],
    ]
    args += build_common_cmake_args(bin_dir)

    launcher = find_tool("sccache")
    if launcher:
        args.append(f"-DCMAKE_C_COMPILER_LAUNCHER={launcher}")
        args.append(f"-DCMAKE_CXX_COMPILER_LAUNCHER={launcher}")
    return args


def linux_variant_flags(variant: str) -> list[str]:
    if variant == "x86_64":
        return []
    if variant == "x86":
        return [
            "-DCMAKE_SYSTEM_PROCESSOR=i686",
            "-DCMAKE_C_FLAGS=-m32",
            "-DCMAKE_CXX_FLAGS=-m32",
            "-DCMAKE_EXE_LINKER_FLAGS=-m32",
            "-DCMAKE_SHARED_LINKER_FLAGS=-m32",
        ]

    cross_map = {
        "arm64": {
            "processor": "aarch64",
            "compiler": "aarch64-linux-gnu-gcc",
            "cxx": "aarch64-linux-gnu-g++",
            "ar": "aarch64-linux-gnu-ar",
            "ranlib": "aarch64-linux-gnu-ranlib",
            "root": "/usr/aarch64-linux-gnu",
        },
        "armv7": {
            "processor": "armv7",
            "compiler": "arm-linux-gnueabihf-gcc",
            "cxx": "arm-linux-gnueabihf-g++",
            "ar": "arm-linux-gnueabihf-ar",
            "ranlib": "arm-linux-gnueabihf-ranlib",
            "root": "/usr/arm-linux-gnueabihf",
        },
        "riscv64": {
            "processor": "riscv64",
            "compiler": "riscv64-linux-gnu-gcc",
            "cxx": "riscv64-linux-gnu-g++",
            "ar": "riscv64-linux-gnu-ar",
            "ranlib": "riscv64-linux-gnu-ranlib",
            "root": "/usr/riscv64-linux-gnu",
        },
    }
    config = cross_map.get(variant)
    if not config:
        raise ValueError(f"Unsupported Linux variant: {variant}")

    missing_tools = [
        tool for tool in [config["compiler"], config["cxx"], config["ar"], config["ranlib"]]
        if not find_tool(tool)
    ]
    if missing_tools:
        raise FileNotFoundError(", ".join(missing_tools))

    return [
        "-DCMAKE_SYSTEM_NAME=Linux",
        f"-DCMAKE_SYSTEM_PROCESSOR={config['processor']}",
        f"-DCMAKE_C_COMPILER={config['compiler']}",
        f"-DCMAKE_CXX_COMPILER={config['cxx']}",
        f"-DCMAKE_AR={config['ar']}",
        f"-DCMAKE_RANLIB={config['ranlib']}",
        f"-DCMAKE_FIND_ROOT_PATH={config['root']}",
        "-DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER",
        "-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY",
        "-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY",
        "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
    ]


def unix_configure_args(platform: str, variant: str, build_dir: Path, bin_dir: Path) -> list[str]:
    args = ["cmake", "-S", str(ROOT), "-B", str(build_dir)]
    if find_tool("ninja"):
        args += ["-G", "Ninja"]
    args += build_common_cmake_args(bin_dir)

    launcher = find_tool("ccache")
    if launcher:
        args.append(f"-DCMAKE_C_COMPILER_LAUNCHER={launcher}")
        args.append(f"-DCMAKE_CXX_COMPILER_LAUNCHER={launcher}")

    if platform == "linux":
        args += linux_variant_flags(variant)
    elif platform == "macos":
        args.append(f"-DCMAKE_OSX_ARCHITECTURES={variant}")

    return args


def cmake_build_args(build_dir: Path, is_windows: bool, jobs: int) -> list[str]:
    args = ["cmake", "--build", str(build_dir)]
    if is_windows:
        args += ["--config", "Release"]
    args += ["--parallel", str(jobs)]
    return args


def collect_windows_debug_files(build_dir: Path, bin_dir: Path) -> None:
    ensure_dir(bin_dir)
    for pdb_file in build_dir.rglob("*.pdb"):
        shutil.copy2(pdb_file, bin_dir / pdb_file.name)


def run_cmake_variant(platform: str, variant: str, jobs: int) -> tuple[bool, int]:
    log_dir = LOGS_ROOT / platform / variant
    build_dir = BUILD_ROOT / platform / variant
    bin_dir = BIN_ROOT / platform / variant

    reset_dir(log_dir)
    reset_dir(build_dir)
    reset_dir(bin_dir)
    write_variant_info(platform, variant, log_dir)
    write_environment_info(log_dir)

    configure_log = log_dir / "configure.log"
    build_log = log_dir / "build.log"

    try:
        try:
            if platform == "win":
                configure_args = windows_configure_args(variant, build_dir, bin_dir)
            else:
                configure_args = unix_configure_args(platform, variant, build_dir, bin_dir)
        except FileNotFoundError as exc:
            write_lines(configure_log, [f"Missing toolchain executables: {exc}"])
            record_result(log_dir, False, 1)
            return False, 1
        except ValueError as exc:
            write_lines(configure_log, [str(exc)])
            record_result(log_dir, False, 1)
            return False, 1

        configure_exit = run_logged(configure_args, configure_log)
        copy_cmake_diagnostics(build_dir, log_dir)
        if configure_exit != 0:
            if platform == "win" and variant == "arm64":
                annotate_windows_arm64_failure(configure_log)
            record_result(log_dir, False, configure_exit)
            return False, configure_exit

        build_exit = run_logged(cmake_build_args(build_dir, platform == "win", jobs), build_log)
        if platform == "win":
            collect_windows_debug_files(build_dir, bin_dir)

        success = build_exit == 0
        record_result(log_dir, success, build_exit)
        return success, build_exit
    finally:
        cleanup_build_dir(build_dir)


def run_wasm_variant(variant: str, jobs: int) -> tuple[bool, int]:
    platform = "wasm"
    log_dir = LOGS_ROOT / platform / variant
    output_dir = BIN_ROOT / platform / variant
    web_dir = BIN_ROOT / "web"

    reset_dir(log_dir)
    reset_dir(output_dir)
    if web_dir.exists():
        shutil.rmtree(web_dir)

    write_variant_info(platform, variant, log_dir)
    write_environment_info(log_dir)

    build_log = log_dir / "build.log"
    command = [
        sys.executable,
        str(ROOT / "build.py"),
        "--platform", "wasm", variant,
        "--clean",
        "--jobs", str(jobs),
        "--log-level", "debug",
        "--log-file", str(build_log),
    ]

    with build_log.open("a", encoding="utf-8", errors="replace") as handle:
        handle.write("\n" + "=" * 78 + "\n")
        handle.write(f"CMD: {command_text(command)}\n")
        handle.write(f"CWD: {ROOT}\n")
        handle.write("=" * 78 + "\n\n")

    process = subprocess.run(command, cwd=str(ROOT), check=False)

    if web_dir.exists():
        for item in web_dir.iterdir():
            target = output_dir / item.name
            if item.is_dir():
                shutil.copytree(item, target, dirs_exist_ok=True)
            else:
                shutil.copy2(item, target)

    success = process.returncode == 0
    record_result(log_dir, success, process.returncode)
    return success, process.returncode


def run_variant(platform: str, variant: str, jobs: int) -> tuple[bool, int]:
    if platform == "wasm":
        return run_wasm_variant(variant, jobs)
    return run_cmake_variant(platform, variant, jobs)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run CI builds sequentially per platform.")
    parser.add_argument("--platform", choices=sorted(DEFAULT_VARIANTS), required=True)
    parser.add_argument("--variants", nargs="+", help="Explicit variant order for the selected platform.")
    parser.add_argument("--jobs", type=int, default=4)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    platform = args.platform
    variants = args.variants or DEFAULT_VARIANTS[platform]

    ensure_dir(LOGS_ROOT)
    ensure_dir(BIN_ROOT)
    ensure_dir(BUILD_ROOT)

    platform_logs = LOGS_ROOT / platform
    platform_bins = BIN_ROOT / platform
    if platform_logs.exists():
        shutil.rmtree(platform_logs)
    if platform_bins.exists():
        shutil.rmtree(platform_bins)
    ensure_dir(platform_logs)
    ensure_dir(platform_bins)

    summary_lines = []
    failed_variants = []
    for variant in variants:
        print(f"==> {platform}/{variant}")
        success, exit_code = run_variant(platform, variant, args.jobs)
        status = "SUCCESS" if success else f"FAILED ({exit_code})"
        summary_lines.append(f"{variant}: {status}")
        if not success:
            failed_variants.append(variant)

    write_lines(platform_logs / "SUMMARY.txt", summary_lines)

    if failed_variants:
        print(f"Failures: {', '.join(failed_variants)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())