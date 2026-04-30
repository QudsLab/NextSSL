"""Sequential CI build runner with durable per-variant logs.

This runner uses the Python interpreter that launched it and does not require
activating a virtual environment.
"""

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

WIN_VARIANT_PROFILES = {
    "x86_64": {"toolchain": "msvc", "generator_arch": "x64"},
    "x86": {"toolchain": "msvc", "generator_arch": "Win32"},
    "arm64": {"toolchain": "msvc", "generator_arch": "ARM64"},
    "x86_64-msvc": {"toolchain": "msvc", "generator_arch": "x64"},
    "x86-msvc": {"toolchain": "msvc", "generator_arch": "Win32"},
    "arm64-msvc": {"toolchain": "msvc", "generator_arch": "ARM64"},
    "armv7-msvc": {"toolchain": "msvc", "generator_arch": "ARM"},
    "x86_64-mingw": {"toolchain": "mingw"},
    "x86-mingw": {"toolchain": "mingw"},
}

LINUX_GLIBC_VARIANTS = {
    "x86": {
        "processor": "i686",
        "compiler": "i686-linux-gnu-gcc",
        "ar": "i686-linux-gnu-ar",
        "ranlib": "i686-linux-gnu-ranlib",
    },
    "arm64": {
        "processor": "aarch64",
        "compiler": "aarch64-linux-gnu-gcc",
        "ar": "aarch64-linux-gnu-ar",
        "ranlib": "aarch64-linux-gnu-ranlib",
    },
    "armv7": {
        "processor": "armv7",
        "compiler": "arm-linux-gnueabihf-gcc",
        "ar": "arm-linux-gnueabihf-ar",
        "ranlib": "arm-linux-gnueabihf-ranlib",
    },
    "riscv64": {
        "processor": "riscv64",
        "compiler": "riscv64-linux-gnu-gcc",
        "ar": "riscv64-linux-gnu-ar",
        "ranlib": "riscv64-linux-gnu-ranlib",
    },
    "s390x": {
        "processor": "s390x",
        "compiler": "s390x-linux-gnu-gcc",
        "ar": "s390x-linux-gnu-ar",
        "ranlib": "s390x-linux-gnu-ranlib",
    },
    "ppc64le": {
        "processor": "ppc64le",
        "compiler": "powerpc64le-linux-gnu-gcc",
        "ar": "powerpc64le-linux-gnu-ar",
        "ranlib": "powerpc64le-linux-gnu-ranlib",
    },
    "loongarch64": {
        "processor": "loongarch64",
        "compiler": ("loongarch64-linux-gnu-gcc", "loongarch64-linux-gnu-gcc-14", "loongarch64-linux-gnu-gcc-13"),
        "ar": ("loongarch64-linux-gnu-ar",),
        "ranlib": ("loongarch64-linux-gnu-ranlib",),
    },
}

LINUX_MUSL_VARIANTS = {
    "x86_64": {"processor": "x86_64", "target": "x86_64-linux-musl"},
    "arm64": {"processor": "aarch64", "target": "aarch64-linux-musl"},
    "armv7": {"processor": "armv7", "target": "arm-linux-musleabihf"},
}

ANDROID_VARIANTS = {
    "arm64-v8a": {"abi": "arm64-v8a", "platform": "android-24"},
    "armeabi-v7a": {"abi": "armeabi-v7a", "platform": "android-21"},
    "x86_64": {"abi": "x86_64", "platform": "android-24"},
    "x86": {"abi": "x86", "platform": "android-21"},
}

IOS_VARIANTS = {
    "device-arm64": {"arch": "arm64", "sysroot": "iphoneos"},
    "sim-arm64": {"arch": "arm64", "sysroot": "iphonesimulator"},
    "sim-x86_64": {"arch": "x86_64", "sysroot": "iphonesimulator"},
}

DEFAULT_VARIANTS = {
    "win": ["x86_64-msvc", "x86-msvc", "arm64-msvc", "x86_64-mingw", "x86-mingw", "armv7-msvc"],
    "linux": ["x86_64", "x86", "arm64", "armv7", "riscv64"],
    "linux-glibc": ["x86_64", "x86", "arm64", "armv7", "riscv64", "s390x", "ppc64le", "loongarch64"],
    "linux-musl": ["x86_64", "arm64", "armv7"],
    "macos": ["x86_64", "arm64", "universal"],
    "wasm": ["emscripten-wasm32", "wasi-wasm32"],
    "android": ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"],
    "ios": ["device-arm64", "sim-arm64", "sim-x86_64"],
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


def collect_native_artifacts(platform: str, bin_dir: Path) -> list[Path]:
    patterns = {
        "win": ("*.dll", "*.lib", "*.dll.a"),
        "linux": ("*.so", "*.a"),
        "linux-glibc": ("*.so", "*.a"),
        "linux-musl": ("*.so", "*.a"),
        "macos": ("*.dylib", "*.a"),
        "android": ("*.so",),
        "ios": ("*.a",),
        "wasm": ("*.wasm", "*.js", "*.so", "*.a"),
    }
    artifacts: list[Path] = []
    for pattern in patterns.get(platform, ()): 
        artifacts.extend(sorted(bin_dir.rglob(pattern)))
    return artifacts


def find_tool(name: str) -> str | None:
    return shutil.which(name)


def require_tool(name: str) -> str:
    resolved = find_tool(name)
    if not resolved:
        raise FileNotFoundError(name)
    return resolved


def require_any_tool(*names: str) -> str:
    for name in names:
        resolved = find_tool(name)
        if resolved:
            return resolved
    raise FileNotFoundError(", ".join(names))


def build_common_cmake_args(bin_dir: Path, shared: bool = True) -> list[str]:
    return [
        "-DCMAKE_BUILD_TYPE=Release",
        f"-DNEXTSSL_SHARED={'ON' if shared else 'OFF'}",
        f"-DNEXTSSL_OUTPUT_ARCH={bin_dir.name}",
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


def write_artifacts_info(log_dir: Path, artifacts: list[Path]) -> None:
    write_lines(
        log_dir / "artifacts.txt",
        [str(path.relative_to(ROOT)) for path in artifacts],
    )


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


def record_result(log_dir: Path, status: str, exit_code: int | None = None,
                  reason: str | None = None) -> None:
    lines = [f"status: {status}"]
    if exit_code is not None:
        lines.append(f"exit_code: {exit_code}")
    if reason:
        lines.append(f"reason: {reason}")
    write_lines(log_dir / "result.txt", lines)


def record_skipped_variant(platform: str, variant: str, reason: str) -> None:
    log_dir = LOGS_ROOT / platform / variant
    reset_dir(log_dir)
    record_result(log_dir, "skipped", reason=reason)


def annotate_windows_cross_failure(log_path: Path, variant: str) -> None:
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
            f"[ci_runner] Note: local Windows {variant} configure failed before compilation.",
            "[ci_runner] This machine does not appear to have the required MSBuild cross-platform toolset installed.",
            "[ci_runner] The log is complete; validate this variant on the hosted runner image or install the matching VS workload locally.",
        ],
    )


def windows_configure_args(variant: str, build_dir: Path, bin_dir: Path) -> list[str]:
    profile = WIN_VARIANT_PROFILES.get(variant)
    if not profile:
        raise ValueError(f"Unsupported Windows variant: {variant}")

    args = [
        "cmake",
        "-S", str(ROOT),
        "-B", str(build_dir),
    ]
    args += build_common_cmake_args(bin_dir)

    if profile["toolchain"] == "msvc":
        generator = os.environ.get("NEXTSSL_WINDOWS_GENERATOR", "Visual Studio 17 2022")
        if variant == "armv7-msvc":
            sdk_version = os.environ.get("NEXTSSL_ARMV7_WINDOWS_SDK", "10.0.22621.0")
            args += ["-G", generator, "-A", f"{profile['generator_arch']},version={sdk_version}"]
            args.append(f"-DCMAKE_SYSTEM_VERSION={sdk_version}")
            args.append(f"-DCMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION={sdk_version}")
        else:
            args += ["-G", generator, "-A", profile["generator_arch"]]

        launcher = find_tool("sccache")
        if launcher:
            args.append(f"-DCMAKE_C_COMPILER_LAUNCHER={launcher}")
            args.append(f"-DCMAKE_CXX_COMPILER_LAUNCHER={launcher}")
        return args

    if find_tool("ninja"):
        args += ["-G", "Ninja"]
    elif find_tool("mingw32-make"):
        args += ["-G", "MinGW Makefiles"]

    args += [
        "-DCMAKE_SYSTEM_NAME=Windows",
        "-DCMAKE_C_COMPILER=gcc",
        "-DCMAKE_CXX_COMPILER=g++",
    ]
    rc_compiler = find_tool("windres")
    if rc_compiler:
        args.append(f"-DCMAKE_RC_COMPILER={Path(rc_compiler).as_posix()}")
    return args


def linux_glibc_variant_flags(variant: str) -> list[str]:
    if variant == "x86_64":
        return []

    config = LINUX_GLIBC_VARIANTS.get(variant)
    if not config:
        raise ValueError(f"Unsupported Linux glibc variant: {variant}")

    compiler_names = config["compiler"] if isinstance(config["compiler"], tuple) else (config["compiler"],)
    ar_names = config["ar"] if isinstance(config["ar"], tuple) else (config["ar"],)
    ranlib_names = config["ranlib"] if isinstance(config["ranlib"], tuple) else (config["ranlib"],)

    compiler = require_any_tool(*compiler_names)
    ar = require_any_tool(*ar_names)
    ranlib = require_any_tool(*ranlib_names)

    return [
        "-DCMAKE_SYSTEM_NAME=Linux",
        f"-DCMAKE_SYSTEM_PROCESSOR={config['processor']}",
        f"-DCMAKE_C_COMPILER={compiler}",
        f"-DCMAKE_AR={ar}",
        f"-DCMAKE_RANLIB={ranlib}",
        "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
    ]


def linux_musl_variant_flags(variant: str) -> list[str]:
    config = LINUX_MUSL_VARIANTS.get(variant)
    if not config:
        raise ValueError(f"Unsupported Linux musl variant: {variant}")

    zig = require_tool("zig")
    return [
        "-DCMAKE_SYSTEM_NAME=Linux",
        f"-DCMAKE_SYSTEM_PROCESSOR={config['processor']}",
        f"-DCMAKE_C_COMPILER={zig}",
        "-DCMAKE_C_COMPILER_ARG1=cc",
        f"-DCMAKE_C_COMPILER_TARGET={config['target']}",
        "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
    ]


def android_variant_flags(variant: str) -> list[str]:
    config = ANDROID_VARIANTS.get(variant)
    if not config:
        raise ValueError(f"Unsupported Android variant: {variant}")

    ndk_home = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    if not ndk_home:
        raise FileNotFoundError("ANDROID_NDK_HOME")

    toolchain = Path(ndk_home) / "build" / "cmake" / "android.toolchain.cmake"
    if not toolchain.exists():
        raise FileNotFoundError(str(toolchain))

    return [
        f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
        f"-DANDROID_ABI={config['abi']}",
        f"-DANDROID_PLATFORM={config['platform']}",
        "-DANDROID_STL=none",
        "-DANDROID_USE_LEGACY_TOOLCHAIN_FILE=OFF",
    ]


def ios_variant_flags(variant: str) -> list[str]:
    config = IOS_VARIANTS.get(variant)
    if not config:
        raise ValueError(f"Unsupported iOS variant: {variant}")

    return [
        "-DCMAKE_SYSTEM_NAME=iOS",
        f"-DCMAKE_OSX_ARCHITECTURES={config['arch']}",
        f"-DCMAKE_OSX_SYSROOT={config['sysroot']}",
        "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
    ]


def wasi_variant_flags(variant: str) -> list[str]:
    if variant != "wasi-wasm32":
        raise ValueError(f"Unsupported WASI variant: {variant}")

    wasi_sdk = os.environ.get("WASI_SDK_PATH") or os.environ.get("WASI_SDK")
    if not wasi_sdk:
        raise FileNotFoundError("WASI_SDK_PATH")

    toolchain = Path(wasi_sdk) / "share" / "cmake" / "wasi-sdk.cmake"
    if not toolchain.exists():
        raise FileNotFoundError(str(toolchain))

    return [
        f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
        "-DCMAKE_SYSTEM_NAME=WASI",
        "-DCMAKE_SYSTEM_PROCESSOR=wasm32",
    ]


def unix_configure_args(platform: str, variant: str, build_dir: Path, bin_dir: Path) -> list[str]:
    args = ["cmake", "-S", str(ROOT), "-B", str(build_dir)]
    if find_tool("ninja"):
        args += ["-G", "Ninja"]
    args += build_common_cmake_args(bin_dir, shared=platform != "ios")

    launcher = find_tool("ccache")
    if launcher:
        args.append(f"-DCMAKE_C_COMPILER_LAUNCHER={launcher}")
        args.append(f"-DCMAKE_CXX_COMPILER_LAUNCHER={launcher}")

    if platform in {"linux", "linux-glibc"}:
        args += linux_glibc_variant_flags(variant)
    elif platform == "linux-musl":
        args += linux_musl_variant_flags(variant)
    elif platform == "macos":
        osx_arch = "arm64;x86_64" if variant == "universal" else variant
        args.append(f"-DCMAKE_OSX_ARCHITECTURES={osx_arch}")
    elif platform == "android":
        args += android_variant_flags(variant)
    elif platform == "ios":
        args += ios_variant_flags(variant)
    elif platform == "wasm":
        args += wasi_variant_flags(variant)

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
            record_result(log_dir, "failed", exit_code=1)
            return False, 1
        except ValueError as exc:
            write_lines(configure_log, [str(exc)])
            record_result(log_dir, "failed", exit_code=1)
            return False, 1

        configure_exit = run_logged(configure_args, configure_log)
        copy_cmake_diagnostics(build_dir, log_dir)
        if configure_exit != 0:
            if platform == "win" and variant in {"arm64", "arm64-msvc", "armv7-msvc"}:
                annotate_windows_cross_failure(configure_log, variant)
            record_result(log_dir, "failed", exit_code=configure_exit)
            return False, configure_exit

        build_exit = run_logged(cmake_build_args(build_dir, platform == "win", jobs), build_log)
        if platform == "win" and WIN_VARIANT_PROFILES.get(variant, {}).get("toolchain") == "msvc":
            collect_windows_debug_files(build_dir, bin_dir)

        success = build_exit == 0
        failure_reason = None
        if success:
            artifacts = collect_native_artifacts(platform, bin_dir)
            if artifacts:
                write_artifacts_info(log_dir, artifacts)
            else:
                success = False
                build_exit = 1
                failure_reason = f"no staged artifacts found in {bin_dir}"
                append_lines(
                    build_log,
                    [f"[ci_runner] Build completed but no expected artifacts were found under {bin_dir}"],
                )

        record_result(
            log_dir,
            "success" if success else "failed",
            exit_code=build_exit,
            reason=failure_reason,
        )
        return success, build_exit
    finally:
        cleanup_build_dir(build_dir)


def run_wasm_variant(variant: str, jobs: int) -> tuple[bool, int]:
    platform = "wasm"
    if variant == "wasi-wasm32":
        return run_cmake_variant(platform, variant, jobs)

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
    actual_variant = "wasm32" if variant in {"wasm32", "emscripten-wasm32"} else variant
    command = [
        sys.executable,
        str(ROOT / "build.py"),
        "--platform", "wasm", actual_variant,
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
    exit_code = process.returncode
    failure_reason = None
    if success:
        artifacts = collect_native_artifacts(platform, output_dir)
        if artifacts:
            write_artifacts_info(log_dir, artifacts)
        else:
            success = False
            exit_code = 1
            failure_reason = f"no staged artifacts found in {output_dir}"
            append_lines(
                build_log,
                [f"[ci_runner] Build completed but no expected artifacts were found under {output_dir}"],
            )

    record_result(
        log_dir,
        "success" if success else "failed",
        exit_code=exit_code,
        reason=failure_reason,
    )
    return success, exit_code


def run_variant(platform: str, variant: str, jobs: int) -> tuple[bool, int]:
    if platform == "wasm":
        return run_wasm_variant(variant, jobs)
    return run_cmake_variant(platform, variant, jobs)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run CI builds sequentially per platform with the current Python interpreter."
    )
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
    for index, variant in enumerate(variants):
        print(f"==> {platform}/{variant}")
        success, exit_code = run_variant(platform, variant, args.jobs)
        status = "SUCCESS" if success else f"FAILED ({exit_code})"
        summary_lines.append(f"{variant}: {status}")
        if not success:
            failed_variants.append(variant)
            skip_reason = f"stopped after {variant} failed with exit code {exit_code}"
            for skipped_variant in variants[index + 1:]:
                print(f"==> {platform}/{skipped_variant} [skipped]")
                record_skipped_variant(platform, skipped_variant, skip_reason)
                summary_lines.append(f"{skipped_variant}: SKIPPED ({skip_reason})")
            break

    write_lines(platform_logs / "SUMMARY.txt", summary_lines)

    if failed_variants:
        print(f"Failures: {', '.join(failed_variants)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())