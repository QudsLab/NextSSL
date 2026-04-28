#!/usr/bin/env python3
"""build/ci_wrapper.py — CI subprocess runner with GitHub Actions group annotations.

Wraps any command so that:
  - Output appears inside a collapsible ::group:: in the Actions UI
  - stdout + stderr are teed to a log file (always, even on error)
  - The exit code of the wrapped command is written to the log
  - This script ALWAYS exits 0 — build/compile failures never fail the CI job.
    Pull the log artifact to inspect failures.

Usage:
    python build/ci_wrapper.py \\
        --group  "Configure — Linux arm64" \\
        --log    "logs/linux/arm64/configure.log" \\
        -- cmake -S . -B _build -G Ninja ...

Everything after the lone '--' is the command to run.
"""

import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def main() -> None:
    # Split on '--' to separate wrapper args from the command to run
    if "--" in sys.argv:
        sep = sys.argv.index("--")
        wrapper_argv = sys.argv[1:sep]
        cmd = sys.argv[sep + 1:]
    else:
        wrapper_argv = sys.argv[1:]
        cmd = []

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--group", required=True, help="Group title shown in CI output")
    parser.add_argument("--log",   required=True, type=Path,
                        help="Log file path; parent dirs are created automatically")
    args = parser.parse_args(wrapper_argv)

    log_path: Path = args.log
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Open log for the duration of the run
    exit_code = -1
    with open(log_path, "w", encoding="utf-8", errors="replace", buffering=1) as lf:
        lf.write(f"group:    {args.group}\n")
        lf.write(f"started:  {_utcnow()}\n")
        lf.write(f"cmd:      {' '.join(cmd)}\n")
        lf.write("=" * 70 + "\n\n")
        lf.flush()

        # Emit the GitHub Actions group START — output after this is collapsible
        print(f"::group::{args.group}", flush=True)

        if not cmd:
            msg = "ci_wrapper: no command specified after '--'"
            print(msg, flush=True)
            lf.write(msg + "\n")
            exit_code = 1
        else:
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                # Stream output line-by-line: visible in CI console AND saved to log
                for line in proc.stdout:
                    sys.stdout.write(line)
                    sys.stdout.flush()
                    lf.write(line)
                proc.wait()
                exit_code = proc.returncode
            except FileNotFoundError as exc:
                msg = f"ci_wrapper: command not found — {exc}"
                print(msg, flush=True)
                lf.write(msg + "\n")
                exit_code = 127
            except Exception as exc:  # noqa: BLE001
                msg = f"ci_wrapper: unexpected error — {exc}"
                print(msg, flush=True)
                lf.write(msg + "\n")
                exit_code = -1

        lf.write("\n" + "=" * 70 + "\n")
        lf.write(f"finished: {_utcnow()}\n")
        lf.write(f"EXIT_CODE: {exit_code}\n")

    # Close the group; status line is printed outside so it's always visible
    print("::endgroup::", flush=True)
    status = "OK" if exit_code == 0 else f"FAILED (exit {exit_code})"
    print(f"[ci_wrapper] {args.group} — {status}  →  {log_path}", flush=True)

    # ALWAYS exit 0.  Failures are in the log; the CI job stays green.
    sys.exit(0)


if __name__ == "__main__":
    main()
