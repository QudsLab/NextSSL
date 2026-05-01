"""Write durable skipped-variant CI logs.

This helper is used by GitHub Actions jobs that are visible in the UI but need
to stop a platform queue after an earlier variant failed.
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LOGS_ROOT = ROOT / "logs" / "build"


def write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Write skipped CI logs for a platform variant.")
    parser.add_argument("--platform", required=True)
    parser.add_argument("--variant", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--blocked-by", default="")
    parser.add_argument("--blocked-status", default="")
    args = parser.parse_args()

    log_dir = LOGS_ROOT / args.platform / args.variant
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    job_info = [
        f"platform: {args.platform}",
        f"variant: {args.variant}",
        f"run_id: {os.environ.get('GITHUB_RUN_ID', 'local')}",
        f"attempt: {os.environ.get('GITHUB_RUN_ATTEMPT', '1')}",
        f"sha: {os.environ.get('GITHUB_SHA', 'local')}",
        f"ref: {os.environ.get('GITHUB_REF', 'local')}",
        f"started: {started}",
    ]
    if args.blocked_by:
        job_info.append(f"blocked_by: {args.blocked_by}")
    if args.blocked_status:
        job_info.append(f"blocked_status: {args.blocked_status}")

    write_lines(log_dir / "job_info.txt", job_info)
    write_lines(
        log_dir / "result.txt",
        [
            "status: skipped",
            f"reason: {args.reason}",
        ],
    )
    write_lines(
        log_dir / "build.log",
        [
            f"[ci_skip] skipped {args.platform}/{args.variant}",
            f"[ci_skip] reason: {args.reason}",
            *([f"[ci_skip] blocked_by: {args.blocked_by}"] if args.blocked_by else []),
            *([f"[ci_skip] blocked_status: {args.blocked_status}"] if args.blocked_status else []),
        ],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())