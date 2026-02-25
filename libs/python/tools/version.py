import argparse
import re
import subprocess
from pathlib import Path


def run(cmd, cwd):
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def parse_version(tag):
    match = re.match(r"^v?(\d+)\.(\d+)\.(\d+)$", tag)
    if not match:
        return None
    return tuple(int(x) for x in match.groups())


def latest_tag(prefix, cwd):
    tags = run(["git", "tag", "--list", f"{prefix}*","--sort=-v:refname"], cwd).splitlines()
    return tags[0] if tags else None


def get_changes_since(ref, cwd):
    if not ref:
        return []
    output = run(["git", "diff", "--name-only", f"{ref}..HEAD"], cwd)
    return [line.strip() for line in output.splitlines() if line.strip()]


def compute_version(repo_root):
    main_tag = latest_tag("v", repo_root)
    main_version = parse_version(main_tag) if main_tag else (0, 0, 0)

    py_tag = latest_tag("py-v", repo_root)
    py_version = parse_version(py_tag.replace("py-", "", 1)) if py_tag else (0, 0, 0)

    base_ref = py_tag or main_tag
    changes = get_changes_since(base_ref, repo_root)

    c_changed = any(path.startswith("src/") and Path(path).suffix in {".c", ".h", ".S", ".s"} for path in changes)
    py_changed = any(path.startswith("libs/python/") for path in changes)

    major, minor, patch = py_version
    if c_changed:
        minor += 1
        patch = 0
    elif py_changed:
        patch += 1

    if major != 0:
        major = 0

    version = (major, minor, patch)
    return main_version, version


def write_version(version, repo_root):
    version_str = ".".join(str(x) for x in version)
    target = repo_root / "libs" / "python" / "src" / "nextssl" / "__init__.py"
    
    # Read existing file
    content = target.read_text(encoding="utf-8")
    
    # Replace version line using regex
    new_content = re.sub(
        r'^__version__\s*=\s*["\'][\d.]+["\']',
        f'__version__ = "{version_str}"',
        content,
        flags=re.MULTILINE
    )
    
    # Write back
    target.write_text(new_content, encoding="utf-8")
    return version_str


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--set", type=str)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[3]
    _, version = compute_version(repo_root)
    version_str = ".".join(str(x) for x in version)

    if args.set:
        parts = tuple(int(x) for x in args.set.strip().split("."))
        version_str = write_version(parts, repo_root)

    if args.write:
        version_str = write_version(version, repo_root)

    print(version_str)


if __name__ == "__main__":
    main()
