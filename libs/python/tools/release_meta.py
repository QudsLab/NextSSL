import argparse
import re
import subprocess
from pathlib import Path


def run(cmd, cwd):
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def latest_tag(prefix, cwd):
    tags = run(["git", "tag", "--list", f"{prefix}*","--sort=-v:refname"], cwd).splitlines()
    return tags[0] if tags else None


def parse_version(tag):
    match = re.match(r"^v?(\d+)\.(\d+)\.(\d+)$", tag)
    if not match:
        return None
    return tuple(int(x) for x in match.groups())


def parse_stem(stem, prefix):
    if prefix == "v":
        if stem.startswith("v"):
            stem = stem[1:]
    elif stem.startswith(prefix):
        stem = stem[len(prefix):]
    stem = stem.lstrip("_")
    parts = re.split(r"[_\\.]", stem)
    nums = [int(p) for p in parts if re.match(r"^\d+$", p)]
    return tuple(nums) if nums else None


def find_note(note_dir, prefix):
    candidates = []
    for path in note_dir.glob(f"{prefix}*.md"):
        version = parse_stem(path.stem, prefix)
        if version:
            candidates.append((version, path))
    if not candidates:
        return None, None
    candidates.sort()
    return candidates[-1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True)
    parser.add_argument("--force", default="false")
    parser.add_argument("--version", type=str, help="Custom version (e.g., 0.0.2)")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[3]
    note_dir = repo_root / "note"

    mode = args.mode.lower()
    prefixes = {
        "release": "v",
        "test": "PreRelease_",
        "beta": "Beta_",
        "alpha": "Alpha_",
    }
    if mode not in prefixes:
        raise RuntimeError(f"Unknown mode: {mode}")

    # If custom version provided, use it
    if args.version:
        # Parse custom version
        custom_parts = args.version.strip().lstrip('v').replace('_', '.').split('.')
        version = tuple(int(p) for p in custom_parts if p.isdigit())
        if not version or len(version) < 3:
            raise RuntimeError(f"Invalid version format: {args.version}. Expected: X.Y.Z or X_Y_Z")
        
        # Create a synthetic note path for reporting (won't be used but needed for metadata)
        note_filename = f"{prefixes[mode]}{args.version.replace('.', '_')}.md"
        note_path = note_dir / note_filename
        
        # Validate against main version if in release mode
        main_tag = latest_tag("v", repo_root)
        main_version = parse_version(main_tag) if main_tag else None
        if mode == "release" and main_version and version <= main_version:
            raise RuntimeError(f"Custom version {version} must be greater than current release {main_version}")
    else:
        # File-based version lookup (original behavior)
        version, note_path = find_note(note_dir, prefixes[mode])
        if not note_path:
            raise RuntimeError(f"No release note found for {mode}")

        main_tag = latest_tag("v", repo_root)
        main_version = parse_version(main_tag) if main_tag else None
        if main_version and version and version > main_version:
            raise RuntimeError("Release note version exceeds main release tag")

    version_str = ".".join(str(x) for x in version)
    prerelease = mode in {"test", "beta", "alpha"}
    skip_publish = (mode in {"beta", "alpha"}) and args.force.lower() != "true"

    print(f"PY_VERSION={version_str}")
    print(f"NOTE_PATH={note_path.as_posix()}")
    print(f"RELEASE_MODE={mode}")
    print(f"PRERELEASE={'true' if prerelease else 'false'}")
    print(f"SKIP_PUBLISH={'true' if skip_publish else 'false'}")


if __name__ == "__main__":
    main()
