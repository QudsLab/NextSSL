import importlib.util
from pathlib import Path
from typing import Any, Dict, List

KAT_DATA_DIR = Path(__file__).resolve().parent
IGNORED_FILES = {"__init__.py", "kat_base.py"}
VALID_GROUPS = {"encoding", "hash", "modern", "pqc"}

REQUIRED_META_KEYS = {"group", "algorithm", "source", "source_ref", "generated_by", "date"}
REQUIRED_CASE_KEYS = {"id", "input", "config", "output"}
OPTIONAL_CASE_KEYS = {"notes", "tags"}


def _module_name_from_path(path: Path) -> str:
    return path.relative_to(KAT_DATA_DIR).with_suffix("").as_posix()


def _module_path_from_name(module_name: str) -> Path:
    path = KAT_DATA_DIR / module_name
    if path.suffix == "":
        path = path.with_suffix(".py")
    return path


def load_kat_module(module_name: str):
    """Load a KAT module from KAT/data by module name.

    The module name may be a nested path like `encoding/base16` or
    `hash/sha256`.
    """
    path = _module_path_from_name(module_name)
    if not path.exists():
        raise FileNotFoundError(f"KAT module not found: {path}")

    spec = importlib.util.spec_from_file_location(_module_name_from_path(path), path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module spec for {path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_all_kats(validate: bool = True) -> Dict[str, Any]:
    """Load all KAT modules found in KAT/data and its subfolders."""
    modules = {}
    for path in sorted(KAT_DATA_DIR.rglob("*.py")):
        if path.name in IGNORED_FILES:
            continue
        module_name = _module_name_from_path(path)
        module = load_kat_module(module_name)
        if validate:
            validate_kat_module(module)
        modules[module_name] = module
    return modules


def validate_kat_module(module: Any) -> bool:
    """Validate that a module exports the required KAT structure."""
    if not hasattr(module, "meta"):
        raise ValueError("KAT module must export a 'meta' dict")
    if not hasattr(module, "cases"):
        raise ValueError("KAT module must export a 'cases' list")
    if not isinstance(module.meta, dict):
        raise TypeError("module.meta must be a dict")
    if not isinstance(module.cases, list):
        raise TypeError("module.cases must be a list")

    missing_meta = REQUIRED_META_KEYS - set(module.meta.keys())
    if missing_meta:
        raise ValueError(f"Missing required meta keys: {sorted(missing_meta)}")

    group = module.meta.get("group")
    if group not in VALID_GROUPS:
        raise ValueError(f"Invalid meta.group: {group}; expected one of {sorted(VALID_GROUPS)}")

    for index, case in enumerate(module.cases, start=1):
        _validate_case(case, index)
    return True


def _validate_case(case: Any, index: int) -> bool:
    if not isinstance(case, dict):
        raise TypeError(f"Case #{index} must be a dict")

    missing = REQUIRED_CASE_KEYS - set(case.keys())
    if missing:
        raise ValueError(f"Case #{index} is missing required keys: {sorted(missing)}")

    unknown = set(case.keys()) - REQUIRED_CASE_KEYS - OPTIONAL_CASE_KEYS
    if unknown:
        raise ValueError(f"Case #{index} contains unknown keys: {sorted(unknown)}")

    if not isinstance(case["id"], str):
        raise TypeError(f"Case #{index} 'id' must be a string")
    if not isinstance(case["input"], dict):
        raise TypeError(f"Case #{index} 'input' must be a dict")
    if not isinstance(case["config"], dict):
        raise TypeError(f"Case #{index} 'config' must be a dict")
    if not isinstance(case["output"], dict) and not isinstance(case["output"], str):
        raise TypeError(f"Case #{index} 'output' must be a dict or a string")

    if "notes" in case and case["notes"] is not None and not isinstance(case["notes"], str):
        raise TypeError(f"Case #{index} 'notes' must be a string or None")
    if "tags" in case and case["tags"] is not None and not isinstance(case["tags"], list):
        raise TypeError(f"Case #{index} 'tags' must be a list or None")
    return True
