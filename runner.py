import argparse
import sys
import os
import io
import time
import subprocess

# Force UTF-8 output on Windows to handle binary PQC key/signature bytes
if hasattr(sys.stdout, 'buffer'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'buffer'):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add project root to path (current directory)
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from script.core import Config, Logger, Builder
from script.gen.main import hash as hash_main
from script.gen.main import pqc as pqc_main
from script.gen.main import core as core_main

# Primary Layer (Layer 4) - Full and Lite
from script.gen.primary import system as system_main
from script.gen.primary import system_lite as lite_system

# Lite Variant - only unified system DLL (primary/main_lite)
from script.gen.main import pow as pow_main
from script.test.main import pow as test_pow_main
from script.test.main import hash as test_hash_main
from script.test.main import pqc as test_pqc_main
from script.test.main import core as test_core_main

# Primary Layer Tests
from script.test.primary import system as test_system_main
from script.test.primary import system_lite as test_system_lite

# WASM KAT modules (Python/wasmtime)
from script.web import hash as web_hash_test
from script.web import core as web_core_test
from script.web import pqc as web_pqc_test
from script.web import pow as web_pow_test
from script.web import system as web_system_test

PLATFORM_LIB_EXT = {
    'windows': '.dll',
    'linux': '.so',
    'mac': '.dylib',
    'web': '.wasm'
}

# ── Load-map integration ───────────────────────────────────────────────────────
from script.core.load import LOAD_MAP, LOAD_MAP_ALL, LOAD_MAP_QUICK, PRIMARY_ALWAYS
from script.core.test_catalog import QUICK_MAP, FULL_MAP, HYPER_MAP

_LOAD_MAPS = {
    'gen':      LOAD_MAP,
    'genAll':   LOAD_MAP_ALL,
    'genQuick': LOAD_MAP_QUICK,
}

# Maps load.py module_path → imported test module object
# Updated whenever test imports change in runner.py
_MODULE_REGISTRY = {
    # main
    'main/hash':                          test_hash_main,
    'main/pqc':                           test_pqc_main,
    'main/core':                          test_core_main,
    'main/pow':                           test_pow_main,   # includes dhcm + pow_combined
    # primary
    'primary/system':                     test_system_main,
    'primary/system_lite':                test_system_lite,
    # web/wasm (Python/wasmtime KAT modules)
    'web/main/hash':                      web_hash_test,
    'web/main/core':                      web_core_test,
    'web/main/pqc':                       web_pqc_test,
    'web/main/pow':                       web_pow_test,
    'web/primary/main':                   web_system_test,
}


def _resolve_modules_from_map(load_map, target):
    """Return ordered list of test modules for group:tier from a LOAD_MAP.

    Returns None if the target format is not group:tier (caller falls back to
    legacy dispatch).  Returns an empty list if the map says build-only for
    every module in this tier×group.
    """
    parts = target.split(':')
    if len(parts) < 2:
        return None

    group, tier = parts[0], parts[1]

    # system:main lives in load_map['primary']
    map_tier = 'primary' if (group == 'system' or tier == 'system') else tier
    if map_tier not in load_map:
        return None

    tier_map = load_map[map_tier]

    # Build the filter for this group within the tier
    if map_tier == 'primary':
        filtered = {k: v for k, v in tier_map.items() if 'system' in k}
    elif map_tier == 'main':
        filtered = {k: v for k, v in tier_map.items()
                    if k == f'main/{group}'
                    or k.startswith(f'main/{group}_')
                    or k.startswith(f'main/{group}/')}
    else:
        return None

    modules = []
    seen_ids = set()
    for mod_path, test_keys in filtered.items():
        if not test_keys:
            # build-only marker unless PRIMARY_ALWAYS overrides it
            if map_tier != 'primary' or not PRIMARY_ALWAYS.get(mod_path):
                continue
        module = _MODULE_REGISTRY.get(mod_path)
        if module is not None and id(module) not in seen_ids:
            modules.append(module)
            seen_ids.add(id(module))

    return modules

def resolve_platform_settings(platform, project_root):
    if not platform:
        return None, None
    platform = platform.lower()
    lib_ext = PLATFORM_LIB_EXT.get(platform)
    if platform == 'web':
        return os.path.join(project_root, 'bin', 'web'), lib_ext
    if platform in ['windows', 'linux', 'mac']:
        return os.path.join(project_root, 'bin', platform), lib_ext
    return None, None

# ── Layer → DLL name mapping (layer strings don't always match file names) ────
_LAYER_DLL_MAP = {
    'main/hash':           ('main',    'hash'),
    'main/core':           ('main',    'core'),
    'main/pqc':            ('main',    'pqc'),
    'main/pow':            ('main',    'pow'),
    'main/dhcm':           ('main',    'dhcm'),
    'primary/system':      ('primary', 'main'),
    'primary/system_lite': ('primary', 'main_lite'),
}

# Symbol name hints for quickTest: layer → canonical exported C symbol.
# Used when the default "nextssl_{item}" derivation is ambiguous.
_LAYER_SYMBOL_HINT = {
    'main/pqc':            'nextssl_mlkem768_keypair',
    'main/pow':            'nextssl_pow_server_generate_challenge',
    'primary/system':      'nextssl_hash',
    'primary/system_lite': 'nextssl_hash',
}

def _resolve_dll_path_for_layer(config, layer):
    """Return the absolute DLL path for a layer string like 'main/hash'."""
    mapping = _LAYER_DLL_MAP.get(layer)
    if mapping:
        return config.get_lib_path(mapping[0], mapping[1])
    # Fallback: split layer and use last part as name
    parts = layer.rstrip('/').split('/')
    if len(parts) >= 2:
        return config.get_lib_path(parts[0], parts[-1])
    return None

def _get_symbol_for_entry(key, layer):
    """Derive the C symbol name to hasattr-check for a quickTest catalog entry."""
    # Use layer-level hint for layers where entry-level derivation is wrong
    hint = _LAYER_SYMBOL_HINT.get(layer)
    if hint:
        return hint
    # Default: nextssl_{item}  e.g. hash.sha256 → nextssl_sha256
    item = key.split('.', 1)[1]
    # Special-case normalisations
    if item == 'chacha20':
        return 'nextssl_chacha20_poly1305_encrypt'
    if item.startswith('root_'):
        return f'nextssl_{item}'
    return f'nextssl_{item}'

def run_mode_test(config, mode_map, label, args):
    """Run one of the three structured test modes (quick/full/hyper).

    Groups mode_map entries by layer to avoid loading each DLL more than once.
    Returns 0 if all checks pass, 1 otherwise.
    """
    import ctypes
    from collections import defaultdict
    from script.core import console

    MIN_WASM_SIZE = 50 * 1024  # bytes — anything under 50 KB is likely a dead-stripped stub

    is_web = (config.get_shared_lib_ext() == '.wasm')

    # Group entries by layer
    layer_entries = defaultdict(list)
    for key, entry in mode_map.items():
        layer_entries[entry['layer']].append((key, entry))

    results = []  # list of (key, passed: bool)

    for layer in sorted(layer_entries.keys()):
        entries = layer_entries[layer]

        # ── WASM checks ───────────────────────────────────────────────────────
        if layer.startswith('web/'):
            if not is_web:
                continue  # skip wasm entries on non-web platforms            # Derive wasm path: 'web/main/hash' → config.bin_dir/main/hash.wasm
            rel = '/'.join(layer.split('/')[1:])   # 'main/hash'
            wasm_path = os.path.join(config.bin_dir, *rel.split('/')) + '.wasm' \
                        if config.bin_dir else None

            for key, entry in entries:
                if wasm_path is None:
                    console.print_fail(f"[{label}] {key}: no bin dir configured")
                    results.append((key, False))
                    continue

                check = entry['check']
                if check == 'file_size':
                    exists = os.path.exists(wasm_path)
                    size = os.path.getsize(wasm_path) if exists else 0
                    ok = exists and size > MIN_WASM_SIZE
                    if ok:
                        console.print_pass(f"[{label}] {key}: {os.path.basename(wasm_path)} ({size} B)")
                    else:
                        console.print_fail(f"[{label}] {key}: missing or stub ({size} B) — {wasm_path}")
                    results.append((key, ok))

                elif check == 'wasm_exec':
                    if not (wasm_path and os.path.exists(wasm_path)):
                        console.print_fail(f"[{label}] {key}: WASM file not found — {wasm_path}")
                        results.append((key, False))
                        continue
                    try:
                        r = subprocess.run(
                            ['wasmtime', '--invoke', 'nextssl_wasm_selftest', wasm_path],
                            capture_output=True, text=True
                        )
                        ok = (r.stdout.strip() == "0")
                        if ok:
                            console.print_pass(f"[{label}] {key}: selftest OK")
                        else:
                            console.print_fail(f"[{label}] {key}: selftest failed (stdout={r.stdout.strip()!r})")
                        results.append((key, ok))
                    except FileNotFoundError:
                        console.print_fail(f"[{label}] {key}: wasmtime not found in PATH")
                        results.append((key, False))
                    except Exception as e:
                        console.print_fail(f"[{label}] {key}: {e}")
                        results.append((key, False))

                elif check == 'wasm_module':
                    module = _MODULE_REGISTRY.get(layer)
                    if module is None:
                        console.print_fail(f"[{label}] {key}: no web test module for '{layer}'")
                        results.append((key, False))
                        continue
                    try:
                        ok = (module.main() == 0)
                    except Exception as exc:
                        ok = False
                        console.print_fail(f"[{label}] {layer}: {exc}")
                    if ok:
                        console.print_pass(f"[{label}] {key}: WASM KAT OK")
                    else:
                        console.print_fail(f"[{label}] {key}: WASM KAT FAILED")
                    results.append((key, ok))
            continue

        # ── Native checks ─────────────────────────────────────────────────────
        if is_web:
            continue  # on web platform only wasm.* entries are checked
        check_types = {e['check'] for _, e in entries}

        if 'symbol' in check_types:
            # Load DLL once, check one symbol per entry
            dll_path = _resolve_dll_path_for_layer(config, layer)
            lib = None
            if dll_path and os.path.exists(dll_path):
                try:
                    lib = ctypes.CDLL(dll_path)
                except Exception as load_err:
                    lib = None
            for key, entry in entries:
                if lib is None:
                    console.print_fail(f"[{label}] {key}: DLL not loaded ({dll_path})")
                    results.append((key, False))
                else:
                    sym = _get_symbol_for_entry(key, layer)
                    if hasattr(lib, sym):
                        console.print_pass(f"[{label}] {key}: {sym} OK")
                        results.append((key, True))
                    else:
                        console.print_fail(f"[{label}] {key}: symbol '{sym}' not found in {dll_path}")
                        results.append((key, False))

        elif 'execute' in check_types:
            # Run the test module once; all entries for this layer share the result
            module = _MODULE_REGISTRY.get(layer)
            if module is None:
                for key, _ in entries:
                    console.print_fail(f"[{label}] {key}: no test module registered for layer '{layer}'")
                    results.append((key, False))
                continue

            try:
                res = module.main()
                ok = (res == 0)
            except Exception as exc:
                ok = False
                console.print_fail(f"[{label}] {layer}: module.main() crashed: {exc}")

            for key, _ in entries:
                if ok:
                    console.print_pass(f"[{label}] {key}")
                else:
                    console.print_fail(f"[{label}] {key}: FAILED")
                results.append((key, ok))

    total = len(results)
    failed = sum(1 for _, ok in results if not ok)

    print(f"\n{'='*50}")
    if failed == 0:
        console.print_pass(f"[{label}] ALL TESTS PASSED ({total} checks)")
    else:
        console.print_fail(f"[{label}] FAILED: {failed}/{total} checks")

    return 0 if failed == 0 else 1

def create_config(args):
    project_root = os.path.abspath(os.path.dirname(__file__))
    platform = args.platform or os.getenv('NEXTSSL_PLATFORM')
    bin_dir, lib_ext = resolve_platform_settings(platform, project_root)
    if args.bin_root:
        bin_dir = os.path.abspath(os.path.join(project_root, args.bin_root)) if not os.path.isabs(args.bin_root) else args.bin_root
    no_log = getattr(args, 'no_log', False)
    log_dir = None if no_log else (args.log_root or os.path.join(project_root, 'logs'))
    lib_ext = args.lib_ext or lib_ext
    if bin_dir:
        os.environ['NEXTSSL_BIN_DIR'] = bin_dir
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
        os.environ['NEXTSSL_LOG_DIR'] = log_dir
    if lib_ext:
        os.environ['NEXTSSL_LIB_EXT'] = lib_ext
    return Config(bin_dir=bin_dir, log_dir=log_dir, lib_ext=lib_ext)

def pick_module_by_name(name, modules):
    for module in modules:
        if module.__name__.endswith(name):
            return module
    return None

def resolve_web_paths(config, selector):
    ext = config.get_shared_lib_ext()
    def make(tier, name, subdirs=None, root=False):
        if root:
            return os.path.join(config.bin_dir, f"{name}{ext}")
        if subdirs:
            return os.path.join(config.bin_dir, tier, *subdirs, f"{name}{ext}")
        return os.path.join(config.bin_dir, tier, f"{name}{ext}")

    parts = selector.split(':')
    if selector == 'system:main':
        return [make('primary', 'main')]
    if selector == 'lite:main':
        return [make('primary', 'main_lite')]

    if len(parts) < 2:
        return []

    group = parts[0]
    item = parts[1]

    if group == 'hash':
        if item == 'main':
            return [make('main', 'hash')]
        return []

    if group == 'core':
        if item == 'main':
            return [make('main', 'core')]
        return []

    if group == 'dhcm':
        if item == 'main':
            return [make('main', 'dhcm')]
        return []

    if group == 'pqc':
        if item == 'main':
            return [make('main', 'pqc')]
        return []

    if group == 'pow':
        if item == 'main':
            return [make('main', 'pow')]
        return []

    return []

def run_web_test(config, selector):
    paths = resolve_web_paths(config, selector)
    if not paths:
        console.print_fail(f"Web test selector not supported: {selector}")
        return 1
    missing = []
    for path in paths:
        if not os.path.exists(path):
            missing.append(path)
        else:
            size = os.path.getsize(path)
            if size <= 0:
                missing.append(path)
            else:
                console.print_pass(f"WASM present: {path}")
    if missing:
        for path in missing:
            console.print_fail(f"WASM missing: {path}")
        return 1
    failures = 0
    for path in paths:
        try:
            result = subprocess.run(
                ['wasmtime', '--invoke', 'nextssl_wasm_selftest', path],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                console.print_fail(f"WASM execute failed: {path}")
                failures += 1
            else:
                console.print_pass(f"WASM execute ok: {path}")
        except FileNotFoundError:
            console.print_fail("wasmtime not found in PATH")
            return 1
        except Exception as e:
            console.print_fail(f"WASM execute error: {e}")
            return 1
    return 0 if failures == 0 else 1

def run_build(args):
    config = create_config(args)
    target = args.build
    platform = args.platform if hasattr(args, 'platform') else Platform.get_os()
    variant = args.variant if hasattr(args, 'variant') else 'full'
    
    # Use new runner log structure
    action_log = getattr(args, 'action_log', None)
    no_log = getattr(args, 'no_log', False)
    if no_log:
        log_path = None
    elif action_log:
        project_root = os.path.abspath(os.path.dirname(__file__))
        log_path = action_log if os.path.isabs(action_log) else os.path.join(project_root, action_log)
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
    else:
        action_type = getattr(args, 'action', None)
        log_path = config.get_runner_log_path(action_type)
    with Logger(log_path) as logger:
        builder = Builder(config, logger)
        build_ok = True
        def build_list(modules):
            nonlocal build_ok
            for m in modules:
                if not m.build(builder):
                    build_ok = False
        
        # Hash Modules
        hash_main_list = [hash_main]
        
        # PQC Modules
        pqc_main_list = [pqc_main]

        # Core Modules
        core_main_list = [core_main]
        system_main_list = [system_main]

        # Lite Variant - single unified DLL
        lite_main_list = [lite_system]

        # PoW Modules (includes dhcm + pow_combined builds)
        pow_main_list = [pow_main]
        pow_main_map = {
            'combined': pow_main,
            'pair': pow_main,
            'client': pow_main,
            'server': pow_main
        }
        
        # Build logic
        build_hash = False
        build_pqc = False
        build_core = False
        build_pow = False
        build_system = False
        build_lite = False
        
        # Handle variant flag
        # Determine variant (default to both when building all)
        variant = args.variant if hasattr(args, 'variant') else ('both' if target == 'all' else 'full')
        
        if target == 'all':
            if variant == 'lite':
                build_lite = True
            elif variant == 'full':
                build_hash = True
                build_pqc = True
                build_core = True
                build_pow = True
                build_system = True
            elif variant == 'both':
                build_hash = True
                build_pqc = True
                build_core = True
                build_pow = True
                build_system = True
                build_lite = True
        elif target == 'lite':
            build_lite = True
        elif target == 'hash':
            build_hash = True
        elif target == 'pqc':
            build_pqc = True
        elif target == 'core':
            build_core = True
        elif target == 'dhcm':
            build_pow = True   # dhcm is built by pow module
        elif target == 'pow':
            build_pow = True
        elif target == 'system':
            build_system = True
        elif target.startswith('hash:'):
            if target == 'hash:main':
                build_list(hash_main_list)
            else:
                name = target.split(':')[-1]
                module = pick_module_by_name(name, hash_main_list)
                if module:
                    build_list([module])
                else:
                    logger.error(f"Unknown target: {target}")
                    build_ok = False
            return build_ok
        elif target.startswith('pqc:'):
            if target == 'pqc:main':
                build_list(pqc_main_list)
            else:
                name = target.split(':')[-1]
                module = pick_module_by_name(name, pqc_main_list)
                if module:
                    build_list([module])
                else:
                    logger.error(f"Unknown target: {target}")
                    build_ok = False
            return build_ok
        elif target.startswith('core:'):
            if target == 'core:main':
                build_list(core_main_list)
            else:
                name = target.split(':')[-1]
                module = pick_module_by_name(name, core_main_list)
                if module:
                    build_list([module])
                else:
                    logger.error(f"Unknown target: {target}")
                    build_ok = False
            return build_ok
        elif target.startswith('dhcm:'):
            # dhcm is built/tested by pow module
            build_list(pow_main_list)
            return build_ok
        elif target.startswith('pow:'):
            if target == 'pow:main':
                build_list(pow_main_list)
            else:
                parts = target.split(':')
                module = None
                if len(parts) >= 3 and parts[1] == 'main':
                    module = pow_main_map.get(parts[2])
                if module:
                    build_list([module])
                else:
                    logger.error(f"Unknown target: {target}")
                    build_ok = False
            return build_ok
        elif target.startswith('system:'):
            if target == 'system:main':
                build_list(system_main_list)
            else:
                logger.error(f"Unknown target: {target}")
                build_ok = False
            return build_ok
        elif target.startswith('lite:'):
            # Specific lite target
            if target == 'lite:main':
                build_list(lite_main_list)
            else:
                name = target.split(':')[-1]
                module = pick_module_by_name(name, lite_main_list)
                if module:
                    build_list([module])
                else:
                    logger.error(f"Unknown target: {target}")
                    build_ok = False
            return build_ok
        else:
            logger.error(f"Unknown build target: {target}")
            return False

        if build_hash:
            logger.info("Building Hash targets...")
            build_list(hash_main_list)

        if build_pqc:
            logger.info("Building PQC targets...")
            build_list(pqc_main_list)

        if build_core:
            logger.info("Building Core targets...")
            build_list(core_main_list)

        if build_pow:
            logger.info("Building PoW+DHCM targets...")
            build_list(pow_main_list)
        
        if build_system:
            logger.info("Building System targets...")
            build_list(system_main_list)
        
        if build_lite:
            logger.info("Building Lite variant...")
            build_list(lite_main_list)
        
        return build_ok

def run_test(args):
    config = create_config(args)
    platform = args.platform if hasattr(args, 'platform') else Platform.get_os()
    variant = args.variant if hasattr(args, 'variant') else 'full'
    
    # Use new runner log structure
    action_log = getattr(args, 'action_log', None)
    no_log = getattr(args, 'no_log', False)
    if no_log:
        log_path = None
    elif action_log:
        project_root = os.path.abspath(os.path.dirname(__file__))
        log_path = action_log if os.path.isabs(action_log) else os.path.join(project_root, action_log)
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
    else:
        action_type = getattr(args, 'action', None)
        log_path = config.get_runner_log_path(action_type)
    with Logger(log_path, console_output=False) as logger:
        from script.core import console
        console.set_logger(logger)

        # ── Structured test modes (--quickTest / --fullTest / --hyperTest) ────
        if getattr(args, 'quick_test', False):
            return run_mode_test(config, QUICK_MAP, 'quickTest', args)
        if getattr(args, 'full_test', False):
            return run_mode_test(config, FULL_MAP, 'fullTest', args)
        if getattr(args, 'hyper_test', False):
            return run_mode_test(config, HYPER_MAP, 'hyperTest', args)

        target = args.test
        results = []
        test_modules = []
        
        if args.platform == 'web' or config.get_shared_lib_ext() == '.wasm':
            res = run_web_test(config, target)
            results.append((target, res))
            return res

        # ── Load-map dispatch (--load-mode gen|genAll|genQuick) ───────────────
        load_mode = getattr(args, 'load_mode', None) or 'gen'
        if load_mode in _LOAD_MAPS:
            resolved = _resolve_modules_from_map(_LOAD_MAPS[load_mode], target)
            if resolved is not None:
                if not resolved:
                    console.print_step(f"[LOAD] {target} is build-only in {load_mode} map — skipping tests")
                    return 0
                test_modules = resolved
                # jump directly to the run loop below
            # else: unrecognised format, fall through to legacy dispatch below


        if not test_modules:
            hash_main_list = [test_hash_main]
        
            # PQC Tests
            pqc_main_list = [test_pqc_main]

            # Core Tests
            core_main_list = [test_core_main]
            system_main_list = [test_system_main]

            # Lite Variant Tests - no individual module tests (single unified DLL)
            lite_hash_list = [test_system_lite]

            pow_main_list = [test_pow_main]   # includes dhcm + pow_combined tests
            pow_main_map = {
                'combined': test_pow_main,
                'pair': test_pow_main,
                'client': test_pow_main,
                'server': test_pow_main
            }

            run_hash = False
            run_pqc = False
            run_core = False
            run_pow = False
            run_system = False
            run_lite = False

            if target == 'all':
                run_hash = True
                run_pqc = True
                run_core = True
                run_pow = True
                run_system = True
                if variant == 'both' or variant == 'lite':
                    run_lite = True
            elif target == 'hash':
                run_hash = True
            elif target == 'pqc':
                run_pqc = True
            elif target == 'core':
                run_core = True
            elif target == 'dhcm':
                run_pow = True   # dhcm tested via pow module
            elif target == 'pow':
                run_pow = True
            elif target == 'system':
                run_system = True
            elif target.startswith('hash:'):
                if target == 'hash:main':
                    test_modules = hash_main_list
                else:
                    name = target.split(':')[-1]
                    module = pick_module_by_name(name, hash_main_list)
                    test_modules = [module] if module else []
            elif target.startswith('pqc:'):
                if target == 'pqc:main':
                    test_modules = pqc_main_list
                else:
                    name = target.split(':')[-1]
                    module = pick_module_by_name(name, pqc_main_list)
                    test_modules = [module] if module else []
            elif target.startswith('core:'):
                if target == 'core:main':
                    test_modules = core_main_list
                else:
                    name = target.split(':')[-1]
                    module = pick_module_by_name(name, core_main_list)
                    test_modules = [module] if module else []
            elif target.startswith('dhcm:'):
                # dhcm is tested via pow module
                test_modules = pow_main_list
            elif target.startswith('pow:'):
                if target == 'pow:main':
                    test_modules = pow_main_list
                else:
                    parts = target.split(':')
                    module = None
                    if len(parts) >= 3 and parts[1] == 'main':
                        module = pow_main_map.get(parts[2])
                    test_modules = [module] if module else []
            elif target.startswith('system:'):
                if target == 'system:main':
                    test_modules = system_main_list
            elif target.startswith('lite:'):
                # Lite variant tests
                if target == 'lite:main':
                    test_modules = lite_hash_list
                elif target == 'lite:all':
                    run_lite = True
                else:
                    console.print_fail(f"Unknown lite test: {target}")
                    return
            else:
                console.print_fail(f"Unknown test target: {target}")
                return

            if run_hash:
                test_modules.extend(hash_main_list)
            if run_pqc:
                test_modules.extend(pqc_main_list)
            if run_core:
                test_modules.extend(core_main_list)
            if run_pow:
                test_modules.extend(pow_main_list)
            if run_system:
                test_modules.extend(system_main_list)
            if run_lite:
                test_modules.extend(lite_hash_list)

        console.print_header(f"Running {len(test_modules)} test suites...")
        
        failed_count = 0
        for module in test_modules:
            console.print_step(f"Running {module.__name__}")
            try:
                res = module.main()
                results.append((module.__name__, res))
                if res != 0:
                    failed_count += 1
            except Exception as e:
                console.print_fail(f"Test crashed: {e}")
                results.append((module.__name__, 1))
                failed_count += 1

        print(f"\n{'='*50}")
        if failed_count == 0:
            console.print_pass("ALL TESTS PASSED")
        else:
            console.print_fail(f"TEST SUITE FAILED: {failed_count} modules failed")
            for name, res in results:
                if res != 0:
                    console.print_fail(f"  - {name} FAILED")
        return 0 if failed_count == 0 else 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NextSSL Build & Test Runner")
    parser.add_argument('--build', help="Build target (e.g., hash, hash:main, pow:main:combined)")
    parser.add_argument('--test', help="Test target (e.g., hash, hash:main, system:main)")
    parser.add_argument('--platform', type=str, choices=['windows', 'linux', 'mac', 'web'], help='Platform output selector')
    parser.add_argument('--variant', type=str, choices=['lite', 'full', 'both'], default='both', 
                        help='Build variant: lite (9 algorithms ~500KB), full (all algorithms ~5MB), or both')
    parser.add_argument('--action', type=str, help='GitHub action type (stores logs in logs/action/{action}/)')
    parser.add_argument('--action-log', type=str, dest='action_log', help='Write the runner log to this exact file path (e.g. logs/action/web/main/hash.log)')
    parser.add_argument('--bin-root', type=str, help='Override bin output root')
    parser.add_argument('--log-root', type=str, help='Override log output root')
    parser.add_argument('--lib-ext', type=str, help='Override output library extension')
    parser.add_argument('--no-color', action='store_true', help="Disable colored output")
    parser.add_argument('--load-mode', type=str, dest='load_mode',
                        choices=['gen', 'genAll', 'genQuick'], default='gen',
                        help='Test load mode: gen=default LOAD_MAP, genAll=LOAD_MAP_ALL, genQuick=LOAD_MAP_QUICK')
    parser.add_argument('--noLog', action='store_true', dest='no_log',
                        help='Disable file-based logging; console output is unaffected')
    parser.add_argument('--quickTest', action='store_true', dest='quick_test',
                        help='Symbol/presence check only — no algo execution')
    parser.add_argument('--fullTest', action='store_true', dest='full_test',
                        help='Full execution, each algo tested once in its home layer')
    parser.add_argument('--hyperTest', action='store_true', dest='hyper_test',
                        help='Full execution across every eligible layer (max coverage)')
    
    args = parser.parse_args()
    
    from script.core import console

    # --quickTest / --fullTest / --hyperTest activate run_test without --test
    mode_test = args.quick_test or args.full_test or args.hyper_test
    if mode_test and args.test:
        console.set_color(not args.no_color)
        print("ERROR: --quickTest/--fullTest/--hyperTest cannot be combined with --test")
        sys.exit(1)

    # Check for no-args behavior: default to build all + test all
    if not args.build and not args.test and not mode_test:
        args.build = 'all'
        args.test = 'all'

    # Mode-test flags need run_test to be invoked (with a dummy target so the
    # function is entered; the dispatch at the top of run_test handles it).
    if mode_test and not args.test:
        args.test = '__mode_test__'
    
    # Configure console colors
    console.set_color(not args.no_color)

    # Record start time
    start_time = time.time()
    console.print_header("NextSSL Build & Test Runner")

    build_ok = True
    if args.build:
        build_ok = run_build(args)
    
    # Record build time
    build_time = time.time() - start_time
    console.print_step(f"Build completed in {build_time:.2f} seconds")

    if not build_ok:
        console.print_fail("Build failed")
        sys.exit(1)

    test_code = 0
    if args.test:
        test_code = run_test(args)
    
    # Record test time
    test_time = time.time() - start_time - build_time
    console.print_step(f"Test completed in {test_time:.2f} seconds")
    sys.exit(test_code)
