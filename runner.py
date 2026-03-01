import argparse
import sys
import os
import time
import subprocess

# Add project root to path (current directory)
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from script.core import Config, Logger, Builder

from script.gen.partial.hash import primitive_fast, primitive_memory_hard, primitive_sponge_xof, legacy_alive, legacy_unsafe
from script.gen.base import hash_primitive_main, hash_legacy_main
from script.gen.main import hash as hash_main

from script.gen.partial.pqc import kem_lattice, kem_code_based, sign_lattice, sign_hash_based
from script.gen.base import pqc_kem_main, pqc_sign_main
from script.gen.main import pqc as pqc_main

from script.gen.partial.core import aes_modes, aes_aead, stream_aead, macs, ecc
from script.gen.base import core_cipher_main, core_mac_main, core_ecc_main
from script.gen.main import core as core_main

from script.gen.partial.dhcm import primitive_fast as dhcm_primitive_fast, primitive_memory_hard as dhcm_primitive_memory_hard, primitive_sponge_xof as dhcm_primitive_sponge_xof, legacy_alive as dhcm_legacy_alive, legacy_unsafe as dhcm_legacy_unsafe
from script.gen.base import dhcm_primitive_main, dhcm_legacy_main
from script.gen.main import dhcm as dhcm_main

# Primary Layer (Layer 4) - Full and Lite
from script.gen.primary import system as system_main
from script.gen.primary import system_lite as lite_system

# Lite Variant - only unified system DLL (primary/main_lite)

from script.gen.partial.pow.server import primitive_fast as pow_server_primitive_fast, primitive_memory_hard as pow_server_primitive_memory_hard, primitive_sponge_xof as pow_server_primitive_sponge_xof, legacy_alive as pow_server_legacy_alive, legacy_unsafe as pow_server_legacy_unsafe
from script.gen.partial.pow.client import primitive_fast as pow_client_primitive_fast, primitive_memory_hard as pow_client_primitive_memory_hard, primitive_sponge_xof as pow_client_primitive_sponge_xof, legacy_alive as pow_client_legacy_alive, legacy_unsafe as pow_client_legacy_unsafe
from script.gen.partial.pow.combined import primitive_fast as pow_combined_primitive_fast, primitive_memory_hard as pow_combined_primitive_memory_hard, primitive_sponge_xof as pow_combined_primitive_sponge_xof, legacy_alive as pow_combined_legacy_alive, legacy_unsafe as pow_combined_legacy_unsafe
from script.gen.base import pow_primitive, pow_legacy, pow_combined as pow_combined_base
from script.gen.main import pow as pow_main, pow_combined as pow_combined_main

from script.test.partial.pow import primitive_fast as test_pow_primitive_fast
from script.test.partial.pow import primitive_memory_hard as test_pow_primitive_memory_hard
from script.test.partial.pow import primitive_sponge_xof as test_pow_primitive_sponge_xof
from script.test.partial.pow import legacy_alive as test_pow_legacy_alive
from script.test.partial.pow import legacy_unsafe as test_pow_legacy_unsafe
from script.test.partial.pow.combined import primitive_fast as test_pow_combined_primitive_fast
from script.test.partial.pow.combined import primitive_memory_hard as test_pow_combined_primitive_memory_hard
from script.test.partial.pow.combined import primitive_sponge_xof as test_pow_combined_primitive_sponge_xof
from script.test.partial.pow.combined import legacy_alive as test_pow_combined_legacy_alive
from script.test.partial.pow.combined import legacy_unsafe as test_pow_combined_legacy_unsafe
from script.test.base import pow_primitive as test_pow_primitive, pow_legacy as test_pow_legacy, pow_combined as test_pow_combined_base
from script.test.main import pow as test_pow_main, pow_combined as test_pow_combined_main
from script.test.partial.hash import primitive_fast as test_primitive_fast
from script.test.partial.hash import primitive_memory_hard as test_primitive_memory_hard
from script.test.partial.hash import primitive_sponge_xof as test_primitive_sponge_xof
from script.test.partial.hash import legacy_alive as test_legacy_alive
from script.test.partial.hash import legacy_unsafe as test_legacy_unsafe
from script.test.base import hash_primitive_main as test_hash_primitive_main
from script.test.base import hash_legacy_main as test_hash_legacy_main
from script.test.main import hash as test_hash_main

from script.test.partial.pqc import kem_lattice as test_kem_lattice
from script.test.partial.pqc import kem_code_based as test_kem_code_based
from script.test.partial.pqc import sign_lattice as test_sign_lattice
from script.test.partial.pqc import sign_hash_based as test_sign_hash_based
from script.test.base import pqc_kem_main as test_pqc_kem_main
from script.test.base import pqc_sign_main as test_pqc_sign_main
from script.test.main import pqc as test_pqc_main

from script.test.partial.core import aes_modes as test_aes_modes
from script.test.partial.core import aes_aead as test_aes_aead
from script.test.partial.core import stream_aead as test_stream_aead
from script.test.partial.core import macs as test_macs
from script.test.partial.core import ecc as test_ecc
from script.test.base import core_cipher_main as test_core_cipher_main
from script.test.base import core_mac_main as test_core_mac_main
from script.test.base import core_ecc_main as test_core_ecc_main
from script.test.main import core as test_core_main

# Primary Layer Tests
from script.test.primary import system as test_system_main
from script.test.primary import system_lite as test_system_lite

# Lite Variant Tests - tested via primary/main_lite

from script.test.partial.dhcm import primitive_fast as test_dhcm_primitive_fast
from script.test.partial.dhcm import primitive_memory_hard as test_dhcm_primitive_memory_hard
from script.test.partial.dhcm import primitive_sponge_xof as test_dhcm_primitive_sponge_xof
from script.test.partial.dhcm import legacy_alive as test_dhcm_legacy_alive
from script.test.partial.dhcm import legacy_unsafe as test_dhcm_legacy_unsafe
from script.test.base import dhcm_primitive_main as test_dhcm_primitive_main
from script.test.base import dhcm_legacy_main as test_dhcm_legacy_main
from script.test.main import dhcm as test_dhcm_main

PLATFORM_LIB_EXT = {
    'windows': '.dll',
    'linux': '.so',
    'mac': '.dylib',
    'web': '.wasm'
}

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

def create_config(args):
    project_root = os.path.abspath(os.path.dirname(__file__))
    platform = args.platform or os.getenv('NEXTSSL_PLATFORM')
    bin_dir, lib_ext = resolve_platform_settings(platform, project_root)
    if args.bin_root:
        bin_dir = os.path.abspath(os.path.join(project_root, args.bin_root)) if not os.path.isabs(args.bin_root) else args.bin_root
    log_dir = args.log_root or os.path.join(project_root, 'logs')
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

    hash_partial_items = ['legacy_alive', 'legacy_unsafe', 'primitive_fast', 'primitive_memory_hard', 'primitive_sponge_xof']
    hash_base_items = ['hash_legacy', 'hash_primitive']
    core_partial_items = ['aes_aead', 'aes_modes', 'ecc', 'macs', 'stream_aead']
    core_base_items = ['core_cipher_main', 'core_ecc_main', 'core_mac_main']
    dhcm_partial_items = ['legacy_alive', 'legacy_unsafe', 'primitive_fast', 'primitive_memory_hard', 'primitive_sponge_xof']
    dhcm_base_items = ['dhcm_legacy', 'dhcm_primitive']
    pqc_partial_items = ['kem_code_based', 'kem_lattice', 'sign_hash_based', 'sign_lattice']
    pqc_base_items = ['pqc_kem_main', 'pqc_sign_main']
    pow_partial_items = ['primitive_fast', 'primitive_memory_hard', 'primitive_sponge_xof', 'legacy_alive', 'legacy_unsafe']
    pow_partial_subdirs = ['server', 'client', 'combined']

    parts = selector.split(':')
    if selector == 'system:main':
        return [make(None, 'main', root=True)]

    if len(parts) < 2:
        return []

    group = parts[0]
    item = parts[1]

    if group == 'hash':
        if item == 'main':
            return [make('main', 'hash')]
        if item == 'partial':
            return [make('partial', name, ['hash']) for name in hash_partial_items]
        if item == 'base':
            return [make('base', name) for name in hash_base_items]
        if item == 'hash_legacy_main':
            return [make('base', 'hash_legacy')]
        if item == 'hash_primitive_main':
            return [make('base', 'hash_primitive')]
        return [make('partial', item, ['hash'])]

    if group == 'core':
        if item == 'main':
            return [make('main', 'core')]
        if item == 'partial':
            return [make('partial', name, ['core']) for name in core_partial_items]
        if item == 'base':
            return [make('base', name) for name in core_base_items]
        if item in ['core_cipher_main', 'core_ecc_main', 'core_mac_main']:
            return [make('base', item)]
        return [make('partial', item, ['core'])]

    if group == 'dhcm':
        if item == 'main':
            return [make('main', 'dhcm')]
        if item == 'partial':
            return [make('partial', name, ['dhcm']) for name in dhcm_partial_items]
        if item == 'base':
            return [make('base', name) for name in dhcm_base_items]
        if item == 'dhcm_legacy_main':
            return [make('base', 'dhcm_legacy')]
        if item == 'dhcm_primitive_main':
            return [make('base', 'dhcm_primitive')]
        return [make('partial', item, ['dhcm'])]

    if group == 'pqc':
        if item == 'main':
            return [make('main', 'pqc')]
        if item == 'partial':
            return [make('partial', name, ['pqc']) for name in pqc_partial_items]
        if item == 'base':
            return [make('base', name) for name in pqc_base_items]
        if item == 'pqc_kem_main':
            return [make('base', 'pqc_kem_main')]
        if item == 'pqc_sign_main':
            return [make('base', 'pqc_sign_main')]
        return [make('partial', item, ['pqc'])]

    if group == 'pow':
        if item == 'main':
            if len(parts) == 2 or parts[2] == 'pair':
                return [make('main', 'pow_client'), make('main', 'pow_server')]
            if parts[2] == 'client':
                return [make('main', 'pow_client')]
            if parts[2] == 'server':
                return [make('main', 'pow_server')]
            if parts[2] == 'combined':
                return [make('main', 'pow_combined')]
        if item == 'partial':
            return [
                make('partial', name, ['pow', subdir])
                for name in pow_partial_items
                for subdir in pow_partial_subdirs
            ]
        if item == 'base':
            if len(parts) == 2:
                return [
                    make('base', 'pow_client_primitive'),
                    make('base', 'pow_server_primitive'),
                    make('base', 'pow_client_legacy'),
                    make('base', 'pow_server_legacy'),
                    make('base', 'pow_combined')
                ]
            if len(parts) >= 3 and parts[2] == 'primitive':
                return [make('base', 'pow_client_primitive'), make('base', 'pow_server_primitive')]
            if len(parts) >= 3 and parts[2] == 'legacy':
                return [make('base', 'pow_client_legacy'), make('base', 'pow_server_legacy')]
            if len(parts) >= 3 and parts[2] == 'combined':
                return [make('base', 'pow_combined')]
        if item == 'partial':
            if len(parts) >= 4 and parts[2] in ['server', 'client']:
                return [make('partial', parts[3], ['pow', parts[2]])]
            if len(parts) >= 4 and parts[2] == 'combined':
                return [make('partial', parts[3], ['pow', 'combined'])]
            if len(parts) >= 4 and parts[2] == 'pair':
                return [
                    make('partial', parts[3], ['pow', 'server']),
                    make('partial', parts[3], ['pow', 'client'])
                ]
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
    if action_log:
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
        hash_partial = [primitive_fast, primitive_memory_hard, primitive_sponge_xof, legacy_alive, legacy_unsafe]
        hash_base = [hash_primitive_main, hash_legacy_main]
        hash_main_list = [hash_main]
        
        # PQC Modules
        pqc_partial = [kem_lattice, kem_code_based, sign_lattice, sign_hash_based]
        pqc_base = [pqc_kem_main, pqc_sign_main]
        pqc_main_list = [pqc_main]

        # Core Modules
        core_partial = [aes_modes, aes_aead, stream_aead, macs, ecc]
        core_base = [core_cipher_main, core_mac_main, core_ecc_main]
        core_main_list = [core_main]
        system_main_list = [system_main]

        # Lite Variant - single unified DLL
        lite_main_list = [lite_system]

        # DHCM Modules
        dhcm_partial = [dhcm_primitive_fast, dhcm_primitive_memory_hard, dhcm_primitive_sponge_xof, dhcm_legacy_alive, dhcm_legacy_unsafe]
        dhcm_base = [dhcm_primitive_main, dhcm_legacy_main]
        dhcm_main_list = [dhcm_main]

        # PoW Modules
        pow_partial = [
            pow_server_primitive_fast, pow_client_primitive_fast, pow_combined_primitive_fast,
            pow_server_primitive_memory_hard, pow_client_primitive_memory_hard, pow_combined_primitive_memory_hard,
            pow_server_primitive_sponge_xof, pow_client_primitive_sponge_xof, pow_combined_primitive_sponge_xof,
            pow_server_legacy_alive, pow_client_legacy_alive, pow_combined_legacy_alive,
            pow_server_legacy_unsafe, pow_client_legacy_unsafe, pow_combined_legacy_unsafe
        ]
        pow_base = [pow_primitive, pow_legacy, pow_combined_base]
        pow_main_list = [pow_main, pow_combined_main]
        pow_partial_map = {
            ('server', 'primitive_fast'): pow_server_primitive_fast,
            ('server', 'primitive_memory_hard'): pow_server_primitive_memory_hard,
            ('server', 'primitive_sponge_xof'): pow_server_primitive_sponge_xof,
            ('server', 'legacy_alive'): pow_server_legacy_alive,
            ('server', 'legacy_unsafe'): pow_server_legacy_unsafe,
            ('client', 'primitive_fast'): pow_client_primitive_fast,
            ('client', 'primitive_memory_hard'): pow_client_primitive_memory_hard,
            ('client', 'primitive_sponge_xof'): pow_client_primitive_sponge_xof,
            ('client', 'legacy_alive'): pow_client_legacy_alive,
            ('client', 'legacy_unsafe'): pow_client_legacy_unsafe,
            ('combined', 'primitive_fast'): pow_combined_primitive_fast,
            ('combined', 'primitive_memory_hard'): pow_combined_primitive_memory_hard,
            ('combined', 'primitive_sponge_xof'): pow_combined_primitive_sponge_xof,
            ('combined', 'legacy_alive'): pow_combined_legacy_alive,
            ('combined', 'legacy_unsafe'): pow_combined_legacy_unsafe
        }
        pow_base_map = {
            'primitive': pow_primitive,
            'legacy': pow_legacy,
            'combined': pow_combined_base
        }
        pow_main_map = {
            'combined': pow_combined_main,
            'pair': pow_main,
            'client': pow_main,
            'server': pow_main
        }
        
        # Build logic
        build_hash = False
        build_pqc = False
        build_core = False
        build_dhcm = False
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
                build_dhcm = True
                build_pow = True
                build_system = True
            elif variant == 'both':
                build_hash = True
                build_pqc = True
                build_core = True
                build_dhcm = True
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
            build_dhcm = True
        elif target == 'pow':
            build_pow = True
        elif target == 'system':
            build_system = True
        elif target.startswith('hash:'):
            # Specific hash target
            if target == 'hash:partial':
                build_list(hash_partial)
            elif target == 'hash:base':
                build_list(hash_base)
            elif target == 'hash:main':
                build_list(hash_main_list)
            else:
                name = target.split(':')[-1]
                module = pick_module_by_name(name, hash_partial + hash_base + hash_main_list)
                if module:
                    build_list([module])
                else:
                    logger.error(f"Unknown target: {target}")
                    build_ok = False
            return build_ok
        elif target.startswith('pqc:'):
            # Specific PQC target
            if target == 'pqc:partial':
                build_list(pqc_partial)
            elif target == 'pqc:base':
                build_list(pqc_base)
            elif target == 'pqc:main':
                build_list(pqc_main_list)
            else:
                name = target.split(':')[-1]
                module = pick_module_by_name(name, pqc_partial + pqc_base + pqc_main_list)
                if module:
                    build_list([module])
                else:
                    logger.error(f"Unknown target: {target}")
                    build_ok = False
            return build_ok
        elif target.startswith('core:'):
            # Specific Core target
            if target == 'core:partial':
                build_list(core_partial)
            elif target == 'core:base':
                build_list(core_base)
            elif target == 'core:main':
                build_list(core_main_list)
            else:
                name = target.split(':')[-1]
                module = pick_module_by_name(name, core_partial + core_base + core_main_list)
                if module:
                    build_list([module])
                else:
                    logger.error(f"Unknown target: {target}")
                    build_ok = False
            return build_ok
        elif target.startswith('dhcm:'):
            # Specific DHCM target
            if target == 'dhcm:partial':
                build_list(dhcm_partial)
            elif target == 'dhcm:base':
                build_list(dhcm_base)
            elif target == 'dhcm:main':
                build_list(dhcm_main_list)
            else:
                name = target.split(':')[-1]
                module = pick_module_by_name(name, dhcm_partial + dhcm_base + dhcm_main_list)
                if module:
                    build_list([module])
                else:
                    logger.error(f"Unknown target: {target}")
                    build_ok = False
            return build_ok
        elif target.startswith('pow:'):
            if target == 'pow:partial':
                build_list(pow_partial)
            elif target == 'pow:base':
                build_list(pow_base)
            elif target == 'pow:main':
                build_list(pow_main_list)
            else:
                parts = target.split(':')
                module = None
                if len(parts) >= 3 and parts[1] == 'partial':
                    if len(parts) >= 4 and parts[2] == 'pair':
                        server_module = pow_partial_map.get(('server', parts[3]))
                        client_module = pow_partial_map.get(('client', parts[3]))
                        if server_module:
                            build_list([server_module])
                        if client_module:
                            build_list([client_module])
                        if not server_module and not client_module:
                            logger.error(f"Unknown target: {target}")
                            build_ok = False
                        return build_ok
                    if len(parts) >= 4:
                        module = pow_partial_map.get((parts[2], parts[3]))
                    else:
                        module = pick_module_by_name(parts[2], pow_partial)
                elif len(parts) >= 3 and parts[1] == 'base':
                    module = pow_base_map.get(parts[2])
                elif len(parts) >= 3 and parts[1] == 'main':
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
            build_list(hash_partial + hash_base + hash_main_list)

        if build_pqc:
            logger.info("Building PQC targets...")
            build_list(pqc_partial + pqc_base + pqc_main_list)

        if build_core:
            logger.info("Building Core targets...")
            build_list(core_partial + core_base + core_main_list)

        if build_dhcm:
            logger.info("Building DHCM targets...")
            build_list(dhcm_partial + dhcm_base + dhcm_main_list)

        if build_pow:
            logger.info("Building PoW targets...")
            build_list(pow_partial + pow_base + pow_main_list)
        
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
    if action_log:
        project_root = os.path.abspath(os.path.dirname(__file__))
        log_path = action_log if os.path.isabs(action_log) else os.path.join(project_root, action_log)
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
    else:
        action_type = getattr(args, 'action', None)
        log_path = config.get_runner_log_path(action_type)
    with Logger(log_path, console_output=False) as logger:
        from script.core import console
        console.set_logger(logger)
        
        target = args.test
        results = []
        test_modules = []
        
        if args.platform == 'web' or config.get_shared_lib_ext() == '.wasm':
            res = run_web_test(config, target)
            results.append((target, res))
            return res
    
        # Hash Tests
        hash_partial = [
            test_primitive_fast, test_primitive_memory_hard, test_primitive_sponge_xof, 
            test_legacy_alive, test_legacy_unsafe
        ]
        hash_base = [test_hash_primitive_main, test_hash_legacy_main]
        hash_main_list = [test_hash_main]
        
        # PQC Tests
        pqc_partial = [
            test_kem_lattice, test_kem_code_based, test_sign_lattice, test_sign_hash_based
        ]
        pqc_base = [test_pqc_kem_main, test_pqc_sign_main]
        pqc_main_list = [test_pqc_main]

        # Core Tests
        core_partial = [
            test_aes_modes, test_aes_aead, test_stream_aead, test_macs, test_ecc
        ]
        core_base = [test_core_cipher_main, test_core_mac_main, test_core_ecc_main]
        core_main_list = [test_core_main]
        system_main_list = [test_system_main]

        # Lite Variant Tests - no individual module tests (single unified DLL)
        lite_hash_list = [test_system_lite]

        # DHCM Tests
        dhcm_partial = [
            test_dhcm_primitive_fast, test_dhcm_primitive_memory_hard, test_dhcm_primitive_sponge_xof,
            test_dhcm_legacy_alive, test_dhcm_legacy_unsafe
        ]
        dhcm_base = [test_dhcm_primitive_main, test_dhcm_legacy_main]
        dhcm_main_list = [test_dhcm_main]

        # PoW Tests
        pow_partial = [
            test_pow_primitive_fast,
            test_pow_primitive_memory_hard,
            test_pow_primitive_sponge_xof,
            test_pow_legacy_alive,
            test_pow_legacy_unsafe,
            test_pow_combined_primitive_fast,
            test_pow_combined_primitive_memory_hard,
            test_pow_combined_primitive_sponge_xof,
            test_pow_combined_legacy_alive,
            test_pow_combined_legacy_unsafe
        ]
        pow_base = [test_pow_primitive, test_pow_legacy, test_pow_combined_base]
        pow_main_list = [test_pow_main, test_pow_combined_main]
        pow_partial_map = {
            ('server', 'primitive_fast'): test_pow_primitive_fast,
            ('server', 'primitive_memory_hard'): test_pow_primitive_memory_hard,
            ('server', 'primitive_sponge_xof'): test_pow_primitive_sponge_xof,
            ('server', 'legacy_alive'): test_pow_legacy_alive,
            ('server', 'legacy_unsafe'): test_pow_legacy_unsafe,
            ('client', 'primitive_fast'): test_pow_primitive_fast,
            ('client', 'primitive_memory_hard'): test_pow_primitive_memory_hard,
            ('client', 'primitive_sponge_xof'): test_pow_primitive_sponge_xof,
            ('client', 'legacy_alive'): test_pow_legacy_alive,
            ('client', 'legacy_unsafe'): test_pow_legacy_unsafe,
            ('combined', 'primitive_fast'): test_pow_combined_primitive_fast,
            ('combined', 'primitive_memory_hard'): test_pow_combined_primitive_memory_hard,
            ('combined', 'primitive_sponge_xof'): test_pow_combined_primitive_sponge_xof,
            ('combined', 'legacy_alive'): test_pow_combined_legacy_alive,
            ('combined', 'legacy_unsafe'): test_pow_combined_legacy_unsafe,
            ('pair', 'primitive_fast'): test_pow_primitive_fast,
            ('pair', 'primitive_memory_hard'): test_pow_primitive_memory_hard,
            ('pair', 'primitive_sponge_xof'): test_pow_primitive_sponge_xof,
            ('pair', 'legacy_alive'): test_pow_legacy_alive,
            ('pair', 'legacy_unsafe'): test_pow_legacy_unsafe
        }
        pow_base_map = {
            'primitive': test_pow_primitive,
            'legacy': test_pow_legacy,
            'combined': test_pow_combined_base
        }
        pow_main_map = {
            'combined': test_pow_combined_main,
            'pair': test_pow_main,
            'client': test_pow_main,
            'server': test_pow_main
        }

        run_hash = False
        run_pqc = False
        run_core = False
        run_dhcm = False
        run_pow = False
        run_system = False
        run_lite = False

        if target == 'all':
            run_hash = True
            run_pqc = True
            run_core = True
            run_dhcm = True
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
            run_dhcm = True
        elif target == 'pow':
            run_pow = True
        elif target == 'system':
            run_system = True
        elif target.startswith('hash:'):
            if target == 'hash:partial': test_modules = hash_partial
            elif target == 'hash:base': test_modules = hash_base
            elif target == 'hash:main': test_modules = hash_main_list
            else:
                name = target.split(':')[-1]
                module = pick_module_by_name(name, hash_partial + hash_base + hash_main_list)
                test_modules = [module] if module else []
        elif target.startswith('pqc:'):
            if target == 'pqc:partial': test_modules = pqc_partial
            elif target == 'pqc:base': test_modules = pqc_base
            elif target == 'pqc:main': test_modules = pqc_main_list
            else:
                name = target.split(':')[-1]
                module = pick_module_by_name(name, pqc_partial + pqc_base + pqc_main_list)
                test_modules = [module] if module else []
        elif target.startswith('core:'):
            if target == 'core:partial': test_modules = core_partial
            elif target == 'core:base': test_modules = core_base
            elif target == 'core:main': test_modules = core_main_list
            else:
                name = target.split(':')[-1]
                module = pick_module_by_name(name, core_partial + core_base + core_main_list)
                test_modules = [module] if module else []
        elif target.startswith('dhcm:'):
            if target == 'dhcm:partial': test_modules = dhcm_partial
            elif target == 'dhcm:base': test_modules = dhcm_base
            elif target == 'dhcm:main': test_modules = dhcm_main_list
            else:
                name = target.split(':')[-1]
                module = pick_module_by_name(name, dhcm_partial + dhcm_base + dhcm_main_list)
                test_modules = [module] if module else []
        elif target.startswith('pow:'):
            if target == 'pow:partial': test_modules = pow_partial
            elif target == 'pow:base': test_modules = pow_base
            elif target == 'pow:main': test_modules = pow_main_list
            else:
                parts = target.split(':')
                module = None
                if len(parts) >= 3 and parts[1] == 'partial':
                    if len(parts) >= 4:
                        module = pow_partial_map.get((parts[2], parts[3]))
                    else:
                        module = pick_module_by_name(parts[2], pow_partial)
                elif len(parts) >= 3 and parts[1] == 'base':
                    module = pow_base_map.get(parts[2])
                elif len(parts) >= 3 and parts[1] == 'main':
                    module = pow_main_map.get(parts[2])
                test_modules = [module] if module else []
        elif target.startswith('system:'):
            if target == 'system:main':
                test_modules = system_main_list
        elif target.startswith('lite:'):
            # Lite variant tests
            if target == 'lite:all':
                run_lite = True
            else:
                console.print_fail(f"Unknown lite test: {target}")
                return
        else:
            console.print_fail(f"Unknown test target: {target}")
            return

        if run_hash:
            test_modules.extend(hash_partial + hash_base + hash_main_list)
        if run_pqc:
            test_modules.extend(pqc_partial + pqc_base + pqc_main_list)
        if run_core:
            test_modules.extend(core_partial + core_base + core_main_list)
        if run_dhcm:
            test_modules.extend(dhcm_partial + dhcm_base + dhcm_main_list)
        if run_pow:
            test_modules.extend(pow_partial + pow_base + pow_main_list)
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
    parser.add_argument('--build', help="Build target (e.g., hash, hash:partial)")
    parser.add_argument('--test', help="Test target (e.g., hash, hash:partial)")
    parser.add_argument('--platform', type=str, choices=['windows', 'linux', 'mac', 'web'], help='Platform output selector')
    parser.add_argument('--variant', type=str, choices=['lite', 'full', 'both'], default='both', 
                        help='Build variant: lite (9 algorithms ~500KB), full (all algorithms ~5MB), or both')
    parser.add_argument('--action', type=str, help='GitHub action type (stores logs in logs/action/{action}/)')
    parser.add_argument('--action-log', type=str, dest='action_log', help='Write the runner log to this exact file path (e.g. logs/action/web/partial/core.log)')
    parser.add_argument('--bin-root', type=str, help='Override bin output root')
    parser.add_argument('--log-root', type=str, help='Override log output root')
    parser.add_argument('--lib-ext', type=str, help='Override output library extension')
    parser.add_argument('--no-color', action='store_true', help="Disable colored output")
    
    args = parser.parse_args()
    
    from script.core import console

    # Check for no-args behavior: default to build all + test all
    if not args.build and not args.test:
        args.build = 'all'
        args.test = 'all'
    
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
