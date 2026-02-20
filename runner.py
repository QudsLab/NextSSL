import argparse
import sys
import os
import time

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

from script.gen.partial.pow.server import primitive_fast as pow_server_primitive_fast, primitive_memory_hard as pow_server_primitive_memory_hard, primitive_sponge_xof as pow_server_primitive_sponge_xof, legacy_alive as pow_server_legacy_alive, legacy_unsafe as pow_server_legacy_unsafe
from script.gen.partial.pow.client import primitive_fast as pow_client_primitive_fast, primitive_memory_hard as pow_client_primitive_memory_hard, primitive_sponge_xof as pow_client_primitive_sponge_xof, legacy_alive as pow_client_legacy_alive, legacy_unsafe as pow_client_legacy_unsafe
from script.gen.partial.pow.combined import primitive_fast as pow_combined_primitive_fast, primitive_memory_hard as pow_combined_primitive_memory_hard, primitive_sponge_xof as pow_combined_primitive_sponge_xof, legacy_alive as pow_combined_legacy_alive, legacy_unsafe as pow_combined_legacy_unsafe
from script.gen.base import pow_primitive, pow_legacy
from script.gen.main import pow as pow_main

from script.test.partial.pow import primitive_fast as test_pow_primitive_fast
from script.test.partial.pow import primitive_memory_hard as test_pow_primitive_memory_hard
from script.test.partial.pow import primitive_sponge_xof as test_pow_primitive_sponge_xof
from script.test.partial.pow import legacy_alive as test_pow_legacy_alive
from script.test.partial.pow import legacy_unsafe as test_pow_legacy_unsafe
from script.test.suites import pow_integration as test_pow_integration
from script.test.base import pow_primitive as test_pow_primitive, pow_legacy as test_pow_legacy
from script.test.main import pow as test_pow_main
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

from script.test.partial.dhcm import primitive_fast as test_dhcm_primitive_fast
from script.test.partial.dhcm import primitive_memory_hard as test_dhcm_primitive_memory_hard
from script.test.partial.dhcm import primitive_sponge_xof as test_dhcm_primitive_sponge_xof
from script.test.partial.dhcm import legacy_alive as test_dhcm_legacy_alive
from script.test.partial.dhcm import legacy_unsafe as test_dhcm_legacy_unsafe
from script.test.base import dhcm_primitive_main as test_dhcm_primitive_main
from script.test.base import dhcm_legacy_main as test_dhcm_legacy_main
from script.test.main import dhcm as test_dhcm_main

def run_build(args):
    config = Config()
    target = args.build
    
    with Logger(config.get_log_path('runner', 'build')) as logger:
        builder = Builder(config, logger)
        
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
        pow_base = [pow_primitive, pow_legacy]
        pow_main_list = [pow_main]
        
        # Build logic
        build_hash = False
        build_pqc = False
        build_core = False
        build_dhcm = False
        build_pow = False
        
        if target == 'all':
            build_hash = True
            build_pqc = True
            build_core = True
            build_dhcm = True
            build_pow = True
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
        elif target.startswith('hash:'):
            # Specific hash target
            if target == 'hash:partial':
                for m in hash_partial: m.build(builder)
            elif target == 'hash:base':
                for m in hash_base: m.build(builder)
            elif target == 'hash:main':
                for m in hash_main_list: m.build(builder)
            else:
                name = target.split(':')[-1]
                module = next((m for m in hash_partial if m.__name__.endswith(name)), None)
                if module: module.build(builder)
                else: logger.error(f"Unknown target: {target}")
            return # Done
        elif target.startswith('pqc:'):
            # Specific PQC target
            if target == 'pqc:partial':
                for m in pqc_partial: m.build(builder)
            elif target == 'pqc:base':
                for m in pqc_base: m.build(builder)
            elif target == 'pqc:main':
                for m in pqc_main_list: m.build(builder)
            else:
                name = target.split(':')[-1]
                module = next((m for m in pqc_partial if m.__name__.endswith(name)), None)
                if module: module.build(builder)
                else: logger.error(f"Unknown target: {target}")
            return # Done
        elif target.startswith('core:'):
            # Specific Core target
            if target == 'core:partial':
                for m in core_partial: m.build(builder)
            elif target == 'core:base':
                for m in core_base: m.build(builder)
            elif target == 'core:main':
                for m in core_main_list: m.build(builder)
            else:
                name = target.split(':')[-1]
                module = next((m for m in core_partial if m.__name__.endswith(name)), None)
                if module: module.build(builder)
                else: logger.error(f"Unknown target: {target}")
            return # Done
        elif target.startswith('dhcm:'):
            # Specific DHCM target
            if target == 'dhcm:partial':
                for m in dhcm_partial: m.build(builder)
            elif target == 'dhcm:base':
                for m in dhcm_base: m.build(builder)
            elif target == 'dhcm:main':
                for m in dhcm_main_list: m.build(builder)
            else:
                name = target.split(':')[-1]
                module = next((m for m in dhcm_partial if m.__name__.endswith(name)), None)
                if module: module.build(builder)
                else: logger.error(f"Unknown target: {target}")
            return # Done
        elif target.startswith('pow:'):
            # Specific PoW target
            if target == 'pow:partial':
                for m in pow_partial: m.build(builder)
            elif target == 'pow:base':
                for m in pow_base: m.build(builder)
            elif target == 'pow:main':
                for m in pow_main_list: m.build(builder)
            else:
                name = target.split(':')[-1]
                module = next((m for m in pow_partial if m.__name__.endswith(name)), None)
                if module: module.build(builder)
                else: logger.error(f"Unknown target: {target}")
            return # Done
        else:
            logger.error(f"Unknown build target: {target}")
            return

        if build_hash:
            logger.info("Building Hash targets...")
            for m in hash_partial + hash_base + hash_main_list:
                m.build(builder)

        if build_pqc:
            logger.info("Building PQC targets...")
            for m in pqc_partial + pqc_base + pqc_main_list:
                m.build(builder)

        if build_core:
            logger.info("Building Core targets...")
            for m in core_partial + core_base + core_main_list:
                m.build(builder)

        if build_dhcm:
            logger.info("Building DHCM targets...")
            for m in dhcm_partial + dhcm_base + dhcm_main_list:
                m.build(builder)

        if build_pow:
            logger.info("Building PoW targets...")
            for m in pow_partial + pow_base + pow_main_list:
                m.build(builder)

def run_test(args):
    config = Config()
    
    # Setup test logging
    with Logger(config.get_log_path('runner', 'test'), console_output=False) as logger:
        from script.core import console
        console.set_logger(logger)
        
        target = args.test
        results = []
        test_modules = []
    
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
            test_pow_legacy_unsafe
        ]
        pow_base = [test_pow_primitive, test_pow_legacy]
        pow_main_list = [test_pow_main]
        pow_suites = [test_pow_integration]

        run_hash = False
        run_pqc = False
        run_core = False
        run_dhcm = False
        run_pow = False

        if target == 'all':
            run_hash = True
            run_pqc = True
            run_core = True
            run_dhcm = True
            run_pow = True
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
        elif target.startswith('hash:'):
            if target == 'hash:partial': test_modules = hash_partial
            elif target == 'hash:base': test_modules = hash_base
            elif target == 'hash:main': test_modules = hash_main_list
            else:
                name = target.split(':')[-1]
                test_modules = [m for m in hash_partial if m.__name__.endswith(name)]
        elif target.startswith('pqc:'):
            if target == 'pqc:partial': test_modules = pqc_partial
            elif target == 'pqc:base': test_modules = pqc_base
            elif target == 'pqc:main': test_modules = pqc_main_list
            else:
                name = target.split(':')[-1]
                test_modules = [m for m in pqc_partial if m.__name__.endswith(name)]
        elif target.startswith('core:'):
            if target == 'core:partial': test_modules = core_partial
            elif target == 'core:base': test_modules = core_base
            elif target == 'core:main': test_modules = core_main_list
            else:
                name = target.split(':')[-1]
                test_modules = [m for m in core_partial if m.__name__.endswith(name)]
        elif target.startswith('dhcm:'):
            if target == 'dhcm:partial': test_modules = dhcm_partial
            elif target == 'dhcm:base': test_modules = dhcm_base
            elif target == 'dhcm:main': test_modules = dhcm_main_list
            else:
                name = target.split(':')[-1]
                test_modules = [m for m in dhcm_partial if m.__name__.endswith(name)]
        elif target.startswith('pow:'):
            if target == 'pow:partial': test_modules = pow_partial
            elif target == 'pow:base': test_modules = pow_base
            elif target == 'pow:main': test_modules = pow_main_list
            elif target == 'pow:integration': test_modules = pow_suites
            else:
                name = target.split(':')[-1]
                test_modules = [m for m in pow_partial if m.__name__.endswith(name)]
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
            test_modules.extend(pow_partial + pow_base + pow_main_list + pow_suites)

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NextSSL Build & Test Runner")
    parser.add_argument('--build', help="Build target (e.g., hash, hash:partial)")
    parser.add_argument('--test', help="Test target (e.g., hash, hash:partial)")
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

    if args.build:
        run_build(args)
    
    # Record build time
    build_time = time.time() - start_time
    console.print_step(f"Build completed in {build_time:.2f} seconds")

    if args.test:
        run_test(args)
    
    # Record test time
    test_time = time.time() - start_time - build_time
    console.print_step(f"Test completed in {test_time:.2f} seconds")