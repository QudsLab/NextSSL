"""Test utilities and runner for NextSSL Python library.

This module provides:
- TestLogger: Dual stdout + file logger
- Test runner: Automatic discovery and execution
- Common test vectors and utilities
"""

from .common import TestLogger, VECTORS, REPO_ROOT, TESTS_DIR, LOG_DIR

__all__ = ["TestLogger", "VECTORS", "REPO_ROOT", "TESTS_DIR", "LOG_DIR", "run_all"]


def run_all():
    """Run all test modules and generate summary."""
    import pathlib
    import importlib
    
    # Create summary logger
    summary_log = TestLogger("summary", "")
    summary_log.section("NextSSL Python Library - Test Suite")
    
    total_passed = 0
    total_failed = 0
    failed_modules = []
    
    # Discover test modules
    utils_dir = pathlib.Path(__file__).parent
    test_modules = []
    
    # Find all test_*.py files recursively
    for test_file in sorted(utils_dir.rglob("test_*.py")):
        # Convert file path to module path
        rel_path = test_file.relative_to(utils_dir)
        module_parts = ["tests", "utils"] + list(rel_path.parts[:-1]) + [rel_path.stem]
        module_name = ".".join(module_parts)
        test_modules.append((module_name, test_file))
    
    summary_log.info(f"Found {len(test_modules)} test modules")
    
    # Run each test module
    for module_name, test_file in test_modules:
        try:
            summary_log.info(f"Running {module_name}...")
            module = importlib.import_module(module_name)
            
            if hasattr(module, "run"):
                # Module has a run() function
                passed, failed = module.run()
                total_passed += passed
                total_failed += failed
                
                if failed > 0:
                    failed_modules.append(module_name)
                    summary_log.fail(module_name, passed=passed, failed=failed)
                else:
                    summary_log.pass_(module_name, passed=passed, failed=failed)
            else:
                summary_log.info(f"Skipping {module_name} (no run() function)")
        
        except Exception as e:
            summary_log.fail(module_name, error=str(e))
            failed_modules.append(module_name)
            import traceback
            traceback.print_exc()
    
    # Final summary
    summary_log.section("Final Test Summary")
    summary_log.info(f"Total Passed: {total_passed}")
    summary_log.info(f"Total Failed: {total_failed}")
    
    if failed_modules:
        summary_log.info(f"Failed Modules ({len(failed_modules)}):")
        for mod in failed_modules:
            summary_log.info(f"  - {mod}")
    
    passed, failed = summary_log.summary()
    
    return total_passed, total_failed
