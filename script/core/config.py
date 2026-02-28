import os
import time
from .platform import Platform

class Config:
    def __init__(self, bin_dir=None, log_dir=None, lib_ext=None):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
        self.src_dir = os.path.join(self.project_root, 'src')
        env_bin_dir = os.getenv('LEYLINE_BIN_DIR')
        env_log_dir = os.getenv('LEYLINE_LOG_DIR')
        env_lib_ext = os.getenv('LEYLINE_LIB_EXT')
        self.bin_dir = env_bin_dir or bin_dir or os.path.join(self.project_root, 'bin')
        self.log_dir = env_log_dir or log_dir or os.path.join(self.project_root, 'logs')
        self.lib_ext = env_lib_ext or lib_ext
        
        self.includes = [
            os.path.join(self.src_dir),
            os.path.join(self.src_dir, 'include'),
            os.path.join(self.src_dir, 'primitives'),
            os.path.join(self.src_dir, 'primitives', 'hash', 'fast', 'blake3'),
            os.path.join(self.src_dir, 'primitives', 'hash', 'memory_hard', 'utils'),
            os.path.join(self.src_dir, 'legacy', 'alive'),
            os.path.join(self.src_dir, 'legacy', 'unsafe'),
            os.path.join(self.src_dir, 'utils'),
        ]
        
        self.excluded_dirs = [
            'test', 'bench', 'gen_kat', 'sphincs', 'avx2', 'aarch64', 
            'keccak4x', 'keccak2x', 'examples', 'script', 'external_sources', 'optional', 'pow'
        ]
        
        self.excluded_files = [
            'benchmark.c', 'main.c', 'opt.c', 
            'blake3_avx2.c', 'blake3_avx512.c', 'blake3_sse2.c', 'blake3_sse41.c', 'blake3_neon.c'
        ]
        
        self.macros = [
            'BLAKE3_NO_AVX2',
            'BLAKE3_NO_AVX512',
            'BLAKE3_NO_SSE2',
            'BLAKE3_NO_SSE41',
            'BLAKE3_NO_THREADING',
            'BLAKE3_ATOMICS=0',
            'EXCLUDE_SPHINCS'
        ]
        if Platform.get_os() == 'macos':
            self.macros.append('BLAKE3_USE_NEON=0')

    def get_log_path(self, tier, name, timed=True, variant=None, platform=None):
        """
        Generate log path matching bin structure
        
        Args:
            tier: Layer tier (partial, base, main, primary)
            name: Module name
            timed: Whether to include timestamp
            variant: Build variant (full, lite) - optional
            platform: Target platform - optional
        
        Returns:
            Log file path matching bin/{platform}/{tier}/{variant}/
        """
        # Build log directory matching bin structure
        log_parts = [self.log_dir]
        
        if platform:
            log_parts.append(platform)
        
        log_parts.append(tier)
        
        if variant:
            log_parts.append(variant)
        
        log_subdir = os.path.join(*log_parts)
        os.makedirs(log_subdir, exist_ok=True)
        
        # Generate filename
        if timed:
            filename = f"{name}_{time.strftime('%Y%m%d_%H%M%S')}.log"
        else:
            filename = f"{name}.log"
        
        return os.path.join(log_subdir, filename)
    
    def get_runner_log_path(self, action_type=None):
        """
        Generate runner log path
        
        For normal runs: logs/run/YYYY-MM-DD-HH-MM-SS_runner.log
        For GitHub actions: logs/bin/{action_type}/...
        
        Args:
            action_type: If provided, creates GitHub action log structure
        
        Returns:
            Log file path
        """
        timestamp = time.strftime('%Y-%m-%d-%H-%M-%S')
        
        if action_type:
            # GitHub action logs: logs/bin/{action_type}/
            log_dir = os.path.join(self.log_dir, 'bin', action_type)
            os.makedirs(log_dir, exist_ok=True)
            return os.path.join(log_dir, f"{timestamp}_runner.log")
        else:
            # Normal runs: logs/run/YYYY-MM-DD-HH-MM-SS_runner.log
            log_dir = os.path.join(self.log_dir, 'run')
            os.makedirs(log_dir, exist_ok=True)
            return os.path.join(log_dir, f"{timestamp}_runner.log")

    def get_shared_lib_ext(self):
        if self.lib_ext:
            return self.lib_ext
        return Platform.get_shared_lib_ext()

    def get_output_path(self, tier, name):
        out_subdir = os.path.join(self.bin_dir, tier)
        out_subdir = os.path.normpath(out_subdir)
        os.makedirs(out_subdir, exist_ok=True)
        return os.path.join(out_subdir, f"{name}{self.get_shared_lib_ext()}")

    def get_bin_path(self, *parts):
        return os.path.join(self.bin_dir, *parts)

    def get_lib_path(self, tier, name, *subdirs):
        return os.path.join(self.bin_dir, tier, *subdirs, f"{name}{self.get_shared_lib_ext()}")
