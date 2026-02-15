import os
import time
from .platform import Platform

class Config:
    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
        self.src_dir = os.path.join(self.project_root, 'src')
        self.bin_dir = os.path.join(self.project_root, 'bin')
        self.log_dir = os.path.join(self.project_root, 'logs')
        
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
            'keccak4x', 'keccak2x', 'examples', 'script', 'external_sources'
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

    def get_log_path(self, tier, name, timed=True):
        os.makedirs(self.log_dir, exist_ok=True)
        if timed:
            return os.path.join(self.log_dir, f"{time.strftime('%Y%m%d_%H%M%S')}_{tier}_{name}.log")
        return os.path.join(self.log_dir, f"{tier}_{name}.log")

    def get_output_path(self, tier, name):
        out_subdir = os.path.join(self.bin_dir, tier)
        out_subdir = os.path.normpath(out_subdir)
        os.makedirs(out_subdir, exist_ok=True)
        return os.path.join(out_subdir, f"{name}{Platform.get_shared_lib_ext()}")
