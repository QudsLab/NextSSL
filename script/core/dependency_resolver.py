"""
Dependency Resolver - Automatically detects source file dependencies
Scans #include statements to build dependency tree
"""

import os
import re
from typing import Set, List, Dict
from pathlib import Path


class DependencyResolver:
    """
    Automatically resolves C source file dependencies by scanning #include statements.
    This eliminates manual source path tracking in generators.
    """
    
    def __init__(self, src_dir: str):
        """
        Initialize dependency resolver
        
        Args:
            src_dir: Root source directory (e.g., 'src/')
        """
        self.src_dir = Path(src_dir).resolve()
        self.include_cache: Dict[str, Set[str]] = {}
        self.source_cache: Dict[str, Path] = {}
        
    def scan_includes(self, file_path: Path) -> Set[str]:
        """
        Scan a file for #include statements
        
        Args:
            file_path: Path to C/H file
            
        Returns:
            Set of included header paths (relative to src/)
        """
        if str(file_path) in self.include_cache:
            return self.include_cache[str(file_path)]
        
        includes = set()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Match #include "..." and #include <...> from project
            include_pattern = r'#\s*include\s+[<"]([^>"]+)[>"]'
            matches = re.findall(include_pattern, content)
            
            for match in matches:
                # Skip system headers
                if match.startswith('std') or match.startswith('windows.h') or match.startswith('pthread'):
                    continue
                    
                # Normalize path
                include_path = match.replace('\\', '/')
                
                # Remove leading ../ or ./ 
                while include_path.startswith('../') or include_path.startswith('./'):
                    include_path = include_path[3:] if include_path.startswith('../') else include_path[2:]
                
                includes.add(include_path)
        
        except Exception as e:
            # Silently ignore read errors
            pass
        
        self.include_cache[str(file_path)] = includes
        return includes
    
    def find_source_for_header(self, header_path: str) -> List[Path]:
        """
        Find corresponding .c file(s) for a .h header
        
        Args:
            header_path: Header path relative to src/ (e.g., 'primitives/hash/fast/sha256/sha256.h')
            
        Returns:
            List of .c file paths that implement this header
        """
        # Try to find .c file in same directory
        header_full = self.src_dir / header_path
        
        if not header_full.exists():
            return []
        
        sources = []
        header_dir = header_full.parent
        header_name = header_full.stem  # filename without extension
        
        # Look for .c files in same directory
        for c_file in header_dir.glob('*.c'):
            sources.append(c_file)
        
        return sources
    
    def resolve_dependencies(self, entry_points: List[str], recursive: bool = True) -> Set[Path]:
        """
        Resolve all dependencies for given entry point headers/sources
        
        Args:
            entry_points: List of header/source paths relative to src/ 
                         (e.g., ['primitives/hash/fast/sha256/sha256.h'])
            recursive: Whether to recursively resolve dependencies
            
        Returns:
            Set of absolute paths to all required .c files
        """
        sources = set()
        visited_headers = set()
        to_process = list(entry_points)
        
        while to_process:
            current = to_process.pop(0)
            
            if current in visited_headers:
                continue
            
            visited_headers.add(current)
            
            # If it's a .c file, add directly
            if current.endswith('.c'):
                full_path = self.src_dir / current
                if full_path.exists():
                    sources.add(full_path)
                continue
            
            # If it's a .h file, find corresponding .c files
            if current.endswith('.h'):
                c_files = self.find_source_for_header(current)
                sources.update(c_files)
                
                # Scan header for more includes if recursive
                if recursive:
                    header_path = self.src_dir / current
                    if header_path.exists():
                        includes = self.scan_includes(header_path)
                        to_process.extend(includes)
                
                # Scan each .c file for includes
                if recursive:
                    for c_file in c_files:
                        includes = self.scan_includes(c_file)
                        to_process.extend(includes)
        
        return sources
    
    def collect_sources_from_dirs(self, directories: List[str], recursive: bool = True) -> Set[Path]:
        """
        Collect all .c sources from directories (classic approach, still useful)
        
        Args:
            directories: List of directory paths relative to src/
            recursive: Whether to search recursively
            
        Returns:
            Set of absolute paths to .c files
        """
        sources = set()
        
        for directory in directories:
            dir_path = self.src_dir / directory
            
            if not dir_path.exists():
                continue
            
            if recursive:
                for c_file in dir_path.rglob('*.c'):
                    sources.add(c_file)
            else:
                for c_file in dir_path.glob('*.c'):
                    sources.add(c_file)
        
        return sources
    
    def get_dependencies_for_algorithm(self, algorithm: str, category: str = 'hash') -> Set[Path]:
        """
        Smart dependency resolution for common algorithm patterns
        
        Args:
            algorithm: Algorithm name (e.g., 'sha256', 'aes_gcm', 'kyber1024')
            category: Category (hash, aead, ecc, pqc, etc.)
            
        Returns:
            Set of .c files needed for this algorithm
        """
        sources = set()
        
        # Map algorithm to typical locations
        if category == 'hash':
            if algorithm in ['sha256', 'sha512', 'blake3', 'sha1']:
                sources.update(self.collect_sources_from_dirs([f'primitives/hash/fast/{algorithm}']))
            elif algorithm in ['argon2', 'argon2i', 'argon2d', 'argon2id']:
                sources.update(self.collect_sources_from_dirs([f'primitives/hash/memory_hard/{algorithm}']))
        
        elif category == 'aead':
            if 'aes' in algorithm.lower():
                sources.update(self.collect_sources_from_dirs(['primitives/cipher/aes_core']))
                sources.update(self.collect_sources_from_dirs([f'primitives/aead/{algorithm}']))
            elif 'chacha' in algorithm.lower():
                sources.update(self.collect_sources_from_dirs(['primitives/cipher/chacha20']))
                sources.update(self.collect_sources_from_dirs(['primitives/aead/chacha20_poly1305']))
        
        elif category == 'pqc':
            if 'kyber' in algorithm.lower() or 'ml-kem' in algorithm.lower():
                sources.update(self.collect_sources_from_dirs([f'PQCrypto/crypto_kem/{algorithm}']))
                sources.update(self.collect_sources_from_dirs(['PQCrypto/common']))
            elif 'dilithium' in algorithm.lower() or 'ml-dsa' in algorithm.lower():
                sources.update(self.collect_sources_from_dirs([f'PQCrypto/crypto_sign/{algorithm}']))
                sources.update(self.collect_sources_from_dirs(['PQCrypto/common']))
        
        elif category == 'ecc':
            sources.update(self.collect_sources_from_dirs([f'primitives/ecc/{algorithm}']))
        
        return sources


# Convenience function for generators
def auto_resolve_sources(src_dir: str, algorithms: Dict[str, List[str]]) -> List[str]:
    """
    Automatically resolve sources for multiple algorithms
    
    Args:
        src_dir: Source directory path
        algorithms: Dict mapping category to algorithm list
                   e.g., {'hash': ['sha256', 'blake3'], 'aead': ['aes_gcm']}
    
    Returns:
        List of source file paths (strings, relative to project root)
    """
    resolver = DependencyResolver(src_dir)
    sources = set()
    
    for category, algo_list in algorithms.items():
        for algorithm in algo_list:
            deps = resolver.get_dependencies_for_algorithm(algorithm, category)
            sources.update(deps)
    
    # Convert to strings relative to project root
    result = []
    project_root = Path(src_dir).parent
    
    for source in sources:
        try:
            rel_path = source.relative_to(project_root)
            result.append(str(rel_path).replace('\\', '/'))
        except ValueError:
            result.append(str(source).replace('\\', '/'))
    
    return sorted(result)
