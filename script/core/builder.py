import os
import subprocess
import glob
from .config import Config
from .logger import Logger
from .platform import Platform

class Builder:
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger

    def get_sources(self, directories, recursive=True):
        sources = []
        for d in directories:
            if not os.path.exists(d):
                self.logger.error(f"Source directory not found: {d}")
                continue
                
            if recursive:
                for root, dirs, files in os.walk(d):
                    # Filter excluded directories
                    dirs[:] = [d for d in dirs if d not in self.config.excluded_dirs]
                    
                    for file in files:
                        if file.endswith('.c') and file not in self.config.excluded_files:
                            sources.append(os.path.join(root, file))
            else:
                for file in os.listdir(d):
                    if file.endswith('.c') and file not in self.config.excluded_files:
                        sources.append(os.path.join(d, file))
        return sources

    def build_target(self, name, sources, extra_libs=None, output_subdir='', macros=None, remove_macros=None, includes=None):
        if not sources:
            self.logger.error(f"No sources found for target {name}")
            return False

        output_path = self.config.get_output_path(output_subdir, name)
        output_dir = os.path.dirname(output_path)
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Arguments for GCC
        args = ['-shared', '-fPIC', '-O2', '-Wall', '-static']
        
        # Add includes
        for inc in self.config.includes:
            args.append(f'-I{inc}')
        
        if includes:
            for inc in includes:
                args.append(f'-I{inc}')
            
        # Add macros
        current_macros = list(self.config.macros)
        if remove_macros:
            for m in remove_macros:
                if m in current_macros:
                    current_macros.remove(m)
        
        if macros:
            current_macros.extend(macros)

        for macro in current_macros:
            if isinstance(macro, tuple):
                args.append(f'-D{macro[0]}={macro[1]}')
            else:
                args.append(f'-D{macro}')
            
        # Add sources
        args.extend(sources)
        
        # Output
        args.append('-o')
        args.append(output_path)
        
        # Add extra libs (like -lpthread) - usually at the end
        if extra_libs:
            args.extend(extra_libs)

        # Write arguments to response file to avoid command line length limits
        rsp_file = os.path.join(output_dir, f"{name}.rsp")
        try:
            with open(rsp_file, 'w') as f:
                for arg in args:
                    # Normalize paths to forward slashes to avoid backslash escape issues
                    clean_arg = arg.replace('\\', '/')
                    if ' ' in clean_arg:
                        clean_arg = f'"{clean_arg}"'
                    f.write(clean_arg + '\n')
        except Exception as e:
             self.logger.error(f"Failed to write response file: {e}")
             return False

        # Run gcc with response file
        cmd = ['gcc', f'@{rsp_file}']
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            # Clean up response file
            if os.path.exists(rsp_file):
                try:
                    os.remove(rsp_file)
                except OSError:
                    pass
            
            if result.returncode != 0:
                self.logger.error(f"Compilation failed for {name}:")
                self.logger.error(result.stderr)
                return False
                
            self.logger.info(f"Successfully built {name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Build error for {name}: {e}")
            if os.path.exists(rsp_file):
                try:
                    os.remove(rsp_file)
                except OSError:
                    pass
            return False
