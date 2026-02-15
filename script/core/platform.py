import platform
import os

class Platform:
    @staticmethod
    def get_os():
        system = platform.system().lower()
        if system == 'windows':
            return 'windows'
        elif system == 'linux':
            return 'linux'
        elif system == 'darwin':
            return 'macos'
        else:
            return 'unknown'

    @staticmethod
    def get_shared_lib_ext():
        os_name = Platform.get_os()
        if os_name == 'windows':
            return '.dll'
        elif os_name == 'linux':
            return '.so'
        elif os_name == 'macos':
            return '.dylib'
        else:
            return '.so'

    @staticmethod
    def get_exe_ext():
        return '.exe' if Platform.get_os() == 'windows' else ''
