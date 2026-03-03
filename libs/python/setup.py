"""
Force a platform-specific wheel even though there is no C extension module.
The package bundles a pre-compiled native shared library (.dll / .so / .dylib)
so the wheel must be tagged for the target platform and NOT marked as pure-Python.

This file is intentionally minimal.  All project metadata lives in pyproject.toml.
"""
from setuptools import setup
from setuptools.dist import Distribution


class BinaryDistribution(Distribution):
    """Report that the distribution has extension modules to get a platform wheel."""

    def has_ext_modules(self) -> bool:  # type: ignore[override]
        return True

    def is_pure(self) -> bool:  # type: ignore[override]
        return False


setup(distclass=BinaryDistribution)
