"""
Build a platform-specific wheel for the nextssl ctypes bindings.

The package bundles a pre-compiled native shared library (.dll / .so / .dylib).
Because we load it via ctypes (not a C extension), the correct wheel tag is
    py3-none-<platform>   (any Python 3, no ABI requirement, platform-specific)

We achieve this by:
  1. BinaryDistribution  — marks the dist as non-pure so setuptools produces a
                           platform wheel instead of a universal one.
  2. CustomBdistWheel    — overrides get_tag() to return 'py3' / 'none' for the
                           python and abi slots regardless of what Python is
                           running the build.  The platform tag comes from the
                           --plat-name CLI argument passed by the CI workflow.

All project metadata lives in pyproject.toml.
"""
from setuptools import setup
from setuptools.dist import Distribution

try:
    from wheel.bdist_wheel import bdist_wheel as _BdistWheel

    class CustomBdistWheel(_BdistWheel):
        """Produce py3-none-<platform> wheels for ctypes-only packages."""

        def get_tag(self):
            # Let the base class compute the platform tag (respects --plat-name).
            _, _, plat = _BdistWheel.get_tag(self)
            return 'py3', 'none', plat

    _cmdclass = {'bdist_wheel': CustomBdistWheel}
except ImportError:
    # wheel not installed — fall back to default behaviour
    _cmdclass = {}


class BinaryDistribution(Distribution):
    """Mark as non-pure so setuptools generates a platform wheel."""

    def has_ext_modules(self) -> bool:  # type: ignore[override]
        return True

    def is_pure(self) -> bool:  # type: ignore[override]
        return False


setup(distclass=BinaryDistribution, cmdclass=_cmdclass)
