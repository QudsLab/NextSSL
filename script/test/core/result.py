"""script/test/core/result.py — shared pass/fail accumulator."""
from script.core import console


class Results:
    def __init__(self, label: str):
        self.label  = label
        self.passed = 0
        self.failed = 0

    def ok(self, name: str) -> None:
        console.print_pass(name)
        self.passed += 1

    def fail(self, name: str, reason: str = "", debug_data: dict = None) -> None:
        console.print_fail(name)
        if reason:
            print(f"  reason: {reason}")
        if debug_data:
            for k, v in debug_data.items():
                console.print_debug_val(k, v, hex_dump=isinstance(v, (bytes, bytearray)))
        self.failed += 1

    def summary(self) -> int:
        console.print_info(
            f"{self.label}: {self.passed} passed, {self.failed} failed"
        )
        return 0 if self.failed == 0 else 1
