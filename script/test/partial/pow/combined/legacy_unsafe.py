import sys
from script.test.partial.pow.combined.common import run_combined_test

def main():
    algos = ["md2", "md4", "sha0", "has160", "ripemd128", "ripemd256", "ripemd320"]
    difficulties = [1, 4]
    return run_combined_test("legacy_unsafe", algos, difficulties)

if __name__ == "__main__":
    sys.exit(main())
