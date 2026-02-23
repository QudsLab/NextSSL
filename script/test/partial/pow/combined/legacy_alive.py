import sys
from script.test.partial.pow.combined.common import run_combined_test

def main():
    algos = ["md5", "sha1", "ripemd160", "whirlpool", "nt"]
    difficulties = [1, 4]
    return run_combined_test("legacy_alive", algos, difficulties)

if __name__ == "__main__":
    sys.exit(main())
