import sys
from script.test.partial.pow.combined.common import run_combined_test

def main():
    algos = ["sha256", "sha512", "blake3", "blake2b", "blake2s"]
    difficulties = [1, 4]
    return run_combined_test("primitive_fast", algos, difficulties)

if __name__ == "__main__":
    sys.exit(main())
