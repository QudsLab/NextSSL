import sys
from script.test.partial.pow.combined.common import run_combined_test

def main():
    algos = ["sha3_256", "sha3_512", "keccak_256", "shake128", "shake256"]
    difficulties = [1, 4]
    return run_combined_test("primitive_sponge_xof", algos, difficulties)

if __name__ == "__main__":
    sys.exit(main())
