import sys
from script.test.partial.pow.combined.common import run_combined_test

def main():
    algos = ["argon2id", "argon2i", "argon2d"]
    difficulties = [1, 4]
    return run_combined_test("primitive_memory_hard", algos, difficulties)

if __name__ == "__main__":
    sys.exit(main())
