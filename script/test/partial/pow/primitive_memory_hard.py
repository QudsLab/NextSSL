import ctypes
import os
import sys
import time
from script.core import Config, console

def leading_zero_bits(data):
    count = 0
    for b in data:
        if b == 0:
            count += 8
            continue
        for i in range(8):
            if b & (0x80 >> i):
                return count + i
        return count + 8
    return count

def bytes_to_bin(data):
    return " ".join(f"{b:08b}" for b in data)

def prefix_bits(data, bits):
    if bits <= 0:
        return ""
    return "".join(f"{b:08b}" for b in data)[:bits]

def main():
    """Test server + client + combined DLLs for primitive_memory_hard algorithms (Argon2)."""
    
    config = Config()
    server_dll_path = config.get_lib_path('partial', 'primitive_memory_hard', 'pow', 'server')
    client_dll_path = config.get_lib_path('partial', 'primitive_memory_hard', 'pow', 'client')
    
    if not os.path.exists(server_dll_path):
        console.print_fail(f"Server DLL not found: {server_dll_path}")
        return 1
        
    try:
        server_dll = ctypes.CDLL(server_dll_path)
        client_dll = ctypes.CDLL(client_dll_path)
    except OSError as e:
        console.print_fail(f"Error loading DLLs: {e}")
        return 1

    class Argon2Params(ctypes.Structure):
        _fields_ = [
            ("out_len", ctypes.c_uint32),
            ("memory_kib", ctypes.c_uint32),
            ("iterations", ctypes.c_uint32),
            ("threads", ctypes.c_uint32)
        ]

    class POWChallenge(ctypes.Structure):
        _fields_ = [
            ("version", ctypes.c_uint8),
            ("challenge_id", ctypes.c_uint8 * 16),
            ("algorithm_id", ctypes.c_char * 32),
            ("context", ctypes.c_uint8 * 256),
            ("context_len", ctypes.c_size_t),
            ("target", ctypes.c_uint8 * 64),
            ("target_len", ctypes.c_size_t),
            ("difficulty_bits", ctypes.c_uint32),
            ("wu", ctypes.c_uint64),
            ("mu", ctypes.c_uint64),
            ("expires_unix", ctypes.c_uint64),
            ("algo_params", ctypes.c_void_p),
            ("algo_params_size", ctypes.c_size_t)
        ]

    class POWSolution(ctypes.Structure):
        _fields_ = [
            ("challenge_id", ctypes.c_uint8 * 16),
            ("nonce", ctypes.c_uint64),
            ("hash_output", ctypes.c_uint8 * 64),
            ("hash_output_len", ctypes.c_size_t),
            ("solve_time_seconds", ctypes.c_double),
            ("attempts", ctypes.c_uint64)
        ]

    class POWConfig(ctypes.Structure):
        _fields_ = [
            ("default_difficulty_bits", ctypes.c_uint32),
            ("max_wu_per_challenge", ctypes.c_uint64),
            ("challenge_ttl_seconds", ctypes.c_uint64),
            ("allowed_algos", ctypes.c_char_p * 32),
            ("allowed_algos_count", ctypes.c_size_t),
            ("max_challenges_per_ip", ctypes.c_uint32),
            ("rate_limit_window_seconds", ctypes.c_uint32)
        ]

    # Signatures
    server_dll.leyline_pow_server_generate_challenge.argtypes = [
        ctypes.POINTER(POWConfig), ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8), 
        ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(POWChallenge)
    ]
    server_dll.leyline_pow_server_generate_challenge.restype = ctypes.c_int

    server_dll.leyline_pow_server_verify_solution.argtypes = [
        ctypes.POINTER(POWChallenge), ctypes.POINTER(POWSolution), ctypes.POINTER(ctypes.c_bool)
    ]
    server_dll.leyline_pow_server_verify_solution.restype = ctypes.c_int

    client_dll.leyline_pow_client_solve.argtypes = [
        ctypes.POINTER(POWChallenge), ctypes.POINTER(POWSolution)
    ]
    client_dll.leyline_pow_client_solve.restype = ctypes.c_int

    # Test
    console.print_header("Starting Primitive Memory Hard PoW Test")
    config = POWConfig()
    config.default_difficulty_bits = 1
    config.max_wu_per_challenge = 10000000000
    config.challenge_ttl_seconds = 60

    algos = ["argon2id", "argon2i", "argon2d"]
    difficulties = [1, 2]
    
    for algo in algos:
        for difficulty in difficulties:
            console.print_step(f"Testing {algo} (Diff: {difficulty})...")
            challenge = POWChallenge()
            
            context_str = "HelloWorld"
            context_len = len(context_str)
            context = (ctypes.c_uint8 * 256)()
            for i in range(context_len):
                context[i] = ord(context_str[i])
            
            console.print_info(f"Generating challenge ({algo})...")
            ret = server_dll.leyline_pow_server_generate_challenge(
                ctypes.byref(config),
                algo.encode('utf-8'),
                context,
                context_len,
                difficulty,
                ctypes.byref(challenge)
            )
            
            if ret != 0:
                console.print_fail(f"Generate failed", expected=0, got=ret)
                continue
            
            console.print_info(f"Challenge Generated:")
            console.print_info(f"  ID: {bytes(challenge.challenge_id).hex()}")
            console.print_info(f"  Algorithm: {challenge.algorithm_id.decode('utf-8')}")
            console.print_info(f"  Difficulty: {challenge.difficulty_bits}")
            target_bytes = bytes(challenge.target[:challenge.target_len])
            console.print_info(f"  Target: {target_bytes.hex()}")
            console.print_info(f"  Target (Bin): {bytes_to_bin(target_bytes)}")
            console.print_info(f"  Target Prefix Bits: {prefix_bits(target_bytes, challenge.difficulty_bits)}")
            console.print_info(f"  Context (Hex): {bytes(challenge.context[:challenge.context_len]).hex()}")
            console.print_info(f"  Context (Str): {bytes(challenge.context[:challenge.context_len]).decode('utf-8', errors='replace')}")
            console.print_info(f"  WU: {challenge.wu}")
            console.print_info(f"  MU: {challenge.mu}")

            if challenge.algo_params and challenge.algo_params_size > 0:
                params = ctypes.cast(challenge.algo_params, ctypes.POINTER(Argon2Params)).contents
                console.print_info(f"  Params: m={params.memory_kib}KiB, t={params.iterations}, p={params.threads}")

            console.print_info(f"Solving...")
            solution = POWSolution()
            ret = client_dll.leyline_pow_client_solve(
                ctypes.byref(challenge),
                ctypes.byref(solution)
            )
        
            if ret != 0:
                console.print_fail(f"Solve failed", expected=0, got=ret)
                continue
            
            console.print_info(f"Solved in {solution.solve_time_seconds:.4f}s (Attempts: {solution.attempts})")
            console.print_info(f"  Nonce: {solution.nonce}")
            hash_bytes = bytes(solution.hash_output[:solution.hash_output_len])
            console.print_info(f"  Hash: {hash_bytes.hex()}")
            console.print_info(f"  Hash (Bin): {bytes_to_bin(hash_bytes)}")
            console.print_info(f"  Hash Prefix Bits: {prefix_bits(hash_bytes, challenge.difficulty_bits)}")
            lz = leading_zero_bits(hash_bytes)
            if lz < challenge.difficulty_bits:
                console.print_fail(f"Difficulty check failed", expected=challenge.difficulty_bits, got=lz)
                return 1
        
            input_str = f"{context_str}{solution.nonce}"
            console.print_info(f"  Verify Input String: \"{input_str}\"")
        
            console.print_info(f"Verifying...")
            is_valid = ctypes.c_bool(False)
            ret = server_dll.leyline_pow_server_verify_solution(
                ctypes.byref(challenge), ctypes.byref(solution), ctypes.byref(is_valid)
            )
        
            if ret != 0:
                console.print_fail(f"Verify failed", expected=0, got=ret)
                return 1
            
            if is_valid.value:
                console.print_pass(f"VERIFICATION PASSED for {algo}!")
            else:
                console.print_fail(f"VERIFICATION FAILED for {algo}!")
                return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
