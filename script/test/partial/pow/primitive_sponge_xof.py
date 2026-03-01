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
    """Test server + client + combined DLLs for primitive_sponge_xof algorithms."""
    
    config = Config()
    server_dll_path = config.get_lib_path('partial', 'primitive_sponge_xof', 'pow', 'server')
    client_dll_path = config.get_lib_path('partial', 'primitive_sponge_xof', 'pow', 'client')
    
    # Check if DLLs exist
    if not os.path.exists(server_dll_path):
        console.print_fail(f"Server DLL not found: {server_dll_path}")
        return 1
    if not os.path.exists(client_dll_path):
        console.print_fail(f"Client DLL not found: {client_dll_path}")
        return 1
        
    # Load DLLs
    try:
        server_dll = ctypes.CDLL(server_dll_path)
        client_dll = ctypes.CDLL(client_dll_path)
    except OSError as e:
        console.print_fail(f"Error loading DLLs: {e}")
        return 1

    console.print_info("DLLs loaded successfully.")

    # Define structures matching C code
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

    # Setup function signatures
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

    # --- Test Logic ---
    console.print_header("Starting Primitive Sponge XOF PoW Test")

    # 1. Config
    config = POWConfig()
    config.default_difficulty_bits = 1 # Easiest difficulty
    config.max_wu_per_challenge = 1000000000
    config.challenge_ttl_seconds = 60

    algos = ["sha3_256", "sha3_512", "keccak_256", "shake128", "shake256"]
    difficulties = [1, 4]

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
                console.print_fail(f"Failed to generate challenge", expected=0, got=ret)
                continue
            
        # Log Challenge Details
            console.print_info(f"Challenge Generated:")
            console.log_data(f"  ID: {bytes(challenge.challenge_id).hex()}")
            console.log_data(f"  Algorithm: {challenge.algorithm_id.decode('utf-8')}")
            console.log_data(f"  Difficulty: {challenge.difficulty_bits}")
            target_bytes = bytes(challenge.target[:challenge.target_len])
            console.print_info(f"  Target: {target_bytes.hex()}")
            console.log_data(f"  Target (Bin): {bytes_to_bin(target_bytes)}")
            console.log_data(f"  Target Prefix Bits: {prefix_bits(target_bytes, challenge.difficulty_bits)}")
            console.log_data(f"  Context (Hex): {bytes(challenge.context[:challenge.context_len]).hex()}")
            console.log_data(f"  Context (Str): {bytes(challenge.context[:challenge.context_len]).decode('utf-8', errors='replace')}")
            console.log_data(f"  WU: {challenge.wu}")
            console.log_data(f"  MU: {challenge.mu}")

        # 3. Solve
            console.print_info(f"Solving challenge...")
            solution = POWSolution()
            
            start = time.time()
            ret = client_dll.leyline_pow_client_solve(
                ctypes.byref(challenge),
                ctypes.byref(solution)
            )
            end = time.time()
            
            if ret != 0:
                console.print_fail(f"Failed to solve challenge", expected=0, got=ret)
                continue
                
            console.print_info(f"Solution found in {solution.solve_time_seconds:.4f}s (Attempts: {solution.attempts})")
            console.log_data(f"  Nonce: {solution.nonce}")
            hash_bytes = bytes(solution.hash_output[:solution.hash_output_len])
            console.print_info(f"  Hash: {hash_bytes.hex()}")
            console.log_data(f"  Hash (Bin): {bytes_to_bin(hash_bytes)}")
            console.log_data(f"  Hash Prefix Bits: {prefix_bits(hash_bytes, challenge.difficulty_bits)}")
            lz = leading_zero_bits(hash_bytes)
            if lz < challenge.difficulty_bits:
                console.print_fail(f"Difficulty check failed", expected=challenge.difficulty_bits, got=lz)
                return 1
        
        # Log the full input string for verification
            input_str = f"{context_str}{solution.nonce}"
            console.log_data(f"  Verify Input String: \"{input_str}\"")

        # 4. Verify
            console.print_info(f"Verifying solution...")
            is_valid = ctypes.c_bool(False)
            
            ret = server_dll.leyline_pow_server_verify_solution(
                ctypes.byref(challenge),
                ctypes.byref(solution),
                ctypes.byref(is_valid)
            )
            
            if ret != 0:
                console.print_fail(f"Server verify error", expected=0, got=ret)
                return 1
                
            if is_valid.value:
                console.print_pass(f"VERIFICATION PASSED for {algo}!")
            else:
                console.print_fail(f"VERIFICATION FAILED for {algo}!")
                return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
