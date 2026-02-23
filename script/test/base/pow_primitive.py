import ctypes
import os
import sys
import time
import threading
from script.core import console

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

# --- Structures ---
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

def load_dll_pair():
    bin_dir = os.path.join(os.getcwd(), 'bin/base')
    # Assuming pow_primitive_server.dll or pow_server_primitive.dll
    # Based on gen script: 'pow_server_primitive', output_subdir='base'
    # So it should be bin/base/pow_server_primitive.dll
    
    server_path = os.path.join(bin_dir, 'pow_server_primitive.dll')
    client_path = os.path.join(bin_dir, 'pow_client_primitive.dll')
    
    if not os.path.exists(server_path): # Check relative to cwd if bin_dir is absolute
        # bin_dir is absolute
        pass

    if not os.path.exists(server_path) or not os.path.exists(client_path):
        console.print_warn(f"Skipping Primitive Base: DLLs not found at {server_path}")
        return None, None
        
    try:
        server = ctypes.CDLL(server_path)
        client = ctypes.CDLL(client_path)
        
        # Setup signatures
        server.leyline_pow_server_generate_challenge.argtypes = [
            ctypes.POINTER(POWConfig), ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8), 
            ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(POWChallenge)
        ]
        server.leyline_pow_server_generate_challenge.restype = ctypes.c_int

        server.leyline_pow_server_verify_solution.argtypes = [
            ctypes.POINTER(POWChallenge), ctypes.POINTER(POWSolution), ctypes.POINTER(ctypes.c_bool)
        ]
        server.leyline_pow_server_verify_solution.restype = ctypes.c_int

        client.leyline_pow_client_solve.argtypes = [
            ctypes.POINTER(POWChallenge), ctypes.POINTER(POWSolution)
        ]
        client.leyline_pow_client_solve.restype = ctypes.c_int
        
        return server, client
    except Exception as e:
        console.print_fail(f"Error loading Primitive Base DLLs: {e}")
        return None, None

def boss_control_loop(server_dll, client_dll, algos, difficulty=1):
    config = POWConfig()
    config.default_difficulty_bits = difficulty
    config.max_wu_per_challenge = 10**10
    config.challenge_ttl_seconds = 60
    
    expected_ops = 2 ** difficulty
    success = True
    
    for algo in algos:
        console.print_step(f"Testing {algo} (Diff: {difficulty})...")
        
        challenge = POWChallenge()
        context = (ctypes.c_uint8 * 32)(*([0x00]*32))
        
        # 1. Server Generate
        start_gen = time.time()
        ret = server_dll.leyline_pow_server_generate_challenge(
            ctypes.byref(config), 
            algo.encode('utf-8'), 
            context, 
            32, 
            difficulty, 
            ctypes.byref(challenge)
        )
        if ret != 0:
            console.print_fail(f"Generate failed for {algo}", expected=0, got=ret)
            success = False
            continue
            
        console.log_data(f"{algo}_challenge_id", bytes(challenge.challenge_id).hex())
        target_bytes = bytes(challenge.target[:challenge.target_len])
        console.print_info(f"Target (Hex): {target_bytes.hex()}")
        console.print_info(f"Target (Bin): {bytes_to_bin(target_bytes)}")
        console.print_info(f"Target Prefix Bits: {prefix_bits(target_bytes, challenge.difficulty_bits)}")
        
        # 2. Client Solve
        solution = POWSolution()
        result_container = {'ret': -1}
        def solve_task():
            result_container['ret'] = client_dll.leyline_pow_client_solve(ctypes.byref(challenge), ctypes.byref(solution))
            
        t = threading.Thread(target=solve_task)
        t.daemon = True
        t.start()
        t.join(timeout=10.0)
        
        if t.is_alive():
            console.print_fail(f"Watchdog timeout: {algo}")
            success = False
            continue
            
        ret = result_container['ret']
        if ret != 0:
            console.print_fail(f"Solve failed for {algo}", expected=0, got=ret)
            success = False
            continue
            
        hash_bytes = bytes(solution.hash_output[:solution.hash_output_len])
        console.print_info(f"Hash (Hex): {hash_bytes.hex()}")
        console.print_info(f"Hash (Bin): {bytes_to_bin(hash_bytes)}")
        console.print_info(f"Hash Prefix Bits: {prefix_bits(hash_bytes, challenge.difficulty_bits)}")
        lz = leading_zero_bits(hash_bytes)
        if lz < challenge.difficulty_bits:
            console.print_fail(f"Difficulty check failed for {algo}", expected=challenge.difficulty_bits, got=lz)
            success = False
            continue
            
        is_valid = ctypes.c_bool(False)
        ret = server_dll.leyline_pow_server_verify_solution(
            ctypes.byref(challenge), 
            ctypes.byref(solution), 
            ctypes.byref(is_valid)
        )
        
        if ret != 0 or not is_valid.value:
            console.print_fail(f"Verify failed for {algo}")
            success = False
        else:
            console.print_pass(f"{algo} verified successfully.")
            
    return success

def main():
    console.print_header("=== Starting PoW Primitive Base Test ===")
    
    algos = [
        'sha256', 'sha512', 'blake3', 'blake2b', 'blake2s',
        'argon2id', 'argon2i', 'argon2d',
        'shake128', 'shake256', 'sha3_256', 'sha3_512', 'keccak_256'
    ]
    difficulties = [1, 4]
    
    server, client = load_dll_pair()
    if server and client:
        all_ok = True
        for difficulty in difficulties:
            if not boss_control_loop(server, client, algos, difficulty=difficulty):
                all_ok = False
        if all_ok:
            return 0
    return 1

if __name__ == "__main__":
    sys.exit(main())
