"""DHCM (Dynamic Hash Cost Model) - Hash algorithm cost calculation."""
import ctypes
from enum import IntEnum
from typing import Optional, Tuple
from ._loader import get_loader


class DHCMAlgorithm(IntEnum):
    """DHCM Hash Algorithms - ALL variants from DHCM adapters."""
    # Primitive Fast
    SHA256 = 0
    SHA512 = 1
    BLAKE2B = 2
    BLAKE2S = 3
    BLAKE3 = 4
    
    # Primitive Memory Hard (Argon2 variants)
    ARGON2D = 100
    ARGON2I = 101
    ARGON2ID = 102
    
    # Primitive Sponge/XOF
    SHA3_256 = 200
    SHA3_512 = 201
    KECCAK_256 = 202
    SHAKE128 = 203
    SHAKE256 = 204
    
    # Legacy Alive (deprecated but still used)
    MD5 = 300
    SHA1 = 301
    RIPEMD160 = 302
    WHIRLPOOL = 303
    NT = 304
    
    # Legacy Unsafe (broken, for compatibility only)
    MD2 = 400
    MD4 = 401
    SHA0 = 402
    HAS160 = 403
    RIPEMD128 = 404
    RIPEMD256 = 405
    RIPEMD320 = 406


class DHCMDifficultyModel(IntEnum):
    """Difficulty models for PoW."""
    LEADING_ZEROS_BITS = 0
    LEADING_ZEROS_BYTES = 1
    LESS_THAN_TARGET = 2


class DHCMParams(ctypes.Structure):
    """DHCM calculation parameters."""
    _fields_ = [
        ("algorithm", ctypes.c_int),
        ("input_size", ctypes.c_size_t),
        ("target_zeros", ctypes.c_uint32),
        ("difficulty_model", ctypes.c_int),
        ("memory_cost", ctypes.c_uint32),
        ("time_cost", ctypes.c_uint32),
        ("parallelism", ctypes.c_uint32),
        ("output_size", ctypes.c_size_t),
    ]


class DHCMResult(ctypes.Structure):
    """DHCM calculation result."""
    _fields_ = [
        ("work_units", ctypes.c_uint64),
        ("memory_usage", ctypes.c_uint64),
        ("expected_trials", ctypes.c_double),
        ("algorithm_name", ctypes.c_char * 64),
        ("cost_model_version", ctypes.c_char * 32),
    ]


class DHCM:
    """DHCM API wrapper."""
    
    def __init__(self, use_system: bool = True):
        """
        Initialize DHCM.
        
        Args:
            use_system: Use system library (all algorithms) vs individual libraries
        """
        loader = get_loader()
        if use_system:
            self._lib = loader.load_system()
        else:
            # Load main dhcm library (all variants)
            self._lib = loader.load("dhcm", "main")
        
        # Setup function signatures
        self._lib.leyline_dhcm_calculate.argtypes = [
            ctypes.POINTER(DHCMParams),
            ctypes.POINTER(DHCMResult)
        ]
        self._lib.leyline_dhcm_calculate.restype = ctypes.c_int
        
        self._lib.leyline_dhcm_expected_trials.argtypes = [
            ctypes.c_int,
            ctypes.c_uint32
        ]
        self._lib.leyline_dhcm_expected_trials.restype = ctypes.c_double
    
    def calculate(
        self,
        algorithm: DHCMAlgorithm,
        input_size: int = 32,
        target_zeros: int = 0,
        difficulty_model: DHCMDifficultyModel = DHCMDifficultyModel.LEADING_ZEROS_BITS,
        memory_cost: int = 0,
        time_cost: int = 0,
        parallelism: int = 1,
        output_size: int = 0
    ) -> dict:
        """
        Calculate hash algorithm cost.
        
        Args:
            algorithm: Hash algorithm to analyze
            input_size: Input data size in bytes
            target_zeros: PoW difficulty (leading zeros)
            difficulty_model: How difficulty is measured
            memory_cost: Memory cost parameter (for Argon2/scrypt)
            time_cost: Time cost parameter (for Argon2)
            parallelism: Parallelism parameter (for Argon2)
            output_size: Output size for XOF functions (SHAKE)
        
        Returns:
            Dictionary with work_units, memory_usage, expected_trials, etc.
        """
        params = DHCMParams(
            algorithm=algorithm,
            input_size=input_size,
            target_zeros=target_zeros,
            difficulty_model=difficulty_model,
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism,
            output_size=output_size
        )
        
        result = DHCMResult()
        ret = self._lib.leyline_dhcm_calculate(ctypes.byref(params), ctypes.byref(result))
        
        if ret != 0:
            raise RuntimeError(f"DHCM calculation failed with code {ret}")
        
        return {
            "work_units": result.work_units,
            "memory_usage": result.memory_usage,
            "expected_trials": result.expected_trials,
            "algorithm_name": result.algorithm_name.decode('utf-8'),
            "cost_model_version": result.cost_model_version.decode('utf-8')
        }
    
    def expected_trials(
        self,
        difficulty_model: DHCMDifficultyModel,
        target_zeros: int
    ) -> float:
        """
        Calculate expected number of trials for given difficulty.
        
        Args:
            difficulty_model: How difficulty is measured
            target_zeros: Number of leading zeros required
        
        Returns:
            Expected number of trials
        """
        return self._lib.leyline_dhcm_expected_trials(difficulty_model, target_zeros)
