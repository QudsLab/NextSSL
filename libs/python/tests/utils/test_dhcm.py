"""DHCM tests - Dynamic Hash Cost Model."""

from .common import has_binaries
import ctypes


def run(log):
    from nextssl.dhcm import DHCMAlgorithm, DHCMDifficultyModel, DHCMParams, DHCMResult

    # ------------------------------------------------------------------
    log.section("DHCMAlgorithm enum validation")
    # ------------------------------------------------------------------

    expected = {
        "SHA256": 0, "SHA512": 1, "BLAKE2B": 2, "BLAKE2S": 3, "BLAKE3": 4,
        "ARGON2D": 100, "ARGON2I": 101, "ARGON2ID": 102,
        "SHA3_256": 200, "SHA3_512": 201, "KECCAK_256": 202, "SHAKE128": 203, "SHAKE256": 204,
        "MD5": 300, "SHA1": 301, "RIPEMD160": 302, "WHIRLPOOL": 303, "NT": 304,
        "MD2": 400, "MD4": 401, "SHA0": 402, "HAS160": 403,
        "RIPEMD128": 404, "RIPEMD256": 405, "RIPEMD320": 406,
    }

    for name, val in expected.items():
        member = DHCMAlgorithm[name]
        log.check(member.value == val, f"DHCMAlgorithm.{name}", value=member.value, expected=val)

    log.check(len(DHCMAlgorithm) == len(expected),
              "DHCMAlgorithm member count", got=len(DHCMAlgorithm), expected=len(expected))

    # ------------------------------------------------------------------
    log.section("DHCMDifficultyModel enum validation")
    # ------------------------------------------------------------------

    diff_expected = {
        "LEADING_ZEROS_BITS": 0, "LEADING_ZEROS_BYTES": 1, "LESS_THAN_TARGET": 2,
    }

    for name, val in diff_expected.items():
        member = DHCMDifficultyModel[name]
        log.check(member.value == val, f"DHCMDifficultyModel.{name}", value=member.value, expected=val)

    # ------------------------------------------------------------------
    log.section("DHCMParams structure fields")
    # ------------------------------------------------------------------

    field_names = [f[0] for f in DHCMParams._fields_]
    required = ["algorithm", "input_size", "target_zeros", "difficulty_model",
                "memory_cost", "time_cost", "parallelism", "output_size"]
    for f in required:
        log.check(f in field_names, f"DHCMParams.{f} exists")

    # ------------------------------------------------------------------
    log.section("DHCMResult structure fields")
    # ------------------------------------------------------------------

    result_fields = [f[0] for f in DHCMResult._fields_]
    required_result = ["work_units", "memory_usage", "expected_trials",
                       "algorithm_name", "cost_model_version"]
    for f in required_result:
        log.check(f in result_fields, f"DHCMResult.{f} exists")

    # ------------------------------------------------------------------
    # Functional tests require C binaries
    # ------------------------------------------------------------------

    if not has_binaries():
        log.info("C binaries not available - skipping functional DHCM tests")
        return

    from nextssl.dhcm import DHCM

    log.section("Functional: DHCM calculate")

    dhcm = DHCM()
    result = dhcm.calculate(DHCMAlgorithm.SHA256, input_size=32, target_zeros=8)
    log.check("work_units" in result, "Result has work_units")
    log.check("expected_trials" in result, "Result has expected_trials")

    log.section("Functional: expected_trials scaling")

    t8 = dhcm.expected_trials(DHCMDifficultyModel.LEADING_ZEROS_BITS, 8)
    t16 = dhcm.expected_trials(DHCMDifficultyModel.LEADING_ZEROS_BITS, 16)
    log.check(t16 > t8, "16 zeros > 8 zeros", t8=t8, t16=t16)
