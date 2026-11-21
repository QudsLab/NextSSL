# ORIGIN: xmssmt-sha2-40-8-192

- repository: https://github.com/XMSS/xmss-reference
- commit: 171ccbd26f098542a67eb5d2b128281c80bd71a6
- license: CC0-1.0
- copied verbatim: the reference (non-BDS) implementation xmss_core.c, params.c, hash.c, fips202.c, wots.c, ...; randombytes.c is not compiled (shim.c supplies randombytes)
- parameter set: XMSSMT-SHA2_40/8_192 (OID 0x00000025)
