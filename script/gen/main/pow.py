import os
from script.core import Builder

_POW_MACROS_BASE = [
    'POW_ENABLE_PRIMITIVE_FAST',
    'POW_ENABLE_PRIMITIVE_MEMORY_HARD',
    'POW_ENABLE_PRIMITIVE_SPONGE_XOF',
    'POW_ENABLE_LEGACY_ALIVE',
    'POW_ENABLE_LEGACY_UNSAFE',
    'POW_NO_GENERIC_API',
]

def build(builder: Builder):
    """Build PoW + DHCM main DLLs: pow (merged server+client), dhcm."""
    src_dir = builder.config.src_dir

    # ── Shared PoW sources ────────────────────────────────────────────────────
    core_sources = builder.get_sources([
        os.path.join(src_dir, 'PoW/core/')
    ], recursive=True)

    adapter_sources = []
    adapter_dirs = [
        os.path.join(src_dir, 'PoW/adapters/primitive_fast/'),
        os.path.join(src_dir, 'PoW/adapters/primitive_memory_hard/'),
        os.path.join(src_dir, 'PoW/adapters/primitive_sponge_xof/'),
        os.path.join(src_dir, 'PoW/adapters/legacy_alive/'),
        os.path.join(src_dir, 'PoW/adapters/legacy_unsafe/')
    ]
    for d in adapter_dirs:
        adapter_sources.extend(
            s for s in builder.get_sources([d], recursive=True)
            if not s.endswith('dispatcher.c')
        )
    adapter_sources.append(os.path.join(src_dir, 'PoW/adapters/dispatcher_main.c'))

    hash_sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'hash', 'fast'),
        os.path.join(src_dir, 'primitives', 'hash', 'sponge_xof'),
        os.path.join(src_dir, 'primitives', 'hash', 'memory_hard'),
        os.path.join(src_dir, 'legacy/alive/'),
        os.path.join(src_dir, 'legacy/unsafe/')
    ], recursive=True)
    hash_wrapper = os.path.join(src_dir, 'utils', 'hash', 'primitive_memory_hard.c')
    if os.path.exists(hash_wrapper):
        hash_sources.append(hash_wrapper)

    aes_sources = builder.get_sources([
        os.path.join(src_dir, 'primitives/cipher/aes_core/')
    ], recursive=True)

    core_sources.append(os.path.join(src_dir, 'utils/radix/radix_common.c'))
    core_sources.append(os.path.join(src_dir, 'utils/radix/base64.c'))
    core_sources.append(os.path.join(src_dir, 'PoW/mock_deps.c'))

    # ── 1. pow  (server + client merged into a single DLL) ───────────────────
    pow_sources = (core_sources + adapter_sources + hash_sources + aes_sources
                   + builder.get_sources([
                       os.path.join(src_dir, 'PoW/server/'),
                       os.path.join(src_dir, 'PoW/client/')
                   ], recursive=True))

    # Server utils
    for f in ['api.c', 'primitive_fast.c', 'primitive_memory_hard.c',
              'primitive_sponge_xof.c', 'legacy_alive.c', 'legacy_unsafe.c']:
        pow_sources.append(os.path.join(src_dir, 'utils/pow/server', f))
    # Client utils
    for f in ['api.c', 'primitive_fast.c', 'primitive_memory_hard.c',
              'primitive_sponge_xof.c', 'legacy_alive.c', 'legacy_unsafe.c']:
        pow_sources.append(os.path.join(src_dir, 'utils/pow/client', f))
    ret_pow = builder.build_target(
        'pow', pow_sources,
        extra_libs=['-lpthread'], output_subdir='main',
        macros=['POW_ENABLE_SERVER', 'POW_ENABLE_CLIENT'] + _POW_MACROS_BASE,
    )

    # ── 4. dhcm ───────────────────────────────────────────────────────────────
    dhcm_sources = builder.get_sources([
        os.path.join(src_dir, 'DHCM/core/'),
        os.path.join(src_dir, 'DHCM/adapters/primitive_fast/'),
        os.path.join(src_dir, 'DHCM/adapters/primitive_memory_hard/'),
        os.path.join(src_dir, 'DHCM/adapters/primitive_sponge_xof/'),
        os.path.join(src_dir, 'DHCM/adapters/legacy_alive/'),
        os.path.join(src_dir, 'DHCM/adapters/legacy_unsafe/'),
        os.path.join(src_dir, 'DHCM/utils/'),
    ], recursive=True)

    ret_dhcm = builder.build_target(
        'dhcm', dhcm_sources,
        output_subdir='main',
        macros=[
            'DHCM_VERSION_MAJOR=1', 'DHCM_VERSION_MINOR=0',
            'DHCM_ENABLE_PRIMITIVE_FAST',
            'DHCM_ENABLE_PRIMITIVE_MEMORY_HARD',
            'DHCM_ENABLE_PRIMITIVE_SPONGE_XOF',
            'DHCM_ENABLE_LEGACY_ALIVE',
            'DHCM_ENABLE_LEGACY_UNSAFE',
        ],
    )

    return ret_pow or ret_dhcm

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('main', 'pow')) as logger:
        build(Builder(config, logger))
