/* hash_ops_disabled_stubs.c
 *
 * Disabled memory-hard hashes must fail at build time rather than silently
 * register zero-producing stand-ins.
 */

#if !defined(ENABLE_SCRYPT)
#error "ENABLE_SCRYPT must be enabled or scrypt must be removed from the registry; silent disabled stubs are forbidden"
#endif

#if !defined(ENABLE_YESCRYPT)
#error "ENABLE_YESCRYPT must be enabled or yescrypt must be removed from the registry; silent disabled stubs are forbidden"
#endif

#if !defined(ENABLE_CATENA)
#error "ENABLE_CATENA must be enabled or catena must be removed from the registry; silent disabled stubs are forbidden"
#endif

#if !defined(ENABLE_LYRA2)
#error "ENABLE_LYRA2 must be enabled or lyra2 must be removed from the registry; silent disabled stubs are forbidden"
#endif
