/* platform-specific.inc -- generic build (x86_64/arm64/other)
 * No platform-specific assembly. All asm_* flags default to 0,
 * meaning uECC.c uses its portable C fallback for all VLI ops.
 * The static muladd() helper is defined inside uECC.c itself.
 */
