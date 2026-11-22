/* NextSSL compat (not upstream), MSVC targets only: catena.c includes <sys/param.h> and uses nothing
 * from it (its byte-order test compares macros that are absent here and so equal: little endian). */
