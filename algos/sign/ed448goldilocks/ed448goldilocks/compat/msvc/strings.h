/* NextSSL compat (not upstream), MSVC targets only: POSIX <strings.h>; crandom.h includes it, the
 * functions it needs are in <string.h>. */
#include <string.h>
