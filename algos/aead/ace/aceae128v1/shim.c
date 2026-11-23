/* Allocation guard (not crypto). The upstream returns from some error paths without freeing its
 * heap buffers (they can hold key-dependent state). The force-included preamble routes its malloc/free
 * here; after every C call the glue calls nextssl__aceae128v1__mem_release(), which zeroizes and frees whatever the call
 * left allocated. A table overflow or an unknown pointer aborts: no allocation is ever untracked. */
#include <stdlib.h>
#include <string.h>
#undef malloc
#undef free

#if defined(_MSC_VER)
#define NS_TLS __declspec(thread)
#else
#define NS_TLS _Thread_local
#endif

#define NS_SLOTS 64
static NS_TLS void *ns_ptr[NS_SLOTS];
static NS_TLS size_t ns_len[NS_SLOTS];

static void ns_wipe(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

void *nextssl__aceae128v1__mem_alloc(size_t n) {
    for (int i = 0; i < NS_SLOTS; i++) {
        if (ns_ptr[i] == NULL) {
            void *p = malloc(n ? n : 1);
            if (p != NULL) {
                ns_ptr[i] = p;
                ns_len[i] = n;
            }
            return p;
        }
    }
    abort();
}

void nextssl__aceae128v1__mem_free(void *p) {
    if (p == NULL) return;
    for (int i = 0; i < NS_SLOTS; i++) {
        if (ns_ptr[i] == p) {
            ns_wipe(p, ns_len[i]);
            free(p);
            ns_ptr[i] = NULL;
            return;
        }
    }
    abort();
}

void nextssl__aceae128v1__mem_release(void) {
    for (int i = 0; i < NS_SLOTS; i++) {
        if (ns_ptr[i] != NULL) {
            ns_wipe(ns_ptr[i], ns_len[i]);
            free(ns_ptr[i]);
            ns_ptr[i] = NULL;
        }
    }
}
