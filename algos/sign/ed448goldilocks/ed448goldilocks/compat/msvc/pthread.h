/* NextSSL compat (not upstream), MSVC targets only. goldilocks.c (GOLDILOCKS_USE_PTHREAD) uses one
 * process-global mutex: init, lock, unlock. Windows has no pthreads, so those three map onto a slim
 * reader/writer lock taken exclusively, which keeps the upstream's thread safety. */
#ifndef NEXTSSL_COMPAT_PTHREAD_H
#define NEXTSSL_COMPAT_PTHREAD_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef SRWLOCK pthread_mutex_t;
typedef int pthread_mutexattr_t;

static int pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *attr) {
    if (attr != NULL) return 22; /* EINVAL: attributes are not supported here */
    InitializeSRWLock(m);
    return 0;
}

static int pthread_mutex_lock(pthread_mutex_t *m) {
    AcquireSRWLockExclusive(m);
    return 0;
}

static int pthread_mutex_unlock(pthread_mutex_t *m) {
    ReleaseSRWLockExclusive(m);
    return 0;
}
#endif
