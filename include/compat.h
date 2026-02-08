#ifndef _COMPAT_H_
#define _COMPAT_H_

/* Secure memory clearing - prefer memset_explicit (C23) over explicit_bzero */
#if !defined(HAVE_MEMSET_EXPLICIT) && !defined(HAVE_EXPLICIT_BZERO)
#include <stddef.h>
extern void explicit_bzero(void *s, size_t n);
#elif defined(HAVE_MEMSET_EXPLICIT) && !defined(HAVE_EXPLICIT_BZERO)
#include <string.h>
#define explicit_bzero(s, n) memset_explicit((s), 0, (n))
#endif

#endif
