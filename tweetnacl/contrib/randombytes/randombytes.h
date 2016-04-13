/*
randombytes/randombytes.h version 20080713
D. J. Bernstein
Public domain.
*/

#ifndef randombytes_H
#define randombytes_H

/*
    Disable warnings for this source only, rather than for the whole
    codebase when building with C99 or with Microsoft's compiler
*/
#if defined __GNUC__ && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 2)) && __STDC_VERSION__ < 201112L
#   pragma GCC diagnostic ignored "-Wsign-compare"
#elif defined _MSC_VER
#   pragma warning (disable:4018 4244 4146)
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern void randombytes(unsigned char *,unsigned long long);
extern int randombytes_close(void);

#ifdef __cplusplus
}
#endif

#endif
