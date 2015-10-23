/*
randombytes/randombytes.h version 20080713
D. J. Bernstein
Public domain.
*/

#ifndef randombytes_H
#define randombytes_H

#ifdef __cplusplus
extern "C" {
#endif

extern void randombytes(unsigned char *,unsigned long long);
extern int randombytes_close(void);

#ifdef __cplusplus
}
#endif

#endif
