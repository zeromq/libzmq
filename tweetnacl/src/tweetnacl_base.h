#ifndef TWEETNACL_BASE_H
#define TWEETNACL_BASE_H

/*
    Disable warnings for this source only, rather than for the whole
    codebase when building with C99 or with Microsoft's compiler
*/
#if defined __GNUC__ && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 2)) && __STDC_VERSION__ < 201112L
#   pragma GCC diagnostic ignored "-Wsign-compare"
#elif defined _MSC_VER
#   pragma warning (disable:4018 4244 4146)
#endif

/* the original file seems to be a compability layer for NaCL */

/* This here is for direct tweetnacl usage */ 

#define crypto_box_SECRETKEYBYTES 32
#define crypto_box_BOXZEROBYTES 16
#define crypto_box_NONCEBYTES 24
#define crypto_box_ZEROBYTES 32
#define crypto_box_PUBLICKEYBYTES 32
#define crypto_box_BEFORENMBYTES 32
#define crypto_secretbox_KEYBYTES 32
#define crypto_secretbox_NONCEBYTES 24
#define crypto_secretbox_ZEROBYTES 32
#define crypto_secretbox_BOXZEROBYTES 16
typedef unsigned char u8;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef long long i64;
typedef i64 gf[16];

#ifdef __cplusplus
extern "C" {
#endif
int crypto_box_keypair(u8 *y,u8 *x);
int crypto_box_afternm(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k);


int crypto_box_open_afternm(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *k);
int crypto_box(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *y,const u8 *x);
int crypto_box_open(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *y,const u8 *x);
int crypto_box_beforenm(u8 *k,const u8 *y,const u8 *x);
int crypto_secretbox(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k);
int crypto_secretbox_open(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *k);
#ifdef __cplusplus
}
#endif

#endif
