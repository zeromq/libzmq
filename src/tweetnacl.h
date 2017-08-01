/*
    Copyright (c) 2016-2017 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef TWEETNACL_H
#define TWEETNACL_H

#if defined (ZMQ_USE_TWEETNACL)

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
void randombytes (unsigned char *, unsigned long long);
//  Do not call manually! Use random_close from random.hpp
int randombytes_close (void);
//  Do not call manually! Use random_open from random.hpp
int sodium_init (void);

int crypto_box_keypair(u8 *y,u8 *x);
int crypto_box_afternm(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k);
int crypto_box_open_afternm(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *k);
int crypto_box(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *y,const u8 *x);
int crypto_box_open(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *y,const u8 *x);
int crypto_box_beforenm(u8 *k,const u8 *y,const u8 *x);
int crypto_scalarmult_base(u8 *q,const u8 *n);
int crypto_secretbox(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k);
int crypto_secretbox_open(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *k);
#ifdef __cplusplus
}
#endif

#endif

#endif
