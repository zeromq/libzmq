/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_UTILS_H_INCLUDED__
#define __ZMQ_UTILS_H_INCLUDED__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*  Define integer types needed for event interface                          */
#if defined ZMQ_HAVE_SOLARIS || defined ZMQ_HAVE_OPENVMS
#   include <inttypes.h>
#elif defined _MSC_VER && _MSC_VER < 1600
#   ifndef int32_t
typedef __int32 int32_t;
#   endif
#   ifndef uint16_t
typedef unsigned __int16 uint16_t;
#   endif
#else
#   include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*  Handle DSO symbol visibility                                             */
#if defined _WIN32
#   if defined ZMQ_STATIC
#       define ZMQ_EXPORT
#   elif defined DLL_EXPORT
#       define ZMQ_EXPORT __declspec(dllexport)
#   else
#       define ZMQ_EXPORT __declspec(dllimport)
#   endif
#else
#   if defined __SUNPRO_C  || defined __SUNPRO_CC
#       define ZMQ_EXPORT __global
#   elif (defined __GNUC__ && __GNUC__ >= 4) || defined __INTEL_COMPILER
#       define ZMQ_EXPORT __attribute__ ((visibility("default")))
#   else
#       define ZMQ_EXPORT
#   endif
#endif

/* These functions are documented by man pages                                */

/* Encode data with Z85 encoding. Returns encoded data                        */
ZMQ_EXPORT char *zmq_z85_encode (char *dest, uint8_t *data, size_t size);

/* Decode data with Z85 encoding. Returns decoded data                        */
ZMQ_EXPORT uint8_t *zmq_z85_decode (uint8_t *dest, char *string);

/* Generate z85-encoded public and private keypair with libsodium.            */
/* Returns 0 on success.                                                      */
ZMQ_EXPORT int zmq_curve_keypair (char *z85_public_key, char *z85_secret_key);

typedef void (zmq_thread_fn) (void*);

/*  These functions are not documented by man pages                           */

/*  Helper functions are used by perf tests so that they don't have to care   */
/*  about minutiae of time-related functions on different OS platforms.       */

/*  Starts the stopwatch. Returns the handle to the watch.                    */
ZMQ_EXPORT void *zmq_stopwatch_start (void);

/*  Stops the stopwatch. Returns the number of microseconds elapsed since     */
/*  the stopwatch was started.                                                */
ZMQ_EXPORT unsigned long zmq_stopwatch_stop (void *watch_);

/*  Sleeps for specified number of seconds.                                   */
ZMQ_EXPORT void zmq_sleep (int seconds_);

/* Start a thread. Returns a handle to the thread.                            */
ZMQ_EXPORT void *zmq_threadstart (zmq_thread_fn* func, void* arg);

/* Wait for thread to complete then free up resources.                        */
ZMQ_EXPORT void zmq_threadclose (void* thread);

#undef ZMQ_EXPORT

#ifdef __cplusplus
}
#endif

#endif
