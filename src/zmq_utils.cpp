/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

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

#include "platform.hpp"

#include "clock.hpp"
#include "err.hpp"
#include "thread.hpp"
#include <assert.h>
#include "../include/zmq_utils.h"

#if !defined ZMQ_HAVE_WINDOWS
#include <unistd.h>
#else
#include "windows.hpp"
#endif

#ifdef HAVE_LIBSODIUM
#ifdef HAVE_TWEETNACL
#include "tweetnacl_base.h"
#else
#include "sodium.h"
#endif
#endif


void zmq_sleep (int seconds_)
{
#if defined ZMQ_HAVE_WINDOWS
    Sleep (seconds_ * 1000);
#else
    sleep (seconds_);
#endif
}

void *zmq_stopwatch_start ()
{
    uint64_t *watch = (uint64_t*) malloc (sizeof (uint64_t));
    alloc_assert (watch);
    *watch = zmq::clock_t::now_us ();
    return (void*) watch;
}

unsigned long zmq_stopwatch_stop (void *watch_)
{
    uint64_t end = zmq::clock_t::now_us ();
    uint64_t start = *(uint64_t*) watch_;
    free (watch_);
    return (unsigned long) (end - start);
}

void *zmq_threadstart(zmq_thread_fn* func, void* arg)
{
    zmq::thread_t* thread = new zmq::thread_t;
    thread->start(func, arg);
    return thread;
}

void zmq_threadclose(void* thread)
{
    zmq::thread_t* pThread = static_cast<zmq::thread_t*>(thread);
    pThread->stop();
    delete pThread;
}

//  Z85 codec, taken from 0MQ RFC project, implements RFC32 Z85 encoding

//  Maps base 256 to base 85
static char encoder [85 + 1] = {
    "0123456789" "abcdefghij" "klmnopqrst" "uvwxyzABCD"
    "EFGHIJKLMN" "OPQRSTUVWX" "YZ.-:+=^!/" "*?&<>()[]{" 
    "}@%$#"
};

//  Maps base 85 to base 256
//  We chop off lower 32 and higher 128 ranges
static uint8_t decoder [96] = {
    0x00, 0x44, 0x00, 0x54, 0x53, 0x52, 0x48, 0x00, 
    0x4B, 0x4C, 0x46, 0x41, 0x00, 0x3F, 0x3E, 0x45, 
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
    0x08, 0x09, 0x40, 0x00, 0x49, 0x42, 0x4A, 0x47, 
    0x51, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 
    0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 
    0x3B, 0x3C, 0x3D, 0x4D, 0x00, 0x4E, 0x43, 0x00, 
    0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 
    0x21, 0x22, 0x23, 0x4F, 0x00, 0x50, 0x00, 0x00
};

//  --------------------------------------------------------------------------
//  Encode a binary frame as a string; destination string MUST be at least
//  size * 5 / 4 bytes long plus 1 byte for the null terminator. Returns
//  dest. Size must be a multiple of 4.
//  Returns NULL and sets errno = EINVAL for invalid input.

char *zmq_z85_encode (char *dest, const uint8_t *data, size_t size)
{
    if (size % 4 != 0) {
        errno = EINVAL;
        return NULL;
    }
    unsigned int char_nbr = 0;
    unsigned int byte_nbr = 0;
    uint32_t value = 0;
    while (byte_nbr < size) {
        //  Accumulate value in base 256 (binary)
        value = value * 256 + data [byte_nbr++];
        if (byte_nbr % 4 == 0) {
            //  Output value in base 85
            unsigned int divisor = 85 * 85 * 85 * 85;
            while (divisor) {
                dest [char_nbr++] = encoder [value / divisor % 85];
                divisor /= 85;
            }
            value = 0;
        }
    }
    assert (char_nbr == size * 5 / 4);
    dest [char_nbr] = 0;
    return dest;
}


//  --------------------------------------------------------------------------
//  Decode an encoded string into a binary frame; dest must be at least
//  strlen (string) * 4 / 5 bytes long. Returns dest. strlen (string) 
//  must be a multiple of 5.
//  Returns NULL and sets errno = EINVAL for invalid input.

uint8_t *zmq_z85_decode (uint8_t *dest, const char *string)
{
    if (strlen (string) % 5 != 0) {
        errno = EINVAL;
        return NULL;
    }
    unsigned int byte_nbr = 0;
    unsigned int char_nbr = 0;
    unsigned int string_len = strlen (string);
    uint32_t value = 0;
    while (char_nbr < string_len) {
        //  Accumulate value in base 85
        value = value * 85 + decoder [(uint8_t) string [char_nbr++] - 32];
        if (char_nbr % 5 == 0) {
            //  Output value in base 256
            unsigned int divisor = 256 * 256 * 256;
            while (divisor) {
                dest [byte_nbr++] = value / divisor % 256;
                divisor /= 256;
            }
            value = 0;
        }
    }
    assert (byte_nbr == strlen (string) * 4 / 5);
    return dest;
}

//  --------------------------------------------------------------------------
//  Generate a public/private keypair with libsodium.
//  Generated keys will be 40 byte z85-encoded strings.
//  Returns 0 on success, -1 on failure, setting errno.
//  Sets errno = ENOTSUP in the absence of libsodium.

int zmq_curve_keypair (char *z85_public_key, char *z85_secret_key)
{
#ifdef HAVE_LIBSODIUM
#   if crypto_box_PUBLICKEYBYTES != 32 \
    || crypto_box_SECRETKEYBYTES != 32
#       error "libsodium not built correctly"
#   endif

    uint8_t public_key [32];
    uint8_t secret_key [32];

    int rc = crypto_box_keypair (public_key, secret_key);
    //  Is there a sensible errno to set here?
    if (rc)
        return rc;

    zmq_z85_encode (z85_public_key, public_key, 32);
    zmq_z85_encode (z85_secret_key, secret_key, 32);

    return 0;
#else // requires libsodium
    (void) z85_public_key, (void) z85_secret_key;
    errno = ENOTSUP;
    return -1;
#endif
}
