/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_CURVE_MECHANISM_BASE_HPP_INCLUDED__
#define __ZMQ_CURVE_MECHANISM_BASE_HPP_INCLUDED__

#ifdef ZMQ_HAVE_CURVE

#if defined(ZMQ_USE_TWEETNACL)
#include "tweetnacl.h"
#elif defined(ZMQ_USE_LIBSODIUM)
#include "sodium.h"
#endif

#if crypto_box_NONCEBYTES != 24 || crypto_box_PUBLICKEYBYTES != 32             \
  || crypto_box_SECRETKEYBYTES != 32 || crypto_box_ZEROBYTES != 32             \
  || crypto_box_BOXZEROBYTES != 16 || crypto_secretbox_NONCEBYTES != 24        \
  || crypto_secretbox_ZEROBYTES != 32 || crypto_secretbox_BOXZEROBYTES != 16
#error "CURVE library not built properly"
#endif

#include "mechanism_base.hpp"
#include "options.hpp"

#include <memory>

namespace zmq
{
class curve_mechanism_base_t : public virtual mechanism_base_t
{
  public:
    curve_mechanism_base_t (session_base_t *session_,
                            const options_t &options_,
                            const char *encode_nonce_prefix_,
                            const char *decode_nonce_prefix_);

    // mechanism implementation
    virtual int encode (msg_t *msg_);
    virtual int decode (msg_t *msg_);

  protected:
    const char *encode_nonce_prefix;
    const char *decode_nonce_prefix;

    uint64_t cn_nonce;
    uint64_t cn_peer_nonce;

    //  Intermediary buffer used to speed up boxing and unboxing.
    uint8_t cn_precom[crypto_box_BEFORENMBYTES];
};
}

#endif

#endif
