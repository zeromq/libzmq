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

#ifndef __ZMQ_CURVE_CLIENT_TOOLS_HPP_INCLUDED__
#define __ZMQ_CURVE_CLIENT_TOOLS_HPP_INCLUDED__

#ifdef ZMQ_HAVE_CURVE

#if defined(ZMQ_USE_TWEETNACL)
#include "tweetnacl.h"
#elif defined(ZMQ_USE_LIBSODIUM)
#include "sodium.h"
#endif

#if crypto_box_NONCEBYTES != 24 || crypto_box_PUBLICKEYBYTES != 32             \
  || crypto_box_SECRETKEYBYTES != 32 || crypto_box_ZEROBYTES != 32             \
  || crypto_box_BOXZEROBYTES != 16
#error "CURVE library not built properly"
#endif

#include "wire.hpp"
#include "err.hpp"
#include "secure_allocator.hpp"

#include <vector>

namespace zmq
{
struct curve_client_tools_t
{
    static int produce_hello (void *data_,
                              const uint8_t *server_key_,
                              const uint64_t cn_nonce_,
                              const uint8_t *cn_public_,
                              const uint8_t *cn_secret_)
    {
        uint8_t hello_nonce[crypto_box_NONCEBYTES];
        std::vector<uint8_t, secure_allocator_t<uint8_t> > hello_plaintext (
          crypto_box_ZEROBYTES + 64, 0);
        uint8_t hello_box[crypto_box_BOXZEROBYTES + 80];

        //  Prepare the full nonce
        memcpy (hello_nonce, "CurveZMQHELLO---", 16);
        put_uint64 (hello_nonce + 16, cn_nonce_);

        //  Create Box [64 * %x0](C'->S)
        const int rc =
          crypto_box (hello_box, &hello_plaintext[0], hello_plaintext.size (),
                      hello_nonce, server_key_, cn_secret_);
        if (rc == -1)
            return -1;

        uint8_t *hello = static_cast<uint8_t *> (data_);

        memcpy (hello, "\x05HELLO", 6);
        //  CurveZMQ major and minor version numbers
        memcpy (hello + 6, "\1\0", 2);
        //  Anti-amplification padding
        memset (hello + 8, 0, 72);
        //  Client public connection key
        memcpy (hello + 80, cn_public_, crypto_box_PUBLICKEYBYTES);
        //  Short nonce, prefixed by "CurveZMQHELLO---"
        memcpy (hello + 112, hello_nonce + 16, 8);
        //  Signature, Box [64 * %x0](C'->S)
        memcpy (hello + 120, hello_box + crypto_box_BOXZEROBYTES, 80);

        return 0;
    }

    static int process_welcome (const uint8_t *msg_data_,
                                size_t msg_size_,
                                const uint8_t *server_key_,
                                const uint8_t *cn_secret_,
                                uint8_t *cn_server_,
                                uint8_t *cn_cookie_,
                                uint8_t *cn_precom_)
    {
        if (msg_size_ != 168) {
            errno = EPROTO;
            return -1;
        }

        uint8_t welcome_nonce[crypto_box_NONCEBYTES];
        std::vector<uint8_t, secure_allocator_t<uint8_t> > welcome_plaintext (
          crypto_box_ZEROBYTES + 128);
        uint8_t welcome_box[crypto_box_BOXZEROBYTES + 144];

        //  Open Box [S' + cookie](C'->S)
        memset (welcome_box, 0, crypto_box_BOXZEROBYTES);
        memcpy (welcome_box + crypto_box_BOXZEROBYTES, msg_data_ + 24, 144);

        memcpy (welcome_nonce, "WELCOME-", 8);
        memcpy (welcome_nonce + 8, msg_data_ + 8, 16);

        int rc = crypto_box_open (&welcome_plaintext[0], welcome_box,
                                  sizeof welcome_box, welcome_nonce,
                                  server_key_, cn_secret_);
        if (rc != 0) {
            errno = EPROTO;
            return -1;
        }

        memcpy (cn_server_, &welcome_plaintext[crypto_box_ZEROBYTES], 32);
        memcpy (cn_cookie_, &welcome_plaintext[crypto_box_ZEROBYTES + 32],
                16 + 80);

        //  Message independent precomputation
        rc = crypto_box_beforenm (cn_precom_, cn_server_, cn_secret_);
        zmq_assert (rc == 0);

        return 0;
    }

    static int produce_initiate (void *data_,
                                 size_t size_,
                                 const uint64_t cn_nonce_,
                                 const uint8_t *server_key_,
                                 const uint8_t *public_key_,
                                 const uint8_t *secret_key_,
                                 const uint8_t *cn_public_,
                                 const uint8_t *cn_secret_,
                                 const uint8_t *cn_server_,
                                 const uint8_t *cn_cookie_,
                                 const uint8_t *metadata_plaintext_,
                                 const size_t metadata_length_)
    {
        uint8_t vouch_nonce[crypto_box_NONCEBYTES];
        std::vector<uint8_t, secure_allocator_t<uint8_t> > vouch_plaintext (
          crypto_box_ZEROBYTES + 64);
        uint8_t vouch_box[crypto_box_BOXZEROBYTES + 80];

        //  Create vouch = Box [C',S](C->S')
        std::fill (vouch_plaintext.begin (),
                   vouch_plaintext.begin () + crypto_box_ZEROBYTES, 0);
        memcpy (&vouch_plaintext[crypto_box_ZEROBYTES], cn_public_, 32);
        memcpy (&vouch_plaintext[crypto_box_ZEROBYTES + 32], server_key_, 32);

        memset (vouch_nonce, 0, crypto_box_NONCEBYTES);
        memcpy (vouch_nonce, "VOUCH---", 8);
        randombytes (vouch_nonce + 8, 16);

        int rc =
          crypto_box (vouch_box, &vouch_plaintext[0], vouch_plaintext.size (),
                      vouch_nonce, cn_server_, secret_key_);
        if (rc == -1)
            return -1;

        uint8_t initiate_nonce[crypto_box_NONCEBYTES];
        std::vector<uint8_t> initiate_box (crypto_box_BOXZEROBYTES + 144
                                           + metadata_length_);
        std::vector<uint8_t, secure_allocator_t<uint8_t> > initiate_plaintext (
          crypto_box_ZEROBYTES + 128 + metadata_length_);

        //  Create Box [C + vouch + metadata](C'->S')
        std::fill (initiate_plaintext.begin (),
                   initiate_plaintext.begin () + crypto_box_ZEROBYTES, 0);
        memcpy (&initiate_plaintext[crypto_box_ZEROBYTES], public_key_, 32);
        memcpy (&initiate_plaintext[crypto_box_ZEROBYTES + 32], vouch_nonce + 8,
                16);
        memcpy (&initiate_plaintext[crypto_box_ZEROBYTES + 48],
                vouch_box + crypto_box_BOXZEROBYTES, 80);
        if (metadata_length_) {
            memcpy (&initiate_plaintext[crypto_box_ZEROBYTES + 48 + 80],
                    metadata_plaintext_, metadata_length_);
        }

        memcpy (initiate_nonce, "CurveZMQINITIATE", 16);
        put_uint64 (initiate_nonce + 16, cn_nonce_);

        rc = crypto_box (&initiate_box[0], &initiate_plaintext[0],
                         crypto_box_ZEROBYTES + 128 + metadata_length_,
                         initiate_nonce, cn_server_, cn_secret_);

        if (rc == -1)
            return -1;

        uint8_t *initiate = static_cast<uint8_t *> (data_);

        zmq_assert (size_
                    == 113 + 128 + crypto_box_BOXZEROBYTES + metadata_length_);

        memcpy (initiate, "\x08INITIATE", 9);
        //  Cookie provided by the server in the WELCOME command
        memcpy (initiate + 9, cn_cookie_, 96);
        //  Short nonce, prefixed by "CurveZMQINITIATE"
        memcpy (initiate + 105, initiate_nonce + 16, 8);
        //  Box [C + vouch + metadata](C'->S')
        memcpy (initiate + 113, &initiate_box[crypto_box_BOXZEROBYTES],
                128 + metadata_length_ + crypto_box_BOXZEROBYTES);

        return 0;
    }

    static bool is_handshake_command_welcome (const uint8_t *msg_data_,
                                              const size_t msg_size_)
    {
        return is_handshake_command (msg_data_, msg_size_, "\7WELCOME");
    }

    static bool is_handshake_command_ready (const uint8_t *msg_data_,
                                            const size_t msg_size_)
    {
        return is_handshake_command (msg_data_, msg_size_, "\5READY");
    }

    static bool is_handshake_command_error (const uint8_t *msg_data_,
                                            const size_t msg_size_)
    {
        return is_handshake_command (msg_data_, msg_size_, "\5ERROR");
    }

    //  non-static functions
    curve_client_tools_t (
      const uint8_t (&curve_public_key_)[crypto_box_PUBLICKEYBYTES],
      const uint8_t (&curve_secret_key_)[crypto_box_SECRETKEYBYTES],
      const uint8_t (&curve_server_key_)[crypto_box_PUBLICKEYBYTES])
    {
        int rc;
        memcpy (public_key, curve_public_key_, crypto_box_PUBLICKEYBYTES);
        memcpy (secret_key, curve_secret_key_, crypto_box_SECRETKEYBYTES);
        memcpy (server_key, curve_server_key_, crypto_box_PUBLICKEYBYTES);

        //  Generate short-term key pair
        memset (cn_secret, 0, crypto_box_SECRETKEYBYTES);
        memset (cn_public, 0, crypto_box_PUBLICKEYBYTES);
        rc = crypto_box_keypair (cn_public, cn_secret);
        zmq_assert (rc == 0);
    }

    int produce_hello (void *data_, const uint64_t cn_nonce_) const
    {
        return produce_hello (data_, server_key, cn_nonce_, cn_public,
                              cn_secret);
    }

    int process_welcome (const uint8_t *msg_data_,
                         size_t msg_size_,
                         uint8_t *cn_precom_)
    {
        return process_welcome (msg_data_, msg_size_, server_key, cn_secret,
                                cn_server, cn_cookie, cn_precom_);
    }

    int produce_initiate (void *data_,
                          size_t size_,
                          const uint64_t cn_nonce_,
                          const uint8_t *metadata_plaintext_,
                          const size_t metadata_length_) const
    {
        return produce_initiate (data_, size_, cn_nonce_, server_key,
                                 public_key, secret_key, cn_public, cn_secret,
                                 cn_server, cn_cookie, metadata_plaintext_,
                                 metadata_length_);
    }

    //  Our public key (C)
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];

    //  Our secret key (c)
    uint8_t secret_key[crypto_box_SECRETKEYBYTES];

    //  Our short-term public key (C')
    uint8_t cn_public[crypto_box_PUBLICKEYBYTES];

    //  Our short-term secret key (c')
    uint8_t cn_secret[crypto_box_SECRETKEYBYTES];

    //  Server's public key (S)
    uint8_t server_key[crypto_box_PUBLICKEYBYTES];

    //  Server's short-term public key (S')
    uint8_t cn_server[crypto_box_PUBLICKEYBYTES];

    //  Cookie received from server
    uint8_t cn_cookie[16 + 80];

  private:
    template <size_t N>
    static bool is_handshake_command (const uint8_t *msg_data_,
                                      const size_t msg_size_,
                                      const char (&prefix_)[N])
    {
        return msg_size_ >= (N - 1) && !memcmp (msg_data_, prefix_, N - 1);
    }
};
}

#endif

#endif
