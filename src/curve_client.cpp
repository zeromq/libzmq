/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

#include "platform.hpp"

#ifdef ZMQ_HAVE_CURVE

#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include "msg.hpp"
#include "session_base.hpp"
#include "err.hpp"
#include "curve_client.hpp"
#include "wire.hpp"

zmq::curve_client_t::curve_client_t (const options_t &options_) :
    mechanism_t (options_),
    state (send_hello),
    cn_nonce(1),
    cn_peer_nonce(1),
    sync()
{
    int rc;
    memcpy (public_key, options_.curve_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy (secret_key, options_.curve_secret_key, crypto_box_SECRETKEYBYTES);
    memcpy (server_key, options_.curve_server_key, crypto_box_PUBLICKEYBYTES);
    scoped_lock_t lock (sync);
#if defined (ZMQ_USE_TWEETNACL)
    // allow opening of /dev/urandom
    unsigned char tmpbytes[4];
    randombytes(tmpbytes, 4);
#else
    rc = sodium_init ();
    zmq_assert (rc != -1);
#endif

    //  Generate short-term key pair
    rc = crypto_box_keypair (cn_public, cn_secret);
    zmq_assert (rc == 0);
}

zmq::curve_client_t::~curve_client_t ()
{
}

int zmq::curve_client_t::next_handshake_command (msg_t *msg_)
{
    int rc = 0;

    switch (state) {
        case send_hello:
            rc = produce_hello (msg_);
            if (rc == 0)
                state = expect_welcome;
            break;
        case send_initiate:
            rc = produce_initiate (msg_);
            if (rc == 0)
                state = expect_ready;
            break;
        default:
            errno = EAGAIN;
            rc = -1;
    }
    return rc;
}

int zmq::curve_client_t::process_handshake_command (msg_t *msg_)
{
    const unsigned char *msg_data =
        static_cast <unsigned char *> (msg_->data ());
    const size_t msg_size = msg_->size ();

    int rc = 0;
    if (msg_size >= 8 && !memcmp (msg_data, "\7WELCOME", 8))
        rc = process_welcome (msg_data, msg_size);
    else
    if (msg_size >= 6 && !memcmp (msg_data, "\5READY", 6))
        rc = process_ready (msg_data, msg_size);
    else
    if (msg_size >= 6 && !memcmp (msg_data, "\5ERROR", 6))
        rc = process_error (msg_data, msg_size);
    else {
        errno = EPROTO;
        rc = -1;
    }

    if (rc == 0) {
        rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
    }

    return rc;
}

int zmq::curve_client_t::encode (msg_t *msg_)
{
    zmq_assert (state == connected);

    uint8_t flags = 0;
    if (msg_->flags () & msg_t::more)
        flags |= 0x01;

    uint8_t message_nonce [crypto_box_NONCEBYTES];
    memcpy (message_nonce, "CurveZMQMESSAGEC", 16);
    put_uint64 (message_nonce + 16, cn_nonce);

    const size_t mlen = crypto_box_ZEROBYTES + 1 + msg_->size ();

    uint8_t *message_plaintext = static_cast <uint8_t *> (malloc (mlen));
    alloc_assert (message_plaintext);

    memset (message_plaintext, 0, crypto_box_ZEROBYTES);
    message_plaintext [crypto_box_ZEROBYTES] = flags;
    memcpy (message_plaintext + crypto_box_ZEROBYTES + 1,
            msg_->data (), msg_->size ());

    uint8_t *message_box = static_cast <uint8_t *> (malloc (mlen));
    alloc_assert (message_box);

    int rc = crypto_box_afternm (message_box, message_plaintext,
                                 mlen, message_nonce, cn_precom);
    zmq_assert (rc == 0);

    rc = msg_->close ();
    zmq_assert (rc == 0);

    rc = msg_->init_size (16 + mlen - crypto_box_BOXZEROBYTES);
    zmq_assert (rc == 0);

    uint8_t *message = static_cast <uint8_t *> (msg_->data ());

    memcpy (message, "\x07MESSAGE", 8);
    memcpy (message + 8, message_nonce + 16, 8);
    memcpy (message + 16, message_box + crypto_box_BOXZEROBYTES,
            mlen - crypto_box_BOXZEROBYTES);

    free (message_plaintext);
    free (message_box);

    cn_nonce++;

    return 0;
}

int zmq::curve_client_t::decode (msg_t *msg_)
{
    zmq_assert (state == connected);

    if (msg_->size () < 33) {
        errno = EPROTO;
        return -1;
    }

    const uint8_t *message = static_cast <uint8_t *> (msg_->data ());
    if (memcmp (message, "\x07MESSAGE", 8)) {
        errno = EPROTO;
        return -1;
    }

    uint8_t message_nonce [crypto_box_NONCEBYTES];
    memcpy (message_nonce, "CurveZMQMESSAGES", 16);
    memcpy (message_nonce + 16, message + 8, 8);
    uint64_t nonce = get_uint64(message + 8);
    if (nonce <= cn_peer_nonce) {
        errno = EPROTO;
        return -1;
    }
    cn_peer_nonce = nonce;

    const size_t clen = crypto_box_BOXZEROBYTES + (msg_->size () - 16);

    uint8_t *message_plaintext = static_cast <uint8_t *> (malloc (clen));
    alloc_assert (message_plaintext);

    uint8_t *message_box = static_cast <uint8_t *> (malloc (clen));
    alloc_assert (message_box);

    memset (message_box, 0, crypto_box_BOXZEROBYTES);
    memcpy (message_box + crypto_box_BOXZEROBYTES,
            message + 16, msg_->size () - 16);

    int rc = crypto_box_open_afternm (message_plaintext, message_box,
                                      clen, message_nonce, cn_precom);
    if (rc == 0) {
        rc = msg_->close ();
        zmq_assert (rc == 0);

        rc = msg_->init_size (clen - 1 - crypto_box_ZEROBYTES);
        zmq_assert (rc == 0);

        const uint8_t flags = message_plaintext [crypto_box_ZEROBYTES];
        if (flags & 0x01)
            msg_->set_flags (msg_t::more);

        memcpy (msg_->data (),
                message_plaintext + crypto_box_ZEROBYTES + 1,
                msg_->size ());
    }
    else
        errno = EPROTO;

    free (message_plaintext);
    free (message_box);

    return rc;
}

zmq::mechanism_t::status_t zmq::curve_client_t::status () const
{
    if (state == connected)
        return mechanism_t::ready;
    else
    if (state == error_received)
        return mechanism_t::error;
    else
        return mechanism_t::handshaking;
}

int zmq::curve_client_t::produce_hello (msg_t *msg_)
{
    uint8_t hello_nonce [crypto_box_NONCEBYTES];
    uint8_t hello_plaintext [crypto_box_ZEROBYTES + 64];
    uint8_t hello_box [crypto_box_BOXZEROBYTES + 80];

    //  Prepare the full nonce
    memcpy (hello_nonce, "CurveZMQHELLO---", 16);
    put_uint64 (hello_nonce + 16, cn_nonce);

    //  Create Box [64 * %x0](C'->S)
    memset (hello_plaintext, 0, sizeof hello_plaintext);

    int rc = crypto_box (hello_box, hello_plaintext,
                         sizeof hello_plaintext,
                         hello_nonce, server_key, cn_secret);
    if (rc == -1)
        return -1;

    rc = msg_->init_size (200);
    errno_assert (rc == 0);
    uint8_t *hello = static_cast <uint8_t *> (msg_->data ());

    memcpy (hello, "\x05HELLO", 6);
    //  CurveZMQ major and minor version numbers
    memcpy (hello + 6, "\1\0", 2);
    //  Anti-amplification padding
    memset (hello + 8, 0, 72);
    //  Client public connection key
    memcpy (hello + 80, cn_public, crypto_box_PUBLICKEYBYTES);
    //  Short nonce, prefixed by "CurveZMQHELLO---"
    memcpy (hello + 112, hello_nonce + 16, 8);
    //  Signature, Box [64 * %x0](C'->S)
    memcpy (hello + 120, hello_box + crypto_box_BOXZEROBYTES, 80);

    cn_nonce++;

    return 0;
}

int zmq::curve_client_t::process_welcome (
        const uint8_t *msg_data, size_t msg_size)
{
    if (msg_size != 168) {
        errno = EPROTO;
        return -1;
    }

    uint8_t welcome_nonce [crypto_box_NONCEBYTES];
    uint8_t welcome_plaintext [crypto_box_ZEROBYTES + 128];
    uint8_t welcome_box [crypto_box_BOXZEROBYTES + 144];

    //  Open Box [S' + cookie](C'->S)
    memset (welcome_box, 0, crypto_box_BOXZEROBYTES);
    memcpy (welcome_box + crypto_box_BOXZEROBYTES, msg_data + 24, 144);

    memcpy (welcome_nonce, "WELCOME-", 8);
    memcpy (welcome_nonce + 8, msg_data + 8, 16);

    int rc = crypto_box_open (welcome_plaintext, welcome_box,
                              sizeof welcome_box,
                              welcome_nonce, server_key, cn_secret);
    if (rc != 0) {
        errno = EPROTO;
        return -1;
    }

    memcpy (cn_server, welcome_plaintext + crypto_box_ZEROBYTES, 32);
    memcpy (cn_cookie, welcome_plaintext + crypto_box_ZEROBYTES + 32, 16 + 80);

    //  Message independent precomputation
    rc = crypto_box_beforenm (cn_precom, cn_server, cn_secret);
    zmq_assert (rc == 0);

    state = send_initiate;

    return 0;
}

int zmq::curve_client_t::produce_initiate (msg_t *msg_)
{
    uint8_t vouch_nonce [crypto_box_NONCEBYTES];
    uint8_t vouch_plaintext [crypto_box_ZEROBYTES + 64];
    uint8_t vouch_box [crypto_box_BOXZEROBYTES + 80];

    //  Create vouch = Box [C',S](C->S')
    memset (vouch_plaintext, 0, crypto_box_ZEROBYTES);
    memcpy (vouch_plaintext + crypto_box_ZEROBYTES, cn_public, 32);
    memcpy (vouch_plaintext + crypto_box_ZEROBYTES + 32, server_key, 32);

    memcpy (vouch_nonce, "VOUCH---", 8);
    randombytes (vouch_nonce + 8, 16);

    int rc = crypto_box (vouch_box, vouch_plaintext,
                         sizeof vouch_plaintext,
                         vouch_nonce, cn_server, secret_key);
    if (rc == -1)
        return -1;

    //  Assume here that metadata is limited to 256 bytes
    uint8_t initiate_nonce [crypto_box_NONCEBYTES];
    uint8_t initiate_plaintext [crypto_box_ZEROBYTES + 128 + 256];
    uint8_t initiate_box [crypto_box_BOXZEROBYTES + 144 + 256];

    //  Create Box [C + vouch + metadata](C'->S')
    memset (initiate_plaintext, 0, crypto_box_ZEROBYTES);
    memcpy (initiate_plaintext + crypto_box_ZEROBYTES,
            public_key, 32);
    memcpy (initiate_plaintext + crypto_box_ZEROBYTES + 32,
            vouch_nonce + 8, 16);
    memcpy (initiate_plaintext + crypto_box_ZEROBYTES + 48,
            vouch_box + crypto_box_BOXZEROBYTES, 80);

    //  Metadata starts after vouch
    uint8_t *ptr = initiate_plaintext + crypto_box_ZEROBYTES + 128;

    //  Add socket type property
    const char *socket_type = socket_type_string (options.type);
    ptr += add_property (ptr, "Socket-Type", socket_type, strlen (socket_type));

    //  Add identity property
    if (options.type == ZMQ_REQ
    ||  options.type == ZMQ_DEALER
    ||  options.type == ZMQ_ROUTER)
        ptr += add_property (ptr, "Identity", options.identity, options.identity_size);

    const size_t mlen = ptr - initiate_plaintext;

    memcpy (initiate_nonce, "CurveZMQINITIATE", 16);
    put_uint64 (initiate_nonce + 16, cn_nonce);

    rc = crypto_box (initiate_box, initiate_plaintext,
                     mlen, initiate_nonce, cn_server, cn_secret);
    if (rc == -1)
        return -1;

    rc = msg_->init_size (113 + mlen - crypto_box_BOXZEROBYTES);
    errno_assert (rc == 0);

    uint8_t *initiate = static_cast <uint8_t *> (msg_->data ());

    memcpy (initiate, "\x08INITIATE", 9);
    //  Cookie provided by the server in the WELCOME command
    memcpy (initiate + 9, cn_cookie, 96);
    //  Short nonce, prefixed by "CurveZMQINITIATE"
    memcpy (initiate + 105, initiate_nonce + 16, 8);
    //  Box [C + vouch + metadata](C'->S')
    memcpy (initiate + 113, initiate_box + crypto_box_BOXZEROBYTES,
            mlen - crypto_box_BOXZEROBYTES);
    cn_nonce++;

    return 0;
}

int zmq::curve_client_t::process_ready (
        const uint8_t *msg_data, size_t msg_size)
{
    if (msg_size < 30) {
        errno = EPROTO;
        return -1;
    }

    const size_t clen = (msg_size - 14) + crypto_box_BOXZEROBYTES;

    uint8_t ready_nonce [crypto_box_NONCEBYTES];
    uint8_t ready_plaintext [crypto_box_ZEROBYTES + 256];
    uint8_t ready_box [crypto_box_BOXZEROBYTES + 16 + 256];

    memset (ready_box, 0, crypto_box_BOXZEROBYTES);
    memcpy (ready_box + crypto_box_BOXZEROBYTES,
            msg_data + 14, clen - crypto_box_BOXZEROBYTES);

    memcpy (ready_nonce, "CurveZMQREADY---", 16);
    memcpy (ready_nonce + 16, msg_data + 6, 8);
    cn_peer_nonce = get_uint64(msg_data + 6);

    int rc = crypto_box_open_afternm (ready_plaintext, ready_box,
                                      clen, ready_nonce, cn_precom);

    if (rc != 0) {
        errno = EPROTO;
        return -1;
    }

    rc = parse_metadata (ready_plaintext + crypto_box_ZEROBYTES,
                         clen - crypto_box_ZEROBYTES);
    if (rc == 0)
        state = connected;

    return rc;
}

int zmq::curve_client_t::process_error (
        const uint8_t *msg_data, size_t msg_size)
{
    if (state != expect_welcome && state != expect_ready) {
        errno = EPROTO;
        return -1;
    }
    if (msg_size < 7) {
        errno = EPROTO;
        return -1;
    }
    const size_t error_reason_len = static_cast <size_t> (msg_data [6]);
    if (error_reason_len > msg_size - 7) {
        errno = EPROTO;
        return -1;
    }
    state = error_received;
    return 0;
}

#endif
