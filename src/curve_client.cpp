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

#include "precompiled.hpp"
#include "macros.hpp"

#ifdef ZMQ_HAVE_CURVE

#include "msg.hpp"
#include "session_base.hpp"
#include "err.hpp"
#include "curve_client.hpp"
#include "wire.hpp"
#include "curve_client_tools.hpp"

zmq::curve_client_t::curve_client_t (const options_t &options_) :
    mechanism_t (options_),
    state (send_hello),
    tools (options_.curve_public_key,
           options_.curve_secret_key,
           options_.curve_server_key),
    cn_nonce (1),
    cn_peer_nonce (1)
{
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
    if (curve_client_tools_t::is_handshake_command_welcome (msg_data, msg_size))
        rc = process_welcome (msg_data, msg_size);
    else if (curve_client_tools_t::is_handshake_command_ready (msg_data,
                                                               msg_size))
        rc = process_ready (msg_data, msg_size);
    else if (curve_client_tools_t::is_handshake_command_error (msg_data,
                                                               msg_size))
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
    if (msg_->flags () & msg_t::command)
        flags |= 0x02;

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

    int rc = crypto_box_afternm (message_box, message_plaintext, mlen,
                                 message_nonce, tools.cn_precom);
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

    int rc = crypto_box_open_afternm (message_plaintext, message_box, clen,
                                      message_nonce, tools.cn_precom);
    if (rc == 0) {
        rc = msg_->close ();
        zmq_assert (rc == 0);

        rc = msg_->init_size (clen - 1 - crypto_box_ZEROBYTES);
        zmq_assert (rc == 0);

        const uint8_t flags = message_plaintext [crypto_box_ZEROBYTES];
        if (flags & 0x01)
            msg_->set_flags (msg_t::more);
        if (flags & 0x02)
            msg_->set_flags (msg_t::command);

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
    int rc = msg_->init_size (200);
    errno_assert (rc == 0);

    rc = tools.produce_hello (msg_->data (), cn_nonce);
    if (rc == -1) {
        // TODO this is somewhat inconsistent: we call init_size, but we may 
        // not close msg_; i.e. we assume that msg_ is initialized but empty 
        // (if it were non-empty, calling init_size might cause a leak!)

        // msg_->close ();
        return -1;
    }

    cn_nonce++;

    return 0;
}

int zmq::curve_client_t::process_welcome (const uint8_t *msg_data,
                                          size_t msg_size)
{
    int rc = tools.process_welcome (msg_data, msg_size);

    if (rc == -1) {
        errno = EPROTO;
        return -1;
    }

    state = send_initiate;

    return 0;
}

int zmq::curve_client_t::produce_initiate (msg_t *msg_)
{
    //  Assume here that metadata is limited to 256 bytes
    //  FIXME see https://github.com/zeromq/libzmq/issues/2681
    uint8_t metadata_plaintext [256];

    //  Metadata starts after vouch
    uint8_t *ptr = metadata_plaintext;

    //  Add socket type property
    const char *socket_type = socket_type_string (options.type);
    ptr += add_property (ptr, 256, ZMQ_MSG_PROPERTY_SOCKET_TYPE, socket_type,
                         strlen (socket_type));

    //  Add identity property
    if (options.type == ZMQ_REQ || options.type == ZMQ_DEALER
        || options.type == ZMQ_ROUTER)
        ptr += add_property (ptr, 256 - (ptr - metadata_plaintext),
                             ZMQ_MSG_PROPERTY_IDENTITY, options.identity,
                             options.identity_size);

    const size_t metadata_length = ptr - metadata_plaintext;

    size_t msg_size = 113 + 128 + crypto_box_BOXZEROBYTES + metadata_length;
    int rc = msg_->init_size (msg_size);
    errno_assert (rc == 0);

    if (-1
        == tools.produce_initiate (msg_->data (), msg_size, cn_nonce,
                                   metadata_plaintext, metadata_length)) {
        // TODO see comment in produce_hello
        return -1;
    }

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
                                      clen, ready_nonce, tools.cn_precom);

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
