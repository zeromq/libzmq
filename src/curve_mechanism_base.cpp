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
#include "curve_mechanism_base.hpp"
#include "msg.hpp"
#include "wire.hpp"
#include "session_base.hpp"

#ifdef ZMQ_HAVE_CURVE

zmq::curve_mechanism_base_t::curve_mechanism_base_t (
  session_base_t *session_,
  const options_t &options_,
  const char *encode_nonce_prefix_,
  const char *decode_nonce_prefix_) :
    mechanism_base_t (session_, options_),
    encode_nonce_prefix (encode_nonce_prefix_),
    decode_nonce_prefix (decode_nonce_prefix_),
    cn_nonce (1),
    cn_peer_nonce (1)
{
}

int zmq::curve_mechanism_base_t::encode (msg_t *msg_)
{
    const size_t mlen = crypto_box_ZEROBYTES + 1 + msg_->size ();

    uint8_t message_nonce[crypto_box_NONCEBYTES];
    memcpy (message_nonce, encode_nonce_prefix, 16);
    put_uint64 (message_nonce + 16, cn_nonce);

    uint8_t flags = 0;
    if (msg_->flags () & msg_t::more)
        flags |= 0x01;
    if (msg_->flags () & msg_t::command)
        flags |= 0x02;

    uint8_t *message_plaintext = static_cast<uint8_t *> (malloc (mlen));
    alloc_assert (message_plaintext);

    memset (message_plaintext, 0, crypto_box_ZEROBYTES);
    message_plaintext[crypto_box_ZEROBYTES] = flags;
    memcpy (message_plaintext + crypto_box_ZEROBYTES + 1, msg_->data (),
            msg_->size ());

    uint8_t *message_box = static_cast<uint8_t *> (malloc (mlen));
    alloc_assert (message_box);

    int rc = crypto_box_afternm (message_box, message_plaintext, mlen,
                                 message_nonce, cn_precom);
    zmq_assert (rc == 0);

    rc = msg_->close ();
    zmq_assert (rc == 0);

    rc = msg_->init_size (16 + mlen - crypto_box_BOXZEROBYTES);
    zmq_assert (rc == 0);

    uint8_t *message = static_cast<uint8_t *> (msg_->data ());

    memcpy (message, "\x07MESSAGE", 8);
    memcpy (message + 8, message_nonce + 16, 8);
    memcpy (message + 16, message_box + crypto_box_BOXZEROBYTES,
            mlen - crypto_box_BOXZEROBYTES);

    free (message_plaintext);
    free (message_box);

    cn_nonce++;

    return 0;
}

int zmq::curve_mechanism_base_t::decode (msg_t *msg_)
{
    int rc = check_basic_command_structure (msg_);
    if (rc == -1)
        return -1;

    const size_t size = msg_->size ();
    const uint8_t *message = static_cast<uint8_t *> (msg_->data ());

    if (size < 8 || memcmp (message, "\x07MESSAGE", 8)) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        return -1;
    }

    if (size < 33) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE);
        errno = EPROTO;
        return -1;
    }

    uint8_t message_nonce[crypto_box_NONCEBYTES];
    memcpy (message_nonce, decode_nonce_prefix, 16);
    memcpy (message_nonce + 16, message + 8, 8);
    uint64_t nonce = get_uint64 (message + 8);
    if (nonce <= cn_peer_nonce) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_SEQUENCE);
        errno = EPROTO;
        return -1;
    }
    cn_peer_nonce = nonce;

    const size_t clen = crypto_box_BOXZEROBYTES + msg_->size () - 16;

    uint8_t *message_plaintext = static_cast<uint8_t *> (malloc (clen));
    alloc_assert (message_plaintext);

    uint8_t *message_box = static_cast<uint8_t *> (malloc (clen));
    alloc_assert (message_box);

    memset (message_box, 0, crypto_box_BOXZEROBYTES);
    memcpy (message_box + crypto_box_BOXZEROBYTES, message + 16,
            msg_->size () - 16);

    rc = crypto_box_open_afternm (message_plaintext, message_box, clen,
                                  message_nonce, cn_precom);
    if (rc == 0) {
        rc = msg_->close ();
        zmq_assert (rc == 0);

        rc = msg_->init_size (clen - 1 - crypto_box_ZEROBYTES);
        zmq_assert (rc == 0);

        const uint8_t flags = message_plaintext[crypto_box_ZEROBYTES];
        if (flags & 0x01)
            msg_->set_flags (msg_t::more);
        if (flags & 0x02)
            msg_->set_flags (msg_t::command);

        memcpy (msg_->data (), message_plaintext + crypto_box_ZEROBYTES + 1,
                msg_->size ());
    } else {
        // CURVE I : connection key used for MESSAGE is wrong
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);
        errno = EPROTO;
    }
    free (message_plaintext);
    free (message_box);

    return rc;
}

#endif
