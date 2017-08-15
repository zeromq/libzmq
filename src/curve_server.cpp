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
#include "curve_server.hpp"
#include "wire.hpp"

zmq::curve_server_t::curve_server_t (session_base_t *session_,
                                     const std::string &peer_address_,
                                     const options_t &options_) :
    mechanism_t (options_),
    session (session_),
    peer_address (peer_address_),
    state (expect_hello),
    current_error_detail (no_detail),
    cn_nonce (1),
    cn_peer_nonce(1)
{
    int rc;
    //  Fetch our secret key from socket options
    memcpy (secret_key, options_.curve_secret_key, crypto_box_SECRETKEYBYTES);

    //  Generate short-term key pair
    rc = crypto_box_keypair (cn_public, cn_secret);
    zmq_assert (rc == 0);
}

zmq::curve_server_t::~curve_server_t ()
{
}

int zmq::curve_server_t::next_handshake_command (msg_t *msg_)
{
    int rc = 0;

    switch (state) {
        case send_welcome:
            rc = produce_welcome (msg_);
            if (rc == 0)
                state = expect_initiate;
            break;
        case send_ready:
            rc = produce_ready (msg_);
            if (rc == 0)
                state = connected;
            break;
        case send_error:
            rc = produce_error (msg_);
            if (rc == 0)
                state = error_sent;
            break;
        default:
            errno = EAGAIN;
            rc = -1;
            break;
    }
    return rc;
}

int zmq::curve_server_t::process_handshake_command (msg_t *msg_)
{
    int rc = 0;

    switch (state) {
        case expect_hello:
            rc = process_hello (msg_);
            break;
        case expect_initiate:
            rc = process_initiate (msg_);
            break;
        default:
            // TODO I think this is not a case reachable with a misbehaving 
            // client. It is not an "invalid handshake command", but would be 
            // trying to process a handshake command in an invalid state, 
            // which is purely under control of this peer. 
            // Therefore, it should be changed to zmq_assert (false);

            // CURVE I: invalid handshake command
            current_error_detail = zmtp;
            errno = EPROTO;
            rc = -1;
            break;
    }
    if (rc == 0) {
        rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
    }
    return rc;
}

int zmq::curve_server_t::encode (msg_t *msg_)
{
    zmq_assert (state == connected);

    const size_t mlen = crypto_box_ZEROBYTES + 1 + msg_->size ();

    uint8_t message_nonce [crypto_box_NONCEBYTES];
    memcpy (message_nonce, "CurveZMQMESSAGES", 16);
    put_uint64 (message_nonce + 16, cn_nonce);

    uint8_t flags = 0;
    if (msg_->flags () & msg_t::more)
        flags |= 0x01;
    if (msg_->flags () & msg_t::command)
        flags |= 0x02;

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

int zmq::curve_server_t::decode (msg_t *msg_)
{
    zmq_assert (state == connected);

    if (msg_->size () < 33) {
        // CURVE I : invalid CURVE client, sent malformed command
        current_error_detail = zmtp;
        errno = EPROTO;
        return -1;
    }

    const uint8_t *message = static_cast <uint8_t *> (msg_->data ());
    if (memcmp (message, "\x07MESSAGE", 8)) {
        // CURVE I: invalid CURVE client, did not send MESSAGE
        current_error_detail = zmtp;
        errno = EPROTO;
        return -1;
    }

    uint8_t message_nonce [crypto_box_NONCEBYTES];
    memcpy (message_nonce, "CurveZMQMESSAGEC", 16);
    memcpy (message_nonce + 16, message + 8, 8);
    uint64_t nonce = get_uint64(message + 8);
    if (nonce <= cn_peer_nonce) {
        errno = EPROTO;
        return -1;
    }
    cn_peer_nonce = nonce;

    const size_t clen = crypto_box_BOXZEROBYTES + msg_->size () - 16;

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
        if (flags & 0x02)
            msg_->set_flags (msg_t::command);

        memcpy (msg_->data (),
                message_plaintext + crypto_box_ZEROBYTES + 1,
                msg_->size ());
    }
    else {
        // CURVE I : connection key used for MESSAGE is wrong
        current_error_detail = encryption;
        errno = EPROTO;
    }
    free (message_plaintext);
    free (message_box);

    return rc;
}

int zmq::curve_server_t::zap_msg_available ()
{
    //  TODO I don't think that it is possible that this is called in any 
    //  state other than expect_zap_reply. It should be changed to
    //  zmq_assert (state == expect_zap_reply);
    if (state != expect_zap_reply) {
        errno = EFSM;
        return -1;
    }
    const int rc = receive_and_process_zap_reply ();
    if (rc == 0)
        handle_zap_status_code ();
    return rc;
}

zmq::mechanism_t::status_t zmq::curve_server_t::status () const
{
    if (state == connected)
        return mechanism_t::ready;
    else
    if (state == error_sent)
        return mechanism_t::error;
    else
        return mechanism_t::handshaking;
}

zmq::mechanism_t::error_detail_t zmq::curve_server_t::error_detail() const
{
    return current_error_detail;
}

int zmq::curve_server_t::process_hello (msg_t *msg_)
{
    if (msg_->size () != 200) {
        // CURVE I: client HELLO is not correct size
        current_error_detail = zmtp;
        errno = EPROTO;
        return -1;
    }

    const uint8_t * const hello = static_cast <uint8_t *> (msg_->data ());
    if (memcmp (hello, "\x05HELLO", 6)) {
        // CURVE I: client HELLO has invalid command name
        current_error_detail = zmtp;
        errno = EPROTO;
        return -1;
    }

    const uint8_t major = hello [6];
    const uint8_t minor = hello [7];

    if (major != 1 || minor != 0) {
        // CURVE I: client HELLO has unknown version number
        current_error_detail = zmtp;
        errno = EPROTO;
        return -1;
    }

    //  Save client's short-term public key (C')
    memcpy (cn_client, hello + 80, 32);

    uint8_t hello_nonce [crypto_box_NONCEBYTES];
    uint8_t hello_plaintext [crypto_box_ZEROBYTES + 64];
    uint8_t hello_box [crypto_box_BOXZEROBYTES + 80];

    memcpy (hello_nonce, "CurveZMQHELLO---", 16);
    memcpy (hello_nonce + 16, hello + 112, 8);
    cn_peer_nonce = get_uint64(hello + 112);

    memset (hello_box, 0, crypto_box_BOXZEROBYTES);
    memcpy (hello_box + crypto_box_BOXZEROBYTES, hello + 120, 80);

    //  Open Box [64 * %x0](C'->S)
    int rc = crypto_box_open (hello_plaintext, hello_box,
                              sizeof hello_box,
                              hello_nonce, cn_client, secret_key);
    if (rc != 0) {
        // CURVE I: cannot open client HELLO -- wrong server key?
        current_error_detail = encryption;
        errno = EPROTO;
        return -1;
    }

    state = send_welcome;
    return rc;
}

int zmq::curve_server_t::produce_welcome (msg_t *msg_)
{
    uint8_t cookie_nonce [crypto_secretbox_NONCEBYTES];
    uint8_t cookie_plaintext [crypto_secretbox_ZEROBYTES + 64];
    uint8_t cookie_ciphertext [crypto_secretbox_BOXZEROBYTES + 80];

    //  Create full nonce for encryption
    //  8-byte prefix plus 16-byte random nonce
    memcpy (cookie_nonce, "COOKIE--", 8);
    randombytes (cookie_nonce + 8, 16);

    //  Generate cookie = Box [C' + s'](t)
    memset (cookie_plaintext, 0, crypto_secretbox_ZEROBYTES);
    memcpy (cookie_plaintext + crypto_secretbox_ZEROBYTES,
            cn_client, 32);
    memcpy (cookie_plaintext + crypto_secretbox_ZEROBYTES + 32,
            cn_secret, 32);

    //  Generate fresh cookie key
    randombytes (cookie_key, crypto_secretbox_KEYBYTES);

    //  Encrypt using symmetric cookie key
    int rc = crypto_secretbox (cookie_ciphertext, cookie_plaintext,
                               sizeof cookie_plaintext,
                               cookie_nonce, cookie_key);
    zmq_assert (rc == 0);

    uint8_t welcome_nonce [crypto_box_NONCEBYTES];
    uint8_t welcome_plaintext [crypto_box_ZEROBYTES + 128];
    uint8_t welcome_ciphertext [crypto_box_BOXZEROBYTES + 144];

    //  Create full nonce for encryption
    //  8-byte prefix plus 16-byte random nonce
    memcpy (welcome_nonce, "WELCOME-", 8);
    randombytes (welcome_nonce + 8, crypto_box_NONCEBYTES - 8);

    //  Create 144-byte Box [S' + cookie](S->C')
    memset (welcome_plaintext, 0, crypto_box_ZEROBYTES);
    memcpy (welcome_plaintext + crypto_box_ZEROBYTES, cn_public, 32);
    memcpy (welcome_plaintext + crypto_box_ZEROBYTES + 32,
            cookie_nonce + 8, 16);
    memcpy (welcome_plaintext + crypto_box_ZEROBYTES + 48,
            cookie_ciphertext + crypto_secretbox_BOXZEROBYTES, 80);

    rc = crypto_box (welcome_ciphertext, welcome_plaintext,
                     sizeof welcome_plaintext,
                     welcome_nonce, cn_client, secret_key);

    //  TODO I think we should change this back to zmq_assert (rc == 0);
    //  as it was before https://github.com/zeromq/libzmq/pull/1832
    //  The reason given there was that secret_key might be 0ed.
    //  But if it were, we would never get this far, since we could
    //  not have opened the client's hello box with a 0ed key.

    if (rc == -1)
        return -1;

    rc = msg_->init_size (168);
    errno_assert (rc == 0);

    uint8_t * const welcome = static_cast <uint8_t *> (msg_->data ());
    memcpy (welcome, "\x07WELCOME", 8);
    memcpy (welcome + 8, welcome_nonce + 8, 16);
    memcpy (welcome + 24, welcome_ciphertext + crypto_box_BOXZEROBYTES, 144);

    return 0;
}

int zmq::curve_server_t::process_initiate (msg_t *msg_)
{
    if (msg_->size () < 257) {
        // CURVE I: client INITIATE is not correct size
        current_error_detail = zmtp;
        errno = EPROTO;
        return -1;
    }

    const uint8_t *initiate = static_cast <uint8_t *> (msg_->data ());
    if (memcmp (initiate, "\x08INITIATE", 9)) {
        // CURVE I: client INITIATE has invalid command name
        current_error_detail = zmtp;
        errno = EPROTO;
        return -1;
    }

    uint8_t cookie_nonce [crypto_secretbox_NONCEBYTES];
    uint8_t cookie_plaintext [crypto_secretbox_ZEROBYTES + 64];
    uint8_t cookie_box [crypto_secretbox_BOXZEROBYTES + 80];

    //  Open Box [C' + s'](t)
    memset (cookie_box, 0, crypto_secretbox_BOXZEROBYTES);
    memcpy (cookie_box + crypto_secretbox_BOXZEROBYTES, initiate + 25, 80);

    memcpy (cookie_nonce, "COOKIE--", 8);
    memcpy (cookie_nonce + 8, initiate + 9, 16);

    int rc = crypto_secretbox_open (cookie_plaintext, cookie_box,
                                    sizeof cookie_box,
                                    cookie_nonce, cookie_key);
    if (rc != 0) {
        // CURVE I: cannot open client INITIATE cookie
        current_error_detail = encryption;
        errno = EPROTO;
        return -1;
    }

    //  Check cookie plain text is as expected [C' + s']
    if (memcmp (cookie_plaintext + crypto_secretbox_ZEROBYTES, cn_client, 32)
    ||  memcmp (cookie_plaintext + crypto_secretbox_ZEROBYTES + 32, cn_secret, 32)) {
        // TODO this case is very hard to test, as it would require a modified
        //  client that knows the server's secret temporary cookie key

        // CURVE I: client INITIATE cookie is not valid
        current_error_detail = encryption;
        errno = EPROTO;
        return -1;
    }

    const size_t clen = (msg_->size () - 113) + crypto_box_BOXZEROBYTES;

    uint8_t initiate_nonce [crypto_box_NONCEBYTES];
    uint8_t initiate_plaintext [crypto_box_ZEROBYTES + 128 + 256];
    uint8_t initiate_box [crypto_box_BOXZEROBYTES + 144 + 256];

    //  Open Box [C + vouch + metadata](C'->S')
    memset (initiate_box, 0, crypto_box_BOXZEROBYTES);
    memcpy (initiate_box + crypto_box_BOXZEROBYTES,
            initiate + 113, clen - crypto_box_BOXZEROBYTES);

    memcpy (initiate_nonce, "CurveZMQINITIATE", 16);
    memcpy (initiate_nonce + 16, initiate + 105, 8);
    cn_peer_nonce = get_uint64(initiate + 105);

    rc = crypto_box_open (initiate_plaintext, initiate_box,
                          clen, initiate_nonce, cn_client, cn_secret);
    if (rc != 0) {
        // CURVE I: cannot open client INITIATE
        current_error_detail = encryption;
        errno = EPROTO;
        return -1;
    }

    const uint8_t *client_key = initiate_plaintext + crypto_box_ZEROBYTES;

    uint8_t vouch_nonce [crypto_box_NONCEBYTES];
    uint8_t vouch_plaintext [crypto_box_ZEROBYTES + 64];
    uint8_t vouch_box [crypto_box_BOXZEROBYTES + 80];

    //  Open Box Box [C',S](C->S') and check contents
    memset (vouch_box, 0, crypto_box_BOXZEROBYTES);
    memcpy (vouch_box + crypto_box_BOXZEROBYTES,
            initiate_plaintext + crypto_box_ZEROBYTES + 48, 80);

    memcpy (vouch_nonce, "VOUCH---", 8);
    memcpy (vouch_nonce + 8,
            initiate_plaintext + crypto_box_ZEROBYTES + 32, 16);

    rc = crypto_box_open (vouch_plaintext, vouch_box,
                          sizeof vouch_box,
                          vouch_nonce, client_key, cn_secret);
    if (rc != 0) {
        // CURVE I: cannot open client INITIATE vouch
        current_error_detail = encryption;
        errno = EPROTO;
        return -1;
    }

    //  What we decrypted must be the client's short-term public key
    if (memcmp (vouch_plaintext + crypto_box_ZEROBYTES, cn_client, 32)) {
        // TODO this case is very hard to test, as it would require a modified
        //  client that knows the server's secret short-term key

        // CURVE I: invalid handshake from client (public key)
        current_error_detail = encryption;
        errno = EPROTO;
        return -1;
    }

    //  Precompute connection secret from client key
    rc = crypto_box_beforenm (cn_precom, cn_client, cn_secret);
    zmq_assert (rc == 0);

    //  Use ZAP protocol (RFC 27) to authenticate the user.
    //  Note that rc will be -1 only if ZAP is not set up (Stonehouse pattern -
    //  encryption without authentication), but if it was requested and it does
    //  not work properly the program will abort.
    rc = session->zap_connect ();
    if (rc == 0) {
        rc = send_zap_request (client_key);
        if (rc != 0)
            return -1;
        rc = receive_and_process_zap_reply ();
        if (rc == 0)
            handle_zap_status_code ();
        else
        if (errno == EAGAIN)
            state = expect_zap_reply;
        else
            return -1;
    }
    else
        state = send_ready;

    return parse_metadata (initiate_plaintext + crypto_box_ZEROBYTES + 128,
                           clen - crypto_box_ZEROBYTES - 128);
}

int zmq::curve_server_t::produce_ready (msg_t *msg_)
{
    const size_t metadata_length = basic_properties_len ();
    uint8_t ready_nonce [crypto_box_NONCEBYTES];

    uint8_t *ready_plaintext =
      (uint8_t *) malloc (crypto_box_ZEROBYTES + metadata_length);
    alloc_assert (ready_plaintext);

    //  Create Box [metadata](S'->C')
    memset (ready_plaintext, 0, crypto_box_ZEROBYTES);
    uint8_t *ptr = ready_plaintext + crypto_box_ZEROBYTES;

    ptr += add_basic_properties (ptr, metadata_length);
    const size_t mlen = ptr - ready_plaintext;

    memcpy (ready_nonce, "CurveZMQREADY---", 16);
    put_uint64 (ready_nonce + 16, cn_nonce);

    uint8_t *ready_box =
      (uint8_t *) malloc (crypto_box_BOXZEROBYTES + 16 + metadata_length);
    alloc_assert (ready_box);

    int rc = crypto_box_afternm (ready_box, ready_plaintext, mlen, ready_nonce,
                                 cn_precom);
    zmq_assert (rc == 0);

    free (ready_plaintext);

    rc = msg_->init_size (14 + mlen - crypto_box_BOXZEROBYTES);
    errno_assert (rc == 0);

    uint8_t *ready = static_cast <uint8_t *> (msg_->data ());

    memcpy (ready, "\x05READY", 6);
    //  Short nonce, prefixed by "CurveZMQREADY---"
    memcpy (ready + 6, ready_nonce + 16, 8);
    //  Box [metadata](S'->C')
    memcpy (ready + 14, ready_box + crypto_box_BOXZEROBYTES,
            mlen - crypto_box_BOXZEROBYTES);
    free (ready_box);

    cn_nonce++;

    return 0;
}

int zmq::curve_server_t::produce_error (msg_t *msg_) const
{
    const size_t expected_status_code_length = 3;
    zmq_assert (status_code.length () == 3);
    const int rc = msg_->init_size (6 + 1 + expected_status_code_length);
    zmq_assert (rc == 0);
    char *msg_data = static_cast <char *> (msg_->data ());
    memcpy (msg_data, "\5ERROR", 6);
    msg_data [6] = expected_status_code_length;
    memcpy (msg_data + 7, status_code.c_str (), expected_status_code_length);
    return 0;
}

int zmq::curve_server_t::send_zap_request (const uint8_t *key)
{
    // TODO  I don't think the rc can be -1 anywhere below.
    // It might only be -1 if the HWM was exceeded, but on the ZAP socket, 
    // the HWM is disabled. They should be changed to zmq_assert (rc == 0);
    // The method's return type can be changed to void then.

    int rc;
    msg_t msg;

    //  Address delimiter frame
    rc = msg.init ();
    errno_assert (rc == 0);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Version frame
    rc = msg.init_size (3);
    errno_assert (rc == 0);
    memcpy (msg.data (), "1.0", 3);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Request ID frame
    rc = msg.init_size (1);
    errno_assert (rc == 0);
    memcpy (msg.data (), "1", 1);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Domain frame
    rc = msg.init_size (options.zap_domain.length ());
    errno_assert (rc == 0);
    memcpy (msg.data (), options.zap_domain.c_str (), options.zap_domain.length ());
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Address frame
    rc = msg.init_size (peer_address.length ());
    errno_assert (rc == 0);
    memcpy (msg.data (), peer_address.c_str (), peer_address.length ());
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Identity frame
    rc = msg.init_size (options.identity_size);
    errno_assert (rc == 0);
    memcpy (msg.data (), options.identity, options.identity_size);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Mechanism frame
    rc = msg.init_size (5);
    errno_assert (rc == 0);
    memcpy (msg.data (), "CURVE", 5);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Credentials frame
    rc = msg.init_size (crypto_box_PUBLICKEYBYTES);
    errno_assert (rc == 0);
    memcpy (msg.data (), key, crypto_box_PUBLICKEYBYTES);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    return 0;
}

int zmq::curve_server_t::receive_and_process_zap_reply ()
{
    int rc = 0;
    msg_t msg [7];  //  ZAP reply consists of 7 frames

    //  Initialize all reply frames
    for (int i = 0; i < 7; i++) {
        rc = msg [i].init ();
        errno_assert (rc == 0);
    }

    for (int i = 0; i < 7; i++) {
        rc = session->read_zap_msg (&msg [i]);
        if (rc == -1)
            return close_and_return (msg, -1);
        if ((msg [i].flags () & msg_t::more) == (i < 6? 0: msg_t::more)) {
            // CURVE I : ZAP handler sent incomplete reply message
            current_error_detail = zap;
            errno = EPROTO;
            return close_and_return (msg, -1);
        }
    }

    //  Address delimiter frame
    if (msg [0].size () > 0) {
        // CURVE I: ZAP handler sent malformed reply message
        current_error_detail = zap;
        errno = EPROTO;
        return close_and_return (msg, -1);
    }

    //  Version frame
    if (msg [1].size () != 3 || memcmp (msg [1].data (), "1.0", 3)) {
        // CURVE I: ZAP handler sent bad version number
        current_error_detail = zap;
        errno = EPROTO;
        return close_and_return (msg, -1);
    }

    //  Request id frame
    if (msg [2].size () != 1 || memcmp (msg [2].data (), "1", 1)) {
        // CURVE I: ZAP handler sent bad request ID
        current_error_detail = zap;
        errno = EPROTO;
        return close_and_return (msg, -1);
    }

    //  Status code frame, only 200, 300, 400 and 500 are valid status codes
    char *status_code_data = static_cast <char*> (msg [3].data());
    if (msg [3].size () != 3 || status_code_data [0] < '2'
          || status_code_data [0] > '5' || status_code_data [1] != '0'
          || status_code_data [2] != '0') {
        // CURVE I: ZAP handler sent invalid status code
        current_error_detail = zap;
        errno = EPROTO;
        return close_and_return (msg, -1);
    }

    //  Save status code
    status_code.assign (static_cast <char *> (msg [3].data ()), 3);

    //  Save user id
    set_user_id (msg [5].data (), msg [5].size ());

    //  Process metadata frame
    rc = parse_metadata (static_cast <const unsigned char*> (msg [6].data ()),
                         msg [6].size (), true);

    if (rc != 0)
        return close_and_return (msg, -1);

    //  Close all reply frames
    for (int i = 0; i < 7; i++) {
        const int rc2 = msg [i].close ();
        errno_assert (rc2 == 0);
    }

    return 0;
}

void zmq::curve_server_t::handle_zap_status_code ()
{
    //  we can assume here that status_code is a valid ZAP status code, 
    //  i.e. 200, 300, 400 or 500
    if (status_code [0] == '2') {
        state = send_ready;
    } else {
        state = send_error;

        int err = 0;
        switch (status_code [0]) {
            case '3':
                err = EAGAIN;
                break;
            case '4':
                err = EACCES;
                break;
            case '5':
                err = EFAULT;
                break;
        }
        //  TODO use event_handshake_failed_zap here? but this is not a ZAP 
        //  protocol error
        
        session->get_socket ()->event_handshake_failed_no_detail (
          session->get_endpoint (), err);
    }
}

#endif
