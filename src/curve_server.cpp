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

#ifdef HAVE_LIBSODIUM

#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

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
    cn_nonce (1),
    cn_peer_nonce(1),
    sync()
{
    //  Fetch our secret key from socket options
    memcpy (secret_key, options_.curve_secret_key, crypto_box_SECRETKEYBYTES);
    scoped_lock_t lock (sync);
#if defined(HAVE_TWEETNACL)
    // allow opening of /dev/urandom
    unsigned char tmpbytes[4];
    randombytes(tmpbytes, 4);
#else
    // todo check return code
    sodium_init();
#endif

    //  Generate short-term key pair
    const int rc = crypto_box_keypair (cn_public, cn_secret);
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
            //  Temporary support for security debugging
            puts ("CURVE I: invalid handshake command");
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
        //  Temporary support for security debugging
        puts ("CURVE I: invalid CURVE client, sent malformed command");
        errno = EPROTO;
        return -1;
    }

    const uint8_t *message = static_cast <uint8_t *> (msg_->data ());
    if (memcmp (message, "\x07MESSAGE", 8)) {
        //  Temporary support for security debugging
        puts ("CURVE I: invalid CURVE client, did not send MESSAGE");
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

        memcpy (msg_->data (),
                message_plaintext + crypto_box_ZEROBYTES + 1,
                msg_->size ());
    }
    else {
        //  Temporary support for security debugging
        puts ("CURVE I: connection key used for MESSAGE is wrong");
        errno = EPROTO;
    }
    free (message_plaintext);
    free (message_box);

    return rc;
}

int zmq::curve_server_t::zap_msg_available ()
{
    if (state != expect_zap_reply) {
        errno = EFSM;
        return -1;
    }
    const int rc = receive_and_process_zap_reply ();
    if (rc == 0)
        state = status_code == "200"
            ? send_ready
            : send_error;
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

int zmq::curve_server_t::process_hello (msg_t *msg_)
{
    if (msg_->size () != 200) {
        //  Temporary support for security debugging
        puts ("CURVE I: client HELLO is not correct size");
        errno = EPROTO;
        return -1;
    }

    const uint8_t * const hello = static_cast <uint8_t *> (msg_->data ());
    if (memcmp (hello, "\x05HELLO", 6)) {
        //  Temporary support for security debugging
        puts ("CURVE I: client HELLO has invalid command name");
        errno = EPROTO;
        return -1;
    }

    const uint8_t major = hello [6];
    const uint8_t minor = hello [7];

    if (major != 1 || minor != 0) {
        //  Temporary support for security debugging
        puts ("CURVE I: client HELLO has unknown version number");
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
        //  Temporary support for security debugging
        puts ("CURVE I: cannot open client HELLO -- wrong server key?");
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
    zmq_assert (rc == 0);

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
        //  Temporary support for security debugging
        puts ("CURVE I: client INITIATE is not correct size");
        errno = EPROTO;
        return -1;
    }

    const uint8_t *initiate = static_cast <uint8_t *> (msg_->data ());
    if (memcmp (initiate, "\x08INITIATE", 9)) {
        //  Temporary support for security debugging
        puts ("CURVE I: client INITIATE has invalid command name");
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
        //  Temporary support for security debugging
        puts ("CURVE I: cannot open client INITIATE cookie");
        errno = EPROTO;
        return -1;
    }

    //  Check cookie plain text is as expected [C' + s']
    if (memcmp (cookie_plaintext + crypto_secretbox_ZEROBYTES, cn_client, 32)
    ||  memcmp (cookie_plaintext + crypto_secretbox_ZEROBYTES + 32, cn_secret, 32)) {
        //  Temporary support for security debugging
        puts ("CURVE I: client INITIATE cookie is not valid");
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
        //  Temporary support for security debugging
        puts ("CURVE I: cannot open client INITIATE");
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
        //  Temporary support for security debugging
        puts ("CURVE I: cannot open client INITIATE vouch");
        errno = EPROTO;
        return -1;
    }

    //  What we decrypted must be the client's short-term public key
    if (memcmp (vouch_plaintext + crypto_box_ZEROBYTES, cn_client, 32)) {
        //  Temporary support for security debugging
        puts ("CURVE I: invalid handshake from client (public key)");
        errno = EPROTO;
        return -1;
    }

    //  Precompute connection secret from client key
    rc = crypto_box_beforenm (cn_precom, cn_client, cn_secret);
    zmq_assert (rc == 0);

    //  Use ZAP protocol (RFC 27) to authenticate the user.
    rc = session->zap_connect ();
    if (rc == 0) {
        send_zap_request (client_key);
        rc = receive_and_process_zap_reply ();
        if (rc == 0)
            state = status_code == "200"
                ? send_ready
                : send_error;
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
    uint8_t ready_nonce [crypto_box_NONCEBYTES];
    uint8_t ready_plaintext [crypto_box_ZEROBYTES + 256];
    uint8_t ready_box [crypto_box_BOXZEROBYTES + 16 + 256];

    //  Create Box [metadata](S'->C')
    memset (ready_plaintext, 0, crypto_box_ZEROBYTES);
    uint8_t *ptr = ready_plaintext + crypto_box_ZEROBYTES;

    //  Add socket type property
    const char *socket_type = socket_type_string (options.type);
    ptr += add_property (ptr, "Socket-Type", socket_type, strlen (socket_type));

    //  Add identity property
    if (options.type == ZMQ_REQ
    ||  options.type == ZMQ_DEALER
    ||  options.type == ZMQ_ROUTER)
        ptr += add_property (ptr, "Identity", options.identity, options.identity_size);

    const size_t mlen = ptr - ready_plaintext;

    memcpy (ready_nonce, "CurveZMQREADY---", 16);
    put_uint64 (ready_nonce + 16, cn_nonce);

    int rc = crypto_box_afternm (ready_box, ready_plaintext,
                                 mlen, ready_nonce, cn_precom);
    zmq_assert (rc == 0);

    rc = msg_->init_size (14 + mlen - crypto_box_BOXZEROBYTES);
    errno_assert (rc == 0);

    uint8_t *ready = static_cast <uint8_t *> (msg_->data ());

    memcpy (ready, "\x05READY", 6);
    //  Short nonce, prefixed by "CurveZMQREADY---"
    memcpy (ready + 6, ready_nonce + 16, 8);
    //  Box [metadata](S'->C')
    memcpy (ready + 14, ready_box + crypto_box_BOXZEROBYTES,
            mlen - crypto_box_BOXZEROBYTES);

    cn_nonce++;

    return 0;
}

int zmq::curve_server_t::produce_error (msg_t *msg_) const
{
    zmq_assert (status_code.length () == 3);
    const int rc = msg_->init_size (6 + 1 + status_code.length ());
    zmq_assert (rc == 0);
    char *msg_data = static_cast <char *> (msg_->data ());
    memcpy (msg_data, "\5ERROR", 6);
    msg_data [6] = sizeof status_code;
    memcpy (msg_data + 7, status_code.c_str (), status_code.length ());
    return 0;
}

void zmq::curve_server_t::send_zap_request (const uint8_t *key)
{
    int rc;
    msg_t msg;

    //  Address delimiter frame
    rc = msg.init ();
    errno_assert (rc == 0);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Version frame
    rc = msg.init_size (3);
    errno_assert (rc == 0);
    memcpy (msg.data (), "1.0", 3);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Request ID frame
    rc = msg.init_size (1);
    errno_assert (rc == 0);
    memcpy (msg.data (), "1", 1);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Domain frame
    rc = msg.init_size (options.zap_domain.length ());
    errno_assert (rc == 0);
    memcpy (msg.data (), options.zap_domain.c_str (), options.zap_domain.length ());
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Address frame
    rc = msg.init_size (peer_address.length ());
    errno_assert (rc == 0);
    memcpy (msg.data (), peer_address.c_str (), peer_address.length ());
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Identity frame
    rc = msg.init_size (options.identity_size);
    errno_assert (rc == 0);
    memcpy (msg.data (), options.identity, options.identity_size);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Mechanism frame
    rc = msg.init_size (5);
    errno_assert (rc == 0);
    memcpy (msg.data (), "CURVE", 5);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Credentials frame
    rc = msg.init_size (crypto_box_PUBLICKEYBYTES);
    errno_assert (rc == 0);
    memcpy (msg.data (), key, crypto_box_PUBLICKEYBYTES);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);
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
            break;
        if ((msg [i].flags () & msg_t::more) == (i < 6? 0: msg_t::more)) {
            //  Temporary support for security debugging
            puts ("CURVE I: ZAP handler sent incomplete reply message");
            errno = EPROTO;
            rc = -1;
            break;
        }
    }

    if (rc != 0)
        goto error;

    //  Address delimiter frame
    if (msg [0].size () > 0) {
        //  Temporary support for security debugging
        puts ("CURVE I: ZAP handler sent malformed reply message");
        errno = EPROTO;
        rc = -1;
        goto error;
    }

    //  Version frame
    if (msg [1].size () != 3 || memcmp (msg [1].data (), "1.0", 3)) {
        //  Temporary support for security debugging
        puts ("CURVE I: ZAP handler sent bad version number");
        errno = EPROTO;
        rc = -1;
        goto error;
    }

    //  Request id frame
    if (msg [2].size () != 1 || memcmp (msg [2].data (), "1", 1)) {
        //  Temporary support for security debugging
        puts ("CURVE I: ZAP handler sent bad request ID");
        errno = EPROTO;
        rc = -1;
        goto error;
    }

    //  Status code frame
    if (msg [3].size () != 3) {
        //  Temporary support for security debugging
        puts ("CURVE I: ZAP handler rejected client authentication");
        errno = EACCES;
        rc = -1;
        goto error;
    }

    //  Save status code
    status_code.assign (static_cast <char *> (msg [3].data ()), 3);

    //  Save user id
    set_user_id (msg [5].data (), msg [5].size ());

    //  Process metadata frame
    rc = parse_metadata (static_cast <const unsigned char*> (msg [6].data ()),
                         msg [6].size (), true);

error:
    for (int i = 0; i < 7; i++) {
        const int rc2 = msg [i].close ();
        errno_assert (rc2 == 0);
    }

    return rc;
}

#endif
