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
#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "err.hpp"
#include "msg.hpp"
#include "session_base.hpp"
#include "wire.hpp"
#include "null_mechanism.hpp"

zmq::null_mechanism_t::null_mechanism_t (session_base_t *session_,
                                         const std::string &peer_address_,
                                         const options_t &options_) :
    mechanism_t (options_),
    session (session_),
    peer_address (peer_address_),
    ready_command_sent (false),
    error_command_sent (false),
    ready_command_received (false),
    error_command_received (false),
    zap_connected (false),
    zap_request_sent (false),
    zap_reply_received (false)
{
    //  NULL mechanism only uses ZAP if there's a domain defined
    //  This prevents ZAP requests on naive sockets
    if (options.zap_domain.size () > 0
    &&  session->zap_connect () == 0)
        zap_connected = true;
}

zmq::null_mechanism_t::~null_mechanism_t ()
{
}

int zmq::null_mechanism_t::next_handshake_command (msg_t *msg_)
{
    if (ready_command_sent || error_command_sent) {
        errno = EAGAIN;
        return -1;
    }
    if (zap_connected && !zap_reply_received) {
        if (zap_request_sent) {
            errno = EAGAIN;
            return -1;
        }
        send_zap_request ();
        zap_request_sent = true;
        const int rc = receive_and_process_zap_reply ();
        if (rc != 0)
            return -1;
        zap_reply_received = true;
    }

    if (zap_reply_received
    &&  strncmp (status_code, "200", sizeof status_code) != 0) {
        const int rc = msg_->init_size (6 + 1 + sizeof status_code);
        zmq_assert (rc == 0);
        unsigned char *msg_data =
            static_cast <unsigned char *> (msg_->data ());
        memcpy (msg_data, "\5ERROR", 6);
        msg_data [6] = sizeof status_code;
        memcpy (msg_data + 7, status_code, sizeof status_code);
        error_command_sent = true;
        return 0;
    }

    unsigned char *const command_buffer = (unsigned char *) malloc (512);
    alloc_assert (command_buffer);

    unsigned char *ptr = command_buffer;

    //  Add mechanism string
    memcpy (ptr, "\5READY", 6);
    ptr += 6;

    //  Add socket type property
    const char *socket_type = socket_type_string (options.type);
    ptr += add_property (ptr, "Socket-Type", socket_type, strlen (socket_type));

    //  Add identity property
    if (options.type == ZMQ_REQ
    ||  options.type == ZMQ_DEALER
    ||  options.type == ZMQ_ROUTER)
        ptr += add_property (ptr, "Identity", options.identity, options.identity_size);

    const size_t command_size = ptr - command_buffer;
    const int rc = msg_->init_size (command_size);
    errno_assert (rc == 0);
    memcpy (msg_->data (), command_buffer, command_size);
    free (command_buffer);

    ready_command_sent = true;

    return 0;
}

int zmq::null_mechanism_t::process_handshake_command (msg_t *msg_)
{
    if (ready_command_received || error_command_received) {
        //  Temporary support for security debugging
        puts ("NULL I: client sent invalid NULL handshake (duplicate READY)");
        errno = EPROTO;
        return -1;
    }

    const unsigned char *cmd_data =
        static_cast <unsigned char *> (msg_->data ());
    const size_t data_size = msg_->size ();

    int rc = 0;
    if (data_size >= 6 && !memcmp (cmd_data, "\5READY", 6))
        rc = process_ready_command (cmd_data, data_size);
    else
    if (data_size >= 6 && !memcmp (cmd_data, "\5ERROR", 6))
        rc = process_error_command (cmd_data, data_size);
    else {
        //  Temporary support for security debugging
        puts ("NULL I: client sent invalid NULL handshake (not READY)");
        errno = EPROTO;
        rc = -1;
    }

    if (rc == 0) {
        int rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
    }
    return rc;
}

int zmq::null_mechanism_t::process_ready_command (
        const unsigned char *cmd_data, size_t data_size)
{
    ready_command_received = true;
    return parse_metadata (cmd_data + 6, data_size - 6);
}

int zmq::null_mechanism_t::process_error_command (
        const unsigned char *cmd_data, size_t data_size)
{
    if (data_size < 7) {
        errno = EPROTO;
        return -1;
    }
    const size_t error_reason_len = static_cast <size_t> (cmd_data [6]);
    if (error_reason_len > data_size - 7) {
        errno = EPROTO;
        return -1;
    }
    error_command_received = true;
    return 0;
}

int zmq::null_mechanism_t::zap_msg_available ()
{
    if (zap_reply_received) {
        errno = EFSM;
        return -1;
    }
    const int rc = receive_and_process_zap_reply ();
    if (rc == 0)
        zap_reply_received = true;
    return rc;
}

zmq::mechanism_t::status_t zmq::null_mechanism_t::status () const
{
    const bool command_sent =
        ready_command_sent || error_command_sent;
    const bool command_received =
        ready_command_received || error_command_received;

    if (ready_command_sent && ready_command_received)
        return ready;
    else
    if (command_sent && command_received)
        return error;
    else
        return handshaking;
}

void zmq::null_mechanism_t::send_zap_request ()
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

    //  Request id frame
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
    rc = msg.init_size (4);
    errno_assert (rc == 0);
    memcpy (msg.data (), "NULL", 4);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);
}

int zmq::null_mechanism_t::receive_and_process_zap_reply ()
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
            puts ("NULL I: ZAP handler sent incomplete reply message");
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
        puts ("NULL I: ZAP handler sent malformed reply message");
        errno = EPROTO;
        rc = -1;
        goto error;
    }

    //  Version frame
    if (msg [1].size () != 3 || memcmp (msg [1].data (), "1.0", 3)) {
        //  Temporary support for security debugging
        puts ("NULL I: ZAP handler sent bad version number");
        errno = EPROTO;
        rc = -1;
        goto error;
    }

    //  Request id frame
    if (msg [2].size () != 1 || memcmp (msg [2].data (), "1", 1)) {
        //  Temporary support for security debugging
        puts ("NULL I: ZAP handler sent bad request ID");
        errno = EPROTO;
        rc = -1;
        goto error;
    }

    //  Status code frame
    if (msg [3].size () != 3) {
        //  Temporary support for security debugging
        puts ("NULL I: ZAP handler rejected client authentication");
        errno = EPROTO;
        rc = -1;
        goto error;
    }

    //  Save status code
    memcpy (status_code, msg [3].data (), sizeof status_code);

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
