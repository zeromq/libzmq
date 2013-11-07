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

#include "platform.hpp"
#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include <string.h>
#include <string>

#include "msg.hpp"
#include "session_base.hpp"
#include "err.hpp"
#include "gssapi_server.hpp"
#include "wire.hpp"

zmq::gssapi_server_t::gssapi_server_t (session_base_t *session_,
                                       const std::string &peer_address_,
                                       const options_t &options_) :
    gssapi_mechanism_base_t (options_),
    session (session_),
    peer_address (peer_address_),
    state (recv_next_token),
    security_context_established (false)
{
    service_name = (char *) "host"; // TODO: add service_name to options
    int rc = acquire_credentials (service_name, &cred); // TODO: add creds to options too?
    if (rc == 0)
        maj_stat = GSS_S_CONTINUE_NEEDED;
    else
        maj_stat = GSS_S_FAILURE;
}

zmq::gssapi_server_t::~gssapi_server_t ()
{
    if(cred)
        gss_release_cred(&min_stat, &cred);
}

int zmq::gssapi_server_t::next_handshake_command (msg_t *msg_)
{
    if (state == send_ready) {
        int rc = produce_ready(msg_);
        if (rc == 0)
            state = recv_ready;

        return rc;
    }

    if (state != send_next_token) {
        errno = EAGAIN;
        return -1;
    }

    if (produce_next_token (msg_) < 0)
        return -1;

    if (maj_stat != GSS_S_CONTINUE_NEEDED && maj_stat != GSS_S_COMPLETE)
        return -1;

    if (maj_stat == GSS_S_COMPLETE) {
        gss_release_name(&min_stat, &target_name);
        security_context_established = true;
    }

    state = recv_next_token;

    return 0;
}

int zmq::gssapi_server_t::process_handshake_command (msg_t *msg_)
{
    if (state == recv_ready) {
        int rc = process_ready(msg_);
        if (rc == 0) 
            state = connected;

        return rc;
    }

    if (state != recv_next_token) {
        errno = EPROTO;
        return -1;
    }

    if (security_context_established) {
        state = send_ready;
        return 0;
    }

    if (process_next_token (msg_) < 0)
        return -1;

    accept_context ();
    state = send_next_token;

    errno_assert (msg_->close () == 0);
    errno_assert (msg_->init () == 0);

    return 0;
}

int zmq::gssapi_server_t::encode (msg_t *msg_)
{
    zmq_assert (state == connected);
    return encode_message (msg_);
}

int zmq::gssapi_server_t::decode (msg_t *msg_)
{
    zmq_assert (state == connected);
    return decode_message (msg_);
}

int zmq::gssapi_server_t::zap_msg_available ()
{
    return 0;
}

bool zmq::gssapi_server_t::is_handshake_complete () const
{
    return state == connected;
}

int zmq::gssapi_server_t::produce_next_token (msg_t *msg_)
{
    if (send_tok.length != 0) { // Client expects another token
        if (produce_initiate(msg_, send_tok.value, send_tok.length) < 0)
            return -1;
        gss_release_buffer(&min_stat, &send_tok);
    }

    if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
        gss_release_name(&min_stat, &target_name);
        if (context != GSS_C_NO_CONTEXT)
            gss_delete_sec_context(&min_stat, &context, GSS_C_NO_BUFFER);
        return -1;
    }

    return 0;
}

int zmq::gssapi_server_t::process_next_token (msg_t *msg_)
{
    if (maj_stat == GSS_S_CONTINUE_NEEDED) {
        if (process_initiate(msg_, &recv_tok.value, recv_tok.length) < 0) {
            if (target_name != GSS_C_NO_NAME)
                gss_release_name(&min_stat, &target_name);
            return -1;
        }
    }

    return 0;
}

void zmq::gssapi_server_t::accept_context ()
{
    maj_stat = gss_accept_sec_context(&init_sec_min_stat, &context, cred,
                                      &recv_tok, GSS_C_NO_CHANNEL_BINDINGS,
                                      &target_name, &doid, &send_tok,
                                      &ret_flags, NULL, NULL);

    if (recv_tok.value) {
        free (recv_tok.value);
        recv_tok.value = NULL;
    }
}

