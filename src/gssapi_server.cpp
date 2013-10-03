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
    gssapi_mechanism_base_t (),
    mechanism_t (options_),
    session (session_),
    peer_address (peer_address_),
    state (recv_next_token),
    security_context_established (false)
{
    service_name = (char *) "host";                         /// FIXME add service_name to options
    int rc = acquire_credentials (service_name, &cred);     /// FIXME add creds to options too?
    if (rc == 0) {
        fprintf(stderr, "%s:%d: acquire creds successful\n", __FILE__, __LINE__); /// FIXME remove
        maj_stat = GSS_S_CONTINUE_NEEDED;
    }
    else {
        fprintf(stderr, "%s:%d: acquire creds failed\n", __FILE__, __LINE__); /// FIXME  remove
        maj_stat = GSS_S_FAILURE;
    }
}

zmq::gssapi_server_t::~gssapi_server_t ()
{
    if(cred)
        gss_release_cred(&min_stat, &cred);
}

int zmq::gssapi_server_t::next_handshake_command (msg_t *msg_)
{
    int rc = 0;

    switch (state) {
        case send_next_token:
            rc = produce_next_token (msg_);
            if (rc == 0)
                state = security_context_established? almost_ready: recv_next_token;
            break;
        case almost_ready:
            state = ready;
            break;
        default:
            errno = EPROTO;
            rc = -1;
            break;
    }
    return rc;
}

int zmq::gssapi_server_t::process_handshake_command (msg_t *msg_)
{
    int rc = 0;

    switch (state) {
        case recv_next_token:
            rc = process_next_token (msg_);
            if (rc == 0)
                state = send_next_token;
            break;
        case almost_ready:
            state = ready;
            break;
        default:
            errno = EAGAIN;
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

int zmq::gssapi_server_t::zap_msg_available ()
{
    return 0;
}

bool zmq::gssapi_server_t::is_handshake_complete () const
{
    fprintf(stderr, "%s:%d: is_handshake_complete=%d\n", __FILE__, __LINE__, (state==ready)); /// FIXME remove
    return state == ready;
}

int zmq::gssapi_server_t::produce_next_token (msg_t *msg_)
{
    if (send_tok.length != 0) { // client expects another token
        fprintf(stderr, "%s:%d: producing token\n", __FILE__, __LINE__); /// FIXME die("creating context", maj_stat, init_sec_min_stat); /// FIXME die("creating context", maj_stat, init_sec_min_stat);
        if (produce_token(msg_, TOKEN_CONTEXT, send_tok.value, send_tok.length) < 0) {
            fprintf(stderr, "%s:%d: failed to produce token!\n", __FILE__, __LINE__); /// FIXME die("creating context", maj_stat, init_sec_min_stat); /// FIXME die("creating context", maj_stat, init_sec_min_stat);
            return -1;
        }
        gss_release_buffer(&min_stat, &send_tok);
    }
    else
        fprintf(stderr, "%s:%d: skip producing token\n", __FILE__, __LINE__); /// FIXME die("creating context", maj_stat, init_sec_min_stat); /// FIXME die("creating context", maj_stat, init_sec_min_stat);

    if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
        fprintf(stderr, "%s:%d: failed to create GSSAPI security context\n", __FILE__, __LINE__); /// FIXME die("creating context", maj_stat, init_sec_min_stat); /// FIXME die("creating context", maj_stat, init_sec_min_stat);
        gss_release_name(&min_stat, &target_name);
        if (context != GSS_C_NO_CONTEXT)
            gss_delete_sec_context(&min_stat, &context, GSS_C_NO_BUFFER);
        return -1;
    }

    if (maj_stat == GSS_S_COMPLETE) {
        gss_release_name(&min_stat, &target_name);
        security_context_established = true;
    }

    return 0;
}

int zmq::gssapi_server_t::process_next_token (msg_t *msg_)
{
    if (maj_stat == GSS_S_CONTINUE_NEEDED) {
        fprintf(stderr, "%s:%d: processing token\n", __FILE__, __LINE__); /// FIXME die("creating context", maj_stat, init_sec_min_stat); /// FIXME die("creating context", maj_stat, init_sec_min_stat);
        if (process_token(msg_, token_flags, &recv_tok.value, recv_tok.length) < 0) {
            if (target_name != GSS_C_NO_NAME)
                gss_release_name(&min_stat, &target_name);
            fprintf(stderr, "%s:%d: failed to process token!\n", __FILE__, __LINE__); /// FIXME die("creating context", maj_stat, init_sec_min_stat); /// FIXME die("creating context", maj_stat, init_sec_min_stat);
            return -1;
        }
    }
    else
        fprintf(stderr, "%s:%d: skip processing token\n", __FILE__, __LINE__); /// FIXME die("creating context", maj_stat, init_sec_min_stat); /// FIXME die("creating context", maj_stat, init_sec_min_stat);
    
    maj_stat = gss_accept_sec_context(&init_sec_min_stat, &context, cred,
                                      &recv_tok, GSS_C_NO_CHANNEL_BINDINGS,
                                      &target_name, &doid, &send_tok,
                                      &ret_flags, NULL, NULL);

    if (recv_tok.value) {
        free (recv_tok.value);
        recv_tok.value = NULL;
    }
 
    return 0;
}

