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
#include "gssapi_client.hpp"
#include "wire.hpp"

zmq::gssapi_client_t::gssapi_client_t (const options_t &options_) :
    gssapi_mechanism_base_t (),
    mechanism_t (options_),
    state (send_next_token),
    token_ptr (GSS_C_NO_BUFFER),
    mechs (),
    security_context_established (false)
{
    maj_stat = GSS_S_COMPLETE;
    service_name = strdup("host"); /// FIXME add service_name to options
    mechs.elements = NULL;
    mechs.count = 0;
}

zmq::gssapi_client_t::~gssapi_client_t ()
{
    if(service_name)
        free (service_name);
    /// FIXME release this or not?
    if(cred)
        gss_release_cred(&min_stat, &cred);
}

int zmq::gssapi_client_t::next_handshake_command (msg_t *msg_)
{
    int rc = 0;

    switch (state) {
        case send_next_token:
            rc = produce_next_token (msg_);
            if (rc == 0)
                state = recv_next_token;
            break;
        case almost_ready:
            state = ready;
            break;
        default:
            errno = EAGAIN;
            rc = -1;
            break;
    }
    return rc;
}

int zmq::gssapi_client_t::process_handshake_command (msg_t *msg_)
{
    int rc = 0;

    switch (state) {
        case recv_next_token:
            rc = process_next_token (msg_);
            if (rc == 0)
                state = security_context_established? almost_ready: send_next_token;
            break;
        case almost_ready:
            state = ready;
            break;
        default:
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

int zmq::gssapi_client_t::encode (msg_t *msg_)
{
    int rc = 0;
    zmq_assert (state == ready);
    return rc;
}

int zmq::gssapi_client_t::decode (msg_t *msg_)
{
    int rc = 0;
    zmq_assert (state == ready);
    return rc;
}

bool zmq::gssapi_client_t::is_handshake_complete () const
{
    fprintf(stderr, "%s:%d: is_handshake_complete=%d, security_context_established=%d\n", __FILE__, __LINE__, (state==ready), security_context_established); /// FIXME remove
    return state == ready;
}

int zmq::gssapi_client_t::produce_next_token (msg_t *msg_)
{
    // First time through, import service_name into target_name
    if (target_name == GSS_C_NO_NAME) {
        send_tok.value = service_name;
        send_tok.length = strlen(service_name);
        OM_uint32 maj = gss_import_name(&min_stat, &send_tok,
                                        gss_nt_service_name, &target_name);
 
        if (maj != GSS_S_COMPLETE) {
            fprintf(stderr, "%s:%d: failed to import service name\n", __FILE__, __LINE__); /// FIXME die("creating context", maj_stat, init_sec_min_stat); /// FIXME die("parsing name", maj_stat, min_stat);
            return -1;
        }
    }

    maj_stat = gss_init_sec_context(&init_sec_min_stat, cred, &context,
                                    target_name, mechs.elements,
                                    gss_flags, 0, NULL, token_ptr, NULL,
                                    &send_tok, &ret_flags, NULL);

    if (token_ptr != GSS_C_NO_BUFFER)
        free(recv_tok.value);
     
    if (send_tok.length != 0) { // server expects another token
        fprintf(stderr, "%s:%d: producing token\n", __FILE__, __LINE__); /// FIXME die("creating context", maj_stat, init_sec_min_stat); /// FIXME die("parsing name", maj_stat, min_stat);
        if (produce_token (msg_, TOKEN_CONTEXT, send_tok.value, send_tok.length) < 0) {
            gss_release_buffer(&min_stat, &send_tok);
            gss_release_name(&min_stat, &target_name);
            return -1;
        }
    }
    else
        fprintf(stderr, "%s:%d: skip producing token\n", __FILE__, __LINE__); /// FIXME die("creating context", maj_stat, init_sec_min_stat); /// FIXME die("parsing name", maj_stat, min_stat);

    gss_release_buffer(&min_stat, &send_tok);

    if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
        fprintf(stderr, "%s:%d: failed to create GSSAPI security context\n", __FILE__, __LINE__); /// FIXME die("creating context", maj_stat, init_sec_min_stat);
        gss_release_name(&min_stat, &target_name);
        if (context != GSS_C_NO_CONTEXT)
            gss_delete_sec_context(&min_stat, &context, GSS_C_NO_BUFFER);
        return -1;
    }

    return 0;
}

int zmq::gssapi_client_t::process_next_token (msg_t *msg_)
{
    if (maj_stat == GSS_S_CONTINUE_NEEDED) {
        fprintf(stderr, "%s:%d: processing token\n", __FILE__, __LINE__); /// FIXME die("creating context", maj_stat, init_sec_min_stat); /// FIXME die("parsing name", maj_stat, min_stat);
        if (process_token(msg_, token_flags, &recv_tok.value, recv_tok.length) < 0) {
            gss_release_name(&min_stat, &target_name);
            return -1;
        }
        token_ptr = &recv_tok;
    }
    else
        fprintf(stderr, "%s:%d: skip processing token\n", __FILE__, __LINE__); /// FIXME die("creating context", maj_stat, init_sec_min_stat); /// FIXME die("parsing name", maj_stat, min_stat);

    if (maj_stat == GSS_S_COMPLETE)
        security_context_established = true;

    return 0;
}

