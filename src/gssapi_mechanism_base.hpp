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

#ifndef __ZMQ_GSSAPI_MECHANISM_BASE_HPP_INCLUDED__
#define __ZMQ_GSSAPI_MECHANISM_BASE_HPP_INCLUDED__

#ifdef HAVE_LIBGSSAPI_KRB5

#if HAVE_GSSAPI_GSSAPI_GENERIC_H
#include <gssapi/gssapi_generic.h>
#endif
#include <gssapi/gssapi_krb5.h>

#include "mechanism.hpp"
#include "options.hpp"

namespace zmq
{

    class msg_t;

    /// Commonalities between clients and servers are captured here.
    /// For example, clients and servers both need to produce and
    /// process context-level GSSAPI tokens (via INITIATE commands)
    /// and per-message GSSAPI tokens (via MESSAGE commands).
    class gssapi_mechanism_base_t:
        public mechanism_t
    {
    public:
        gssapi_mechanism_base_t (const options_t &options_);
        virtual ~gssapi_mechanism_base_t () = 0;

    protected:
        //  Produce a context-level GSSAPI token (INITIATE command)
        //  during security context initialization.
        int produce_initiate (msg_t *msg_, void *data_, size_t data_len_);

        //  Process a context-level GSSAPI token (INITIATE command)
        //  during security context initialization.
        int process_initiate (msg_t *msg_, void **data_, size_t &data_len_);

        // Produce a metadata ready msg (READY) to conclude handshake
        int produce_ready (msg_t *msg_);

        // Process a metadata ready msg (READY)
        int process_ready (msg_t *msg_);

        //  Encode a per-message GSSAPI token (MESSAGE command) using
        //  the established security context.
        int encode_message (msg_t *msg_);

        //  Decode a per-message GSSAPI token (MESSAGE command) using
        //  the  established security context.
        int decode_message (msg_t *msg_);

        //  Acquire security context credentials from the
        //  underlying mechanism.
        static int acquire_credentials (char * principal_name_,
                                        gss_cred_id_t * cred_);

    protected:
        //  Opaque GSSAPI token for outgoing data
        gss_buffer_desc send_tok;

        //  Opaque GSSAPI token for incoming data
        gss_buffer_desc recv_tok;

        //  Opaque GSSAPI representation of principal
        gss_name_t target_name;

        //  Human-readable principal name
        char * principal_name;

        //  Status code returned by GSSAPI functions
        OM_uint32 maj_stat;

        //  Status code returned by the underlying mechanism
        OM_uint32 min_stat;

        //  Status code returned by the underlying mechanism
        //  during context initialization
        OM_uint32 init_sec_min_stat;

        //  Flags returned by GSSAPI (ignored)
        OM_uint32 ret_flags;

        //  Flags returned by GSSAPI (ignored)
        OM_uint32 gss_flags;

        //  Credentials used to establish security context
        gss_cred_id_t cred;

        //  Opaque GSSAPI representation of the security context
        gss_ctx_id_t context;

        //  If true, use gss to encrypt messages. If false, only utilize gss for auth.
        bool do_encryption;
    };

}

#endif

#endif
