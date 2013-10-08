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

#ifndef __ZMQ_GSSAPI_MECHANISM_BASE_HPP_INCLUDED__
#define __ZMQ_GSSAPI_MECHANISM_BASE_HPP_INCLUDED__

#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>
#include <gssapi/gssapi_ext.h>

namespace zmq
{

    class msg_t;

    /// Commonalities between clients and servers are captured here.
    /// For example, clients and server both need to produce and
    /// process INITIATE and MESSAGE commands.
    class gssapi_mechanism_base_t
    {
    public:
        gssapi_mechanism_base_t ();
        virtual ~gssapi_mechanism_base_t () = 0;

    protected:
        /// Produce an INITIATE during security context initialization
        int produce_initiate (msg_t *msg_, void *data_, size_t data_len_);
        /// Process an INITIATE during  security context initialization
        int process_initiate (msg_t *msg_, void **data_, size_t &data_len_);
        /// Encode a MESSAGE using the established security context
        int encode_message (msg_t *msg_);
        /// Decode a MESSAGE using the established security context
        int decode_message (msg_t *msg_);
        /// Acquire security context credentials
        static int acquire_credentials (char * service_name_,
                                        gss_cred_id_t * cred_);

    protected:
        /// Opaque GSSAPI token for outgoing data
        gss_buffer_desc send_tok;
        
        /// Opaque GSSAPI token for incoming data
        gss_buffer_desc recv_tok;
        
        /// Opaque GSSAPI representation of service_name
        gss_name_t target_name;
        
        /// Human-readable service principal name
        char * service_name;

        /// Status code returned by GSSAPI functions
        OM_uint32 maj_stat;

        /// Status code returned by the underlying mechanism
        OM_uint32 min_stat;

        /// Status code returned by the underlying mechanism
        /// during context initialization
        OM_uint32 init_sec_min_stat;

        /// Flags returned by GSSAPI (ignored)
        OM_uint32 ret_flags;
        
        /// Flags returned by GSSAPI (ignored)
        OM_uint32 gss_flags;
        
        /// Credentials used to establish security context
        gss_cred_id_t cred;

        /// Opaque GSSAPI representation of the security context
        gss_ctx_id_t context;
    };

}
    
#endif

