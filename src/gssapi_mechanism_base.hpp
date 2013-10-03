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

    // Both gssapi_server and gssapi_client need to produce and process
    // GSSAPI tokens.  Common implementation is captured here.

    class gssapi_mechanism_base_t
    {
    public:
        gssapi_mechanism_base_t ();
        virtual ~gssapi_mechanism_base_t () = 0;

    protected:
        int produce_token (msg_t *msg_, int flags_, void *token_value_, size_t token_length_);
        int process_token (msg_t *msg_, int &flags_, void **token_value_, size_t &token_length_);
    };

}

#endif
