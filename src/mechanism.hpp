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

#ifndef __ZMQ_MECHANISM_HPP_INCLUDED__
#define __ZMQ_MECHANISM_HPP_INCLUDED__

#include <stdint.h>

#include "options.hpp"
#include "blob.hpp"

namespace zmq
{

    //  Abstract class representing security mechanism.
    //  Different mechanism extedns this class.

    class msg_t;

    class mechanism_t
    {
    public:

        mechanism_t (const options_t &options_);

        virtual ~mechanism_t ();

        //  Prepare next handshake message that is to be sent to the peer.
        virtual int next_handshake_message (msg_t *msg_) = 0;

        //  Process the handshake message received from the peer.
        virtual int process_handshake_message (msg_t *msg_) = 0;

        //  True iff the handshake stage is complete?
        virtual bool is_handshake_complete () const = 0;

        void set_peer_identity (const void *id_ptr, size_t id_size);

        void peer_identity (msg_t *msg_);

    protected:

        const char *socket_type_string (int socket_type) const;

        size_t add_property (unsigned char *ptr, const char *name,
            const void *value, size_t value_len) const;

        options_t options;

    private:

        blob_t identity;
    };

}

#endif
