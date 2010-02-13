/*
    Copyright (c) 2007-2010 iMatix Corporation

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_ZMQ_INIT_HPP_INCLUDED__
#define __ZMQ_ZMQ_INIT_HPP_INCLUDED__

#include "i_inout.hpp"
#include "i_engine.hpp"
#include "owned.hpp"
#include "fd.hpp"
#include "stdint.hpp"
#include "options.hpp"
#include "stdint.hpp"
#include "blob.hpp"

namespace zmq
{

    //  The class handles initialisation phase of 0MQ wire-level protocol.

    class zmq_init_t : public owned_t, public i_inout
    {
    public:

        zmq_init_t (class io_thread_t *parent_, socket_base_t *owner_,
            fd_t fd_, const options_t &options_, bool reconnect_,
            const char *protocol_, const char *address_,
            uint64_t session_ordinal_);
        ~zmq_init_t ();

    private:

        void finalise ();

        //  i_inout interface implementation.
        bool read (::zmq_msg_t *msg_);
        bool write (::zmq_msg_t *msg_);
        void flush ();
        void detach (owned_t *reconnecter_);
        class io_thread_t *get_io_thread ();
        class socket_base_t *get_owner ();
        uint64_t get_ordinal ();

        //  Handlers for incoming commands.
        void process_plug ();
        void process_unplug ();

        //  Associated wite-protocol engine.
        i_engine *engine;

        //  True if our own identity was already sent to the peer.
        bool sent;

        //  True if peer's identity was already received.
        bool received;

        //  Identity of the peer socket.
        blob_t peer_identity;

        //  TCP connecter creates session before the name of the peer is known.
        //  Thus we know only its ordinal number.
        uint64_t session_ordinal;

        //  Associated socket options.
        options_t options;

        zmq_init_t (const zmq_init_t&);
        void operator = (const zmq_init_t&);
    };

}

#endif
