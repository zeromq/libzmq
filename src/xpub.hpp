/*
    Copyright (c) 2007-2011 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_XPUB_HPP_INCLUDED__
#define __ZMQ_XPUB_HPP_INCLUDED__

#include <deque>

#include "socket_base.hpp"
#include "mtrie.hpp"
#include "array.hpp"
#include "blob.hpp"
#include "dist.hpp"

namespace zmq
{

    class xpub_t :
        public socket_base_t
    {
    public:

        xpub_t (class ctx_t *parent_, uint32_t tid_);
        ~xpub_t ();

        //  Implementations of virtual functions from socket_base_t.
        void xattach_pipe (class pipe_t *pipe_, const blob_t &peer_identity_);
        int xsend (class msg_t *msg_, int flags_);
        bool xhas_out ();
        int xrecv (class msg_t *msg_, int flags_);
        bool xhas_in ();
        void xread_activated (class pipe_t *pipe_);
        void xwrite_activated (class pipe_t *pipe_);
        void xterminated (class pipe_t *pipe_);

    private:

        //  Function to be applied to the trie to send all the subsciptions
        //  upstream.
        static void send_unsubscription (unsigned char *data_, size_t size_,
            void *arg_);

        //  Function to be applied to each matching pipes.
        static void mark_as_matching (class pipe_t *pipe_, void *arg_);

        //  List of all subscriptions mapped to corresponding pipes.
        mtrie_t subscriptions;

        //  Distributor of messages holding the list of outbound pipes.
        dist_t dist;

        //  List of pending (un)subscriptions, ie. those that were already
        //  applied to the trie, but not yet received by the user.
        typedef std::deque <blob_t> pending_t;
        pending_t pending;

        xpub_t (const xpub_t&);
        const xpub_t &operator = (const xpub_t&);
    };

}

#endif
