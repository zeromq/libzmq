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

#include "named_session.hpp"
#include "socket_base.hpp"

zmq::named_session_t::named_session_t (class io_thread_t *io_thread_,
      socket_base_t *socket_, const options_t &options_,
      const blob_t &peer_identity_) :
    session_t (io_thread_, socket_, options_),
    peer_identity (peer_identity_)
{
    //  Make double sure that the peer's identity is not transient.
    zmq_assert (!peer_identity.empty ());
    zmq_assert (peer_identity [0] != 0);

    bool ok = socket_->register_session (peer_identity, this);

    //  If new session is being created, the caller should have already
    //  checked that the session for specified identity doesn't exist yet.
    //  Thus, register_session should not fail.
    zmq_assert (ok);
}

zmq::named_session_t::~named_session_t ()
{
    //  Unregister the session from the global list of named sessions.
    unregister_session (peer_identity);
}

void zmq::named_session_t::attached (const blob_t &peer_identity_)
{
    //  The owner should take care to not attach the session
    //  to an unrelated peer.
    zmq_assert (peer_identity == peer_identity_);
}

void zmq::named_session_t::detached ()
{
    //  Do nothing. Named sessions are never destroyed because of disconnection.
    //  Neither they have to actively reconnect.
}

