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

#include "precompiled.hpp"
#include "macros.hpp"
#include "peer.hpp"
#include "pipe.hpp"
#include "wire.hpp"
#include "random.hpp"
#include "likely.hpp"
#include "err.hpp"

zmq::peer_t::peer_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    server_t (parent_, tid_, sid_)
{
    options.type = ZMQ_PEER;
    options.can_send_hello_msg = true;
    options.can_recv_disconnect_msg = true;
}

uint32_t zmq::peer_t::connect_peer (const char *endpoint_uri_)
{
    scoped_optional_lock_t sync_lock (&_sync);

    // connect_peer cannot work with immediate enabled
    if (options.immediate == 1) {
        errno = EFAULT;
        return 0;
    }

    int rc = socket_base_t::connect_internal (endpoint_uri_);
    if (rc != 0)
        return 0;

    return _peer_last_routing_id;
}

void zmq::peer_t::xattach_pipe (pipe_t *pipe_,
                                bool subscribe_to_all_,
                                bool locally_initiated_)
{
    server_t::xattach_pipe (pipe_, subscribe_to_all_, locally_initiated_);
    _peer_last_routing_id = pipe_->get_server_socket_routing_id ();
}
