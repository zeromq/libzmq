/* SPDX-License-Identifier: MPL-2.0 */

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
    options.can_recv_hiccup_msg = true;
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
