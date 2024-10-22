/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_PEER_HPP_INCLUDED__
#define __ZMQ_PEER_HPP_INCLUDED__

#include <map>

#include "socket_base.hpp"
#include "server.hpp"
#include "session_base.hpp"
#include "stdint.hpp"
#include "blob.hpp"
#include "fq.hpp"

namespace zmq
{
class ctx_t;
class msg_t;
class pipe_t;

class peer_t ZMQ_FINAL : public server_t
{
  public:
    peer_t (zmq::ctx_t *parent_, uint32_t tid_, int sid_);

    //  Overrides of functions from socket_base_t.
    void xattach_pipe (zmq::pipe_t *pipe_,
                       bool subscribe_to_all_,
                       bool locally_initiated_);

    uint32_t connect_peer (const char *endpoint_uri_);

  private:
    uint32_t _peer_last_routing_id;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (peer_t)
};
}

#endif
