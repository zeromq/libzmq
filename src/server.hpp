/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_SERVER_HPP_INCLUDED__
#define __ZMQ_SERVER_HPP_INCLUDED__

#include <map>

#include "socket_base.hpp"
#include "session_base.hpp"
#include "stdint.hpp"
#include "blob.hpp"
#include "fq.hpp"

namespace zmq
{
class ctx_t;
class msg_t;
class pipe_t;

//  TODO: This class uses O(n) scheduling. Rewrite it to use O(1) algorithm.
class server_t : public socket_base_t
{
  public:
    server_t (zmq::ctx_t *parent_, uint32_t tid_, int sid_);
    ~server_t ();

    //  Overrides of functions from socket_base_t.
    void xattach_pipe (zmq::pipe_t *pipe_,
                       bool subscribe_to_all_,
                       bool locally_initiated_);
    int xsend (zmq::msg_t *msg_);
    int xrecv (zmq::msg_t *msg_);
    bool xhas_in ();
    bool xhas_out ();
    void xread_activated (zmq::pipe_t *pipe_);
    void xwrite_activated (zmq::pipe_t *pipe_);
    void xpipe_terminated (zmq::pipe_t *pipe_);

  private:
    //  Fair queueing object for inbound pipes.
    fq_t _fq;

    struct outpipe_t
    {
        zmq::pipe_t *pipe;
        bool active;
    };

    //  Outbound pipes indexed by the peer IDs.
    typedef std::map<uint32_t, outpipe_t> out_pipes_t;
    out_pipes_t _out_pipes;

    //  Routing IDs are generated. It's a simple increment and wrap-over
    //  algorithm. This value is the next ID to use (if not used already).
    uint32_t _next_routing_id;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (server_t)
};
}

#endif
