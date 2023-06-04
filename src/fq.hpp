/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_FQ_HPP_INCLUDED__
#define __ZMQ_FQ_HPP_INCLUDED__

#include "array.hpp"
#include "blob.hpp"

namespace zmq
{
class msg_t;
class pipe_t;

//  Class manages a set of inbound pipes. On receive it performs fair
//  queueing so that senders gone berserk won't cause denial of
//  service for decent senders.

class fq_t
{
  public:
    fq_t ();
    ~fq_t ();

    void attach (pipe_t *pipe_);
    void activated (pipe_t *pipe_);
    void pipe_terminated (pipe_t *pipe_);

    int recv (msg_t *msg_);
    int recvpipe (msg_t *msg_, pipe_t **pipe_);
    bool has_in ();

  private:
    //  Inbound pipes.
    typedef array_t<pipe_t, 1> pipes_t;
    pipes_t _pipes;

    //  Number of active pipes. All the active pipes are located at the
    //  beginning of the pipes array.
    pipes_t::size_type _active;

    //  Index of the next bound pipe to read a message from.
    pipes_t::size_type _current;

    //  If true, part of a multipart message was already received, but
    //  there are following parts still waiting in the current pipe.
    bool _more;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (fq_t)
};
}

#endif
