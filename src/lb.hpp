/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_LB_HPP_INCLUDED__
#define __ZMQ_LB_HPP_INCLUDED__

#include "array.hpp"

namespace zmq
{
class msg_t;
class pipe_t;

//  This class manages a set of outbound pipes. On send it load balances
//  messages fairly among the pipes.

class lb_t
{
  public:
    lb_t ();
    ~lb_t ();

    void attach (pipe_t *pipe_);
    void activated (pipe_t *pipe_);
    void pipe_terminated (pipe_t *pipe_);

    int send (msg_t *msg_);

    //  Sends a message and stores the pipe that was used in pipe_.
    //  It is possible for this function to return success but keep pipe_
    //  unset if the rest of a multipart message to a terminated pipe is
    //  being dropped. For the first frame, this will never happen.
    int sendpipe (msg_t *msg_, pipe_t **pipe_);

    bool has_out ();

  private:
    //  List of outbound pipes.
    typedef array_t<pipe_t, 2> pipes_t;
    pipes_t _pipes;

    //  Number of active pipes. All the active pipes are located at the
    //  beginning of the pipes array.
    pipes_t::size_type _active;

    //  Points to the last pipe that the most recent message was sent to.
    pipes_t::size_type _current;

    //  True if last we are in the middle of a multipart message.
    bool _more;

    //  True if we are dropping current message.
    bool _dropping;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (lb_t)
};
}

#endif
