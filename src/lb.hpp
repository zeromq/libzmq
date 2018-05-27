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

    lb_t (const lb_t &);
    const lb_t &operator= (const lb_t &);
};
}

#endif
