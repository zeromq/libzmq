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

#ifndef __ZMQ_DIST_HPP_INCLUDED__
#define __ZMQ_DIST_HPP_INCLUDED__

#include <vector>

#include "array.hpp"

namespace zmq
{
class pipe_t;
class msg_t;

//  Class manages a set of outbound pipes. It sends each messages to
//  each of them.
class dist_t
{
  public:
    dist_t ();
    ~dist_t ();

    //  Adds the pipe to the distributor object.
    void attach (zmq::pipe_t *pipe_);

    //  Activates pipe that have previously reached high watermark.
    void activated (zmq::pipe_t *pipe_);

    //  Mark the pipe as matching. Subsequent call to send_to_matching
    //  will send message also to this pipe.
    void match (zmq::pipe_t *pipe_);

    //  Marks all pipes that are not matched as matched and vice-versa.
    void reverse_match ();

    //  Mark all pipes as non-matching.
    void unmatch ();

    //  Removes the pipe from the distributor object.
    void pipe_terminated (zmq::pipe_t *pipe_);

    //  Send the message to the matching outbound pipes.
    int send_to_matching (zmq::msg_t *msg_);

    //  Send the message to all the outbound pipes.
    int send_to_all (zmq::msg_t *msg_);

    bool has_out ();

    // check HWM of all pipes matching
    bool check_hwm ();

  private:
    //  Write the message to the pipe. Make the pipe inactive if writing
    //  fails. In such a case false is returned.
    bool write (zmq::pipe_t *pipe_, zmq::msg_t *msg_);

    //  Put the message to all active pipes.
    void distribute (zmq::msg_t *msg_);

    //  List of outbound pipes.
    typedef array_t<zmq::pipe_t, 2> pipes_t;
    pipes_t _pipes;

    //  Number of all the pipes to send the next message to.
    pipes_t::size_type _matching;

    //  Number of active pipes. All the active pipes are located at the
    //  beginning of the pipes array. These are the pipes the messages
    //  can be sent to at the moment.
    pipes_t::size_type _active;

    //  Number of pipes eligible for sending messages to. This includes all
    //  the active pipes plus all the pipes that we can in theory send
    //  messages to (the HWM is not yet reached), but sending a message
    //  to them would result in partial message being delivered, ie. message
    //  with initial parts missing.
    pipes_t::size_type _eligible;

    //  True if last we are in the middle of a multipart message.
    bool _more;

    dist_t (const dist_t &);
    const dist_t &operator= (const dist_t &);
};
}

#endif
