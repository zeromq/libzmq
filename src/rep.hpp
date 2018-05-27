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

#ifndef __ZMQ_REP_HPP_INCLUDED__
#define __ZMQ_REP_HPP_INCLUDED__

#include "router.hpp"

namespace zmq
{
class ctx_t;
class msg_t;
class io_thread_t;
class socket_base_t;

class rep_t : public router_t
{
  public:
    rep_t (zmq::ctx_t *parent_, uint32_t tid_, int sid_);
    ~rep_t ();

    //  Overrides of functions from socket_base_t.
    int xsend (zmq::msg_t *msg_);
    int xrecv (zmq::msg_t *msg_);
    bool xhas_in ();
    bool xhas_out ();

  private:
    //  If true, we are in process of sending the reply. If false we are
    //  in process of receiving a request.
    bool _sending_reply;

    //  If true, we are starting to receive a request. The beginning
    //  of the request is the backtrace stack.
    bool _request_begins;

    rep_t (const rep_t &);
    const rep_t &operator= (const rep_t &);
};
}

#endif
