/*
    Copyright (c) 2007-2019 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_RAW_ENGINE_HPP_INCLUDED__
#define __ZMQ_RAW_ENGINE_HPP_INCLUDED__

#include <stddef.h>

#include "fd.hpp"
#include "i_engine.hpp"
#include "io_object.hpp"
#include "i_encoder.hpp"
#include "i_decoder.hpp"
#include "options.hpp"
#include "socket_base.hpp"
#include "metadata.hpp"
#include "msg.hpp"
#include "stream_engine_base.hpp"

namespace zmq
{
//  Protocol revisions

class io_thread_t;
class session_base_t;
class mechanism_t;

//  This engine handles any socket with SOCK_STREAM semantics,
//  e.g. TCP socket or an UNIX domain socket.

class raw_engine_t ZMQ_FINAL : public stream_engine_base_t
{
  public:
    raw_engine_t (fd_t fd_,
                  const options_t &options_,
                  const endpoint_uri_pair_t &endpoint_uri_pair_);
    ~raw_engine_t ();

  protected:
    void error (error_reason_t reason_);
    void plug_internal ();
    bool handshake ();

  private:
    int push_raw_msg_to_session (msg_t *msg_);

    ZMQ_NON_COPYABLE_NOR_MOVABLE (raw_engine_t)
};
}

#endif
