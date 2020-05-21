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

#ifndef __ZMQ_CURVE_CLIENT_HPP_INCLUDED__
#define __ZMQ_CURVE_CLIENT_HPP_INCLUDED__

#ifdef ZMQ_HAVE_CURVE

#include "curve_mechanism_base.hpp"
#include "options.hpp"
#include "curve_client_tools.hpp"

namespace zmq
{
class msg_t;
class session_base_t;

class curve_client_t ZMQ_FINAL : public curve_mechanism_base_t
{
  public:
    curve_client_t (session_base_t *session_,
                    const options_t &options_,
                    const bool downgrade_sub_);
    ~curve_client_t () ZMQ_FINAL;

    // mechanism implementation
    int next_handshake_command (msg_t *msg_) ZMQ_FINAL;
    int process_handshake_command (msg_t *msg_) ZMQ_FINAL;
    int encode (msg_t *msg_) ZMQ_FINAL;
    int decode (msg_t *msg_) ZMQ_FINAL;
    status_t status () const ZMQ_FINAL;

  private:
    enum state_t
    {
        send_hello,
        expect_welcome,
        send_initiate,
        expect_ready,
        error_received,
        connected
    };

    //  Current FSM state
    state_t _state;

    //  CURVE protocol tools
    curve_client_tools_t _tools;

    int produce_hello (msg_t *msg_);
    int process_welcome (const uint8_t *msg_data_, size_t msg_size_);
    int produce_initiate (msg_t *msg_);
    int process_ready (const uint8_t *msg_data_, size_t msg_size_);
    int process_error (const uint8_t *msg_data_, size_t msg_size_);
};
}

#endif

#endif
