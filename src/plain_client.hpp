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

#ifndef __ZMQ_PLAIN_CLIENT_HPP_INCLUDED__
#define __ZMQ_PLAIN_CLIENT_HPP_INCLUDED__

#include "mechanism_base.hpp"
#include "options.hpp"

namespace zmq
{
class msg_t;

class plain_client_t : public mechanism_base_t
{
  public:
    plain_client_t (session_base_t *const session_, const options_t &options_);
    virtual ~plain_client_t ();

    // mechanism implementation
    virtual int next_handshake_command (msg_t *msg_);
    virtual int process_handshake_command (msg_t *msg_);
    virtual status_t status () const;

  private:
    enum state_t
    {
        sending_hello,
        waiting_for_welcome,
        sending_initiate,
        waiting_for_ready,
        error_command_received,
        ready
    };

    state_t _state;

    void produce_hello (msg_t *msg_) const;
    void produce_initiate (msg_t *msg_) const;

    int process_welcome (const unsigned char *cmd_data_, size_t data_size_);
    int process_ready (const unsigned char *cmd_data_, size_t data_size_);
    int process_error (const unsigned char *cmd_data_, size_t data_size_);
};
}

#endif
