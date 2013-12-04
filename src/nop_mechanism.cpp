/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "platform.hpp"
#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "err.hpp"
#include "msg.hpp"
#include "session_base.hpp"
#include "wire.hpp"
#include "nop_mechanism.hpp"

zmq::nop_mechanism_t::nop_mechanism_t (session_base_t *session_,
                                         const std::string &peer_address_,
                                         const options_t &options_) :
    mechanism_t (options_),
    session (session_),
    peer_address (peer_address_),
    ready_command_sent (false),
    ready_command_received (false),
    zap_connected (false),
    zap_request_sent (false),
    zap_reply_received (false)
{
}

zmq::nop_mechanism_t::~nop_mechanism_t ()
{
}

int zmq::nop_mechanism_t::next_handshake_command (msg_t *msg_)
{
    if (ready_command_sent) {
        errno = EAGAIN;
        return -1;
    }

    ready_command_sent = true;

    return 0;
}

int zmq::nop_mechanism_t::process_handshake_command (msg_t *msg_)
{
    if (ready_command_received) {
        errno = EPROTO;
        return -1;
    }

    ready_command_received = true;

    return 0;
}

int zmq::nop_mechanism_t::zap_msg_available ()
{
    return 0;
}

bool zmq::nop_mechanism_t::is_handshake_complete () const
{
    return ready_command_received && ready_command_sent;
}

void zmq::nop_mechanism_t::send_zap_request ()
{
}

int zmq::nop_mechanism_t::receive_and_process_zap_reply ()
{
	return 0;
}
