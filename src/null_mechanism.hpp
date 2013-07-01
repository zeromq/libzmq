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

#ifndef __ZMQ_NULL_MECHANISM_HPP_INCLUDED__
#define __ZMQ_NULL_MECHANISM_HPP_INCLUDED__

#include "mechanism.hpp"
#include "options.hpp"

namespace zmq
{

    class msg_t;

    class null_mechanism_t : public mechanism_t
    {
    public:

        null_mechanism_t (const options_t &options_);
        virtual ~null_mechanism_t ();

        // mechanism implementation
        virtual int next_handshake_message (msg_t *msg_);
        virtual int process_handshake_message (msg_t *msg_);
        virtual bool is_handshake_complete () const;

    private:

        bool ready_command_sent;
        bool ready_command_received;
    };

}

#endif
