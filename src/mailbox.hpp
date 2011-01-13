/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#ifndef __ZMQ_MAILBOX_HPP_INCLUDED__
#define __ZMQ_MAILBOX_HPP_INCLUDED__

#include <stddef.h>

#include "platform.hpp"
#include "fd.hpp"
#include "stdint.hpp"
#include "config.hpp"
#include "command.hpp"

namespace zmq
{

    class mailbox_t
    {
    public:

        mailbox_t ();
        ~mailbox_t ();

        fd_t get_fd ();
        void send (const command_t &cmd_);
        int recv (command_t *cmd_, bool block_);
        
    private:

        //  Write & read end of the socketpair.
        fd_t w;
        fd_t r;

        //  Platform-dependent function to create a socketpair.
        static int make_socketpair (fd_t *r_, fd_t *w_);

        //  Disable copying of mailbox_t object.
        mailbox_t (const mailbox_t&);
        const mailbox_t &operator = (const mailbox_t&);
    };

}

#endif
