/*
    Copyright (c) 2007-2012 iMatix Corporation
    Copyright (c) 2007-2012 Other contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_I_MSG_SOURCE_HPP_INCLUDED__
#define __ZMQ_I_MSG_SOURCE_HPP_INCLUDED__

namespace zmq
{

    //  Forward declaration
    class msg_t;

    //  Interface to be implemented by message source.

    struct i_msg_source
    {
        virtual ~i_msg_source () {}

        //  Fetch a message. Returns 0 if successful; -1 otherwise.
        //  The caller is responsible for freeing the message when no
        //  longer used.
        virtual int pull_msg (msg_t *msg_) = 0;
    };

}

#endif
