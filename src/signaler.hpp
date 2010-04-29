/*
    Copyright (c) 2007-2010 iMatix Corporation

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_SIGNALER_HPP_INCLUDED__
#define __ZMQ_SIGNALER_HPP_INCLUDED__

#include "platform.hpp"
#include "fd.hpp"
#include "stdint.hpp"

namespace zmq
{

    //  This object can be used to send individual signals from one thread to
    //  another. The specific of this pipe is that it has associated file
    //  descriptor and so it can be polled on. Same signal cannot be sent twice
    //  unless signals are retrieved by the reader side in the meantime.

    class signaler_t
    {
    public:

        signaler_t ();
        ~signaler_t ();

        //  i_signaler interface implementation.
        void signal (int signal_);
        uint64_t poll ();
        uint64_t check ();
        fd_t get_fd ();

    private:

#if defined ZMQ_HAVE_OPENVMS

         //  Whilst OpenVMS supports socketpair - it maps to AF_INET only.
         //  Further, it does not set the socket options TCP_NODELAY and
         //  TCP_NODELACK which can lead to performance problems. We'll
         //  overload the socketpair function for this class.
         //
         //  The bug will be fixed in V5.6 ECO4 and beyond.  In the
         //  meantime, we'll create the socket pair manually.
         static int socketpair (int domain_, int type_, int protocol_,
             int sv_ [2]);

#endif

#if defined ZMQ_HAVE_EVENTFD
        //  Eventfd descriptor.
        fd_t fd;
#else
        //  Write & read end of the socketpair.
        fd_t w;
        fd_t r;
#endif

        //  Disable copying of fd_signeler object.
        signaler_t (const signaler_t&);
        void operator = (const signaler_t&);
    };

}

#endif
