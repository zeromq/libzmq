/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_SIGNALER_HPP_INCLUDED__
#define __ZMQ_SIGNALER_HPP_INCLUDED__

#ifdef HAVE_FORK
#include <unistd.h>
#endif

#include "fd.hpp"

namespace zmq
{

    //  This is a cross-platform equivalent to signal_fd. However, as opposed
    //  to signal_fd there can be at most one signal in the signaler at any
    //  given moment. Attempt to send a signal before receiving the previous
    //  one will result in undefined behaviour.

    class signaler_t
    {
    public:

        signaler_t ();
        ~signaler_t ();

        fd_t get_fd () const;
        void send ();
        int wait (int timeout_);
        void recv ();

#ifdef HAVE_FORK
        // close the file descriptors in a forked child process so that they
        // do not interfere with the context in the parent process.
        void forked ();
#endif

    private:

        //  Creates a pair of filedescriptors that will be used
        //  to pass the signals.
        static int make_fdpair (fd_t *r_, fd_t *w_);

        //  Underlying write & read file descriptor
        //  Will be -1 if we exceeded number of available handles
        fd_t w;
        fd_t r;

        //  Disable copying of signaler_t object.
        signaler_t (const signaler_t&);
        const signaler_t &operator = (const signaler_t&);

#ifdef HAVE_FORK
        // the process that created this context. Used to detect forking.
        pid_t pid;
        // idempotent close of file descriptors that is safe to use by destructor
        // and forked().
        void close_internal ();
#endif
    };
}

#endif
