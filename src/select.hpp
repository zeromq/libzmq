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

#ifndef __ZMQ_SELECT_HPP_INCLUDED__
#define __ZMQ_SELECT_HPP_INCLUDED__

//  poller.hpp decides which polling mechanism to use.
#include "poller.hpp"
#if defined ZMQ_USE_SELECT

#include <stddef.h>
#include <vector>
#include <map>

#if defined ZMQ_HAVE_WINDOWS
#elif defined ZMQ_HAVE_OPENVMS
#include <sys/types.h>
#include <sys/time.h>
#else
#include <sys/select.h>
#endif

#include "ctx.hpp"
#include "fd.hpp"
#include "thread.hpp"
#include "poller_base.hpp"

namespace zmq
{

    struct i_poll_events;

    //  Implements socket polling mechanism using POSIX.1-2001 select()
    //  function.

    class select_t : public poller_base_t
    {
    public:

        typedef fd_t handle_t;

        select_t (const ctx_t &ctx_);
        ~select_t ();

        //  "poller" concept.
        handle_t add_fd (fd_t fd_, zmq::i_poll_events *events_);
        void rm_fd (handle_t handle_);
        void set_pollin (handle_t handle_);
        void reset_pollin (handle_t handle_);
        void set_pollout (handle_t handle_);
        void reset_pollout (handle_t handle_);
        void start ();
        void stop ();

        static int max_fds ();

    private:

        //  Main worker thread routine.
        static void worker_routine (void *arg_);

        //  Main event loop.
        void loop ();

        //  Reference to ZMQ context.
        const ctx_t &ctx;

        //  Internal state.
        struct fds_set_t
        {
            fds_set_t ();
            fds_set_t (const fds_set_t& other_);
            fds_set_t& operator=(const fds_set_t& other_);
            //  Convinient method to descriptor from all sets.
            void remove_fd (const fd_t& fd_);

            fd_set read;
            fd_set write;
            fd_set error;
        };

        struct fd_entry_t
        {
            fd_t fd;
            zmq::i_poll_events* events;
        };
        typedef std::vector<fd_entry_t> fd_entries_t;

#if defined ZMQ_HAVE_WINDOWS
        struct family_entry_t
        {
            family_entry_t ();

            fd_entries_t fd_entries;
            fds_set_t fds_set;
            bool retired;
        };
        typedef std::map<u_short, family_entry_t> family_entries_t;

        struct wsa_events_t
        {
            wsa_events_t ();
            ~wsa_events_t ();

            //  read, write, error and readwrite
            WSAEVENT events [4];
        };
#endif

#if defined ZMQ_HAVE_WINDOWS
        family_entries_t family_entries;
        // See loop for details.
        family_entries_t::iterator current_family_entry_it;
#else
        fd_entries_t fd_entries;
        fds_set_t fds_set;
        fd_t maxfd;
        bool retired;
#endif

#if defined ZMQ_HAVE_WINDOWS
        //  Socket's family or AF_UNSPEC on error.
        static u_short get_fd_family (fd_t fd_);
#endif
        //  Checks if an fd_entry_t is retired.
        static bool is_retired_fd (const fd_entry_t &entry);

        //  If true, thread is shutting down.
        bool stopping;

        //  Handle of the physical thread doing the I/O work.
        thread_t worker;

        select_t (const select_t&);
        const select_t &operator = (const select_t&);
    };

    typedef select_t poller_t;

}

#endif

#endif
