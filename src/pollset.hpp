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

#ifndef __ZMQ_POLLSET_HPP_INCLUDED__
#define __ZMQ_POLLSET_HPP_INCLUDED__

//  poller.hpp decides which polling mechanism to use.
#include "poller.hpp"
#if defined ZMQ_IOTHREAD_POLLER_USE_POLLSET

#include <sys/poll.h>
#include <sys/pollset.h>
#include <vector>

#include "ctx.hpp"
#include "fd.hpp"
#include "thread.hpp"
#include "poller_base.hpp"

namespace zmq
{
struct i_poll_events;

//  This class implements socket polling mechanism using the AIX-specific
//  pollset mechanism.

class pollset_t ZMQ_FINAL : public poller_base_t
{
  public:
    typedef void *handle_t;

    pollset_t (const thread_ctx_t &ctx_);
    ~pollset_t () ZMQ_FINAL;

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
    void loop () ZMQ_FINAL;

    // Reference to ZMQ context.
    const thread_ctx_t &ctx;

    //  Main pollset file descriptor
    ::pollset_t pollset_fd;

    struct poll_entry_t
    {
        fd_t fd;
        bool flag_pollin;
        bool flag_pollout;
        zmq::i_poll_events *events;
    };

    //  List of retired event sources.
    typedef std::vector<poll_entry_t *> retired_t;
    retired_t retired;

    //  This table stores data for registered descriptors.
    typedef std::vector<poll_entry_t *> fd_table_t;
    fd_table_t fd_table;

    //  If true, thread is in the process of shutting down.
    bool stopping;

    //  Handle of the physical thread doing the I/O work.
    thread_t worker;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (pollset_t)
};

typedef pollset_t poller_t;
}

#endif

#endif
