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

#ifndef __ZMQ_POLLER_BASE_HPP_INCLUDED__
#define __ZMQ_POLLER_BASE_HPP_INCLUDED__

#include <map>

#include "clock.hpp"
#include "atomic_counter.hpp"
#include "ctx.hpp"

namespace zmq
{
struct i_poll_events;

// A build of libzmq must provide an implementation of the poller_t concept. By
// convention, this is done via a typedef.
//
// At the time of writing, the following implementations of the poller_t
// concept exist: zmq::devpoll_t, zmq::epoll_t, zmq::kqueue_t, zmq::poll_t,
// zmq::pollset_t, zmq::select_t
//
// An implementation of the poller_t concept must provide the following public
// methods:
//   Returns load of the poller.
// int get_load() const;
//
//   Add a timeout to expire in timeout_ milliseconds. After the
//   expiration, timer_event on sink_ object will be called with
//   argument set to id_.
// void add_timer(int timeout_, zmq::i_poll_events *sink_, int id_);
//
//   Cancel the timer created by sink_ object with ID equal to id_.
// void cancel_timer(zmq::i_poll_events *sink_, int id_);
//
//   Adds a fd to the poller. Initially, no events are activated. These must
//   be activated by the set_* methods using the returned handle_.
// handle_t add_fd(fd_t fd_, zmq::i_poll_events *events_);
//
//   Deactivates any events that may be active for the given handle_, and
//   removes the fd associated with the given handle_.
// void rm_fd(handle_t handle_);
//
//   The set_* and reset_* methods activate resp. deactivate polling for
//   input/output readiness on the respective handle_, such that the
//   in_event/out_event methods on the associated zmq::i_poll_events object
//   will be called.
//   Note: while handle_t and fd_t may be the same type, and may even have the
//   same values for some implementation, this may not be assumed in general.
//   The methods may only be called with the handle returned by add_fd.
// void set_pollin(handle_t handle_);
// void reset_pollin(handle_t handle_);
// void set_pollout(handle_t handle_);//
// void reset_pollout(handle_t handle_);
//
//   Starts operation of the poller. See below for details.
// void start();
//
//   Request termination of the poller.
//   TODO: might be removed in the future, as it has no effect.
// void stop();
//
//   Returns the maximum number of fds that can be added to an instance of the
//   poller at the same time, or -1 if there is no such fixed limit.
// static int max_fds();
//
// Most of the methods may only be called from a zmq::i_poll_events callback
// function when invoked by the poller (and, therefore, typically from the
// poller's worker thread), with the following exceptions:
// - get_load may be called from outside
// - add_fd and add_timer may be called from outside before start
// - start may be called from outside once
//
// After a poller is started, it waits for the registered events (input/output
// readiness, timeout) to happen, and calls the respective functions on the
// zmq::i_poll_events object. It terminates when no further registrations (fds
// or timers) exist.
//
// Before start, add_fd must have been called at least once. Behavior may be
// undefined otherwise.
//
// If the poller is implemented by a single worker thread (the
// worker_poller_base_t base  class may be used to implement such a poller),
// no synchronization is required for the data structures modified by
// add_fd, rm_fd, add_timer, cancel_timer, (re)set_poll(in|out). However,
// reentrancy must be considered, e.g. when one of the functions modifies
// a container that is being iterated by the poller.


// A class that can be used as a base class for implementations of the poller
// concept.
//
// For documentation of the public methods, see the description of the poller_t
// concept.
class poller_base_t
{
  public:
    poller_base_t ();
    virtual ~poller_base_t ();

    // Methods from the poller concept.
    int get_load () const;
    void add_timer (int timeout_, zmq::i_poll_events *sink_, int id_);
    void cancel_timer (zmq::i_poll_events *sink_, int id_);

  protected:
    //  Called by individual poller implementations to manage the load.
    void adjust_load (int amount_);

    //  Executes any timers that are due. Returns number of milliseconds
    //  to wait to match the next timer or 0 meaning "no timers".
    uint64_t execute_timers ();

  private:
    //  Clock instance private to this I/O thread.
    clock_t _clock;

    //  List of active timers.
    struct timer_info_t
    {
        zmq::i_poll_events *sink;
        int id;
    };
    typedef std::multimap<uint64_t, timer_info_t> timers_t;
    timers_t _timers;

    //  Load of the poller. Currently the number of file descriptors
    //  registered.
    atomic_counter_t _load;

    poller_base_t (const poller_base_t &);
    const poller_base_t &operator= (const poller_base_t &);
};

//  Base class for a poller with a single worker thread.
class worker_poller_base_t : public poller_base_t
{
  public:
    worker_poller_base_t (const thread_ctx_t &ctx_);

    // Methods from the poller concept.
    void start (const char *name = NULL);

  protected:
    //  Checks whether the currently executing thread is the worker thread
    //  via an assertion.
    //  Should be called by the add_fd, removed_fd, set_*, reset_* functions
    //  to ensure correct usage.
    void check_thread ();

    //  Stops the worker thread. Should be called from the destructor of the
    //  leaf class.
    void stop_worker ();

  private:
    //  Main worker thread routine.
    static void worker_routine (void *arg_);

    virtual void loop () = 0;

    // Reference to ZMQ context.
    const thread_ctx_t &_ctx;

    //  Handle of the physical thread doing the I/O work.
    thread_t _worker;
};
}

#endif
