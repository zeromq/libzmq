/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_SELECT_HPP_INCLUDED__
#define __ZMQ_SELECT_HPP_INCLUDED__

//  poller.hpp decides which polling mechanism to use.
#include "poller.hpp"
#if defined ZMQ_IOTHREAD_POLLER_USE_SELECT

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
#include "poller_base.hpp"

namespace zmq
{
struct i_poll_events;

//  Implements socket polling mechanism using POSIX.1-2001 select()
//  function.

class select_t ZMQ_FINAL : public worker_poller_base_t
{
  public:
    typedef fd_t handle_t;

    select_t (const thread_ctx_t &ctx_);
    ~select_t () ZMQ_FINAL;

    //  "poller" concept.
    handle_t add_fd (fd_t fd_, zmq::i_poll_events *events_);
    void rm_fd (handle_t handle_);
    void set_pollin (handle_t handle_);
    void reset_pollin (handle_t handle_);
    void set_pollout (handle_t handle_);
    void reset_pollout (handle_t handle_);
    void stop ();

    static int max_fds ();

  private:
    //  Main event loop.
    void loop () ZMQ_FINAL;

    //  Internal state.
    struct fds_set_t
    {
        fds_set_t ();
        fds_set_t (const fds_set_t &other_);
        fds_set_t &operator= (const fds_set_t &other_);
        //  Convenience method to descriptor from all sets.
        void remove_fd (const fd_t &fd_);

        fd_set read;
        fd_set write;
        fd_set error;
    };

    struct fd_entry_t
    {
        fd_t fd;
        zmq::i_poll_events *events;
    };
    typedef std::vector<fd_entry_t> fd_entries_t;

    void trigger_events (const fd_entries_t &fd_entries_,
                         const fds_set_t &local_fds_set_,
                         int event_count_);

    struct family_entry_t
    {
        family_entry_t ();

        fd_entries_t fd_entries;
        fds_set_t fds_set;
        bool has_retired;
    };

    void select_family_entry (family_entry_t &family_entry_,
                              int max_fd_,
                              bool use_timeout_,
                              struct timeval &tv_);

#if defined ZMQ_HAVE_WINDOWS
    typedef std::map<u_short, family_entry_t> family_entries_t;

    struct wsa_events_t
    {
        wsa_events_t ();
        ~wsa_events_t ();

        //  read, write, error and readwrite
        WSAEVENT events[4];
    };

    family_entries_t _family_entries;
    // See loop for details.
    family_entries_t::iterator _current_family_entry_it;

    int try_retire_fd_entry (family_entries_t::iterator family_entry_it_,
                             zmq::fd_t &handle_);

    static const size_t fd_family_cache_size = 8;
    std::pair<fd_t, u_short> _fd_family_cache[fd_family_cache_size];

    u_short get_fd_family (fd_t fd_);

    //  Socket's family or AF_UNSPEC on error.
    static u_short determine_fd_family (fd_t fd_);
#else
    //  on non-Windows, we can treat all fds as one family
    family_entry_t _family_entry;
    fd_t _max_fd;
#endif

    void cleanup_retired ();
    bool cleanup_retired (family_entry_t &family_entry_);

    //  Checks if an fd_entry_t is retired.
    static bool is_retired_fd (const fd_entry_t &entry_);

    static fd_entries_t::iterator
    find_fd_entry_by_handle (fd_entries_t &fd_entries_, handle_t handle_);

    ZMQ_NON_COPYABLE_NOR_MOVABLE (select_t)
};

typedef select_t poller_t;
}

#endif

#endif
