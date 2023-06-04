/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_EPOLL_HPP_INCLUDED__
#define __ZMQ_EPOLL_HPP_INCLUDED__

//  poller.hpp decides which polling mechanism to use.
#include "poller.hpp"
#if defined ZMQ_IOTHREAD_POLLER_USE_EPOLL

#include <vector>

#if defined ZMQ_HAVE_WINDOWS
#include "../external/wepoll/wepoll.h"
#else
#include <sys/epoll.h>
#endif

#include "ctx.hpp"
#include "fd.hpp"
#include "thread.hpp"
#include "poller_base.hpp"
#include "mutex.hpp"

namespace zmq
{
struct i_poll_events;

//  This class implements socket polling mechanism using the Linux-specific
//  epoll mechanism.

class epoll_t ZMQ_FINAL : public worker_poller_base_t
{
  public:
    typedef void *handle_t;

    epoll_t (const thread_ctx_t &ctx_);
    ~epoll_t () ZMQ_OVERRIDE;

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
#if defined ZMQ_HAVE_WINDOWS
    typedef HANDLE epoll_fd_t;
    static const epoll_fd_t epoll_retired_fd;
#else
    typedef fd_t epoll_fd_t;
    enum
    {
        epoll_retired_fd = retired_fd
    };
#endif

    //  Main event loop.
    void loop () ZMQ_OVERRIDE;

    //  Main epoll file descriptor
    epoll_fd_t _epoll_fd;

    struct poll_entry_t
    {
        fd_t fd;
        epoll_event ev;
        zmq::i_poll_events *events;
    };

    //  List of retired event sources.
    typedef std::vector<poll_entry_t *> retired_t;
    retired_t _retired;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (epoll_t)
};

typedef epoll_t poller_t;
}

#endif

#endif
