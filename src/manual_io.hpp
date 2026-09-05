/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_MANUAL_IO_HPP_INCLUDED__
#define __ZMQ_MANUAL_IO_HPP_INCLUDED__

#include "poller.hpp"

#if defined ZMQ_BUILD_DRAFT_API && !defined ZMQ_HAVE_VXWORKS                  \
  && !defined ZMQ_HAVE_OPENPGM && !defined ZMQ_HAVE_NORM                      \
  && (defined ZMQ_IOTHREAD_POLLER_USE_EPOLL                                  \
      || defined ZMQ_IOTHREAD_POLLER_USE_KQUEUE                              \
      || defined ZMQ_IOTHREAD_POLLER_USE_POLL                                \
      || defined ZMQ_IOTHREAD_POLLER_USE_SELECT)
#define ZMQ_HAVE_MANUAL_IO 1

#include "i_poll_events.hpp"
#include "mailbox.hpp"
#include "mutex.hpp"
#include "thread.hpp"

namespace zmq
{
//  One wait set for all actors. This class and its handles are never exported.
class manual_io_t : public i_poll_events
{
  public:
    manual_io_t (const thread_ctx_t &ctx_, mailbox_t &term_mailbox_);
    ~manual_io_t ();

    bool enter ();
    void leave ();
    poller_t *poller () { return &_poller; }
    bool done () const { return _done; }

    void in_event ();
    void out_event ();
    void timer_event (int id_);

  private:
    poller_t _poller;
    mailbox_t &_term_mailbox;
    poller_t::handle_t _term_handle;
    mutex_t _sync;
    thread_t _owner;
    bool _active;
    bool _done;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (manual_io_t)
};
}
#endif

#endif
