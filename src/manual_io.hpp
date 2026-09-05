/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_MANUAL_IO_HPP_INCLUDED__
#define __ZMQ_MANUAL_IO_HPP_INCLUDED__

#include "poller.hpp"

#if defined ZMQ_BUILD_DRAFT_API && !defined ZMQ_HAVE_VXWORKS                   \
  && !defined ZMQ_HAVE_OPENPGM && !defined ZMQ_HAVE_NORM                       \
  && (defined ZMQ_IOTHREAD_POLLER_USE_EPOLL                                    \
      || defined ZMQ_IOTHREAD_POLLER_USE_KQUEUE                                \
      || defined ZMQ_IOTHREAD_POLLER_USE_POLL                                  \
      || defined ZMQ_IOTHREAD_POLLER_USE_SELECT)
#define ZMQ_HAVE_MANUAL_IO 1

#include "i_poll_events.hpp"
#include "mailbox.hpp"
#include "mutex.hpp"
#include "thread.hpp"
#include <list>

namespace zmq
{
class manual_mailbox_t;
//  One wait set for all actors. This class and its handles are never exported.
class ZMQ_PRIVATE manual_io_t : public i_poll_events
{
  public:
    manual_io_t (const thread_ctx_t &ctx_);
    ~manual_io_t ();

    bool enter ();
    void leave ();
    poller_t *poller () { return &_poller; }
    mailbox_t *term_mailbox () { return &_term_mailbox; }
    bool valid () const { return _term_mailbox.valid (); }
    bool done () const { return _done; }
    bool begin_worker_stop ()
    {
        if (_workers_stopping)
            return false;
        _workers_stopping = true;
        return true;
    }
    bool has_workers ()
    {
        return _poller.get_load () > 1 || _poller.next_timer_delay () >= 0;
    }
    int run (const zmq_ctx_step_budget_t &budget_,
             zmq_ctx_step_result_t *result_);
    poller_step_t &state () { return *_state; }
    void defer (manual_mailbox_t *mailbox_);
    void cancel (manual_mailbox_t *mailbox_);
    void completed () { _done = true; }

    void in_event ();
    void out_event ();
    void timer_event (int id_);

  private:
    poller_t _poller;
    manual_mailbox_channel_t _term_mailbox;
    poller_t::handle_t _term_handle;
    mutex_t _sync;
    thread_t _owner;
    bool _active;
    bool _done;
    poller_step_t *_state;
    manual_mailbox_t *_term_receiver;
    std::list<manual_mailbox_t *> _pending;
    bool _pending_first;
    bool _workers_stopping;

    void resume_pending ();

    ZMQ_NON_COPYABLE_NOR_MOVABLE (manual_io_t)
};

//  Selected only for manual actors. The normal receiver callbacks stay intact.
class ZMQ_PRIVATE manual_mailbox_t : public i_poll_events
{
  public:
    typedef void (*callback_t) (manual_mailbox_t *, bool);
    manual_mailbox_t (manual_io_t &driver_,
                      i_mailbox &mailbox_,
                      callback_t callback_ = NULL,
                      void *arg_ = NULL);
    ~manual_mailbox_t ();
    bool drain ();
    void *arg () const { return _arg; }
    void in_event ();
    void out_event ();
    void timer_event (int id_);

  private:
    friend class manual_io_t;
    void dispatch (bool notification_);
    manual_io_t &_driver;
    i_mailbox &_mailbox;
    callback_t _callback;
    void *_arg;
    command_t _command;
    bool _has_command;
    bool _queued;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (manual_mailbox_t)
};
}
#endif

#endif
