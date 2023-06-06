/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_REAPER_HPP_INCLUDED__
#define __ZMQ_REAPER_HPP_INCLUDED__

#include "object.hpp"
#include "mailbox.hpp"
#include "poller.hpp"
#include "i_poll_events.hpp"

namespace zmq
{
class ctx_t;
class socket_base_t;

class reaper_t ZMQ_FINAL : public object_t, public i_poll_events
{
  public:
    reaper_t (zmq::ctx_t *ctx_, uint32_t tid_);
    ~reaper_t ();

    mailbox_t *get_mailbox ();

    void start ();
    void stop ();

    //  i_poll_events implementation.
    void in_event ();
    void out_event ();
    void timer_event (int id_);

  private:
    //  Command handlers.
    void process_stop ();
    void process_reap (zmq::socket_base_t *socket_);
    void process_reaped ();

    //  Reaper thread accesses incoming commands via this mailbox.
    mailbox_t _mailbox;

    //  Handle associated with mailbox' file descriptor.
    poller_t::handle_t _mailbox_handle;

    //  I/O multiplexing is performed using a poller object.
    poller_t *_poller;

    //  Number of sockets being reaped at the moment.
    int _sockets;

    //  If true, we were already asked to terminate.
    bool _terminating;

#ifdef HAVE_FORK
    // the process that created this context. Used to detect forking.
    pid_t _pid;
#endif

    ZMQ_NON_COPYABLE_NOR_MOVABLE (reaper_t)
};
}

#endif
