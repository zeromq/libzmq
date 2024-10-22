/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_IO_THREAD_HPP_INCLUDED__
#define __ZMQ_IO_THREAD_HPP_INCLUDED__

#include "stdint.hpp"
#include "object.hpp"
#include "poller.hpp"
#include "i_poll_events.hpp"
#include "mailbox.hpp"

namespace zmq
{
class ctx_t;

//  Generic part of the I/O thread. Polling-mechanism-specific features
//  are implemented in separate "polling objects".

class io_thread_t ZMQ_FINAL : public object_t, public i_poll_events
{
  public:
    io_thread_t (zmq::ctx_t *ctx_, uint32_t tid_);

    //  Clean-up. If the thread was started, it's necessary to call 'stop'
    //  before invoking destructor. Otherwise the destructor would hang up.
    ~io_thread_t ();

    //  Launch the physical thread.
    void start ();

    //  Ask underlying thread to stop.
    void stop ();

    //  Returns mailbox associated with this I/O thread.
    mailbox_t *get_mailbox ();

    //  i_poll_events implementation.
    void in_event ();
    void out_event ();
    void timer_event (int id_);

    //  Used by io_objects to retrieve the associated poller object.
    poller_t *get_poller () const;

    //  Command handlers.
    void process_stop ();

    //  Returns load experienced by the I/O thread.
    int get_load () const;

  private:
    //  I/O thread accesses incoming commands via this mailbox.
    mailbox_t _mailbox;

    //  Handle associated with mailbox' file descriptor.
    poller_t::handle_t _mailbox_handle;

    //  I/O multiplexing is performed using a poller object.
    poller_t *_poller;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (io_thread_t)
};
}

#endif
