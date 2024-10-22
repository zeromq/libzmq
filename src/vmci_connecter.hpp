/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_VMCI_CONNECTER_HPP_INCLUDED__
#define __ZMQ_VMCI_CONNECTER_HPP_INCLUDED__

#include "platform.hpp"

#if defined ZMQ_HAVE_VMCI

#include "fd.hpp"
#include "own.hpp"
#include "stdint.hpp"
#include "io_object.hpp"
#include "stream_connecter_base.hpp"

namespace zmq
{
class io_thread_t;
class session_base_t;
struct address_t;

class vmci_connecter_t ZMQ_FINAL : public stream_connecter_base_t
{
  public:
    //  If 'delayed_start' is true connecter first waits for a while,
    //  then starts connection process.
    vmci_connecter_t (zmq::io_thread_t *io_thread_,
                      zmq::session_base_t *session_,
                      const options_t &options_,
                      address_t *addr_,
                      bool delayed_start_);
    ~vmci_connecter_t ();

  protected:
    std::string get_socket_name (fd_t fd_, socket_end_t socket_end_) const;

  private:
    //  ID of the timer used to check the connect timeout, must be different from stream_connecter_base_t::reconnect_timer_id.
    enum
    {
        connect_timer_id = 2
    };

    //  Handlers for incoming commands.
    void process_term (int linger_);

    //  Handlers for I/O events.
    void in_event ();
    void out_event ();
    void timer_event (int id_);

    //  Internal function to start the actual connection establishment.
    void start_connecting ();

    //  Internal function to add a connect timer
    void add_connect_timer ();

    //  Internal function to return a reconnect backoff delay.
    //  Will modify the current_reconnect_ivl used for next call
    //  Returns the currently used interval
    int get_new_reconnect_ivl ();

    //  Open VMCI connecting socket. Returns -1 in case of error,
    //  0 if connect was successful immediately. Returns -1 with
    //  EAGAIN errno if async connect was launched.
    int open ();

    //  Get the file descriptor of newly created connection. Returns
    //  retired_fd if the connection was unsuccessful.
    fd_t connect ();

    //  True iff a timer has been started.
    bool _connect_timer_started;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (vmci_connecter_t)
};
}

#endif

#endif
