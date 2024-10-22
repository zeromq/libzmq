/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __IPC_CONNECTER_HPP_INCLUDED__
#define __IPC_CONNECTER_HPP_INCLUDED__

#if defined ZMQ_HAVE_IPC

#include "fd.hpp"
#include "stream_connecter_base.hpp"

namespace zmq
{
class ipc_connecter_t ZMQ_FINAL : public stream_connecter_base_t
{
  public:
    //  If 'delayed_start' is true connecter first waits for a while,
    //  then starts connection process.
    ipc_connecter_t (zmq::io_thread_t *io_thread_,
                     zmq::session_base_t *session_,
                     const options_t &options_,
                     address_t *addr_,
                     bool delayed_start_);

  private:
    //  Handlers for I/O events.
    void out_event ();

    //  Internal function to start the actual connection establishment.
    void start_connecting ();

    //  Open IPC connecting socket. Returns -1 in case of error,
    //  0 if connect was successful immediately. Returns -1 with
    //  EAGAIN errno if async connect was launched.
    int open ();

    //  Get the file descriptor of newly created connection. Returns
    //  retired_fd if the connection was unsuccessful.
    fd_t connect ();

    ZMQ_NON_COPYABLE_NOR_MOVABLE (ipc_connecter_t)
};
}

#endif

#endif
