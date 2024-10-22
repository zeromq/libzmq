/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __WS_CONNECTER_HPP_INCLUDED__
#define __WS_CONNECTER_HPP_INCLUDED__

#include "fd.hpp"
#include "stdint.hpp"
#include "stream_connecter_base.hpp"

namespace zmq
{
class ws_connecter_t ZMQ_FINAL : public stream_connecter_base_t
{
  public:
    //  If 'delayed_start' is true connecter first waits for a while,
    //  then starts connection process.
    ws_connecter_t (zmq::io_thread_t *io_thread_,
                    zmq::session_base_t *session_,
                    const options_t &options_,
                    address_t *addr_,
                    bool delayed_start_,
                    bool wss_,
                    const std::string &tls_hostname_);
    ~ws_connecter_t ();

  protected:
    void create_engine (fd_t fd, const std::string &local_address_);

  private:
    //  ID of the timer used to check the connect timeout, must be different from stream_connecter_base_t::reconnect_timer_id.
    enum
    {
        connect_timer_id = 2
    };

    //  Handlers for incoming commands.
    void process_term (int linger_);

    //  Handlers for I/O events.
    void out_event ();
    void timer_event (int id_);

    //  Internal function to start the actual connection establishment.
    void start_connecting ();

    //  Internal function to add a connect timer
    void add_connect_timer ();

    //  Open TCP connecting socket. Returns -1 in case of error,
    //  0 if connect was successful immediately. Returns -1 with
    //  EAGAIN errno if async connect was launched.
    int open ();

    //  Get the file descriptor of newly created connection. Returns
    //  retired_fd if the connection was unsuccessful.
    fd_t connect ();

    //  Tunes a connected socket.
    bool tune_socket (fd_t fd_);

    //  True iff a timer has been started.
    bool _connect_timer_started;

    bool _wss;
    const std::string &_hostname;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (ws_connecter_t)
};
}

#endif
