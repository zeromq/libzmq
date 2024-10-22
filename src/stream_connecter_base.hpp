/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __STREAM_CONNECTER_BASE_HPP_INCLUDED__
#define __STREAM_CONNECTER_BASE_HPP_INCLUDED__

#include "fd.hpp"
#include "own.hpp"
#include "io_object.hpp"

namespace zmq
{
class io_thread_t;
class session_base_t;
struct address_t;

class stream_connecter_base_t : public own_t, public io_object_t
{
  public:
    //  If 'delayed_start' is true connecter first waits for a while,
    //  then starts connection process.
    stream_connecter_base_t (zmq::io_thread_t *io_thread_,
                             zmq::session_base_t *session_,
                             const options_t &options_,
                             address_t *addr_,
                             bool delayed_start_);

    ~stream_connecter_base_t () ZMQ_OVERRIDE;

  protected:
    //  Handlers for incoming commands.
    void process_plug () ZMQ_FINAL;
    void process_term (int linger_) ZMQ_OVERRIDE;

    //  Handlers for I/O events.
    void in_event () ZMQ_OVERRIDE;
    void timer_event (int id_) ZMQ_OVERRIDE;

    //  Internal function to create the engine after connection was established.
    virtual void create_engine (fd_t fd, const std::string &local_address_);

    //  Internal function to add a reconnect timer
    void add_reconnect_timer ();

    //  Removes the handle from the poller.
    void rm_handle ();

    //  Close the connecting socket.
    void close ();

    //  Address to connect to. Owned by session_base_t.
    //  It is non-const since some parts may change during opening.
    address_t *const _addr;

    //  Underlying socket.
    fd_t _s;

    //  Handle corresponding to the listening socket, if file descriptor is
    //  registered with the poller, or NULL.
    handle_t _handle;

    // String representation of endpoint to connect to
    std::string _endpoint;

    // Socket
    zmq::socket_base_t *const _socket;

  private:
    //  ID of the timer used to delay the reconnection.
    enum
    {
        reconnect_timer_id = 1
    };

    //  Internal function to return a reconnect backoff delay.
    //  Will modify the current_reconnect_ivl used for next call
    //  Returns the currently used interval
    int get_new_reconnect_ivl ();

    virtual void start_connecting () = 0;

    //  If true, connecter is waiting a while before trying to connect.
    const bool _delayed_start;

    //  True iff a timer has been started.
    bool _reconnect_timer_started;

    //  Current reconnect ivl, updated for backoff strategy
    int _current_reconnect_ivl;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (stream_connecter_base_t)

  protected:
    //  Reference to the session we belong to.
    zmq::session_base_t *const _session;
};
}

#endif
