/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_SOCKET_BASE_HPP_INCLUDED__
#define __ZMQ_SOCKET_BASE_HPP_INCLUDED__

#include <string>
#include <map>
#include <stdarg.h>

#include "own.hpp"
#include "array.hpp"
#include "blob.hpp"
#include "stdint.hpp"
#include "poller.hpp"
#include "i_poll_events.hpp"
#include "i_mailbox.hpp"
#include "clock.hpp"
#include "pipe.hpp"
#include "endpoint.hpp"

extern "C" {
void zmq_free_event (void *data_, void *hint_);
}

namespace zmq
{
class ctx_t;
class msg_t;
class pipe_t;

class socket_base_t : public own_t,
                      public array_item_t<>,
                      public i_poll_events,
                      public i_pipe_events
{
    friend class reaper_t;

  public:
    //  Returns false if object is not a socket.
    bool check_tag () const;

    //  Returns whether the socket is thread-safe.
    bool is_thread_safe () const;

    //  Create a socket of a specified type.
    static socket_base_t *
    create (int type_, zmq::ctx_t *parent_, uint32_t tid_, int sid_);

    //  Returns the mailbox associated with this socket.
    i_mailbox *get_mailbox () const;

    //  Interrupt blocking call if the socket is stuck in one.
    //  This function can be called from a different thread!
    void stop ();

    //  Interface for communication with the API layer.
    int setsockopt (int option_, const void *optval_, size_t optvallen_);
    int getsockopt (int option_, void *optval_, size_t *optvallen_);
    int bind (const char *endpoint_uri_);
    int connect (const char *endpoint_uri_);
    int term_endpoint (const char *endpoint_uri_);
    int send (zmq::msg_t *msg_, int flags_);
    int recv (zmq::msg_t *msg_, int flags_);
    void add_signaler (signaler_t *s_);
    void remove_signaler (signaler_t *s_);
    int close ();

    //  These functions are used by the polling mechanism to determine
    //  which events are to be reported from this socket.
    bool has_in ();
    bool has_out ();

    //  Joining and leaving groups
    int join (const char *group_);
    int leave (const char *group_);

    //  Using this function reaper thread ask the socket to register with
    //  its poller.
    void start_reaping (poller_t *poller_);

    //  i_poll_events implementation. This interface is used when socket
    //  is handled by the poller in the reaper thread.
    void in_event ();
    void out_event ();
    void timer_event (int id_);

    //  i_pipe_events interface implementation.
    void read_activated (pipe_t *pipe_);
    void write_activated (pipe_t *pipe_);
    void hiccuped (pipe_t *pipe_);
    void pipe_terminated (pipe_t *pipe_);
    void lock ();
    void unlock ();

    int monitor (const char *endpoint_,
                 uint64_t events_,
                 int event_version_,
                 int type_);

    void event_connected (const endpoint_uri_pair_t &endpoint_uri_pair_,
                          zmq::fd_t fd_);
    void event_connect_delayed (const endpoint_uri_pair_t &endpoint_uri_pair_,
                                int err_);
    void event_connect_retried (const endpoint_uri_pair_t &endpoint_uri_pair_,
                                int interval_);
    void event_listening (const endpoint_uri_pair_t &endpoint_uri_pair_,
                          zmq::fd_t fd_);
    void event_bind_failed (const endpoint_uri_pair_t &endpoint_uri_pair_,
                            int err_);
    void event_accepted (const endpoint_uri_pair_t &endpoint_uri_pair_,
                         zmq::fd_t fd_);
    void event_accept_failed (const endpoint_uri_pair_t &endpoint_uri_pair_,
                              int err_);
    void event_closed (const endpoint_uri_pair_t &endpoint_uri_pair_,
                       zmq::fd_t fd_);
    void event_close_failed (const endpoint_uri_pair_t &endpoint_uri_pair_,
                             int err_);
    void event_disconnected (const endpoint_uri_pair_t &endpoint_uri_pair_,
                             zmq::fd_t fd_);
    void event_handshake_failed_no_detail (
      const endpoint_uri_pair_t &endpoint_uri_pair_, int err_);
    void event_handshake_failed_protocol (
      const endpoint_uri_pair_t &endpoint_uri_pair_, int err_);
    void
    event_handshake_failed_auth (const endpoint_uri_pair_t &endpoint_uri_pair_,
                                 int err_);
    void
    event_handshake_succeeded (const endpoint_uri_pair_t &endpoint_uri_pair_,
                               int err_);

    //  Query the state of a specific peer. The default implementation
    //  always returns an ENOTSUP error.
    virtual int get_peer_state (const void *routing_id_,
                                size_t routing_id_size_) const;

    //  Request for pipes statistics - will generate a ZMQ_EVENT_PIPES_STATS
    //  after gathering the data asynchronously. Requires event monitoring to
    //  be enabled.
    int query_pipes_stats ();

  protected:
    socket_base_t (zmq::ctx_t *parent_,
                   uint32_t tid_,
                   int sid_,
                   bool thread_safe_ = false);
    virtual ~socket_base_t ();

    //  Concrete algorithms for the x- methods are to be defined by
    //  individual socket types.
    virtual void xattach_pipe (zmq::pipe_t *pipe_,
                               bool subscribe_to_all_ = false,
                               bool locally_initiated_ = false) = 0;

    //  The default implementation assumes there are no specific socket
    //  options for the particular socket type. If not so, override this
    //  method.
    virtual int
    xsetsockopt (int option_, const void *optval_, size_t optvallen_);

    //  The default implementation assumes that send is not supported.
    virtual bool xhas_out ();
    virtual int xsend (zmq::msg_t *msg_);

    //  The default implementation assumes that recv in not supported.
    virtual bool xhas_in ();
    virtual int xrecv (zmq::msg_t *msg_);

    //  i_pipe_events will be forwarded to these functions.
    virtual void xread_activated (pipe_t *pipe_);
    virtual void xwrite_activated (pipe_t *pipe_);
    virtual void xhiccuped (pipe_t *pipe_);
    virtual void xpipe_terminated (pipe_t *pipe_) = 0;

    //  the default implementation assumes that joub and leave are not supported.
    virtual int xjoin (const char *group_);
    virtual int xleave (const char *group_);

    //  Delay actual destruction of the socket.
    void process_destroy ();

  private:
    // test if event should be sent and then dispatch it
    void event (const endpoint_uri_pair_t &endpoint_uri_pair_,
                uint64_t values_[],
                uint64_t values_count_,
                uint64_t type_);

    // Socket event data dispatch
    void monitor_event (uint64_t event_,
                        uint64_t values_[],
                        uint64_t values_count_,
                        const endpoint_uri_pair_t &endpoint_uri_pair_) const;

    // Monitor socket cleanup
    void stop_monitor (bool send_monitor_stopped_event_ = true);

    //  Creates new endpoint ID and adds the endpoint to the map.
    void add_endpoint (const endpoint_uri_pair_t &endpoint_pair_,
                       own_t *endpoint_,
                       pipe_t *pipe_);

    //  Map of open endpoints.
    typedef std::pair<own_t *, pipe_t *> endpoint_pipe_t;
    typedef std::multimap<std::string, endpoint_pipe_t> endpoints_t;
    endpoints_t _endpoints;

    //  Map of open inproc endpoints.
    class inprocs_t
    {
      public:
        void emplace (const char *endpoint_uri_, pipe_t *pipe_);
        int erase_pipes (const std::string &endpoint_uri_str_);
        void erase_pipe (pipe_t *pipe_);

      private:
        typedef std::multimap<std::string, pipe_t *> map_t;
        map_t _inprocs;
    };
    inprocs_t _inprocs;

    //  To be called after processing commands or invoking any command
    //  handlers explicitly. If required, it will deallocate the socket.
    void check_destroy ();

    //  Moves the flags from the message to local variables,
    //  to be later retrieved by getsockopt.
    void extract_flags (msg_t *msg_);

    //  Used to check whether the object is a socket.
    uint32_t _tag;

    //  If true, associated context was already terminated.
    bool _ctx_terminated;

    //  If true, object should have been already destroyed. However,
    //  destruction is delayed while we unwind the stack to the point
    //  where it doesn't intersect the object being destroyed.
    bool _destroyed;

    //  Parse URI string.
    static int
    parse_uri (const char *uri_, std::string &protocol_, std::string &path_);

    //  Check whether transport protocol, as specified in connect or
    //  bind, is available and compatible with the socket type.
    int check_protocol (const std::string &protocol_) const;

    //  Register the pipe with this socket.
    void attach_pipe (zmq::pipe_t *pipe_,
                      bool subscribe_to_all_ = false,
                      bool locally_initiated_ = false);

    //  Processes commands sent to this socket (if any). If timeout is -1,
    //  returns only after at least one command was processed.
    //  If throttle argument is true, commands are processed at most once
    //  in a predefined time period.
    int process_commands (int timeout_, bool throttle_);

    //  Handlers for incoming commands.
    void process_stop ();
    void process_bind (zmq::pipe_t *pipe_);
    void process_pipe_stats_publish (uint64_t outbound_queue_count_,
                                     uint64_t inbound_queue_count_,
                                     endpoint_uri_pair_t *endpoint_pair_);
    void process_term (int linger_);
    void process_term_endpoint (std::string *endpoint_);

    void update_pipe_options (int option_);

    std::string resolve_tcp_addr (std::string endpoint_uri_,
                                  const char *tcp_address_);

    //  Socket's mailbox object.
    i_mailbox *_mailbox;

    //  List of attached pipes.
    typedef array_t<pipe_t, 3> pipes_t;
    pipes_t _pipes;

    //  Reaper's poller and handle of this socket within it.
    poller_t *_poller;
    poller_t::handle_t _handle;

    //  Timestamp of when commands were processed the last time.
    uint64_t _last_tsc;

    //  Number of messages received since last command processing.
    int _ticks;

    //  True if the last message received had MORE flag set.
    bool _rcvmore;

    //  Improves efficiency of time measurement.
    clock_t _clock;

    // Monitor socket;
    void *_monitor_socket;

    // Bitmask of events being monitored
    int64_t _monitor_events;

    // Last socket endpoint resolved URI
    std::string _last_endpoint;

    // Indicate if the socket is thread safe
    const bool _thread_safe;

    // Signaler to be used in the reaping stage
    signaler_t *_reaper_signaler;

    // Mutex for synchronize access to the socket in thread safe mode
    mutex_t _sync;

    // Mutex to synchronize access to the monitor Pair socket
    mutex_t _monitor_sync;

    socket_base_t (const socket_base_t &);
    const socket_base_t &operator= (const socket_base_t &);
};

class routing_socket_base_t : public socket_base_t
{
  protected:
    routing_socket_base_t (class ctx_t *parent_, uint32_t tid_, int sid_);
    ~routing_socket_base_t ();

    // methods from socket_base_t
    virtual int
    xsetsockopt (int option_, const void *optval_, size_t optvallen_);
    virtual void xwrite_activated (pipe_t *pipe_);

    // own methods
    std::string extract_connect_routing_id ();
    bool connect_routing_id_is_set () const;

    struct out_pipe_t
    {
        pipe_t *pipe;
        bool active;
    };

    void add_out_pipe (blob_t routing_id_, pipe_t *pipe_);
    bool has_out_pipe (const blob_t &routing_id_) const;
    out_pipe_t *lookup_out_pipe (const blob_t &routing_id_);
    const out_pipe_t *lookup_out_pipe (const blob_t &routing_id_) const;
    void erase_out_pipe (pipe_t *pipe_);
    out_pipe_t try_erase_out_pipe (const blob_t &routing_id_);
    template <typename Func> bool any_of_out_pipes (Func func_)
    {
        bool res = false;
        for (out_pipes_t::iterator it = _out_pipes.begin ();
             it != _out_pipes.end () && !res; ++it) {
            res |= func_ (*it->second.pipe);
        }

        return res;
    }

  private:
    //  Outbound pipes indexed by the peer IDs.
    typedef std::map<blob_t, out_pipe_t> out_pipes_t;
    out_pipes_t _out_pipes;

    // Next assigned name on a zmq_connect() call used by ROUTER and STREAM socket types
    std::string _connect_routing_id;
};
}

#endif
