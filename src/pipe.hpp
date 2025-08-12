/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_PIPE_HPP_INCLUDED__
#define __ZMQ_PIPE_HPP_INCLUDED__

#include "ypipe_base.hpp"
#include "config.hpp"
#include "object.hpp"
#include "stdint.hpp"
#include "array.hpp"
#include "blob.hpp"
#include "options.hpp"
#include "endpoint.hpp"
#include "msg.hpp"

namespace zmq
{
class pipe_t;

//  Create a pipepair for bi-directional transfer of messages.
//  First HWM is for messages passed from first pipe to the second pipe.
//  Second HWM is for messages passed from second pipe to the first pipe.
//  Delay specifies how the pipe behaves when the peer terminates. If true
//  pipe receives all the pending messages before terminating, otherwise it
//  terminates straight away.
//  If conflate is true, only the most recently arrived message could be
//  read (older messages are discarded)
int pipepair (zmq::object_t *parents_[2],
              zmq::pipe_t *pipes_[2],
              const int hwms_[2],
              const bool conflate_[2]);

struct i_pipe_events
{
    virtual ~i_pipe_events () ZMQ_DEFAULT;

    virtual void read_activated (zmq::pipe_t *pipe_) = 0;
    virtual void write_activated (zmq::pipe_t *pipe_) = 0;
    virtual void hiccuped (zmq::pipe_t *pipe_) = 0;
    virtual void pipe_terminated (zmq::pipe_t *pipe_) = 0;
};

//  Note that pipe can be stored in three different arrays.
//  The array of inbound pipes (1), the array of outbound pipes (2) and
//  the generic array of pipes to be deallocated (3).

class pipe_t ZMQ_FINAL : public object_t,
                         public array_item_t<1>,
                         public array_item_t<2>,
                         public array_item_t<3>
{
    //  This allows pipepair to create pipe objects.
    friend int pipepair (zmq::object_t *parents_[2],
                         zmq::pipe_t *pipes_[2],
                         const int hwms_[2],
                         const bool conflate_[2]);

  public:
    //  Specifies the object to send events to.
    void set_event_sink (i_pipe_events *sink_);

    //  Pipe endpoint can store an routing ID to be used by its clients.
    void set_server_socket_routing_id (uint32_t server_socket_routing_id_);
    uint32_t get_server_socket_routing_id () const;

    //  Pipe endpoint can store an opaque ID to be used by its clients.
    void set_router_socket_routing_id (const blob_t &router_socket_routing_id_);
    const blob_t &get_routing_id () const;

    //  Returns true if there is at least one message to read in the pipe.
    bool check_read ();

    //  Reads a message to the underlying pipe.
    bool read (msg_t *msg_);

    //  Checks whether messages can be written to the pipe. If the pipe is
    //  closed or if writing the message would cause high watermark the
    //  function returns false.
    bool check_write ();

    //  Writes a message to the underlying pipe. Returns false if the
    //  message does not pass check_write. If false, the message object
    //  retains ownership of its message buffer.
    bool write (const msg_t *msg_);

    //  Remove unfinished parts of the outbound message from the pipe.
    void rollback () const;

    //  Flush the messages downstream.
    void flush ();

    //  Temporarily disconnects the inbound message stream and drops
    //  all the messages on the fly. Causes 'hiccuped' event to be generated
    //  in the peer.
    void hiccup ();

    //  Ensure the pipe won't block on receiving pipe_term.
    void set_nodelay ();

    //  Ask pipe to terminate. The termination will happen asynchronously
    //  and user will be notified about actual deallocation by 'terminated'
    //  event. If delay is true, the pending messages will be processed
    //  before actual shutdown.
    void terminate (bool delay_);

    //  Set the high water marks.
    void set_hwms (int inhwm_, int outhwm_);

    //  Set the boost to high water marks, used by inproc sockets so total hwm are sum of connect and bind sockets watermarks
    void set_hwms_boost (int inhwmboost_, int outhwmboost_);

    // send command to peer for notify the change of hwm
    void send_hwms_to_peer (int inhwm_, int outhwm_);

    //  Returns true if HWM is not reached
    bool check_hwm () const;

    bool is_active () const;

    void set_endpoint_pair (endpoint_uri_pair_t endpoint_pair_);
    const endpoint_uri_pair_t &get_endpoint_pair () const;

    void send_stats_to_peer (own_t *socket_base_);

    void send_disconnect_msg ();
    void set_disconnect_msg (const std::vector<unsigned char> &disconnect_);

    void send_hiccup_msg (const std::vector<unsigned char> &hiccup_);

  private:
    //  Type of the underlying lock-free pipe.
    typedef ypipe_base_t<msg_t> upipe_t;

    //  Command handlers.
    void process_activate_read () ZMQ_OVERRIDE;
    void process_activate_write (uint64_t msgs_read_) ZMQ_OVERRIDE;
    void process_hiccup (void *pipe_) ZMQ_OVERRIDE;
    void
    process_pipe_peer_stats (uint64_t queue_count_,
                             own_t *socket_base_,
                             endpoint_uri_pair_t *endpoint_pair_) ZMQ_OVERRIDE;
    void process_pipe_term () ZMQ_OVERRIDE;
    void process_pipe_term_ack () ZMQ_OVERRIDE;
    void process_pipe_hwm (int inhwm_, int outhwm_) ZMQ_OVERRIDE;

    //  Handler for delimiter read from the pipe.
    void process_delimiter ();

    //  Constructor is private. Pipe can only be created using
    //  pipepair function.
    pipe_t (object_t *parent_,
            upipe_t *inpipe_,
            upipe_t *outpipe_,
            int inhwm_,
            int outhwm_,
            bool conflate_);

    //  Pipepair uses this function to let us know about
    //  the peer pipe object.
    void set_peer (pipe_t *peer_);

    //  Destructor is private. Pipe objects destroy themselves.
    ~pipe_t () ZMQ_OVERRIDE;

    //  Underlying pipes for both directions.
    upipe_t *_in_pipe;
    upipe_t *_out_pipe;

    //  Can the pipe be read from / written to?
    bool _in_active;
    bool _out_active;

    //  High watermark for the outbound pipe.
    int _hwm;

    //  Low watermark for the inbound pipe.
    int _lwm;

    // boosts for high and low watermarks, used with inproc sockets so hwm are sum of send and recv hmws on each side of pipe
    int _in_hwm_boost;
    int _out_hwm_boost;

    //  Number of messages read and written so far.
    uint64_t _msgs_read;
    uint64_t _msgs_written;

    //  Last received peer's msgs_read. The actual number in the peer
    //  can be higher at the moment.
    uint64_t _peers_msgs_read;

    //  The pipe object on the other side of the pipepair.
    pipe_t *_peer;

    //  Sink to send events to.
    i_pipe_events *_sink;

    //  States of the pipe endpoint:
    //  active: common state before any termination begins,
    //  delimiter_received: delimiter was read from pipe before
    //      term command was received,
    //  waiting_for_delimiter: term command was already received
    //      from the peer but there are still pending messages to read,
    //  term_ack_sent: all pending messages were already read and
    //      all we are waiting for is ack from the peer,
    //  term_req_sent1: 'terminate' was explicitly called by the user,
    //  term_req_sent2: user called 'terminate' and then we've got
    //      term command from the peer as well.
    enum
    {
        active,
        delimiter_received,
        waiting_for_delimiter,
        term_ack_sent,
        term_req_sent1,
        term_req_sent2
    } _state;

    //  If true, we receive all the pending inbound messages before
    //  terminating. If false, we terminate immediately when the peer
    //  asks us to.
    bool _delay;

    //  Routing id of the writer. Used uniquely by the reader side.
    blob_t _router_socket_routing_id;

    //  Routing id of the writer. Used uniquely by the reader side.
    int _server_socket_routing_id;

    //  Returns true if the message is delimiter; false otherwise.
    static bool is_delimiter (const msg_t &msg_);

    //  Computes appropriate low watermark from the given high watermark.
    static int compute_lwm (int hwm_);

    const bool _conflate;

    // The endpoints of this pipe.
    endpoint_uri_pair_t _endpoint_pair;

    // Disconnect msg
    msg_t _disconnect_msg;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (pipe_t)
};

void send_routing_id (pipe_t *pipe_, const options_t &options_);

void send_hello_msg (pipe_t *pipe_, const options_t &options_);
}

#endif
