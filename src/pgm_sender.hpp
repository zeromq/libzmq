/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_PGM_SENDER_HPP_INCLUDED__
#define __ZMQ_PGM_SENDER_HPP_INCLUDED__

#if defined ZMQ_HAVE_OPENPGM

#include "stdint.hpp"
#include "io_object.hpp"
#include "i_engine.hpp"
#include "options.hpp"
#include "pgm_socket.hpp"
#include "v1_encoder.hpp"
#include "msg.hpp"

namespace zmq
{
class io_thread_t;
class session_base_t;

class pgm_sender_t ZMQ_FINAL : public io_object_t, public i_engine
{
  public:
    pgm_sender_t (zmq::io_thread_t *parent_, const options_t &options_);
    ~pgm_sender_t ();

    int init (bool udp_encapsulation_, const char *network_);

    //  i_engine interface implementation.
    bool has_handshake_stage () { return false; };
    void plug (zmq::io_thread_t *io_thread_, zmq::session_base_t *session_);
    void terminate ();
    bool restart_input ();
    void restart_output ();
    void zap_msg_available () {}
    const endpoint_uri_pair_t &get_endpoint () const;

    //  i_poll_events interface implementation.
    void in_event ();
    void out_event ();
    void timer_event (int token);

  private:
    //  Unplug the engine from the session.
    void unplug ();

    //  TX and RX timeout timer ID's.
    enum
    {
        tx_timer_id = 0xa0,
        rx_timer_id = 0xa1
    };

    const endpoint_uri_pair_t _empty_endpoint;

    //  Timers are running.
    bool has_tx_timer;
    bool has_rx_timer;

    session_base_t *session;

    //  Message encoder.
    v1_encoder_t encoder;

    msg_t msg;

    //  Keeps track of message boundaries.
    bool more_flag;

    //  PGM socket.
    pgm_socket_t pgm_socket;

    //  Socket options.
    options_t options;

    //  Poll handle associated with PGM socket.
    handle_t handle;
    handle_t uplink_handle;
    handle_t rdata_notify_handle;
    handle_t pending_notify_handle;

    //  Output buffer from pgm_socket.
    unsigned char *out_buffer;

    //  Output buffer size.
    size_t out_buffer_size;

    //  Number of bytes in the buffer to be written to the socket.
    //  If zero, there are no data to be sent.
    size_t write_size;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (pgm_sender_t)
};
}
#endif

#endif
