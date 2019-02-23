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

class pgm_sender_t : public io_object_t, public i_engine
{
  public:
    pgm_sender_t (zmq::io_thread_t *parent_, const options_t &options_);
    ~pgm_sender_t ();

    int init (bool udp_encapsulation_, const char *network_);

    //  i_engine interface implementation.
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

    pgm_sender_t (const pgm_sender_t &);
    const pgm_sender_t &operator= (const pgm_sender_t &);
};
}
#endif

#endif
