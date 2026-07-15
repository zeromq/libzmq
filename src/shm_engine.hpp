/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_SHM_ENGINE_HPP_INCLUDED__
#define __ZMQ_SHM_ENGINE_HPP_INCLUDED__

#if defined ZMQ_HAVE_LINUX

#include "endpoint.hpp"
#include "fd.hpp"
#include "i_engine.hpp"
#include "io_object.hpp"
#include "msg.hpp"
#include "shm_channel.hpp"
#include "stdint.hpp"

namespace zmq
{
class io_thread_t;
class session_base_t;

class shm_engine_t ZMQ_FINAL : public io_object_t, public i_engine
{
  public:
    shm_engine_t (fd_t fd_,
                  void *mapping_,
                  size_t mapping_size_,
                  bool server_,
                  const endpoint_uri_pair_t &endpoint_);
    ~shm_engine_t ();

    static size_t mapping_size ();
    static int initialize_mapping (void *mapping_, size_t mapping_size_);

    bool valid () const;
    bool has_handshake_stage () ZMQ_FINAL { return false; }
    void plug (io_thread_t *io_thread_, session_base_t *session_);
    void terminate ();
    bool restart_input ();
    void restart_output ();
    void zap_msg_available () {}
    void in_event ();
    void out_event () {}
    const endpoint_uri_pair_t &get_endpoint () const;

  private:
    bool pump_input ();
    bool pump_output ();
    bool notify_peer (bool allow_closed_);
    bool input_drained () const;
    void error (error_reason_t reason_);

    bool _plugged;
    fd_t _fd;
    void *_mapping;
    size_t _mapping_size;
    shm_channel_t _channel;
    session_base_t *_session;
    handle_t _handle;
    endpoint_uri_pair_t _endpoint;
    uint64_t _send_position;
    uint64_t _receive_position;
    msg_t _out_msg;
    msg_t _in_msg;
    bool _out_pending;
    bool _in_pending;
    bool _peer_closed;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (shm_engine_t)
};
}

#endif

#endif
