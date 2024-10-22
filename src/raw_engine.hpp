/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_RAW_ENGINE_HPP_INCLUDED__
#define __ZMQ_RAW_ENGINE_HPP_INCLUDED__

#include <stddef.h>

#include "fd.hpp"
#include "i_engine.hpp"
#include "io_object.hpp"
#include "i_encoder.hpp"
#include "i_decoder.hpp"
#include "options.hpp"
#include "socket_base.hpp"
#include "metadata.hpp"
#include "msg.hpp"
#include "stream_engine_base.hpp"

namespace zmq
{
//  Protocol revisions

class io_thread_t;
class session_base_t;
class mechanism_t;

//  This engine handles any socket with SOCK_STREAM semantics,
//  e.g. TCP socket or an UNIX domain socket.

class raw_engine_t ZMQ_FINAL : public stream_engine_base_t
{
  public:
    raw_engine_t (fd_t fd_,
                  const options_t &options_,
                  const endpoint_uri_pair_t &endpoint_uri_pair_);
    ~raw_engine_t ();

  protected:
    void error (error_reason_t reason_);
    void plug_internal ();
    bool handshake ();

  private:
    int push_raw_msg_to_session (msg_t *msg_);

    ZMQ_NON_COPYABLE_NOR_MOVABLE (raw_engine_t)
};
}

#endif
