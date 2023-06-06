/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "macros.hpp"

#include <limits.h>
#include <string.h>

#ifndef ZMQ_HAVE_WINDOWS
#include <unistd.h>
#endif

#include <new>
#include <sstream>

#include "raw_engine.hpp"
#include "io_thread.hpp"
#include "session_base.hpp"
#include "v1_encoder.hpp"
#include "v1_decoder.hpp"
#include "v2_encoder.hpp"
#include "v2_decoder.hpp"
#include "null_mechanism.hpp"
#include "plain_client.hpp"
#include "plain_server.hpp"
#include "gssapi_client.hpp"
#include "gssapi_server.hpp"
#include "curve_client.hpp"
#include "curve_server.hpp"
#include "raw_decoder.hpp"
#include "raw_encoder.hpp"
#include "config.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "tcp.hpp"
#include "likely.hpp"
#include "wire.hpp"

zmq::raw_engine_t::raw_engine_t (
  fd_t fd_,
  const options_t &options_,
  const endpoint_uri_pair_t &endpoint_uri_pair_) :
    stream_engine_base_t (fd_, options_, endpoint_uri_pair_, false)
{
}

zmq::raw_engine_t::~raw_engine_t ()
{
}

void zmq::raw_engine_t::plug_internal ()
{
    // no handshaking for raw sock, instantiate raw encoder and decoders
    _encoder = new (std::nothrow) raw_encoder_t (_options.out_batch_size);
    alloc_assert (_encoder);

    _decoder = new (std::nothrow) raw_decoder_t (_options.in_batch_size);
    alloc_assert (_decoder);

    _next_msg = &raw_engine_t::pull_msg_from_session;
    _process_msg = static_cast<int (stream_engine_base_t::*) (msg_t *)> (
      &raw_engine_t::push_raw_msg_to_session);

    properties_t properties;
    if (init_properties (properties)) {
        //  Compile metadata.
        zmq_assert (_metadata == NULL);
        _metadata = new (std::nothrow) metadata_t (properties);
        alloc_assert (_metadata);
    }

    if (_options.raw_notify) {
        //  For raw sockets, send an initial 0-length message to the
        // application so that it knows a peer has connected.
        msg_t connector;
        connector.init ();
        push_raw_msg_to_session (&connector);
        connector.close ();
        session ()->flush ();
    }

    set_pollin ();
    set_pollout ();
    //  Flush all the data that may have been already received downstream.
    in_event ();
}

bool zmq::raw_engine_t::handshake ()
{
    return true;
}

void zmq::raw_engine_t::error (error_reason_t reason_)
{
    if (_options.raw_socket && _options.raw_notify) {
        //  For raw sockets, send a final 0-length message to the application
        //  so that it knows the peer has been disconnected.
        msg_t terminator;
        terminator.init ();
        push_raw_msg_to_session (&terminator);
        terminator.close ();
    }
    stream_engine_base_t::error (reason_);
}

int zmq::raw_engine_t::push_raw_msg_to_session (msg_t *msg_)
{
    if (_metadata && _metadata != msg_->metadata ())
        msg_->set_metadata (_metadata);
    return push_msg_to_session (msg_);
}
