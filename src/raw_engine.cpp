/*
    Copyright (c) 2007-2019 Contributors as noted in the AUTHORS file

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
        (this->*_process_msg) (&terminator);
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
