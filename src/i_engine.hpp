/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_I_ENGINE_HPP_INCLUDED__
#define __ZMQ_I_ENGINE_HPP_INCLUDED__

#include "endpoint.hpp"
#include "macros.hpp"

namespace zmq
{
class io_thread_t;

//  Abstract interface to be implemented by various engines.

struct i_engine
{
    enum error_reason_t
    {
        protocol_error,
        connection_error,
        timeout_error
    };

    virtual ~i_engine () ZMQ_DEFAULT;

    //  Indicate if the engine has an handshake stage.
    //  If engine has handshake stage, engine must call session.engine_ready when the handshake is complete.
    virtual bool has_handshake_stage () = 0;

    //  Plug the engine to the session.
    virtual void plug (zmq::io_thread_t *io_thread_,
                       class session_base_t *session_) = 0;

    //  Terminate and deallocate the engine. Note that 'detached'
    //  events are not fired on termination.
    virtual void terminate () = 0;

    //  This method is called by the session to signalise that more
    //  messages can be written to the pipe.
    //  Returns false if the engine was deleted due to an error.
    //  TODO it is probably better to change the design such that the engine
    //  does not delete itself
    virtual bool restart_input () = 0;

    //  This method is called by the session to signalise that there
    //  are messages to send available.
    virtual void restart_output () = 0;

    virtual void zap_msg_available () = 0;

    virtual const endpoint_uri_pair_t &get_endpoint () const = 0;
};
}

#endif
