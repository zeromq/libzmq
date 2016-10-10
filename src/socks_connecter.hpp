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

#ifndef __SOCKS_CONNECTER_HPP_INCLUDED__
#define __SOCKS_CONNECTER_HPP_INCLUDED__

#include "fd.hpp"
#include "io_object.hpp"
#include "own.hpp"
#include "stdint.hpp"
#include "socks.hpp"

namespace zmq
{

    class io_thread_t;
    class session_base_t;
    struct address_t;

    class socks_connecter_t : public own_t, public io_object_t
    {
    public:

        //  If 'delayed_start' is true connecter first waits for a while,
        //  then starts connection process.
        socks_connecter_t (zmq::io_thread_t *io_thread_,
            zmq::session_base_t *session_, const options_t &options_,
            address_t *addr_, address_t *proxy_addr_,  bool delayed_start_);
        ~socks_connecter_t ();

    private:
        enum {
            unplugged,
            waiting_for_reconnect_time,
            waiting_for_proxy_connection,
            sending_greeting,
            waiting_for_choice,
            sending_request,
            waiting_for_response
        };

        //  ID of the timer used to delay the reconnection.
        enum { reconnect_timer_id = 1 };

        //  Method ID
        enum { socks_no_auth_required = 0 };

        //  Handlers for incoming commands.
        virtual void process_plug ();
        virtual void process_term (int linger_);

        //  Handlers for I/O events.
        virtual void in_event ();
        virtual void out_event ();
        virtual void timer_event (int id_);

        //  Internal function to start the actual connection establishment.
        void initiate_connect ();

        int process_server_response (const socks_choice_t &response);
        int process_server_response (const socks_response_t &response);

        int parse_address (const std::string &address_,
                std::string &hostname_, uint16_t &port_);

        int connect_to_proxy ();

        void error ();

        //  Internal function to start reconnect timer
        void start_timer ();

        //  Internal function to return a reconnect backoff delay.
        //  Will modify the current_reconnect_ivl used for next call
        //  Returns the currently used interval
        int get_new_reconnect_ivl ();

        //  Open TCP connecting socket. Returns -1 in case of error,
        //  0 if connect was successful immediately. Returns -1 with
        //  EAGAIN errno if async connect was launched.
        int open ();

        //  Close the connecting socket.
        void close ();

        //  Get the file descriptor of newly created connection. Returns
        //  retired_fd if the connection was unsuccessful.
        zmq::fd_t check_proxy_connection ();

        socks_greeting_encoder_t greeting_encoder;
        socks_choice_decoder_t choice_decoder;
        socks_request_encoder_t request_encoder;
        socks_response_decoder_t response_decoder;

        //  Address to connect to. Owned by session_base_t.
        address_t *addr;

        //  SOCKS address; owned by this connecter.
        address_t *proxy_addr;

        int status;

        //  Underlying socket.
        fd_t s;

        //  Handle corresponding to the listening socket.
        handle_t handle;

        //  If true file descriptor is registered with the poller and 'handle'
        //  contains valid value.
        bool handle_valid;

        //  If true, connecter is waiting a while before trying to connect.
        const bool delayed_start;

        //  True iff a timer has been started.
        bool timer_started;

        //  Reference to the session we belong to.
        zmq::session_base_t *session;

        //  Current reconnect ivl, updated for backoff strategy
        int current_reconnect_ivl;

        // String representation of endpoint to connect to
        std::string endpoint;

        // Socket
        zmq::socket_base_t *socket;

        socks_connecter_t (const socks_connecter_t&);
        const socks_connecter_t &operator = (const socks_connecter_t&);
    };

}

#endif
