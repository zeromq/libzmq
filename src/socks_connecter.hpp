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
#include "stream_connecter_base.hpp"
#include "stdint.hpp"
#include "socks.hpp"

namespace zmq
{
class io_thread_t;
class session_base_t;
struct address_t;

class socks_connecter_t ZMQ_FINAL : public stream_connecter_base_t
{
  public:
    //  If 'delayed_start' is true connecter first waits for a while,
    //  then starts connection process.
    socks_connecter_t (zmq::io_thread_t *io_thread_,
                       zmq::session_base_t *session_,
                       const options_t &options_,
                       address_t *addr_,
                       address_t *proxy_addr_,
                       bool delayed_start_);
    ~socks_connecter_t ();

    void set_auth_method_basic (const std::string &username,
                                const std::string &password);
    void set_auth_method_none ();


  private:
    enum
    {
        unplugged,
        waiting_for_reconnect_time,
        waiting_for_proxy_connection,
        sending_greeting,
        waiting_for_choice,
        sending_basic_auth_request,
        waiting_for_auth_response,
        sending_request,
        waiting_for_response
    };

    //  Method ID
    enum
    {
        socks_no_auth_required = 0x00,
        socks_basic_auth = 0x02,
        socks_no_acceptable_method = 0xff
    };

    //  Handlers for I/O events.
    void in_event ();
    void out_event ();

    //  Internal function to start the actual connection establishment.
    void start_connecting ();

    static int process_server_response (const socks_choice_t &response_);
    static int process_server_response (const socks_response_t &response_);
    static int process_server_response (const socks_auth_response_t &response_);

    static int parse_address (const std::string &address_,
                              std::string &hostname_,
                              uint16_t &port_);

    int connect_to_proxy ();

    void error ();

    //  Open TCP connecting socket. Returns -1 in case of error,
    //  0 if connect was successful immediately. Returns -1 with
    //  EAGAIN errno if async connect was launched.
    int open ();

    //  Get the file descriptor of newly created connection. Returns
    //  retired_fd if the connection was unsuccessful.
    zmq::fd_t check_proxy_connection () const;

    socks_greeting_encoder_t _greeting_encoder;
    socks_choice_decoder_t _choice_decoder;
    socks_basic_auth_request_encoder_t _basic_auth_request_encoder;
    socks_auth_response_decoder_t _auth_response_decoder;
    socks_request_encoder_t _request_encoder;
    socks_response_decoder_t _response_decoder;

    //  SOCKS address; owned by this connecter.
    address_t *_proxy_addr;

    // User defined authentication method
    int _auth_method;

    // Credentials for basic authentication
    std::string _auth_username;
    std::string _auth_password;

    int _status;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (socks_connecter_t)
};
}

#endif
