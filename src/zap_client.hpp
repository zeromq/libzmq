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

#ifndef __ZMQ_ZAP_CLIENT_HPP_INCLUDED__
#define __ZMQ_ZAP_CLIENT_HPP_INCLUDED__

#include "mechanism_base.hpp"

namespace zmq
{
class zap_client_t : public virtual mechanism_base_t
{
  public:
    zap_client_t (session_base_t *const session_,
                  const std::string &peer_address_,
                  const options_t &options_);

    void send_zap_request (const char *mechanism_,
                           size_t mechanism_length_,
                           const uint8_t *credentials_,
                           size_t credentials_size_);

    void send_zap_request (const char *mechanism_,
                           size_t mechanism_length_,
                           const uint8_t **credentials_,
                           size_t *credentials_sizes_,
                           size_t credentials_count_);

    virtual int receive_and_process_zap_reply ();
    virtual void handle_zap_status_code ();

  protected:
    const std::string peer_address;

    //  Status code as received from ZAP handler
    std::string status_code;
};

class zap_client_common_handshake_t : public zap_client_t
{
  protected:
    enum state_t
    {
        waiting_for_hello,
        sending_welcome,
        waiting_for_initiate,
        waiting_for_zap_reply,
        sending_ready,
        sending_error,
        error_sent,
        ready
    };

    zap_client_common_handshake_t (session_base_t *const session_,
                                   const std::string &peer_address_,
                                   const options_t &options_,
                                   state_t zap_reply_ok_state_);

    //  methods from mechanism_t
    status_t status () const;
    int zap_msg_available ();

    //  zap_client_t methods
    int receive_and_process_zap_reply ();
    void handle_zap_status_code ();

    //  Current FSM state
    state_t state;

  private:
    const state_t _zap_reply_ok_state;
};
}

#endif
