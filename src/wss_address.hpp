/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_WSS_ADDRESS_HPP_INCLUDED__
#define __ZMQ_WSS_ADDRESS_HPP_INCLUDED__

#include "ws_address.hpp"

namespace zmq
{
class wss_address_t : public ws_address_t
{
  public:
    wss_address_t ();
    wss_address_t (const sockaddr *sa_, socklen_t sa_len_);
    //  The opposite to resolve()
    int to_string (std::string &addr_) const;
};
}

#endif
