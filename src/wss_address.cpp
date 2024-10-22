/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include <string>
#include <sstream>

#include "wss_address.hpp"

zmq::wss_address_t::wss_address_t () : ws_address_t ()
{
}

zmq::wss_address_t::wss_address_t (const sockaddr *sa_, socklen_t sa_len_) :
    ws_address_t (sa_, sa_len_)
{
}

int zmq::wss_address_t::to_string (std::string &addr_) const
{
    std::ostringstream os;
    os << std::string ("wss://") << host () << std::string (":")
       << _address.port () << path ();
    addr_ = os.str ();

    return 0;
}
