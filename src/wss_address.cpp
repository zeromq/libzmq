/*
    Copyright (c) 2019 Contributors as noted in the AUTHORS file

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
