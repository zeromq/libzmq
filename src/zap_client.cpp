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

#include "precompiled.hpp"

#include "zap_client.hpp"
#include "msg.hpp"

namespace zmq
{
int zap_client_t::send_zap_request (const char *mechanism,
                                    size_t mechanism_length,
                                    const uint8_t *credentials,
                                    size_t credentials_size)
{
    // TODO  I don't think the rc can be -1 anywhere below.
    // It might only be -1 if the HWM was exceeded, but on the ZAP socket,
    // the HWM is disabled. They should be changed to zmq_assert (rc == 0);
    // The method's return type can be changed to void then.

    int rc;
    msg_t msg;

    //  Address delimiter frame
    rc = msg.init ();
    errno_assert (rc == 0);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Version frame
    rc = msg.init_size (3);
    errno_assert (rc == 0);
    memcpy (msg.data (), "1.0", 3);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Request ID frame
    rc = msg.init_size (1);
    errno_assert (rc == 0);
    memcpy (msg.data (), "1", 1);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Domain frame
    rc = msg.init_size (options.zap_domain.length ());
    errno_assert (rc == 0);
    memcpy (msg.data (), options.zap_domain.c_str (),
            options.zap_domain.length ());
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Address frame
    rc = msg.init_size (peer_address.length ());
    errno_assert (rc == 0);
    memcpy (msg.data (), peer_address.c_str (), peer_address.length ());
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Identity frame
    rc = msg.init_size (options.identity_size);
    errno_assert (rc == 0);
    memcpy (msg.data (), options.identity, options.identity_size);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Mechanism frame
    rc = msg.init_size (mechanism_length);
    errno_assert (rc == 0);
    memcpy (msg.data (), mechanism, mechanism_length);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Credentials frame
    //  Skip if credential is NULL
    if (credentials) {
        rc = msg.init_size (credentials_size);
        errno_assert (rc == 0);
        memcpy (msg.data (), credentials, credentials_size);
        rc = session->write_zap_msg (&msg);
        if (rc != 0)
            return close_and_return (&msg, -1);
    }

    return 0;
}
}
