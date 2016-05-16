/*
    Copyright (c) 2016 Contributors as noted in the AUTHORS file

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

#include "testutil.hpp"

void str_send_to (void *s_, const char *content_, const char *address_)
{
    //  Send the address part
    int rc = s_sendmore (s_, address_);
    assert (rc > 0);

    rc = s_send (s_, content_);
    assert (rc > 0);
}

void str_recv_from (void *s_, char **ptr_content_, char **ptr_address_)
{
    *ptr_address_ = s_recv (s_);
    assert (ptr_address_);

    *ptr_content_ = s_recv (s_);
    assert (ptr_content_);
}

int main (void)
{
    setup_test_environment ();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    char* message_string;
    char* address;

    void *sender = zmq_socket (ctx, ZMQ_DGRAM);
    void *listener = zmq_socket (ctx, ZMQ_DGRAM);

    //  Connecting dgram shoudl fail
    int rc = zmq_connect (listener, "udp://127.0.0.1:5556");
    assert (rc == -1);

    rc = zmq_bind (listener, "udp://*:5556");
    assert (rc == 0);

    rc = zmq_bind (sender, "udp://*:5557");
    assert (rc == 0);

    str_send_to (sender, "Is someone there ?", "127.0.0.1:5556");

    str_recv_from (listener, &message_string, &address);
    assert (strcmp(message_string, "Is someone there ?") == 0);
    assert (strcmp(address, "127.0.0.1:5557") == 0);
    free (message_string);

    str_send_to (listener, "Yes, there is !", address);
    free (address);

    str_recv_from (sender, &message_string, &address);
    assert (strcmp(message_string, "Yes, there is !") == 0);
    assert (strcmp(address, "127.0.0.1:5556") == 0);
    free (message_string);
    free (address);

    rc = zmq_close (sender);
    assert (rc == 0);

    rc = zmq_close (listener);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
