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

int str_send_to (void *s_, const char *content_, const void *address_, const size_t addrlen_)
{
    zmq_msg_t msg;
  
    int rc = zmq_msg_init_size (&msg, addrlen_);
    if (rc != 0)
        return rc;

    if (address_ != NULL)
        memcpy (zmq_msg_data (&msg), address_, addrlen_);

    rc = zmq_msg_send (&msg, s_, ZMQ_SNDMORE);
    if (rc != 0) {
        zmq_msg_close (&msg);
        return rc;
    }
    
    zmq_msg_close (&msg);
    
    rc = zmq_msg_init_size (&msg, strlen(content_));
    if (rc != 0)
        return rc;

    memcpy (zmq_msg_data (&msg), content_, strlen(content_));
    
    rc = zmq_msg_send (&msg, s_, 0);

    zmq_msg_close (&msg);

    return rc;
}

int str_recv_from (void *s_, char **ptr_content_, void **ptr_address_, size_t *ptr_addrlen_)
{
    zmq_msg_t msg;
  
    int rc = zmq_msg_init (&msg);
    if (rc != 0)
        return -1;

    rc = zmq_msg_recv (&msg, s_, ZMQ_RCVMORE);
    if (rc == -1) {
        zmq_msg_close(&msg);
        return -1;
    }

    *ptr_addrlen_ = zmq_msg_size (&msg);
    *ptr_address_ = malloc( *ptr_addrlen_ );
    memcpy (*ptr_address_, zmq_msg_data (&msg), *ptr_addrlen_);
    
    rc = zmq_msg_recv (&msg, s_, 0);
    if (rc == -1) {
        zmq_msg_close(&msg);
        return -1;
    }
    
    *ptr_content_ = (char*) malloc (sizeof(char) * (zmq_msg_size (&msg) + 1));
    memcpy (*ptr_content_, zmq_msg_data (&msg), zmq_msg_size (&msg));
    *ptr_content_ [zmq_msg_size (&msg)] = '\0';

    zmq_msg_close (&msg);

    return rc;
}

int main (void)
{
    setup_test_environment ();
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    
    char* message_string;
    void* address;
    size_t address_length;

    void *sender = zmq_socket (ctx, ZMQ_DGRAM);
    void *listener = zmq_socket (ctx, ZMQ_DGRAM);

    int rc = zmq_bind (listener, "udp://*:5556");
    assert (rc == 0);

    rc = zmq_connect (sender, "udp://127.0.0.1:5556");
    assert (rc == 0);

    msleep (SETTLE_TIME);

    rc = str_send_to (sender, "Is someone there ?", NULL, 0);
    assert (rc == 0);

    rc = str_recv_from (listener, &message_string, &address, &address_length);
    assert (rc == 0);
    assert (address_length == sizeof(sockaddr_in));
    assert (strcmp(message_string, "Is someone there ?") == 0);
    
    rc = str_send_to (sender, "Yes, there is !", address, address_length);
    assert (rc == 0);

    rc = zmq_close (sender);
    assert (rc == 0);

    rc = zmq_close (listener);
    assert (rc == 0);
    
    
    rc = zmq_bind (listener, "udp://226.1.1.1:5556");
    assert (rc == 0);

    rc = zmq_connect (sender, "udp://226.1.1.1:5556");
    assert (rc == 0);

    msleep (SETTLE_TIME);

    rc = str_send_to (sender, "Is someone there [MULTICAST]?", NULL, 0);
    assert (rc == 0);

    rc = str_recv_from (listener, &message_string, &address, &address_length);
    assert (rc == 0);
    assert (address_length == sizeof(sockaddr_in));
    assert (strcmp(message_string, "Is someone there ?") == 0);
    
    rc = str_send_to (sender, "Yes, there is [MULTICAST]!", address, address_length);
    assert (rc == 0);

    rc = zmq_close (sender);
    assert (rc == 0);

    rc = zmq_close (listener);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
