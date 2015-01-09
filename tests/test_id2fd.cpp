/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "testutil.hpp"


int main (void)
{
    setup_test_environment();

    void *ctx = zmq_ctx_new ();
    assert (ctx);
    
    void *client = zmq_socket (ctx, ZMQ_REQ);
    assert (client);

    void *server = zmq_socket (ctx, ZMQ_ROUTER);
    assert (server);

    //  Now do a basic ping test
    int rc = zmq_bind (server, "tcp://127.0.0.1:9998");
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://127.0.0.1:9998");
    assert (rc == 0);
    
    rc=zmq_send(client,"1234567890",10,0);
    assert (rc != -1);
    

    int partnumber=1;
    int recvfd=-1;
    zmq_msg_t part;
    do {
        /* if not first free prev message part */
        if (partnumber!=1) zmq_msg_close (&part); 

        /* Create an empty ØMQ message to hold the message part */
        int rc = zmq_msg_init (&part);
        assert (rc == 0);
        
        /* Block until a message is available to be received from socket */
        rc = zmq_msg_recv (&part,server, 0);
        assert (rc != -1);
        if (partnumber==1) {// this is the identity of the receiving pipe
            
            //buffer for  zmq_getsockopt / ZMQ_IDENTITY_FD
            char idbuf[255]; 
            size_t  idbufsz=zmq_msg_size (&part);
            
            assert (idbufsz<=255);
            memcpy(idbuf,zmq_msg_data(&part),idbufsz);
            
            rc = zmq_getsockopt (server, ZMQ_IDENTITY_FD, idbuf, &idbufsz);
            assert (rc == 0);
            
            memcpy(&recvfd,idbuf,sizeof(recvfd));
            
            //depending on your system this should be around 14
            assert (recvfd > 0);
        }
        partnumber++;
    } while (zmq_msg_more(&part));
    zmq_msg_close (&part); 

    close_zero_linger (client);
    close_zero_linger (server);

    zmq_ctx_term (ctx);

    return 0 ;
}
