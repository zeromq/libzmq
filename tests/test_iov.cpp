/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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

// XSI vector I/O
#if defined ZMQ_HAVE_UIO
#include <sys/uio.h>
#else
struct iovec {
    void *iov_base;
    size_t iov_len;
};
#endif

void do_check(void* sb, void* sc, unsigned int msgsz)
{
    setup_test_environment();
    int rc;
    int sum =0;
    for (int i = 0; i < 10; i++)
    {
        zmq_msg_t msg;
        zmq_msg_init_size(&msg, msgsz);
        void * data = zmq_msg_data(&msg);
        memcpy(data,&i, sizeof(int));
        rc = zmq_msg_send(&msg,sc,i==9 ? 0 :ZMQ_SNDMORE);
        assert (rc == (int)msgsz);
        zmq_msg_close(&msg);
        sum += i;
    }

    struct iovec ibuffer[32] ;
    memset(&ibuffer[0], 0, sizeof(ibuffer));
    
    size_t count = 10;
    rc = zmq_recviov(sb,&ibuffer[0],&count,0);
    assert (rc == 10);

    int rsum=0;
    for(;count;--count)
    {
        int v;
        memcpy(&v,ibuffer[count-1].iov_base,sizeof(int));
        rsum += v;
        assert(ibuffer[count-1].iov_len == msgsz);
        // free up the memory
        free(ibuffer[count-1].iov_base);
    }
    
    assert ( sum == rsum );

}

int main (void)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    int rc;
   
    void *sb = zmq_socket (ctx, ZMQ_PULL);
    assert (sb);
  
    rc = zmq_bind (sb, "inproc://a");
    assert (rc == 0);

    msleep (SETTLE_TIME);
    void *sc = zmq_socket (ctx, ZMQ_PUSH);
  
    rc = zmq_connect (sc, "inproc://a");
    assert (rc == 0);


    // message bigger than vsm max
    do_check(sb,sc,100);

    // message smaller than vsm max
    do_check(sb,sc,10);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
