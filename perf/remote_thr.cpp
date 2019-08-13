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

#include "../include/zmq.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "readerwriterqueue.h"

// keys are arbitrary but must match local_lat.cpp
const char server_pubkey[] = "DX4nh=yUn{-9ugra0X3Src4SU-4xTgqxcYY.+<SH";
const char client_pubkey[] = "<n^oA}I:66W+*ds3tAmi1+KJzv-}k&fC2aA5Bj0K";
const char client_prvkey[] = "9R9bV}[6z6DC-%$!jTVTKvWc=LEL{4i4gzUe$@Zx";

#define SIZE_OF_CONTENT_T_USED_BY_ZMQ_VLM (40)
#define MAX_ACTIVE_MESSAGES (8192)
#define MSG_BLOCK_SIZE (256)

#define MAX_MESSAGE_SIZE                                                       \
    (MSG_BLOCK_SIZE - SIZE_OF_CONTENT_T_USED_BY_ZMQ_VLM - 1 /* canary */)

typedef struct
{
    uint8_t content_block
      [SIZE_OF_CONTENT_T_USED_BY_ZMQ_VLM]; // will be used by ZMQ internally
    uint8_t raw_data[MAX_MESSAGE_SIZE];
    uint8_t canary;
} msg_block_t;


class ZmqMessagePool
{
  public:
    ZmqMessagePool ()
    {
        // enqueue all available blocks in the free list:
        for (int i = 0; i < MAX_ACTIVE_MESSAGES; i++) {
            m_storage[i].canary = 0xAB;
            m_free_list.enqueue (&m_storage[i]);
        }
    }
    ~ZmqMessagePool () {}


    bool allocate_msg (zmq_msg_t *out,
                       size_t len) // consumer thread: user app thread
    {
        assert (len < MAX_MESSAGE_SIZE);

        // consume 1 block from the list of free msg blocks
        msg_block_t *next_avail = nullptr;
        if (!m_free_list.try_dequeue (next_avail)) {
            assert (0); // I want to find out if this ever happens
            return false;
        }

        assert (next_avail);
        int rc = zmq_msg_init_data (
          out, next_avail, len + SIZE_OF_CONTENT_T_USED_BY_ZMQ_VLM,
          (zmq_free_fn *) ZmqMessagePool::deallocate_msg, this);
        assert (rc == 0);

        assert (zmq_msg_size (out) == len);
        assert (zmq_msg_data (out) == next_avail->raw_data);

        return true;
    }

    static void
    deallocate_msg (void *data_,
                    void *hint_) // producer thread: ZMQ background IO thread
    {
        ZmqMessagePool *pPool = reinterpret_cast<ZmqMessagePool *> (hint_);

        // recover the beginning of this msg_block:
        uint8_t *data_ptr_ = (uint8_t *) data_;
        msg_block_t *to_return =
          (msg_block_t *) (data_ptr_ - SIZE_OF_CONTENT_T_USED_BY_ZMQ_VLM);
        assert (to_return->canary == 0xAB);

        // produce a new free msg block:
        pPool->m_free_list.enqueue (to_return);
    }

    size_t size () const { return m_free_list.size_approx (); }

  private:
    msg_block_t m_storage[MAX_ACTIVE_MESSAGES];
    moodycamel::ReaderWriterQueue<msg_block_t *> m_free_list;
};


int main (int argc, char *argv[])
{
    const char *connect_to;
    int message_count;
    int message_size;
    void *ctx;
    void *s;
    int rc;
    int i;
    zmq_msg_t msg;
    int curve = 0;

    if (argc != 4 && argc != 5) {
        printf ("usage: remote_thr <connect-to> <message-size> "
                "<message-count> [<enable_curve>]\n");
        return 1;
    }
    connect_to = argv[1];
    message_size = atoi (argv[2]);
    message_count = atoi (argv[3]);
    if (argc >= 5 && atoi (argv[4])) {
        curve = 1;
    }

    ctx = zmq_init (1);
    if (!ctx) {
        printf ("error in zmq_init: %s\n", zmq_strerror (errno));
        return -1;
    }

    s = zmq_socket (ctx, ZMQ_PUSH);
    if (!s) {
        printf ("error in zmq_socket: %s\n", zmq_strerror (errno));
        return -1;
    }

    //  Add your socket options here.
    //  For example ZMQ_RATE, ZMQ_RECOVERY_IVL and ZMQ_MCAST_LOOP for PGM.
    if (curve) {
        rc = zmq_setsockopt (s, ZMQ_CURVE_SECRETKEY, client_prvkey,
                             sizeof (client_prvkey));
        if (rc != 0) {
            printf ("error in zmq_setsockoopt: %s\n", zmq_strerror (errno));
            return -1;
        }

        rc = zmq_setsockopt (s, ZMQ_CURVE_PUBLICKEY, client_pubkey,
                             sizeof (client_pubkey));
        if (rc != 0) {
            printf ("error in zmq_setsockoopt: %s\n", zmq_strerror (errno));
            return -1;
        }

        rc = zmq_setsockopt (s, ZMQ_CURVE_SERVERKEY, server_pubkey,
                             sizeof (server_pubkey));
        if (rc != 0) {
            printf ("error in zmq_setsockoopt: %s\n", zmq_strerror (errno));
            return -1;
        }
    }

    rc = zmq_connect (s, connect_to);
    if (rc != 0) {
        printf ("error in zmq_connect: %s\n", zmq_strerror (errno));
        return -1;
    }

#if 0
    for (i = 0; i != message_count; i++) {
        rc = zmq_msg_init_size (&msg, message_size);
        if (rc != 0) {
            printf ("error in zmq_msg_init_size: %s\n", zmq_strerror (errno));
            return -1;
        }
        rc = zmq_sendmsg (s, &msg, 0);
        if (rc < 0) {
            printf ("error in zmq_sendmsg: %s\n", zmq_strerror (errno));
            return -1;
        }
        rc = zmq_msg_close (&msg);
        if (rc != 0) {
            printf ("error in zmq_msg_close: %s\n", zmq_strerror (errno));
            return -1;
        }
    }
#else
    printf ("msg block size: %zu; max msg size: %d\n", sizeof (msg_block_t),
            MAX_MESSAGE_SIZE);
    ZmqMessagePool pool;
    for (i = 0; i != message_count; i++) {
        pool.allocate_msg (&msg, message_size);

        // to be fair when comparing the results generated by the other #if/#endif branch
        // avoid any kind of initialization of message memory:
        //memset (zmq_msg_data (&msg), message_size, 0xAB);

        rc = zmq_sendmsg (s, &msg, 0);
        if (rc < 0) {
            printf ("error in zmq_sendmsg: %s\n", zmq_strerror (errno));
            return -1;
        }
        rc = zmq_msg_close (&msg);
        if (rc != 0) {
            printf ("error in zmq_msg_close: %s\n", zmq_strerror (errno));
            return -1;
        }

        //if ((i % 1000) == 0)
        //    printf ("mempool msg size: %zu\n", pool.size ());
    }
#endif

    rc = zmq_close (s);
    if (rc != 0) {
        printf ("error in zmq_close: %s\n", zmq_strerror (errno));
        return -1;
    }

    rc = zmq_ctx_term (ctx);
    if (rc != 0) {
        printf ("error in zmq_ctx_term: %s\n", zmq_strerror (errno));
        return -1;
    }

    return 0;
}
