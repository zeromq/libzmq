/* SPDX-License-Identifier: MPL-2.0 */

#include "../include/zmq.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//
// This perf tool works identically to remote_thr but it demonstrates
// the use of a custom message allocator.
//

// keys are arbitrary but must match local_lat.cpp
const char server_pubkey[] = "DX4nh=yUn{-9ugra0X3Src4SU-4xTgqxcYY.+<SH";
const char client_pubkey[] = "<n^oA}I:66W+*ds3tAmi1+KJzv-}k&fC2aA5Bj0K";
const char client_prvkey[] = "9R9bV}[6z6DC-%$!jTVTKvWc=LEL{4i4gzUe$@Zx";

#ifdef _MSC_VER
//
// Demo helper
//

const char *HintToString (_In_ ZMQ_MSG_ALLOC_HINT hint)
{
    switch (hint) {
        case ZMQ_MSG_ALLOC_HINT_NONE:
            return "ZMQ_MSG_ALLOC_HINT_NONE";
        case ZMQ_MSG_ALLOC_HINT_OUTGOING:
            return "ZMQ_MSG_ALLOC_HINT_OUTGOING";
        case ZMQ_MSG_ALLOC_HINT_INCOMING:
            return "ZMQ_MSG_ALLOC_HINT_INCOMING";
        case ZMQ_MSG_ALLOC_HINT_FIXED_SIZE:
            return "ZMQ_MSG_ALLOC_HINT_FIXED_SIZE";
        default:
            return "Unknown";
    }
}

//
// Alloc/Free. In this example, we KNOW the message size
// is identical for all messages. Regardless of what size
// it is, we choose to keep a certain number in a lookaside
// list instead of returning them to the heap. This is an
// example of a possible application of the custom allocator.
// 
// Note: This is not a  good example of perf improvement
// in the sense that nothing else is allocating anything
// in the process and the CRT heap is very good. There is
// therefore no fragmentation and the heap is very fast.
// 
// The gain is marginal (maybe 6-7%) at messages sizes 128
// and number of messages in the 100M to 1B range over IPC.
//
// Extensive perf testing in real-world workloads is required
// to determine if this approach is worth it or not.
//

#include <windows.h>
#include <mutex>

#define USE_HEAPALLOC
#define KEEP_ASIDE 1000

#ifdef USE_HEAPALLOC
HANDLE hHeap;
#endif

SLIST_HEADER LookasideList;

_Must_inspect_result_ _Ret_opt_bytecap_ (cb) void *ZMQ_CDECL
  msg_alloc (_In_ size_t cb, _In_ ZMQ_MSG_ALLOC_HINT hint)
{
    if (hint == ZMQ_MSG_ALLOC_HINT_OUTGOING) {
        void *ptr = InterlockedPopEntrySList (&LookasideList);
        if (ptr != NULL) {
            return ptr;
        } else {
#ifdef USE_HEAPALLOC
            return HeapAlloc (hHeap, 0, cb);
#else
            return malloc (cb);
#endif
        }
    } else {
#ifdef USE_HEAPALLOC
        return HeapAlloc (hHeap, 0, cb);
#else
        return malloc (cb);
#endif
    }
}

void ZMQ_CDECL msg_free (_Pre_maybenull_ _Post_invalid_ void *ptr_,
                         _In_ ZMQ_MSG_ALLOC_HINT hint)
{
    if (hint == ZMQ_MSG_ALLOC_HINT_OUTGOING) {
        if (ptr_ != NULL && QueryDepthSList (&LookasideList) < KEEP_ASIDE) {
            InterlockedPushEntrySList (&LookasideList, (PSLIST_ENTRY)ptr_);
        } else {
#ifdef USE_HEAPALLOC
            (void) HeapFree (hHeap, 0, ptr_);
#else
            free(ptr_);
#endif
        }
    } else {
#ifdef USE_HEAPALLOC
        (void)HeapFree (hHeap, 0, ptr_);
#else
        free (ptr_);
#endif
    }
}
#else
//
// Alloc/Free. Simply forward the call to malloc/free.
//

_Must_inspect_result_ _Ret_opt_bytecap_ (cb) void *ZMQ_CDECL
  msg_alloc (_In_ size_t cb, _In_ ZMQ_MSG_ALLOC_HINT /*hint*/)
{
    
    return malloc (cb);
}

void ZMQ_CDECL msg_free (_Pre_maybenull_ _Post_invalid_ void *ptr_,
                         _In_ ZMQ_MSG_ALLOC_HINT /*hint*/)
{
    free (ptr_);
}

#endif

int ZMQ_CDECL main (int argc, char *argv[])
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

#ifdef USE_HEAPALLOC
    hHeap = HeapCreate (HEAP_NO_SERIALIZE, 1024 * 1024, 0);
#endif

    InitializeSListHead (&LookasideList);
    (void)zmq_set_custom_msg_allocator (msg_alloc, msg_free);

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

    //
    // Free any set aside leftovers.
    //

    unsigned count = QueryDepthSList (&LookasideList);

    printf ("Freeing %u entries in lookaside list\n", count);

    for (void *ptr = InterlockedPopEntrySList (&LookasideList); ptr != NULL;
         ptr = InterlockedPopEntrySList (&LookasideList)) {
#ifdef USE_HEAPALLOC
        (void) HeapFree (hHeap, 0, ptr);
#else
        free (ptr);
#endif
    }

#ifdef USE_HEAPALLOC
    HeapDestroy (hHeap);
#endif

    return 0;
}
