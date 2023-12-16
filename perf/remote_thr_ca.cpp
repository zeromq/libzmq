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
// Note: This test app is not a good example to demonstrate
// perf improvements in the sense that nothing else is
// allocating anything within the process and the CRT heap is
// very good. There is therefore not much fragmentation.
// 
// The gain is marginal (maybe 6-7%) at messages size 128
// and number of messages in the 100M to 1B range over IPC.
// 
// For most uses, a custom allocator is not worth the pain. Now,
// if you wrote a doctoral thesis on heaps, low fragmentation, and
// fized-block allocators, then you might be able to squeeze out
// some performance gains.
//
// Extensive perf testing in real-world workloads is required
// to determine if the approach is worth it or not. As a first
// step, the message sizes should be recorded, for example
// using performance counters. From there, statistics will
// reveal the distribution of message sizes and their frequency.
// 
// The time it takes to allocate/free also must be recorded and
// a real-world workload on a real system should run for a long time
// (days/weeks) with many millions of messages exchanged together
// with normal system use. This is why you need to use perfcounters
// as the data collection cannot be intrusive.
// 
// Armed with the numbers, it is possible to deternine if there is
// anything to gain in speeding up the heap, and where to put the
// size breaks to cover the most common message sizes, as well as
// the peak number of messages in flight, to decide how to shape
// a fixed-block allocator pool.
// 
// This article is a good starting point for a possible allocator
// implementation in C:
// 
// https://www.codeproject.com/Articles/1272619/A-Fixed-Block-Memory-Allocator-in-C
//
// Another approach could be to extend the lookaside idea presented here
// to multiple block sizes. Hint: HeapSize() knows the size of a block given
// a pointer. The strategy is to round the size up and serve all requests
// fitting into that bucket with blocks of the same size, going to
// the same lookaside list. 3-4 buckets should be enough, the last one is
// "everything above". You can have a different HWM's for each bucket
// depending on what you learned about frequencies, and how much you want
// to spend for the lookasides. You control the tradeoffs. This may be a
// little bit faster provided there is no contention on the allocator.
// 
// Yet another approach is to use the Intel TBB scalable allocator which
// is frigteningly quick even in presence of heavy contention.
//
// Then remember the three rules: measure, measure, measure. The
// chances that you significantly and consistently improve on the
// CRT or Win32 heaps are very slim. -- A Windows Kernel dev.
//

#include <windows.h>
#include <mutex>

// #define ZMQ_HAVE_TBB_SCALABLE_ALLOCATOR

#if defined(ZMQ_HAVE_TBB_SCALABLE_ALLOCATOR)
#include <tbb/scalable_allocator.h>
#endif

#define USE_HEAPALLOC
#define KEEP_ASIDE_HWM 1000

#ifdef USE_HEAPALLOC
HANDLE hHeap;
#endif

SLIST_HEADER LookasideList;

_Must_inspect_result_ _Ret_opt_bytecap_ (cb) void *ZMQ_CDECL
  msg_alloc (_In_ size_t cb, _In_ ZMQ_MSG_ALLOC_HINT hint)
{
#if defined(ZMQ_HAVE_TBB_SCALABLE_ALLOCATOR)
    hint; // Unused
    return scalable_malloc (cb);
#else
    if (hint == ZMQ_MSG_ALLOC_HINT_OUTGOING) {
        void *ptr = InterlockedPopEntrySList (&LookasideList);
        if (ptr != NULL) {
            return ptr;
        } else {
            // We need to allocate at least sizeof (SLIST_ENTRY) bytes
            // as the returned blocks are overwritten with the SList
            // Next pointer, so we need at least a pointer's size.
#ifdef USE_HEAPALLOC
            return HeapAlloc (hHeap, 0, std::max (cb, sizeof (SLIST_ENTRY)));
#else
            return malloc (std::max (cb, sizeof (SLIST_ENTRY)));
#endif
        }
    } else {
#ifdef USE_HEAPALLOC
        return HeapAlloc (hHeap, 0, cb);
#else
        return malloc (cb);
#endif
    }
#endif
}

void ZMQ_CDECL msg_free (_Pre_maybenull_ _Post_invalid_ void *ptr_,
                         _In_ ZMQ_MSG_ALLOC_HINT hint)
{
#if defined(ZMQ_HAVE_TBB_SCALABLE_ALLOCATOR)
    hint; // Unused
    return scalable_free (ptr_);
#else
    if (hint == ZMQ_MSG_ALLOC_HINT_OUTGOING) {
        // There is a possibility that we sligthly exceed the HWM in case
        // of heavy contention. Not really a problem.
        if ((ptr_ != NULL) && (QueryDepthSList (&LookasideList) < KEEP_ASIDE_HWM)) {
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
        (void) HeapFree (hHeap, 0, ptr_);
#else
        free (ptr_);
#endif
    }
#endif
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

#if !defined(ZMQ_HAVE_TBB_SCALABLE_ALLOCATOR)
#ifdef USE_HEAPALLOC
    hHeap = HeapCreate (HEAP_NO_SERIALIZE, 1024 * 1024, 0);
#endif
    InitializeSListHead (&LookasideList);
#endif

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
    // Free any leftovers in the lookaside.
    //

    unsigned count = QueryDepthSList (&LookasideList);

    if (count) {
        for (void *ptr = InterlockedPopEntrySList (&LookasideList); ptr != NULL;
             ptr = InterlockedPopEntrySList (&LookasideList)) {

#if !defined(ZMQ_HAVE_TBB_SCALABLE_ALLOCATOR)
    #ifdef USE_HEAPALLOC
                (void) HeapFree (hHeap, 0, ptr);
    #else
                free (ptr);
    #endif
#else
                scalable_free (ptr);
#endif
        }
    }

#if !defined(ZMQ_HAVE_TBB_SCALABLE_ALLOCATOR)
#ifdef USE_HEAPALLOC
    HeapDestroy (hHeap);
#endif
#endif

    return 0;
}
