/* SPDX-License-Identifier: MPL-2.0 */

#include "../include/zmq.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined __linux__
#include <sched.h>
#endif

namespace
{
enum bench_mode_t
{
    mode_ipc,
    mode_shm_copy,
    mode_shm_direct
};

struct usage_t
{
    double user_s;
    double system_s;
};

struct affinity_t
{
    int parent_cpu;
    int child_cpu;
};

enum scan_mode_t
{
    scan_sample,
    scan_full
};

static uint64_t now_us ()
{
    struct timespec ts;
    if (clock_gettime (CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return static_cast<uint64_t> (ts.tv_sec) * UINT64_C (1000000)
           + static_cast<uint64_t> (ts.tv_nsec) / UINT64_C (1000);
}

static double timeval_to_s (const struct timeval &tv_)
{
    return static_cast<double> (tv_.tv_sec)
           + static_cast<double> (tv_.tv_usec) / 1000000.0;
}

static usage_t total_usage ()
{
    struct rusage self_usage;
    struct rusage child_usage;
    memset (&self_usage, 0, sizeof self_usage);
    memset (&child_usage, 0, sizeof child_usage);
    getrusage (RUSAGE_SELF, &self_usage);
    getrusage (RUSAGE_CHILDREN, &child_usage);

    usage_t usage;
    usage.user_s = timeval_to_s (self_usage.ru_utime)
                   + timeval_to_s (child_usage.ru_utime);
    usage.system_s = timeval_to_s (self_usage.ru_stime)
                     + timeval_to_s (child_usage.ru_stime);
    return usage;
}

static void fill_payload (void *data_, size_t size_, uint64_t seq_)
{
    unsigned char *const data = static_cast<unsigned char *> (data_);
    memset (data, static_cast<int> (seq_ & 0xffu), size_);
    if (size_ >= sizeof seq_)
        memcpy (data, &seq_, sizeof seq_);
}

static uint64_t sample_payload (const void *data_, size_t size_)
{
    const unsigned char *const data =
      static_cast<const unsigned char *> (data_);
    uint64_t sum = 0;
    if (size_)
        sum += data[0];
    if (size_ > 1)
        sum += data[size_ - 1];
    if (size_ > 4096)
        sum += data[size_ / 2];
    return sum;
}

static uint64_t scan_payload (const void *data_, size_t size_)
{
    const unsigned char *const data =
      static_cast<const unsigned char *> (data_);
    uint64_t sum = 0;
    for (size_t i = 0; i != size_; ++i)
        sum += data[i];
    return sum;
}

static const char *mode_name (bench_mode_t mode_)
{
    switch (mode_) {
        case mode_ipc:
            return "ipc";
        case mode_shm_copy:
            return "shm-copy";
        case mode_shm_direct:
            return "shm-direct";
    }
    return "unknown";
}

static int parse_mode (const char *value_, bench_mode_t *mode_)
{
    if (strcmp (value_, "ipc") == 0) {
        *mode_ = mode_ipc;
        return 0;
    }
    if (strcmp (value_, "shm-copy") == 0) {
        *mode_ = mode_shm_copy;
        return 0;
    }
    if (strcmp (value_, "shm-direct") == 0) {
        *mode_ = mode_shm_direct;
        return 0;
    }
    return -1;
}

static const char *scan_name (scan_mode_t mode_)
{
    return mode_ == scan_full ? "full" : "sample";
}

static int env_scan_mode (scan_mode_t *mode_)
{
    const char *const value = getenv ("ZMQ_SHM_PAIR_THR_SCAN");
    if (!value || !*value || strcmp (value, "sample") == 0) {
        *mode_ = scan_sample;
        return 0;
    }
    if (strcmp (value, "full") == 0) {
        *mode_ = scan_full;
        return 0;
    }
    fprintf (stderr, "invalid ZMQ_SHM_PAIR_THR_SCAN\n");
    return -1;
}

static int checked (int rc_, const char *what_)
{
    if (rc_ == -1) {
        fprintf (stderr, "%s: %s\n", what_, zmq_strerror (errno));
        return -1;
    }
    return 0;
}

static int env_cpu (const char *name_)
{
    const char *const value = getenv (name_);
    if (!value || !*value)
        return -1;
    char *end = NULL;
    const long cpu = strtol (value, &end, 10);
    if (!end || *end || cpu < 0 || cpu > 65535) {
        fprintf (stderr, "invalid %s\n", name_);
        return -2;
    }
    return static_cast<int> (cpu);
}

static int pin_to_cpu (int cpu_)
{
    if (cpu_ < 0)
        return 0;
#if defined __linux__
    cpu_set_t set;
    CPU_ZERO (&set);
    CPU_SET (cpu_, &set);
    if (sched_setaffinity (0, sizeof set, &set) != 0) {
        perror ("sched_setaffinity");
        return -1;
    }
    return 0;
#else
    (void) cpu_;
    fprintf (stderr, "CPU pinning is only supported on Linux\n");
    return -1;
#endif
}

static int send_regular (void *socket_,
                         unsigned char *buffer_,
                         size_t size_,
                         uint64_t seq_)
{
    fill_payload (buffer_, size_, seq_);
    const int rc = zmq_send (socket_, buffer_, size_, 0);
    if (rc == -1) {
        fprintf (stderr, "zmq_send: %s\n", zmq_strerror (errno));
        return -1;
    }
    if (static_cast<size_t> (rc) != size_) {
        fprintf (stderr, "zmq_send: short send\n");
        return -1;
    }
    return 0;
}

static int send_direct (void *socket_, size_t size_, uint64_t seq_)
{
    zmq_msg_t msg;
    while (zmq_shm_msg_init (socket_, &msg, size_) == -1) {
        if (errno != EAGAIN) {
            fprintf (stderr, "zmq_shm_msg_init: %s\n", zmq_strerror (errno));
            return -1;
        }
        usleep (100);
    }
    fill_payload (zmq_msg_data (&msg), size_, seq_);
    const int rc = zmq_shm_msg_send (&msg, socket_, 0);
    if (rc == -1) {
        fprintf (stderr, "zmq_shm_msg_send: %s\n", zmq_strerror (errno));
        zmq_msg_close (&msg);
        return -1;
    }
    if (static_cast<size_t> (rc) != size_) {
        fprintf (stderr, "zmq_shm_msg_send: short send\n");
        zmq_msg_close (&msg);
        return -1;
    }
    if (checked (zmq_msg_close (&msg), "zmq_msg_close") != 0)
        return -1;
    return 0;
}

static int sender_main (const char *endpoint_,
                        bench_mode_t mode_,
                        size_t message_size_,
                        uint64_t message_count_,
                        int child_cpu_)
{
    if (pin_to_cpu (child_cpu_) != 0)
        return 1;

    void *ctx = zmq_ctx_new ();
    if (!ctx) {
        fprintf (stderr, "zmq_ctx_new: %s\n", zmq_strerror (errno));
        return 1;
    }
    void *socket = zmq_socket (ctx, ZMQ_PAIR);
    if (!socket) {
        fprintf (stderr, "zmq_socket: %s\n", zmq_strerror (errno));
        return 1;
    }
    if (checked (zmq_connect (socket, endpoint_), "zmq_connect") != 0)
        return 1;

    unsigned char *buffer = NULL;
    if (mode_ != mode_shm_direct) {
        buffer = static_cast<unsigned char *> (malloc (message_size_));
        if (!buffer) {
            fprintf (stderr, "malloc failed\n");
            return 1;
        }
    }

    for (uint64_t i = 0; i != message_count_ + 1; ++i) {
        const int rc = mode_ == mode_shm_direct
                         ? send_direct (socket, message_size_, i)
                         : send_regular (socket, buffer, message_size_, i);
        if (rc != 0) {
            free (buffer);
            return 1;
        }
    }

    free (buffer);
    if (checked (zmq_close (socket), "zmq_close") != 0)
        return 1;
    if (checked (zmq_ctx_term (ctx), "zmq_ctx_term") != 0)
        return 1;
    return 0;
}

static pid_t start_sender (const char *program_,
                           const char *endpoint_,
                           bench_mode_t mode_,
                           size_t message_size_,
                           uint64_t message_count_,
                           int child_cpu_)
{
    char size_arg[32];
    char count_arg[32];
    char cpu_arg[32];
    snprintf (size_arg, sizeof size_arg, "%zu", message_size_);
    snprintf (count_arg, sizeof count_arg, "%" PRIu64, message_count_);
    snprintf (cpu_arg, sizeof cpu_arg, "%d", child_cpu_);

    const pid_t child = fork ();
    if (child == -1)
        return -1;
    if (child == 0) {
        execl (program_, program_, "--sender", endpoint_, mode_name (mode_),
               size_arg, count_arg, cpu_arg,
               static_cast<char *> (NULL));
        perror ("execl");
        _exit (127);
    }
    return child;
}

static int recv_one (void *socket_,
                     size_t message_size_,
                     scan_mode_t scan_mode_,
                     uint64_t *checksum_)
{
    zmq_msg_t msg;
    if (checked (zmq_msg_init (&msg), "zmq_msg_init") != 0)
        return -1;
    const int rc = zmq_msg_recv (&msg, socket_, 0);
    if (rc == -1) {
        fprintf (stderr, "zmq_msg_recv: %s\n", zmq_strerror (errno));
        zmq_msg_close (&msg);
        return -1;
    }
    if (static_cast<size_t> (rc) != message_size_) {
        fprintf (stderr, "zmq_msg_recv: expected %zu, got %d\n",
                 message_size_, rc);
        zmq_msg_close (&msg);
        return -1;
    }
    *checksum_ +=
      scan_mode_ == scan_full
        ? scan_payload (zmq_msg_data (&msg), zmq_msg_size (&msg))
        : sample_payload (zmq_msg_data (&msg), zmq_msg_size (&msg));
    if (checked (zmq_msg_close (&msg), "zmq_msg_close") != 0)
        return -1;
    return 0;
}

static int run (const char *program_,
                bench_mode_t mode_,
                size_t message_size_,
                uint64_t message_count_)
{
    affinity_t affinity;
    affinity.parent_cpu = env_cpu ("ZMQ_SHM_PAIR_THR_PARENT_CPU");
    affinity.child_cpu = env_cpu ("ZMQ_SHM_PAIR_THR_CHILD_CPU");
    if (affinity.parent_cpu == -2 || affinity.child_cpu == -2)
        return 1;
    scan_mode_t scan_mode = scan_sample;
    if (env_scan_mode (&scan_mode) != 0)
        return 1;

    char path[128];
    snprintf (path, sizeof path, "/tmp/libzmq-shm-pair-thr-%ld",
              static_cast<long> (getpid ()));
    unlink (path);

    char endpoint[160];
    snprintf (endpoint, sizeof endpoint, "%s://%s",
              mode_ == mode_ipc ? "ipc" : "shm", path);

    const usage_t before = total_usage ();
    void *ctx = zmq_ctx_new ();
    if (!ctx) {
        fprintf (stderr, "zmq_ctx_new: %s\n", zmq_strerror (errno));
        return 1;
    }
    void *socket = zmq_socket (ctx, ZMQ_PAIR);
    if (!socket) {
        fprintf (stderr, "zmq_socket: %s\n", zmq_strerror (errno));
        return 1;
    }
    if (checked (zmq_bind (socket, endpoint), "zmq_bind") != 0)
        return 1;

    const pid_t child = start_sender (program_, endpoint, mode_, message_size_,
                                      message_count_, affinity.child_cpu);
    if (child == -1) {
        perror ("fork");
        return 1;
    }

    if (pin_to_cpu (affinity.parent_cpu) != 0)
        return 1;

    uint64_t checksum = 0;
    if (recv_one (socket, message_size_, scan_mode, &checksum) != 0)
        return 1;

    const uint64_t start_us = now_us ();
    for (uint64_t i = 0; i != message_count_; ++i)
        if (recv_one (socket, message_size_, scan_mode, &checksum) != 0)
            return 1;
    const uint64_t elapsed_us = now_us () - start_us;

    int status = 0;
    if (waitpid (child, &status, 0) != child) {
        perror ("waitpid");
        return 1;
    }
    if (!WIFEXITED (status) || WEXITSTATUS (status) != 0) {
        fprintf (stderr, "sender failed\n");
        return 1;
    }

    const usage_t after = total_usage ();
    checked (zmq_close (socket), "zmq_close");
    checked (zmq_ctx_term (ctx), "zmq_ctx_term");
    unlink (path);

    const double elapsed_s =
      static_cast<double> (elapsed_us ? elapsed_us : 1) / 1000000.0;
    const double msg_s = static_cast<double> (message_count_) / elapsed_s;
    const double gib_s =
      static_cast<double> (message_count_)
      * static_cast<double> (message_size_) / elapsed_s
      / (1024.0 * 1024.0 * 1024.0);
    const double user_s = after.user_s - before.user_s;
    const double system_s = after.system_s - before.system_s;
    const double cpu_s = user_s + system_s;

    printf ("mode,scan,message_size,message_count,parent_cpu,child_cpu,elapsed_us,msg_per_s,gib_per_s,user_s,system_s,cpu_s,cpu_us_per_msg,checksum\n");
    printf ("%s,%s,%zu,%" PRIu64 ",%d,%d,%" PRIu64 ",%.3f,%.6f,%.6f,%.6f,%.6f,%.6f,%" PRIu64 "\n",
            mode_name (mode_), scan_name (scan_mode), message_size_,
            message_count_, affinity.parent_cpu, affinity.child_cpu,
            elapsed_us, msg_s, gib_s, user_s,
            system_s, cpu_s,
            cpu_s * 1000000.0 / static_cast<double> (message_count_),
            checksum);
    return 0;
}
}

int main (int argc, char **argv)
{
    if (argc == 7 && strcmp (argv[1], "--sender") == 0) {
        bench_mode_t mode;
        if (parse_mode (argv[3], &mode) != 0) {
            fprintf (stderr, "unknown mode: %s\n", argv[3]);
            return 1;
        }

        char *end = NULL;
        const unsigned long long message_size = strtoull (argv[4], &end, 10);
        if (!end || *end || message_size == 0) {
            fprintf (stderr, "invalid message size\n");
            return 1;
        }
        end = NULL;
        const unsigned long long message_count = strtoull (argv[5], &end, 10);
        if (!end || *end || message_count == 0) {
            fprintf (stderr, "invalid message count\n");
            return 1;
        }
        end = NULL;
        const long child_cpu = strtol (argv[6], &end, 10);
        if (!end || *end || child_cpu < -1 || child_cpu > 65535) {
            fprintf (stderr, "invalid child CPU\n");
            return 1;
        }

        return sender_main (argv[2], mode, static_cast<size_t> (message_size),
                            static_cast<uint64_t> (message_count),
                            static_cast<int> (child_cpu));
    }

    if (argc != 4) {
        printf ("usage: shm_pair_thr <ipc|shm-copy|shm-direct> "
                "<message-size> <message-count>\n");
        return 1;
    }

    bench_mode_t mode;
    if (parse_mode (argv[1], &mode) != 0) {
        fprintf (stderr, "unknown mode: %s\n", argv[1]);
        return 1;
    }

    char *end = NULL;
    const unsigned long long message_size = strtoull (argv[2], &end, 10);
    if (!end || *end || message_size == 0) {
        fprintf (stderr, "invalid message size\n");
        return 1;
    }
    end = NULL;
    const unsigned long long message_count = strtoull (argv[3], &end, 10);
    if (!end || *end || message_count == 0) {
        fprintf (stderr, "invalid message count\n");
        return 1;
    }

    return run (argv[0], mode, static_cast<size_t> (message_size),
                static_cast<uint64_t> (message_count));
}
