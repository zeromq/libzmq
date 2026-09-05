/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"
#include <cstdlib>
#include <cstring>
#ifdef ZMQ_HAVE_WINDOWS
#include <tlhelp32.h>
#elif defined ZMQ_HAVE_LINUX
#include <dirent.h>
#endif

#ifdef ZMQ_BUILD_DRAFT_API

void setUp ()
{
}
void tearDown ()
{
}

static void *manual_context (int slots_ = 1)
{
    void *ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx);
    if (zmq_ctx_set (ctx, ZMQ_MANUAL_IO_THREADS, 1) == -1) {
        TEST_ASSERT_EQUAL_INT (ENOTSUP, errno);
        TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (ctx));
        TEST_IGNORE_MESSAGE (
          "Selected backend/dependencies do not support manual I/O");
    }
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_set (ctx, ZMQ_IO_THREADS, slots_));
    return ctx;
}

static void *socket_with_linger (void *ctx_, int type_, int linger_ = 0)
{
    void *s = zmq_socket (ctx_, type_);
    TEST_ASSERT_NOT_NULL (s);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (s, ZMQ_LINGER, &linger_, sizeof linger_));
    return s;
}

static void bind_endpoint (void *socket_, const char *address_, char *endpoint_)
{
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (socket_, address_));
    size_t size = 256;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket_, ZMQ_LAST_ENDPOINT, endpoint_, &size));
}

static void
receive_byte (void *ctx_, void *socket_, char expected_, bool proof_ = false)
{
    for (int i = 0; i != 2000; ++i) {
        char byte;
        const int rc = zmq_recv (socket_, &byte, 1, ZMQ_DONTWAIT);
        if (rc == 1) {
            TEST_ASSERT_EQUAL_INT (expected_, byte);
            return;
        }
        TEST_ASSERT_EQUAL_INT (-1, rc);
        TEST_ASSERT_EQUAL_INT (EAGAIN, errno);
        //  Fault-injection proof: removing stepping must fail the TCP test.
        if (!(proof_ && std::getenv ("ZMQ_TEST_MANUAL_NO_STEP")))
            TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_step (ctx_, 2));
    }
    TEST_FAIL_MESSAGE ("No delivery within the bounded manual step loop");
}

static void test_no_progress_without_step ()
{
    void *ctx = manual_context ();
    void *pull = socket_with_linger (ctx, ZMQ_PULL);
    void *push = socket_with_linger (ctx, ZMQ_PUSH);
    char endpoint[256];
    bind_endpoint (pull, "tcp://127.0.0.1:*", endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (push, endpoint));
    TEST_ASSERT_EQUAL_INT (1, zmq_send (push, "a", 1, ZMQ_DONTWAIT));
    zmq_pollitem_t item = {pull, 0, ZMQ_POLLIN, 0};
    TEST_ASSERT_EQUAL_INT (0, zmq_poll (&item, 1, 50));
    char byte;
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (pull, &byte, 1, ZMQ_DONTWAIT));
    receive_byte (ctx, pull, 'a', true);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (push));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (pull));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (ctx));
}

static void round_trip (const char *address_)
{
    void *ctx = manual_context ();
    void *rep = socket_with_linger (ctx, ZMQ_REP);
    void *req = socket_with_linger (ctx, ZMQ_REQ);
    char endpoint[256];
    bind_endpoint (rep, address_, endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (req, endpoint));
    TEST_ASSERT_EQUAL_INT (1, zmq_send (req, "q", 1, ZMQ_DONTWAIT));
    receive_byte (ctx, rep, 'q');
    TEST_ASSERT_EQUAL_INT (1, zmq_send (rep, "r", 1, ZMQ_DONTWAIT));
    receive_byte (ctx, req, 'r');
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (req));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (rep));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (ctx));
}

static void test_tcp_round_trip ()
{
    round_trip ("tcp://127.0.0.1:*");
}
static void test_inproc_round_trip ()
{
    round_trip ("inproc://manual-round-trip");
}
static void test_ipc_round_trip ()
{
#ifdef ZMQ_HAVE_IPC
    round_trip ("ipc://*");
#else
    TEST_IGNORE_MESSAGE ("IPC unavailable");
#endif
}

static void test_termination_and_shutdown ()
{
    for (int linger = 0; linger <= 20; linger += 20) {
        void *ctx = manual_context ();
        void *push = socket_with_linger (ctx, ZMQ_PUSH, linger);
        //  Reserve and release an ephemeral endpoint: no listening peer.
        void *reservation = socket_with_linger (ctx, ZMQ_PULL);
        char endpoint[256];
        bind_endpoint (reservation, "tcp://127.0.0.1:*", endpoint);
        TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (reservation, endpoint));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (push, endpoint));
        TEST_ASSERT_EQUAL_INT (1, zmq_send (push, "x", 1, ZMQ_DONTWAIT));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_close (push));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_close (reservation));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (ctx));
    }
    void *ctx = manual_context ();
    void *s = socket_with_linger (ctx, ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_step (ctx, 0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_shutdown (ctx));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (s));
    for (int i = 0; i != 10; ++i)
        TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_step (ctx, 0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (ctx));
}

static void test_budget_and_fairness ()
{
    void *ctx = manual_context (4);
    void *push[4], *pull[4];
    bool received[4] = {false, false, false, false};
    for (int i = 0; i != 4; ++i) {
        pull[i] = socket_with_linger (ctx, ZMQ_PULL);
        push[i] = socket_with_linger (ctx, ZMQ_PUSH);
        const uint64_t affinity = uint64_t (1) << i;
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (push[i], ZMQ_AFFINITY, &affinity, sizeof affinity));
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (pull[i], ZMQ_AFFINITY, &affinity, sizeof affinity));
        char endpoint[256];
        bind_endpoint (pull[i], "tcp://127.0.0.1:*", endpoint);
        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (push[i], endpoint));
        TEST_ASSERT_EQUAL_INT (1, zmq_send (push[i], "f", 1, ZMQ_DONTWAIT));
    }
    bool exhausted = false;
    int count = 0;
    const zmq_ctx_step_budget_t budget = {2, 1, 1, 1};
    for (int tick = 0; tick != 4000 && count != 4; ++tick) {
        zmq_ctx_step_result_t result;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_step_budget (ctx, &budget, &result));
        TEST_ASSERT_LESS_OR_EQUAL_UINT32 (1, result.events_processed);
        TEST_ASSERT_LESS_OR_EQUAL_UINT32 (1, result.commands_processed);
        TEST_ASSERT_LESS_OR_EQUAL_UINT32 (1, result.timers_processed);
        if (result.flags & ZMQ_CTX_STEP_BUDGET_EXHAUSTED) {
            exhausted = true;
            TEST_ASSERT_TRUE (result.flags & ZMQ_CTX_STEP_MORE_WORK);
            TEST_ASSERT_EQUAL_INT (0, result.next_timeout_ms);
        }
        for (int i = 0; i != 4; ++i) {
            char byte;
            if (!received[i]
                && zmq_recv (pull[i], &byte, 1, ZMQ_DONTWAIT) == 1) {
                received[i] = true;
                ++count;
            }
        }
    }
    TEST_ASSERT_EQUAL_INT (4, count);
    TEST_ASSERT_TRUE (exhausted);
    for (int i = 0; i != 4; ++i) {
        TEST_ASSERT_SUCCESS_ERRNO (zmq_close (push[i]));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_close (pull[i]));
    }
    //  Also budget closed-socket mailboxes while the reaper is active.
    for (int i = 0; i != 100; ++i) {
        zmq_ctx_step_result_t result;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_step_budget (ctx, &budget, &result));
        TEST_ASSERT_LESS_OR_EQUAL_UINT32 (1, result.commands_processed);
    }
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (ctx));
}

static void test_misuse_and_idle ()
{
    TEST_ASSERT_FAILURE_ERRNO (EFAULT, zmq_ctx_step (NULL, 0));
    void *ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx);
    TEST_ASSERT_FAILURE_ERRNO (ENOTSUP, zmq_ctx_step (ctx, 0));
    TEST_ASSERT_FAILURE_ERRNO (EINVAL,
                               zmq_ctx_set (ctx, ZMQ_MANUAL_IO_THREADS, 2));
    const int rc = zmq_ctx_set (ctx, ZMQ_MANUAL_IO_THREADS, 1);
    if (rc == -1) {
        TEST_ASSERT_EQUAL_INT (ENOTSUP, errno);
        TEST_ASSERT_EQUAL_INT (0, zmq_ctx_get (ctx, ZMQ_MANUAL_IO_THREADS));
    } else {
        TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_ctx_step (ctx, -1));
        zmq_ctx_step_result_t result;
        TEST_ASSERT_EQUAL_INT (0, zmq_ctx_step_budget (ctx, NULL, &result));
        TEST_ASSERT_EQUAL_UINT32 (ZMQ_CTX_STEP_IDLE, result.flags);
        TEST_ASSERT_EQUAL_INT (-1, result.next_timeout_ms);
    }
    void *s = socket_with_linger (ctx, ZMQ_PAIR);
    TEST_ASSERT_FAILURE_ERRNO (EINVAL,
                               zmq_ctx_set (ctx, ZMQ_MANUAL_IO_THREADS, 0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (s));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (ctx));
}

static int monitor_event (void *monitor_)
{
    unsigned char data[6];
    const int rc = zmq_recv (monitor_, data, sizeof data, ZMQ_DONTWAIT);
    if (rc == -1) {
        TEST_ASSERT_EQUAL_INT (EAGAIN, errno);
        return 0;
    }
    TEST_ASSERT_EQUAL_INT (6, rc);
    uint16_t event;
    memcpy (&event, data, sizeof event);
    char endpoint[256];
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_recv (monitor_, endpoint, sizeof endpoint, ZMQ_DONTWAIT));
    return event;
}

static void test_reconnect_timers ()
{
    void *ctx = manual_context (2);
    void *peer = socket_with_linger (ctx, ZMQ_PULL);
    char endpoint[256];
    bind_endpoint (peer, "tcp://127.0.0.1:*", endpoint);
    void *client[2], *monitor[2];
    for (int i = 0; i != 2; ++i) {
        client[i] = socket_with_linger (ctx, ZMQ_PUSH);
        monitor[i] = socket_with_linger (ctx, ZMQ_PAIR);
        const int interval = 20;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (client[i], ZMQ_RECONNECT_IVL,
                                                   &interval, sizeof interval));
        const char *address =
          i ? "inproc://manual-monitor-1" : "inproc://manual-monitor-0";
        TEST_ASSERT_SUCCESS_ERRNO (zmq_socket_monitor (
          client[i], address,
          ZMQ_EVENT_DISCONNECTED | ZMQ_EVENT_CONNECT_RETRIED));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (monitor[i], address));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client[i], endpoint));
        TEST_ASSERT_EQUAL_INT (1, zmq_send (client[i], "t", 1, ZMQ_DONTWAIT));
        receive_byte (ctx, peer, 't');
    }
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (peer));
    bool retried[2] = {false, false};
    bool disconnected[2] = {false, false};
    bool next_deadline = false;
    for (int i = 0; i != 2000 && (!retried[0] || !retried[1]); ++i) {
        const zmq_ctx_step_budget_t budget = {2, 0, 0, 0};
        zmq_ctx_step_result_t result;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_step_budget (ctx, &budget, &result));
        next_deadline |= result.next_timeout_ms > 0;
        for (int j = 0; j != 2; ++j) {
            int event;
            while ((event = monitor_event (monitor[j])) != 0) {
                retried[j] |= event == ZMQ_EVENT_CONNECT_RETRIED;
                disconnected[j] |= event == ZMQ_EVENT_DISCONNECTED;
            }
        }
    }
    TEST_ASSERT_TRUE (retried[0] && retried[1] && disconnected[0]
                      && disconnected[1]);
    TEST_ASSERT_TRUE (next_deadline);
    //  Deliberately leave timers overdue between host frames. No stepping.
    TEST_ASSERT_EQUAL_INT (0, zmq_poll (NULL, 0, 80));
    const zmq_ctx_step_budget_t budget = {0, 0, 0, 1};
    zmq_ctx_step_result_t result;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_step_budget (ctx, &budget, &result));
    TEST_ASSERT_EQUAL_UINT32 (1, result.timers_processed);
    TEST_ASSERT_TRUE (result.flags & ZMQ_CTX_STEP_BUDGET_EXHAUSTED);
    TEST_ASSERT_TRUE (result.flags & ZMQ_CTX_STEP_MORE_WORK);
    TEST_ASSERT_EQUAL_INT (0, result.next_timeout_ms);
    for (int i = 0; i != 2; ++i) {
        TEST_ASSERT_SUCCESS_ERRNO (zmq_close (client[i]));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_close (monitor[i]));
    }
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (ctx));
}

struct callback_state_t
{
    void *ctx;
    void *barrier;
    bool called;
    int step_errno, term_errno, worker_rc;
};

static void blocked_free (void *data_, void *hint_)
{
    callback_state_t *state = static_cast<callback_state_t *> (hint_);
    state->called = true;
    const int step_rc = zmq_ctx_step (state->ctx, 0);
    state->step_errno = step_rc == -1 ? errno : 0;
    const int term_rc = zmq_ctx_term (state->ctx);
    state->term_errno = term_rc == -1 ? errno : 0;
    //  The application callback deliberately blocks, making overlap deterministic.
    const int send_rc = zmq_send (state->barrier, "b", 1, 0);
    char byte;
    const int recv_rc = zmq_recv (state->barrier, &byte, 1, 0);
    state->worker_rc = send_rc == 1 && recv_rc == 1 ? 0 : -1;
    std::free (data_);
}

static void stepping_worker (void *arg_)
{
    callback_state_t *state = static_cast<callback_state_t *> (arg_);
    for (int i = 0; i != 2000 && !state->called; ++i)
        if (zmq_ctx_step (state->ctx, 2) == -1) {
            state->worker_rc = -1;
            return;
        }
}

static void test_concurrent_reentrant_and_handoff ()
{
    void *ctx = manual_context ();
    void *pull = socket_with_linger (ctx, ZMQ_PULL);
    void *push = socket_with_linger (ctx, ZMQ_PUSH);
    char endpoint[256];
    bind_endpoint (pull, "tcp://127.0.0.1:*", endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (push, endpoint));
    TEST_ASSERT_EQUAL_INT (1, zmq_send (push, "s", 1, ZMQ_DONTWAIT));
    receive_byte (ctx, pull, 's');

    //  Separate, ordinary context supplies a bounded application-owned barrier.
    void *sync_ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (sync_ctx);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_set (sync_ctx, ZMQ_IO_THREADS, 0));
    void *main_barrier = socket_with_linger (sync_ctx, ZMQ_PAIR);
    void *worker_barrier = socket_with_linger (sync_ctx, ZMQ_PAIR);
    const int timeout = 5000;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (main_barrier, ZMQ_RCVTIMEO, &timeout, sizeof timeout));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (worker_barrier, ZMQ_RCVTIMEO, &timeout, sizeof timeout));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_bind (main_barrier, "inproc://step-barrier"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (worker_barrier, "inproc://step-barrier"));

    callback_state_t state = {ctx, worker_barrier, false, 0, 0, -1};
    void *data = std::malloc (8192);
    TEST_ASSERT_NOT_NULL (data);
    memset (data, 0x42, 8192);
    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_data (&msg, data, 8192, blocked_free, &state));
    TEST_ASSERT_EQUAL_INT (8192, zmq_msg_send (&msg, push, ZMQ_DONTWAIT));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
    void *thread = zmq_threadstart (stepping_worker, &state);
    char byte;
    TEST_ASSERT_EQUAL_INT (1, zmq_recv (main_barrier, &byte, 1, 0));
    TEST_ASSERT_FAILURE_ERRNO (EBUSY, zmq_ctx_step (ctx, 0));
    TEST_ASSERT_FAILURE_ERRNO (EBUSY, zmq_ctx_term (ctx));
    TEST_ASSERT_EQUAL_INT (1, zmq_send (main_barrier, "r", 1, ZMQ_DONTWAIT));
    zmq_threadclose (thread);
    TEST_ASSERT_EQUAL_INT (EBUSY, state.step_errno);
    TEST_ASSERT_EQUAL_INT (EBUSY, state.term_errno);
    TEST_ASSERT_EQUAL_INT (0, state.worker_rc);
    //  Joining the host worker establishes the required happens-before handoff.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_step (ctx, 0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (pull));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (push));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (ctx));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (main_barrier));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (worker_barrier));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (sync_ctx));
}

static void test_linger_delivers ()
{
    void *ctx = manual_context ();
    void *peer_ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (peer_ctx);
    void *pull = socket_with_linger (peer_ctx, ZMQ_PULL);
    void *push = socket_with_linger (ctx, ZMQ_PUSH, 2000);
    char endpoint[256];
    bind_endpoint (pull, "tcp://127.0.0.1:*", endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (push, endpoint));
    TEST_ASSERT_EQUAL_INT (1, zmq_send (push, "l", 1, ZMQ_DONTWAIT));
    receive_byte (ctx, pull, 'l');
    char payload[65536];
    memset (payload, 'L', sizeof payload);
    for (int i = 0; i != 20; ++i)
        TEST_ASSERT_EQUAL_INT (
          sizeof payload,
          zmq_send (push, payload, sizeof payload, ZMQ_DONTWAIT));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (push));
    //  No explicit step: term itself must transmit the lingering queue.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (ctx));
    const int timeout = 2000;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pull, ZMQ_RCVTIMEO, &timeout, sizeof timeout));
    for (int i = 0; i != 20; ++i)
        TEST_ASSERT_EQUAL_INT (sizeof payload,
                               zmq_recv (pull, payload, sizeof payload, 0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (pull));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (peer_ctx));
}

struct closing_worker_t
{
    void *socket;
    int recv_errno, close_rc;
};

static void close_after_shutdown (void *arg_)
{
    closing_worker_t *state = static_cast<closing_worker_t *> (arg_);
    char byte;
    const int rc = zmq_recv (state->socket, &byte, 1, 0);
    state->recv_errno = rc == -1 ? errno : 0;
    state->close_rc = zmq_close (state->socket);
}

static void test_term_waits_for_application_close ()
{
    void *ctx = manual_context ();
    void *s = socket_with_linger (ctx, ZMQ_PULL);
    closing_worker_t state = {s, 0, -1};
    void *thread = zmq_threadstart (close_after_shutdown, &state);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (ctx));
    zmq_threadclose (thread);
    TEST_ASSERT_EQUAL_INT (ETERM, state.recv_errno);
    TEST_ASSERT_EQUAL_INT (0, state.close_rc);
}

static void test_thread_safe_reaping ()
{
    void *ctx = manual_context ();
    void *server = socket_with_linger (ctx, ZMQ_SERVER);
    void *client = socket_with_linger (ctx, ZMQ_CLIENT);
    char endpoint[256];
    bind_endpoint (server, "tcp://127.0.0.1:*", endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, endpoint));
    TEST_ASSERT_EQUAL_INT (1, zmq_send (client, "s", 1, ZMQ_DONTWAIT));
    receive_byte (ctx, server, 's');
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (client));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (server));
    const zmq_ctx_step_budget_t budget = {0, 1, 1, 1};
    for (int i = 0; i != 100; ++i) {
        zmq_ctx_step_result_t result;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_step_budget (ctx, &budget, &result));
        TEST_ASSERT_LESS_OR_EQUAL_UINT32 (1, result.commands_processed);
    }
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (ctx));
}

static int thread_count ()
{
    int count = 0;
#ifdef ZMQ_HAVE_WINDOWS
    //  Winsock select may lazily start an OS helper in mswsock.dll. Count
    //  application/CRT/libzmq threads, not Windows provider/thread-pool workers.
    //  Resolve the diagnostic API dynamically; it is not available everywhere.
    typedef LONG (NTAPI * query_t) (HANDLE, int, PVOID, ULONG, PULONG);
    const HMODULE ntdll = GetModuleHandleA ("ntdll.dll");
    const HMODULE mswsock = GetModuleHandleA ("mswsock.dll");
    query_t query = reinterpret_cast<query_t> (
      GetProcAddress (ntdll, "NtQueryInformationThread"));
    if (!query)
        TEST_IGNORE_MESSAGE ("Windows thread-entry inspection unavailable");
    HANDLE snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, 0);
    TEST_ASSERT_TRUE (snapshot != INVALID_HANDLE_VALUE);
    THREADENTRY32 entry = {sizeof entry};
    if (Thread32First (snapshot, &entry))
        do {
            if (entry.th32OwnerProcessID == GetCurrentProcessId ()) {
                HANDLE thread = OpenThread (THREAD_QUERY_INFORMATION, FALSE,
                                            entry.th32ThreadID);
                if (!thread)
                    continue; // A Windows helper can exit after the snapshot.
                void *start = NULL;
                //  ThreadQuerySetWin32StartAddress has value 9.
                const LONG rc = query (thread, 9, &start, sizeof start, NULL);
                CloseHandle (thread);
                TEST_ASSERT_EQUAL_INT (0, rc);
                HMODULE module = NULL;
                TEST_ASSERT_TRUE (GetModuleHandleExA (
                  GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                    | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                  static_cast<const char *> (start), &module));
                if (module != ntdll && module != mswsock)
                    ++count;
            }
        } while (Thread32Next (snapshot, &entry));
    CloseHandle (snapshot);
#elif defined ZMQ_HAVE_LINUX
    DIR *tasks = opendir ("/proc/self/task");
    TEST_ASSERT_NOT_NULL (tasks);
    struct dirent *entry;
    while ((entry = readdir (tasks)) != NULL)
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9')
            ++count;
    closedir (tasks);
#else
    TEST_IGNORE_MESSAGE (
      "Native thread enumeration unavailable on this target");
#endif
    return count;
}

static void test_no_actor_threads ()
{
    void *ctx = manual_context (4);
    const int before = thread_count ();
    void *pull = socket_with_linger (ctx, ZMQ_PULL);
    void *push = socket_with_linger (ctx, ZMQ_PUSH);
    char endpoint[256];
    bind_endpoint (pull, "tcp://127.0.0.1:*", endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (push, endpoint));
    TEST_ASSERT_EQUAL_INT (before, thread_count ());
    TEST_ASSERT_EQUAL_INT (1, zmq_send (push, "n", 1, ZMQ_DONTWAIT));
    receive_byte (ctx, pull, 'n');
    TEST_ASSERT_EQUAL_INT (before, thread_count ());
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (push));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (pull));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (ctx));

    //  Positive control: enumeration must see the five ordinary actor workers.
    ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_set (ctx, ZMQ_IO_THREADS, 4));
    pull = socket_with_linger (ctx, ZMQ_PULL);
    TEST_ASSERT_GREATER_OR_EQUAL_INT (before + 5, thread_count ());
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (pull));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (ctx));
}

int main ()
{
    setup_test_environment ();
    UNITY_BEGIN ();
    RUN_TEST (test_no_progress_without_step);
    RUN_TEST (test_tcp_round_trip);
    RUN_TEST (test_inproc_round_trip);
    RUN_TEST (test_ipc_round_trip);
    RUN_TEST (test_termination_and_shutdown);
    RUN_TEST (test_budget_and_fairness);
    RUN_TEST (test_misuse_and_idle);
    RUN_TEST (test_reconnect_timers);
    RUN_TEST (test_concurrent_reentrant_and_handoff);
    RUN_TEST (test_linger_delivers);
    RUN_TEST (test_term_waits_for_application_close);
    RUN_TEST (test_thread_safe_reaping);
    RUN_TEST (test_no_actor_threads);
    return UNITY_END ();
}
#else
int main ()
{
    return 0;
}
#endif
