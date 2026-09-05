# Manual I/O: design (Phase 1)

This design follows the source inventory in [00-survey.md](00-survey.md), based
on revision `8270a123`. The public surface supersedes the branch's unimplemented
IO_MODE declarations and the per-component sketch in
[issue 4903](https://github.com/zeromq/libzmq/issues/4903). Nothing identifying an
internal actor, slot, mailbox, descriptor or poller is exported.

## Public contract and field justification

Everything below is conditional on `ZMQ_BUILD_DRAFT_API`:

```c
/* Boolean context option; set before the first socket. Default: 0. */
#define ZMQ_MANUAL_IO_THREADS 12

typedef struct zmq_ctx_step_budget_t {
    int timeout_ms;          /* Maximum OS wait, in milliseconds; >= 0. */
    uint32_t max_events;     /* Maximum ready records/continuations; 0: unlimited. */
    uint32_t max_commands;   /* Maximum internal mailbox commands; 0: unlimited. */
    uint32_t max_timers;     /* Maximum due timer callbacks; 0: unlimited. */
} zmq_ctx_step_budget_t;

#define ZMQ_CTX_STEP_MORE_WORK 1
#define ZMQ_CTX_STEP_IDLE 2
#define ZMQ_CTX_STEP_BUDGET_EXHAUSTED 4

typedef struct zmq_ctx_step_result_t {
    uint32_t events_processed;
    uint32_t commands_processed;
    uint32_t timers_processed;
    uint32_t flags;
    int next_timeout_ms;     /* 0: work due now; -1: no scheduled timer. */
} zmq_ctx_step_result_t;

/* Advance context-owned work; timeout_ms < 0 fails with EINVAL. */
ZMQ_EXPORT int zmq_ctx_step (void *ctx, int timeout_ms);

/* NULL budget: nonblocking, no explicit count caps. NULL result: discard report.
 * Return total progress units, saturated at INT_MAX; -1 and errno on failure.
 * A ready record can invoke input, output and error callbacks on one source.
 * The count does not measure messages, bytes or successful connections. */
ZMQ_EXPORT int zmq_ctx_step_budget (void *ctx,
                                   const zmq_ctx_step_budget_t *budget,
                                   zmq_ctx_step_result_t *result);
```

`timeout_ms` is in the budget because that function has no separate timeout
argument. Each count cap controls a different potentially large loop: native
readiness, command reception, or timer execution. The three corresponding
result counters make the caps observable. A resumed mailbox is one event unit;
its commands also count individually. Counters saturate instead of overflowing.
`flags` distinguishes observed deferred work, an idle observation, and a cap
which prevented work. `next_timeout_ms` is the minimum next timer delay across
the context, clamped to INT_MAX, overridden to zero for deferred work. It is a
snapshot: a subsequently arriving network packet/command can make earlier
stepping useful.

There is no duration-nanoseconds field: an I/O callback, allocation, user free
callback, or OS resolver cannot be preempted. Count budgets and a maximum OS
wait are precise at their boundaries; a hard execution deadline would be a
false promise. There are no input flags, reserved words or struct-size fields
without a present purpose. These are new draft structs; existing public structs
and constants retain their layouts/numbers. A future draft revision may change
the new structs before stabilization.

The return value is events + commands + timers, not message delivery. MORE_WORK
means a ready record, mailbox continuation or due timer was deferred; IDLE means
no work was performed or observed due. BUDGET_EXHAUSTED means a configured cap
prevented processing observed work; it can accompany MORE_WORK. Observations
cannot promise that the network remains idle after return. Reaching a count
exactly does not by itself prove additional work exists.

Errors: EFAULT for a null/invalid context tag; ENOTSUP for a non-manual context
or unsupported option-enable configuration; EINVAL for negative timeouts,
non-boolean option values, or setting the option after startup; EBUSY for
overlapping/reentrant step or manual term; EINTR for an interrupted wait.
Shutdown does not disable stepping. Normal libzmq lifetime rules still prohibit
accessing a context after successful term.

## 4.1. One source of dispatch per backend

First extract `bool run_once(int timeout_ms)` with no public feature. Its boolean
means "the threaded loop should continue". `-1` is an internal sentinel meaning
use the existing timer-driven wait. An explicit nonnegative value caps the OS
wait, including an actual zero-timeout poll. Preserve original zero-load exits,
retired cleanup, EINTR behavior and callback order. The worker is simply
`while (run_once(-1)) {}`; pollset additionally retains its `stopping` condition.
No event body is copied.

The complete intended epoll body transformation, before applying it to the
other five backends, is:

```diff
 void zmq::epoll_t::loop ()
 {
-    epoll_event ev_buf[max_io_events];
-    while (true) {
-        const int timeout = static_cast<int> (execute_timers ());
-        if (get_load () == 0) {
-            if (timeout == 0)
-                break;
-            continue;
-        }
-        const int n = epoll_wait (_epoll_fd, &ev_buf[0], max_io_events,
-                                  timeout ? timeout : -1);
-        if (n == -1) {
-            errno_assert (errno == EINTR);
-            continue;
-        }
-        for (int i = 0; i < n; i++) {
-            const poll_entry_t *const pe =
-              static_cast<const poll_entry_t *> (ev_buf[i].data.ptr);
-            if (NULL == pe)
-                continue;
-            if (NULL == pe->events)
-                continue;
-            if (pe->fd == retired_fd)
-                continue;
-            if (ev_buf[i].events & (EPOLLERR | EPOLLHUP))
-                pe->events->in_event ();
-            if (pe->fd == retired_fd)
-                continue;
-            if (ev_buf[i].events & EPOLLOUT)
-                pe->events->out_event ();
-            if (pe->fd == retired_fd)
-                continue;
-            if (ev_buf[i].events & EPOLLIN)
-                pe->events->in_event ();
-        }
-        for (retired_t::iterator it = _retired.begin (), end = _retired.end ();
-             it != end; ++it) {
-            LIBZMQ_DELETE (*it);
-        }
-        _retired.clear ();
+    while (run_once (-1)) {
+    }
+}
+
+bool zmq::epoll_t::run_once (int timeout_ms_)
+{
+    epoll_event ev_buf[max_io_events];
+    const int timeout = static_cast<int> (execute_timers ());
+    if (get_load () == 0)
+        return timeout != 0;
+    const int wait = timeout_ms_ < 0 ? (timeout ? timeout : -1)
+                     : timeout ? std::min (timeout, timeout_ms_) : timeout_ms_;
+    const int n = epoll_wait (_epoll_fd, &ev_buf[0], max_io_events, wait);
+    if (n == -1) {
+        errno_assert (errno == EINTR);
+        return true;
+    }
+    for (int i = 0; i < n; i++) {
+        const poll_entry_t *const pe =
+          static_cast<const poll_entry_t *> (ev_buf[i].data.ptr);
+        if (NULL == pe)
+            continue;
+        if (NULL == pe->events)
+            continue;
+        if (pe->fd == retired_fd)
+            continue;
+        if (ev_buf[i].events & (EPOLLERR | EPOLLHUP))
+            pe->events->in_event ();
+        if (pe->fd == retired_fd)
+            continue;
+        if (ev_buf[i].events & EPOLLOUT)
+            pe->events->out_event ();
+        if (pe->fd == retired_fd)
+            continue;
+        if (ev_buf[i].events & EPOLLIN)
+            pe->events->in_event ();
+    }
+    for (retired_t::iterator it = _retired.begin (), end = _retired.end ();
+         it != end; ++it) {
+        LIBZMQ_DELETE (*it);
     }
+    _retired.clear ();
+    return true;
 }
```

Kqueue retains its fork exit and uses a null timespec only for negative waits.
Devpoll retains pending-registration acceptance before timers and sets
`dp_timeout` from the capped wait. Poll retains pre-wait retired compaction and
its timeout fast return. Pollset retains `stopping` and its own worker entry.
Select retains its family helper and `trigger_events`: both the WSA aggregate
wait and the per-family select use the correct zero/nonzero/infinite distinction;
the multi-family follow-up selects always remain nonblocking.

For budgeting, evolve the extracted body into one private template
`run_once_impl<Manual>(timeout_ms, state)`. The threaded wrapper instantiates
`<false>`; the manual driver instantiates `<true>`. Timer execution uses the
same approach. Compile-time conditions remove budget checks/counters/cursor
work from the threaded event loop even in a draft-enabled build. There is one
source location per backend for each native callback dispatch. This is source
sharing through specialization, not two separately maintained event loops.

Native ready records are budget boundaries: all existing callbacks within an
accepted record run in the original order, with original retirement checks.
Unprocessed level readiness remains registered. Epoll/kqueue request at most
the remaining record allowance; poll/select rotate their starting descriptor
when a bounded visit ends, so the next call continues after the last visited
source. Explicit pending work prevents a subsequent blocking wait. No stored
raw pointer outlives the backend's existing retirement rules.

## 4.2. One step and the wait covering all actors

In manual mode **all logical I/O slots and the reaper borrow one context-owned
instance of the selected poller**. Threaded mode continues constructing one
poller per worker. This is the central implementation choice: a single native
wait set contains every internal mailbox and transport registration. There is
no "first poller" on which a timeout can be spent while another has ready work,
no periodic wakeup, and no additional duplicate OS interest registry. Existing
actor objects, tids, `_slots`, command destinations, and pipe ownership remain
intact; `object_t` and `own_t` are unchanged. `ZMQ_IO_THREADS=0` still omits
transport slots. In manual mode affinity chooses a logical slot, not an OS
thread; slot count is not parallelism.

The context also registers its existing termination mailbox in the shared
poller. Its private callback consumes `done` and records completion. This
registration supplies a real wait source even while there are only timers or
no application sockets. It is removed before destroying the shared poller.

A step takes exclusive manual ownership, resumes a bounded snapshot of pending
mailbox continuations in FIFO order, then executes one shared poller iteration.
If it already made progress or has deferred work, its native wait is zero;
otherwise the wait is min(caller timeout, next timer). It executes timers again
after a timed wait so timers that expired during that wait fire in this call,
subject to their count cap. Negative public timeouts fail before any work.
Internal termination is allowed to wait indefinitely when there is no timer.

Fairness is over ready sources, which includes every logical slot mailbox.
Native epoll/kqueue ready queues and capped batches avoid repeatedly discarding
the tail of an oversized fetched batch; poll/select need the explicit rotating
cursor described above. Budgeted command continuations go to the tail of a
FIFO. A busy slot can consume a call's remaining budget but cannot repeatedly
overtake an already-deferred slot. Test with forced socket affinities and tiny
budgets, including the reaper alongside transport work. The guarantee assumes
finite registrations and callbacks that return.

Mailbox reception remains exactly `recv(command,0)` followed by the existing
`destination->process_command(command)`. Manual-only receiver adapters are
selected when registering I/O/reaper/closed-socket mailboxes. At a command cap,
one nonblocking lookahead can retain the next command in the receiver adapter
and enqueue a continuation. This does not change the mailbox implementation,
its producer synchronization, routing or signal transitions; it avoids relying
on an fd wakeup after a mailbox has become active. A retained command counts
when dispatched. Reaped socket adapters preserve their optional mutex, consume
the safe socket's reaper signal only on the original notification, and perform
`check_destroy()` after command processing. Adapter destruction unlinks pending
continuations. Default receivers keep their existing callbacks without a
per-command or per-event manual-mode test.

## 4.3. Timers

Retain absolute millisecond deadlines and remove-before-callback execution.
Due timers run even for timeout zero; overdue timers remain in the map until
the next step. A timer cap leaves unexecuted due timers in place and reports
MORE_WORK, BUDGET_EXHAUSTED and next_timeout_ms == 0. Reconnect, heartbeat,
handshake and linger therefore use their existing callbacks. The next deadline
is computed after callbacks, since they can add/cancel timers. Native wait
timeout is recomputed from that deadline; callback time is not charged as an
additional OS wait after progress has already occurred.

## 4.4. Termination

Manual `ctx_t::terminate()` first acquires the same exclusive ownership used
by step, then performs the existing pending-inproc/stop initiation. It releases
`_slot_sync` before callback execution, exactly as the threaded path releases
it before mailbox receive. Its concrete driver is:

```
while (!manual_done) {
    run pending command continuations;
    run shared poller (infinite maximum wait, limited by next timer);
    propagate EINTR, releasing manual ownership for a later term retry;
}
send existing stop commands to every I/O slot;
while (registrations other than the termination mailbox remain || timers remain)
    run shared poller (infinite maximum wait, limited by next timer);
remove termination-mailbox registration;
delete borrowing actors, then shared poller, then context;
```

The loops wait on actual registered descriptors/timers whenever no progress is
available. They have no retry count, delay, sleep, or polling interval. Finite
linger expires through the same session timer; zero linger discards unsent
queues; infinite linger may still block forever if messages cannot drain.
Applications must close their sockets, including sockets in other threads:
stop wakes blocking operations with ETERM, but term does not close a socket
still owned by another application thread. Its eventual close wakes the
registered reaper mailbox.

Term from a different host thread is supported after a synchronized handoff.
Concurrent term/step or reentrant term returns EBUSY before starting shutdown;
the public term wrapper must not call `shutdown_network()` for that failure.
Successful term invalidates the context, so the caller must prevent later API
entries. Shutdown -> any number of user steps -> term is supported; the
private completion flag preserves `done` even if a prior user step consumed it.

## 4.5. Thread identity and safety

Any host thread may step, one at a time; applications establish happens-before
between calls and obey existing socket thread-affinity rules. The manual
ownership guard uses nonblocking mutex acquisition **plus an active flag**,
because this checkout's `mutex_t` is recursive. Thus both concurrent and
same-thread reentrant calls get EBUSY. A successful acquisition records the
current OS thread identity without starting or joining a `thread_t`. It clears
active ownership on all exits, including EINTR.

The existing debug poller assertion remains unchanged for threaded workers.
For the shared manual poller it asserts that manual ownership is active and
the recorded owner equals the current thread. Setup registration takes the
same ownership guard; it is not made legal on arbitrary threads just because
`_worker.get_started()` is false. Mutation between steps is restricted to
existing application-side command enqueueing, not direct poller mutation.
The context option/startup synchronization prevents changing modes after actor
creation. No scheduling priority, affinity, name or signal-mask changes are
applied to the host's thread.

## 4.6. Backend and build coverage

| Backend/configuration | Manual mode | Verification target |
| --- | --- | --- |
| Linux epoll | supported | Linux CMake/autotools, full baseline and new tests |
| Windows epoll/wepoll | supported | Native Visual Studio CMake and new tests |
| macOS/BSD kqueue | supported | Source review; native runner availability reported separately |
| POSIX poll | supported | Linux forced-backend build/tests |
| Windows select | supported | Native forced-backend build/tests; retain provider-family handling |
| POSIX select | supported | Linux forced-backend build/tests |
| Solaris devpoll | ENOTSUP at option enable | Pure extraction only; no Solaris runner |
| AIX pollset | ENOTSUP at option enable | Pure extraction only; no AIX runner |
| VxWorks, regardless of backend | ENOTSUP at option enable | Existing task join spins; no runtime available |
| Builds with OpenPGM or NORM | ENOTSUP at option enable | External transport threads cannot be advanced by this driver |

Unsupported configurations still build, retain normal threaded behavior, and
reject enabling manual mode before any socket or manual worker is created.
New functions exist only in draft builds. CMake and autotools register the same
draft integration test. Commit sequence after the survey/design: pure backend
extraction; manual ownership/construction plumbing; step/budgets; termination;
integration tests; man pages/context option/NEWS and verification report.

## 4.7. Caller-visible hazards and boundedness

Use DONTWAIT (or zero send/receive timeout) and zero-timeout zmq_poll/poller
queries if the same thread is responsible for stepping. A positive socket
timeout still freezes progress until it expires; an infinite timeout can
deadlock. This is documented, not a new branch in every socket operation:
libzmq cannot infer that no other host thread will step later, and automatic
EAGAIN would change existing socket semantics.

Additional decisions required by the source survey:

* Manual monitor sockets use nonblocking sends configured at monitor creation,
  with the usual whole-message drop behavior under backpressure; the default
  monitor path is unchanged. A stalled observer cannot stall a step.
* Manual TCP reconnect uses an address resolved outside the step path. The
  endpoint's resolved numeric address is retained, so DNS changes require an
  application reconnect. Manual resolution must not run the NIC sleeping retry
  loop from a transport callback. The same audit applies to WS/proxy connects.
* Manual cleanup must use a single close attempt rather than the signaler's
  existing sleep/retry fallback. Preserve mailbox signaling semantics and the
  default cleanup path; isolate this cleanup policy from per-event code.
* Step is not a hard realtime or allocation-free API. A callback, OS operation,
  security provider or user message-free callback may take arbitrary time;
  callback reentry into step/term is rejected. Do not fork a live manual context
  and continue using it in the child. External OS/library helper threads are
  distinguished from libzmq-owned actor workers in verification.
* Application-facing sockets still process their own commands through their
  normal operations. Stepping does not steal a live socket from its owning
  thread. Inproc message progress can occur through socket calls alone; the
  no-progress-without-step proof must use TCP.

## Verification and explicit uncertainties at design time

The initial native Windows Release baseline is 102/102 serially; the first
parallel run had one fixed-port collision. The first Linux run on the Windows
mount had IPC filesystem failures and a radio/dish timeout; it is not a usable
green baseline. Linux-native verification is being established. Both results
must remain visible in the final report rather than being replaced by claims
about tests that have not run.

Native macOS/BSD, Solaris, AIX, VxWorks, Windows CE and mixed VMCI-provider
hardware are not available locally. Kqueue readiness fairness and Windows
mixed-provider behavior require native validation; source review cannot prove
them. Sanitizer/runtime availability and benchmark changes remain unverified
until measured. The survey identifies security/network dependency boundaries
whose internal thread behavior is not supplied by this checkout. These are
limits to report, not reasons to claim support was tested.
