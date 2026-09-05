# Manual I/O: source survey (Phase 0)

Surveyed revision: `8270a123a76401eed724d3f34f531e091efcbd63`, before
implementation. All `file:line` citations below refer to that revision, not to
line numbers after refactoring. This is an inventory of the checked-out sources;
statements about external libraries are identified as boundaries, not assumed
implementations.

Discovery used codebase-memory-mcp, freshly indexed as `D-repos-libzmq` in fast
mode. Its C++ extraction represents most out-of-line member definitions as file
modules and misses the context-start call edges. The exposed server has no
`index_status`, `list_projects`, or `check_index_coverage` tool. Consequently the
inventory was verified by reading the complete six poller implementations,
context startup/shutdown, thread implementation, and the relevant receiver and
socket-operation bodies. Text searches additionally covered `src` and the bundled
wepoll implementation. The index excludes `doc` and `external`; it cannot prove
absence there.

## 1. Context-owned thread creation

`zmq_ctx_new()` first calls `initialize_network()`, then constructs `ctx_t` and
checks its termination mailbox (`src/zmq.cpp:109`, `src/ctx.cpp:128`). The context
constructor sets `_starting = true`; it does not launch the I/O workers or reaper
(`src/ctx.cpp:53`). The actual chain is:

```
zmq_socket -> ctx_t::create_socket -> ctx_t::start
  -> new reaper_t -> reaper_t::start -> poller_t::start("Reaper")
  -> new io_thread_t [one per configured slot]
       -> io_thread_t::start -> poller_t::start("IO/<slot>")
  -> worker_poller_base_t::start
       -> thread_ctx_t::start_thread -> thread_t::start -> OS spawn
```

The entry/socket chain is at `src/zmq.cpp:230`, `src/ctx.cpp:462`,
`src/ctx.cpp:473`; reaper and I/O construction/start at `src/ctx.cpp:413` and
`src/ctx.cpp:424`; poller creation and mailbox registration at
`src/reaper.cpp:20`, `src/io_thread.cpp:16`; worker entry at
`src/reaper.cpp:43`, `src/io_thread.cpp:30`, `src/poller_base.cpp:104`.
The AIX pollset backend has its own `start()` and `worker_routine()` instead of
using `worker_poller_base_t` (`src/pollset.cpp:163`, `src/pollset.cpp:221`).

The final spawn sites are `_beginthreadex` on Windows, `CreateThread` on Windows
CE, `taskSpawn` on VxWorks, and `pthread_create` on the remaining targets
(`src/thread.cpp:37`, `src/thread.cpp:157`, `src/thread.cpp:234`). Their entry
routines ultimately call the stored `_tfn(_arg)` (`src/thread.cpp:25`,
`src/thread.cpp:148`, `src/thread.cpp:215`).

Thread attributes pass through `thread_ctx_t::set()` under `_opt_sync`:
priority, scheduling policy, affinity-set insertion/removal, and name prefix
(`src/ctx.cpp:548`). `start_thread()` calls `setSchedulingParameters()`, builds a
16-byte `ZMQbg` name, and calls `thread_t::start()` (`src/ctx.cpp:532`). POSIX
startup blocks signals except on OpenVMS/Android, then applies scheduling and
name (`src/thread.cpp:215`); scheduling uses `pthread_getschedparam`,
`pthread_setschedparam`, optional `nice(-20)`, and `pthread_setaffinity_np`
(`src/thread.cpp:266`, `src/thread.cpp:317`, `src/thread.cpp:332`). Naming has
platform-specific pthread variants (`src/thread.cpp:349`). Windows scheduling
setters are no-ops; naming uses the debugger exception or MinGW's pthread name
function (`src/thread.cpp:76`, `src/thread.cpp:108`). VxWorks applies priority
with `taskPrioritySet` (`src/thread.cpp:190`).

Additional creation sites/boundaries, beyond the two obvious actors:

* NORM engine initialization calls external `NormCreateInstance()`
  (`src/norm_engine.cpp:112`). Its implementation is not in this tree; a
  no-thread guarantee must not assume this call is passive. On wrapper builds,
  `norm_engine_t::plug()` directly starts `normWrapperThread` with `CreateThread`
  (`src/norm_engine.cpp:280`, `src/norm_engine.cpp:308`). The wrapper blocks on
  a NORM descriptor and forwards events into a socket (`src/norm_engine.cpp:814`).
* OpenPGM initialization is **before** context construction/option setting:
  `zmq_ctx_new -> initialize_network -> pgm_init`. The source explicitly calls
  for threading/timers to be enabled (`src/zmq.cpp:113`, `src/ip.cpp:266`). Its
  thread implementation is external. NORM/OpenPGM builds need an explicit
  support decision, not just suppression of `thread_t::start`.
* Crypto/network initialization calls `random_open`, optional `NSS_NoDB_Init`,
  `gnutls_global_init`, and `WSAStartup` (`src/ctx.cpp:73`, `src/ip.cpp:290`).
  Internal behavior of system/security providers is outside this checkout.
* `zmq_threadstart()` is an explicit application utility, has no context
  argument, and calls `thread_t::start("ZMQapp")`; it is not automatic context
  work (`src/zmq_utils.cpp:54`). Proxies execute on their caller rather than
  acquiring a worker through this utility (`src/proxy.cpp:22`).
* Windows epoll is bundled wepoll (`src/epoll.hpp:12`), whose wait executes
  `GetQueuedCompletionStatusEx` on the calling thread
  (`external/wepoll/wepoll.c:1209`, `external/wepoll/wepoll.c:1241`). Its source
  contains no OS thread-creation call.

## 2. Poller backend inventory and normalized loops

Exactly one I/O poller macro is selected by `src/poller.hpp:6`; all six
implementations are included by `src/poller.hpp:16`. GNU/Hurd has a poll fallback
(`src/poller.hpp:28`). CMake's allowed selection list is at
`CMakeLists.txt:453`; autotools' detection/selection is at `acinclude.m4:1102`.
The application-facing `ZMQ_POLL_BASED_ON_POLL/SELECT` choice is separate
(`src/poller.hpp:35`).

| Implementation | Selection macro | Wait primitive | Full loop source |
| --- | --- | --- | --- |
| `epoll_t` (Linux, Windows wepoll) | `ZMQ_IOTHREAD_POLLER_USE_EPOLL` | `epoll_wait` | `src/epoll.cpp:140` |
| `kqueue_t` (macOS/BSD) | `ZMQ_IOTHREAD_POLLER_USE_KQUEUE` | `kevent` | `src/kqueue.cpp:146` |
| `devpoll_t` (Solaris `/dev/poll`) | `ZMQ_IOTHREAD_POLLER_USE_DEVPOLL` | `ioctl(DP_POLL)` | `src/devpoll.cpp:128` |
| `pollset_t` (AIX) | `ZMQ_IOTHREAD_POLLER_USE_POLLSET` | `pollset_poll` | `src/pollset.cpp:178` |
| `poll_t` | `ZMQ_IOTHREAD_POLLER_USE_POLL` | `poll` | `src/poll.cpp:109` |
| `select_t` (including Windows) | `ZMQ_IOTHREAD_POLLER_USE_SELECT` | `select`, Windows multi-provider WSA wait | `src/select.cpp:277` |

Windows wepoll is an OS implementation beneath `epoll_t`, not a seventh copy
of libzmq's actor-dispatch loop (`src/epoll.hpp:12`). CMake enables it for Windows
epoll (`CMakeLists.txt:466`); autotools `--with-poller=wepoll` defines the epoll
macro (`acinclude.m4:1188`). `ZMQ_IOTHREAD_POLLER_USE_EPOLL_CLOEXEC` changes
creation, not the loop (`src/epoll.cpp:30`).

All signatures are `void zmq::<backend>_t::loop()`. In the descriptions below,
`T = int(execute_timers())`; **T == 0 means no timers, not a nonblocking wait**
(`src/poller_base.cpp:89`). All timer callbacks are in `execute_timers()`, not
in native event dispatch (`src/poller_base.cpp:79`).

### epoll

Normalized complete iteration: execute timers; if load is zero, break when
T == 0, otherwise continue without a wait (an existing `TODO sleep` branch);
`epoll_wait(fd, stack_buffer, max_io_events, T ? T : -1)`; on EINTR continue;
for each native record skip null entry, null sink, or retired fd, dispatch
ERR/HUP to `in_event`, OUT to `out_event`, IN to `in_event`, checking retirement
between callbacks; delete every retired entry and clear the retired vector.
The stack event buffer is outside the `while(true)` (`src/epoll.cpp:140`).
`rm_fd()` removes the OS registration, marks the fd retired and defers entry
deletion; `stop()` only checks thread identity, so loop exit is the zero-load,
zero-timer condition (`src/epoll.cpp:81`, `src/epoll.cpp:130`).

### kqueue

Normalized complete iteration: execute timers; same zero-load/zero-timer break
and timer-only continue; construct stack `kevent` buffer and `timespec(T)`;
`kevent(..., T ? &ts : NULL)`; if fork PID changed, return; EINTR continues;
for each record skip retired entries, deliver EOF as input, WRITE as output,
READ as input, checking retirement between callbacks; delete retired entries
and clear the vector (`src/kqueue.cpp:146`). Registrations use EV_ADD and
EV_DELETE, without EV_CLEAR/EV_ONESHOT; removing a handle marks it retired
after deleting enabled read/write filters (`src/kqueue.cpp:47`,
`src/kqueue.cpp:83`). `stop()` is empty (`src/kqueue.cpp:137`).

### devpoll

Normalized complete iteration: mark the previous `pending_list` registrations
accepted and clear that list; execute timers; same zero-load/zero-timer break
and timer-only continue; build `dvpoll` pointing at stack `pollfd` records;
limit the batch to `OPEN_MAX - 1` on Solaris, otherwise `max_io_events`;
set timeout to T or -1; `ioctl(DP_POLL)`; EINTR continues, other failure asserts;
for every ready fd, look up the fd table, skip invalid/unaccepted entries,
deliver ERR/HUP input, output, input, checking valid/accepted between callbacks
(`src/devpoll.cpp:128`). Registration starts unaccepted; removal uses POLLREMOVE
and clears validity, preventing a reused fd from immediately receiving stale
events (`src/devpoll.cpp:44`, `src/devpoll.cpp:74`). There is no retired heap
entry cleanup; `stop()` only checks thread identity (`src/devpoll.cpp:118`).

### pollset

Normalized complete iteration: `while (!stopping)`, execute timers, call
`pollset_poll(fd, stack_buffer, max_io_events, T ? T : -1)`; EINTR continues;
look up each result's pointer in the fd table, skip null/retired, deliver
ERR/HUP input, output, input with retirement checks; delete retired entries and
clear the vector (`src/pollset.cpp:178`). There is **no load-counter early exit**.
`stop()` sets `stopping = true`; this backend owns its own worker and joins it
in the destructor (`src/pollset.cpp:18`, `src/pollset.cpp:25`,
`src/pollset.cpp:168`). Removal clears the fd table and retains the marked heap
entry until batch cleanup (`src/pollset.cpp:64`). Unlike the other backends it
does not use `check_thread()` (`src/pollset.cpp:35`).

### poll

Normalized complete iteration: execute timers; compact retired pollset entries
and rebuild their fd-table indices; if pollset empty assert zero load, break
when T == 0, otherwise continue; `poll(vector, size, T ? T : -1)`; EINTR or
timeout continues; iterate the vector, assert no POLLNVAL, skip retired fd,
deliver ERR/HUP input, output, input, rechecking retirement after callbacks
(`src/poll.cpp:109`, `src/poll.cpp:158`). Removal marks vector and fd-table
indices retired and decreases load (`src/poll.cpp:55`). `stop()` only checks
identity (`src/poll.cpp:98`).

### select, including the full Windows shape

Normalized complete iteration: execute timers; clean retired entries; if no
families (Windows) or no entries (POSIX), assert zero load and either break at
T == 0 or continue; build `timeval(T)` (`src/select.cpp:277`). POSIX calls
`select_family_entry(_family_entry, _max_fd + 1, T > 0, tv)`
(`src/select.cpp:390`).

On Windows, sockets are grouped by provider family; AF_INET6 is coalesced into
AF_INET (`src/select.cpp:60`, `src/select.cpp:550`). For one family, call
`select_family_entry(..., 0, T > 0, tv)`. For multiple families, construct four
WSA events, associate each descriptor's enabled interests using WSAEventSelect,
call WSAWaitForMultipleEvents with T or INFINITE, continue on timeout, then
visit **every** family with zero-timeout select. `_current_family_entry_it`
tracks the family undergoing callbacks (`src/select.cpp:306`).

`select_family_entry` skips empty entries, copies the fd sets, calls select,
asserts Windows errors or returns on POSIX EINTR, calls `trigger_events`, then
cleans that family's retired entries (`src/select.cpp:395`). `trigger_events`
caches the vector size, visits input, output, exception-as-input in that order,
decrements the select result count after each callback and checks retirement
and count between callbacks; it intentionally does not retain vector references
across callbacks (`src/select.cpp:93`). POSIX marks retired entries, clears all
sets and recomputes max fd if necessary. Windows may erase a descriptor in a
different family immediately but marks it retired in the currently iterated
family (`src/select.cpp:134`, `src/select.cpp:165`). Global cleanup also removes
empty Windows families (`src/select.cpp:485`). `stop()` only checks identity;
`max_fds()` returns FD_SETSIZE (`src/select.cpp:266`).

## 3. Shared base and its invariants

`poller_base_t` owns `clock_t`, a `multimap<uint64_t, timer_info_t>` with
sink/id payloads, and an atomic load counter (`src/poller_base.hpp:114`). Adding
a timer stores `now_ms() + timeout`; cancellation searches by sink/id
(`src/poller_base.cpp:27`, `src/poller_base.cpp:34`). `execute_timers()` samples
time once, repeatedly removes the earliest due timer **before** its callback,
restarts from `begin()` because callbacks mutate timers, and returns positive
milliseconds to the next timer or zero when none remain
(`src/poller_base.cpp:54`). A due timer therefore persists in the map until
execution or explicit cancellation (`src/poller_base.cpp:69`).

Load is the registered-descriptor count, changed atomically on registration
and removal; the base destructor asserts zero load (`src/poller_base.cpp:8`,
`src/poller_base.cpp:14`, `src/poller_base.cpp:19`). Context selection uses the
least-loaded eligible I/O slot and returns NULL for an empty slot vector
(`src/ctx.cpp:651`).

`worker_poller_base_t::start()` asserts positive load and launches one worker.
In debug builds, `check_thread()` asserts either the worker has not started or
the current thread is that worker (`src/poller_base.cpp:104`,
`src/poller_base.cpp:110`). This encodes setup-before-start followed by exclusive
callback-thread mutation, not permanent ownership by the constructing thread.
The concept permits external `get_load`, setup-time registration, and one
external `start`; otherwise registration mutation is callback-owned
(`src/poller_base.hpp:67`). Timers currently have no corresponding identity
assertion in their base methods (`src/poller_base.cpp:27`).

## 4. Shutdown and every wait boundary

`zmq_ctx_shutdown -> ctx_t::shutdown` takes `_slot_sync`, sets `_terminating`,
sends stop commands to sockets, and sends stop to the reaper if there are no
sockets. It does not wait for completion (`src/zmq.cpp:147`,
`src/ctx.cpp:212`). Socket stop is a command which makes subsequent operations
return ETERM; the application remains responsible for close
(`src/socket_base.cpp:1560`).

`zmq_ctx_term -> ctx_t::terminate` first completes pending inproc connections
using temporary sockets, handles already-started termination, sends socket
stops, unlocks `_slot_sync`, and receives the reaper's `done` command with an
**infinite** timeout (`src/zmq.cpp:128`, `src/ctx.cpp:133`, `src/ctx.cpp:184`).
The full wait/completion chain is:

1. `_term_mailbox.recv(&cmd, -1)` reaches `signaler_t::wait(-1)` and then
   `poll(...,-1)` or select with a null timeout; the reaper must send `done`
   (`src/mailbox.cpp:42`, `src/signaler.cpp:203`, `src/reaper.cpp:92`,
   `src/reaper.cpp:112`). EINTR returns to the application for retry
   (`src/ctx.cpp:187`).
2. `zmq_close -> socket_base_t::close` queues `reap`. The reaper's command
   callback registers the closed socket mailbox and starts its existing
   termination protocol. Socket callbacks process acknowledgments, unregister
   themselves, tell the context to destroy the socket, and send `reaped`
   (`src/socket_base.cpp:1447`, `src/reaper.cpp:104`,
   `src/socket_base.cpp:1477`, `src/socket_base.cpp:1724`,
   `src/socket_base.cpp:1752`). Last socket destruction requests reaper stop
   (`src/ctx.cpp:503`).
3. Sessions wait logically for pipes to drain when linger is nonzero. Finite
   linger schedules a poller timer; negative linger has no deadline. Expiry
   terminates the pipe without waiting for its remaining data
   (`src/session_base.cpp:485`, `src/session_base.cpp:524`). These are command
   and timer dependencies, not blocking OS calls in `own_t`.
4. After `done`, deleting the context sends stop to every I/O slot and deletes
   the actors. Poller destruction joins the worker. `thread_t::stop()` uses
   WaitForSingleObject(INFINITE) on Windows or pthread_join on POSIX, expecting
   the worker to remove its mailbox registration and exit its loop
   (`src/ctx.cpp:90`, `src/io_thread.cpp:89`, `src/epoll.cpp:41`,
   `src/thread.cpp:66`, `src/thread.cpp:245`). VxWorks instead has an existing
   taskIdVerify spin (`src/thread.cpp:169`).
5. Optional NORM unplug posts WM_QUIT and calls
   WaitForSingleObject(wrapper_thread_handle, INFINITE); the helper must leave
   MsgWaitForMultipleObjectsEx(INFINITE) (`src/norm_engine.cpp:315`,
   `src/norm_engine.cpp:823`). NormStopInstance/NormDestroyInstance and
   pgm_shutdown are additional external-library termination boundaries
   (`src/norm_engine.cpp:273`, `src/ip.cpp:313`).
6. Context/mailbox/socket mutex acquisition can block for their current
   holders; mailbox destructors synchronize with senders
   (`src/ctx.cpp:135`, `src/mailbox.cpp:17`, `src/mailbox_safe.cpp:19`,
   `src/socket_base.cpp:1731`). These waits require releasing `_slot_sync`
   before driving callbacks that destroy sockets (`src/ctx.cpp:505`).

There is also an existing non-Windows signaler destruction helper which sleeps
and retries close on EAGAIN for up to two seconds; it is reachable while reaping
and at context destruction (`src/signaler.cpp:46`, `src/signaler.cpp:105`).
Windows signaler send retries WSAEWOULDBLOCK (`src/signaler.cpp:158`). These
must be audited explicitly for the manual path, even though mailbox signaling
and command semantics must remain intact.

## 5. Application operations waiting on progress

* Send first drains commands and calls `xsend`. On EAGAIN (including exhausted
  pipe capacity or no eligible connected pipe), DONTWAIT or SNDTIMEO == 0
  returns immediately; otherwise it waits in `process_commands(timeout,false)`
  and retries until a send succeeds or a finite timeout expires
  (`src/socket_base.cpp:1263`, `src/socket_base.cpp:1315`).
* Receive checks messages/commands, returns EAGAIN in the nonblocking case,
  otherwise waits on the socket mailbox until incoming transport progress
  activates a pipe (`src/socket_base.cpp:1351`, `src/socket_base.cpp:1394`,
  `src/socket_base.cpp:1418`). Both paths share mailbox receive through
  `process_commands` (`src/socket_base.cpp:1510`). Safe socket mailboxes wait
  on a condition variable; -1 is unbounded (`src/mailbox_safe.cpp:69`,
  `src/condition_variable.hpp:79`, `src/condition_variable.hpp:224`).
* `ZMQ_FD` is a mailbox notification descriptor, not a transport descriptor;
  `ZMQ_EVENTS` processes socket commands and queries message readiness
  (`src/socket_base.cpp:465`, `src/socket_base.cpp:476`). `zmq_poll` waits on
  these descriptors then checks ZMQ_EVENTS, and repeats without a deadline for
  negative timeouts (`src/zmq.cpp:884`, `src/zmq.cpp:961`,
  `src/zmq.cpp:1103`). The draft socket poller does the same using poll/select
  (`src/socket_poller.cpp:277`, `src/socket_poller.cpp:393`,
  `src/socket_poller.cpp:559`, `src/socket_poller.cpp:619`). None advances a
  transport poller.
* Bind/connect process commands synchronously and schedule listener/session
  work. Transport readiness, handshake, and reconnect are subsequent I/O
  callbacks. Connect is not a synchronous handshake-wait API
  (`src/socket_base.cpp:647`, `src/socket_base.cpp:796`,
  `src/socket_base.cpp:934`, `src/stream_engine_base.cpp:152`). A blocking
  send/receive or waiting for a monitor event can indirectly wait for handshake.
  Reconnect timers and callbacks are at `src/stream_connecter_base.cpp:76` and
  `src/stream_connecter_base.cpp:171`; handshake/heartbeat timers are handled
  by `src/stream_engine_base.cpp:709`, `src/stream_engine_base.cpp:735`, and
  `src/zmtp_engine.cpp:466`.
* Address resolution itself can block: TCP reconnect opens resolve the address
  again (`src/tcp_connecter.cpp:147`); resolver getaddrinfo delegates to the OS
  (`src/ip_resolver.cpp:716`). NIC discovery has a sleeping retry loop
  (`src/ip_resolver.cpp:523`). Thus a wait timeout cannot by itself be a hard
  callback-duration guarantee.
* Monitor emission invokes ordinary socket sends without DONTWAIT; an
  undrained bounded monitor pipe can stall the I/O callback
  (`src/socket_base.cpp:2015`, `src/socket_base.cpp:2044`). The monitor's zero
  linger only addresses termination, not send blocking
  (`src/socket_base.cpp:1891`).
* Termination drains nonzero linger as described in section 4; leaving a socket
  open also prevents completion (`src/ctx.cpp:175`, `src/ctx.cpp:192`,
  `src/session_base.cpp:499`).

## 6. Context option numbers, draft declaration and testing

| Context option | Value | Source |
| --- | ---: | --- |
| ZMQ_IO_THREADS | 1 | `include/zmq.h:181` |
| ZMQ_MAX_SOCKETS | 2 | `include/zmq.h:182` |
| ZMQ_SOCKET_LIMIT (get), ZMQ_THREAD_PRIORITY (set) | 3 | `include/zmq.h:183` |
| ZMQ_THREAD_SCHED_POLICY | 4 | `include/zmq.h:185` |
| ZMQ_MAX_MSGSZ | 5 | `include/zmq.h:186` |
| ZMQ_MSG_T_SIZE | 6 | `include/zmq.h:187` |
| ZMQ_THREAD_AFFINITY_CPU_ADD | 7 | `include/zmq.h:188` |
| ZMQ_THREAD_AFFINITY_CPU_REMOVE | 8 | `include/zmq.h:189` |
| ZMQ_THREAD_NAME_PREFIX | 9 | `include/zmq.h:190` |
| ZMQ_ZERO_COPY_RECV (draft) | 10 | `include/zmq.h:679` |
| ZMQ_IO_MODE (branch-only draft declaration) | 11 | `include/zmq.h:680` |
| ZMQ_IPV6 (shared socket/context constant) | 42 | `include/zmq.h:307` |
| ZMQ_BLOCKY (shared socket/context constant) | 70 | `include/zmq.h:331` |

The context's actual switch is `ctx_t::set/get`, with thread options delegated
to `thread_ctx_t::set/get` (`src/ctx.cpp:235`, `src/ctx.cpp:300`,
`src/ctx.cpp:548`, `src/ctx.cpp:612`). Number 12 is unused **as a context option**;
socket options have a separate namespace, so the existing socket value at 12
does not prevent choosing it here (the complete context switches above).

The public draft block begins at `include/zmq.h:619`; draft context declarations
are at `include/zmq.h:677`. The internal `zmq_draft.h` supplies existing draft
declarations when the public draft macro is absent (`src/zmq_draft.h:11`,
`src/zmq_draft.h:70`). The branch adds IO_MODE_THREADED/CALLER and a one-argument
step declaration, with no corresponding context switch/definition
(`include/zmq.h:682`, `include/zmq.h:695`, `src/ctx.cpp:242`,
`src/zmq.cpp:107`). These are not the requested API and must be reconciled.

ZMQ_EXPORT provides Windows dllexport/dllimport or default visibility
(`include/zmq.h:34`). CMake defines ZMQ_BUILD_DRAFT_API on draft targets
(`CMakeLists.txt:1493`); autotools defines it when drafts are enabled
(`configure.ac:1069`). Existing context tests use Unity RUN_TEST, guard extended
methods with ZMQ_BUILD_DRAFT_API and zero-copy tests with ZMQ_ZERO_COPY_RECV
(`tests/test_ctx_options.cpp:122`, `tests/test_ctx_options.cpp:138`,
`tests/test_ctx_options.cpp:272`). Registration is in `tests/CMakeLists.txt:32`
and the root `Makefile.am:656`, not a tests/Makefile.am. Draft-only test lists
are at `tests/CMakeLists.txt:159` and `Makefile.am:1069`.

## 7. Existing ZMQ_IO_THREADS = 0 behavior

Zero is accepted by `ctx_t::set(ZMQ_IO_THREADS,...)` (`src/ctx.cpp:251`). Startup
still constructs/starts the reaper, but its I/O-slot loop executes zero times
(`src/ctx.cpp:413`, `src/ctx.cpp:427`). `choose_io_thread()` returns NULL for
the resulting empty vector (`src/ctx.cpp:651`). Inproc bind and connect return
from their special pipe/endpoint paths before choosing an I/O thread
(`src/socket_base.cpp:556`, `src/socket_base.cpp:823`). UDP and other transports
require an eligible I/O slot and return EMTHREAD when none exists
(`src/socket_base.cpp:595`, `src/socket_base.cpp:645`,
`src/socket_base.cpp:933`). Thus zero is inproc-only, and **does not** currently
mean zero context-owned threads.

## Consequences for stepping

1. Keep actor construction, slot routing and mailbox registration, but replace
   worker startup with explicit ownership by the stepping caller. Reject
   configurations with unaudited external transport threads before enabling
   manual mode; changing thread attributes must not mutate the host thread.
2. Extract one reusable iteration per backend and preserve each backend's
   dispatch order, retirement rules and default exit behavior. A manual wait
   must cover all ready sources, including Windows providers, without inheriting
   the existing timer-only spin branches.
3. Timers must retain their absolute deadlines and removal-before-callback
   invariant; even a zero-timeout step must execute due timers. Replace the
   worker identity condition with an explicit, serialized manual ownership
   condition while retaining the original check in threaded mode.
4. Term must drive callbacks to `done` and drain the I/O stop commands itself,
   with `_slot_sync` released during callbacks. Its idle wait must include all
   internal readiness and timer deadlines, preserve linger and externally open
   socket semantics, and avoid signaler/DNS sleeping retry paths.
5. Document nonblocking socket operations and zero-timeout readiness queries
   for the sole stepping thread. Address monitor backpressure and synchronous
   name-resolution hazards explicitly; callback counts cannot promise a hard
   execution-time limit.
6. Add a new unused context option number and only the two requested draft
   function exports/types; remove the obsolete branch sketch. Register tests
   in both build systems and verify non-draft symbol absence rather than copying
   the existing internal draft fallback indiscriminately.
7. Manual mode must retain usable I/O slots for real transports while suppressing
   the reaper worker as well. Zero configured slots may remain inproc-only;
   stepping is orthogonal to the number of actor slots.
