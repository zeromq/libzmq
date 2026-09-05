# Manual I/O: implementation and verification

Baseline: `8270a123a76401eed724d3f34f531e091efcbd63`. The Phase 0
[survey](00-survey.md) was committed before implementation, followed by the
[design](01-design.md). This report distinguishes executed checks from source
review and unavailable checks. Measurements were made on 2026-09-04.

## Final draft public API

The following declarations are behind `ZMQ_BUILD_DRAFT_API`. Existing public
struct layouts and option numbers are unchanged. Number 11 belonged to the
unimplemented branch sketch; the withdrawn `IO_MODE_*` declarations were removed.

```c
/* Boolean context option. Default 0; set before the first socket is created.
 * Enabling an unsupported configuration fails immediately with ENOTSUP. */
#define ZMQ_MANUAL_IO_THREADS 12

typedef struct zmq_ctx_step_budget_t {
    int timeout_ms;          /* Maximum OS wait; >= 0. Not a callback deadline. */
    uint32_t max_events;     /* Ready records/mailbox continuations; 0 unlimited. */
    uint32_t max_commands;   /* Dispatched mailbox commands; 0 unlimited. */
    uint32_t max_timers;     /* Due timer callbacks; 0 unlimited. */
} zmq_ctx_step_budget_t;

#define ZMQ_CTX_STEP_MORE_WORK 1
#define ZMQ_CTX_STEP_IDLE 2
#define ZMQ_CTX_STEP_BUDGET_EXHAUSTED 4

typedef struct zmq_ctx_step_result_t {
    uint32_t events_processed;
    uint32_t commands_processed;
    uint32_t timers_processed;
    uint32_t flags;          /* Observed pending work, idle, exhausted count cap. */
    int next_timeout_ms;     /* 0 pending; -1 no timer; otherwise next timer delay. */
} zmq_ctx_step_result_t;

/* Advance all internal I/O and shutdown progress on the calling thread.
 * Return events + commands + timers, saturated at INT_MAX; -1/errno on error.
 * Negative timeout: EINVAL. Non-manual context: ENOTSUP. Overlap/reentry: EBUSY.
 * Use nonblocking socket operations if this thread supplies I/O progress. */
ZMQ_EXPORT int zmq_ctx_step (void *ctx, int timeout_ms);

/* NULL budget means zero wait and unlimited counts. NULL result discards it.
 * Counts cannot preempt a callback. One event may invoke multiple callbacks,
 * and its commands also count individually. Due timers run even at timeout 0. */
ZMQ_EXPORT int zmq_ctx_step_budget (void *ctx,
                                  const zmq_ctx_step_budget_t *budget,
                                  zmq_ctx_step_result_t *result);
```

There are no public actor, slot, mailbox, poller-handle or component-step APIs.
The two C functions are the only exported stepping symbols. An ELF dynamic
symbol audit caught CMake's default exposure of unannotated C++ methods; the
subsequent visibility commit hides the new iteration/helpers explicitly.
`nm -D --defined-only` confirms both C exports in the draft library and neither
in the non-draft library. A C99 client compiles with `-Wall -Wextra -Werror`,
links and executes against both builds. It supplies `_POSIX_C_SOURCE=200809L`
for the checkout's existing draft `sigset_t` declaration.

A debug-build audit also identified unoptimized inline accessors. Those are
explicitly hidden too. Before/after extraction and comparison of the Release
library's `.text` section confirmed that this annotation-only follow-up leaves
the benchmarked machine code byte-identical; focused integration tests were
rerun with both build systems.

`MORE_WORK` is an observation, not a promise about subsequent network arrivals.
`BUDGET_EXHAUSTED` requires observed work prevented by a configured cap; merely
reaching a count exactly is insufficient. `next_timeout_ms` is a snapshot of
all internal timers, not an external readiness notification.

## Termination and thread ownership

Manual `zmq_ctx_term` acquires the same nonblocking ownership guard as step,
initiates the existing stop protocol, then releases the context slot lock while
driving the shared native poller. It waits for the ordinary completion command,
queues the existing worker-stop commands once, and continues until those
registrations/timers have drained. Idle iterations block in the native wait
covering the whole context, shortened by the earliest timer. There is no sleep,
readiness-retry count or spin strategy. EINTR leaves resumable termination state.

Zero, finite and infinite linger retain their existing meanings. Termination
does not close a socket that an application thread still owns: that thread is
woken with ETERM and must close it. Shutdown, user-driven steps, then termination
is supported, including when an earlier step has already consumed completion.

Any host thread can step or terminate after a synchronized handoff. Calls must
be serialized, and ordinary socket ownership rules still apply. A try-lock plus
an active flag detects both competing callers and reentry through a recursive
mutex; both return EBUSY. EBUSY term does not start shutdown or tear down
Winsock. Debug poller checks require an active recorded manual owner matching
the current thread; the original threaded check remains. The caller must prevent
new API entries once successful term can free the context.

## Backends

| Backend/configuration | Implementation | Executed verification |
| --- | --- | --- |
| Linux epoll | Supported | CMake and autotools; full suite, manual integration, sanitizers |
| Windows epoll/wepoll | Supported | Native VS CMake; full suite and repeated manual integration |
| macOS/BSD kqueue | Supported in source | Source review only; no native runner |
| POSIX poll | Supported | Forced Linux CMake build; manual, TCP and poller tests |
| POSIX select | Supported | Forced Linux CMake build; manual, TCP and poller tests |
| Windows select | Supported | Native forced build; 10 consecutive manual runs; IPC disabled as required by existing build |
| Solaris devpoll | ENOTSUP at enable | Loop extracted; no Solaris compiler/runtime |
| AIX pollset | ENOTSUP at enable | Loop extracted; no AIX compiler/runtime |
| VxWorks | ENOTSUP at enable | Source gate; no runtime |
| OpenPGM/NORM builds | ENOTSUP at enable | Actual NORM-enabled Linux build: option rejection passes; other manual cases intentionally ignored |

All logical I/O slots and shutdown actors borrow one native poller in manual
mode. This supplies one wait over the entire context, so an idle slot cannot
consume a timeout while a different slot has work. Native queued readiness is
preserved across the final non-dispatching observation. Array-based backends
rotate their scan cursor; native work and FIFO mailbox continuations alternate
priority to avoid starvation with a one-event budget. Windows select retains
provider-family handling and adds a manual-only readiness preflight before its
aggregate wait.

## Tests actually run

The 13 Unity cases in `tests/test_manual_io.cpp` cover:

1. TCP delivers nothing during a bounded no-step interval, then delivers when stepped.
2. Single-threaded TCP request/reply, entirely with DONTWAIT socket calls.
3. Inproc request/reply.
4. IPC request/reply where available.
5. Unsent queues with zero/finite linger; shutdown, steps, then term.
6. Four affinity-selected I/O slots, one-event/command/timer caps and pending flags.
7. Invalid context, late/nonboolean option, unsupported/non-manual mode, negative timeout, null budget and idle result.
8. Two real reconnect paths after peer loss, next-timer reporting and overdue timers with a one-timer budget.
9. Deterministic concurrent and reentrant step/term EBUSY, then synchronized ownership handoff.
10. Term itself transmits a lingering queue of twenty 64-KiB messages to a normal TCP peer.
11. Term waits for an application thread to observe ETERM and close its socket.
12. Budgeted thread-safe CLIENT/SERVER reaping over TCP.
13. No new libzmq worker threads in manual mode; a positive control detects all five ordinary workers.

Windows select intentionally ignores the IPC case. A real NORM-enabled build
passes the misuse case and ignores the other 12 cases, demonstrating option-set
ENOTSUP without silently creating manual-mode workers.

The no-step negative control was executed on the final Windows binary with
`ZMQ_TEST_MANUAL_NO_STEP=1`, disabling only the delivery helper's step calls:
**13 cases, exactly 1 failure** (`No delivery within the bounded manual step
loop`), with the other 12 passing. With the variable absent, the suite passes.
Both Windows epoll and select also passed 10 consecutive integration runs.

### Full-suite before/after counts

These are test-executable counts, not individual Unity assertions/cases.

| Run | Registered | Passed | Skipped | Failed |
| --- | ---: | ---: | ---: | ---: |
| Windows baseline, serial CMake Release/drafts on | 102 | 102 | 0 | 0 |
| Windows after, serial CMake Release/drafts on | 103 | 103 | 0 | 0 |
| Linux baseline on native filesystem, serial CMake Release/drafts on | 140 | 124 | 16 | 0 |
| Linux final after, serial CMake Release/drafts on | 141 | 125 | 16 | 0 |
| Linux after, full autotools/drafts on | 139 | 123 | 16 | 0 |

The ordinary existing tests continue to use ordinary threaded contexts, even in
a draft-enabled build. The final Linux CMake run took 215.15 seconds and used
the original 10-second per-test timeout; `test_radio_dish` finished in 9.90
seconds. The full Windows after-run took 173.61 seconds, versus 169.59 seconds
for the serial baseline. Final test-only refinements were then verified by the
repeated Windows runs and the final Linux full run.

Both draft settings built under native Windows CMake, Linux CMake and Linux
autotools. Focused existing TCP/context/poller checks passed in non-draft builds.
The refactor, plumbing, step, termination and visibility increments were each
built and checked before their implementation commit; the test increment also
passed through both registrations. Native Unix tests ran on the WSL filesystem,
not on the Windows mount.

### Earlier failures retained for context

* The first Windows baseline used parallel tests and hit a fixed-port collision;
  serial baseline execution was 102/102.
* The first Linux baseline ran on `/mnt/d`, which does not support the IPC test
  socket paths. It had 11 failures/timeouts and is not a usable green baseline.
* The native Linux baseline's default 10-second radio/dish timeout was too short.
  An isolated run passed all 16 Unity cases; the full baseline passed after
  changing only generated CTest timeout properties to 60 seconds. No source or
  baseline benchmark binary was changed. An earlier after-run also passed with
  that timeout; the final after-run passed with the original timeout.
* A raw process-thread count failed on Windows select. Diagnostic entry-module
  inspection identified the additional thread in `mswsock.dll`; existing
  background workers entered `ntdll.dll`. The test now excludes those Windows
  provider/thread-pool entry modules and positively verifies that ordinary
  libzmq workers are still counted. Its diagnostic query is dynamically resolved,
  as specified by [Microsoft's thread-query documentation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationthread).

### Sanitizers

* **Full TSan instrumentation:** Clang, `-fsanitize=thread` on ordinary memory
  and atomic accesses, manual integration plus existing `test_reqrep_tcp`:
  2/2 executables pass, with no ThreadSanitizer warnings.
* **ASan plus strict standard UBSan:** project `ENABLE_ASAN=ON`,
  `-fsanitize=undefined -fno-sanitize-recover=undefined`, manual integration plus
  existing TCP: 2/2 pass, with no address/leak/undefined-behavior diagnostics.
* **Project broad ASan/UBSan configuration:** all 13 manual cases pass, and no
  ASan memory/leak error is reported. Its additional integer/conversion checks
  report an unsigned shift in unchanged `src/random.cpp:35` and conversions in
  unchanged `src/pipe.cpp:125` and `src/pipe.cpp:130`. An early new unsigned
  countdown underflow in the pending-work scheduler was found, fixed and rerun;
  it no longer appears. The existing TCP test also reproduces the random shift.
* **Project `ENABLE_TSAN=ON` compatibility configuration:** this checkout disables
  instrumentation of normal memory and atomics (`CMakeLists.txt:53`), obscuring
  existing pipe synchronization. The functional manual cases pass, but the run
  reports 9 warnings and fails the sanitizer exit check. The existing ordinary
  TCP test similarly reports 271 warnings. This is not reported as a clean run;
  the separately fully instrumented run above provides the useful race check.

## Default-mode performance

Baseline and after binaries use matching Release/draft-enabled CMake
options, with CURVE, TLS, libbsd and libsodium disabled. The baseline binaries
are preserved from the original checkout. Existing inproc and TCP latency and
throughput benchmark bodies are unmodified; both processes use normal contexts.
Runs pin to the same two available CPUs, warm up each executable, and alternate
before/after order. The final comparison uses fifteen paired repetitions per
case, 64-byte messages, 50,000 latency roundtrips and 1,000,000 throughput messages.

| Benchmark | Before median | After median | Median change | Paired change 95% interval |
| --- | ---: | ---: | ---: | ---: |
| Inproc latency (microseconds) | 32.852 | 32.657 | -0.59% | -1.42% to +1.53% |
| Inproc throughput (messages/second) | 8,940,545 | 8,923,870 | -0.19% | -1.39% to +2.04% |
| TCP latency (microseconds) | 57.163 | 57.394 | +0.40% | -0.79% to +1.68% |
| TCP throughput (messages/second) | 7,501,087 | 7,547,226 | +0.62% | -0.76% to +2.28% |

Lower latency and higher throughput are better. Intervals are percentile
bootstrap intervals for the geometric mean of paired after/before ratios
(20,000 resamples, seed 4903), not intervals for the displayed marginal medians.
No interval excludes zero change, so this run does not establish a regression
or a speedup. In particular, the small positive TCP latency change is not
presented as an improvement or as proof of exactly zero overhead.

The initial nine-sample run measured median changes of -1.61% inproc latency,
+1.45% inproc throughput, +1.49% TCP latency and +6.29% TCP throughput. These
overlapping noisy ranges prompted the longer final comparison; they are retained
here rather than silently replaced. The first TCP harness attempt read only the
server's output; latency is printed by the client, so that attempt produced no
TCP measurement and was corrected.

## Source/ABI audit

`git grep` finds a single readiness-dispatch body in each backend: epoll
`src/epoll.cpp:214`, kqueue `src/kqueue.cpp:223`, poll `src/poll.cpp:180`, select
`src/select.cpp:125`, devpoll `src/devpoll.cpp:176`, pollset `src/pollset.cpp:209`.
Each body retains its existing error/output/input calls; those three calls are
not three event loops. There is one timer callback site, `src/poller_base.cpp:117`.
Supported backends share a compile-time-specialized body; the threaded
specialization has no runtime manual-mode tests in descriptor dispatch.

`git diff --name-only` against the baseline is empty for `own_t` and `object_t`
sources/headers. Mailbox pipe ordering, flushing, commands and locking remain
the existing actor model. Manual channels choose a different OS retry policy,
not a different routing protocol. The public header contains neither withdrawn
per-component stepping functions nor internal handles. Existing option values
and existing exported struct definitions were not renumbered/relaid out.

## Documentation and local evidence

The [API man page](../../doc/zmq_ctx_step.adoc), context option/getter pages,
shutdown/termination pages and NEWS are updated. Asciidoctor generated the new
page in man and HTML formats. A documentation-enabled autotools build completed,
and a staged `install-man` installed both `zmq_ctx_step.3` and its
`zmq_ctx_step_budget.3` alias. The alias is included in distribution/installation
metadata without pretending it has a separate source page.

Local raw evidence is retained under the ignored `build/manual-verification/`
directory: baseline/after full-suite logs, backend and sanitizer logs, initial
and final benchmark JSONL, the negative-control output and the thread-origin
diagnostic. Verification-only harnesses are under `build/`; none changes a
product benchmark body. Linux build trees and preserved baseline binaries are
under `/var/tmp/libzmq-manual-verification` in the Ubuntu WSL environment.

Representative commands (from an appropriately configured build directory):

```sh
cmake -S <source> -B <build> -DENABLE_DRAFTS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build <build> --parallel 6
ctest --test-dir <build> --output-on-failure -j 1
# Repeat with ENABLE_DRAFTS=OFF; force POLLER=poll/select for backend checks.

<source>/configure --enable-drafts --disable-curve --without-documentation
make -j6
make check -j1
# Repeat out-of-tree with --disable-drafts.

ZMQ_TEST_MANUAL_NO_STEP=1 <build>/bin/test_manual_io # exactly one expected failure
git grep -n -E -- '->(in_event|out_event|timer_event) \(' src/*poll*.cpp src/kqueue.cpp src/select.cpp
nm -D --defined-only <build>/lib/libzmq.so
```

## Caller-visible hazards

* The sole progress thread must use DONTWAIT or zero send/receive timeouts and
  nonblocking socket-poller queries. No implicit EAGAIN conversion was added.
* Infinite linger or a socket that its application owner never closes can still
  make termination wait forever. Successful term invalidates the context.
* Handoff between host threads requires synchronization. Socket ownership does
  not transfer implicitly. Reentrant/concurrent step or term returns EBUSY.
* A next-timer value is not a wakeup handle. Even -1 does not mean a context
  with live network connections can stop being stepped.
* Callbacks, allocation and OS/security operations are not preempted by a count
  budget. This is neither hard-realtime nor allocation-free.
* Manual TCP reconnect caches connect-time resolution. DNS changes require an
  application reconnect; resolution failures surface at connect. WS reuses its
  resolved address; SOCKS caches the proxy and delegates destination DNS to it.
  Manual reconnect does not perform a resolver-driven IPv4 fallback after an
  IPv6 socket-open failure; select IPv4 on an IPv4-only host.
* Manual monitor output is nonblocking and may drop whole notifications under
  backpressure. Existing ordinary monitor behavior is unchanged.
* All sources share native descriptor limits. Additional logical I/O slots do
  not add capacity or parallelism. Zero slots still means inproc-only.
* Thread attributes are not imposed on the host thread. Libzmq-owned workers
  are suppressed; OS or third-party provider threads are not controlled. Windows
  select was observed starting a Winsock helper. Forking a live manual context
  and continuing to use it in the child is unsupported.

## Uncertainties and checks not performed

* No native macOS/BSD kqueue execution or compiler was available. Its refactor,
  pointer/filter retirement and preserved-ready-record handling were reviewed,
  not proven by a native run. This remains a maintainer/CI validation gate.
* Solaris/AIX/VxWorks and Windows CE builds were not available. Unsupported
  legacy option gates were reviewed; their full native builds were not run.
* Windows mixed-provider/VMCI hardware was unavailable. The aggregate-wait
  preflight and family fairness are source-reviewed, not hardware-tested.
* NORM's rejection was executed; OpenPGM's rejection was source-checked only.
  Security providers and other external libraries were not exhaustively audited
  for hidden threads or blocking OS behavior.
* No exhaustive FD-limit/OOM/startup-failure injection, live-fork test, signal-
  interrupted termination stress run, DNS-change test, SOCKS proxy integration,
  or monitor-backpressure stress test was performed. Those paths were reviewed.
* Tests establish bounded fairness for four slots, not a formal starvation proof
  for every workload, transport and native provider.
* Performance samples cover this Windows-hosted Linux environment and ordinary
  inproc/TCP workloads only. They cannot establish identical performance on all
  architectures, compilers, transports or under security-provider load.
* The project's broad integer/conversion and compatibility-TSan runs are not
  clean, as detailed above. No claim is made that unrelated baseline diagnostics
  have been fixed.
