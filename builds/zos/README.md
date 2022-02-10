# ZeroMQ on z/OS UNIX System Services

ZeroMQ has been successfully built on z/OS, using [z/OS UNIX System
Services](http://www-03.ibm.com/systems/z/os/zos/features/unix/),
a certified UNIX environment for the [IBM
z-series](http://www-03.ibm.com/systems/z/).  The build is possible
with the shell scripts in this directory, as described below.

Tested build combinations:

* ZeroMQ 4.0.4, using IBM XL C/C++ compiler, as XPLINK in ILP32 mode

* ZeroMQ 4.0.4, using IBM XL C/C++ compiler, as XPLINK in LP64 mode

* ZeroMQ 4.1-git, using IBM XL C/C++ compiler, as XPLINK in ILP32 mode

Other combinations are likely to work, possibly with minor changes,
but have not been tested.  Both static library and DLL modes have been
tested.

There are some minor limitations (detailed below), but all core
functionality tests run successfully.


## Quickstart: building ZeroMQ on z/OS UNIX System Services

Assuming [z/OS UNIX System
Services](http://www-03.ibm.com/systems/z/os/zos/features/unix/) is
installed, and the [z/OS XL C/C++
compiler suite](http://www-03.ibm.com/software/products/en/czos) is 
installed, ZeroMQ can be built as follows:

*   Download and extract ZeroMQ tar file

*   Ensure contents of this directory are present at `builds/zos`
    within that extracted directory (eg, `zeromq-VERSION/builds/zos/`; 
    copy these files in, if not already present, and make sure the
    shell scripts are executable)

*   (Optional) set ZCXXFLAGS for additional compile flags (see below)

*   Build `libzmq.a` static library and `libzmq.so` dynamic
    library, with:

        cd zeromq-VERSION
        builds/zos/makelibzmq

    or to skip the `libzmq.so` dynamic library (only building `libzmq.a`):

        cd zeromq-VERSION
        BUILD_DLL=false
        export BUILD_DLL
        builds/zos/makelibzmq

*   (Optional, but recommended) build and run the core tests with:

        cd zeromq-VERSION
        builds/zos/maketests
        builds/zos/runtests

*   To remove built files, to start again (eg, rebuild with different
    compile/link flags):

        cd zeromq-VERSION
        builds/zos/makeclean

There are details on specifying alternative compilation flags below.


## Quickstart: using ZeroMQ on z/OS UNIX System Services

### Static linking

Install `include/*.h` somewhere on your compiler include path.

Install `src/libzmq.a` somewhere on your library search path.

Compile and link application with:

    c++ -Wc,xplink -Wl,xplink ... -+ -o myprog myprog.cpp -lzmq

Run with:

    ./myprog


### Dynamic linking

Install `include/*.h` somewhere on your compiler include path.

Install `src/libzmq.so` somewhere on your LIBPATH.

Install `src/libzmq.x` somewhere you can reference for import linking.

Compile and link application:

    c++ -Wc,xplink -Wc,dll ... -+ -c -o myprog.o myprog.cpp
    c++ -Wl,xplink -o myprog myprog.o /PATH/TO/libzmq.x

Run with:

    LIBPATH=/DIR/OF/LIBZMQ.SO:/lib:/usr/lib:...    # if not in default path
    export LIBPATH
    ./myprog


## ZeroMQ on z/OS UNIX System Services: Application considerations

z/0S UNIX System Services does not provide a way to block the
[`SIGPIPE` signal being generated when a thread writes to a closed socket](http://pic.dhe.ibm.com/infocenter/zvm/v6r2/index.jsp?topic=%2Fcom.ibm.zos.r12.cbcpx01%2Fcbcpg1b0287.htm)
(compare with other platforms that support the `SO_NOSIGPIPE` socket
option, and/or the `MSG_NOSIGNAL` flag on `send()`; z/OS UNIX System
Services supports neither).

As a result, applications using ZeroMQ on z/OS UNIX System Services
have to expect to encounter `SIGPIPE` at various times during the use
of the library, if sockets are unexpectedly disconnected.  Normally
`SIGPIPE` will terminate the application.

A simple solution, if `SIGPIPE` is not required for normal operation
of the application (eg, it is not part of a unix pipeline, the
traditional use of `SIGPIPE`), is to set `SIGPIPE` to be ignored
with code like:

    #include <signal.h>
    ...
    signal(SIGPIPE, SIG_IGN);

near the start of the application (eg, before initialising the ZeroMQ
library).

If `SIGPIPE` is required for normal operation it is recommended that
the application install a signal handler that flags the signal was
received, and allows the application main loop to determine if it
was received for one of its own file descriptors -- and ignores it if it
none of the applications own file descriptors seems to have changed.

Linking to the `libzmq.a` static library will pull in substantially
all of the library code, which will add about 4MB to the application
size (per executable statically linked with ZeroMQ).  If this is a
significant consideration, use of the DLL version is recommended.

See also ZeroMQ test status on z/OS UNIX System Services below
for other caveats.


## Setting other compilation flags

### Optimisation

To build with optimisation:

*   set `ZCXXFLAGS` to "`-O2`" before starting build process above


### Full debugging symbols

To build with debugging symbols:

*   set `ZCXXFLAGS` to "`-g`" before starting build process above

### 64-bit mode (LP64/amode=64)

To build in 64-bit mode:

The default build is
[ILP32](http://publib.boulder.ibm.com/infocenter/zvm/v6r1/index.jsp?topic=/com.ibm.zos.r9.cbcux01/lp64cop.htm),
the default for the IBM XL C/C++ compiler.  To build in LP64 mode
(64-bit):

*    set  `ZCXXFLAGS` to "`-Wc,lp64 -Wl,lp64`" before starting build

(64-bit mode can be combined with optimisation or debug symbols.)

### Combining compilation flags

Other build flags can be used in `ZXCCFLAGS` if desired.  Beware that
they are passed through (Bourne) shell expansion, and passed to both
the compile and link stages; some experimentation of argument quoting
may be required (and arguments requiring parenthesis are particularly
complicated).


## ZeroMQ test status on z/OS UNIX System Services

As of 2014-07-22, 41 of the 43 tests in the core ZeroMQ test suite
pass. There are two tests that are expected to fail:

0.  `test_abstract_ipc`: tests Linux-specific IPC functions, and is
    expected to fail on non-Linux platforms.

0.  `test_fork`: tests ability to use ZeroMQ both before *and* after
    fork (and before exec()); this relies on the ability to use 
    pthreads both before *and* after fork.  On z/OS (and some other
    UNIX compliant platforms) functions like `pthreads_create` (used
    by ZeroMQ) cannot be used after fork and before exec; on z/OS the
    call after fork fails with `ELEMULTITHREADFORK` (errno=257) if
    ZeroMQ was also used before fork.  (On z/OS it appears possible
    to use z/OS *after* fork, *providing* it has not been used before
    fork -- the problem is the two separate initialisations of the
    threading library, before and after fork, attempting to mix
    together.)  In practice this is unlikely to affect many real-world
    programs -- most programs use threads or fork without exec, but
    not both.

0.  `test_diffserv`: tests ability to set IP_TOS ([IP Type of
    Service](http://en.wikipedia.org/wiki/Type_of_service), or
    [DiffServ](http://en.wikipedia.org/wiki/Differentiated_Services_Code_Point))
    values on sockets.  While z/OS UNIX System Services has the
    preprocessor defines required, it appears not to support the
    required functionality (call fails with "EDC8109I Protocol not
    available.")

These three "expected to fail" tests are listed as XFAIL_TESTS, and
`runtests` will still consider the test run successful when they fail
as expected.  (`builds/zos/runtests` will automatically skip these
"expected to fail" tests if running "all" tests.)

In addition `test_security_curve` does not do any meaningful testing,
as a result of the CURVE support not being compiled in; it requires
[`libsodium`](http://doc.libsodium.org/), which has not been
ported to z/OS UNIX System Services yet.

Multicast (via `libpgm`) is also not ported or compiled in.

[TIPC](http://hintjens.com/blog:70), a cluster IPC protocol,
is only supported on Linux, so it is not compiled into the z/OS
UNIX System Services port -- and the tests are automatically skipped
if running "all" tests.  (However they are not listed in XFAIL_TESTS
because without the TIPC support there is no point in even running
them, and it would be non-trivial to track them by hand.)


## ZeroMQ on z/OS UNIX System Services: Library portability notes

### *.cpp

The source code in ZeroMQ is a combination of a C++ core library
(in `*.cpp` and `*.hpp` files), and a C wrapper (also in `*.cpp`
files).  It is all compiled with the C++ compiler.  The IBM XL C/C++
compiler (at least the version used for initial porting) insists
that C++ source be in `*.C` files (note capital C).  To work around
this issue the compile flag `-+` is used (specified in the `zc++`
compiler wrapper), which tells the compiler the file should be
considered C++ despite the file extension.

### XPLINK

The library (and tests) are built in
[XPLINK](http://www.redbooks.ibm.com/abstracts/sg245991.html) mode
with the flags `-Wc,xplink -Wl,xplink` (specified in  the `zc++`
compiler wrapper).  This is [recommended by IBM for C++
code](http://publib.boulder.ibm.com/infocenter/zvm/v5r4/index.jsp?topic=/com.ibm.zos.r9.ceea200/xplrunt.htm)
due to the small functions.  (Amongst other things, using XPLINK
enables function calls with some arguments passed in registers.)

### long long

ZeroMQ makes use of `uint64_t` (which is `unsigned long long` in ILP32
mode).  To enable this the compile flag `-Wc,lang(longlong)` is passed
to enable `long long`.  This is passed from the `zc++` compiler wrapper
in order to be able to specifically quote the argument to protect the 
parentheses from shell expansion.

### BSD-style sockets, with IPv6 support

ZeroMQ uses BSD-style socket handling, with extensions to support IPv6.
BSD-style sockets were merged into SysV-derived UNIX at least a decade
ago, and are required as part of the X/Open Portability Guide at least
as of XPG 4.2.  To access this functionality two feature macros are 
defined:

    _XOPEN_SOURCE_EXTENDED=1

    _OPEN_SYS_SOCK_IPV6

The first enables the XPG 4.2 features (including functionality like
`getsockname()`), and the latter exposes IPv6 specific functionality
like `sa_family_t`.  These flags are defined in the `cxxall` script.

(The traditional BSD-sockets API, exposed with `_OE_SOCKETS` cannot
be used because it does not support functions like `getsockname()`,
nor does it support IPv6 -- and the API definitions prevent compiling
in LP64 mode due to assumptions about long being 32 bits.  Using
`_XOPEN_SOURCE_EXTENDED=1` avoids all these problems.)

### pthreads

ZeroMQ uses the pthreads library to create additional threads to handle
background communication without blocking the main application.  This
functionaity is enabled on z/OS UNIX System Services by defining:

    _OPEN_THREADS=3

which is done in the `cxxall` script.  (The "3" value exposes later
pthreads functionality like `pthread_atfork`, although ZeroMQ does not
currently use all these features.)

If compiling on a *recent* version of z/OS UNIX System Services it
may be worth compiling with:

    _UNIX03_THREADS=1

which enables a later version of the threading support, potentially
including `pthread_getschedparam` and pthread_setschedparam`; at
present in the z/OS UNIX System Services port these functions are
hidden and never called.  (See [IBM z/OS pthread.h
documentation](http://pic.dhe.ibm.com/infocenter/zos/v1r11/index.jsp?topic=/com.ibm.zos.r11.bpxbd00/pthrdh.htm)
for details on the differences.)


## `platform.hpp` on z/OS UNIX System Services

The build (described above) on z/OS UNIX System Services uses a static
pre-built `platform.hpp` file.  (By default `src/platform.hpp` is 
dynamically generated as a result of running the `./configure` script.)
The master version of this is in `builds/zos/platform.hpp`.

Beware that this file contains the version number for libzmq (usually
included during the configure phase).  If taking the `platform.hpp` from
an older version to use on a newer libzmq be sure to update the version
information near the top of the file.

The pre-built file is used because z/OS does not have the GNU auto tools
(`automake`, `autoconf`, `libtool`, etc) installed, and particularly the
libtool replacement does not work properly with the IBM XL C/C++
compiler.

The `./configure` script (only supplied in the tarballs); built with
`automake` and `autoconf` on another platform), with one small edit,
was used to generate the z/OS `platform.hpp` and then two small changes
(described below) were made by hand to the generated `platform.hpp`.

To be able to run the ./configure script to completion (in tcsh 
syntax):

*   Edit `./configure` and add:

        openedition)
              ;;

    immediately before the line:

        as_fn_error $? "unsupported system: ${host_os}." "$LINENO" 5

    (somewhere around 17637).  This avoids the configure script giving
    up early because `openedition` is not recognised.

*   set `CXX` to point that the full  path to the `builds/zos/zc++` wrapper, eg

        setenv CXX "/u/0mq/zeromq-4.0.4/builds/zos/zc++"

*   set `CPPFLAGS` to for the feature macros required, eg:

        setenv CPPFLAGS "-D_XOPEN_SOURCE_EXTENDED=1 -D_OPEN_THREADS=3 -D_OPEN_SYS_SOCK_IPV6 -DZMQ_HAVE_ZOS"

*   set `CXXFLAGS` to enable XPLINK:

        setenv CXXFLAGS "-Wc,xplink -Wl,xplink -+"

*   run configure script with `--disable-eventfd` (`sys/eventfd.h` does
    not exist, but the test for its existence has a false positive on
    z/OS UNIX System Services, apparently due to the way the `c++`
    compiler wrapper passes errors back from the IBM XL C/C++ compiler),
    and with `--with-poller=poll` because `poll` is the most advanced
    of the file descriptor status tests available on z/OS.  That is:

        ./configure --disable-eventfd --with-poller=poll

All going well several Makefiles, and `src/platform.hpp` should be
produced.  Two additional changes are required to `src/platform.hpp`
which can be appended to the end:

    /* ---- Special case for z/OS Unix Services: openedition ---- */
    #include <pthread.h>
    #ifndef   NI_MAXHOST
    #define   NI_MAXHOST 1025
    #endif

(many includes require pthreads-related methods or data structures to
be defined, but not all of them include `pthread.h`, and the value
`NI_MAXHOST` is not defined on z/OS UNIX System Services -- the 1025
value is the conventional value on other platforms).

Having done this the Makefiles can be used to compile individual files
if desired, eg:

    cd src
    make zmq.o

but note:

*   IBM Make will warn of duplicate prerequisites on *every* run of
    `make`, and both the generated `src/Makefile` and `tests/Makefile`
    have several duplicates.  (For `src/Makefile` edit
    `libzmq_la_SOURCES` to remove the duplicates.)

*   IBM Make does not understand the `@` prefix (eg, `@echo`) as a way
    to avoid echoing the command, resulting in an error and the command
    being echoed anyway.

*   Many of the make targets result in GNU auto tools (`aclocal`, etc)
    being invoked, which are likely to fail, and most of the
    library-related targets will invoke `libtool` which will cause
    compile failures (due to differences in expected arguments).

However running `./configure` to regenerate `src/platform.hpp` may 
be useful for later versions of ZeroMQ which add more feature tests.


## Transferring from GitHub to z/OS UNIX System Services

The process of transferring files from GitHub to z/OS UNIX System
Services is somewhat convoluted because:

*   There is not a port of git for z/OS UNIX System Services; and

*   z/OS uses the EBCDIC (IBM-1047) character set rather than the
    ASCII/ISO-8859-1 character set used by the ZeroMQ source code
    on GitHub

A workable transfer process is:

*   On an ASCII/ISO-8859-1/UTF-8 system with `git` (eg, a Linux system):

        git clone https://github.com/zeromq/libzmq.git
        git archive --prefix=libzmq-git/ -o /var/tmp/libzmq-git.tar master

*   On a ASCII/ISO-8859-1/UTF-8 system with `tar`, and `pax`, and
    optionally the GNU auto tools (eg, the same Linux system):

        mkdir /var/tmp/zos
        cd /var/tmp/zos
        tar -xpf /var/tmp/libzmq-git.tar
        cd libzmq-git
        ./autogen.sh             # Optional: to be able to run ./configure
        cd ..
        pax -wf /var/tmp/libzmq-git.pax libzmq-git
        compress libzmq-git.pax  # If available, reduce transfer size

*   Transfer the resulting file (`libzmq-git.pax` or `libzmq-git.pax.Z`)
    to the z/OS UNIX System Services system.  If using FTP be sure to
    transfer the file in `bin` (binary/Image) mode to avoid corruption.

*   On the z/OS UNIX System Services system, unpack the `pax` file and
    convert all the files to EBCDIC with:

        pax -o from=iso8859-1 -pp -rvf  libzmq-git-2014-07-23.pax

    or if the file was compressed:

        pax -o from=iso8859-1 -pp -rvzf libzmq-git-2014-07-23.pax.Z

The result should be a `libzmq-git` directory with the source in
EBCDIC format, on the z/OS UNIX System Services system ready to start
building.

See also the [`pax` man
page](http://pic.dhe.ibm.com/infocenter/zos/v1r13/index.jsp?topic=%2Fcom.ibm.zos.r13.bpxa500%2Fr4paxsh.htm),
some [`pax` conversion
examples](http://pic.dhe.ibm.com/infocenter/zos/v1r13/index.jsp?topic=%2Fcom.ibm.zos.r13.bpxa400%2Fbpxza4c0291.htm),
and [IBM's advice on ASCII to EBCDIC conversion
options](http://www-03.ibm.com/systems/z/os/zos/features/unix/bpxa1p03.html)
