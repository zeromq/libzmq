#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.61)
#
# The 0MQ version number is extracted from include/zmq.h using
# the version.sh script. Hence, it should be updated there.
# The version in git should reflect the *next* version planned.
#
AC_INIT([zeromq],[m4_esyscmd([./version.sh])],[zeromq-dev@lists.zeromq.org])

AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR(config)
AC_CONFIG_HEADERS([src/platform.hpp])
AM_INIT_AUTOMAKE(foreign subdir-objects tar-ustar dist-zip)
# Allow "configure --disable-maintainer-mode" to disable timestamp checking 
AM_MAINTAINER_MODE([enable])

m4_pattern_allow([AC_PROG_CC_C99])
m4_include([m4/ax_check_compile_flag.m4])
m4_include([m4/ax_cxx_compile_stdcxx_11.m4])
m4_include([m4/ax_code_coverage.m4])
m4_include([m4/ax_valgrind_check.m4])
m4_include([m4/ax_check_vscript.m4])
m4_include([m4/ax_func_posix_memalign.m4])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# This lets us use PACKAGE_VERSION in Makefiles
AC_SUBST(PACKAGE_VERSION)

# Libtool -version-info (ABI version)
#
# Don't change this unless you know exactly what you're doing and have read and
# understand:
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
#
# Changes:
#
# ZeroMQ versions prior to 2.1.0 use 0:0:0 (undefined)
# ZeroMQ versions 2.1.x: 1:0:0 (ABI version 1)
# ZeroMQ version 3.0: 2:0:0 (ABI version 2)
# ZeroMQ version 3.1: 3:0:0 (ABI version 3)
# ZeroMQ version 4.0: 4:0:0 (ABI version 4)
# ZeroMQ version 4.1: 5:0:0 (ABI version 5)
# ZeroMQ version 4.2.0: 6:0:1 (ABI version 5)
# ZeroMQ version 4.2.1: 6:1:1 (ABI version 5)
# ZeroMQ version 4.2.2: 6:2:1 (ABI version 5)
# ZeroMQ version 4.2.3: 6:3:1 (ABI version 5)
# ZeroMQ version 4.2.4: 6:4:1 (ABI version 5)
# ZeroMQ version 4.2.5: 6:5:1 (ABI version 5)
# ZeroMQ version 4.3.0: 7:0:2 (ABI version 5)
# ZeroMQ version 4.3.1: 7:1:2 (ABI version 5)
# ZeroMQ version 4.3.2: 7:2:2 (ABI version 5)
# ZeroMQ version 4.3.3: 7:3:2 (ABI version 5)
#
# libzmq -version-info current:revision:age
LTVER="7:3:2"
AC_SUBST(LTVER)

# Take a copy of original flags
ZMQ_ORIG_CFLAGS="${CFLAGS:-none}"
ZMQ_ORIG_CPPFLAGS="${CPPFLAGS:-none}"
ZMQ_ORIG_CXXFLAGS="${CXXFLAGS:-none}"

# Checks for programs.
AC_PROG_CC
AX_CHECK_COMPILE_FLAG([-std=gnu11], [CFLAGS+=" -std=gnu11"], [AC_PROG_CC_C99])
AC_PROG_CXX
AX_CODE_COVERAGE
AM_PROG_CC_C_O
AC_PROG_SED
AC_PROG_AWK
PKG_PROG_PKG_CONFIG
m4_pattern_forbid([^PKG_[A-Z_]+$], [missing some pkg-config macros (pkg-config package)])

# Libtool configuration for different targets. See acinclude.m4
AC_ARG_VAR([XMLTO], [path to xmlto command])
AC_PATH_PROG([XMLTO], [xmlto])
AC_ARG_VAR([ASCIIDOC], [path to asciidoc command])
AC_PATH_PROG([ASCIIDOC], [asciidoc])
LIBZMQ_CONFIG_LIBTOOL
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL
AX_VALGRIND_CHECK
AX_CHECK_VSCRIPT
AX_FUNC_POSIX_MEMALIGN

AC_ARG_ENABLE([force-CXX98-compat],
    [AS_HELP_STRING([--enable-force-CXX98-compat], [force C++98 build [default=disabled]])])
if test "x$enable_force_CXX98_compat" = "xyes"; then
    AC_LANG_PUSH([C++])
    AX_CHECK_COMPILE_FLAG([-std=gnu++98], [CXXFLAGS+=" -std=gnu++98"], [])
    AX_CHECK_COMPILE_FLAG([-Wc++98-compat -Wc++98-compat-pedantic], [CXXFLAGS+=" -Wc++98-compat"], [])
    AC_LANG_POP([C++])
else
    AX_CXX_COMPILE_STDCXX_11([ext], [optional])
fi

# Check whether to build a with debug symbols
LIBZMQ_CHECK_ENABLE_DEBUG

# Check whether to enable code coverage
LIBZMQ_WITH_GCOV

AC_MSG_CHECKING([if TIPC is available and supports nonblocking connect])

AC_RUN_IFELSE(
    [AC_LANG_PROGRAM([[
            #include <stdlib.h>
            #include <string.h>
            #include <fcntl.h>
            #include <errno.h>
            #include <sys/socket.h>
            #include <linux/tipc.h>
        ]],[[
            struct sockaddr_tipc topsrv;
            int sd = socket(AF_TIPC, SOCK_SEQPACKET, 0);
            memset(&topsrv, 0, sizeof(topsrv));
            topsrv.family = AF_TIPC;
            topsrv.addrtype = TIPC_ADDR_NAME;
            topsrv.addr.name.domain = tipc_addr (10, 10, 10);
            topsrv.addr.name.name.type = TIPC_TOP_SRV;
            topsrv.addr.name.name.instance = TIPC_TOP_SRV;
            fcntl(sd, F_SETFL, O_NONBLOCK);
        ]])
    ],
    [libzmq_tipc_support=yes],
    [libzmq_tipc_support=no],
    [libzmq_tipc_support=no])

AC_MSG_RESULT([$libzmq_tipc_support])

AC_ARG_ENABLE([pedantic],
    [AS_HELP_STRING([--disable-pedantic], [disable pedantic compiler checks [default=enabled]])],
    [libzmq_pedantic=$enableval], [libzmq_pedantic=yes])

AC_ARG_WITH([militant],
    [AS_HELP_STRING([--with-militant],
        [enable militant API assertions])],
    [zmq_militant="yes"],
    [])

if test "x$zmq_militant" = "xyes"; then
    AC_DEFINE(ZMQ_ACT_MILITANT, 1, [Enable militant API assertions])
fi

# Disable IPC on unsupported platforms.
case "${host_os}" in
    *vxworks*|*openvms*|*mingw*)
        ;;
    *)
        AC_DEFINE(ZMQ_HAVE_IPC, 1, [Have AF_UNIX sockets for ipc transport])
        ;;
esac

# Data race/deadlock detection
# NOTE: Running libzmq under TSAN doesn't make much sense -- synchronization in libzmq is to some extent
# handled by the code "knowing" what threads are allowed to do, rather than by enforcing those
# restrictions, so TSAN generates a lot of (presumably) false positives from libzmq.
# The settings below are intended to enable libzmq to be built with minimal support for TSAN
# such that it can be used along with other code that is also built with TSAN.
AC_MSG_CHECKING([whether to enable TSan])
AC_ARG_ENABLE(thread-sanitizer, [AS_HELP_STRING([--enable-thread-sanitizer=yes/no],
                  [Build with clang Thread Sanitizer instrumentation])],
                  [ZMQ_TSAN="$enableval"])

if test "x${ZMQ_TSAN}" = "xyes"; then
    TSAN_FLAGS="-fno-omit-frame-pointer -fsanitize=thread"
    TSAN_CCFLAGS="${TSAN_CCFLAGS} -mllvm -tsan-instrument-memory-accesses=0"
    TSAN_CCFLAGS="${TSAN_CCFLAGS} -mllvm -tsan-instrument-atomics=0"
    TSAN_CCFLAGS="${TSAN_CCFLAGS} -mllvm -tsan-instrument-func-entry-exit=1"
    CFLAGS="${CFLAGS} ${TSAN_FLAGS} ${TSAN_CCFLAGS}"
    CXXFLAGS="${CXXFLAGS} ${TSAN_FLAGS} ${TSAN_CCFLAGS}"
    LDFLAGS="${LDFLAGS} ${TSAN_FLAGS} -pie"

    AM_CONDITIONAL(ENABLE_TSAN, true)
    AC_MSG_RESULT([yes])
else
    AM_CONDITIONAL(ENABLE_TSAN, false)
    AC_MSG_RESULT([no])
fi

# Memory mis-use detection
AC_MSG_CHECKING([whether to enable ASan])
AC_ARG_ENABLE(address-sanitizer, [AS_HELP_STRING([--enable-address-sanitizer=yes/no],
                  [Build with GCC Address Sanitizer instrumentation])],
                  [ZMQ_ASAN="$enableval"])

if test "x${ZMQ_ASAN}" = "xyes"; then
    CFLAGS="${CFLAGS} -fsanitize=address -fsanitize=undefined -fsanitize=leak -fno-sanitize-recover=all"
    CXXFLAGS="${CXXFLAGS} -fsanitize=address -fsanitize=undefined -fsanitize=leak -fno-sanitize-recover=all"

    AM_CONDITIONAL(ENABLE_ASAN, true)
    AC_MSG_RESULT([yes])
else
    AM_CONDITIONAL(ENABLE_ASAN, false)
    AC_MSG_RESULT([no])
fi

# By default compiling with -Werror except on OSX and Solaris when building
# with libsodium.
AC_ARG_ENABLE([Werror],
    [AS_HELP_STRING([--disable-Werror], [disable Werror compiler flag [default=enabled]])],
    [libzmq_werror=$enableval], [libzmq_werror=yes])

# By default use DSO visibility
libzmq_dso_visibility="yes"

# Platform specific checks
libzmq_on_mingw="no"
libzmq_on_cygwin="no"
libzmq_on_android="no"
libzmq_on_linux="no"
libzmq_on_gnu="no"

# Set some default features required by ZeroMQ code
CPPFLAGS="-D_REENTRANT -D_THREAD_SAFE $CPPFLAGS"
CXXFLAGS="-Wno-long-long $CXXFLAGS"

# Will be used to add flags to pkg-config useful when apps want to statically link
PKGCFG_LIBS_PRIVATE=""
PKGCFG_NAMES_PRIVATE=""

# For host type checks
AC_CANONICAL_HOST

# OS-specific tests
case "${host_os}" in
    *linux*)
        # Define on Linux to enable all library features. Define if using a gnu compiler
        if test "x$GXX" = "xyes"; then
            CPPFLAGS="-D_GNU_SOURCE $CPPFLAGS"
        fi
        AC_DEFINE(ZMQ_HAVE_LINUX, 1, [Have Linux OS])
        libzmq_on_linux="yes"

        if test "x$libzmq_tipc_support" = "xyes"; then
            AC_DEFINE(ZMQ_HAVE_TIPC, 1, [Have TIPC support])
        fi
        case "${host_os}" in
            *android*)
                AC_DEFINE(ZMQ_HAVE_ANDROID, 1, [Have Android OS])
                libzmq_on_android="yes"
            ;;
        esac
        ;;
    *solaris*)
        # Define on Solaris to enable all library features
        CPPFLAGS="-D_PTHREADS $CPPFLAGS"
        CXXFLAGS="-Wno-sign-compare $CXXFLAGS"
        AC_DEFINE(ZMQ_HAVE_SOLARIS, 1, [Have Solaris OS])
        AC_CHECK_LIB(socket, socket)
        AC_CHECK_LIB(nsl, gethostbyname)
        AC_MSG_CHECKING([whether atomic operations can be used])
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
            [[#include <atomic.h>]],
            [[uint32_t value;
              atomic_cas_32 (&value, 0, 0);
              return 0;]])],
            [solaris_has_atomic=yes],
            [solaris_has_atomic=no])
        AC_MSG_RESULT([$solaris_has_atomic])
        # Solaris 8 does not have atomic operations exported to user space.
        if test "x$solaris_has_atomic" = "xno"; then
            AC_DEFINE(ZMQ_FORCE_MUTEXES, 1, [Force to use mutexes])
        fi
        ;;
    *freebsd*)
        # Define on FreeBSD to enable all library features
        CPPFLAGS="-D__BSD_VISIBLE $CPPFLAGS"
        AC_DEFINE(ZMQ_HAVE_FREEBSD, 1, [Have FreeBSD OS])
        ;;
    *dragonfly*)
        CPPFLAGS="-D__BSD_VISIBLE $CPPFLAGS"
        AC_DEFINE(ZMQ_HAVE_FREEBSD, 1, [Have DragonFly OS])
        AC_DEFINE(ZMQ_HAVE_DRAGONFLY, 1, [Have DragonFly OS])
        ;;
    *darwin*)
        # Define on Darwin to enable all library features
        CPPFLAGS="-D_DARWIN_C_SOURCE $CPPFLAGS"
        libzmq_pedantic="no"
        AC_DEFINE(ZMQ_HAVE_OSX, 1, [Have DarwinOSX OS])
        ;;
    *haiku*)
        AC_DEFINE(ZMQ_HAVE_HAIKU, 1, [Have Haiku OS])
        AC_CHECK_LIB(network, socket)
        ;;
    *netbsd*)
        # Define on NetBSD to enable all library features
        CPPFLAGS="-D_NETBSD_SOURCE $CPPFLAGS"
        AC_DEFINE(ZMQ_HAVE_NETBSD, 1, [Have NetBSD OS])
        # NetBSD 5.0 and newer provides atomic operations but we can
        # only use these on systems where PR #42842 has been fixed so
        # we must try and link a test program using C++.
        libzmq_netbsd_has_atomic=no
        AC_MSG_CHECKING([whether atomic operations can be used])
        AC_LANG_PUSH([C++])
        AC_LINK_IFELSE([AC_LANG_PROGRAM(
            [[#include <atomic.h>]],
            [[uint32_t value;
              atomic_cas_32 (&value, 0, 0);
              return 0;]])],
            [libzmq_netbsd_has_atomic=yes],
            [libzmq_netbsd_has_atomic=no])
        AC_LANG_POP([C++])
        AC_MSG_RESULT([$libzmq_netbsd_has_atomic])
        if test "x$libzmq_netbsd_has_atomic" = "xno"; then
            AC_DEFINE(ZMQ_FORCE_MUTEXES, 1, [Force to use mutexes])
        fi
        ;;
    *openbsd*|*bitrig*)
        # Define on OpenBSD to enable all library features
        CPPFLAGS="-D_BSD_SOURCE $CPPFLAGS"
        AC_DEFINE(ZMQ_HAVE_OPENBSD, 1, [Have OpenBSD OS])
        ;;
    *nto-qnx*)
        libzmq_pedantic="no"
        AC_DEFINE(ZMQ_HAVE_QNXNTO, 1, [Have QNX Neutrino OS])
        AC_CHECK_LIB(socket, socket)
        ;;
    *aix*|*os400*)
        AC_DEFINE(ZMQ_HAVE_AIX, 1, [Have AIX OS])
        ;;
    *hpux*)
        # Define on HP-UX to enable all library features
        CPPFLAGS="-D_POSIX_C_SOURCE=200112L $CPPFLAGS"
        AC_DEFINE(ZMQ_HAVE_HPUX, 1, [Have HPUX OS])
        LIBZMQ_CHECK_LANG_FLAG_PREPEND([-Ae])
        AC_CHECK_FUNCS(gethrtime)
        ;;
    *mingw*|*msys*)
        AC_DEFINE(ZMQ_HAVE_WINDOWS, 1, [Have Windows OS])
        AC_DEFINE(ZMQ_HAVE_MINGW, 1, [Have MinGW])
        AC_CHECK_HEADERS(windows.h)
        AC_CHECK_LIB(ws2_32, main, ,
            [AC_MSG_ERROR([cannot link with ws2_32.dll.])])
        AC_CHECK_LIB(rpcrt4, main, ,
            [AC_MSG_ERROR([cannot link with rpcrt4.dll.])])
        AC_CHECK_LIB(iphlpapi, main, ,
            [AC_MSG_ERROR([cannot link with iphlpapi.dll.])])
        libzmq_on_mingw="yes"
        libzmq_dso_visibility="no"

        if test "x$enable_static" = "xyes"; then
            CPPFLAGS="-DZMQ_STATIC $CPPFLAGS"
            PKGCFG_LIBS_PRIVATE="$PKGCFG_LIBS_PRIVATE -liphlpapi"
        fi
	# Set FD_SETSIZE to 16384
	CPPFLAGS=" -DFD_SETSIZE=16384 $CPPFLAGS"
        ;;
    *cygwin*)
        # Define on Cygwin to enable all library features
        CPPFLAGS="-D_GNU_SOURCE $CPPFLAGS"
        AC_DEFINE(ZMQ_HAVE_CYGWIN, 1, [Have Cygwin])
        libzmq_on_cygwin="yes"
        libzmq_dso_visibility="no"
        if test "x$enable_static" = "xyes"; then
            AC_MSG_ERROR([Building static libraries is not supported under Cygwin])
        fi
        ;;
    gnu*)
        # Define on GNU/Hurd to enable all library features. Define if using a gnu compiler
        if test "x$GXX" = "xyes"; then
            CPPFLAGS="-D_GNU_SOURCE $CPPFLAGS"
        fi
        AC_DEFINE(ZMQ_HAVE_GNU, 1, [Have GNU/Hurd OS])
        libzmq_on_gnu="yes"
	AC_CHECK_LIB(rt, sem_init)
        ;;
    *)
        AC_MSG_ERROR([unsupported system: ${host_os}.])
        ;;
esac

# Sun Studio does not like anonymous structures in unions and does not have weak attribute
if test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler" = "xyes"; then
    CXXFLAGS="${CXXFLAGS} -features=extensions"
    CFLAGS="${CFLAGS} -features=extensions"
    CPPFLAGS="${CPPFLAGS} -DUNITY_WEAK_PRAGMA"
fi

# Checks for libraries
AC_CHECK_LIB([pthread], [pthread_create])
if test "x$ac_cv_lib_pthread_pthread_create" = "xyes"; then
    PKGCFG_LIBS_PRIVATE="$PKGCFG_LIBS_PRIVATE -lpthread"
fi
AC_CHECK_LIB([rt], [clock_gettime])
if test "x$ac_cv_lib_rt_clock_gettime" = "xyes"; then
    PKGCFG_LIBS_PRIVATE="$PKGCFG_LIBS_PRIVATE -lrt"
fi

#
# Check if the compiler supports -fvisibility=hidden flag. MinGW uses __declspec
#
if test "x$libzmq_dso_visibility" = "xyes"; then
    AC_LANG_PUSH([C++])
    LIBZMQ_CHECK_LANG_VISIBILITY([LIBZMQ_EXTRA_CXXFLAGS="$libzmq_cv_[]_AC_LANG_ABBREV[]_visibility_flag ${LIBZMQ_EXTRA_CXXFLAGS}"])
    AC_LANG_POP([C++])
fi

# CPU-specific optimizations
case "${host_cpu}" in
    *sparc64*)
        AC_LANG_PUSH([C++])
        LIBZMQ_CHECK_LANG_FLAG_PREPEND([-mcpu=v9])
        AC_LANG_POP([C++])
    ;;
    *)
    ;;
esac

# Check whether to build docs / install man pages
LIBZMQ_CHECK_DOC_BUILD

# Check polling system, set appropriate macro in src/platform.hpp
LIBZMQ_CHECK_POLLER

# Check cacheline size, set appropriate macro in src/platform.hpp
LIBZMQ_CHECK_CACHELINE

# Check condition variable implementation, set appropriate macro in src/platform.hpp
LIBZMQ_CHECK_CV_IMPL

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(\
    errno.h \
    time.h \
    unistd.h \
    limits.h \
    stddef.h \
    stdlib.h \
    string.h \
    arpa/inet.h \
    netinet/tcp.h \
    netinet/in.h \
    sys/socket.h \
    sys/time.h)

# Check if we have ifaddrs.h header file.
AC_CHECK_HEADERS(ifaddrs.h, [AC_DEFINE(ZMQ_HAVE_IFADDRS, 1, [Have ifaddrs.h header.])])

# Check if we have sys/uio.h header file.
AC_CHECK_HEADERS(sys/uio.h, [AC_DEFINE(ZMQ_HAVE_UIO, 1, [Have uio.h header.])])

# Force not to use eventfd
AC_ARG_ENABLE([eventfd],
    [AS_HELP_STRING([--disable-eventfd], [disable eventfd [default=enabled]])],
    [zmq_enable_eventfd=$enableval],
    [zmq_enable_eventfd=yes])

if test "x$zmq_enable_eventfd" = "xyes"; then
    # Check if we have eventfd.h header file.
    AC_CHECK_HEADERS(sys/eventfd.h, [
        AC_DEFINE(ZMQ_HAVE_EVENTFD, 1, [Have eventfd extension])
        LIBZMQ_CHECK_EVENTFD_CLOEXEC([
            AC_DEFINE([ZMQ_HAVE_EVENTFD_CLOEXEC],
               [1],
               [Whether EFD_CLOEXEC is defined and functioning.])
            ])
    ])
fi

# Conditionally build performance measurement tools
AC_ARG_ENABLE([perf],
    [AS_HELP_STRING([--disable-perf], [don't build performance measurement tools [default=build]])],
    [zmq_enable_perf=$enableval],
    [zmq_enable_perf=yes])

AM_CONDITIONAL(ENABLE_PERF, test "x$zmq_enable_perf" = "xyes")

# Conditionally build curve key generation tool
AC_ARG_ENABLE([curve-keygen],
    [AS_HELP_STRING([--disable-curve-keygen], [don't build curve-keygen tool [default=build]])],
    [zmq_enable_curve_keygen=$enableval],
    [zmq_enable_curve_keygen=yes])

# Use c++ in subsequent tests
AC_LANG_PUSH(C++)

AC_CHECK_DECLS([SO_PEERCRED],
    [AC_DEFINE(ZMQ_HAVE_SO_PEERCRED, 1, [Have SO_PEERCRED socket option])],
    [],
    [#include <sys/socket.h>])

AC_CHECK_DECLS([LOCAL_PEERCRED],
    [AC_DEFINE(ZMQ_HAVE_LOCAL_PEERCRED, 1, [Have LOCAL_PEERCRED socket option])],
    [],
    [#include <sys/socket.h>])

AM_CONDITIONAL(HAVE_IPC_PEERCRED, test "x$ac_cv_have_decl_SO_PEERCRED" = "xyes" || test "x$ac_cv_have_decl_LOCAL_PEERCRED" = "xyes")

AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE

# Checks for typedefs, structures, and compiler characteristics.
if test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler" = "xyes"; then
    dnl 279: controlling expression is constant
    dnl Fixes build with ICC 12.x
    LIBZMQ_CHECK_WITH_FLAG([-wd279], [AC_TYPE_SIZE_T])
    LIBZMQ_CHECK_WITH_FLAG([-wd279], [AC_TYPE_SSIZE_T])
else
    AC_TYPE_SIZE_T
    AC_TYPE_SSIZE_T
fi

AC_HEADER_TIME
AC_TYPE_UINT32_T
AC_C_VOLATILE

# build using libgssapi_krb5
AC_ARG_WITH([libgssapi_krb5], [AS_HELP_STRING([--with-libgssapi_krb5],
    [require libzmq build with libgssapi_krb5 [default=no]])],
    [require_libgssapi_krb5_ext=$withval],
    [require_libgssapi_krb5_ext=no])

# conditionally require libgssapi_krb5
if test "x$require_libgssapi_krb5_ext" != "xno"; then
    PKG_CHECK_MODULES([gssapi_krb5], [krb5-gssapi], [
        have_gssapi_library="yes"
        PKGCFG_NAMES_PRIVATE="$PKGCFG_NAMES_PRIVATE krb5-gssapi"
    ], [
        AC_CHECK_HEADERS(gssapi/gssapi_generic.h)
        AC_SEARCH_LIBS([gss_init_sec_context], [gssapi_krb5 gssapi],
            have_gssapi_library="yes",
            AC_MSG_ERROR(libgssapi_krb5 is needed for GSSAPI security))
        PKGCFG_LIBS_PRIVATE="$PKGCFG_LIBS_PRIVATE -lgssapi_krb5"
    ])
fi
if test "x$have_gssapi_library" = "xyes"; then
    AC_DEFINE(HAVE_LIBGSSAPI_KRB5, [1], [Enabled GSSAPI security])
fi
AM_CONDITIONAL(BUILD_GSSAPI, test "x$have_gssapi_library" = "xyes")

# Select curve encryption library, defaults to tweetnacl
# To use libsodium instead, use --with-libsodium (must be installed)
# To disable curve, use --disable-curve

AC_ARG_WITH([libsodium],
    [AS_HELP_STRING([--with-libsodium], [use libsodium instead of built-in tweetnacl [default=no]])])

AS_IF([test "x$with_libsodium" = "xyes"], [
    PKG_CHECK_MODULES([sodium], [libsodium], [libsodium_found=yes], [
        AC_MSG_ERROR(libsodium is not installed. Install it, then run configure again)
    ])
])

AC_ARG_ENABLE([curve],
    [AS_HELP_STRING([--disable-curve], [disable CURVE security [default=no]])])

if test "x$enable_curve" = "xno"; then
    curve_library=""
    AC_MSG_NOTICE([CURVE security is disabled])

elif test "x$with_libsodium" = "xyes"; then
    AC_MSG_NOTICE([Using libsodium for CURVE security])
    AC_DEFINE(ZMQ_HAVE_CURVE, [1], [Using curve encryption])
    AC_DEFINE(ZMQ_USE_LIBSODIUM, [1], [Using libsodium for curve encryption])
    curve_library="libsodium"
    enable_curve="yes"

    case "${host_os}" in
        *solaris*)
            dnl On Solaris, libsodium depends on libssp
            LDFLAGS="-lssp $LDFLAGS"
            libzmq_pedantic="no"
            libzmq_werror="no"
        ;;
        *darwin*)
            dnl On Darwin, building with libsodium causes
            dnl macro redefinition warnings
            libzmq_werror="no"
        ;;
    esac

    PKGCFG_NAMES_PRIVATE="$PKGCFG_NAMES_PRIVATE libsodium"
else
    AC_MSG_NOTICE([Using tweetnacl for CURVE security])
    AC_DEFINE(ZMQ_HAVE_CURVE, [1], [Using curve encryption])
    AC_DEFINE(ZMQ_USE_TWEETNACL, [1], [Using tweetnacl for curve encryption])
    curve_library="tweetnacl"
    enable_curve="yes"
fi

AM_CONDITIONAL(ENABLE_CURVE_KEYGEN, test "x$enable_curve" = "xyes" -a "x$zmq_enable_curve_keygen" = "xyes")

AM_CONDITIONAL(USE_LIBSODIUM, test "$curve_library" = "libsodium")
AM_CONDITIONAL(USE_TWEETNACL, test "$curve_library" = "tweetnacl")
AM_CONDITIONAL(HAVE_CURVE, test "x$curve_library" != "x")
AM_CONDITIONAL(USE_WEPOLL, test "$poller" = "wepoll")

# Check requiring packages for WebSocket
ws_crypto_library=""

AC_ARG_ENABLE([ws],
    [AS_HELP_STRING([--enable-ws], [Enable WebSocket transport [default=state of DRAFT]])],
    [enable_ws=$enableval],
    [enable_ws=$enable_drafts])

AC_ARG_WITH([nss],
    [AS_HELP_STRING([--with-nss], [use nss instead of built-in sha1 [default=no]])])

AC_ARG_WITH([tls],
    [AS_HELP_STRING([--with-tls], [Enable TLS (WSS transport) [default=no]])])

if test "x$enable_ws" != "xno"; then
    if test "x$with_tls" = "xyes"; then
        PKG_CHECK_MODULES([GNUTLS], [gnutls >= 3.1.4], [
            PKGCFG_NAMES_PRIVATE="$PKGCFG_NAMES_PRIVATE gnutls >= 3.1.4"
            ws_crypto_library="gnutls"
            AC_DEFINE(ZMQ_USE_GNUTLS, [1], [Use GNUTLS for TLS])
            AC_DEFINE(ZMQ_HAVE_WS, [1], [Using websocket])
            AC_DEFINE(ZMQ_HAVE_WSS, [1], [WSS enabled])
            AC_MSG_NOTICE(Using gnutls)
        ],[
          AC_MSG_ERROR([GnuTLS is not installed. Install it, then run configure again])
        ])
    elif test "x$with_nss" = "xyes"; then
        PKG_CHECK_MODULES([NSS3], [nss], [
            PKGCFG_NAMES_PRIVATE="$PKGCFG_NAMES_PRIVATE nss"
            AC_DEFINE(ZMQ_USE_NSS, [1], [Using NSS])
            AC_DEFINE(ZMQ_HAVE_WS, [1], [Using websocket])
            ws_crypto_library="nss"
            AC_MSG_NOTICE(Using NSS)
        ], [
            AC_MSG_ERROR([nss is not installed. Install it, then run configure again])
        ])
    else
        AC_DEFINE(ZMQ_HAVE_WS, [1], [Using websocket])
        AC_DEFINE(ZMQ_USE_BUILTIN_SHA1, [1], [Using built-in sha1])
        AC_MSG_NOTICE(Using builting SHA1)
        ws_crypto_library="builtin"
    fi
fi

AM_CONDITIONAL(HAVE_WS, test "x$ws_crypto_library" != "x")
AM_CONDITIONAL(USE_NSS, test "x$ws_crypto_library" = "xnss")
AM_CONDITIONAL(USE_BUILTIN_SHA1, test "x$ws_crypto_library" = "xbuiltin")
AM_CONDITIONAL(USE_GNUTLS, test "x$ws_crypto_library" = "xgnutls")
AM_CONDITIONAL(HAVE_WSS, test "x$ws_crypto_library" = "xgnutls")

# build using pgm
have_pgm_library="no"

AC_ARG_WITH([pgm], [AS_HELP_STRING([--with-pgm],
    [build libzmq with PGM extension. Requires pkg-config [default=no]])],
    [with_pgm_ext=$withval],
    [with_pgm_ext=no])

# conditionally require pgm package
if test "x$with_pgm_ext" != "xno"; then
    PKG_CHECK_MODULES([pgm], [openpgm-5.3 >= 5.3], [
        have_pgm_library="yes"
        PKGCFG_NAMES_PRIVATE="$PKGCFG_NAMES_PRIVATE openpgm-5.3 >= 5.3"
    ], [
        PKG_CHECK_MODULES([pgm], [openpgm-5.2 >= 5.2], [
            have_pgm_library="yes"
            PKGCFG_NAMES_PRIVATE="$PKGCFG_NAMES_PRIVATE openpgm-5.2 >= 5.2"
        ], [
            PKG_CHECK_MODULES([pgm], [openpgm-5.1 >= 5.1], [
                have_pgm_library="yes"
                PKGCFG_NAMES_PRIVATE="$PKGCFG_NAMES_PRIVATE openpgm-5.1 >= 5.1"
            ])
        ])
    ])
fi

if test "x$have_pgm_library" = "xyes"; then
    AC_DEFINE(ZMQ_HAVE_OPENPGM, [1], [Have OpenPGM extension])
fi

AM_CONDITIONAL(HAVE_PGM, test "x$have_pgm_library" = "xyes")


# This uses "--with-norm" to point to the "norm" directory
# for "norm/include" and "norm/lib"
#(if "--with-norm=yes" is given, then assume installed on system)
AC_ARG_WITH([norm],
    [AS_HELP_STRING([--with-norm],
        [build libzmq with NORM protocol extension, optionally specifying norm path [default=no]])],
    [with_norm_ext=$withval],
    [with_norm_ext=no])

AC_MSG_CHECKING("with_norm_ext = ${with_norm_ext}")

if test "x$with_norm_ext" != "xno"; then
    PKG_CHECK_MODULES([norm], [norm], [
        have_norm_library="yes"
        PKGCFG_NAMES_PRIVATE="$PKGCFG_NAMES_PRIVATE norm"
    ], [
        AC_MSG_RESULT([yes])

        norm_LIBS=""
        norm_CFLAGS=""
        if test "x$with_norm_ext" != "xyes"; then
            norm_path="${with_norm_ext}"
            norm_CFLAGS="${norm_CFLAGS} -I${norm_path}/include"
            norm_LIBS="${norm_LIBS} -L${norm_path}/lib"
        fi
        norm_LIBS="${norm_LIBS} -lnorm"
        have_norm_library="yes"
        PKGCFG_LIBS_PRIVATE="$PKGCFG_LIBS_PRIVATE $norm_LIBS"
        AC_SUBST(norm_LIBS)
        AC_SUBST(norm_CFLAGS)
    ])
else
    AC_MSG_RESULT([no])
fi
if test "x$have_norm_library" = "xyes"; then
    AC_DEFINE(ZMQ_HAVE_NORM, [1], [Have NORM protocol extension])
fi
AM_CONDITIONAL(HAVE_NORM, test "x$have_norm_library" = "xyes")

# build using vmci
have_vmci_library="no"

AC_ARG_WITH([vmci], [AS_HELP_STRING([--with-vmci],
    [build libzmq with VMCI transport [default=no]])],
    [have_vmci_ext=$withval],
    [have_vmci_ext=no])

if test "x$have_vmci_ext" != "xno"; then
    AC_DEFINE(ZMQ_HAVE_VMCI, 1, [Have VMCI transport])

    if test "x$have_vmci_ext" != "xyes"; then
        vmci_path="${have_vmci_ext}"
        LIBZMQ_VMCI_CXXFLAGS="-I${vmci_path}"
        LIBZMQ_VMCI_LDFLAGS="-I${vmci_path}"
        LIBZMQ_EXTRA_CXXFLAGS="${LIBZMQ_VMCI_CXXFLAGS} ${LIBZMQ_EXTRA_CXXFLAGS}"
        LIBZMQ_EXTRA_LDFLAGS="${LIBZMQ_VMCI_LDFLAGS} ${LIBZMQ_EXTRA_LDFLAGS}"
    fi
fi

AM_CONDITIONAL(HAVE_VMCI, test "x$have_vmci_ext" != "xno")

# Set -Wall, -Werror and -pedantic
AC_LANG_PUSH([C++])

# Check how to enable -Wall
LIBZMQ_LANG_WALL([CXXFLAGS="$libzmq_cv_[]_AC_LANG_ABBREV[]_wall_flag $CXXFLAGS"])

if test "x$libzmq_werror" = "xyes" -a "x$libzmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler" != "xyes"; then
    LIBZMQ_LANG_WERROR([CXXFLAGS="$libzmq_cv_[]_AC_LANG_ABBREV[]_werror_flag $CXXFLAGS"])
fi

if test "x$libzmq_pedantic" = "xyes"; then
    LIBZMQ_LANG_STRICT([CXXFLAGS="$libzmq_cv_[]_AC_LANG_ABBREV[]_strict_flag $CXXFLAGS"])
fi
AC_LANG_POP([C++])

AM_CONDITIONAL(BUILD_TIPC, test "x$libzmq_tipc_support" = "xyes")
AM_CONDITIONAL(ON_MINGW, test "x$libzmq_on_mingw" = "xyes")
AM_CONDITIONAL(ON_CYGWIN, test "x$libzmq_on_cygwin" = "xyes")
AM_CONDITIONAL(ON_ANDROID, test "x$libzmq_on_android" = "xyes")
AM_CONDITIONAL(ON_LINUX, test "x$libzmq_on_linux" = "xyes")
AM_CONDITIONAL(ON_GNU, test "x$libzmq_on_gnu" = "xyes")

# Check for __atomic_Xxx compiler intrinsics
AC_LANG_PUSH([C++])
AX_CHECK_COMPILE_FLAG([-Watomic-alignment],
    [CXXFLAGS+=" -Wno-atomic-alignment"],
    [],
    [-Werror])
LIBZMQ_CHECK_ATOMIC_INTRINSICS([
    AC_DEFINE([ZMQ_HAVE_ATOMIC_INTRINSICS],
              [1],
              [Whether compiler has __atomic_Xxx intrinsics.])
    ])
AC_LANG_POP([C++])

# Checks for library functions.
AC_TYPE_SIGNAL
AC_CHECK_FUNCS(perror gettimeofday clock_gettime memset socket getifaddrs freeifaddrs fork mkdtemp accept4)
AC_CHECK_HEADERS([alloca.h])

# string.h doesn't seem to be included by default in Fedora 30
AC_MSG_CHECKING([whether strnlen is available])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <string.h>]],
		[[size_t bar = strnlen ("foo", 1); (void)bar; return 0;]])
	],[
		AC_MSG_RESULT([yes])
		AC_DEFINE(HAVE_STRNLEN, [1],
		    [strnlen is available])
	],[
		AC_MSG_RESULT([no])
])

AC_ARG_ENABLE([libbsd],
    [AS_HELP_STRING([--enable-libbsd],
        [enable libbsd [default=auto]])],
    [enable_libbsd=$enableval],
    [enable_libbsd="auto"])

if test "x$enable_libbsd" != "xno"; then
    PKG_CHECK_MODULES(LIBBSD, [libbsd],
        [
            AC_DEFINE(ZMQ_HAVE_LIBBSD, 1, [The libbsd library is to be used])
            AC_SUBST([LIBBSD_CFLAGS])
            AC_SUBST([LIBBSD_LIBS])
            PKGCFG_NAMES_PRIVATE="$PKGCFG_NAMES_PRIVATE libbsd"
            found_libbsd="yes"
        ],
        [
            found_libbsd="no"
            if test "x$enable_libbsd" = "xyes"; then
                AC_MSG_ERROR([Cannot find libbsd])
            else
                AC_MSG_WARN([Cannot find libbsd])
            fi
        ])
fi
if test "x$found_libbsd" != "xyes"; then
    AC_MSG_CHECKING([whether strlcpy is available])
    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM(
            [[#include <string.h>]],
            [[char buf [100]; size_t bar = strlcpy (buf, "foo", 100); (void)bar; return 0;]])
        ],[
            AC_MSG_RESULT([yes])
            AC_DEFINE(ZMQ_HAVE_STRLCPY, [1],
                [strlcpy is available])
        ],[
            AC_MSG_RESULT([no])
    ])
fi

# pthread_setname is non-posix, and there are at least 4 different implementations
AC_MSG_CHECKING([whether signature of pthread_setname_np() has 1 argument])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <pthread.h>]],
		[[pthread_setname_np ("foo"); return 0;]])
	],[
		AC_MSG_RESULT([yes])
		AC_DEFINE(ZMQ_HAVE_PTHREAD_SETNAME_1, [1],
		    [Whether pthread_setname_np() has 1 argument])
	],[
		AC_MSG_RESULT([no])
])
AC_MSG_CHECKING([whether signature of pthread_setname_np() has 2 arguments])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <pthread.h>]],
		[[pthread_setname_np (pthread_self (), "foo"); return 0;]])
	],[
		AC_MSG_RESULT([yes])
		AC_DEFINE(ZMQ_HAVE_PTHREAD_SETNAME_2, [1],
		    [Whether pthread_setname_np() has 2 arguments])
	],[
		AC_MSG_RESULT([no])
])
AC_MSG_CHECKING([whether signature of pthread_setname_np() has 3 arguments])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <pthread.h>]],
		[[pthread_setname_np (pthread_self(), "foo", (void *)0); return 0;]])
	],[
		AC_MSG_RESULT([yes])
		AC_DEFINE(ZMQ_HAVE_PTHREAD_SETNAME_3, [1],
		    [Whether pthread_setname_np() has 3 arguments])
	],[
		AC_MSG_RESULT([no])
])
AC_MSG_CHECKING([whether pthread_set_name_np() exists])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <pthread.h>]],
		[[pthread_set_name_np (pthread_self(), "foo"); return 0;]])
	],[
		AC_MSG_RESULT([yes])
		AC_DEFINE(ZMQ_HAVE_PTHREAD_SET_NAME, [1],
		    [Whether pthread_set_name_np() exists])
	],[
		AC_MSG_RESULT([no])
])


# pthread_setaffinity_np is non-posix:
AC_MSG_CHECKING([whether pthread_setaffinity_np() exists])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <pthread.h>]],
		[[cpu_set_t test; pthread_setaffinity_np (pthread_self(), sizeof(cpu_set_t), &test); return 0;]])
	],[
		AC_MSG_RESULT([yes])
		AC_DEFINE(ZMQ_HAVE_PTHREAD_SET_AFFINITY, [1],
		    [Whether pthread_setaffinity_np() exists])
	],[
		AC_MSG_RESULT([no])
])


LIBZMQ_CHECK_SOCK_CLOEXEC([
    AC_DEFINE([ZMQ_HAVE_SOCK_CLOEXEC],
        [1],
        [Whether SOCK_CLOEXEC is defined and functioning.])
    ])

LIBZMQ_CHECK_O_CLOEXEC([
    AC_DEFINE([ZMQ_HAVE_O_CLOEXEC],
        [1],
        [Whether O_CLOEXEC is defined and functioning.])
    ])

LIBZMQ_CHECK_SO_BINDTODEVICE([
    AC_DEFINE([ZMQ_HAVE_SO_BINDTODEVICE],
        [1],
        [Whether SO_BINDTODEVICE is supported.])
    ])

# TCP keep-alives Checks.
LIBZMQ_CHECK_SO_KEEPALIVE([
    AC_DEFINE([ZMQ_HAVE_SO_KEEPALIVE],
        [1],
        [Whether SO_KEEPALIVE is supported.])
    ])

LIBZMQ_CHECK_TCP_KEEPCNT([
    AC_DEFINE([ZMQ_HAVE_TCP_KEEPCNT],
        [1],
        [Whether TCP_KEEPCNT is supported.])
    ])

LIBZMQ_CHECK_TCP_KEEPIDLE([
    AC_DEFINE([ZMQ_HAVE_TCP_KEEPIDLE],
        [1],
        [Whether TCP_KEEPIDLE is supported.])
    ])

LIBZMQ_CHECK_TCP_KEEPINTVL([
    AC_DEFINE([ZMQ_HAVE_TCP_KEEPINTVL],
        [1],
        [Whether TCP_KEEPINTVL is supported.])
    ])

LIBZMQ_CHECK_TCP_KEEPALIVE([
    AC_DEFINE([ZMQ_HAVE_TCP_KEEPALIVE],
        [1],
        [Whether TCP_KEEPALIVE is supported.])
    ])

LIBZMQ_CHECK_GETRANDOM([
    AC_DEFINE([ZMQ_HAVE_GETRANDOM],
        [1],
        [Whether getrandom is supported.])
    ])

AM_CONDITIONAL(HAVE_FORK, test "x$ac_cv_func_fork" = "xyes")

if test "x$cross_compiling" = "xyes"; then
    #   Enable draft by default when cross-compiling
    defaultval=yes
else
    # enable draft API by default if we're in a git repository
    # else disable it by default; then allow --enable-drafts=yes/no override
    AC_CHECK_FILE($srcdir/.git, [defaultval=yes], [defaultval=no])
fi

AC_ARG_ENABLE([drafts],
    AS_HELP_STRING([--enable-drafts],
        [Build and install draft classes and methods [default=yes]]),
    [enable_drafts=$enableval],
    [enable_drafts=$defaultval])

AM_CONDITIONAL([ENABLE_DRAFTS], [test x$enable_drafts != xno])

if test "x$enable_drafts" = "xyes"; then
    AC_MSG_NOTICE([Building stable and legacy API + draft API])
    AC_DEFINE(ZMQ_BUILD_DRAFT_API, 1, [Provide draft classes and methods])
    AC_SUBST(pkg_config_defines, "-DZMQ_BUILD_DRAFT_API=1")
else
    AC_MSG_NOTICE([Building stable and legacy API (no draft API)])
    AC_SUBST(pkg_config_defines, "")
fi

AC_ARG_ENABLE([libunwind],
    [AS_HELP_STRING([--enable-libunwind],
        [enable libunwind [default=auto]])],
    [enable_libunwind=$enableval],
    [enable_libunwind="auto"])

if test "x$enable_libunwind" != "xno"; then
    PKG_CHECK_MODULES(LIBUNWIND, [libunwind],
        [
            AC_DEFINE(HAVE_LIBUNWIND, 1, [The libunwind library is to be used])
            AC_SUBST([LIBUNWIND_CFLAGS])
            AC_SUBST([LIBUNWIND_LIBS])
            AC_CHECK_LIB([dl], [dladdr], [
                PKGCFG_LIBS_PRIVATE="$PKGCFG_LIBS_PRIVATE -ldl"
                LIBS="-ldl $LIBS"
            ], [
                AC_CHECK_LIB([dld], [dladdr], [
                    PKGCFG_LIBS_PRIVATE="$PKGCFG_LIBS_PRIVATE -ldld"
                    LIBS="-ldld $LIBS"
                ])
            ])
            PKGCFG_NAMES_PRIVATE="$PKGCFG_NAMES_PRIVATE libunwind"
        ],
        [
            if test "x$enable_libunwind" = "xyes"; then
                AC_MSG_ERROR([Cannot find libunwind])
            else
                AC_MSG_WARN([Cannot find libunwind])
            fi
        ])
fi

AC_ARG_ENABLE([radix-tree],
    AS_HELP_STRING([--enable-radix-tree],
        [Use radix tree implementation to manage subscriptions [default=DRAFT]]),
    [radix_tree=$enableval],
    [radix_tree=$enable_drafts])

AM_CONDITIONAL([ENABLE_RADIX_TREE], [test x$radix_tree != xno])

if test "x$radix_tree" = "xyes"; then
    AC_MSG_NOTICE([Using radix tree implementation to manage subscriptions])
    AC_DEFINE(ZMQ_USE_RADIX_TREE, 1, [Use radix tree implementation to manage subscriptions])
else
    AC_MSG_NOTICE([Using mtree implementation to manage subscriptions])
fi

# See if clang-format is in PATH; the result unblocks the relevant recipes
WITH_CLANG_FORMAT=""
AS_IF([test x"$CLANG_FORMAT" = x],
    [AC_PATH_PROG([CLANG_FORMAT], [clang-format], [])],
    [AC_CHECK_PROG([WITH_CLANG_FORMAT], [$CLANG_FORMAT], [true], [fail])])
AS_IF([test x"$CLANG_FORMAT" != x && test x"$WITH_CLANG_FORMAT" = x],
    [AS_IF([test -x "$CLANG_FORMAT"],
        [WITH_CLANG_FORMAT=true],
        [AC_CHECK_PROG([WITH_CLANG_FORMAT], [$CLANG_FORMAT], [true], [false])])])
AS_IF([test "$WITH_CLANG_FORMAT" = fail],
    [AC_MSG_ERROR([Caller explicitly referenced CLANG_FORMAT=$CLANG_FORMAT which was not found])])
AM_CONDITIONAL([WITH_CLANG_FORMAT], [$WITH_CLANG_FORMAT])

# unittests will not build without the static libzmq.a
AM_CONDITIONAL(ENABLE_STATIC, test "x$enable_static" = "xyes")

# build using a fuzzing engine - fuzzers will be built separately and statically
AC_ARG_WITH([fuzzing-engine], [AS_HELP_STRING([--with-fuzzing-engine],
    [build libzmq with an exernal fuzzing engine [default=no]])],
    [have_fuzzing_engine_ext=$withval],
    [have_fuzzing_engine_ext=no])
AC_ARG_WITH([fuzzing-installdir],
    AS_HELP_STRING([--with-fuzzing-installdir=PATH],
        [Path where to install fuzzer binaries]),
    [fuzzing_installdir="$withval"])

if test "x$have_fuzzing_engine_ext" != "xno" && test "x$fuzzing_installdir" != "x" && test "x$enable_static" = "xyes"; then
    FUZZING_ENGINE_LIB="${have_fuzzing_engine_ext}"
    FUZZING_INSTALLDIR="${fuzzing_installdir}"
    AC_SUBST(FUZZING_ENGINE_LIB)
    AC_SUBST(FUZZING_INSTALLDIR)
    AC_DEFINE(ZMQ_USE_FUZZING_ENGINE, 1, [fuzz tests will be built with fuzzing engine])
fi
AM_CONDITIONAL(FUZZING_ENGINE_LIB, test "x$FUZZING_ENGINE_LIB" != "x")

# clang 6 has a warning that does not make sense on multi-platform code
AC_LANG_PUSH([C])
AX_CHECK_COMPILE_FLAG([-Wtautological-constant-compare],
    [CFLAGS+=" -Wno-tautological-constant-compare"],
    [],
    [-Werror])
AC_LANG_POP([C])
AX_CHECK_COMPILE_FLAG([-Wtautological-constant-compare],
    [CXXFLAGS+=" -Wno-tautological-constant-compare"],
    [],
    [-Werror])

# LTO is enabled by default on SUSE Tumbleweed and RPM lint generates an error if
# the flag is not used to compile archives:
# E: lto-no-text-in-archive
AC_LANG_PUSH([C])
AX_CHECK_COMPILE_FLAG([-ffat-lto-objects],
    [CFLAGS+=" -ffat-lto-objects"],
    [],
    [-Werror])
AC_LANG_POP([C])
AX_CHECK_COMPILE_FLAG([-ffat-lto-objects],
    [CXXFLAGS+=" -ffat-lto-objects"],
    [],
    [-Werror])

# Subst LIBZMQ_EXTRA_CFLAGS & CXXFLAGS & LDFLAGS
AC_SUBST(LIBZMQ_EXTRA_CFLAGS)
AC_SUBST(LIBZMQ_EXTRA_CXXFLAGS)
AC_SUBST(LIBZMQ_EXTRA_LDFLAGS)

AC_SUBST(LIBZMQ_VMCI_CXXFLAGS)
AC_SUBST(LIBZMQ_VMCI_LDFLAGS)

AC_SUBST(pkg_config_libs_private, $PKGCFG_LIBS_PRIVATE)
AC_SUBST(pkg_config_names_private, $PKGCFG_NAMES_PRIVATE)

# set pkgconfigdir, allow override
AC_ARG_WITH([pkgconfigdir],
    AS_HELP_STRING([--with-pkgconfigdir=PATH],
        [Path to the pkgconfig directory [[LIBDIR/pkgconfig]]]),
    [pkgconfigdir="$withval"],
    [pkgconfigdir='${libdir}/pkgconfig'])
AC_SUBST([pkgconfigdir])

AC_CONFIG_FILES([ \
    Makefile \
    src/libzmq.pc \
    doc/Makefile \
    builds/Makefile \
    builds/deprecated-msvc/Makefile])

AC_OUTPUT
