lib_LTLIBRARIES = libzmq.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libzmq.pc

if BUILD_CPP
include_HEADERS = ../bindings/cpp/zmq.hpp ../bindings/c/zmq.h
endif

if BUILD_C
if BUILD_CPP

else
include_HEADERS = ../bindings/c/zmq.h
endif
endif

if BUILD_PGM2
pgm_sources = ../foreign/openpgm/@pgm_basename@/openpgm/pgm/packet.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/time.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/if.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/getifaddrs.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/getnodeaddr.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/indextoaddr.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/indextoname.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/nametoindex.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/inet_network.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/md5.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/gsi.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/tsi.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/signal.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/txwi.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/rxwi.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/transport.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/source.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/receiver.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/recv.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/pgm.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/timer.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/net.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/rate_control.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/async.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/checksum.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/reed_solomon.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/galois_tables.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/wsastrerror.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/glib-compat.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/backtrace.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/log.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/sockaddr.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/version.c
endif

nodist_libzmq_la_SOURCES = $(pgm_sources)

libzmq_la_SOURCES = app_thread.hpp \
    atomic_bitmap.hpp \
    atomic_counter.hpp \
    atomic_ptr.hpp \
    command.hpp \
    config.hpp \
    decoder.hpp \
    devpoll.hpp \
    dispatcher.hpp \
    downstream.hpp \
    encoder.hpp \
    epoll.hpp \
    err.hpp \
    fd.hpp \
    fd_signaler.hpp \
    fq.hpp \
    i_inout.hpp \
    io_object.hpp \
    io_thread.hpp \
    ip.hpp \
    i_endpoint.hpp \
    i_engine.hpp \
    i_poll_events.hpp \
    i_signaler.hpp \
    kqueue.hpp \
    lb.hpp \
    likely.hpp \
    msg_content.hpp \
    mutex.hpp \
    object.hpp \
    options.hpp \
    owned.hpp \
    pgm_receiver.hpp \
    pgm_sender.hpp \
    pgm_socket.hpp \
    pipe.hpp \
    platform.hpp \
    poll.hpp \
    poller.hpp \
    p2p.hpp \
    prefix_tree.hpp \
    pub.hpp \
    rep.hpp \
    req.hpp \
    select.hpp \
    session.hpp \
    simple_semaphore.hpp \
    socket_base.hpp \
    stdint.hpp \
    sub.hpp \
    tcp_connecter.hpp \
    tcp_listener.hpp \
    tcp_socket.hpp \
    thread.hpp \
    upstream.hpp \
    uuid.hpp \
    windows.hpp \
    wire.hpp \
    xrep.hpp \
    xreq.hpp \
    yarray.hpp \
    yarray_item.hpp \
    ypipe.hpp \
    ypollset.hpp \
    yqueue.hpp \
    zmq_connecter.hpp \
    zmq_decoder.hpp \
    zmq_encoder.hpp \
    zmq_engine.hpp \
    zmq_init.hpp \
    zmq_listener.hpp \
    app_thread.cpp \
    devpoll.cpp \
    dispatcher.cpp \
    downstream.cpp \
    epoll.cpp \
    err.cpp \
    fd_signaler.cpp \
    fq.cpp \
    io_object.cpp \
    io_thread.cpp \
    ip.cpp \
    kqueue.cpp \
    lb.cpp \
    object.cpp \
    options.cpp \
    owned.cpp \
    pgm_receiver.cpp \
    pgm_sender.cpp \
    pgm_socket.cpp \
    p2p.cpp \
    prefix_tree.cpp \
    pipe.cpp \
    poll.cpp \
    pub.cpp \
    rep.cpp \
    req.cpp \
    select.cpp \
    session.cpp \
    socket_base.cpp \
    sub.cpp \
    tcp_connecter.cpp \
    tcp_listener.cpp \
    tcp_socket.cpp \
    thread.cpp \
    upstream.cpp \
    uuid.cpp \
    xrep.cpp \
    xreq.cpp \
    ypollset.cpp \
    zmq.cpp \
    zmq_connecter.cpp \
    zmq_decoder.cpp \
    zmq_encoder.cpp \
    zmq_engine.cpp \
    zmq_init.cpp \
    zmq_listener.cpp

libzmq_la_LDFLAGS = -version-info @LTVER@ @LIBZMQ_EXTRA_LDFLAFS@

if BUILD_PGM2

if ON_MINGW
libpgm_diff_flags = \
    -D_WIN32_WINNT=0x0501 \
    -DCONFIG_HAVE_IFR_NETMASK \
    -DCONFIG_BIND_INADDR_ANY \
    -DCONFIG_GALOIS_MUL_LUT \
    -DIF_NAMESIZE=256 \
    -DPGM_GNUC_INTERNAL=G_GNUC_INTERNAL \
    -DCONFIG_HAVE_WSACMSGHDR \
    -DGETTEXT_PACKAGE='"pgm"' \
    -DG_LOG_DOMAIN='"Pgm"'

else
libpgm_diff_flags = \
    -D__need_IOV_MAX \
    -DCONFIG_HAVE_PSELECT \
    -DCONFIG_HAVE_POLL \
    -DCONFIG_HAVE_PPOLL \
    -DCONFIG_HAVE_EPOLL \
    -DCONFIG_HAVE_CLOCK_GETTIME \
    -DCONFIG_HAVE_CLOCK_NANOSLEEP \
    -DCONFIG_HAVE_NANOSLEEP \
    -DCONFIG_HAVE_USLEEP \
    -DCONFIG_HAVE_RTC \
    -DCONFIG_HAVE_TSC \
    -DCONFIG_HAVE_IFR_NETMASK \
    -DCONFIG_HAVE_GETIFADDRS \
    -DCONFIG_HAVE_GETHOSTBYNAME2 \
    -DCONFIG_HAVE_GETPROTOBYNAME_R \
    -DCONFIG_BIND_INADDR_ANY \
    -DCONFIG_GALOIS_MUL_LUT \
    -DCONFIG_HAVE_MCAST_JOIN \
    -DCONFIG_HAVE_IP_MREQN \
    -DCONFIG_HAVE_SPRINTF_GROUPING \
    -DCONFIG_HAVE_HPET \
    -DPGM_GNUC_INTERNAL=G_GNUC_INTERNAL \
    -DGETTEXT_PACKAGE='"pgm"' \
    -DG_LOG_DOMAIN='"Pgm"'
endif

libzmq_la_CFLAGS = -I$(top_srcdir)/foreign/openpgm/@pgm_basename@/openpgm/pgm/include/ @LIBZMQ_EXTRA_CXXFLAGS@ \
    -pipe \
    -Wall \
    -Wextra \
    -Wfloat-equal \
    -Wshadow \
    -Wunsafe-loop-optimizations \
    -Wpointer-arith \
    -Wbad-function-cast \
    -Wcast-qual \
    -Wcast-align \
    -Wwrite-strings \
    -Waggregate-return \
    -Wstrict-prototypes \
    -Wold-style-definition \
    -Wmissing-prototypes \
    -Wmissing-declarations \
    -Wmissing-noreturn \
    -Wmissing-format-attribute \
    -Wredundant-decls \
    -Wnested-externs \
    -Winline \
    -pedantic \
    -std=gnu99 \
    --param max-inline-insns-single=600 \
    -D_REENTRANT \
    -D_GNU_SOURCE \
    ${libpgm_diff_flags}

libzmq_la_CXXFLAGS = -I$(top_srcdir)/foreign/openpgm/@pgm_basename@/openpgm/pgm/include/ \
    -Wall @LIBZMQ_EXTRA_CXXFLAGS@ ${libpgm_diff_flags}
endif

if BUILD_NO_PGM
libzmq_la_CXXFLAGS = -Wall @LIBZMQ_EXTRA_CXXFLAGS@
endif

dist-hook:
		-rm $(distdir)/platform.hpp


