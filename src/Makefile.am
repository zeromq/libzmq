lib_LTLIBRARIES = libzmq.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libzmq.pc

include_HEADERS = ../include/zmq.h ../include/zmq.hpp

if BUILD_PGM
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

../foreign/openpgm/@pgm_basename@/openpgm/pgm/version.c: ../foreign/openpgm/@pgm_basename@/openpgm/pgm/version_generator.py
	python ../foreign/openpgm/@pgm_basename@/openpgm/pgm/version_generator.py > $@

../foreign/openpgm/@pgm_basename@/openpgm/pgm/galois_tables.c: ../foreign/openpgm/@pgm_basename@/openpgm/pgm/galois_generator.pl
	perl ../foreign/openpgm/@pgm_basename@/openpgm/pgm/galois_generator.pl > $@
endif

nodist_libzmq_la_SOURCES = $(pgm_sources)

libzmq_la_SOURCES = app_thread.hpp \
    atomic_counter.hpp \
    atomic_ptr.hpp \
    blob.hpp \
    command.hpp \
    config.hpp \
    ctx.hpp \
    decoder.hpp \
    devpoll.hpp \
    downstream.hpp \
    encoder.hpp \
    epoll.hpp \
    err.hpp \
    fd.hpp \
    forwarder.hpp \
    fq.hpp \
    i_inout.hpp \
    io_object.hpp \
    io_thread.hpp \
    ip.hpp \
    i_endpoint.hpp \
    i_engine.hpp \
    i_poll_events.hpp \
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
    pair.hpp \
    prefix_tree.hpp \
    pub.hpp \
    queue.hpp \
    rep.hpp \
    req.hpp \
    select.hpp \
    session.hpp \
    signaler.hpp \
    socket_base.hpp \
    stdint.hpp \
    streamer.hpp \
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
    yqueue.hpp \
    zmq_connecter.hpp \
    zmq_decoder.hpp \
    zmq_encoder.hpp \
    zmq_engine.hpp \
    zmq_init.hpp \
    zmq_listener.hpp \
    app_thread.cpp \
    command.cpp \
    ctx.cpp \
    devpoll.cpp \
    downstream.cpp \
    epoll.cpp \
    err.cpp \
    forwarder.cpp \
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
    pair.cpp \
    prefix_tree.cpp \
    pipe.cpp \
    poll.cpp \
    pub.cpp \
    queue.cpp \
    rep.cpp \
    req.cpp \
    select.cpp \
    session.cpp \
    signaler.cpp \
    socket_base.cpp \
    streamer.cpp \
    sub.cpp \
    tcp_connecter.cpp \
    tcp_listener.cpp \
    tcp_socket.cpp \
    thread.cpp \
    upstream.cpp \
    uuid.cpp \
    xrep.cpp \
    xreq.cpp \
    zmq.cpp \
    zmq_connecter.cpp \
    zmq_decoder.cpp \
    zmq_encoder.cpp \
    zmq_engine.cpp \
    zmq_init.cpp \
    zmq_listener.cpp

if ON_MINGW
libzmq_la_LDFLAGS = -no-undefined -avoid-version -version-info @LTVER@ @LIBZMQ_EXTRA_LDFLAGS@
else
libzmq_la_LDFLAGS = -version-info @LTVER@ @LIBZMQ_EXTRA_LDFLAGS@
endif

if BUILD_PGM

if ON_MINGW
libpgm_diff_flags = \
    -D_WIN32_WINNT=0x0501 \
    -DCONFIG_16BIT_CHECKSUM \
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
    -DCONFIG_16BIT_CHECKSUM \
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
    -Wall \
    -pedantic \
    -std=gnu99 \
    -fno-strict-aliasing \
    --param max-inline-insns-single=600 \
    -D_REENTRANT \
    -D_GNU_SOURCE \
    ${libpgm_diff_flags}

libzmq_la_CXXFLAGS = -I$(top_srcdir)/foreign/openpgm/@pgm_basename@/openpgm/pgm/include/ \
    @LIBZMQ_EXTRA_CXXFLAGS@
endif

if BUILD_NO_PGM
libzmq_la_CXXFLAGS = @LIBZMQ_EXTRA_CXXFLAGS@
endif

dist-hook:
		-rm $(distdir)/platform.hpp


