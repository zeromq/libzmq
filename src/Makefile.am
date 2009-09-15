lib_LTLIBRARIES = libzmq.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libzmq.pc

if BUILD_CPP
include_HEADERS = ../cpp/zmq.hpp ../c/zmq.h
endif

if BUILD_C
if BUILD_CPP

else
include_HEADERS = ../c/zmq.h
endif
endif

if BUILD_PGM
pgm_sources = ../foreign/openpgm/@pgm_basename@/openpgm/pgm/packet.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/timer.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/if.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/gsi.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/signal.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/txwi.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/rxwi.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/transport.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/rate_control.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/async.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/checksum.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/reed_solomon.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/version.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/galois_tables.c
endif

libzmq_la_SOURCES = $(pgm_sources) \
    app_thread.hpp \
    atomic_bitmap.hpp \
    atomic_counter.hpp \
    atomic_ptr.hpp \
    command.hpp \
    config.hpp \
    decoder.hpp \
    devpoll.hpp \
    dispatcher.hpp \
    encoder.hpp \
    epoll.hpp \
    err.hpp \
    fd.hpp \
    fd_signaler.hpp \
    i_inout.hpp \
    io_object.hpp \
    io_thread.hpp \
    ip.hpp \
    i_endpoint.hpp \
    i_engine.hpp \
    i_poller.hpp \
    i_poll_events.hpp \
    i_signaler.hpp \
    kqueue.hpp \
    msg_content.hpp \
    mutex.hpp \
    object.hpp \
    options.hpp \
    owned.hpp \
    pgm_sender.hpp \
    pgm_socket.hpp \
    pipe.hpp \
    platform.hpp \
    poll.hpp \
    pub.hpp \
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
    uuid.hpp \
    windows.hpp \
    wire.hpp \
    ypipe.hpp \
    ypollset.hpp \
    yqueue.hpp \
    zmq_connecter.hpp \
    zmq_connecter_init.hpp \
    zmq_decoder.hpp \
    zmq_encoder.hpp \
    zmq_engine.hpp \
    zmq_listener.hpp \
    zmq_listener_init.hpp \
    app_thread.cpp \
    devpoll.cpp \
    dispatcher.cpp \
    epoll.cpp \
    err.cpp \
    fd_signaler.cpp \
    io_object.cpp \
    io_thread.cpp \
    ip.cpp \
    kqueue.cpp \
    object.cpp \
    options.cpp \
    owned.cpp \
    pgm_sender.cpp \
    pgm_socket.cpp \
    pipe.cpp \
    poll.cpp \
    pub.cpp \
    select.cpp \
    session.cpp \
    socket_base.cpp \
    sub.cpp \
    tcp_connecter.cpp \
    tcp_listener.cpp \
    tcp_socket.cpp \
    thread.cpp \
    uuid.cpp \
    ypollset.cpp \
    zmq.cpp \
    zmq_connecter.cpp \
    zmq_connecter_init.cpp \
    zmq_decoder.cpp \
    zmq_encoder.cpp \
    zmq_engine.cpp \
    zmq_listener.cpp \
    zmq_listener_init.cpp

libzmq_la_LDFLAGS = -version-info @LTVER@ @LIBZMQ_EXTRA_LDFLAFS@

if BUILD_PGM
libzmq_la_CXXFLAGS = -I$(top_srcdir)/foreign/openpgm/@pgm_basename@/openpgm/pgm/include/ -Wall @LIBZMQ_EXTRA_CXXFLAGS@
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
    -D__need_IOV_MAX \
    -DCONFIG_HAVE_EPOLL \
    -DCONFIG_HAVE_RTC \
    -DCONFIG_HAVE_TSC \
    -DCONFIG_HAVE_IFR_NETMASK \
    -DCONFIG_HAVE_GETIFADDRS \
    -DCONFIG_HAVE_GETHOSTBYNAME2 \
    -DCONFIG_HAVE_GETPROTOBYNAME_R \
    -DCONFIG_HAVE_SIGHANDLER_T \
    -DCONFIG_BIND_INADDR_ANY \
    -DCONFIG_GALOIS_MUL_LUT
else
libzmq_la_CXXFLAGS = -Wall @LIBZMQ_EXTRA_CXXFLAGS@
endif

dist-hook:
		-rm $(distdir)/src/platform.hpp


