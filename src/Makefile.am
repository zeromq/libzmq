lib_LTLIBRARIES = libzmq.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libzmq.pc

include_HEADERS = ../include/zmq.h ../include/zmq.hpp ../include/zmq_utils.h

if BUILD_PGM
noinst_LTLIBRARIES = libpgm.la

nodist_libpgm_la_SOURCES = ../foreign/openpgm/@pgm_basename@/openpgm/pgm/thread.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/mem.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/string.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/list.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/slist.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/queue.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/hashtable.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/messages.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/error.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/math.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/packet_parse.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/packet_test.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/sockaddr.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/time.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/if.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/getifaddrs.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/getnodeaddr.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/indextoaddr.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/indextoname.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/nametoindex.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/inet_network.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/md5.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/rand.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/gsi.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/tsi.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/txw.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/rxw.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/skbuff.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/socket.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/source.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/receiver.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/recv.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/engine.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/timer.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/net.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/rate_control.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/checksum.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/reed_solomon.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/galois_tables.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/wsastrerror.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/histogram.c \
    ../foreign/openpgm/@pgm_basename@/openpgm/pgm/version.c

../foreign/openpgm/@pgm_basename@/openpgm/pgm/version.c: ../foreign/openpgm/@pgm_basename@/openpgm/pgm/version_generator.py
	python ../foreign/openpgm/@pgm_basename@/openpgm/pgm/version_generator.py > $@

../foreign/openpgm/@pgm_basename@/openpgm/pgm/galois_tables.c: ../foreign/openpgm/@pgm_basename@/openpgm/pgm/galois_generator.pl
	perl ../foreign/openpgm/@pgm_basename@/openpgm/pgm/galois_generator.pl > $@

libpgm_la_LIBADD = @LTLIBOBJS@
endif

libzmq_la_SOURCES = \
    array.hpp \
    atomic_counter.hpp \
    atomic_ptr.hpp \
    blob.hpp \
    clock.hpp \
    command.hpp \
    config.hpp \
    connect_session.hpp \
    ctx.hpp \
    decoder.hpp \
    device.hpp \
    devpoll.hpp \
    dist.hpp \
    encoder.hpp \
    epoll.hpp \
    err.hpp \
    fd.hpp \
    fq.hpp \
    i_inout.hpp \
    io_object.hpp \
    io_thread.hpp \
    ip.hpp \
    i_engine.hpp \
    i_poll_events.hpp \
    kqueue.hpp \
    lb.hpp \
    likely.hpp \
    mailbox.hpp \
    msg_content.hpp \
    mutex.hpp \
    named_session.hpp \
    object.hpp \
    options.hpp \
    own.hpp \
    pgm_receiver.hpp \
    pgm_sender.hpp \
    pgm_socket.hpp \
    pipe.hpp \
    platform.hpp \
    poll.hpp \
    poller.hpp \
    poller_base.hpp \
    pair.hpp \
    pub.hpp \
    pull.hpp \
    push.hpp \
    reaper.hpp \
    rep.hpp \
    req.hpp \
    select.hpp \
    semaphore.hpp \
    session.hpp \
    socket_base.hpp \
    stdint.hpp \
    sub.hpp \
    swap.hpp \
    tcp_connecter.hpp \
    tcp_listener.hpp \
    tcp_socket.hpp \
    thread.hpp \
    transient_session.hpp \
    trie.hpp \
    uuid.hpp \
    windows.hpp \
    wire.hpp \
    xpub.hpp \
    xrep.hpp \
    xreq.hpp \
    xsub.hpp \
    ypipe.hpp \
    yqueue.hpp \
    zmq_connecter.hpp \
    zmq_engine.hpp \
    zmq_init.hpp \
    zmq_listener.hpp \
    clock.cpp \
    command.cpp \
    ctx.cpp \
    connect_session.cpp \
    decoder.cpp \
    device.cpp \
    devpoll.cpp \
    dist.cpp \
    encoder.cpp \
    epoll.cpp \
    err.cpp \
    fq.cpp \
    io_object.cpp \
    io_thread.cpp \
    ip.cpp \
    kqueue.cpp \
    lb.cpp \
    mailbox.cpp \
    named_session.cpp \
    object.cpp \
    options.cpp \
    own.cpp \
    pair.cpp \
    pgm_receiver.cpp \
    pgm_sender.cpp \
    pgm_socket.cpp \
    pipe.cpp \
    poll.cpp \
    poller_base.cpp \
    pull.cpp \
    push.cpp \
    reaper.cpp \
    pub.cpp \
    rep.cpp \
    req.cpp \
    select.cpp \
    session.cpp \
    socket_base.cpp \
    sub.cpp \
    swap.cpp \
    tcp_connecter.cpp \
    tcp_listener.cpp \
    tcp_socket.cpp \
    thread.cpp \
    transient_session.cpp \
    trie.cpp \
    uuid.cpp \
    xpub.cpp \
    xrep.cpp \
    xreq.cpp \
    xsub.cpp \
    zmq.cpp \
    zmq_connecter.cpp \
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
    -DCONFIG_HAVE_ISO_VARARGS \
    -DCONFIG_HAVE_TSC \
    -DCONFIG_HAVE_WSACMSGHDR \
    -DCONFIG_BIND_INADDR_ANY

else
libpgm_diff_flags = \
    -DCONFIG_HAVE_PROC \
    -DCONFIG_HAVE_BACKTRACE \
    -DCONFIG_HAVE_IFR_NETMASK \
    -DCONFIG_HAVE_MCAST_JOIN \
    -DCONFIG_HAVE_IP_MREQN \
    -DCONFIG_HAVE_SPRINTF_GROUPING \
    -DCONFIG_BIND_INADDR_ANY 
endif

libpgm_la_CFLAGS = -I$(top_srcdir)/foreign/openpgm/@pgm_basename@/openpgm/pgm/include/ @LIBZMQ_EXTRA_CFLAGS@ \
    -D_XOPEN_SOURCE=600 \
    -D_BSD_SOURCE \
    -D_REENTRANT \
    -DCONFIG_16BIT_CHECKSUM \
    -DCONFIG_GALOIS_MUL_LUT \
    -DGETTEXT_PACKAGE='"pgm"' \
    -DPGM_GNUC_INTERNAL= \
    ${libpgm_diff_flags}

libzmq_la_CXXFLAGS = -I$(top_srcdir)/foreign/openpgm/@pgm_basename@/openpgm/pgm/include/ \
    @LIBZMQ_EXTRA_CXXFLAGS@
endif

if !BUILD_PGM
libzmq_la_CXXFLAGS = @LIBZMQ_EXTRA_CXXFLAGS@
endif

if BUILD_PGM
libzmq_la_LIBADD = libpgm.la
endif

dist-hook:
		-rm $(distdir)/platform.hpp


