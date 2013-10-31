lib_LTLIBRARIES = libzmq.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libzmq.pc

include_HEADERS = ../include/zmq.h ../include/zmq_utils.h

libzmq_la_SOURCES = \
    address.hpp \
    array.hpp \
    atomic_counter.hpp \
    atomic_ptr.hpp \
    blob.hpp \
    clock.hpp \
    command.hpp \
    config.hpp \
    ctx.hpp \
    decoder.hpp \
    devpoll.hpp \
    dist.hpp \
    encoder.hpp \
    epoll.hpp \
    err.hpp \
    fd.hpp \
    fq.hpp \
    i_encoder.hpp \
    i_decoder.hpp \
    i_engine.hpp \
    i_msg_sink.hpp \
    i_msg_source.hpp \
    i_poll_events.hpp \
    io_object.hpp \
    io_thread.hpp \
    ip.hpp \
    ipc_address.hpp \
    ipc_connecter.hpp \
    ipc_listener.hpp \
    i_engine.hpp \
    i_poll_events.hpp \
    kqueue.hpp \
    lb.hpp \
    likely.hpp \
    mailbox.hpp \
    msg.hpp \
    mtrie.hpp \
    mutex.hpp \
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
    proxy.hpp \
    pub.hpp \
    pull.hpp \
    push.hpp \
    random.hpp \
    reaper.hpp \
    rep.hpp \
    req.hpp \
    select.hpp \
    session_base.hpp \
    signaler.hpp \
    socket_base.hpp \
    stdint.hpp \
    stream_engine.hpp \
    sub.hpp \
    tcp.hpp \
    tcp_address.hpp \
    tcp_connecter.hpp \
    tcp_listener.hpp \
    thread.hpp \
    trie.hpp \
    windows.hpp \
    wire.hpp \
    xpub.hpp \
    router.hpp \
    dealer.hpp \
    xsub.hpp \
    ypipe.hpp \
    yqueue.hpp \
    address.cpp \
    clock.cpp \
    ctx.cpp \
    decoder.cpp \
    devpoll.cpp \
    dist.cpp \
    encoder.cpp \
    epoll.cpp \
    err.cpp \
    fq.cpp \
    io_object.cpp \
    io_thread.cpp \
    ip.cpp \
    ipc_address.cpp \
    ipc_connecter.cpp \
    ipc_listener.cpp \
    kqueue.cpp \
    lb.cpp \
    mailbox.cpp \
    msg.cpp \
    mtrie.cpp \
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
    proxy.cpp \
    reaper.cpp \
    pub.cpp \
    random.cpp \
    rep.cpp \
    req.cpp \
    select.cpp \
    session_base.cpp \
    signaler.cpp \
    socket_base.cpp \
    stream_engine.cpp \
    sub.cpp \
    tcp.cpp \
    tcp_address.cpp \
    tcp_connecter.cpp \
    tcp_listener.cpp \
    thread.cpp \
    trie.cpp \
    xpub.cpp \
    router.cpp \
    dealer.cpp \
    v1_decoder.cpp \
    v1_decoder.hpp \
    v1_encoder.cpp \
    v1_encoder.hpp \
    v1_protocol.hpp \
    xsub.cpp \
    zmq.cpp \
    zmq_utils.cpp

if ON_MINGW
libzmq_la_LDFLAGS = -no-undefined -avoid-version -version-info @LTVER@ @LIBZMQ_EXTRA_LDFLAGS@
else
if ON_ANDROID
libzmq_la_LDFLAGS = -avoid-version -version-info @LTVER@ @LIBZMQ_EXTRA_LDFLAGS@
else
libzmq_la_LDFLAGS = -version-info @LTVER@ @LIBZMQ_EXTRA_LDFLAGS@
endif
endif

libzmq_la_CXXFLAGS = @LIBZMQ_EXTRA_CXXFLAGS@

if BUILD_PGM
libzmq_la_CPPFLAGS = -I$(top_srcdir)/@pgm_srcdir@/include/
libzmq_la_LIBADD = $(top_srcdir)/@pgm_srcdir@/libpgm_noinst.la
endif

dist-hook:
		-rm $(distdir)/platform.hpp


