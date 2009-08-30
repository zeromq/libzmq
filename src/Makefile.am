lib_LTLIBRARIES = libzmq.la

libzmq_la_SOURCES = \
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
    owner.hpp \
    pipe.hpp \
    platform.hpp \
    poll.hpp \
    select.hpp \
    session.hpp \
    simple_semaphore.hpp \
    socket_base.hpp \
    stdint.hpp \
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
    pipe.cpp \
    poll.cpp \
    select.cpp \
    session.cpp \
    socket_base.cpp \
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

libzmq_la_LDFLAGS = -version-info 0:0:0
libzmq_la_CXXFLAGS = -Wall -pedantic -Werror @ZMQ_EXTRA_CXXFLAGS@

dist-hook:
		-rm $(distdir)/src/platform.hpp


