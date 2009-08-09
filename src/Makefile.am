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
    io_object.hpp \
    io_thread.hpp \
    ip.hpp \
    i_api.hpp \
    i_poller.hpp \
    i_poll_events.hpp \
    i_signaler.hpp \
    i_socket.hpp \
    kqueue.hpp \
    msg.hpp \
    mutex.hpp \
    object.hpp \
    pipe.hpp \
    platform.hpp \
    poll.hpp \
    select.hpp \
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
    zmq_engine.hpp \
    zmq_listener.hpp \
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
    poll.cpp \
    select.cpp \
    socket_base.cpp \
    tcp_connecter.cpp \
    tcp_listener.cpp \
    tcp_socket.cpp \
    thread.cpp \
    uuid.cpp \
    ypollset.cpp \
    zmq.cpp \
    zmq_engine.cpp \
    zmq_listener.cpp

libzmq_la_LDFLAGS = -version-info 0:0:0
libzmq_la_CXXFLAGS = -Wall -pedantic -Werror @ZMQ_EXTRA_CXXFLAGS@

dist-hook:
		-rm $(distdir)/src/platform.hpp


