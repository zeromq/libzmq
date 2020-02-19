DEFINES += ZMQ_HAVE_STRLCPY

SOURCES += \
    $$PWD/../../src/address.cpp \
    $$PWD/../../src/client.cpp \
    $$PWD/../../src/clock.cpp \
    $$PWD/../../src/ctx.cpp \
    $$PWD/../../src/curve_client.cpp \
    $$PWD/../../src/curve_mechanism_base.cpp \
    $$PWD/../../src/curve_server.cpp \
    $$PWD/../../src/dealer.cpp \
    $$PWD/../../src/decoder_allocators.cpp \
    $$PWD/../../src/devpoll.cpp \
    $$PWD/../../src/dgram.cpp \
    $$PWD/../../src/dish.cpp \
    $$PWD/../../src/dist.cpp \
    $$PWD/../../src/endpoint.cpp \
    $$PWD/../../src/epoll.cpp \
    $$PWD/../../src/err.cpp \
    $$PWD/../../src/fq.cpp \
    $$PWD/../../src/gather.cpp \
    $$PWD/../../src/gssapi_client.cpp \
    $$PWD/../../src/gssapi_mechanism_base.cpp \
    $$PWD/../../src/gssapi_server.cpp \
    $$PWD/../../src/io_object.cpp \
    $$PWD/../../src/io_thread.cpp \
    $$PWD/../../src/ip.cpp \
    $$PWD/../../src/ip_resolver.cpp \
    $$PWD/../../src/ipc_address.cpp \
    $$PWD/../../src/ipc_connecter.cpp \
    $$PWD/../../src/ipc_listener.cpp \
    $$PWD/../../src/kqueue.cpp \
    $$PWD/../../src/lb.cpp \
    $$PWD/../../src/mailbox.cpp \
    $$PWD/../../src/mailbox_safe.cpp \
    $$PWD/../../src/mechanism.cpp \
    $$PWD/../../src/mechanism_base.cpp \
    $$PWD/../../src/metadata.cpp \
    $$PWD/../../src/msg.cpp \
    $$PWD/../../src/mtrie.cpp \
    $$PWD/../../src/norm_engine.cpp \
    $$PWD/../../src/null_mechanism.cpp \
    $$PWD/../../src/object.cpp \
    $$PWD/../../src/options.cpp \
    $$PWD/../../src/own.cpp \
    $$PWD/../../src/pair.cpp \
    $$PWD/../../src/peer.cpp \
    $$PWD/../../src/pgm_receiver.cpp \
    $$PWD/../../src/pgm_sender.cpp \
    $$PWD/../../src/pgm_socket.cpp \
    $$PWD/../../src/pipe.cpp \
    $$PWD/../../src/plain_client.cpp \
    $$PWD/../../src/plain_server.cpp \
    $$PWD/../../src/poll.cpp \
    $$PWD/../../src/poller_base.cpp \
    $$PWD/../../src/polling_util.cpp \
    $$PWD/../../src/pollset.cpp \
    $$PWD/../../src/precompiled.cpp \
    $$PWD/../../src/proxy.cpp \
    $$PWD/../../src/pub.cpp \
    $$PWD/../../src/pull.cpp \
    $$PWD/../../src/push.cpp \
    $$PWD/../../src/radio.cpp \
    $$PWD/../../src/radix_tree.cpp \
    $$PWD/../../src/random.cpp \
    $$PWD/../../src/raw_decoder.cpp \
    $$PWD/../../src/raw_encoder.cpp \
    $$PWD/../../src/raw_engine.cpp \
    $$PWD/../../src/reaper.cpp \
    $$PWD/../../src/rep.cpp \
    $$PWD/../../src/req.cpp \
    $$PWD/../../src/router.cpp \
    $$PWD/../../src/scatter.cpp \
    $$PWD/../../src/select.cpp \
    $$PWD/../../src/server.cpp \
    $$PWD/../../src/session_base.cpp \
    $$PWD/../../src/signaler.cpp \
    $$PWD/../../src/socket_base.cpp \
    $$PWD/../../src/socket_poller.cpp \
    $$PWD/../../src/socks.cpp \
    $$PWD/../../src/socks_connecter.cpp \
    $$PWD/../../src/stream.cpp \
    $$PWD/../../src/stream_connecter_base.cpp \
    $$PWD/../../src/stream_engine_base.cpp \
    $$PWD/../../src/stream_listener_base.cpp \
    $$PWD/../../src/sub.cpp \
    $$PWD/../../src/tcp.cpp \
    $$PWD/../../src/tcp_address.cpp \
    $$PWD/../../src/tcp_connecter.cpp \
    $$PWD/../../src/tcp_listener.cpp \
    $$PWD/../../src/thread.cpp \
    $$PWD/../../src/timers.cpp \
    $$PWD/../../src/tipc_address.cpp \
    $$PWD/../../src/tipc_connecter.cpp \
    $$PWD/../../src/tipc_listener.cpp \
    $$PWD/../../src/trie.cpp \
    $$PWD/../../src/udp_address.cpp \
    $$PWD/../../src/udp_engine.cpp \
    $$PWD/../../src/v1_decoder.cpp \
    $$PWD/../../src/v1_encoder.cpp \
    $$PWD/../../src/v2_decoder.cpp \
    $$PWD/../../src/v2_encoder.cpp \
    $$PWD/../../src/v3_1_encoder.cpp \
    $$PWD/../../src/vmci.cpp \
    $$PWD/../../src/vmci_address.cpp \
    $$PWD/../../src/vmci_connecter.cpp \
    $$PWD/../../src/vmci_listener.cpp \
    $$PWD/../../src/ws_address.cpp \
    $$PWD/../../src/ws_connecter.cpp \
    $$PWD/../../src/ws_decoder.cpp \
    $$PWD/../../src/ws_encoder.cpp \
    $$PWD/../../src/ws_engine.cpp \
    $$PWD/../../src/ws_listener.cpp \
    $$PWD/../../src/wss_address.cpp \
    #$$PWD/../../src/wss_engine.cpp \
    $$PWD/../../src/xpub.cpp \
    $$PWD/../../src/xsub.cpp \
    $$PWD/../../src/zap_client.cpp \
    $$PWD/../../src/zmq.cpp \
    $$PWD/../../src/zmq_utils.cpp \
    $$PWD/../../src/zmtp_engine.cpp

HEADERS += \
    $$PWD/../../src/address.hpp \
    $$PWD/../../src/array.hpp \
    $$PWD/../../src/atomic_counter.hpp \
    $$PWD/../../src/atomic_ptr.hpp \
    $$PWD/../../src/blob.hpp \
    $$PWD/../../src/client.hpp \
    $$PWD/../../src/clock.hpp \
    $$PWD/../../src/command.hpp \
    $$PWD/../../src/condition_variable.hpp \
    $$PWD/../../src/config.hpp \
    $$PWD/../../src/ctx.hpp \
    $$PWD/../../src/curve_client.hpp \
    $$PWD/../../src/curve_client_tools.hpp \
    $$PWD/../../src/curve_mechanism_base.hpp \
    $$PWD/../../src/curve_server.hpp \
    $$PWD/../../src/dbuffer.hpp \
    $$PWD/../../src/dealer.hpp \
    $$PWD/../../src/decoder.hpp \
    $$PWD/../../src/decoder_allocators.hpp \
    $$PWD/../../src/devpoll.hpp \
    $$PWD/../../src/dgram.hpp \
    $$PWD/../../src/dish.hpp \
    $$PWD/../../src/dist.hpp \
    $$PWD/../../src/encoder.hpp \
    $$PWD/../../src/endpoint.hpp \
    $$PWD/../../src/epoll.hpp \
    $$PWD/../../src/err.hpp \
    $$PWD/../../src/fd.hpp \
    $$PWD/../../src/fq.hpp \
    $$PWD/../../src/gather.hpp \
    $$PWD/../../src/generic_mtrie.hpp \
    $$PWD/../../src/generic_mtrie_impl.hpp \
    $$PWD/../../src/gssapi_client.hpp \
    $$PWD/../../src/gssapi_mechanism_base.hpp \
    $$PWD/../../src/gssapi_server.hpp \
    $$PWD/../../src/i_decoder.hpp \
    $$PWD/../../src/i_encoder.hpp \
    $$PWD/../../src/i_engine.hpp \
    $$PWD/../../src/i_mailbox.hpp \
    $$PWD/../../src/i_poll_events.hpp \
    $$PWD/../../src/io_object.hpp \
    $$PWD/../../src/io_thread.hpp \
    $$PWD/../../src/ip.hpp \
    $$PWD/../../src/ip_resolver.hpp \
    $$PWD/../../src/ipc_address.hpp \
    $$PWD/../../src/ipc_connecter.hpp \
    $$PWD/../../src/ipc_listener.hpp \
    $$PWD/../../src/kqueue.hpp \
    $$PWD/../../src/lb.hpp \
    $$PWD/../../src/likely.hpp \
    $$PWD/../../src/macros.hpp \
    $$PWD/../../src/mailbox.hpp \
    $$PWD/../../src/mailbox_safe.hpp \
    $$PWD/../../src/mechanism.hpp \
    $$PWD/../../src/mechanism_base.hpp \
    $$PWD/../../src/metadata.hpp \
    $$PWD/../../src/msg.hpp \
    $$PWD/../../src/mtrie.hpp \
    $$PWD/../../src/mutex.hpp \
    $$PWD/../../src/norm_engine.hpp \
    $$PWD/../../src/null_mechanism.hpp \
    $$PWD/../../src/object.hpp \
    $$PWD/../../src/options.hpp \
    $$PWD/../../src/own.hpp \
    $$PWD/../../src/pair.hpp \
    $$PWD/../../src/peer.hpp \
    $$PWD/../../src/pgm_receiver.hpp \
    $$PWD/../../src/pgm_sender.hpp \
    $$PWD/../../src/pgm_socket.hpp \
    $$PWD/../../src/pipe.hpp \
    $$PWD/../../src/plain_client.hpp \
    $$PWD/../../src/plain_common.hpp \
    $$PWD/../../src/plain_server.hpp \
    $$PWD/../../src/poll.hpp \
    $$PWD/../../src/poller.hpp \
    $$PWD/../../src/poller_base.hpp \
    $$PWD/../../src/polling_util.hpp \
    $$PWD/../../src/pollset.hpp \
    $$PWD/../../src/precompiled.hpp \
    $$PWD/../../src/proxy.hpp \
    $$PWD/../../src/pub.hpp \
    $$PWD/../../src/pull.hpp \
    $$PWD/../../src/push.hpp \
    $$PWD/../../src/radio.hpp \
    $$PWD/../../src/radix_tree.hpp \
    $$PWD/../../src/random.hpp \
    $$PWD/../../src/raw_decoder.hpp \
    $$PWD/../../src/raw_encoder.hpp \
    $$PWD/../../src/raw_engine.hpp \
    $$PWD/../../src/reaper.hpp \
    $$PWD/../../src/rep.hpp \
    $$PWD/../../src/req.hpp \
    $$PWD/../../src/router.hpp \
    $$PWD/../../src/scatter.hpp \
    $$PWD/../../src/secure_allocator.hpp \
    $$PWD/../../src/select.hpp \
    $$PWD/../../src/server.hpp \
    $$PWD/../../src/session_base.hpp \
    $$PWD/../../src/signaler.hpp \
    $$PWD/../../src/socket_base.hpp \
    $$PWD/../../src/socket_poller.hpp \
    $$PWD/../../src/socks.hpp \
    $$PWD/../../src/socks_connecter.hpp \
    $$PWD/../../src/stdint.hpp \
    $$PWD/../../src/stream.hpp \
    $$PWD/../../src/stream_connecter_base.hpp \
    $$PWD/../../src/stream_engine_base.hpp \
    $$PWD/../../src/stream_listener_base.hpp \
    $$PWD/../../src/sub.hpp \
    $$PWD/../../src/tcp.hpp \
    $$PWD/../../src/tcp_address.hpp \
    $$PWD/../../src/tcp_connecter.hpp \
    $$PWD/../../src/tcp_listener.hpp \
    $$PWD/../../src/thread.hpp \
    $$PWD/../../src/timers.hpp \
    $$PWD/../../src/tipc_address.hpp \
    $$PWD/../../src/tipc_connecter.hpp \
    $$PWD/../../src/tipc_listener.hpp \
    $$PWD/../../src/trie.hpp \
    $$PWD/../../src/udp_address.hpp \
    $$PWD/../../src/udp_engine.hpp \
    $$PWD/../../src/v1_decoder.hpp \
    $$PWD/../../src/v1_encoder.hpp \
    $$PWD/../../src/v2_decoder.hpp \
    $$PWD/../../src/v2_encoder.hpp \
    $$PWD/../../src/v2_protocol.hpp \
    $$PWD/../../src/v3_1_encoder.hpp \
    $$PWD/../../src/vmci.hpp \
    $$PWD/../../src/vmci_address.hpp \
    $$PWD/../../src/vmci_connecter.hpp \
    $$PWD/../../src/vmci_listener.hpp \
    $$PWD/../../src/wire.hpp \
    $$PWD/../../src/ws_address.hpp \
    $$PWD/../../src/ws_connecter.hpp \
    $$PWD/../../src/ws_decoder.hpp \
    $$PWD/../../src/ws_encoder.hpp \
    $$PWD/../../src/ws_engine.hpp \
    $$PWD/../../src/ws_listener.hpp \
    $$PWD/../../src/ws_protocol.hpp \
    $$PWD/../../src/wss_address.hpp \
    #$$PWD/../../src/wss_engine.hpp \
    $$PWD/../../src/xpub.hpp \
    $$PWD/../../src/xsub.hpp \
    $$PWD/../../src/ypipe.hpp \
    $$PWD/../../src/ypipe_base.hpp \
    $$PWD/../../src/ypipe_conflate.hpp \
    $$PWD/../../src/yqueue.hpp \
    $$PWD/../../src/zap_client.hpp \
    $$PWD/../../src/zmtp_engine.hpp

win32 {
    HEADERS += $$PWD/../../src/windows.hpp
}

INCLUDEPATH += \
    $$PWD/../../include

win32 {
    INCLUDEPATH += \
        $$PWD/windows

    ## Externals

    # Sha1
    SOURCES += \
    #    $$PWD/../../external/sha1/sha1.c # Redefined in czmq

    HEADERS += \
        $$PWD/../../external/sha1/sha1.h

    # Wepoll
    SOURCES += \
        $$PWD/../../external/wepoll/wepoll.c

    HEADERS += \
        $$PWD/../../external/wepoll/wepoll.h

}

unix {
    INCLUDEPATH += \
        $$PWD/macos
}
