{
  'targets': [
    {
      'target_name': 'test_system',
      'type': 'executable',
      'sources': [
        '../../tests/test_system.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_pair_inproc',
      'type': 'executable',
      'sources': [
        '../../tests/test_pair_inproc.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_pair_tcp',
      'type': 'executable',
      'sources': [
        '../../tests/test_pair_tcp.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_reqrep_inproc',
      'type': 'executable',
      'sources': [
        '../../tests/test_reqrep_inproc.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_reqrep_tcp',
      'type': 'executable',
      'sources': [
        '../../tests/test_reqrep_tcp.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_hwm',
      'type': 'executable',
      'sources': [
        '../../tests/test_hwm.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_hwm_pubsub',
      'type': 'executable',
      'sources': [
        '../../tests/test_hwm_pubsub.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_reqrep_device',
      'type': 'executable',
      'sources': [
        '../../tests/test_reqrep_device.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_sub_forward',
      'type': 'executable',
      'sources': [
        '../../tests/test_sub_forward.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_invalid_rep',
      'type': 'executable',
      'sources': [
        '../../tests/test_invalid_rep.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_msg_flags',
      'type': 'executable',
      'sources': [
        '../../tests/test_msg_flags.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_msg_ffn',
      'type': 'executable',
      'sources': [
        '../../tests/test_msg_ffn.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_connect_resolve',
      'type': 'executable',
      'sources': [
        '../../tests/test_connect_resolve.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_immediate',
      'type': 'executable',
      'sources': [
        '../../tests/test_immediate.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_last_endpoint',
      'type': 'executable',
      'sources': [
        '../../tests/test_last_endpoint.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_term_endpoint',
      'type': 'executable',
      'sources': [
        '../../tests/test_term_endpoint.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_srcfd',
      'type': 'executable',
      'sources': [
        '../../tests/test_srcfd.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_monitor',
      'type': 'executable',
      'sources': [
        '../../tests/test_monitor.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_router_mandatory',
      'type': 'executable',
      'sources': [
        '../../tests/test_router_mandatory.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_router_mandatory_hwm',
      'type': 'executable',
      'sources': [
        '../../tests/test_router_mandatory_hwm.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_router_handover',
      'type': 'executable',
      'sources': [
        '../../tests/test_router_handover.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_probe_router',
      'type': 'executable',
      'sources': [
        '../../tests/test_probe_router.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_stream',
      'type': 'executable',
      'sources': [
        '../../tests/test_stream.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_stream_empty',
      'type': 'executable',
      'sources': [
        '../../tests/test_stream_empty.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_stream_disconnect',
      'type': 'executable',
      'sources': [
        '../../tests/test_stream_disconnect.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_stream_timeout',
      'type': 'executable',
      'sources': [
        '../../tests/test_stream_timeout.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_disconnect_inproc',
      'type': 'executable',
      'sources': [
        '../../tests/test_disconnect_inproc.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_unbind_inproc',
      'type': 'executable',
      'sources': [
        '../../tests/test_unbind_inproc.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_unbind_wildcard',
      'type': 'executable',
      'sources': [
        '../../tests/test_unbind_wildcard.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_ctx_options',
      'type': 'executable',
      'sources': [
        '../../tests/test_ctx_options.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_ctx_destroy',
      'type': 'executable',
      'sources': [
        '../../tests/test_ctx_destroy.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_security_null',
      'type': 'executable',
      'sources': [
        '../../tests/test_security_null.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_security_plain',
      'type': 'executable',
      'sources': [
        '../../tests/test_security_plain.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_security_curve',
      'type': 'executable',
      'sources': [
        '../../tests/test_security_curve.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_security_zap',
      'type': 'executable',
      'sources': [
        '../../tests/test_security_zap.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_iov',
      'type': 'executable',
      'sources': [
        '../../tests/test_iov.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_spec_req',
      'type': 'executable',
      'sources': [
        '../../tests/test_spec_req.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_spec_rep',
      'type': 'executable',
      'sources': [
        '../../tests/test_spec_rep.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_spec_dealer',
      'type': 'executable',
      'sources': [
        '../../tests/test_spec_dealer.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_spec_router',
      'type': 'executable',
      'sources': [
        '../../tests/test_spec_router.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_spec_pushpull',
      'type': 'executable',
      'sources': [
        '../../tests/test_spec_pushpull.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_req_correlate',
      'type': 'executable',
      'sources': [
        '../../tests/test_req_correlate.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_req_relaxed',
      'type': 'executable',
      'sources': [
        '../../tests/test_req_relaxed.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_conflate',
      'type': 'executable',
      'sources': [
        '../../tests/test_conflate.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_inproc_connect',
      'type': 'executable',
      'sources': [
        '../../tests/test_inproc_connect.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_issue_566',
      'type': 'executable',
      'sources': [
        '../../tests/test_issue_566.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_proxy',
      'type': 'executable',
      'sources': [
        '../../tests/test_proxy.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_proxy_single_socket',
      'type': 'executable',
      'sources': [
        '../../tests/test_proxy_single_socket.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_proxy_terminate',
      'type': 'executable',
      'sources': [
        '../../tests/test_proxy_terminate.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_getsockopt_memset',
      'type': 'executable',
      'sources': [
        '../../tests/test_getsockopt_memset.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_setsockopt',
      'type': 'executable',
      'sources': [
        '../../tests/test_setsockopt.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_many_sockets',
      'type': 'executable',
      'sources': [
        '../../tests/test_many_sockets.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_ipc_wildcard',
      'type': 'executable',
      'sources': [
        '../../tests/test_ipc_wildcard.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_diffserv',
      'type': 'executable',
      'sources': [
        '../../tests/test_diffserv.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_connect_rid',
      'type': 'executable',
      'sources': [
        '../../tests/test_connect_rid.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_bind_src_address',
      'type': 'executable',
      'sources': [
        '../../tests/test_bind_src_address.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_metadata',
      'type': 'executable',
      'sources': [
        '../../tests/test_metadata.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_capabilities',
      'type': 'executable',
      'sources': [
        '../../tests/test_capabilities.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_xpub_nodrop',
      'type': 'executable',
      'sources': [
        '../../tests/test_xpub_nodrop.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_xpub_manual',
      'type': 'executable',
      'sources': [
        '../../tests/test_xpub_manual.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_xpub_welcome_msg',
      'type': 'executable',
      'sources': [
        '../../tests/test_xpub_welcome_msg.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_atomics',
      'type': 'executable',
      'sources': [
        '../../tests/test_atomics.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_client_server',
      'type': 'executable',
      'sources': [
        '../../tests/test_client_server.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_thread_safe',
      'type': 'executable',
      'sources': [
        '../../tests/test_thread_safe.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_sockopt_hwm',
      'type': 'executable',
      'sources': [
        '../../tests/test_sockopt_hwm.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_heartbeats',
      'type': 'executable',
      'sources': [
        '../../tests/test_heartbeats.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_stream_exceeds_buffer',
      'type': 'executable',
      'sources': [
        '../../tests/test_stream_exceeds_buffer.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_poller',
      'type': 'executable',
      'sources': [
        '../../tests/test_poller.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_timers',
      'type': 'executable',
      'sources': [
        '../../tests/test_timers.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_radio_dish',
      'type': 'executable',
      'sources': [
        '../../tests/test_radio_dish.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_udp',
      'type': 'executable',
      'sources': [
        '../../tests/test_udp.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_shutdown_stress',
      'type': 'executable',
      'sources': [
        '../../tests/test_shutdown_stress.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_pair_ipc',
      'type': 'executable',
      'sources': [
        '../../tests/test_pair_ipc.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_rebind_ipc',
      'type': 'executable',
      'sources': [
        '../../tests/test_rebind_ipc.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_reqrep_ipc',
      'type': 'executable',
      'sources': [
        '../../tests/test_reqrep_ipc.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_use_fd_ipc',
      'type': 'executable',
      'sources': [
        '../../tests/test_use_fd_ipc.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_use_fd_tcp',
      'type': 'executable',
      'sources': [
        '../../tests/test_use_fd_tcp.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_timeo',
      'type': 'executable',
      'sources': [
        '../../tests/test_timeo.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_filter_ipc',
      'type': 'executable',
      'sources': [
        '../../tests/test_filter_ipc.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_fork',
      'type': 'executable',
      'sources': [
        '../../tests/test_fork.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    },
    {
      'target_name': 'test_abstract_ipc',
      'type': 'executable',
      'sources': [
        '../../tests/test_abstract_ipc.cpp',
        '../../tests/testutil.hpp'
      ],
      'dependencies': [
        'libzmq'
      ],
    }
  ]
}
