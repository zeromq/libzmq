/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"

#include "ip.hpp"
#include "hvsocket.hpp"
#include "hvsocket_address.hpp"

#if defined ZMQ_HAVE_HVSOCKET

zmq::fd_t
zmq::hvsocket_open_socket (const char *address_,
                           const zmq::options_t &options_,
                           zmq::hvsocket_address_t *out_hvsocket_addr_)
{
    if ((options_.connect_timeout < 0)
        || (options_.connect_timeout > HVSOCKET_CONNECT_TIMEOUT_MAX)) {
        errno = EINVAL;
        return retired_fd;
    }

    //
    //  Convert the textual address into address structure.
    //

    int rc = out_hvsocket_addr_->resolve (address_);

    if (rc != 0) {
        return retired_fd;
    }

    //
    //  Create the socket.
    //

    fd_t s =
      open_socket (out_hvsocket_addr_->family (), SOCK_STREAM, HV_PROTOCOL_RAW);

    if (s == retired_fd) {
        return retired_fd;
    }

    //
    // Best effort to set socket options.
    //

    const int non_zero_value = 1;

    if (options_.hvsocket_container_passthru) {
        rc =
          setsockopt (s, HV_PROTOCOL_RAW, HVSOCKET_CONTAINER_PASSTHRU,
                      (const char *) &non_zero_value, sizeof (non_zero_value));
#ifndef NDEBUG
        zmq_assert (rc == 0);
#else
        LIBZMQ_UNUSED (rc);
#endif
    }

    if (options_.hvsocket_connected_suspend) {
        rc = setsockopt (s, HV_PROTOCOL_RAW, HVSOCKET_CONNECTED_SUSPEND,
                         (const char *) &non_zero_value, sizeof (non_zero_value));
#ifndef NDEBUG
        zmq_assert (rc == 0);
#else
        LIBZMQ_UNUSED (rc);
#endif
    }

    if (options_.hvsocket_high_vtl) {
        rc = setsockopt (s, HV_PROTOCOL_RAW, HVSOCKET_HIGH_VTL,
                         (const char *) &non_zero_value, sizeof (non_zero_value));
#ifndef NDEBUG
        zmq_assert (rc == 0);
#else
        LIBZMQ_UNUSED (rc);
#endif
    }

    if (options_.connect_timeout > 0) {
        rc = setsockopt (s, HV_PROTOCOL_RAW, HVSOCKET_CONNECT_TIMEOUT,
                    (const char *) &options_.connect_timeout,
                    sizeof (options_.connect_timeout));
#ifndef NDEBUG
        zmq_assert (rc == 0);
#endif
    }

    return s;
}

#endif
