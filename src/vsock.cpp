/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"

#include "ip.hpp"
#include "vsock.hpp"
#include "vsock_address.hpp"

#if defined ZMQ_HAVE_VSOCK

zmq::fd_t zmq::vsock_open_socket (const char *address_,
                                 const zmq::options_t &options_,
                                 zmq::vsock_address_t *out_vsock_addr_)
{
    //
    //  Convert the textual address into address structure.
    //

    int rc = out_vsock_addr_->resolve (address_);

    if (rc != 0) {
        return retired_fd;
    }

    //
    //  Create the socket.
    //

    fd_t s = open_socket (out_vsock_addr_->family (), SOCK_STREAM, 0);

    if (s == retired_fd) {
        return retired_fd;
    }

    return s;
}

#endif
