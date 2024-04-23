/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_IPC_ADDRESS_HPP_INCLUDED__
#define __ZMQ_IPC_ADDRESS_HPP_INCLUDED__

#if defined ZMQ_HAVE_IPC

#include <string>

#if defined ZMQ_HAVE_WINDOWS
#include <afunix.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#endif

#include "macros.hpp"

namespace zmq
{
class ipc_address_t
{
  public:
    ipc_address_t ();
    ipc_address_t (const sockaddr *sa_, socklen_t sa_len_);
    ~ipc_address_t ();

    //  This function sets up the address for UNIX domain transport.
    int resolve (const char *path_);

    //  The opposite to resolve()
    int to_string (std::string &addr_) const;

    const sockaddr *addr () const;
    socklen_t addrlen () const;

  private:
    struct sockaddr_un _address;
    socklen_t _addrlen;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (ipc_address_t)
};
}

#endif

#endif
