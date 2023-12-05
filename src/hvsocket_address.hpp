/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_HVSOCKET_ADDRESS_HPP_INCLUDED__
#define __ZMQ_HVSOCKET_ADDRESS_HPP_INCLUDED__

#include <string>
#include <hvsocket.h>

#include "platform.hpp"
#include "ctx.hpp"

#if defined(ZMQ_HAVE_HVSOCKET)

#ifndef HVSOCKET_CONNECT_TIMEOUT
#define HVSOCKET_CONNECT_TIMEOUT 0x01
#endif

#ifndef HVSOCKET_CONTAINER_PASSTHRU
#define HVSOCKET_CONTAINER_PASSTHRU 0x02
#endif

#ifndef HVSOCKET_CONNECTED_SUSPEND
#define HVSOCKET_CONNECTED_SUSPEND 0x04
#endif

#ifndef HVSOCKET_HIGH_VTL
#define HVSOCKET_HIGH_VTL 0x08
#endif

#ifndef HVSOCKET_CONNECT_TIMEOUT_MAX
#define HVSOCKET_CONNECT_TIMEOUT_MAX 300000 // 5 minutes
#endif

namespace zmq
{
class hvsocket_address_t
{
  public:
    hvsocket_address_t ();
    hvsocket_address_t (ctx_t *parent_);
    hvsocket_address_t (const sockaddr *sa, socklen_t sa_len, ctx_t *parent_);

    //  This function sets up the address for HVSOCKET transport.
    int resolve (const char *path_);

    //  The opposite to resolve()
    int to_string (std::string &addr_) const;

#if defined ZMQ_HAVE_WINDOWS
    unsigned short family () const;
#else
    sa_family_t family () const;
#endif
    const sockaddr *addr () const;
    socklen_t addrlen () const;

  private:

    SOCKADDR_HV address;
    ctx_t *parent;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (hvsocket_address_t)
};
}

#endif

#endif
