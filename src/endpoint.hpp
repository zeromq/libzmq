/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_ENDPOINT_HPP_INCLUDED__
#define __ZMQ_ENDPOINT_HPP_INCLUDED__

#include <string>

namespace zmq
{
enum endpoint_type_t
{
    endpoint_type_none,   // a connection-less endpoint
    endpoint_type_bind,   // a connection-oriented bind endpoint
    endpoint_type_connect // a connection-oriented connect endpoint
};

struct endpoint_uri_pair_t
{
    endpoint_uri_pair_t () : local_type (endpoint_type_none) {}
    endpoint_uri_pair_t (const std::string &local,
                         const std::string &remote,
                         endpoint_type_t local_type) :
        local (local), remote (remote), local_type (local_type)
    {
    }

    const std::string &identifier () const
    {
        return local_type == endpoint_type_bind ? local : remote;
    }

    std::string local, remote;
    endpoint_type_t local_type;
};

endpoint_uri_pair_t
make_unconnected_connect_endpoint_pair (const std::string &endpoint_);

endpoint_uri_pair_t
make_unconnected_bind_endpoint_pair (const std::string &endpoint_);
}

#endif
