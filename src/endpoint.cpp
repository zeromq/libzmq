/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "endpoint.hpp"

zmq::endpoint_uri_pair_t
zmq::make_unconnected_connect_endpoint_pair (const std::string &endpoint_)
{
    return endpoint_uri_pair_t (std::string (), endpoint_,
                                endpoint_type_connect);
}

zmq::endpoint_uri_pair_t
zmq::make_unconnected_bind_endpoint_pair (const std::string &endpoint_)
{
    return endpoint_uri_pair_t (endpoint_, std::string (), endpoint_type_bind);
}
