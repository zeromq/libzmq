/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_PROXY_HPP_INCLUDED__
#define __ZMQ_PROXY_HPP_INCLUDED__

namespace zmq
{
int proxy (class socket_base_t *frontend_,
           class socket_base_t *backend_,
           class socket_base_t *capture_);

int proxy_steerable (class socket_base_t *frontend_,
                     class socket_base_t *backend_,
                     class socket_base_t *capture_,
                     class socket_base_t *control_);
}

#endif
