/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_STREAM_LISTENER_BASE_HPP_INCLUDED__
#define __ZMQ_STREAM_LISTENER_BASE_HPP_INCLUDED__

#include <string>

#include "fd.hpp"
#include "own.hpp"
#include "stdint.hpp"
#include "io_object.hpp"
#include "tipc_address.hpp"

namespace zmq
{
class io_thread_t;
class socket_base_t;

#if defined(ZMQ_HAVE_HPUX) || defined(ZMQ_HAVE_VXWORKS)
typedef int zmq_socklen_t;
#else
typedef socklen_t zmq_socklen_t;
#endif

class stream_listener_base_t : public own_t, public io_object_t
{
  public:
    stream_listener_base_t (zmq::io_thread_t *io_thread_,
                            zmq::socket_base_t *socket_,
                            const options_t &options_);
    ~stream_listener_base_t ();

    // Get the bound address for use with wildcards
    int get_address (std::string &addr_) const;

  protected:
    static zmq_socklen_t get_socket_address (fd_t fd_, sockaddr_storage *ss_);
    virtual std::string get_socket_name (fd_t fd_) const = 0;

    template <typename T> static std::string get_socket_name (fd_t fd_)
    {
        struct sockaddr_storage ss;
        const zmq_socklen_t sl = get_socket_address (fd_, &ss);
        if (sl == 0) {
            return std::string ();
        }

        const T addr (reinterpret_cast<struct sockaddr *> (&ss), sl);
        std::string address_string;
        addr.to_string (address_string);
        return address_string;
    }

  private:
    //  Handlers for incoming commands.
    void process_plug ();
    void process_term (int linger_);

  protected:
    //  Close the listening socket.
    virtual int close ();

    void create_engine (fd_t fd);

    //  Underlying socket.
    fd_t _s;

    //  Handle corresponding to the listening socket.
    handle_t _handle;

    //  Socket the listener belongs to.
    zmq::socket_base_t *_socket;

    // String representation of endpoint to bind to
    std::string _endpoint;

  private:
    stream_listener_base_t (const stream_listener_base_t &);
    const stream_listener_base_t &operator= (const stream_listener_base_t &);
};
}

#endif
